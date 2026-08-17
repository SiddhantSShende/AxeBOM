// Package store is the report service's persistence layer.
//
// Every tenant-scoped query goes through db.WithTenant. There is exactly ONE
// exception, and it is deliberate: the anonymous share-link path in share.go,
// which presents a token and nothing else and therefore has no tenant to scope
// with. That path uses the narrow SECURITY DEFINER functions from
// migrations/report/0002 — the same shape Phase 3 established for login — and
// never pool.Raw().
//
// Cross-tenant access returns ErrNotFound for free: RLS filters the row out,
// the query finds nothing, and "not found" is the honest answer. A 403 would
// confirm the id exists.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/encorebom/encorebom/libs/go-shared/platform/db"
)

// ErrNotFound is returned when a row does not exist FOR THIS TENANT.
//
// Absent and belonging-to-somebody-else are deliberately indistinguishable,
// because RLS makes them indistinguishable at the database. Handlers turn this
// into a 404.
var ErrNotFound = errors.New("not found")

// Store is the report service's database access.
type Store struct{ pool *db.Pool }

// New builds a store over a pool.
func New(pool *db.Pool) *Store { return &Store{pool: pool} }

// Status is a report's render state.
//
// ⚠ RENDERING IS ASYNC AND THESE ARE THE ONLY STATES. A Complete BOM can exceed
// 50k components; a synchronous request would time out long before the PDF
// finished, and the customer would retry, and the worker would render it twice.
type Status string

const (
	// StatusQueued means the render has been requested and nothing has started.
	StatusQueued Status = "queued"
	// StatusRendering means a worker has claimed it.
	StatusRendering Status = "rendering"
	// StatusReady means the artifact is in object storage and signed.
	StatusReady Status = "ready"
	// StatusFailed means the render will not be retried automatically.
	StatusFailed Status = "failed"
)

// Report mirrors report.reports.
type Report struct {
	ID       string
	TenantID string
	ScanID   string

	BOMDocumentIDs []string
	BOMType        string
	Level          string
	Standard       string
	Format         string

	// Visibility gates the download. A private report carries vulnerability
	// detail (CERT-In §5.3.2) and a Viewer may not have it.
	Visibility string
	Status     Status

	StorageRef string
	SHA256     string
	SizeBytes  int64

	Signature    string
	SigningKeyID string

	Truncated      bool
	TruncationNote string

	ErrorCode string
	CreatedAt time.Time
	UpdatedAt time.Time
}

const reportColumns = `
	SELECT id, tenant_id, scan_id, bom_document_ids, bom_type, level, standard,
	       format, visibility, status,
	       COALESCE(storage_ref,''), COALESCE(sha256,''), COALESCE(size_bytes,0),
	       COALESCE(signature,''), COALESCE(signing_key_id,''),
	       truncated, COALESCE(truncation_note,''), COALESCE(error_code,''),
	       created_at, updated_at`

func scanReport(row pgx.Row, r *Report) error {
	return row.Scan(&r.ID, &r.TenantID, &r.ScanID, &r.BOMDocumentIDs, &r.BOMType,
		&r.Level, &r.Standard, &r.Format, &r.Visibility, &r.Status,
		&r.StorageRef, &r.SHA256, &r.SizeBytes,
		&r.Signature, &r.SigningKeyID,
		&r.Truncated, &r.TruncationNote, &r.ErrorCode,
		&r.CreatedAt, &r.UpdatedAt)
}

// CreateRequest is what a caller asks for.
type CreateRequest struct {
	TenantID       string
	ScanID         string
	BOMDocumentIDs []string
	BOMType        string
	Level          string
	Standard       string
	Format         string
	Visibility     string
}

// Create records a queued render.
func (s *Store) Create(ctx context.Context, req CreateRequest) (Report, error) {
	// ⚠ A NIL SLICE BECOMES SQL NULL, AND A NULL INSERT DOES NOT USE THE '{}'
	// DEFAULT. The same trap Phase 6 hit on engine_runs: a report over zero BOM
	// documents would fail the NOT NULL rather than storing an empty array.
	docIDs := req.BOMDocumentIDs
	if docIDs == nil {
		docIDs = []string{}
	}

	var out Report
	err := s.pool.WithTenant(ctx, req.TenantID, func(ctx context.Context, tx db.Tx) error {
		return scanReport(tx.QueryRow(ctx, `
			INSERT INTO report.reports
				(tenant_id, scan_id, bom_document_ids, bom_type, level, standard,
				 format, visibility, status)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'queued')
			RETURNING `+returningColumns,
			req.TenantID, req.ScanID, docIDs, req.BOMType, req.Level,
			req.Standard, req.Format, req.Visibility), &out)
	})
	if err != nil {
		return Report{}, fmt.Errorf("create report: %w", err)
	}
	return out, nil
}

// returningColumns is reportColumns without the leading SELECT, for RETURNING.
const returningColumns = `
	id, tenant_id, scan_id, bom_document_ids, bom_type, level, standard,
	format, visibility, status,
	COALESCE(storage_ref,''), COALESCE(sha256,''), COALESCE(size_bytes,0),
	COALESCE(signature,''), COALESCE(signing_key_id,''),
	truncated, COALESCE(truncation_note,''), COALESCE(error_code,''),
	created_at, updated_at`

// Get reads one report.
func (s *Store) Get(ctx context.Context, tenantID, reportID string) (Report, error) {
	var r Report
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := scanReport(tx.QueryRow(ctx, reportColumns+`
			  FROM report.reports WHERE id = $1`, reportID), &r); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("get report: %w", err)
		}
		return nil
	})
	if err != nil {
		return Report{}, err
	}
	return r, nil
}

// List returns a tenant's reports, newest first.
//
// UUIDv7 ids are time-ordered, so `ORDER BY id DESC` is chronological AND a
// stable keyset cursor — unlike created_at, which ties.
func (s *Store) List(ctx context.Context, tenantID, scanID string, limit int, cursor string) ([]Report, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var out []Report
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		sql := reportColumns + ` FROM report.reports WHERE ($1 = '' OR scan_id = $1::uuid)`
		args := []any{scanID}
		if cursor != "" {
			sql += ` AND id < $2`
			args = append(args, cursor)
		}
		sql += fmt.Sprintf(` ORDER BY id DESC LIMIT %d`, limit)

		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return fmt.Errorf("list reports: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var r Report
			if err := scanReport(rows, &r); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ClaimForRender moves a queued report to `rendering`.
//
// ⚠ THE TRANSITION IS THE LOCK, AND IT IS CONDITIONAL FOR THAT REASON.
//
// `WHERE status = 'queued'` means two workers that receive the same job — which
// JetStream permits, since at-least-once delivery is the contract — cannot both
// claim it. The second sees zero rows affected and drops its copy. Reading the
// status and then updating it would let both pass, and rendering a 3000-page
// PDF twice is not a harmless duplicate: it is two writes racing for the same
// storage key.
func (s *Store) ClaimForRender(ctx context.Context, tenantID, reportID string) (Report, error) {
	var r Report
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		if err := scanReport(tx.QueryRow(ctx, `
			UPDATE report.reports
			   SET status = 'rendering'
			 WHERE id = $1 AND status = 'queued'
			RETURNING `+returningColumns, reportID), &r); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("claim report: %w", err)
		}
		return nil
	})
	if err != nil {
		return Report{}, err
	}
	return r, nil
}

// Completion is everything a finished render produced.
type Completion struct {
	StorageRef     string
	SHA256         string
	SizeBytes      int64
	Signature      string
	SigningKeyID   string
	Truncated      bool
	TruncationNote string
}

// MarkReady records a finished render.
func (s *Store) MarkReady(ctx context.Context, tenantID, reportID string, c Completion) error {
	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE report.reports
			   SET status = 'ready', storage_ref = $2, sha256 = $3, size_bytes = $4,
			       signature = $5, signing_key_id = $6,
			       truncated = $7, truncation_note = NULLIF($8, ''),
			       error_code = NULL
			 WHERE id = $1 AND status = 'rendering'`,
			reportID, c.StorageRef, c.SHA256, c.SizeBytes,
			c.Signature, c.SigningKeyID, c.Truncated, c.TruncationNote)
		if err != nil {
			return fmt.Errorf("mark ready: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// MarkFailed records a render that will not be retried.
//
// ⚠ THE CODE IS STORED, NOT A MESSAGE. `REPORT_TOO_LARGE_FOR_PDF` tells the UI
// to offer the XLSX; a free-text string tells it nothing it can act on, and
// ends up rendered at the customer verbatim.
func (s *Store) MarkFailed(ctx context.Context, tenantID, reportID, errorCode string) error {
	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE report.reports
			   SET status = 'failed', error_code = $2
			 WHERE id = $1 AND status IN ('queued','rendering')`,
			reportID, errorCode)
		if err != nil {
			return fmt.Errorf("mark failed: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}
