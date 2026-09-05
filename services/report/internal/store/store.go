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
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
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

	// ⚠ EVERYTHING BELOW IS NIL/EMPTY UNTIL THIS REPORT REACHES `ready`. It is
	// captured ONCE, by MarkReady, from the exact render.BOM that produced the
	// stored artifact — never re-queried from the normalizer afterward. See
	// migrations/report/0003.
	ProjectName string
	// BOMGeneratedAt is the BOM's own generated_at (RFC3339, the scan's time),
	// distinct from CreatedAt/UpdatedAt below, which describe the render
	// request rather than the data inside it.
	BOMGeneratedAt string
	// LevelNote states what a Top-Level/Complete projection left out. Empty
	// when the level had nothing to note.
	LevelNote string

	// CompletenessPct and DeclarationPct are nil until MarkReady runs. Nil is
	// not zero: a report still queued or rendering has not been scored, and
	// reporting 0.00% would read as "scored, and failed" (CLAUDE.md invariant 3).
	CompletenessPct *float64
	DeclarationPct  *float64
	CoverageFormula string
	CoverageFields  []CoverageField
	Engines         []EngineCoverage
	// EcosystemsWithNoEngine is the list CLAUDE.md invariant 12 exists for:
	// something was detected and nothing this product runs can scan it.
	EcosystemsWithNoEngine []string

	ErrorCode string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CoverageField is one profile field's coverage counts, captured at the
// moment a render completed.
//
// ⚠ NAME, WEIGHT AND SOURCE PAGE ARE PROFILE METADATA, NOT NORMALIZER OUTPUT.
// render.FieldCoverage (what the normalizer's breakdown carries) has only
// FieldID/Present/Declared/Total; the worker enriches it against
// render.FieldsFor(bomType) before it ever reaches this struct, so a client
// reading this response never has to look the profile up itself.
type CoverageField struct {
	FieldID    string `json:"field_id"`
	Name       string `json:"name"`
	Present    int    `json:"present"`
	Declared   int    `json:"declared"`
	Total      int    `json:"total"`
	Weight     int    `json:"weight"`
	SourcePage int    `json:"source_page"`
}

// EngineCoverage is one engine's terminal state, captured at render time.
// Field-for-field the same shape as render.EngineCoverage — this is the
// persisted, wire form of the identical fact.
type EngineCoverage struct {
	EngineID        string   `json:"engine_id"`
	Version         string   `json:"version"`
	Status          string   `json:"status"`
	DatabaseVersion string   `json:"database_version"`
	Ecosystems      []string `json:"ecosystems"`
	Diagnostic      string   `json:"diagnostic"`
}

const reportColumns = `
	SELECT id, tenant_id, scan_id, bom_document_ids, bom_type, level, standard,
	       format, visibility, status,
	       COALESCE(storage_ref,''), COALESCE(sha256,''), COALESCE(size_bytes,0),
	       COALESCE(signature,''), COALESCE(signing_key_id,''),
	       truncated, COALESCE(truncation_note,''),
	       COALESCE(project_name,''), bom_generated_at, COALESCE(level_note,''),
	       completeness_pct, declaration_pct, COALESCE(coverage_formula,''),
	       coverage_fields, engine_coverage, ecosystems_with_no_engine,
	       COALESCE(error_code,''),
	       created_at, updated_at`

func scanReport(row pgx.Row, r *Report) error {
	var (
		bomGeneratedAt    *time.Time
		coverageFieldsRaw []byte
		engineCoverageRaw []byte
	)

	if err := row.Scan(&r.ID, &r.TenantID, &r.ScanID, &r.BOMDocumentIDs, &r.BOMType,
		&r.Level, &r.Standard, &r.Format, &r.Visibility, &r.Status,
		&r.StorageRef, &r.SHA256, &r.SizeBytes,
		&r.Signature, &r.SigningKeyID,
		&r.Truncated, &r.TruncationNote,
		&r.ProjectName, &bomGeneratedAt, &r.LevelNote,
		&r.CompletenessPct, &r.DeclarationPct, &r.CoverageFormula,
		&coverageFieldsRaw, &engineCoverageRaw, &r.EcosystemsWithNoEngine,
		&r.ErrorCode,
		&r.CreatedAt, &r.UpdatedAt); err != nil {
		return err
	}

	if bomGeneratedAt != nil {
		r.BOMGeneratedAt = bomGeneratedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	// ⚠ MALFORMED JSON DOES NOT FAIL THE READ. These two columns are written
	// only by this package's own MarkReady, so malformed content would be our
	// own bug — but a report's core metadata (id, status, download) must stay
	// readable while that is investigated, the same tolerance
	// applyCoverageBreakdown already applies to the normalizer's breakdown.
	if len(coverageFieldsRaw) > 0 {
		_ = json.Unmarshal(coverageFieldsRaw, &r.CoverageFields) //nolint:errcheck // see above
	}
	if len(engineCoverageRaw) > 0 {
		_ = json.Unmarshal(engineCoverageRaw, &r.Engines) //nolint:errcheck // see above
	}
	return nil
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
	truncated, COALESCE(truncation_note,''),
	COALESCE(project_name,''), bom_generated_at, COALESCE(level_note,''),
	completeness_pct, declaration_pct, COALESCE(coverage_formula,''),
	coverage_fields, engine_coverage, ecosystems_with_no_engine,
	COALESCE(error_code,''),
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
// EffectiveLimit is the page size List will actually use.
//
// ⚠ EXPORTED BECAUSE THE HANDLER HAS TO KNOW IT, AND A SECOND COPY WOULD DRIFT.
// The handler decides whether to emit a next_cursor by comparing the row count
// against the limit that was used — so if it guessed 50 while this clamped to
// 200, pagination would stop after the first page of a large listing. One
// function, two callers.
func EffectiveLimit(requested int) int {
	if requested <= 0 || requested > 200 {
		return 50
	}
	return requested
}

func (s *Store) List(ctx context.Context, tenantID, scanID string, limit int, cursor string) ([]Report, error) {
	limit = EffectiveLimit(limit)

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

// ReportSibling is another rendered format of the same scan and BOM type.
type ReportSibling struct {
	ID     string
	Format string
	Status Status
}

// Siblings returns a report's other rendered formats.
//
// ⚠ A SAME-SCHEMA SELF-JOIN, AT READ TIME — NOT DATA SNAPSHOT AT RENDER
// COMPLETION. "What other formats exist for this scan and BOM type" is a live
// relationship: a sibling can still be queued or fail after this report goes
// ready, so freezing the list into Completion would go stale the moment a
// second format finished rendering.
func (s *Store) Siblings(ctx context.Context, tenantID, reportID, scanID, bomType string) ([]ReportSibling, error) {
	var out []ReportSibling
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, format, status
			  FROM report.reports
			 WHERE scan_id = $1 AND bom_type = $2 AND id <> $3
			 ORDER BY format`, scanID, bomType, reportID)
		if err != nil {
			return fmt.Errorf("list report siblings: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var sib ReportSibling
			if err := rows.Scan(&sib.ID, &sib.Format, &sib.Status); err != nil {
				return fmt.Errorf("scan report sibling: %w", err)
			}
			out = append(out, sib)
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
//
// ⚠ THE FIELDS BELOW StorageRef..TruncationNote ARE ARTIFACT METADATA; EVERY
// FIELD AFTER THAT IS CAPTURED FROM THE render.BOM THE WORKER ALREADY HOLDS,
// NOT RE-QUERIED. The worker's copy is what was actually rendered into the
// artifact this same call stores — re-reading the normalizer at this point
// could race a concurrent re-normalization and disagree with the bytes
// already in object storage.
type Completion struct {
	StorageRef     string
	SHA256         string
	SizeBytes      int64
	Signature      string
	SigningKeyID   string
	Truncated      bool
	TruncationNote string

	ProjectName    string
	BOMGeneratedAt string
	LevelNote      string
	// CompletenessPct and DeclarationPct are nil when render.BOM.CoverageComputed
	// was false — the underlying document was never scored. Storing nil here
	// keeps the row's columns NULL, which is what preserves "not yet computed"
	// for a document that genuinely has no numbers yet.
	CompletenessPct        *float64
	DeclarationPct         *float64
	CoverageFormula        string
	CoverageFields         []CoverageField
	Engines                []EngineCoverage
	EcosystemsWithNoEngine []string
}

// MarkReady records a finished render.
func (s *Store) MarkReady(ctx context.Context, tenantID, reportID string, c Completion) error {
	coverageFields, err := json.Marshal(c.CoverageFields)
	if err != nil {
		return fmt.Errorf("marshal coverage fields: %w", err)
	}
	engines, err := json.Marshal(c.Engines)
	if err != nil {
		return fmt.Errorf("marshal engine coverage: %w", err)
	}
	ecosystems := c.EcosystemsWithNoEngine
	if ecosystems == nil {
		ecosystems = []string{}
	}

	// ⚠ AN UNPARSEABLE VALUE STAYS NULL RATHER THAN FAILING THE RENDER. The
	// artifact is already stored and correct; a malformed timestamp here would
	// be this package's own bug, not a reason to withhold a report that
	// otherwise rendered successfully.
	var bomGeneratedAt *time.Time
	if c.BOMGeneratedAt != "" {
		if t, parseErr := time.Parse(time.RFC3339, c.BOMGeneratedAt); parseErr == nil {
			bomGeneratedAt = &t
		}
	}

	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE report.reports
			   SET status = 'ready', storage_ref = $2, sha256 = $3, size_bytes = $4,
			       signature = $5, signing_key_id = $6,
			       truncated = $7, truncation_note = NULLIF($8, ''),
			       project_name = NULLIF($9, ''), bom_generated_at = $10,
			       level_note = NULLIF($11, ''),
			       completeness_pct = $12, declaration_pct = $13,
			       coverage_formula = NULLIF($14, ''),
			       coverage_fields = $15, engine_coverage = $16,
			       ecosystems_with_no_engine = $17,
			       error_code = NULL
			 WHERE id = $1 AND status = 'rendering'`,
			reportID, c.StorageRef, c.SHA256, c.SizeBytes,
			c.Signature, c.SigningKeyID, c.Truncated, c.TruncationNote,
			c.ProjectName, bomGeneratedAt, c.LevelNote,
			c.CompletenessPct, c.DeclarationPct, c.CoverageFormula,
			coverageFields, engines, ecosystems)
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
