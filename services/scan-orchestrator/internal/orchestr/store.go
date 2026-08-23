// Package orchestr owns the scan lifecycle: fan-out, status aggregation, and
// the deadline reaper.
//
// ⚠ THE DATABASE IS THE SOURCE OF TRUTH. Events are advisory.
//
// Every function here is written so that losing a message costs latency, never
// correctness: a job that vanishes is redelivered or reaped, and a lost event
// is recovered by reading state. Nothing derives from having seen a stream.
package orchestr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/encorebom/encorebom/libs/go-shared/events"
	"github.com/encorebom/encorebom/libs/go-shared/platform/db"
)

// ErrNotFound is returned when a scan does not exist FOR THIS TENANT.
//
// Absent and belonging-to-another-tenant are deliberately indistinguishable,
// because RLS makes them the same query result. Both become 404.
var ErrNotFound = errors.New("not found")

// Store is the scan service's persistence layer.
type Store struct{ pool *db.Pool }

func NewStore(pool *db.Pool) *Store { return &Store{pool: pool} }

// Scan mirrors scan.scans.
type Scan struct {
	ID        string
	TenantID  string
	ProjectID string

	Status     events.ScanStatus
	SourceKind events.SourceKind

	// CommitSHA is written EXACTLY ONCE by the fetcher and immutable
	// thereafter — see SetSourceOnce, which enforces it in SQL.
	CommitSHA     string
	ArchiveRef    string
	ArchiveSHA256 string

	// TriggeredBy is user | campaign | api | webhook; TriggerRef is the user or
	// campaign id. Together they answer "who asked for this scan", which every
	// generated report names.
	TriggeredBy string
	TriggerRef  string

	// Families are the requested BOM types (column bom_types).
	Families []string
	// EnginesRequested is what resolution produced at create time. Stored so a
	// report can say what was ASKED for, not only what ran — an engine that
	// went unavailable must still appear in Engine Coverage.
	EnginesRequested []string

	CreatedAt  time.Time
	StartedAt  *time.Time
	FinishedAt *time.Time
}

// EngineRun mirrors scan.engine_runs — one row per (scan, engine).
type EngineRun struct {
	ID       string
	ScanID   string
	TenantID string
	JobID    string
	EngineID string
	Family   string

	Attempt int
	Status  events.EngineStatus
	Weight  int

	EcosystemsCovered []string
	EngineVersion     string
	EngineDBVersion   string

	StartedAt  *time.Time
	FinishedAt *time.Time
	DeadlineAt *time.Time

	ErrorCode    string
	ErrorMessage string
	Diagnostics  []events.Diagnostic

	// Provenance. argv is stored REDACTED — it reaches the provenance manifest
	// and every report, and argv is world-readable in /proc besides.
	ArgvRedacted []string
	ExitCode     *int
	DurationMS   *int
	Summary      events.Summary
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

// CreateScan inserts a scan and its engine runs in one transaction.
//
// One transaction because a scan without its engine rows is a scan the reaper
// cannot time out and the aggregator cannot score — it would sit in `queued`
// forever with nothing to explain why.
func (s *Store) CreateScan(ctx context.Context, sc Scan, runs []EngineRun) (Scan, error) {
	var out Scan
	err := s.pool.WithTenant(ctx, sc.TenantID, func(ctx context.Context, tx db.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO scan.scans
				(tenant_id, project_id, status, source_kind,
				 triggered_by, trigger_ref, bom_types, engines_requested)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			RETURNING id, created_at`,
			sc.TenantID, sc.ProjectID, string(events.ScanQueued),
			string(sc.SourceKind), sc.TriggeredBy, nullIfEmpty(sc.TriggerRef),
			sc.Families, sc.EnginesRequested,
		).Scan(&out.ID, &out.CreatedAt)
		if err != nil {
			return fmt.Errorf("insert scan: %w", err)
		}

		for _, r := range runs {
			if _, err := tx.Exec(ctx, `
				INSERT INTO scan.engine_runs
					(scan_id, tenant_id, job_id, engine_id, attempt,
					 status, weight, deadline_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
				out.ID, sc.TenantID, r.JobID, r.EngineID,
				r.Attempt, statusQueued, r.Weight, r.DeadlineAt,
			); err != nil {
				return fmt.Errorf("insert engine run %s: %w", r.EngineID, err)
			}
		}
		return nil
	})
	if err != nil {
		return Scan{}, err
	}

	out.TenantID = sc.TenantID
	out.ProjectID = sc.ProjectID
	out.Status = events.ScanQueued
	out.SourceKind = sc.SourceKind
	out.Families = sc.Families
	out.TriggeredBy = sc.TriggeredBy
	out.TriggerRef = sc.TriggerRef
	out.EnginesRequested = sc.EnginesRequested
	return out, nil
}

// statusQueued is the initial engine-run status.
//
// Not in events.EngineStatus because it is not a RESULT: an engine never
// reports "queued", the orchestrator writes it. Keeping it out of the result
// enum means a worker cannot publish it by mistake.
const statusQueued = "queued"

// GetScan reads one scan with its engine runs.
func (s *Store) GetScan(ctx context.Context, tenantID, scanID string) (Scan, []EngineRun, error) {
	var sc Scan
	var runs []EngineRun

	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		var status, kind string
		err := tx.QueryRow(ctx, `
			SELECT id, tenant_id, project_id, status, source_kind,
			       COALESCE(source_commit_sha,''), COALESCE(source_archive_ref,''),
			       COALESCE(source_archive_sha256,''),
			       triggered_by, COALESCE(trigger_ref::text,''),
			       bom_types, engines_requested,
			       created_at, started_at, finished_at
			  FROM scan.scans WHERE id = $1`, scanID).
			Scan(&sc.ID, &sc.TenantID, &sc.ProjectID, &status, &kind,
				&sc.CommitSHA, &sc.ArchiveRef, &sc.ArchiveSHA256,
				&sc.TriggeredBy, &sc.TriggerRef,
				&sc.Families, &sc.EnginesRequested,
				&sc.CreatedAt, &sc.StartedAt, &sc.FinishedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get scan: %w", err)
		}
		sc.Status = events.ScanStatus(status)
		sc.SourceKind = events.SourceKind(kind)

		runs, err = loadRuns(ctx, tx, scanID)
		return err
	})
	if err != nil {
		return Scan{}, nil, err
	}
	return sc, runs, nil
}

func loadRuns(ctx context.Context, tx db.Tx, scanID string) ([]EngineRun, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, scan_id, tenant_id, job_id, engine_id, attempt, status,
		       weight, ecosystems_covered,
		       COALESCE(engine_version,''), COALESCE(engine_db_version,''),
		       started_at, finished_at, deadline_at,
		       COALESCE(error_code,''), COALESCE(error_message,''),
		       COALESCE(diagnostics, '[]'::jsonb),
		       COALESCE(summary, '{}'::jsonb)
		  FROM scan.engine_runs
		 WHERE scan_id = $1
		 ORDER BY engine_id, attempt`, scanID)
	if err != nil {
		return nil, fmt.Errorf("load engine runs: %w", err)
	}
	defer rows.Close()

	var out []EngineRun
	for rows.Next() {
		var r EngineRun
		var status string
		var diagnostics, summary []byte
		if err := rows.Scan(&r.ID, &r.ScanID, &r.TenantID, &r.JobID, &r.EngineID,
			&r.Attempt, &status, &r.Weight, &r.EcosystemsCovered,
			&r.EngineVersion, &r.EngineDBVersion,
			&r.StartedAt, &r.FinishedAt, &r.DeadlineAt,
			&r.ErrorCode, &r.ErrorMessage, &diagnostics, &summary); err != nil {
			return nil, err
		}
		r.Status = events.EngineStatus(status)
		if len(diagnostics) > 0 {
			_ = json.Unmarshal(diagnostics, &r.Diagnostics)
		}
		// The column was written from the first engine result and read by
		// nothing, so the counts existed only in the database. A null
		// dimension unmarshals to a nil pointer, which is the point: it means
		// the engine does not measure it, not that it measured zero.
		if len(summary) > 0 {
			_ = json.Unmarshal(summary, &r.Summary)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetSourceOnce records the fetch result.
//
// ⚠ commit_sha IS WRITTEN EXACTLY ONCE AND IS IMMUTABLE (ADR-0008).
//
// The `WHERE source_commit_sha IS NULL` clause is what enforces it, in SQL
// rather than in a comment. A redelivered fetch result — which WILL happen,
// because ack_wait is 30 minutes — updates nothing and reports that it wrote
// no rows, and the caller treats that as success rather than as a conflict.
//
// Without this, a second fetch could repoint a scan at a different commit while
// engines were already running against the first, producing a report with
// components from one commit and vulnerabilities from another.
func (s *Store) SetSourceOnce(ctx context.Context, tenantID, scanID, commitSHA, archiveRef, archiveSHA string) (bool, error) {
	var wrote bool
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE scan.scans
			   SET source_commit_sha = $2,
			       source_archive_ref = $3,
			       source_archive_sha256 = $4,
			       status = 'running',
			       started_at = COALESCE(started_at, now())
			 WHERE id = $1 AND source_commit_sha IS NULL`,
			scanID, commitSHA, archiveRef, archiveSHA)
		if err != nil {
			return fmt.Errorf("set source: %w", err)
		}
		wrote = tag.RowsAffected() > 0
		return nil
	})
	return wrote, err
}

// UpdateScanStatus writes a derived status.
//
// Callers must have computed it with events.DeriveScanStatus. There is no
// "set this scan to completed" path that skips the derivation, because a
// hand-set status is how a scan with a failed engine reports success.
func (s *Store) UpdateScanStatus(ctx context.Context, tenantID, scanID string, status events.ScanStatus) error {
	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		terminal := status == events.ScanCompleted ||
			status == events.ScanCompletedWithErrors ||
			status == events.ScanFailed ||
			status == events.ScanCancelled

		_, err := tx.Exec(ctx, `
			UPDATE scan.scans
			   SET status = $2,
			       finished_at = CASE WHEN $3 THEN COALESCE(finished_at, now()) ELSE finished_at END
			 WHERE id = $1`, scanID, string(status), terminal)
		return err
	})
}

// ---------------------------------------------------------------------------
// Engine runs
// ---------------------------------------------------------------------------

// UpsertEngineRun records a result for one engine.
//
// ⚠ IDEMPOTENT ON job_id, which is what makes redelivery safe.
//
// `ON CONFLICT (job_id)` means the same result arriving twice — from a
// redelivery, a duplicate publish, or a worker that acked late — converges to
// the same row rather than creating a second one or failing.
func (s *Store) UpsertEngineRun(ctx context.Context, r EngineRun) error {
	diagnostics, err := json.Marshal(r.Diagnostics)
	if err != nil {
		diagnostics = []byte("[]")
	}
	summary, err := json.Marshal(r.Summary)
	if err != nil {
		summary = []byte("{}")
	}

	// A nil Go slice becomes SQL NULL, and these columns are NOT NULL with a
	// '{}' default — which a nil INSERT does not use. An engine that covered
	// nothing must store an empty array, not fail the write.
	ecosystems := r.EcosystemsCovered
	if ecosystems == nil {
		ecosystems = []string{}
	}
	argv := r.ArgvRedacted
	if argv == nil {
		argv = []string{}
	}

	return s.pool.WithTenant(ctx, r.TenantID, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO scan.engine_runs
				(scan_id, tenant_id, job_id, engine_id, attempt, status,
				 weight, ecosystems_covered, engine_version, engine_db_version,
				 started_at, finished_at, error_code, error_message, diagnostics,
				 argv_redacted, exit_code, duration_ms, summary)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
			ON CONFLICT (job_id) DO UPDATE SET
				status             = EXCLUDED.status,
				ecosystems_covered = EXCLUDED.ecosystems_covered,
				engine_version     = EXCLUDED.engine_version,
				engine_db_version  = EXCLUDED.engine_db_version,
				started_at         = COALESCE(scan.engine_runs.started_at, EXCLUDED.started_at),
				finished_at        = EXCLUDED.finished_at,
				error_code         = EXCLUDED.error_code,
				error_message      = EXCLUDED.error_message,
				diagnostics        = EXCLUDED.diagnostics,
				argv_redacted      = EXCLUDED.argv_redacted,
				exit_code          = EXCLUDED.exit_code,
				duration_ms        = EXCLUDED.duration_ms,
				summary            = EXCLUDED.summary`,
			r.ScanID, r.TenantID, r.JobID, r.EngineID, r.Attempt,
			string(r.Status), r.Weight, ecosystems,
			nullIfEmpty(r.EngineVersion), nullIfEmpty(r.EngineDBVersion),
			r.StartedAt, r.FinishedAt,
			nullIfEmpty(r.ErrorCode), nullIfEmpty(r.ErrorMessage), diagnostics,
			argv, r.ExitCode, r.DurationMS, summary)
		if err != nil {
			return fmt.Errorf("upsert engine run: %w", err)
		}
		return nil
	})
}

// MarkRunRunning records that a worker picked a job up.
func (s *Store) MarkRunRunning(ctx context.Context, tenantID, jobID string) error {
	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE scan.engine_runs
			   SET status = 'running', started_at = COALESCE(started_at, now())
			 WHERE job_id = $1 AND status = 'queued'`, jobID)
		return err
	})
}

// TerminalStatuses returns the status of every engine run for a scan.
//
// ⚠ TAKES THE HIGHEST ATTEMPT WITH status != 'failed' (docs/02-CONTRACTS.md §4).
//
// A retry that succeeds must not be outvoted by the attempt that failed before
// it. Ordering by attempt DESC and preferring a non-failed row expresses that:
// the scan's status reflects the best outcome each engine reached, not its
// worst.
func (s *Store) TerminalStatuses(ctx context.Context, tenantID, scanID string) ([]events.EngineStatus, error) {
	var out []events.EngineStatus
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT DISTINCT ON (engine_id) status
			  FROM scan.engine_runs
			 WHERE scan_id = $1
			 ORDER BY engine_id,
			          (status = 'failed') ASC,   -- prefer a non-failed attempt
			          attempt DESC`, scanID)
		if err != nil {
			return fmt.Errorf("terminal statuses: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var st string
			if err := rows.Scan(&st); err != nil {
				return err
			}
			out = append(out, events.EngineStatus(st))
		}
		return rows.Err()
	})
	return out, err
}

// AllRunsTerminal reports whether every engine run has finished.
//
// The scan status is only recomputed as final when this is true; before that a
// scan is `running` however many engines have reported.
func (s *Store) AllRunsTerminal(ctx context.Context, tenantID, scanID string) (bool, error) {
	var pending int
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT count(*) FROM scan.engine_runs
			 WHERE scan_id = $1 AND status IN ('queued','running')`, scanID).Scan(&pending)
	})
	return pending == 0, err
}

// ---------------------------------------------------------------------------
// Ecosystems detected — the honest denominator
// ---------------------------------------------------------------------------

// RecordEcosystem notes an ecosystem found in the source.
//
// ⚠ engineAvailable=false ROWS ARE THE POINT OF THIS TABLE.
//
// An ecosystem detected with no engine that can scan it is the single most
// important thing a BOM can disclose. Omitting it converts an unknown into a
// false negative the customer trusts — which is the failure mode this entire
// product exists to avoid. It feeds the mandatory Engine Coverage section.
func (s *Store) RecordEcosystem(ctx context.Context, tenantID, scanID, ecosystem,
	detectedBy string, engineAvailable bool,
) error {
	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO scan.ecosystems_detected
				(scan_id, tenant_id, ecosystem, detected_by, engine_available)
			VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (scan_id, ecosystem, detected_by) DO UPDATE
				SET engine_available = EXCLUDED.engine_available`,
			scanID, tenantID, ecosystem, detectedBy, engineAvailable)
		return err
	})
}

// CoverageGaps returns ecosystems detected with no available engine.
func (s *Store) CoverageGaps(ctx context.Context, tenantID, scanID string) ([]string, error) {
	var out []string
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT DISTINCT ecosystem FROM scan.ecosystems_detected
			 WHERE scan_id = $1 AND engine_available = false
			 ORDER BY ecosystem`, scanID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e string
			if err := rows.Scan(&e); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
