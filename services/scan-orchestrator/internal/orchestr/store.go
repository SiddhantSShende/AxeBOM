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

	"github.com/axebom/axebom/libs/go-shared/events"
	"github.com/axebom/axebom/libs/go-shared/platform/db"
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
// scanColumns is shared by GetScan and ListScans so the two can never drift
// out of column order with each other.
const scanColumns = `
	SELECT id, tenant_id, project_id, status, source_kind,
	       COALESCE(source_commit_sha,''), COALESCE(source_archive_ref,''),
	       COALESCE(source_archive_sha256,''),
	       triggered_by, COALESCE(trigger_ref::text,''),
	       bom_types, engines_requested,
	       created_at, started_at, finished_at`

// scanScanRow reads one scan.scans row. Named to avoid colliding with the Scan
// type; "scan a Scan" reads worse than it already does.
func scanScanRow(row pgx.Row) (Scan, error) {
	var sc Scan
	var status, kind string
	err := row.Scan(&sc.ID, &sc.TenantID, &sc.ProjectID, &status, &kind,
		&sc.CommitSHA, &sc.ArchiveRef, &sc.ArchiveSHA256,
		&sc.TriggeredBy, &sc.TriggerRef,
		&sc.Families, &sc.EnginesRequested,
		&sc.CreatedAt, &sc.StartedAt, &sc.FinishedAt)
	if err != nil {
		return Scan{}, err
	}
	sc.Status = events.ScanStatus(status)
	sc.SourceKind = events.SourceKind(kind)
	return sc, nil
}

func (s *Store) GetScan(ctx context.Context, tenantID, scanID string) (Scan, []EngineRun, error) {
	var sc Scan
	var runs []EngineRun

	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		var err error
		sc, err = scanScanRow(tx.QueryRow(ctx, scanColumns+` FROM scan.scans WHERE id = $1`, scanID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get scan: %w", err)
		}

		runs, err = loadRuns(ctx, tx, scanID)
		return err
	})
	if err != nil {
		return Scan{}, nil, err
	}
	return sc, runs, nil
}

// ListScans returns a tenant's scans, newest first.
//
// ⚠ ONE QUERY FOR EVERY PAGE'S ENGINE RUNS, NOT ONE PER SCAN.
//
// A page of 50 scans naively built by calling GetScan 50 times would be 50
// round trips just for the runs, on top of the list query itself. loadRunsFor
// takes every id from this page in one `WHERE scan_id = ANY($1)` query, the
// same discipline project.loadClassificationsFor uses for a project list.
//
// project_id and status are optional filters, following the same
// empty-argument-matches-everything idiom report.Store.List already uses for
// scan_id — a caller who omits a filter gets the whole tenant page, not zero
// rows.
func (s *Store) ListScans(
	ctx context.Context, tenantID string, limit int, cursor, projectID, status string,
) ([]Scan, map[string][]EngineRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var out []Scan
	runsByScan := map[string][]EngineRun{}

	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		sql := scanColumns + `
		  FROM scan.scans
		 WHERE ($1 = '' OR project_id = $1::uuid)
		   AND ($2 = '' OR status = $2)`
		args := []any{projectID, status}
		if cursor != "" {
			sql += fmt.Sprintf(` AND id < $%d`, len(args)+1)
			args = append(args, cursor)
		}
		sql += fmt.Sprintf(` ORDER BY id DESC LIMIT %d`, limit)

		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return fmt.Errorf("list scans: %w", err)
		}
		defer rows.Close()

		ids := make([]string, 0, limit)
		for rows.Next() {
			sc, err := scanScanRow(rows)
			if err != nil {
				return err
			}
			out = append(out, sc)
			ids = append(ids, sc.ID)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}

		runsByScan, err = loadRunsFor(ctx, tx, ids)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return out, runsByScan, nil
}

// engineRunColumns is shared by loadRuns and loadRunsFor.
const engineRunColumns = `
	SELECT id, scan_id, tenant_id, job_id, engine_id, attempt, status,
	       weight, ecosystems_covered,
	       COALESCE(engine_version,''), COALESCE(engine_db_version,''),
	       started_at, finished_at, deadline_at,
	       COALESCE(error_code,''), COALESCE(error_message,''),
	       COALESCE(diagnostics, '[]'::jsonb),
	       COALESCE(summary, '{}'::jsonb)
	  FROM scan.engine_runs`

func scanEngineRunRow(row pgx.Row) (EngineRun, error) {
	var r EngineRun
	var status string
	var diagnostics, summary []byte
	err := row.Scan(&r.ID, &r.ScanID, &r.TenantID, &r.JobID, &r.EngineID,
		&r.Attempt, &status, &r.Weight, &r.EcosystemsCovered,
		&r.EngineVersion, &r.EngineDBVersion,
		&r.StartedAt, &r.FinishedAt, &r.DeadlineAt,
		&r.ErrorCode, &r.ErrorMessage, &diagnostics, &summary)
	if err != nil {
		return EngineRun{}, err
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
	return r, nil
}

func loadRuns(ctx context.Context, tx db.Tx, scanID string) ([]EngineRun, error) {
	rows, err := tx.Query(ctx, engineRunColumns+`
		 WHERE scan_id = $1
		 ORDER BY engine_id, attempt`, scanID)
	if err != nil {
		return nil, fmt.Errorf("load engine runs: %w", err)
	}
	defer rows.Close()

	var out []EngineRun
	for rows.Next() {
		r, err := scanEngineRunRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// loadRunsFor batches every id in one page into a single query, keyed by scan
// id — the ANY($1) discipline project.loadClassificationsFor uses, so a page
// of 50 scans costs one query here instead of 50.
func loadRunsFor(ctx context.Context, tx db.Tx, scanIDs []string) (map[string][]EngineRun, error) {
	rows, err := tx.Query(ctx, engineRunColumns+`
		 WHERE scan_id = ANY($1)
		 ORDER BY scan_id, engine_id, attempt`, scanIDs)
	if err != nil {
		return nil, fmt.Errorf("load engine runs: %w", err)
	}
	defer rows.Close()

	out := make(map[string][]EngineRun, len(scanIDs))
	for rows.Next() {
		r, err := scanEngineRunRow(rows)
		if err != nil {
			return nil, err
		}
		out[r.ScanID] = append(out[r.ScanID], r)
	}
	return out, rows.Err()
}

// LatestEngineRunsForProject returns this project's most recent run of each
// engine it has ever invoked, keyed by engine id.
//
// ⚠ ACROSS EVERY SCAN, NOT THE LATEST SCAN. A project scanned for SBOM
// yesterday and CBOM today has two current answers, one per engine — reading
// only the latest scan's rows would make yesterday's SBOM engines vanish from
// the Engine Coverage panel the moment an unrelated CBOM scan runs.
// `scan.engine_runs` has no family column (see the comment in
// orchestrator.go), so this is join-and-pick-one-per-engine, not
// join-and-pick-one-per-family.
//
// `scan.engine_runs` and `scan.scans` are both in the `scan` schema — this is
// not the cross-schema join CLAUDE.md invariant #11 forbids.
func (s *Store) LatestEngineRunsForProject(ctx context.Context, tenantID, projectID string) (map[string]EngineRun, error) {
	out := map[string]EngineRun{}
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT DISTINCT ON (er.engine_id)
			       er.id, er.scan_id, er.tenant_id, er.job_id, er.engine_id, er.attempt, er.status,
			       er.weight, er.ecosystems_covered,
			       COALESCE(er.engine_version,''), COALESCE(er.engine_db_version,''),
			       er.started_at, er.finished_at, er.deadline_at,
			       COALESCE(er.error_code,''), COALESCE(er.error_message,''),
			       COALESCE(er.diagnostics, '[]'::jsonb),
			       COALESCE(er.summary, '{}'::jsonb)
			  FROM scan.engine_runs er
			  JOIN scan.scans sc ON sc.id = er.scan_id
			 WHERE sc.project_id = $1
			 ORDER BY er.engine_id, sc.created_at DESC, er.attempt DESC`, projectID)
		if err != nil {
			return fmt.Errorf("load latest engine runs: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			r, err := scanEngineRunRow(rows)
			if err != nil {
				return err
			}
			out[r.EngineID] = r
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
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

// UpsertEngineRun records a result for one engine, returning the row's id.
//
// ⚠ IDEMPOTENT ON job_id, which is what makes redelivery safe.
//
// `ON CONFLICT (job_id)` means the same result arriving twice — from a
// redelivery, a duplicate publish, or a worker that acked late — converges to
// the same row rather than creating a second one or failing.
func (s *Store) UpsertEngineRun(ctx context.Context, r EngineRun) (string, error) {
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

	var id string
	err = s.pool.WithTenant(ctx, r.TenantID, func(ctx context.Context, tx db.Tx) error {
		row := tx.QueryRow(ctx, `
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
				summary            = EXCLUDED.summary
			RETURNING id`,
			r.ScanID, r.TenantID, r.JobID, r.EngineID, r.Attempt,
			string(r.Status), r.Weight, ecosystems,
			nullIfEmpty(r.EngineVersion), nullIfEmpty(r.EngineDBVersion),
			r.StartedAt, r.FinishedAt,
			nullIfEmpty(r.ErrorCode), nullIfEmpty(r.ErrorMessage), diagnostics,
			argv, r.ExitCode, r.DurationMS, summary)
		if err := row.Scan(&id); err != nil {
			return fmt.Errorf("upsert engine run: %w", err)
		}
		return nil
	})
	return id, err
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

// CoverageGaps returns ecosystems with NO available engine.
//
// ⚠ AN ECOSYSTEM CAN HAVE BOTH A false ROW AND A true ROW FOR THE SAME SCAN.
// RecordEcosystem's conflict key is (scan_id, ecosystem, detected_by), one
// row per REPORTING ENGINE — so on a git-source scan, trivy-image (skipped
// for source kind, registered for npm/pypi/deb/rpm/apk/golang) writes
// engine_available=false for npm in the very same scan where syft and
// trivy-fs each wrote engine_available=true for npm after actually
// succeeding. A plain `WHERE engine_available = false` returns npm as a gap
// regardless — reporting a fully-scanned ecosystem as unseen, the exact
// inverse of what this table exists to prevent. The gap is real only when
// EVERY row recorded for that ecosystem in this scan is false.
func (s *Store) CoverageGaps(ctx context.Context, tenantID, scanID string) ([]string, error) {
	var out []string
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT DISTINCT ecosystem FROM scan.ecosystems_detected e1
			 WHERE scan_id = $1 AND engine_available = false
			   AND NOT EXISTS (
			       SELECT 1 FROM scan.ecosystems_detected e2
			        WHERE e2.scan_id = e1.scan_id
			          AND e2.ecosystem = e1.ecosystem
			          AND e2.engine_available = true
			   )
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

// ---------------------------------------------------------------------------
// Raw artifacts
// ---------------------------------------------------------------------------

// RecordRawArtifacts persists one engine result's raw artifacts.
//
// ⚠ THE WRITE PATH FOR A DISPATCHED ENGINE. scan.raw_artifacts is IMMUTABLE
// BY GRANT — UPDATE and DELETE are revoked from axebom_app in
// migrations/scan/0001_init.sql — so this is an append, never a repoint.
// Called once per engine result from HandleResult; a redelivered result
// calls it again, which is harmless duplication of evidence rather than a
// correctness problem (there is no unique constraint to violate, and
// re-recording the same artifact rows a second time changes nothing a
// reader depends on). See RecordProducerArtifacts for the sibling path used
// by fetch and webrecon results, which have no engine_runs row at all.
func (s *Store) RecordRawArtifacts(
	ctx context.Context, tenantID, scanID, engineRunID string, artifacts []events.Artifact,
) error {
	if len(artifacts) == 0 {
		return nil
	}
	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		for _, a := range artifacts {
			if _, err := tx.Exec(ctx, `
				INSERT INTO scan.raw_artifacts
					(tenant_id, scan_id, engine_run_id, role, storage_ref, media_type, sha256, size_bytes)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
				tenantID, scanID, nullIfEmpty(engineRunID), a.Role, a.URI,
				nullIfEmpty(a.MediaType), a.SHA256, a.SizeBytes,
			); err != nil {
				return fmt.Errorf("record raw artifact (role=%s): %w", a.Role, err)
			}
		}
		return nil
	})
}

// RecordProducerArtifacts persists artifacts from a component that is NOT a
// dispatched engine — today, the fetcher's own result (a source archive,
// plus an optional native_output) and services/webrecon's result (a
// native_output discovery + fingerprint document).
//
// ⚠ WHY THIS EXISTS SEPARATELY FROM RecordRawArtifacts. Neither the fetcher
// nor webrecon ever gets a scan.engine_runs row — CreateScan only creates
// one per resolution.Engines entry, and neither is a policy.Engine — so
// there is no engine_run_id to hang their artifacts off. This was a real,
// previously-unnoticed gap: handleFetchResult never called
// RecordRawArtifacts at all, and even if it had, that method's
// engine_run_id-keyed INSERT plus LoadRawArtifactsForEngines's INNER JOIN to
// engine_runs could never have resolved a NULL engine_run_id back to
// "fetcher" — meaning github-dependency-graph-sbom's NativeSBOMRef (Milestone
// 3) has never actually been wired end to end in a real deployment, despite
// passing every unit test (those exercise the adapter and the client in
// isolation, never this path). Found and fixed while building the identical
// mechanism for webrecon (Milestone 5); see migrations/scan/0009.
func (s *Store) RecordProducerArtifacts(
	ctx context.Context, tenantID, scanID, producer string, artifacts []events.Artifact,
) error {
	if len(artifacts) == 0 {
		return nil
	}
	return s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		for _, a := range artifacts {
			if _, err := tx.Exec(ctx, `
				INSERT INTO scan.raw_artifacts
					(tenant_id, scan_id, producer, role, storage_ref, media_type, sha256, size_bytes)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
				tenantID, scanID, producer, a.Role, a.URI,
				nullIfEmpty(a.MediaType), a.SHA256, a.SizeBytes,
			); err != nil {
				return fmt.Errorf("record producer artifact (producer=%s, role=%s): %w", producer, a.Role, err)
			}
		}
		return nil
	})
}

// LoadRawArtifactsForEngines returns a scan's raw artifacts, keyed by engine
// or producer id, restricted to the given ids.
//
// ⚠ SAME SCHEMA, NOT A CROSS-SCHEMA JOIN — scan.raw_artifacts and
// scan.engine_runs are both in the scan schema (CLAUDE.md invariant 11 only
// forbids crossing a SCHEMA boundary in SQL).
//
// ⚠ TWO SOURCES, UNIONED. A dispatched engine's artifacts are keyed by
// engine_runs.engine_id via the join, same as always. A producer's (fetcher,
// webrecon) are keyed by their own literal `producer` column instead — they
// have no engine_runs row to join to. Callers pass both engine ids and
// producer ids in the same slice; the caller does not need to know which is
// which, matching how policy.Engine.ConsumesNativeSBOM only cares whether
// SOMETHING was staged, not by which kind of component.
//
// Used to assemble a NormalizeTriggerV1's envelope (so the normalize
// consumer never needs to query scan.* itself — docs/02-CONTRACTS.md §6a)
// and by FanOut's nativeSBOMRefFor.
func (s *Store) LoadRawArtifactsForEngines(
	ctx context.Context, tenantID, scanID string, engineIDs []string,
) (map[string][]events.Artifact, error) {
	out := map[string][]events.Artifact{}
	if len(engineIDs) == 0 {
		return out, nil
	}
	err := s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT resolved_id, role, storage_ref, media_type, sha256, size_bytes FROM (
				SELECT er.engine_id AS resolved_id, ra.role, ra.storage_ref,
				       COALESCE(ra.media_type,'') AS media_type, ra.sha256, ra.size_bytes,
				       ra.created_at
				  FROM scan.raw_artifacts ra
				  JOIN scan.engine_runs er ON er.id = ra.engine_run_id
				 WHERE ra.scan_id = $1 AND er.engine_id = ANY($2)
				UNION ALL
				SELECT ra.producer AS resolved_id, ra.role, ra.storage_ref,
				       COALESCE(ra.media_type,'') AS media_type, ra.sha256, ra.size_bytes,
				       ra.created_at
				  FROM scan.raw_artifacts ra
				 WHERE ra.scan_id = $1 AND ra.producer = ANY($2)
			) x
			 ORDER BY resolved_id, created_at`, scanID, engineIDs)
		if err != nil {
			return fmt.Errorf("load raw artifacts: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var engineID string
			var a events.Artifact
			if err := rows.Scan(&engineID, &a.Role, &a.URI, &a.MediaType, &a.SHA256, &a.SizeBytes); err != nil {
				return err
			}
			out[engineID] = append(out[engineID], a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Normalize trigger
// ---------------------------------------------------------------------------

// MarkNormalizeTriggered records that this (scan, family) pair's normalize
// trigger has fired, and reports whether THIS CALL is the one that fired it.
//
// ⚠ WRITE-ONCE, mirroring SetSourceOnce's idiom: `ON CONFLICT DO NOTHING`
// rather than a status column, so a redelivered ScanResultV1 that reaches
// this after normalization has already been triggered writes nothing and
// gets fired=false back — the caller treats that as "already handled", not
// a conflict.
func (s *Store) MarkNormalizeTriggered(
	ctx context.Context, tenantID, scanID string, family events.Family, triggerID string,
) (persistedID string, fired bool, err error) {
	err = s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		insertErr := tx.QueryRow(ctx, `
			INSERT INTO scan.normalize_triggers (scan_id, tenant_id, family, trigger_id)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (scan_id, family) DO NOTHING
			RETURNING trigger_id`,
			scanID, tenantID, string(family), triggerID).Scan(&persistedID)
		if errors.Is(insertErr, pgx.ErrNoRows) {
			// Already triggered by a prior call — read back the existing id so
			// the caller still has a stable identity, even though it did not
			// fire this time. It may differ from the triggerID this call
			// offered: whichever call won the race published under its OWN
			// id first, and that is the id this scan/family is permanently
			// associated with — see maybeTriggerNormalize's doc comment.
			return tx.QueryRow(ctx, `
				SELECT trigger_id FROM scan.normalize_triggers
				 WHERE scan_id = $1 AND family = $2`,
				scanID, string(family)).Scan(&persistedID)
		}
		if insertErr != nil {
			return fmt.Errorf("mark normalize triggered: %w", insertErr)
		}
		fired = true
		return nil
	})
	return persistedID, fired, err
}

// NormalizeTriggerID reports whether (scan, family) has already fired a
// normalize trigger, without claiming it.
//
// ⚠ READ-ONLY, UNLIKE MarkNormalizeTriggered. That method's whole point is
// to atomically claim the write-once slot — calling it as a "just checking"
// probe has the side effect of claiming it on the first call, which makes
// it unsuitable for anything that wants to observe state without changing
// it (an operator checking why a scan never normalized; a test asserting
// nothing fired yet). Returns "" with no error when no trigger exists.
func (s *Store) NormalizeTriggerID(
	ctx context.Context, tenantID, scanID string, family events.Family,
) (triggerID string, err error) {
	err = s.pool.WithTenant(ctx, tenantID, func(ctx context.Context, tx db.Tx) error {
		scanErr := tx.QueryRow(ctx, `
			SELECT trigger_id FROM scan.normalize_triggers
			 WHERE scan_id = $1 AND family = $2`,
			scanID, string(family)).Scan(&triggerID)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil
		}
		return scanErr
	})
	return triggerID, err
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
