-- +goose Up
-- ===========================================================================
-- scan — scan lifecycle, per-engine runs, immutable raw artifacts.
-- Implements docs/01-DATA-MODEL.md §3.
-- ===========================================================================

CREATE TABLE scan.scans (
    id                   uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id            uuid NOT NULL,
    project_id           uuid NOT NULL,   -- -> project.projects.id, no FK

    triggered_by         text NOT NULL
                         CHECK (triggered_by IN ('user', 'campaign', 'api', 'webhook')),
    trigger_ref          uuid,

    -- Derived MECHANICALLY from engine_runs, never hand-set:
    --   all succeeded                    -> completed
    --   >=1 succeeded and >=1 not        -> completed_with_errors
    --   zero succeeded                   -> failed
    status               text NOT NULL DEFAULT 'queued'
                         CHECK (status IN ('queued', 'fetching', 'running',
                                           'normalizing', 'completed',
                                           'completed_with_errors', 'failed',
                                           'cancelled')),

    bom_types            text[] NOT NULL DEFAULT '{}',
    report_levels        text[] NOT NULL DEFAULT '{}',
    standards            text[] NOT NULL DEFAULT '{}',
    formats              text[] NOT NULL DEFAULT '{}',
    engines_requested    text[] NOT NULL DEFAULT '{}',

    -- WRITTEN EXACTLY ONCE, by the fetcher, before any engine job is
    -- dispatched (ADR-0008). Six engines cloning independently could land on
    -- six different commits and produce a report describing a codebase that
    -- never existed.
    source_commit_sha    text,
    source_archive_ref   text,
    source_archive_sha256 text,

    -- Resolved tool ids/versions/digests, SPDX license-list version, alias
    -- snapshot id, ruleset version. This is what makes a report defensible
    -- six months later.
    provenance_manifest  jsonb,

    started_at           timestamptz,
    finished_at          timestamptz,
    error_code           text,
    error_message        text,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX scans_tenant_project_idx ON scan.scans (tenant_id, project_id, created_at DESC);
CREATE INDEX scans_status_idx         ON scan.scans (status)
    WHERE status IN ('queued', 'fetching', 'running', 'normalizing');

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON scan.scans
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

SELECT app.enable_tenant_rls('scan.scans');

-- ---------------------------------------------------------------------------
-- engine_runs — ONE ROW PER (scan, engine). This is where partial failure
-- lives, and the reason for one-engine-per-job (ADR-0004).
-- ---------------------------------------------------------------------------
CREATE TABLE scan.engine_runs (
    id                  uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id           uuid NOT NULL,
    scan_id             uuid NOT NULL REFERENCES scan.scans (id) ON DELETE CASCADE,

    -- Idempotency key AND artifact path segment. A retry writes to a new
    -- prefix, so it can never overwrite a prior attempt's artifacts.
    job_id              uuid NOT NULL UNIQUE,

    -- The unit is (tool, mode): trivy-fs and trivy-image are DIFFERENT
    -- engines with different capabilities and different parsers.
    engine_id           text NOT NULL,
    engine_version      text,
    -- REQUIRED for vulnerability engines. Without it a finding cannot be
    -- dated, and a report that cannot say "matched against vulnerability data
    -- as of X" is not defensible.
    engine_db_version   text,

    attempt             int NOT NULL DEFAULT 1 CHECK (attempt >= 1),

    -- `partial` is a FIRST-CLASS STATUS, not an error: 11 of 12 ecosystems
    -- covered is useful output plus a known gap, and both must reach the report.
    status              text NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued', 'running', 'succeeded',
                                          'partial', 'failed', 'timeout',
                                          'unavailable', 'skipped')),

    weight              int NOT NULL DEFAULT 1 CHECK (weight >= 0),
    ecosystems_covered  text[] NOT NULL DEFAULT '{}',

    -- Reproducibility. Secrets stripped: argv is world-readable in /proc.
    argv_redacted       text[] NOT NULL DEFAULT '{}',
    image_digest        text,
    exit_code           int,
    duration_ms         int,

    summary             jsonb NOT NULL DEFAULT '{}'::jsonb,
    diagnostics         jsonb NOT NULL DEFAULT '[]'::jsonb,

    started_at          timestamptz,
    finished_at         timestamptz,
    deadline_at         timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),

    -- The normalizer upserts on (scan_id, engine_id), taking the highest
    -- attempt with status != failed.
    UNIQUE (scan_id, engine_id, attempt)
);

CREATE INDEX engine_runs_scan_idx     ON scan.engine_runs (scan_id, engine_id);
CREATE INDEX engine_runs_tenant_idx   ON scan.engine_runs (tenant_id);
-- Feeds the deadline reaper, which is leader-elected via a Postgres advisory
-- lock. No etcd, no Consul.
CREATE INDEX engine_runs_deadline_idx ON scan.engine_runs (deadline_at)
    WHERE status IN ('queued', 'running');

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON scan.engine_runs
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

SELECT app.enable_tenant_rls('scan.engine_runs');

-- ---------------------------------------------------------------------------
-- raw_artifacts — IMMUTABLE. Never updated, never deleted.
--
-- This is what makes normalization replayable (ADR-0003): a dedup bug is fixed
-- by re-normalizing these, not by re-running scanners. Retention is a
-- compliance decision, not a storage one.
-- ---------------------------------------------------------------------------
CREATE TABLE scan.raw_artifacts (
    id             uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id      uuid NOT NULL,
    scan_id        uuid NOT NULL REFERENCES scan.scans (id) ON DELETE CASCADE,
    engine_run_id  uuid REFERENCES scan.engine_runs (id) ON DELETE CASCADE,

    role           text NOT NULL
                   CHECK (role IN ('native_output', 'log', 'stderr',
                                   'sarif', 'source_archive')),
    storage_ref    text NOT NULL,
    media_type     text,
    sha256         text NOT NULL,
    size_bytes     bigint NOT NULL CHECK (size_bytes >= 0),
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX raw_artifacts_scan_idx   ON scan.raw_artifacts (scan_id, role);
CREATE INDEX raw_artifacts_tenant_idx ON scan.raw_artifacts (tenant_id);
CREATE INDEX raw_artifacts_sha_idx    ON scan.raw_artifacts (sha256);

SELECT app.enable_tenant_rls('scan.raw_artifacts');

-- IMMUTABLE BY GRANT, not by convention. Same reasoning as auth.audit_log:
-- these artifacts are the evidence behind every report.
REVOKE UPDATE, DELETE ON scan.raw_artifacts FROM encorebom_app;

-- ---------------------------------------------------------------------------
-- ecosystems_detected — feeds the mandatory Engine Coverage report section
-- and auto-seeds project.practices.known_unknowns.
--
-- engine_available = false is THE HONEST DENOMINATOR most tools hide: an
-- ecosystem was found in the source and no engine could scan it. Omitting that
-- converts an unknown into a false negative the customer trusts.
-- ---------------------------------------------------------------------------
CREATE TABLE scan.ecosystems_detected (
    id                uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id         uuid NOT NULL,
    scan_id           uuid NOT NULL REFERENCES scan.scans (id) ON DELETE CASCADE,
    ecosystem         text NOT NULL,
    detected_by       text NOT NULL,
    engine_available  boolean NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),

    UNIQUE (scan_id, ecosystem, detected_by)
);

CREATE INDEX ecosystems_detected_scan_idx ON scan.ecosystems_detected (scan_id);
CREATE INDEX ecosystems_detected_gap_idx  ON scan.ecosystems_detected (scan_id)
    WHERE engine_available = false;

SELECT app.enable_tenant_rls('scan.ecosystems_detected');

-- +goose Down
DROP TABLE IF EXISTS scan.ecosystems_detected;
DROP TABLE IF EXISTS scan.raw_artifacts;
DROP TABLE IF EXISTS scan.engine_runs;
DROP TABLE IF EXISTS scan.scans;
