-- +goose Up
-- ===========================================================================
-- campaign — scheduled recurring scans.
-- Implements docs/01-DATA-MODEL.md §9. CERT-In §5.3.4 (automated generation
-- and updates) and the "Frequency" practice.
-- ===========================================================================

CREATE TABLE campaign.campaigns (
    id             uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id      uuid NOT NULL,
    name           text NOT NULL,

    project_ids    uuid[] NOT NULL DEFAULT '{}',

    cron_expr      text NOT NULL,
    -- An IANA name, never a fixed offset. DST transitions are handled by the
    -- scheduler: a 02:30 daily run must not vanish on spring-forward and must
    -- not fire twice on fall-back. Storing an offset makes both bugs certain.
    timezone       text NOT NULL DEFAULT 'UTC',

    bom_types      text[] NOT NULL DEFAULT '{}',
    report_levels  text[] NOT NULL DEFAULT '{}',
    standards      text[] NOT NULL DEFAULT '{}',
    formats        text[] NOT NULL DEFAULT '{}',

    enabled        boolean NOT NULL DEFAULT true,
    next_run_at    timestamptz,
    last_run_at    timestamptz,

    created_by     uuid NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, name)
);

CREATE INDEX campaigns_tenant_idx ON campaign.campaigns (tenant_id);
-- Drives the scheduler tick.
CREATE INDEX campaigns_due_idx    ON campaign.campaigns (next_run_at)
    WHERE enabled = true;

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON campaign.campaigns
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

SELECT app.enable_tenant_rls('campaign.campaigns');

-- ---------------------------------------------------------------------------
-- runs
--
-- ⚠ UNIQUE (campaign_id, scheduled_for) IS THE MOST IMPORTANT LINE IN THIS
-- SCHEMA. It is what makes dispatch IDEMPOTENT across restarts and leader
-- changes: two scheduler instances racing both attempt the insert, one wins,
-- and the loser's unique violation means "someone else already claimed it" —
-- which is SUCCESS, not an error, and must be handled as such.
--
-- Leader election uses a Postgres advisory lock. No etcd, no Consul: the
-- database is already there and already consistent.
-- ---------------------------------------------------------------------------
CREATE TABLE campaign.runs (
    id             uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id      uuid NOT NULL,
    campaign_id    uuid NOT NULL REFERENCES campaign.campaigns (id) ON DELETE CASCADE,

    scheduled_for  timestamptz NOT NULL,
    started_at     timestamptz,
    finished_at    timestamptz,

    status         text NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending','running','completed',
                                     'completed_with_errors','failed','skipped')),
    -- `skipped` records a missed occurrence after downtime. Firing every
    -- missed run would be a thundering herd against the scan queue; firing the
    -- most recent one and RECORDING the rest keeps the gap visible instead of
    -- silent.
    skip_reason    text,

    scan_ids       uuid[] NOT NULL DEFAULT '{}',
    error          text,
    created_at     timestamptz NOT NULL DEFAULT now(),

    UNIQUE (campaign_id, scheduled_for)
);

CREATE INDEX campaign_runs_campaign_idx ON campaign.runs (campaign_id, scheduled_for DESC);
CREATE INDEX campaign_runs_tenant_idx   ON campaign.runs (tenant_id);

SELECT app.enable_tenant_rls('campaign.runs');

-- +goose Down
DROP TABLE IF EXISTS campaign.runs;
DROP TABLE IF EXISTS campaign.campaigns;
