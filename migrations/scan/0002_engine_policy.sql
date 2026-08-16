-- +goose Up
-- ===========================================================================
-- engine_policy — which engines run for a family, as DATA.
--
-- WHY A TABLE AND NOT A CONSTANT: the built-in defaults live in
-- services/scan-orchestrator/internal/policy, but "which engines run for SBOM"
-- is exactly the setting a customer wants changed — to drop dependency-check
-- because its first NVD sync takes an hour, or to pin to syft alone while
-- evaluating. A code constant means a deploy for every such request.
--
-- Rows are OVERRIDES, not the full set. An absent row means "use the built-in
-- default for this family", so a tenant that has never customised anything has
-- no rows at all and picks up new engines automatically.
--
-- Implements docs/01-DATA-MODEL.md §3.
-- ===========================================================================

CREATE TABLE scan.engine_policy (
    id          uuid PRIMARY KEY DEFAULT app.uuid_v7(),

    -- NULL tenant_id is the SYSTEM-WIDE default, visible to every tenant.
    -- Nullable-tenant RLS: a tenant may read the global row and its own, and
    -- may write only its own.
    tenant_id   uuid,

    family      text NOT NULL
                CHECK (family IN ('fetch','sbom','cbom','qbom','aibom','hbom')),

    -- The engines to run for this family, in place of the defaults.
    -- An EMPTY array is meaningful and distinct from an absent row: it means
    -- "run nothing for this family", which is how a tenant disables a BOM type
    -- without removing the classification from every project.
    engine_ids  text[] NOT NULL DEFAULT '{}',

    -- Per-engine weight overrides for progress calculation, as
    -- {"syft": 3, "dependency-check": 1}. Absent keys use the engine's default.
    weights     jsonb NOT NULL DEFAULT '{}'::jsonb,

    enabled     boolean NOT NULL DEFAULT true,
    note        text,

    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    -- One policy per (tenant, family). The partial unique index below covers
    -- the global row, because NULL is not equal to itself in a UNIQUE
    -- constraint and two global rows for one family would otherwise be legal.
    UNIQUE (tenant_id, family)
);

CREATE UNIQUE INDEX engine_policy_global_uniq
    ON scan.engine_policy (family)
    WHERE tenant_id IS NULL;

CREATE INDEX engine_policy_tenant_idx ON scan.engine_policy (tenant_id, family)
    WHERE enabled;

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON scan.engine_policy
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

-- Nullable-tenant RLS: writable with a NULL tenant (the global default, set by
-- a migration or an operator), readable only within a tenant scope.
SELECT app.enable_tenant_rls_nullable('scan.engine_policy');

COMMENT ON TABLE scan.engine_policy IS
'Per-tenant engine selection overrides. An absent row means "use the built-in
default for this family". An empty engine_ids array means "run nothing", which
is different from absent. NULL tenant_id is the system-wide default.';

-- +goose Down
DROP TABLE IF EXISTS scan.engine_policy;
