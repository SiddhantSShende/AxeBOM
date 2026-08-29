-- +goose Up
-- ===========================================================================
-- normalize_triggers — the write-once guard that fires "this scan's engines
-- are done, normalize it" exactly once per (scan, family).
--
-- Modeled on SetSourceOnce's idiom in store.go: a plain table with a
-- conditional INSERT (ON CONFLICT DO NOTHING), not a status column on
-- scan.scans. A redelivered or duplicate trigger publish writes nothing and
-- reports that it wrote nothing, which the caller treats as success rather
-- than a conflict — the same idempotency shape every other write in this
-- schema already uses.
--
-- Per-family, not a single row per scan: this migration wires SBOM only
-- (scan-orchestrator's normalize_trigger.go explicitly gates on
-- events.FamilySBOM), but CBOM/AIBOM can each gain their own trigger later
-- with zero schema change.
-- ===========================================================================
CREATE TABLE scan.normalize_triggers (
    scan_id       uuid NOT NULL REFERENCES scan.scans (id) ON DELETE CASCADE,
    tenant_id     uuid NOT NULL,
    family        text NOT NULL
                  CHECK (family IN ('sbom','cbom','qbom','aibom','hbom')),
    -- Doubles as the NATS Nats-Msg-Id dedup key for the published
    -- scan.normalize.<family> envelope.
    trigger_id    uuid NOT NULL DEFAULT app.uuid_v7(),
    triggered_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (scan_id, family)
);

CREATE INDEX normalize_triggers_tenant_idx ON scan.normalize_triggers (tenant_id);

SELECT app.enable_tenant_rls('scan.normalize_triggers');

-- IMMUTABLE BY GRANT, same reasoning as scan.raw_artifacts: this row is a
-- fired-once fact, not something the application ever legitimately updates.
REVOKE UPDATE, DELETE ON scan.normalize_triggers FROM axebom_app;

-- +goose Down
DROP TABLE IF EXISTS scan.normalize_triggers;
