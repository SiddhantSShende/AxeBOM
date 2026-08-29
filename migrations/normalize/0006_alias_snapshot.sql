-- +goose Up
-- ===========================================================================
-- alias_snapshot — the versioned provenance marker normalize.bom_documents
-- .alias_snapshot_id (NOT NULL uuid) points at. GLOBAL, same reasoning as
-- vuln_clusters: the alias graph is shared knowledge about the world, not
-- tenant data, so this row records a snapshot OF that shared graph, not a
-- per-tenant fact.
--
-- `source` is honest about what today's snapshot actually is: the alias
-- edges consulted for one normalization run, derived scan-locally from that
-- run's own grype/osv-scanner artifacts (see cluster_store.py) — not yet a
-- read of a persisted, versioned global edge set with its own release
-- cadence. A future snapshot mechanism that pins a specific point-in-time
-- copy of normalize.vuln_alias_edges would set `source` to something else;
-- this column exists now so that distinction is representable without a
-- later schema change.
-- ===========================================================================
CREATE TABLE normalize.alias_snapshot (
    id               uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    edge_count       int  NOT NULL DEFAULT 0,
    source           text NOT NULL DEFAULT 'scan-local',
    ruleset_version  text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX alias_snapshot_created_idx ON normalize.alias_snapshot (created_at);

-- ---------------------------------------------------------------------------
-- axebom_normalize_writer — the one deliberate exception to "workers hold no
-- credentials" (axebom_shared.config's docstring), and the FIRST role in this
-- codebase narrower than axebom_app.
--
-- axebom_app has blanket SELECT/INSERT/UPDATE/DELETE across every schema —
-- Postgres grants are not how this system separates services from each
-- other today; that is done entirely by the depguard/schema-per-service
-- discipline at the application layer (CLAUDE.md invariant 11). This role is
-- the first case where the DATABASE itself enforces a narrower boundary:
--
--   - normalize schema ONLY — no auth/project/scan/report/campaign/comment
--     /notify access at all.
--   - SELECT + INSERT only — NO UPDATE, NO DELETE. Normalization is
--     append-only/versioned by design (CLAUDE.md invariant 10: "never
--     overwrite normalized data in place"), so this role structurally
--     cannot violate that even by application bug.
--
-- The one narrow exception is a column-level UPDATE on vuln_clusters below:
-- growing an existing cluster's member_count/flagged_for_review/display_id
-- has no INSERT-only representation, because those are stored (not derived)
-- aggregate columns (ADR-0005) with their own BEFORE UPDATE trigger.
--
-- RLS applies to this role exactly as to any other non-superuser,
-- non-BYPASSRLS role (CLAUDE.md invariant 6) — nothing here weakens tenancy;
-- every normalize table this role writes to is either tenant-scoped and
-- RLS-protected the same way axebom_app's writes are, or global reference
-- data (vuln_clusters, vuln_ids, vuln_alias_edges, alias_snapshot,
-- licenses) that carries no tenant_id at all, matching the existing
-- precedent those tables already established in migration 0002.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axebom_normalize_writer') THEN
    CREATE ROLE axebom_normalize_writer LOGIN PASSWORD 'axebom_normalize_writer';
  END IF;
END
$$;
-- +goose StatementEnd

ALTER ROLE axebom_normalize_writer NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

GRANT USAGE ON SCHEMA normalize, app TO axebom_normalize_writer;

-- Every table this schema has as of this migration — components, findings
-- (and its 16 partitions, via GRANT ON ALL TABLES), raw_findings,
-- bom_documents, component_locations, component_dependencies,
-- component_candidate_identities, component_provenance, vuln_clusters,
-- vuln_cluster_merges, vuln_ids, vuln_alias_edges, licenses, license_refs,
-- crypto_assets, quantum_components, ai_models, ai_datasets,
-- ai_model_dependencies, hardware_components, vex_statements,
-- csaf_advisories, and the alias_snapshot table just created above.
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA normalize TO axebom_normalize_writer;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA normalize TO axebom_normalize_writer;

-- Future normalize-schema tables (e.g. a later CBOM/AIBOM normalize-trigger
-- pass) stay reachable without a second grant migration remembering to add
-- this role — mirrors bootstrap's ALTER DEFAULT PRIVILEGES for axebom_app.
ALTER DEFAULT PRIVILEGES IN SCHEMA normalize
  GRANT SELECT, INSERT ON TABLES TO axebom_normalize_writer;
ALTER DEFAULT PRIVILEGES IN SCHEMA normalize
  GRANT USAGE, SELECT ON SEQUENCES TO axebom_normalize_writer;

-- The one column-scoped exception — see the role's doc comment above for why
-- this cannot be represented as an INSERT.
GRANT UPDATE (member_count, flagged_for_review, display_id, updated_at)
  ON normalize.vuln_clusters TO axebom_normalize_writer;

-- +goose Down
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA normalize FROM axebom_normalize_writer;
DROP TABLE IF EXISTS normalize.alias_snapshot;

-- The role is intentionally NOT dropped — same reasoning as axebom_app in
-- bootstrap: other databases in the cluster may use it, and DROP ROLE fails
-- if any object anywhere still depends on it.
