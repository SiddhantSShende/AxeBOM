-- +goose Up
-- ===========================================================================
-- normalize (4/4) — VEX and CSAF.
-- Implements docs/01-DATA-MODEL.md §7. CERT-In §6 (PDF p.35-36).
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- vex_statements — APPEND-ONLY AND ITERATIVE.
--
-- CERT-In p.35 is explicit: "It is an iterative process and the VEX document
-- gets updated with each update in the vulnerability including the time taken
-- by the supplier along with remediation, workarounds, restart/downtime
-- required, scores, and risks."
--
-- So a new statement SUPERSEDES rather than mutating, and full history is
-- preserved. VEX also NEVER mutates a finding — it joins to it.
--
-- ⚠ ATTACHED TO cluster_id, NOT A RAW VULNERABILITY ID.
-- A triage decision must survive an alias-graph merge. Keying on the raw id
-- would silently orphan every triage when two clusters combine.
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.vex_statements (
    id              uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id       uuid NOT NULL,
    project_id      uuid NOT NULL,   -- -> project.projects.id, no FK (cross-schema)

    component_key   text,
    cluster_id      uuid NOT NULL,   -- -> normalize.vuln_clusters.id

    -- The four statuses, verbatim from CERT-In p.35 and restated identically
    -- for CBOM/QBOM (p.48), AIBOM (p.56) and HBOM (p.62).
    status          text NOT NULL
                    CHECK (status IN ('not_affected','affected','fixed','under_investigation')),

    justification   text,
    remediation     text,
    -- Named explicitly in the guideline text, not just status.
    workarounds     text,
    downtime        text,

    -- Effective status resolves by scope specificity first, then timestamp.
    scope           text NOT NULL DEFAULT 'project'
                    CHECK (scope IN ('project','component','version')),

    version         int NOT NULL DEFAULT 1 CHECK (version >= 1),
    superseded_by   uuid REFERENCES normalize.vex_statements (id) ON DELETE SET NULL,

    author_user_id  uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT vex_not_own_successor CHECK (superseded_by IS NULL OR superseded_by <> id)
);

CREATE INDEX vex_project_cluster_idx ON normalize.vex_statements (project_id, cluster_id);
CREATE INDEX vex_tenant_idx          ON normalize.vex_statements (tenant_id);
-- The current statement for a (project, cluster, component) is the one nothing
-- supersedes.
CREATE INDEX vex_current_idx         ON normalize.vex_statements (project_id, cluster_id, component_key)
    WHERE superseded_by IS NULL;

SELECT app.enable_tenant_rls('normalize.vex_statements');

-- APPEND-ONLY BY GRANT. A superseding statement is an INSERT; UPDATE would
-- destroy the history the guideline requires.
--
-- UPDATE is retained ONLY so superseded_by can be set on the prior row when a
-- new statement replaces it. DELETE is revoked outright.
REVOKE DELETE ON normalize.vex_statements FROM encorebom_app;

-- ---------------------------------------------------------------------------
-- csaf_advisories — published AFTER a VEX statement.
--
-- CERT-In p.35 Figure 7 sequence:
--   discovery -> VEX -> CSAF -> patch/mitigation -> ongoing updates -> SBOM integration
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.csaf_advisories (
    id                 uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id          uuid NOT NULL,
    vex_statement_id   uuid NOT NULL REFERENCES normalize.vex_statements (id) ON DELETE CASCADE,

    tracking_id        text NOT NULL,
    description        text,
    affected_versions  jsonb NOT NULL DEFAULT '[]'::jsonb,
    severity           text,
    mitigation_steps   text,
    published_at       timestamptz,

    -- The full CSAF 2.0 document, stored for round-trip fidelity. Rebuilding
    -- it from columns would lose fields the standard defines and we do not
    -- model, which is exactly what a consumer's validator would notice.
    document           jsonb NOT NULL DEFAULT '{}'::jsonb,

    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, tracking_id)
);

CREATE INDEX csaf_vex_idx    ON normalize.csaf_advisories (vex_statement_id);
CREATE INDEX csaf_tenant_idx ON normalize.csaf_advisories (tenant_id);

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON normalize.csaf_advisories
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

SELECT app.enable_tenant_rls('normalize.csaf_advisories');

-- +goose Down
DROP TABLE IF EXISTS normalize.csaf_advisories;
DROP TABLE IF EXISTS normalize.vex_statements;
