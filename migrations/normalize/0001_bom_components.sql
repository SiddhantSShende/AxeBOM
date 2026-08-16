-- +goose Up
-- ===========================================================================
-- normalize (1/4) — BOM documents, components, provenance, dependency graph.
-- Implements docs/01-DATA-MODEL.md §4.
-- ===========================================================================

CREATE TABLE normalize.bom_documents (
    id                          uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id                   uuid NOT NULL,
    scan_id                     uuid NOT NULL,   -- -> scan.scans.id, no FK (cross-schema)

    bom_type                    text NOT NULL
                                CHECK (bom_type IN ('SBOM','CBOM','QBOM','AIBOM','HBOM')),

    -- Bumped on RE-NORMALIZATION; older rows are retained (ADR-0003). Fixing a
    -- dedup bug re-normalizes stored raw artifacts into version+1 rather than
    -- re-running scanners, so historical reports stay explainable.
    normalization_version       int NOT NULL DEFAULT 1 CHECK (normalization_version >= 1),
    ruleset_version             text NOT NULL,
    alias_snapshot_id           uuid NOT NULL,
    -- SPDX ids are deprecated and added over time; a report must state which
    -- list it was validated against.
    spdx_license_list_version   text NOT NULL,

    -- TWO COVERAGE NUMBERS, ALWAYS BOTH (03-NORMALIZER-SPEC §5.2).
    --   completeness_pct  substantive values only — the honest signal
    --   declaration_pct   includes explicit `not-provided` — a representation
    --                     check, NOT compliance
    -- Publishing only the second and calling it "coverage" is how tools ship
    -- misleading 100% scores.
    completeness_pct            numeric(5,2) CHECK (completeness_pct BETWEEN 0 AND 100),
    declaration_pct             numeric(5,2) CHECK (declaration_pct  BETWEEN 0 AND 100),
    coverage_breakdown          jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Components that fell to `opaque` identity. Kept in the denominator and
    -- reported separately — dropping them lets a bad scan claim 100%.
    unidentified_count          int NOT NULL DEFAULT 0 CHECK (unidentified_count >= 0),

    generated_at                timestamptz NOT NULL DEFAULT now(),
    created_at                  timestamptz NOT NULL DEFAULT now(),

    UNIQUE (scan_id, bom_type, normalization_version)
);

CREATE INDEX bom_documents_tenant_idx ON normalize.bom_documents (tenant_id, scan_id);

SELECT app.enable_tenant_rls('normalize.bom_documents');

-- ---------------------------------------------------------------------------
-- components — CERT-In §4.2 data fields.
--
-- PARTITIONED BY HASH (bom_document_id), 16 ways. A large monorepo yields
-- 50k+ components per scan; partitioning keeps index maintenance and vacuum
-- bounded from day one rather than after the first outage.
--
-- The partition key must be part of every unique constraint, so the primary
-- key is (bom_document_id, id) — which also gives useful locality, since
-- every query is scoped to a document.
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.components (
    id                  uuid NOT NULL DEFAULT app.uuid_v7(),
    tenant_id           uuid NOT NULL,
    bom_document_id     uuid NOT NULL,

    -- THE MERGE KEY (03-NORMALIZER-SPEC §1.2).
    component_key       text NOT NULL,
    identity_rule       text NOT NULL
                        CHECK (identity_rule IN ('purl','cpe','swid','hash','file','name','opaque')),
    identity_confidence text NOT NULL DEFAULT 'high'
                        CHECK (identity_confidence IN ('high','medium','low')),

    -- TWO DIFFERENT IDENTIFIERS. Conflating them breaks dedup AND compliance.
    --   purl               canonical ECOSYSTEM PURL. Every scanner emits it;
    --                      all dedup runs on it.
    --   certin_identifier  CERT-In's own form (pkg:supplier/Org/Name@ver).
    --                      DERIVED, RENDER-ONLY, NEVER a merge key.
    purl                text,
    certin_identifier   text,

    ecosystem           text,
    name                text NOT NULL,                       -- field 1
    -- Stored verbatim. NEVER merge two components whose version_raw differs.
    version_raw         text,                                -- field 2
    -- Display and ordering only.
    version_normalized  text,
    description         text,                                -- field 3
    supplier            text,                                -- field 4

    -- Field 5. declared/concluded/observed are kept SEPARATE: SPDX requires
    -- the distinction and compliance reviewers ask for it. Never overwrite
    -- declared with concluded.
    license_declared    text,
    license_concluded   text,
    license_observed    text,
    license_effective   text,
    license_rule        text,
    -- e.g. GPL-2.0 -> -only vs -or-later is genuinely ambiguous. FLAG IT,
    -- never resolve it: choosing wrong is a legal error, not a data error.
    license_ambiguous   boolean NOT NULL DEFAULT false,

    origin              text                                 -- field 6
                        CHECK (origin IS NULL OR origin IN
                          ('proprietary','open-source','third-party-vendor','unknown')),
    -- Field 9. Derived from fixed_versions vs version_raw using an
    -- ecosystem-correct comparator; `unknown` where none exists — never guess.
    patch_status        text
                        CHECK (patch_status IS NULL OR patch_status IN
                          ('up-to-date','patch-available','no-fix-available','unknown')),
    release_date        date,                                -- field 10
    eol_date            date,                                -- field 11
    criticality         text                                 -- field 12
                        CHECK (criticality IS NULL OR criticality IN
                          ('critical','high','medium','low')),
    usage_restrictions  text,                                -- field 13
    hashes              jsonb NOT NULL DEFAULT '[]'::jsonb,  -- field 14
    comments            text,                                -- field 15
    author_of_sbom_data text,                                -- field 16
    -- Fields 18-20 are tristate: yes | no | not-provided. `not-provided` is
    -- REPORTED but scores 0 for completeness.
    executable_property text CHECK (executable_property IS NULL OR
                                    executable_property IN ('yes','no','not-provided')),
    archive_property    text CHECK (archive_property IS NULL OR
                                    archive_property IN ('yes','no','not-provided')),
    structured_property text CHECK (structured_property IS NULL OR
                                    structured_property IN ('yes','no','not-provided')),

    scope               text NOT NULL DEFAULT 'required'
                        CHECK (scope IN ('required','optional','excluded')),

    -- Stored EXPLICITLY from the root set, never inferred from depth.
    is_direct           boolean NOT NULL DEFAULT false,
    -- NULL for orphans. Never forced to 1 — that silently inflates the
    -- direct-dependency count, which is a headline number.
    depth               int CHECK (depth IS NULL OR depth >= 0),
    is_orphan           boolean NOT NULL DEFAULT false,

    -- Per-field provided / not-provided + reason, keyed by profile field id.
    -- Drives BOTH coverage numbers.
    field_status        jsonb NOT NULL DEFAULT '{}'::jsonb,

    created_at          timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (bom_document_id, id),
    UNIQUE (bom_document_id, component_key)
) PARTITION BY HASH (bom_document_id);

-- +goose StatementBegin
DO $$
BEGIN
  FOR i IN 0..15 LOOP
    EXECUTE format(
      'CREATE TABLE normalize.components_p%s PARTITION OF normalize.components '
      'FOR VALUES WITH (MODULUS 16, REMAINDER %s)',
      lpad(i::text, 2, '0'), i);
  END LOOP;
END
$$;
-- +goose StatementEnd

CREATE INDEX components_tenant_idx    ON normalize.components (tenant_id, bom_document_id);
CREATE INDEX components_purl_idx      ON normalize.components (purl) WHERE purl IS NOT NULL;
CREATE INDEX components_ecosystem_idx ON normalize.components (bom_document_id, ecosystem);
CREATE INDEX components_license_idx   ON normalize.components (bom_document_id, license_effective);
CREATE INDEX components_crit_idx      ON normalize.components (bom_document_id, criticality);
CREATE INDEX components_direct_idx    ON normalize.components (bom_document_id, is_direct);

-- Applies to the parent AND every partition, so a query written directly
-- against normalize.components_p07 cannot bypass tenancy.
SELECT app.enable_tenant_rls_partitioned('normalize.components');

-- ---------------------------------------------------------------------------
-- component_locations — IDENTITY IS THE PACKAGE; LOCATIONS ARE 1:N.
--
-- The same jar vendored at two paths is one component with two locations, not
-- two components. Putting the path in the identity key inflates every count.
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.component_locations (
    id               uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id        uuid NOT NULL,
    bom_document_id  uuid NOT NULL,
    component_id     uuid NOT NULL,
    path             text NOT NULL,
    layer            text,
    sha256           text,
    created_at       timestamptz NOT NULL DEFAULT now(),

    FOREIGN KEY (bom_document_id, component_id)
        REFERENCES normalize.components (bom_document_id, id) ON DELETE CASCADE
);

CREATE INDEX component_locations_comp_idx   ON normalize.component_locations (bom_document_id, component_id);
CREATE INDEX component_locations_tenant_idx ON normalize.component_locations (tenant_id);

SELECT app.enable_tenant_rls('normalize.component_locations');

-- ---------------------------------------------------------------------------
-- component_candidate_identities
--
-- Where a LOW-confidence Dependency-Check CPE attaches WITHOUT merging into a
-- PURL-identified component. Merging would inherit its false positives into
-- otherwise-clean data, and the customer could not tell which findings came
-- from a guess.
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.component_candidate_identities (
    id               uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id        uuid NOT NULL,
    bom_document_id  uuid NOT NULL,
    component_id     uuid NOT NULL,
    kind             text NOT NULL CHECK (kind IN ('cpe','swid','purl','hash','name')),
    value            text NOT NULL,
    source_engine    text NOT NULL,
    confidence       text NOT NULL CHECK (confidence IN ('high','medium','low')),
    created_at       timestamptz NOT NULL DEFAULT now(),

    FOREIGN KEY (bom_document_id, component_id)
        REFERENCES normalize.components (bom_document_id, id) ON DELETE CASCADE
);

CREATE INDEX candidate_identities_comp_idx   ON normalize.component_candidate_identities (bom_document_id, component_id);
CREATE INDEX candidate_identities_tenant_idx ON normalize.component_candidate_identities (tenant_id);

SELECT app.enable_tenant_rls('normalize.component_candidate_identities');

-- ---------------------------------------------------------------------------
-- component_provenance — which engine saw this, from which artifact, under
-- which rule. This is what lets an audit answer "where did this line in this
-- report come from?"
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.component_provenance (
    id                 uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id          uuid NOT NULL,
    bom_document_id    uuid NOT NULL,
    component_id       uuid NOT NULL,

    engine_id          text NOT NULL,
    engine_version     text,
    engine_db_version  text,
    job_id             uuid,
    raw_finding_id     uuid,
    artifact_uri       text,
    artifact_sha256    text,
    rule_id            text,
    rule_version       text,
    confidence         text CHECK (confidence IS NULL OR confidence IN ('high','medium','low')),
    observed_at        timestamptz NOT NULL DEFAULT now(),

    FOREIGN KEY (bom_document_id, component_id)
        REFERENCES normalize.components (bom_document_id, id) ON DELETE CASCADE
);

CREATE INDEX component_provenance_comp_idx   ON normalize.component_provenance (bom_document_id, component_id);
CREATE INDEX component_provenance_engine_idx ON normalize.component_provenance (engine_id);
CREATE INDEX component_provenance_tenant_idx ON normalize.component_provenance (tenant_id);

SELECT app.enable_tenant_rls('normalize.component_provenance');

-- ---------------------------------------------------------------------------
-- component_dependencies — the graph.
--
-- Edges are REPLACED per ecosystem by the highest-trust engine, NOT unioned
-- (03-NORMALIZER-SPEC §4.2). Unioning invents phantom transitive edges and
-- corrupts direct-vs-transitive counts — exactly the number a Top-Level
-- report is built on. owning_engine records who supplied each subgraph.
--
-- CYCLES ARE REAL (Go modules, npm workspaces). Never assume a DAG.
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.component_dependencies (
    id                    uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id             uuid NOT NULL,
    bom_document_id       uuid NOT NULL,
    from_component_id     uuid NOT NULL,
    to_component_id       uuid NOT NULL,

    relationship          text NOT NULL DEFAULT 'depends_on'
                          CHECK (relationship IN ('depends_on','contains','describes',
                                                  'generated_from','variant_of')),
    scope                 text,
    ecosystem             text,
    owning_engine         text,
    confidence            text CHECK (confidence IS NULL OR confidence IN ('high','medium','low')),
    created_at            timestamptz NOT NULL DEFAULT now(),

    UNIQUE (bom_document_id, from_component_id, to_component_id, relationship),
    FOREIGN KEY (bom_document_id, from_component_id)
        REFERENCES normalize.components (bom_document_id, id) ON DELETE CASCADE,
    FOREIGN KEY (bom_document_id, to_component_id)
        REFERENCES normalize.components (bom_document_id, id) ON DELETE CASCADE
);

CREATE INDEX component_deps_from_idx   ON normalize.component_dependencies (bom_document_id, from_component_id);
CREATE INDEX component_deps_to_idx     ON normalize.component_dependencies (bom_document_id, to_component_id);
CREATE INDEX component_deps_tenant_idx ON normalize.component_dependencies (tenant_id);

SELECT app.enable_tenant_rls('normalize.component_dependencies');

-- +goose Down
DROP TABLE IF EXISTS normalize.component_dependencies;
DROP TABLE IF EXISTS normalize.component_provenance;
DROP TABLE IF EXISTS normalize.component_candidate_identities;
DROP TABLE IF EXISTS normalize.component_locations;
DROP TABLE IF EXISTS normalize.components;
DROP TABLE IF EXISTS normalize.bom_documents;
