-- +goose Up
-- ===========================================================================
-- normalize (2/4) — the vulnerability alias graph, findings, licenses.
-- Implements docs/01-DATA-MODEL.md §5 and docs/ADR/0005.
--
-- THE PROBLEM THIS SOLVES: four engines report the same vulnerability under
-- four namespaces — grype emits GHSA, osv-scanner emits OSV/GO/PYSEC,
-- dependency-check emits CVE, trivy emits both. Deduping on the primary id
-- inflates counts roughly 3x, and a report claiming 240 vulnerabilities where
-- there are 80 drives real remediation budgets.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- vuln_clusters — GLOBAL, not tenant-scoped. The alias graph is shared
-- knowledge about the world, not tenant data.
--
-- `id` IS A DURABLE SURROGATE, NEVER DERIVED FROM ITS MEMBERS (ADR-0005).
-- A content-derived id (uuidv5 of the sorted member list) mutates the moment a
-- new alias is published: every foreign key breaks and every previously issued
-- report references an id that no longer exists. The failure is silent and
-- arrives weeks after the code shipped.
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.vuln_clusters (
    id                  uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    -- Lowest-rank member: CVE < GHSA < OSV-native < vendor.
    display_id          text NOT NULL,
    member_count        int NOT NULL DEFAULT 1 CHECK (member_count >= 1),
    -- Above 12 members a cluster is far more likely an over-merge than a real
    -- advisory family. Flagged for review rather than blocked, so the
    -- heuristic's error stays recoverable.
    flagged_for_review  boolean NOT NULL DEFAULT false,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX vuln_clusters_display_idx  ON normalize.vuln_clusters (display_id);
CREATE INDEX vuln_clusters_flagged_idx  ON normalize.vuln_clusters (flagged_for_review)
    WHERE flagged_for_review = true;

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON normalize.vuln_clusters
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

-- ---------------------------------------------------------------------------
-- vuln_cluster_merges — the forwarding table.
--
-- When two clusters merge, the old id is NOT deleted; a forwarding row lets a
-- view resolve it. Reports additionally pin display_id_at_render, so a report
-- issued in March still says CVE-2021-44228 in September.
--
-- evidence_edge_id is mandatory in practice: a compliance product must be able
-- to answer "why did these two findings become one?" If it cannot, the merge
-- should not have happened.
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.vuln_cluster_merges (
    id               uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    from_cluster_id  uuid NOT NULL,
    into_cluster_id  uuid NOT NULL REFERENCES normalize.vuln_clusters (id) ON DELETE CASCADE,
    evidence_edge_id uuid,
    merged_at        timestamptz NOT NULL DEFAULT now(),

    CHECK (from_cluster_id <> into_cluster_id)
);

CREATE INDEX cluster_merges_from_idx ON normalize.vuln_cluster_merges (from_cluster_id);
CREATE INDEX cluster_merges_into_idx ON normalize.vuln_cluster_merges (into_cluster_id);

-- Resolves a possibly-merged cluster id forward to its current cluster.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION normalize.resolve_cluster(start_id uuid)
RETURNS uuid
LANGUAGE plpgsql STABLE
AS $fn$
DECLARE
  current_id uuid := start_id;
  next_id    uuid;
  hops       int := 0;
BEGIN
  LOOP
    SELECT into_cluster_id INTO next_id
      FROM normalize.vuln_cluster_merges
     WHERE from_cluster_id = current_id;
    EXIT WHEN next_id IS NULL;
    current_id := next_id;
    next_id := NULL;
    hops := hops + 1;
    -- Merge chains are short in practice. A cycle would mean the merge log is
    -- corrupt; fail loudly rather than spin.
    IF hops > 64 THEN
      RAISE EXCEPTION 'cluster merge chain exceeded 64 hops from %', start_id;
    END IF;
  END LOOP;
  RETURN current_id;
END;
$fn$;
-- +goose StatementEnd

-- ---------------------------------------------------------------------------
-- vuln_ids — namespaced identifiers belonging to a cluster. GLOBAL.
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.vuln_ids (
    id          uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    cluster_id  uuid NOT NULL REFERENCES normalize.vuln_clusters (id) ON DELETE CASCADE,
    namespace   text NOT NULL
                CHECK (namespace IN ('CVE','GHSA','OSV','SNYK','RHSA','DSA',
                                     'USN','ALAS','ELSA','DLA','NPM')),
    value       text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),

    UNIQUE (namespace, value)
);

CREATE INDEX vuln_ids_cluster_idx ON normalize.vuln_ids (cluster_id);

-- ---------------------------------------------------------------------------
-- vuln_alias_edges — GLOBAL, undirected, monotonically growing.
-- Union-find over this set yields clusters.
--
-- `authoritative` is true only for OSV and GHSA. A CVE<->CVE merge REQUIRES an
-- authoritative edge, because OSV aliases are not always equivalence-safe:
-- batched advisories alias several genuinely distinct CVEs, and MAL- ids alias
-- broadly. Unguarded union-find eventually collapses unrelated vulnerabilities
-- and UNDER-reports — a worse failure than the 3x over-count it was fixing.
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.vuln_alias_edges (
    id             uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    id_a           text NOT NULL,   -- '<NS>-<value>'
    id_b           text NOT NULL,
    source         text NOT NULL,   -- osv | ghsa | grype | trivy | depcheck
    authoritative  boolean NOT NULL DEFAULT false,
    first_seen     timestamptz NOT NULL DEFAULT now(),
    last_seen      timestamptz NOT NULL DEFAULT now(),

    -- Undirected: store the pair in canonical order so (a,b) and (b,a) cannot
    -- both exist.
    CHECK (id_a < id_b),
    UNIQUE (id_a, id_b, source)
);

CREATE INDEX vuln_alias_edges_a_idx    ON normalize.vuln_alias_edges (id_a);
CREATE INDEX vuln_alias_edges_b_idx    ON normalize.vuln_alias_edges (id_b);
CREATE INDEX vuln_alias_edges_auth_idx ON normalize.vuln_alias_edges (authoritative);

-- ---------------------------------------------------------------------------
-- raw_findings — INGESTED VERBATIM, NEVER DEDUPED AT INGEST.
--
-- Deduping here would destroy the audit trail and make the merge
-- unexplainable. normalize.findings is DERIVED from these.
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.raw_findings (
    id              uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id       uuid NOT NULL,
    scan_id         uuid NOT NULL,
    engine_run_id   uuid,
    engine_id       text NOT NULL,
    native_vuln_id  text NOT NULL,
    component_key   text NOT NULL,
    severity_raw    text,
    cvss_vectors    jsonb NOT NULL DEFAULT '[]'::jsonb,
    fix_versions    text[] NOT NULL DEFAULT '{}',
    -- The richest source of alias edges. Losing this is expensive to notice
    -- later, because the symptom is inflated counts, not an error.
    aliases_raw     text[] NOT NULL DEFAULT '{}',
    references_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX raw_findings_scan_idx   ON normalize.raw_findings (scan_id, engine_id);
CREATE INDEX raw_findings_tenant_idx ON normalize.raw_findings (tenant_id);
CREATE INDEX raw_findings_vuln_idx   ON normalize.raw_findings (native_vuln_id);

SELECT app.enable_tenant_rls('normalize.raw_findings');

-- ---------------------------------------------------------------------------
-- findings — the deduped view. Partitioned like components.
--
-- Key is (cluster_id, component_key):
--   two engines, same CVE, same jar    -> ONE finding, detected_by = both
--   same CVE, two components           -> two findings
--   same CVE, same component, 2 paths  -> one finding, two locations
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.findings (
    id                    uuid NOT NULL DEFAULT app.uuid_v7(),
    tenant_id             uuid NOT NULL,
    bom_document_id       uuid NOT NULL,
    component_id          uuid NOT NULL,
    cluster_id            uuid NOT NULL,

    -- PINNED at render time. A report is a compliance artifact, not a live
    -- view: it must still say what it said, even after the cluster absorbs
    -- more aliases and its lowest-rank member changes.
    display_id_at_render  text NOT NULL,

    severity_effective    text
                          CHECK (severity_effective IS NULL OR severity_effective IN
                            ('critical','high','medium','low','none','unknown')),
    severity_source       text,
    -- SURFACED IN THE UI, never hidden. A reviewer will ask why Trivy said
    -- High and Grype said Critical, and the answer must be visible.
    severity_conflict     boolean NOT NULL DEFAULT false,

    -- ALL of them. CVSS v2 / v3.1 / v4.0 use different formulas and ranges and
    -- ARE NOT COMPARABLE — never take a max across versions.
    cvss_vectors          jsonb NOT NULL DEFAULT '[]'::jsonb,
    cvss_primary_score    numeric(3,1) CHECK (cvss_primary_score BETWEEN 0 AND 10),

    fixed_versions        text[] NOT NULL DEFAULT '{}',
    fixed_in_min          text,
    -- `unknown` where no ecosystem comparator exists. Naive string sort is
    -- wrong for every ecosystem: 1.10.0 sorts before 1.9.0 lexically.
    fix_version_ordering  text NOT NULL DEFAULT 'unknown'
                          CHECK (fix_version_ordering IN ('known','unknown')),

    detected_by           text[] NOT NULL DEFAULT '{}',
    references_json       jsonb NOT NULL DEFAULT '[]'::jsonb,

    first_seen_at         timestamptz NOT NULL DEFAULT now(),
    last_seen_at          timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (bom_document_id, id),
    UNIQUE (bom_document_id, cluster_id, component_id)
) PARTITION BY HASH (bom_document_id);

-- +goose StatementBegin
DO $$
BEGIN
  FOR i IN 0..15 LOOP
    EXECUTE format(
      'CREATE TABLE normalize.findings_p%s PARTITION OF normalize.findings '
      'FOR VALUES WITH (MODULUS 16, REMAINDER %s)',
      lpad(i::text, 2, '0'), i);
  END LOOP;
END
$$;
-- +goose StatementEnd

CREATE INDEX findings_tenant_idx    ON normalize.findings (tenant_id, bom_document_id);
CREATE INDEX findings_cluster_idx   ON normalize.findings (cluster_id);
CREATE INDEX findings_component_idx ON normalize.findings (bom_document_id, component_id);
CREATE INDEX findings_severity_idx  ON normalize.findings (bom_document_id, severity_effective);
CREATE INDEX findings_conflict_idx  ON normalize.findings (bom_document_id)
    WHERE severity_conflict = true;

SELECT app.enable_tenant_rls_partitioned('normalize.findings');

-- ---------------------------------------------------------------------------
-- licenses — GLOBAL reference data, seeded from the pinned SPDX license list.
-- Not tenant-scoped: the SPDX list is the same for everyone.
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.licenses (
    id             uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    spdx_id        text NOT NULL UNIQUE,
    name           text NOT NULL,
    category       text,
    is_deprecated  boolean NOT NULL DEFAULT false,
    is_osi_approved boolean NOT NULL DEFAULT false,
    obligations    jsonb NOT NULL DEFAULT '[]'::jsonb,
    text_ref       text,
    list_version   text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX licenses_deprecated_idx ON normalize.licenses (is_deprecated)
    WHERE is_deprecated = true;

-- ---------------------------------------------------------------------------
-- license_refs — TENANT-SCOPED. Unrecognized license text found in a tenant's
-- own code becomes LicenseRef-AxeBOM-<slug>, with the raw text preserved
-- for later human mapping.
-- ---------------------------------------------------------------------------
CREATE TABLE normalize.license_refs (
    id                  uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id           uuid NOT NULL,
    slug                text NOT NULL,
    raw_text            text NOT NULL,
    first_seen_scan_id  uuid,
    mapped_spdx_id      text,
    reviewed_by         uuid,
    reviewed_at         timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, slug)
);

CREATE INDEX license_refs_tenant_idx ON normalize.license_refs (tenant_id);

SELECT app.enable_tenant_rls('normalize.license_refs');

-- +goose Down
DROP TABLE IF EXISTS normalize.license_refs;
DROP TABLE IF EXISTS normalize.licenses;
DROP TABLE IF EXISTS normalize.findings;
DROP TABLE IF EXISTS normalize.raw_findings;
DROP TABLE IF EXISTS normalize.vuln_alias_edges;
DROP TABLE IF EXISTS normalize.vuln_ids;
DROP FUNCTION IF EXISTS normalize.resolve_cluster(uuid);
DROP TABLE IF EXISTS normalize.vuln_cluster_merges;
DROP TABLE IF EXISTS normalize.vuln_clusters;
