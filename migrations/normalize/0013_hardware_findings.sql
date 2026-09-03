-- +goose Up
-- ===========================================================================
-- CERT-In §10.4.1.4 element 24 — `vulnerabilities` on a hardware component.
--
-- ⚠ THIS ELEMENT HAS SCORED ZERO FOR EVERY COMPONENT SINCE PHASE 15. It is
-- modelled in both languages, rendered in the report and exported in both
-- standards, and nothing has ever populated it.
--
-- ---------------------------------------------------------------------------
-- WHY A SEPARATE TABLE AND NOT normalize.findings
-- ---------------------------------------------------------------------------
-- Reusing `findings` would have hidden every hardware finding SILENTLY. Its
-- only reader, services/report/internal/store/bomsource.go's loadFindings, is
-- an INNER JOIN:
--
--     JOIN normalize.components c ON c.id = f.component_id
--                                AND c.bom_document_id = f.bom_document_id
--
-- A row whose component_id points at a hardware component matches nothing and
-- vanishes from the report with no error anywhere — the exact false-negative
-- class invariant 12 exists to prevent. Making that a UNION would also make an
-- SBOM hot path (50k components, 200k findings, 16 hash partitions) pay for a
-- hardware feature.
--
-- The confidence class is different too. An SBOM finding is purl-keyed and
-- exact. This one is a CPE built from a free-text manufacturer string and a
-- model number somebody typed into a spreadsheet. It needs columns
-- `findings` does not have, and its severities must never be summed into the
-- counts an SBOM report quotes.
--
-- ⚠ AND NOT jsonb ON hardware_components. That would re-open exactly the hole
-- migration 0007 closed for findings.cluster_id: a jsonb array carries no
-- foreign key, so a dangling cluster reference becomes undetectable again.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- The three columns that make "no vulnerability" distinguishable from
-- "nobody looked". Without them the two are the same empty list.
-- ---------------------------------------------------------------------------
ALTER TABLE normalize.hardware_components

    -- ⚠ WHY THERE IS NO FINDING IS A DIFFERENT QUESTION FROM WHETHER THERE IS
    -- ONE, AND THIS COLUMN IS THE ONLY PLACE THE ANSWER LIVES.
    --
    --   matched        a CPE was built, searched, and matched something
    --   no-match       a CPE was built and searched, and matched nothing —
    --                  a real, reportable negative
    --   no-cpe         the component states too little to build a CPE from;
    --                  a part with no manufacturer and no model number cannot
    --                  be looked up by anybody, not just by us
    --   not-attempted  no vulnerability source is configured. NOT a failure:
    --                  the NVD path needs an API key, and a customer who has
    --                  not supplied one deserves to be told that rather than
    --                  shown an empty column that reads as "all clear"
    ADD COLUMN vuln_match_status text
        CHECK (vuln_match_status IS NULL OR
               vuln_match_status IN ('matched', 'no-match', 'no-cpe', 'not-attempted')),

    -- The CPEs actually searched with, so an ADVISORY match is auditable
    -- rather than magic. Empty when none could be built.
    ADD COLUMN cpe23_candidates text[] NOT NULL DEFAULT '{}',

    -- When the search ran. A hardware CVE match is a point-in-time statement
    -- about a database that changes daily; a finding with no date is not
    -- defensible six months later, which is the same reason engine_db_version
    -- exists for scanner findings.
    ADD COLUMN vuln_matched_at timestamptz;

-- ===========================================================================
-- hardware_findings — one advisory CPE match.
-- ===========================================================================
CREATE TABLE normalize.hardware_findings (
    id                    uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id             uuid NOT NULL,
    bom_document_id       uuid NOT NULL REFERENCES normalize.bom_documents (id) ON DELETE CASCADE,
    hardware_component_id uuid NOT NULL
                          REFERENCES normalize.hardware_components (id) ON DELETE CASCADE,

    -- The same durable global cluster every SBOM finding points at (ADR-0005),
    -- with the FK migration 0007 added to findings.cluster_id for the same
    -- reason: a finding pointing at a cluster with no row behind it is
    -- indistinguishable at read time from a genuine dangling reference.
    cluster_id            uuid NOT NULL REFERENCES normalize.vuln_clusters (id),
    display_id            text NOT NULL,

    -- ⚠ THE MATCH IS ADVISORY, AND IT SAYS SO IN A COLUMN RATHER THAN A
    -- FOOTNOTE.
    --
    -- An SBOM finding is keyed on a purl the ecosystem itself minted. This one
    -- is keyed on a CPE assembled from a manufacturer string a person typed.
    -- "STMicroelectronics" and "ST Microelectronics" are the same company and
    -- different CPE vendors. Storing what we searched with, what matched, and
    -- how much that is worth is what keeps "candidate" from quietly becoming
    -- "affected" between here and a customer's remediation plan.
    cpe23                 text NOT NULL,
    match_basis           text NOT NULL
                          CHECK (match_basis IN ('vendor+product+version',
                                                 'vendor+product',
                                                 'firmware-version')),

    -- ⚠ DEFAULTS TO 'low'. A default that flatters a guess is how an advisory
    -- becomes a claim somebody acts on.
    match_confidence      text NOT NULL DEFAULT 'low'
                          CHECK (match_confidence IN ('high', 'medium', 'low')),

    severity              text CHECK (severity IS NULL OR
                          severity IN ('critical','high','medium','low','none','unknown')),
    cvss_score            numeric(3,1) CHECK (cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10),
    cvss_vector           text,
    description           text,
    -- Where the match came from — `nvd` today. Named rather than assumed, so a
    -- second source later is a data change and not a schema one.
    source                text NOT NULL,
    -- The source's own version/date stamp. A finding that cannot be dated is
    -- not defensible.
    source_version        text,

    first_seen_at         timestamptz NOT NULL DEFAULT now(),

    -- One row per (component, cluster, CPE). The same CVE reached through two
    -- different CPEs is two pieces of evidence, not one.
    UNIQUE (hardware_component_id, cluster_id, cpe23)
);

CREATE INDEX hardware_findings_doc_idx       ON normalize.hardware_findings (bom_document_id);
CREATE INDEX hardware_findings_component_idx ON normalize.hardware_findings (hardware_component_id);
CREATE INDEX hardware_findings_cluster_idx   ON normalize.hardware_findings (cluster_id);
CREATE INDEX hardware_findings_tenant_idx    ON normalize.hardware_findings (tenant_id, bom_document_id);

-- CLAUDE.md invariant 6: a tenant-scoped table without a policy in the SAME
-- migration is incomplete, and TestRLSCoverage fails on any table without one.
SELECT app.enable_tenant_rls('normalize.hardware_findings');

-- Explicit, for the reason migration 0011 gives: ALTER DEFAULT PRIVILEGES is
-- recorded per grantor, and the failure mode is `permission denied for table`
-- on the first live match, at whatever hour that is.
GRANT SELECT, INSERT ON normalize.hardware_findings TO axebom_normalize_writer;

-- +goose Down
DROP TABLE IF EXISTS normalize.hardware_findings;
ALTER TABLE normalize.hardware_components
    DROP COLUMN IF EXISTS vuln_matched_at,
    DROP COLUMN IF EXISTS cpe23_candidates,
    DROP COLUMN IF EXISTS vuln_match_status;
