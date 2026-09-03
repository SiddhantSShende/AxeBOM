-- +goose Up
-- ===========================================================================
-- vuln_ids.namespace was still missing one value:
-- libs/py-shared/axebom_shared/normalize/aliases.py's own _NAMESPACE_RANK
-- now treats "BIT" as a valid vulnerability-id namespace.
--
-- Found live, not assumed: a real osv-scanner run against a real registered
-- Go project (this codebase's own end-to-end verification, not a fixture)
-- reported a vulnerability whose primary id was "BIT-GOLANG-<year>-<n>" —
-- OSV.dev aggregates Bitnami's own per-image advisory database, whose ids
-- carry this prefix. cluster_store.py's persist_clusters crashed on the
-- INSERT with a CheckViolation, which normalize_consumer.py treats as a
-- permanent failure — silently dropping that scan's entire normalized SBOM,
-- not just the one vulnerability. This is the exact gap
-- 0008_vuln_ids_namespace_widen.sql fixed for GO/PYSEC/RUSTSEC/GSD/MAL: one
-- more real-world namespace this constraint hadn't been hit by yet.
--
-- aliases.py's _NAMESPACE_RANK is the SSOT for the namespace vocabulary
-- (CLAUDE.md invariant 1); this constraint is widened to match it exactly
-- rather than drifting its own, second list.
-- ===========================================================================
ALTER TABLE normalize.vuln_ids DROP CONSTRAINT vuln_ids_namespace_check;

ALTER TABLE normalize.vuln_ids ADD CONSTRAINT vuln_ids_namespace_check
    CHECK (namespace IN ('CVE','GHSA','OSV','GO','PYSEC','RUSTSEC','GSD','MAL',
                          'SNYK','RHSA','DSA','USN','ALAS','ELSA','DLA','NPM',
                          'BIT'));

-- +goose Down
ALTER TABLE normalize.vuln_ids DROP CONSTRAINT vuln_ids_namespace_check;

ALTER TABLE normalize.vuln_ids ADD CONSTRAINT vuln_ids_namespace_check
    CHECK (namespace IN ('CVE','GHSA','OSV','GO','PYSEC','RUSTSEC','GSD','MAL',
                          'SNYK','RHSA','DSA','USN','ALAS','ELSA','DLA','NPM'));
