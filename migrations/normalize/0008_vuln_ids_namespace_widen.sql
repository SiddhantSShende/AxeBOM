-- +goose Up
-- ===========================================================================
-- vuln_ids.namespace was missing five namespaces
-- libs/py-shared/axebom_shared/normalize/aliases.py's own _NAMESPACE_RANK
-- already treats as valid vulnerability-id namespaces: GO, PYSEC, RUSTSEC
-- (osv-scanner's ecosystem-native ids — its own module docstring: "osv-
-- scanner emits OSV-native (GO-, PYSEC-, RUSTSEC-)"), GSD, and MAL.
--
-- Found while wiring cluster_store.py (ADR-0005's durable persistence):
-- osv-scanner is one of exactly two finding-emitting engines, and a real
-- osv-scanner scan against a Go or Rust project routinely reports GO-/
-- RUSTSEC- native ids as the PRIMARY vulnerability id, not just as an
-- alias. Every one of those inserts into normalize.vuln_ids would have
-- failed this CHECK constraint the moment cluster persistence went live —
-- a silent gap until then, because nothing had ever written to this table
-- outside migrations and RLS-coverage tests.
--
-- aliases.py's _NAMESPACE_RANK is the SSOT for the namespace vocabulary
-- (CLAUDE.md invariant 1); this constraint is widened to match it exactly
-- rather than drifting its own, second list.
-- ===========================================================================
ALTER TABLE normalize.vuln_ids DROP CONSTRAINT vuln_ids_namespace_check;

ALTER TABLE normalize.vuln_ids ADD CONSTRAINT vuln_ids_namespace_check
    CHECK (namespace IN ('CVE','GHSA','OSV','GO','PYSEC','RUSTSEC','GSD','MAL',
                          'SNYK','RHSA','DSA','USN','ALAS','ELSA','DLA','NPM'));

-- +goose Down
ALTER TABLE normalize.vuln_ids DROP CONSTRAINT vuln_ids_namespace_check;

ALTER TABLE normalize.vuln_ids ADD CONSTRAINT vuln_ids_namespace_check
    CHECK (namespace IN ('CVE','GHSA','OSV','SNYK','RHSA','DSA',
                          'USN','ALAS','ELSA','DLA','NPM'));
