-- +goose Up
-- ===========================================================================
-- Three changes to normalize.bom_documents, all of them provenance:
--
--   1. supplementary_coverage — a home for scored, NON-compliance field sets,
--      so the manufacturing number can exist without touching the CERT-In one.
--   2. project_id            — HBOM's second, real lineage key.
--   3. alias_snapshot_id     — nullable, and given the FK it never had.
--
-- ⚠ THE BACKFILLS BELOW RUN AGAINST A FORCE-RLS TABLE.
--
-- normalize.bom_documents carries FORCE ROW LEVEL SECURITY, which applies to
-- the table OWNER as well — and migrations connect as the owner
-- (config.Postgres.AdminDSN). Today that role happens to be a superuser in
-- dev, so RLS is bypassed and an UPDATE would work by accident. Relying on
-- that is a trap: under a non-superuser owner the policy's
-- current_setting('app.current_tenant_id') is unset and every backfill below
-- would either raise or match zero rows — silently, in the zero-row case.
--
-- So FORCE is lifted for the length of this migration and restored at the
-- end. Owner-only DDL, works with or without superuser, and the table ends in
-- exactly the state TestRLSCoverage asserts.
-- ===========================================================================
ALTER TABLE normalize.bom_documents NO FORCE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- 1. supplementary_coverage — scored field sets that are NOT compliance.
--
-- ⚠ A KEYED jsonb, NOT A PAIR OF numeric COLUMNS, AND THE REASON IS THE POINT.
--
-- completeness_pct and declaration_pct are load-bearing precisely BECAUSE they
-- are the compliance numbers: `SELECT completeness_pct FROM bom_documents` is
-- a query somebody will write. Giving a non-compliance percentage the same
-- column shape one schema-tab away is exactly how it eventually gets picked up
-- by that query. A different column, a different key, and an `is_compliance:
-- false` field inside the document make that mistake require intent.
--
-- Keyed by profile id because the SET of profiles is data too — the same
-- reasoning as invariant 2, one level up. docs/06-COMPLIANCE-PROFILES.md
-- anticipates sibling profiles (NTIA, EU CRA, internal policy); each would
-- otherwise need its own migration and its own pair of columns.
--
--   {"hbom-manufacturing-v1": {"profile_id": …, "label": …,
--     "is_compliance": false, "completeness_pct": 41.3, …, "fields": [...]}}
--
-- Cost: no cheap ORDER BY. If that is ever needed, a b-tree expression index
-- over the extracted number. Not built now, because nothing sorts on it.
-- ---------------------------------------------------------------------------
ALTER TABLE normalize.bom_documents
    ADD COLUMN supplementary_coverage jsonb NOT NULL DEFAULT '{}'::jsonb;

-- ---------------------------------------------------------------------------
-- 2. project_id — the lineage key HBOM actually needs.
--
-- services/project/internal/store/hbom.go has always written
-- `scan_id = projectID` for HBOM documents, deliberately and with a comment
-- saying why: an imported hardware BOM has no scan to point at, and scan_id
-- has no FK precisely so it could be borrowed.
--
-- That substitution stops working the moment HBOM has REAL scans, because
-- then both meanings are live in one column. They do not collide — a real
-- scan id is never a project id, so nothing corrupts — but GetHardwareTree
-- resolves `WHERE scan_id = $projectID` and would therefore render a
-- freshly-scanned hardware BOM as "nothing imported yet".
--
-- ⚠ HBOM ONLY, AND ONLY BECAUSE scan_id LITERALLY HELD THE PROJECT ID. That
-- is true for no other bom_type, so no other row is touched: every other
-- document keeps project_id NULL and resolves by scan_id exactly as before.
--
-- This is not the duplicated-fact objection (invariant 1): it creates no
-- cross-schema JOIN, it REMOVES the need for one, and an HBOM document
-- genuinely has two provenances — the project it describes, and the scan (if
-- any) that produced it.
-- ---------------------------------------------------------------------------
ALTER TABLE normalize.bom_documents ADD COLUMN project_id uuid;

UPDATE normalize.bom_documents SET project_id = scan_id WHERE bom_type = 'HBOM';

CREATE INDEX bom_documents_project_idx
    ON normalize.bom_documents (tenant_id, project_id, bom_type, generated_at DESC)
    WHERE project_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 3. alias_snapshot_id — nullable, and given a real FK.
--
-- ⚠ THIS CLOSES THE ITEM THE 2026-08-26 AUDIT DELIBERATELY LEFT OPEN
-- "for a session with QBOM/HBOM in scope". That session wrote the FK, watched
-- it break 17 tests and two production paths, and reverted it — because
-- store/hbom.go, store/qbom.go and the CBOM/AIBOM pipelines all write a bare
-- app.uuid_v7()/uuid4() with no backing row. QBOM derives from CBOM and HBOM
-- is an import; neither runs the SBOM alias-closure pipeline this column was
-- designed for, so neither has a snapshot to point at.
--
-- ⚠ NULL, NOT A SHARED SENTINEL ROW. normalize.alias_snapshot has
-- edge_count/source/ruleset_version all NOT NULL, so a sentinel would carry
-- edge_count = 0 and every non-SBOM document would point at it — and a reader
-- who joins bom_documents -> alias_snapshot would get a row back and conclude
-- a snapshot was consulted. NULL says the true thing in the one way SQL has
-- for saying it. Invariant 3's rule is to state a gap rather than hide it; a
-- fabricated row ASSERTS something false, while NULL DECLINES TO ASSERT.
--
-- ⚠ AND NULLABLE-PLUS-FK IS STRICTLY STRONGER THAN WHAT IS THERE NOW. Today
-- the column is NOT NULL with NO FK: it enforces "some uuid is present" and
-- nothing whatever about whether it means anything — the weakest possible
-- combination. After this it enforces the thing that matters: IF a value is
-- present, it resolves. That is the identical gap migration 0007 closed for
-- findings.cluster_id.
-- ---------------------------------------------------------------------------
ALTER TABLE normalize.bom_documents ALTER COLUMN alias_snapshot_id DROP NOT NULL;

-- ⚠ SAFE BY CONSTRUCTION, NOT BY INSPECTION. This NULLs only ids with no
-- backing row — the fabricated ones. Any genuine, resolvable snapshot id
-- fails the NOT EXISTS and is untouched, so no real provenance can be
-- discarded by this statement even if the estimate of which rows are
-- fabricated is wrong.
UPDATE normalize.bom_documents b SET alias_snapshot_id = NULL
 WHERE alias_snapshot_id IS NOT NULL
   AND NOT EXISTS (
       SELECT 1 FROM normalize.alias_snapshot a WHERE a.id = b.alias_snapshot_id);

ALTER TABLE normalize.bom_documents
    ADD CONSTRAINT bom_documents_alias_snapshot_id_fkey
    FOREIGN KEY (alias_snapshot_id) REFERENCES normalize.alias_snapshot (id);

ALTER TABLE normalize.bom_documents FORCE ROW LEVEL SECURITY;

-- +goose Down
ALTER TABLE normalize.bom_documents NO FORCE ROW LEVEL SECURITY;

ALTER TABLE normalize.bom_documents
    DROP CONSTRAINT IF EXISTS bom_documents_alias_snapshot_id_fkey;

-- Restoring NOT NULL needs every NULL to become something. app.uuid_v7() is
-- what the pre-0012 writers used, so the down path reproduces exactly the
-- fabricated-id state this migration replaced — a faithful reversal, not a
-- better one.
UPDATE normalize.bom_documents SET alias_snapshot_id = app.uuid_v7()
 WHERE alias_snapshot_id IS NULL;
ALTER TABLE normalize.bom_documents ALTER COLUMN alias_snapshot_id SET NOT NULL;

DROP INDEX IF EXISTS normalize.bom_documents_project_idx;
ALTER TABLE normalize.bom_documents DROP COLUMN IF EXISTS project_id;
ALTER TABLE normalize.bom_documents DROP COLUMN IF EXISTS supplementary_coverage;

ALTER TABLE normalize.bom_documents FORCE ROW LEVEL SECURITY;
