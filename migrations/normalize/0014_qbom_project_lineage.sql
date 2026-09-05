-- +goose Up
-- ===========================================================================
-- QBOM documents get the project lineage HBOM already has.
--
-- ⚠ THIS CLOSES A DEFECT IN WHICH **EVERY QBOM REPORT FAILED**, without
-- exception, since QBOM reports first became renderable.
--
-- The two halves were built independently and never reconciled:
--
--   WRITER  services/project/internal/store/qbom.go wrote `scan_id = projectID`
--           and no project_id at all — borrowing scan_id exactly as HBOM did,
--           for exactly the same honest reason (a device form has no scan to
--           point at, and scan_id has no FK precisely so it could be borrowed).
--
--   READER  services/report/internal/store/bomsource.go resolves
--           `WHERE scan_id = $1` bound to the REPORT's real scan id, and
--           frontend GenerateFlow posts that real scan id for every selected
--           bom_type — QBOM included.
--
-- A real scan id is never a project id, so the lookup could never match. The
-- user saw "some reports could not be rendered"; the row said
-- NOTFOUND_RESOURCE, "no normalized QBOM exists for this scan".
--
-- Migration 0012 introduced project_id and backfilled `WHERE bom_type = 'HBOM'`
-- only, and said so in as many words — correctly, because HBOM was the only
-- type whose scan_id literally held a project id AT THAT TIME. QBOM has the
-- same shape and was missed. This is the other half of that backfill.
--
-- ⚠ QBOM ONLY. Every other bom_type keeps project_id NULL and resolves by
-- scan_id exactly as before. SBOM/CBOM/AIBOM documents are produced by real
-- scans and their scan_id means what it says.
-- ===========================================================================

UPDATE normalize.bom_documents
   SET project_id = scan_id
 WHERE bom_type = 'QBOM'
   AND project_id IS NULL;

-- +goose Down
-- ⚠ NULLS ONLY THE ROWS THIS MIGRATION SET, NOT EVERY QBOM ROW. After the
-- down-migration the application writes project_id on new QBOM documents
-- anyway (store/qbom.go), so blanket-NULLing would destroy lineage this
-- migration never created.
UPDATE normalize.bom_documents
   SET project_id = NULL
 WHERE bom_type = 'QBOM'
   AND project_id = scan_id;
