-- +goose Up
-- ===========================================================================
-- normalize.bom_documents.normalize_diagnostics — what normalization could not
-- do, stored where the report can read it.
--
-- ⚠ EVERY NORMALIZE-TIME DIAGNOSTIC IN THE PRODUCT WAS BEING COMPUTED AND
-- THROWN AWAY. `workers/{aibom,cbom,hbom}/normalize_consumer.py` each end with
--
--     canonical["diagnostics"] = [*canonical.get("diagnostics", []), *diagnostics]
--
-- and `writer.write_bom_document` never read that key. Its INSERT names
-- thirteen columns and none of them is this one, so the list died at the
-- function boundary. Nothing outside a test has ever consumed it.
--
-- That is a direct CLAUDE.md invariant 12 failure ("every report states what it
-- could not see"). Two concrete losses it was hiding, both reachable today:
--
--   AIBOM_MODEL_RECLASSIFIED     a component the engine called a model, stored
--                                as a dependency instead — the reason a
--                                customer's model count changes
--   AIBOM_DEPENDENCY_NOT_IN_SBOM a dependency the SBOM scan never catalogued,
--                                which `link_dependencies` drops from
--                                `_dependencies` rather than storing
--
-- On real captured `ai-bom` output the two together mean two Python libraries
-- appear in NEITHER the model list nor the dependency list, with nothing in the
-- report saying so. An unexplained count is worse than a wrong one: the reader
-- cannot even tell there is a question.
--
-- ⚠ NOT AN ERROR LOG. These are statements about the BOM's own completeness and
-- belong to the document, which is why they live here rather than beside
-- `scan.engine_runs.diagnostics` (engine-level, already rendered in Engine
-- Coverage). A document carries both; they answer different questions.
--
-- Append-only in practice: a re-normalization writes a NEW document version
-- (invariant 10), so this column is written once with the row and never updated.
-- ===========================================================================

ALTER TABLE normalize.bom_documents
    ADD COLUMN normalize_diagnostics jsonb NOT NULL DEFAULT '[]'::jsonb;

COMMENT ON COLUMN normalize.bom_documents.normalize_diagnostics IS
    'Document-level normalization diagnostics: what this BOM could not resolve, and why. Rendered; never silently dropped.';

-- +goose Down
ALTER TABLE normalize.bom_documents
    DROP COLUMN IF EXISTS normalize_diagnostics;
