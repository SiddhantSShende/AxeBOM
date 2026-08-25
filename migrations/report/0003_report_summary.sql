-- +goose Up
-- ===========================================================================
-- report.reports — the summary a finished render actually produced.
--
-- ⚠ THIS CLOSES A REAL GAP, NOT A COSMETIC ONE.
--
-- Before this migration, `report.reports` recorded ONLY artifact-storage
-- metadata (storage_ref, sha256, signature…). The worker builds a complete
-- render.BOM — project name, coverage numbers, engine coverage, the
-- ecosystems nothing could scan — entirely in memory to produce the PDF/XLSX
-- bytes, and then threw all of it away the moment the artifact was stored.
-- `GET /v1/reports/{id}` had nothing to serve but the artifact's own
-- metadata, so the report VIEWER — the one screen whose entire job is
-- CLAUDE.md invariant 3 (both coverage numbers, always) and invariant 12
-- (every report states what it could not see) — could never show either.
--
-- These columns are populated exactly once, by report.MarkReady, from the
-- SAME in-memory render.BOM that produced the artifact bytes — never
-- re-queried from the normalizer afterward. That is deliberate: it is what
-- was actually rendered into the file this row now points at, and re-reading
-- the normalizer later could race a concurrent re-normalization and disagree
-- with the artifact already in object storage.
-- ===========================================================================

ALTER TABLE report.reports
    ADD COLUMN project_name              text,
    -- The BOM's own generated_at (the scan's time, RFC3339) — distinct from
    -- this row's created_at/updated_at, which describe the RENDER request,
    -- not the data inside it. A re-render must not claim to describe today.
    ADD COLUMN bom_generated_at          timestamptz,
    -- What a Top-Level/Complete projection left out (level.Project's note).
    -- Never populated before this either — the level callout on the viewer
    -- had nothing to show.
    ADD COLUMN level_note                text,

    ADD COLUMN completeness_pct         double precision,
    ADD COLUMN declaration_pct          double precision,
    ADD COLUMN coverage_formula         text,
    -- One row per profile field: {field_id, name, present, declared, total,
    -- weight, source_page}. A default of '[]', not NULL: unlike the pct
    -- columns above (NULL means "not yet rendered"), an empty breakdown is a
    -- valid completed answer for a BOM type with nothing to score.
    ADD COLUMN coverage_fields          jsonb NOT NULL DEFAULT '[]'::jsonb,
    -- One row per requested engine: {engine_id, version, status,
    -- database_version, ecosystems, diagnostic}. Mandatory content
    -- (CLAUDE.md invariant 12), captured verbatim from render.BOM.Engines.
    ADD COLUMN engine_coverage          jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN ecosystems_with_no_engine text[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN report.reports.completeness_pct IS
'NULL until the render that produced this row completes. NULL is not zero: a
report still queued or rendering has not been scored at all, and 0.00% would
read as "scored, and failed" rather than "not yet measured".';

-- +goose Down
ALTER TABLE report.reports
    DROP COLUMN project_name,
    DROP COLUMN bom_generated_at,
    DROP COLUMN level_note,
    DROP COLUMN completeness_pct,
    DROP COLUMN declaration_pct,
    DROP COLUMN coverage_formula,
    DROP COLUMN coverage_fields,
    DROP COLUMN engine_coverage,
    DROP COLUMN ecosystems_with_no_engine;
