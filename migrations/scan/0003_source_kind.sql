-- +goose Up
-- ===========================================================================
-- scans.source_kind — what KIND of input this scan reads.
--
-- WHY IT MUST BE ON THE SCAN AND NOT LOOKED UP:
--
-- The orchestrator needs it to validate engine/source combinations at create
-- time and to tell the fetcher what to materialize. The obvious source is
-- project.projects.source_type — but that is ANOTHER SCHEMA, and cross-schema
-- JOINs are forbidden (CLAUDE.md invariant 11, ADR-0001). A cross-service call
-- in the create path would also make every scan depend on the project service
-- being up.
--
-- So it is denormalized here, captured at create time. That is also more
-- correct: a project whose source_type changes later must not retroactively
-- change what an old scan says it scanned.
--
-- Recorded in docs/01-DATA-MODEL.md §3, which is the SSOT for schema.
-- ===========================================================================

ALTER TABLE scan.scans
    ADD COLUMN source_kind text NOT NULL DEFAULT 'git'
        CHECK (source_kind IN ('git', 'upload', 'image'));

COMMENT ON COLUMN scan.scans.source_kind IS
'Denormalized from the project at create time. Not looked up: cross-schema
JOINs are forbidden, and a project changing source_type later must not
retroactively change what an old scan claims to have scanned.';

-- The default exists only so the column can be added NOT NULL to existing
-- rows. New scans always set it explicitly.
ALTER TABLE scan.scans ALTER COLUMN source_kind DROP DEFAULT;

-- +goose Down
ALTER TABLE scan.scans DROP COLUMN IF EXISTS source_kind;
