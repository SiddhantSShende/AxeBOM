-- +goose Up
-- ===========================================================================
-- scan.scans.source_kind gains 'url' — the fourth SourceKind
-- (libs/go-shared/events/events.go), denormalized from the project's
-- source_type at scan-create time exactly as 'git'/'upload'/'image' already
-- are (see 0003_source_kind.sql's own header for why this is denormalized
-- rather than looked up across the schema boundary).
-- ===========================================================================

ALTER TABLE scan.scans
    DROP CONSTRAINT scans_source_kind_check;

ALTER TABLE scan.scans
    ADD CONSTRAINT scans_source_kind_check
        CHECK (source_kind IN ('git', 'upload', 'image', 'url'));

-- +goose Down
ALTER TABLE scan.scans
    DROP CONSTRAINT scans_source_kind_check;

ALTER TABLE scan.scans
    ADD CONSTRAINT scans_source_kind_check
        CHECK (source_kind IN ('git', 'upload', 'image'));
