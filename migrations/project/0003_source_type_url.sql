-- +goose Up
-- ===========================================================================
-- project.projects.source_type gains 'url' — a project registered from a
-- live link rather than a repository connection or an upload. Its source
-- lives in the new project.web_sources table (0002_web_sources.sql), the
-- same relationship upload has to project.uploads and github/gitlab/
-- bitbucket have to project.repository_connections.
--
-- Additive, backward compatible: every existing row keeps its current value,
-- and every existing reader of this column is unaffected until something
-- actually writes 'url'.
-- ===========================================================================

ALTER TABLE project.projects
    DROP CONSTRAINT projects_source_type_check;

ALTER TABLE project.projects
    ADD CONSTRAINT projects_source_type_check
        CHECK (source_type IN ('github', 'gitlab', 'bitbucket',
                                'upload', 'image', 'manual', 'url'));

-- +goose Down
ALTER TABLE project.projects
    DROP CONSTRAINT projects_source_type_check;

ALTER TABLE project.projects
    ADD CONSTRAINT projects_source_type_check
        CHECK (source_type IN ('github', 'gitlab', 'bitbucket',
                                'upload', 'image', 'manual'));
