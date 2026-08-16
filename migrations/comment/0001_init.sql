-- +goose Up
-- ===========================================================================
-- comment — threaded discussion on reports.
-- Implements docs/01-DATA-MODEL.md §8 (comments).
-- ===========================================================================

CREATE TABLE comment.comments (
    id          uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id   uuid NOT NULL,
    report_id   uuid NOT NULL,   -- -> report.reports.id, no FK (cross-schema)
    user_id     uuid NOT NULL,   -- -> auth.users.id, no FK

    parent_id   uuid REFERENCES comment.comments (id) ON DELETE CASCADE,
    -- Depth is capped at 5 by the application. Unbounded nesting makes a
    -- thread unreadable and the recursive query unbounded.
    depth       int NOT NULL DEFAULT 0 CHECK (depth >= 0 AND depth <= 5),

    body        text NOT NULL,

    edited_at   timestamptz,
    deleted_at  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT comment_not_own_parent CHECK (parent_id IS NULL OR parent_id <> id)
);

CREATE INDEX comments_report_idx ON comment.comments (report_id, created_at)
    WHERE deleted_at IS NULL;
CREATE INDEX comments_parent_idx ON comment.comments (parent_id);
CREATE INDEX comments_tenant_idx ON comment.comments (tenant_id);

SELECT app.enable_tenant_rls('comment.comments');

-- +goose Down
DROP TABLE IF EXISTS comment.comments;
