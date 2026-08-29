-- +goose Up
-- ===========================================================================
-- project.web_sources — a project registered by URL rather than a
-- repository connection or an upload.
--
-- Mirrors repository_connections and uploads exactly, minus the credential
-- path: nothing here is ever authenticated. GET-ing an arbitrary public URL
-- and, for a matching host, running subdomain discovery against it
-- (Milestone 5, services/webrecon) needs no token at all.
--
-- discovery_enabled and max_hosts are the abuse-guard knobs Milestone 5's
-- subfinder pass reads. They exist from this migration onward even though
-- nothing consumes them yet, so that milestone is a pure application change,
-- not a schema change bundled with it.
-- ===========================================================================

CREATE TABLE project.web_sources (
    id                uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id         uuid NOT NULL,
    project_id        uuid NOT NULL REFERENCES project.projects (id) ON DELETE CASCADE,

    root_url          text NOT NULL,

    -- Whether Milestone 5's subdomain-discovery pass may run at all for this
    -- project. Defaulting true keeps the common case a one-field form; a
    -- tenant who wants only the single submitted page scanned can turn it
    -- off per project.
    discovery_enabled boolean NOT NULL DEFAULT true,
    -- The hard ceiling on how many discovered hosts a scan may fetch.
    -- Registering a project "by URL" auto-discovers hosts the tenant never
    -- individually named — a confused-deputy/amplification surface distinct
    -- from SSRF, which this bounds regardless of what subfinder returns.
    max_hosts         int NOT NULL DEFAULT 25 CHECK (max_hosts BETWEEN 1 AND 100),

    last_scanned_at   timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX web_sources_tenant_project_idx ON project.web_sources (tenant_id, project_id);

SELECT app.enable_tenant_rls('project.web_sources');

-- +goose Down
DROP TABLE IF EXISTS project.web_sources;
