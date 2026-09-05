-- +goose Up
-- ===========================================================================
-- project.github_connections — connect GitHub once, not once per project.
--
-- ⚠ BEFORE THIS, EVERY REGISTRATION OPENED ITS OWN OAUTH POPUP. `useGitHubConnect`
-- opens a popup, receives a repo-scoped token by postMessage, hands it to the
-- repo picker and then to `POST /v1/projects/{id}/connections`, which writes it
-- to Vault against that ONE connection. Nothing kept it. So registering three
-- projects meant authorising GitHub three times, and every repo search sent the
-- token back out through the browser again.
--
-- This table records that a tenant has connected GitHub, and WHERE the token
-- lives. It is not the token: `credential_ref` is a Vault path, exactly as
-- project.repository_connections.credential_ref is, so the secret keeps living
-- in one place and Postgres keeps holding none.
--
-- ⚠ ONE ROW PER TENANT, BY PRIMARY KEY. A second connection would mean two
-- tokens with different scopes and no rule for which one a repo search should
-- use — the kind of ambiguity that gets resolved differently in two places.
-- Reconnecting REPLACES the row and overwrites the secret at the same path.
--
-- ⚠ NO FK TO auth.users ON connected_by. Schema-per-service (invariant 11):
-- the user lives in another service's schema and a cross-schema FK is exactly
-- the coupling that makes a service unextractable. The id is recorded for the
-- audit question "who connected this?" and resolved in Go if it is ever needed.
CREATE TABLE project.github_connections (
    tenant_id      uuid        PRIMARY KEY,
    -- The Vault path holding the token. Never the token.
    credential_ref text        NOT NULL,
    -- The GitHub account the authorisation belongs to, shown so a customer can
    -- tell whose access their scans are using before a scan depends on it.
    github_login   text        NOT NULL DEFAULT '',
    connected_by   uuid        NOT NULL,
    connected_at   timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON project.github_connections
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

SELECT app.enable_tenant_rls('project.github_connections');

-- +goose Down
DROP TABLE IF EXISTS project.github_connections;
