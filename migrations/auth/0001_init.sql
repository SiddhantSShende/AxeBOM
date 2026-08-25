-- +goose Up
-- ===========================================================================
-- auth — identity, tenancy root, membership, sessions, audit.
-- Implements docs/01-DATA-MODEL.md §1.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- tenants — the tenancy ROOT. Deliberately NOT RLS-protected: it is the thing
-- every policy keys on. Access is gated at the application layer by membership.
-- ---------------------------------------------------------------------------
CREATE TABLE auth.tenants (
    id          uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    name        text NOT NULL,
    slug        text NOT NULL UNIQUE,
    plan        text NOT NULL DEFAULT 'free'
                CHECK (plan IN ('free', 'team', 'enterprise')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    deleted_at  timestamptz
);

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON auth.tenants
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

-- ---------------------------------------------------------------------------
-- users — GLOBAL, not tenant-scoped.
--
-- One identity may belong to several tenants; membership binds them. That is
-- why there is no tenant_id here and no RLS policy.
--
-- The trade-off, stated plainly: the app role can read any user row. The
-- mitigation is that application code reaches users only through a membership
-- join, never by scanning this table. TestRLSCoverage carries an explicit,
-- reasoned exemption for it rather than silently skipping it.
-- ---------------------------------------------------------------------------
CREATE TABLE auth.users (
    id              uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    email           citext NOT NULL UNIQUE,
    name            text,
    -- argon2id. NULL for SSO-only users, who have no password to verify.
    password_hash   text,
    github_login    text,
    -- Key on the NUMERIC id, never the login: GitHub logins are renameable and
    -- reassignable, so keying on the login lets an attacker who claims a freed
    -- username inherit the account.
    github_user_id  bigint UNIQUE,
    auth_provider   text NOT NULL DEFAULT 'local'
                    CHECK (auth_provider IN ('local', 'github', 'oidc', 'saml')),
    status          text NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'invited', 'suspended')),
    last_login_at   timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz
);

CREATE INDEX users_github_login_idx ON auth.users (github_login)
    WHERE github_login IS NOT NULL;

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON auth.users
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

-- ---------------------------------------------------------------------------
-- memberships — binds a global user to a tenant with a role.
-- ---------------------------------------------------------------------------
CREATE TABLE auth.memberships (
    id           uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id    uuid NOT NULL REFERENCES auth.tenants (id) ON DELETE CASCADE,
    user_id      uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    role         text NOT NULL
                 CHECK (role IN ('owner', 'admin', 'analyst', 'viewer')),
    invited_by   uuid REFERENCES auth.users (id) ON DELETE SET NULL,
    invited_at   timestamptz,
    accepted_at  timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, user_id)
);

-- tenant_id first: RLS appends its predicate to every query, so the tenant
-- column belongs at the front of composite indexes. That is the right order
-- for the application's access patterns anyway.
CREATE INDEX memberships_tenant_user_idx ON auth.memberships (tenant_id, user_id);
CREATE INDEX memberships_user_idx        ON auth.memberships (user_id);

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON auth.memberships
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

SELECT app.enable_tenant_rls('auth.memberships');

-- ---------------------------------------------------------------------------
-- sessions — refresh-token families.
--
-- Only the HASH is stored. A database read must not yield a usable token.
-- ---------------------------------------------------------------------------
CREATE TABLE auth.sessions (
    id                  uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id           uuid NOT NULL REFERENCES auth.tenants (id) ON DELETE CASCADE,
    user_id             uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    refresh_token_hash  text NOT NULL UNIQUE,
    -- Reuse of a rotated refresh token means it was stolen. family_id lets
    -- Phase 3 revoke the whole chain rather than the single leaked token.
    family_id           uuid NOT NULL,
    user_agent          text,
    ip                  inet,
    expires_at          timestamptz NOT NULL,
    revoked_at          timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sessions_tenant_user_idx ON auth.sessions (tenant_id, user_id);
CREATE INDEX sessions_family_idx      ON auth.sessions (family_id);
CREATE INDEX sessions_expiry_idx      ON auth.sessions (expires_at)
    WHERE revoked_at IS NULL;

SELECT app.enable_tenant_rls('auth.sessions');

-- ---------------------------------------------------------------------------
-- audit_log — APPEND-ONLY. Required by CERT-In §5.3.6 (p.33).
--
-- tenant_id is nullable because pre-authentication events (a failed login for
-- an unknown email) belong to no tenant, so this uses the asymmetric policy:
-- writable with NULL, readable only within a tenant.
-- ---------------------------------------------------------------------------
CREATE TABLE auth.audit_log (
    id             uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id      uuid REFERENCES auth.tenants (id) ON DELETE SET NULL,
    actor_user_id  uuid REFERENCES auth.users (id) ON DELETE SET NULL,
    action         text NOT NULL,
    entity_type    text,
    entity_id      uuid,
    -- Never contains secrets or full request bodies. The redaction filter in
    -- platform/obs covers logs; this column is written deliberately, so the
    -- discipline is at the call site.
    metadata       jsonb NOT NULL DEFAULT '{}'::jsonb,
    ip             inet,
    user_agent     text,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_tenant_created_idx ON auth.audit_log (tenant_id, created_at DESC);
CREATE INDEX audit_log_actor_idx          ON auth.audit_log (actor_user_id, created_at DESC);
CREATE INDEX audit_log_action_idx         ON auth.audit_log (action, created_at DESC);
CREATE INDEX audit_log_entity_idx         ON auth.audit_log (entity_type, entity_id);

SELECT app.enable_tenant_rls_nullable('auth.audit_log');

-- APPEND-ONLY BY GRANT, not by convention.
--
-- The default privileges from the bootstrap migration granted UPDATE and
-- DELETE; revoke them here. A convention is something an ORM will cheerfully
-- ignore; a missing grant is not.
REVOKE UPDATE, DELETE ON auth.audit_log FROM axebom_app;

-- +goose Down
DROP TABLE IF EXISTS auth.audit_log;
DROP TABLE IF EXISTS auth.sessions;
DROP TABLE IF EXISTS auth.memberships;
DROP TABLE IF EXISTS auth.users;
DROP TABLE IF EXISTS auth.tenants;
