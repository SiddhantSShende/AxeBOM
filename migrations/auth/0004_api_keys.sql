-- +goose Up
-- ===========================================================================
-- API keys — Phase 16. `libs/go-shared/auth/apikey.go` already has the full
-- pure logic (Mint/Verify/AuthorizeKey, scopes, expiry); this migration is
-- the storage it never had, which is why nothing has been able to call it.
--
-- THE PROBLEM: an API key is a pre-tenant credential, same shape as login
-- (migrations/auth/0002). A caller presents ONLY the key; the tenant is what
-- verification is supposed to recover, so it cannot be a precondition of the
-- lookup. The same fix applies: one narrow SECURITY DEFINER function, keyed
-- on the plaintext id segment, not the whole table opened up.
--
-- docs/05-SECURITY-MODEL.md §6, docs/ADR/0006-rls-tenancy.md
-- ===========================================================================

CREATE TABLE auth.api_keys (
    id            uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id     uuid NOT NULL REFERENCES auth.tenants (id) ON DELETE CASCADE,

    name          text NOT NULL,

    -- The plaintext identifying segment (e.g. "a1b2c3d4e5f6"). Globally
    -- unique, NOT per-tenant: the lookup runs before the tenant is known, so
    -- the id space has to be able to answer "whose key is this" on its own.
    key_id        text NOT NULL UNIQUE,

    -- SHA-256 of the full presented key. Never the key itself — see
    -- apikey.go's own doc comment on why this is a fast hash, not Argon2.
    hash          text NOT NULL,

    scopes        text[] NOT NULL CHECK (array_length(scopes, 1) > 0),

    created_by    uuid NOT NULL REFERENCES auth.users (id) ON DELETE RESTRICT,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    last_used_at  timestamptz,
    revoked_at    timestamptz
);

CREATE INDEX api_keys_tenant_idx ON auth.api_keys (tenant_id, created_at DESC);

SELECT app.enable_tenant_rls('auth.api_keys');

-- ---------------------------------------------------------------------------
-- api_key_by_key_id
--
-- Pre-tenant lookup by the plaintext id segment — the same shape as
-- auth.memberships_for_user and auth.session_by_refresh_hash. Returns the
-- HASH, never the plaintext key (which this table never stores), so the
-- caller can run auth.Verify() itself without a second round trip.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth.api_key_by_key_id(p_key_id text)
RETURNS TABLE (
    id           uuid,
    tenant_id    uuid,
    name         text,
    key_id       text,
    hash         text,
    scopes       text[],
    expires_at   timestamptz,
    revoked_at   timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER            -- runs as the OWNER, so RLS does not apply
SET search_path = auth, pg_temp   -- pin: a mutable search_path on a
                                  -- SECURITY DEFINER function is a privilege
                                  -- escalation vector
AS $fn$
    SELECT k.id, k.tenant_id, k.name, k.key_id, k.hash, k.scopes,
           k.expires_at, k.revoked_at
      FROM auth.api_keys k
     WHERE k.key_id = p_key_id;
$fn$;
-- +goose StatementEnd

COMMENT ON FUNCTION auth.api_key_by_key_id(text) IS
'Pre-tenant API-key lookup. SECURITY DEFINER because request authentication
must discover which tenant a key belongs to BEFORE app.current_tenant_id can
be set. Deliberately narrow: takes one key id, returns only that row. Do not
widen it.';

GRANT EXECUTE ON FUNCTION auth.api_key_by_key_id(text) TO axebom_app;

-- +goose Down
DROP FUNCTION IF EXISTS auth.api_key_by_key_id(text);
DROP TABLE IF EXISTS auth.api_keys;
