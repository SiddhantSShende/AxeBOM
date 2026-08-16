-- +goose Up
-- ===========================================================================
-- Pre-tenant login lookup.
--
-- THE PROBLEM: RLS keys every tenant-scoped table on app.current_tenant_id,
-- and auth.memberships is tenant-scoped. But LOGIN HAPPENS BEFORE A TENANT IS
-- KNOWN — the whole point of the lookup is to discover which tenants a user
-- belongs to. A normal query fails closed (current_setting raises), which is
-- correct behaviour that happens to block the one legitimate case.
--
-- THE WRONG FIXES, and why:
--
--   * Drop RLS from auth.memberships   -> membership IS tenant data; any
--                                         tenant could then enumerate another's
--                                         users.
--   * Give the app role BYPASSRLS      -> disables every policy in the
--                                         database, everywhere, forever.
--   * Connect as the owner for login   -> same, with extra steps.
--
-- THE FIX: one narrow SECURITY DEFINER function that returns memberships FOR A
-- SINGLE USER ID and nothing else. It is a deliberate, reviewable hole of
-- exactly the shape the problem requires, rather than a broad one.
--
-- docs/05-SECURITY-MODEL.md §2, docs/ADR/0006-rls-tenancy.md
-- ===========================================================================

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth.memberships_for_user(p_user_id uuid)
RETURNS TABLE (
    tenant_id    uuid,
    tenant_name  text,
    tenant_slug  text,
    role         text,
    accepted_at  timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER            -- runs as the OWNER, so RLS does not apply
SET search_path = auth, pg_temp   -- pin: a mutable search_path on a
                                  -- SECURITY DEFINER function is a privilege
                                  -- escalation vector
AS $fn$
    SELECT m.tenant_id,
           t.name,
           t.slug,
           m.role,
           m.accepted_at
      FROM auth.memberships m
      JOIN auth.tenants t ON t.id = m.tenant_id
     WHERE m.user_id = p_user_id
       AND m.accepted_at IS NOT NULL
       AND t.deleted_at IS NULL
     ORDER BY m.created_at;
$fn$;
-- +goose StatementEnd

COMMENT ON FUNCTION auth.memberships_for_user(uuid) IS
'Pre-tenant login lookup. SECURITY DEFINER because login must discover a
user''s tenants BEFORE app.current_tenant_id can be set. Deliberately narrow:
takes one user id, returns only that user''s accepted memberships. Do not widen
it — every added parameter is a new way to read across tenants.';

-- The application role may call it, but the underlying tables stay protected.
GRANT EXECUTE ON FUNCTION auth.memberships_for_user(uuid) TO encorebom_app;

-- ---------------------------------------------------------------------------
-- Session lookup by refresh-token hash.
--
-- Same shape of problem: a refresh request presents ONLY a token. The tenant
-- is what we are trying to recover, so it cannot be a precondition.
--
-- Returns the session and its family so the caller can detect REUSE: presenting
-- an already-rotated token means two parties hold it, and since we cannot tell
-- which is legitimate, the whole family is revoked.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth.session_by_refresh_hash(p_hash text)
RETURNS TABLE (
    session_id  uuid,
    tenant_id   uuid,
    user_id     uuid,
    family_id   uuid,
    expires_at  timestamptz,
    revoked_at  timestamptz,
    role        text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = auth, pg_temp
AS $fn$
    SELECT s.id, s.tenant_id, s.user_id, s.family_id,
           s.expires_at, s.revoked_at, m.role
      FROM auth.sessions s
      JOIN auth.memberships m
        ON m.tenant_id = s.tenant_id AND m.user_id = s.user_id
     WHERE s.refresh_token_hash = p_hash;
$fn$;
-- +goose StatementEnd

COMMENT ON FUNCTION auth.session_by_refresh_hash(text) IS
'Pre-tenant refresh lookup. Takes a token HASH (never a plaintext token) and
returns one session. Returns revoked_at so the caller can detect reuse of an
already-rotated token, which indicates theft.';

GRANT EXECUTE ON FUNCTION auth.session_by_refresh_hash(text) TO encorebom_app;

-- ---------------------------------------------------------------------------
-- Family revocation.
--
-- Called when a rotated refresh token is presented a second time. We cannot
-- distinguish the thief from the legitimate holder, so BOTH lose the session.
-- Forcing a re-login is the correct trade against leaving a thief authenticated.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth.revoke_session_family(p_family_id uuid)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = auth, pg_temp
AS $fn$
DECLARE
    n integer;
BEGIN
    UPDATE auth.sessions
       SET revoked_at = now()
     WHERE family_id = p_family_id
       AND revoked_at IS NULL;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$fn$;
-- +goose StatementEnd

GRANT EXECUTE ON FUNCTION auth.revoke_session_family(uuid) TO encorebom_app;

-- ---------------------------------------------------------------------------
-- Pre-tenant audit write.
--
-- A failed login for an unknown email belongs to NO tenant, but must still be
-- recorded (CERT-In §5.3.6). The nullable-tenant RLS policy already permits
-- writing NULL; this function exists so the write does not need a tenant scope
-- it cannot have.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth.record_auth_event(
    p_tenant_id  uuid,
    p_actor      uuid,
    p_action     text,
    p_metadata   jsonb,
    p_ip         inet,
    p_user_agent text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = auth, pg_temp
AS $fn$
DECLARE
    new_id uuid;
BEGIN
    INSERT INTO auth.audit_log
        (tenant_id, actor_user_id, action, metadata, ip, user_agent)
    VALUES
        (p_tenant_id, p_actor, p_action, COALESCE(p_metadata, '{}'::jsonb), p_ip, p_user_agent)
    RETURNING id INTO new_id;
    RETURN new_id;
END;
$fn$;
-- +goose StatementEnd

COMMENT ON FUNCTION auth.record_auth_event(uuid, uuid, text, jsonb, inet, text) IS
'Append-only auth audit write. SECURITY DEFINER so pre-authentication events
(a failed login for an unknown email) can be recorded without a tenant scope.
INSERT only — the audit log has no UPDATE or DELETE grant.';

GRANT EXECUTE ON FUNCTION auth.record_auth_event(uuid, uuid, text, jsonb, inet, text) TO encorebom_app;

-- ---------------------------------------------------------------------------
-- Invitations.
--
-- A separate table rather than a pre-created membership row: an invite may be
-- to an email that has no user yet, and a membership needs a user_id.
-- ---------------------------------------------------------------------------
CREATE TABLE auth.invitations (
    id          uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id   uuid NOT NULL REFERENCES auth.tenants (id) ON DELETE CASCADE,
    email       citext NOT NULL,
    role        text NOT NULL CHECK (role IN ('owner','admin','analyst','viewer')),

    -- Only the HASH. An invite token grants tenant access, so a database read
    -- must not yield a usable one — the same rule as sessions.
    token_hash  text NOT NULL UNIQUE,

    invited_by  uuid REFERENCES auth.users (id) ON DELETE SET NULL,
    expires_at  timestamptz NOT NULL,
    accepted_at timestamptz,
    accepted_by uuid REFERENCES auth.users (id) ON DELETE SET NULL,
    revoked_at  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),

    -- One outstanding invite per email per tenant. Without this, re-inviting
    -- leaves several valid tokens and revoking one does not revoke the rest.
    UNIQUE (tenant_id, email, accepted_at)
);

CREATE INDEX invitations_tenant_idx ON auth.invitations (tenant_id);
CREATE INDEX invitations_email_idx  ON auth.invitations (email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

SELECT app.enable_tenant_rls('auth.invitations');

-- Accepting an invite is also pre-tenant: the invitee is not yet a member, so
-- they have no tenant scope in which to read it.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth.invitation_by_token_hash(p_hash text)
RETURNS TABLE (
    invitation_id uuid,
    tenant_id     uuid,
    tenant_name   text,
    email         citext,
    role          text,
    expires_at    timestamptz,
    accepted_at   timestamptz,
    revoked_at    timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = auth, pg_temp
AS $fn$
    SELECT i.id, i.tenant_id, t.name, i.email, i.role,
           i.expires_at, i.accepted_at, i.revoked_at
      FROM auth.invitations i
      JOIN auth.tenants t ON t.id = i.tenant_id
     WHERE i.token_hash = p_hash;
$fn$;
-- +goose StatementEnd

GRANT EXECUTE ON FUNCTION auth.invitation_by_token_hash(text) TO encorebom_app;

-- ---------------------------------------------------------------------------
-- Accept an invitation: create the membership and mark the invite used.
--
-- One transaction, one function. Doing it in two application steps risks a
-- membership without a consumed invite, which would leave the token replayable.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth.accept_invitation(p_hash text, p_user_id uuid)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = auth, pg_temp
AS $fn$
DECLARE
    inv  auth.invitations%ROWTYPE;
    mem  uuid;
BEGIN
    SELECT * INTO inv FROM auth.invitations WHERE token_hash = p_hash FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'invitation not found' USING ERRCODE = 'no_data_found';
    END IF;
    IF inv.accepted_at IS NOT NULL THEN
        RAISE EXCEPTION 'invitation already accepted' USING ERRCODE = 'unique_violation';
    END IF;
    IF inv.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'invitation revoked' USING ERRCODE = 'check_violation';
    END IF;
    IF inv.expires_at <= now() THEN
        RAISE EXCEPTION 'invitation expired' USING ERRCODE = 'check_violation';
    END IF;

    INSERT INTO auth.memberships (tenant_id, user_id, role, invited_by, invited_at, accepted_at)
    VALUES (inv.tenant_id, p_user_id, inv.role, inv.invited_by, inv.created_at, now())
    ON CONFLICT (tenant_id, user_id) DO UPDATE
        SET role = EXCLUDED.role, accepted_at = COALESCE(auth.memberships.accepted_at, now())
    RETURNING id INTO mem;

    UPDATE auth.invitations
       SET accepted_at = now(), accepted_by = p_user_id
     WHERE id = inv.id;

    RETURN mem;
END;
$fn$;
-- +goose StatementEnd

GRANT EXECUTE ON FUNCTION auth.accept_invitation(text, uuid) TO encorebom_app;

-- +goose Down
DROP FUNCTION IF EXISTS auth.accept_invitation(text, uuid);
DROP FUNCTION IF EXISTS auth.invitation_by_token_hash(text);
DROP TABLE IF EXISTS auth.invitations;
DROP FUNCTION IF EXISTS auth.record_auth_event(uuid, uuid, text, jsonb, inet, text);
DROP FUNCTION IF EXISTS auth.revoke_session_family(uuid);
DROP FUNCTION IF EXISTS auth.session_by_refresh_hash(text);
DROP FUNCTION IF EXISTS auth.memberships_for_user(uuid);
