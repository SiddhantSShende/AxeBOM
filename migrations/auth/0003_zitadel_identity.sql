-- +goose Up
-- ===========================================================================
-- ZITADEL becomes the identity provider; auth.* becomes a local PROJECTION.
--
-- ---------------------------------------------------------------------------
-- WHY auth.tenants AND auth.users SURVIVE AT ALL
--
-- It would be tidier to delete them and read identity straight from the token.
-- Two things make that impossible, and both are load-bearing:
--
--   1. EVERY RLS POLICY CASTS THE TENANT TO uuid.
--      All 43 tenant-scoped tables carry
--          USING (tenant_id = current_setting('app.current_tenant_id')::uuid)
--      and ZITADEL organisation ids are numeric snowflake strings
--      ("339712...") which do not cast. Feeding one in fails every
--      tenant-scoped query in the product with "invalid input syntax for type
--      uuid". Rewriting 43 policies to compare text is a far larger and far
--      riskier change than keeping a mapping.
--
--   2. SIX TABLES HOLD created_by uuid NOT NULL pointing at auth.users.id
--      (project.projects, project.uploads, comment.comments,
--      campaign.campaigns, report.reports, notify.subscriptions). A ZITADEL
--      subject written into one of those columns fails the INSERT.
--
-- So ZITADEL owns AUTHENTICATION and role assignment; these tables own the
-- STABLE INTERNAL IDENTIFIERS that the rest of the schema already references.
-- The bridge is two columns and one function.
--
-- ---------------------------------------------------------------------------
-- WHAT THIS MIGRATION DELIBERATELY DOES NOT DO
--
-- It does not drop auth.users.password_hash, auth.sessions or auth.invitations.
-- ZITADEL supersedes all three, but the hand-rolled auth service is still
-- running at this point and libs/go-shared/platform/db/seed_login_test.go
-- still asserts the seeded hashes verify. Removing a replaced thing before its
-- replacement is proven green is how a migration becomes an outage. They are
-- dropped in the later migration that also deletes services/auth.
--
-- docs/05-SECURITY-MODEL.md §2, docs/ADR/0006-rls-tenancy.md
-- ===========================================================================

-- --------------------------------------------------------------- the mapping
-- Nullable: a tenant created before ZITADEL existed has no org yet, and the
-- seeded development tenants are linked by `axebom iam bootstrap` rather
-- than by this migration. UNIQUE, because two AxeBOM tenants sharing one
-- ZITADEL organisation would make the org->tenant lookup ambiguous — and an
-- ambiguous tenant lookup is a cross-tenant read waiting to happen.
ALTER TABLE auth.tenants
    ADD COLUMN IF NOT EXISTS zitadel_org_id text UNIQUE;

ALTER TABLE auth.users
    ADD COLUMN IF NOT EXISTS zitadel_user_id text UNIQUE;

COMMENT ON COLUMN auth.tenants.zitadel_org_id IS
    'ZITADEL organisation id. The org IS the tenant; this column is the only '
    'bridge between the two id spaces.';
COMMENT ON COLUMN auth.users.zitadel_user_id IS
    'ZITADEL user id (the token subject). NULL for rows that predate ZITADEL.';

-- ---------------------------------------------------------------- resolution
-- ⚠ SECURITY DEFINER, AND FOR THE SAME REASON auth.memberships_for_user IS.
--
-- This runs BEFORE a tenant is known — resolving the tenant is the entire
-- point — so a normal query fails closed on current_setting. The narrow,
-- reviewable hole is a function that takes ZITADEL's own identifiers and
-- returns exactly one user's own mapping. It cannot enumerate: without a
-- ZITADEL org id and user id from a token this instance signed, it creates a
-- fresh unrelated tenant rather than revealing an existing one.
--
-- It is also the JIT provisioning point. A user who exists in ZITADEL but not
-- here is created on first request rather than 500ing, because the alternative
-- is an admin adding every user twice.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION auth.identity_for(
    p_org_id         text,
    p_org_name       text,
    p_user_id        text,
    p_email          text,
    p_email_verified boolean,
    p_name           text,
    p_role           text
)
RETURNS TABLE (tenant_id uuid, user_id uuid, role text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = auth, pg_temp
AS $fn$
-- ⚠ WITHOUT THIS THE FUNCTION RAISES 42702 ON EVERY CALL.
--
-- `RETURNS TABLE (tenant_id, user_id, role)` puts those three names in scope as
-- OUT variables for the whole body, and auth.memberships has columns with the
-- same names — so `ON CONFLICT (tenant_id, user_id) DO UPDATE SET role = …`
-- is ambiguous and plpgsql refuses it: "column reference \"tenant_id\" is
-- ambiguous".
--
-- It fails at CALL time, not at CREATE time, so the migration applied cleanly
-- and every sign-in then 500ed with "the account could not be resolved".
--
-- `use_column` is safe here because the body never READS those OUT variables —
-- it works in v_tenant / v_user / v_role and returns them explicitly.
#variable_conflict use_column
DECLARE
    v_tenant uuid;
    v_user   uuid;
    v_slug   text;
    v_role   text;
BEGIN
    IF p_org_id IS NULL OR p_org_id = '' OR p_user_id IS NULL OR p_user_id = '' THEN
        RAISE EXCEPTION 'identity_for requires both a ZITADEL org id and user id'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- ---------------------------------------------------------- the tenant
    SELECT t.id INTO v_tenant
      FROM auth.tenants t
     WHERE t.zitadel_org_id = p_org_id
       AND t.deleted_at IS NULL;

    IF v_tenant IS NULL THEN
        -- Slug is derived, then made unique by appending the org id. A
        -- collision here is not a conflict to resolve, it is two different
        -- organisations that happen to be called the same thing.
        v_slug := regexp_replace(lower(coalesce(nullif(p_org_name, ''), 'org')),
                                 '[^a-z0-9]+', '-', 'g');
        v_slug := trim(both '-' from v_slug);
        IF v_slug = '' THEN
            v_slug := 'org';
        END IF;
        IF EXISTS (SELECT 1 FROM auth.tenants WHERE slug = v_slug) THEN
            v_slug := v_slug || '-' || p_org_id;
        END IF;

        INSERT INTO auth.tenants (name, slug, zitadel_org_id)
        VALUES (coalesce(nullif(p_org_name, ''), v_slug), v_slug, p_org_id)
        RETURNING id INTO v_tenant;
    END IF;

    -- ------------------------------------------------------------ the user
    SELECT u.id INTO v_user
      FROM auth.users u
     WHERE u.zitadel_user_id = p_user_id
       AND u.deleted_at IS NULL;

    IF v_user IS NULL AND p_email_verified AND coalesce(p_email, '') <> '' THEN
        -- ⚠ ADOPTION BY EMAIL IS GATED ON THE EMAIL BEING VERIFIED.
        --
        -- This is what lets the pre-existing seeded users keep their UUIDs, so
        -- every created_by row already in the database still points at a real
        -- person. Doing it on an UNVERIFIED address would let anyone who can
        -- register an account claim an existing one by typing its address —
        -- account takeover with no exploit required.
        UPDATE auth.users u
           SET zitadel_user_id = p_user_id,
               auth_provider   = 'oidc',
               name            = coalesce(nullif(p_name, ''), u.name),
               updated_at      = now()
         WHERE u.email = p_email
           AND u.zitadel_user_id IS NULL
           AND u.deleted_at IS NULL
        RETURNING u.id INTO v_user;
    END IF;

    IF v_user IS NULL THEN
        INSERT INTO auth.users (email, name, auth_provider, status, zitadel_user_id)
        VALUES (coalesce(nullif(p_email, ''), p_user_id || '@zitadel.local'),
                nullif(p_name, ''), 'oidc', 'active', p_user_id)
        ON CONFLICT (zitadel_user_id) DO UPDATE SET updated_at = now()
        RETURNING id INTO v_user;
    END IF;

    -- ------------------------------------------------------ the membership
    -- ZITADEL is authoritative for the role, so this OVERWRITES rather than
    -- preserving what is here. A role revoked there must not survive here, or
    -- the projection becomes a way to keep access after it was taken away.
    v_role := lower(coalesce(nullif(p_role, ''), 'viewer'));
    IF v_role NOT IN ('owner', 'admin', 'analyst', 'viewer') THEN
        v_role := 'viewer';
    END IF;

    INSERT INTO auth.memberships (tenant_id, user_id, role, accepted_at)
    VALUES (v_tenant, v_user, v_role, now())
    ON CONFLICT (tenant_id, user_id) DO UPDATE
        SET role       = EXCLUDED.role,
            updated_at = now();

    RETURN QUERY SELECT v_tenant, v_user, v_role;
END;
$fn$;
-- +goose StatementEnd

GRANT EXECUTE ON FUNCTION
    auth.identity_for(text, text, text, text, boolean, text, text)
    TO axebom_app;

-- +goose Down
DROP FUNCTION IF EXISTS auth.identity_for(text, text, text, text, boolean, text, text);
ALTER TABLE auth.users   DROP COLUMN IF EXISTS zitadel_user_id;
ALTER TABLE auth.tenants DROP COLUMN IF EXISTS zitadel_org_id;
