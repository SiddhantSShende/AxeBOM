-- +goose Up
-- ===========================================================================
-- Pin the search_path of the shared helper functions.
--
-- THE BUG THIS FIXES, observed in the Phase 3 auth tests:
--
--   ERROR: function gen_random_bytes(integer) does not exist
--
-- app.uuid_v7() called gen_random_bytes() unqualified. pgcrypto installs it
-- into public, so resolution worked whenever the CALLER's search_path happened
-- to contain public — which it did for ordinary application queries, so
-- everything looked fine.
--
-- It stopped working the moment a function with a PINNED search_path called it.
-- migrations/auth/0002 added SECURITY DEFINER functions with
-- `SET search_path = auth, pg_temp`, and every id default evaluated inside them
-- failed. The symptom was an audit write silently failing and an invitation
-- that could never be accepted.
--
-- THE GENERAL RULE: a function's behaviour must not depend on its caller's
-- search_path. For a SECURITY INVOKER function that dependency is a latent
-- breakage like this one; for a SECURITY DEFINER function it is a privilege
-- escalation, because the caller chooses which code runs as the owner.
--
-- So: pin every helper, and schema-qualify what they call.
--
-- `pg_catalog` is listed first because these functions call built-ins
-- (set_byte, get_byte, encode, clock_timestamp); `public` is where pgcrypto
-- lives; `pg_temp` goes LAST, always — a temporary object that shadows a real
-- one is the classic search_path attack.
-- ===========================================================================

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION app.uuid_v7()
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog, public, pg_temp
AS $fn$
DECLARE
  unix_ms bigint;
  uuid_bytes bytea;
BEGIN
  unix_ms := (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint;
  uuid_bytes := public.gen_random_bytes(16);
  -- 48-bit big-endian millisecond timestamp in the first six octets.
  uuid_bytes := set_byte(uuid_bytes, 0, ((unix_ms >> 40) & 255)::int);
  uuid_bytes := set_byte(uuid_bytes, 1, ((unix_ms >> 32) & 255)::int);
  uuid_bytes := set_byte(uuid_bytes, 2, ((unix_ms >> 24) & 255)::int);
  uuid_bytes := set_byte(uuid_bytes, 3, ((unix_ms >> 16) & 255)::int);
  uuid_bytes := set_byte(uuid_bytes, 4, ((unix_ms >>  8) & 255)::int);
  uuid_bytes := set_byte(uuid_bytes, 5, ( unix_ms        & 255)::int);
  -- version 7
  uuid_bytes := set_byte(uuid_bytes, 6, ((get_byte(uuid_bytes, 6) & 15) | 112));
  -- RFC 4122 variant
  uuid_bytes := set_byte(uuid_bytes, 8, ((get_byte(uuid_bytes, 8) & 63) | 128));
  RETURN encode(uuid_bytes, 'hex')::uuid;
END;
$fn$;
-- +goose StatementEnd

COMMENT ON FUNCTION app.uuid_v7() IS
'Time-ordered UUIDv7. search_path is pinned so it resolves gen_random_bytes
identically no matter who calls it — including SECURITY DEFINER functions that
pin their own. Do not remove the pin; see migrations/bootstrap/0002.';

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION app.touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$fn$;
-- +goose StatementEnd

-- ---------------------------------------------------------------------------
-- The RLS helpers run at migration time as the owner and take a regclass, so
-- they are not reachable by application code. Pinning them anyway costs
-- nothing and removes the question from future review.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION app.enable_tenant_rls(target regclass)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', target);
  EXECUTE format('ALTER TABLE %s FORCE  ROW LEVEL SECURITY', target);
  EXECUTE format(
    'CREATE POLICY tenant_isolation ON %s '
    'USING (tenant_id = current_setting(''app.current_tenant_id'')::uuid) '
    'WITH CHECK (tenant_id = current_setting(''app.current_tenant_id'')::uuid)',
    target);
END;
$fn$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION app.enable_tenant_rls_nullable(target regclass)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', target);
  EXECUTE format('ALTER TABLE %s FORCE  ROW LEVEL SECURITY', target);
  EXECUTE format(
    'CREATE POLICY tenant_isolation ON %s '
    'USING (tenant_id = current_setting(''app.current_tenant_id'')::uuid) '
    'WITH CHECK (tenant_id = current_setting(''app.current_tenant_id'')::uuid '
    '            OR tenant_id IS NULL)',
    target);
END;
$fn$;
-- +goose StatementEnd

-- ---------------------------------------------------------------------------
-- A note on what the nullable policy deliberately does NOT do.
--
-- The USING clause has no `OR tenant_id IS NULL`, so a global audit row — a
-- failed login for an email that belongs to no tenant — is WRITE-ONLY as far
-- as the application role is concerned. That is intentional: those rows carry
-- email addresses of people who are not that tenant's users, and letting any
-- tenant read them would leak across the boundary.
--
-- The consequence is honest and must stay visible: nothing in the product can
-- currently display global auth events. They are readable by an operator
-- connecting as the owner role. A platform-admin surface is the right home for
-- them and is not in scope before Phase 16. Recorded in docs/STATE.md.
-- ---------------------------------------------------------------------------

-- +goose Down
-- The Up is a pure redefinition of existing functions. Reverting would restore
-- a known bug, so Down deliberately does nothing rather than reintroduce it.
SELECT 1;
