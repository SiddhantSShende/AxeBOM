-- +goose Up
-- ===========================================================================
-- Bootstrap: schemas, the non-superuser application role, and the RLS helper.
--
-- Runs as the database OWNER. Everything after this runs as the owner too;
-- only the application connects as axebom_app.
--
-- docs/ADR/0006-rls-tenancy.md
-- ===========================================================================

-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS citext;      -- case-insensitive email
CREATE EXTENSION IF NOT EXISTS pgcrypto;    -- gen_random_uuid, digest
-- +goose StatementEnd

-- ---------------------------------------------------------------------------
-- Schemas. One per service (ADR-0001 mitigation 2).
-- NEVER JOIN across a schema boundary in SQL — cross-domain joins happen in Go.
-- That single discipline is what keeps services extractable, and it costs
-- nothing today.
-- ---------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS project;
CREATE SCHEMA IF NOT EXISTS scan;
CREATE SCHEMA IF NOT EXISTS normalize;
CREATE SCHEMA IF NOT EXISTS report;
CREATE SCHEMA IF NOT EXISTS campaign;
CREATE SCHEMA IF NOT EXISTS comment;
CREATE SCHEMA IF NOT EXISTS notify;

-- `app` holds shared helpers, not domain tables.
CREATE SCHEMA IF NOT EXISTS app;

-- ---------------------------------------------------------------------------
-- The application role.
--
-- MUST NOT be SUPERUSER and MUST NOT have BYPASSRLS. Either one silently
-- disables every policy in the database — the queries keep working, the rows
-- keep coming back, and nothing looks wrong. platform/db asserts this at
-- startup because a later GRANT could reintroduce it.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axebom_app') THEN
    CREATE ROLE axebom_app LOGIN PASSWORD 'axebom_app';
  END IF;
END
$$;
-- +goose StatementEnd

ALTER ROLE axebom_app NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

GRANT USAGE ON SCHEMA auth, project, scan, normalize, report, campaign, comment, notify, app
  TO axebom_app;

-- ---------------------------------------------------------------------------
-- The RLS helper.
--
-- Defined once and applied everywhere, rather than repeating the policy in
-- forty tables where one would eventually be written subtly differently.
--
-- Four details, each a hole if missed:
--   ENABLE       turns policies on
--   FORCE        applies them to the table OWNER too — without it the owner
--                bypasses everything, and the migration role IS the owner
--   USING        filters reads
--   WITH CHECK   filters writes; without it a tenant could INSERT rows
--                attributed to another tenant
--
-- current_setting() without the missing_ok argument RAISES when unset. That is
-- deliberate: a query outside WithTenant fails closed rather than returning
-- every tenant's rows.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION app.enable_tenant_rls(target regclass)
RETURNS void
LANGUAGE plpgsql
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

-- ---------------------------------------------------------------------------
-- Variant for tables whose tenant_id is nullable — currently only
-- auth.audit_log, which must record pre-authentication events (a failed login
-- for an unknown email) that belong to no tenant.
--
-- Asymmetric on purpose:
--   WITH CHECK allows NULL  -> system events can be written
--   USING excludes NULL     -> no tenant can read another's, or the system's
--
-- The result is that NULL-tenant audit rows are write-only to the application
-- and readable only through an operator path. That is the correct trade: they
-- are evidence, not tenant data.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION app.enable_tenant_rls_nullable(target regclass)
RETURNS void
LANGUAGE plpgsql
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
-- Applies RLS to a partitioned table AND each of its partitions.
--
-- Postgres applies the parent's policy when a query goes through the parent,
-- which is how the repository layer always queries. Enabling it on the leaves
-- as well removes the footgun where someone queries normalize.components_p07
-- directly and silently bypasses tenancy.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION app.enable_tenant_rls_partitioned(target regclass)
RETURNS void
LANGUAGE plpgsql
AS $fn$
DECLARE
  part regclass;
BEGIN
  PERFORM app.enable_tenant_rls(target);
  FOR part IN
    SELECT inhrelid::regclass FROM pg_inherits WHERE inhparent = target
  LOOP
    PERFORM app.enable_tenant_rls(part);
  END LOOP;
END;
$fn$;
-- +goose StatementEnd

-- ---------------------------------------------------------------------------
-- UUIDv7: time-ordered, so index locality is good and keyset pagination by id
-- is chronological. Postgres 18 has uuidv7() natively; this is the portable
-- implementation for 16/17.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION app.uuid_v7()
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
AS $fn$
DECLARE
  unix_ms bigint;
  uuid_bytes bytea;
BEGIN
  unix_ms := (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint;
  uuid_bytes := gen_random_bytes(16);
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

-- ---------------------------------------------------------------------------
-- updated_at maintenance.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION app.touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$fn$;
-- +goose StatementEnd

-- ---------------------------------------------------------------------------
-- Default privileges, so tables created by later migrations are usable by the
-- app role without every migration remembering to GRANT.
--
-- Note what is NOT granted: TRUNCATE anywhere, and DELETE on audit_log (see
-- the auth migration). The audit log is append-only by grant, not by
-- convention — a convention is something an ORM will cheerfully ignore.
-- ---------------------------------------------------------------------------
ALTER DEFAULT PRIVILEGES IN SCHEMA auth, project, scan, normalize, report, campaign, comment, notify
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO axebom_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA auth, project, scan, normalize, report, campaign, comment, notify
  GRANT USAGE, SELECT ON SEQUENCES TO axebom_app;

-- +goose Down
DROP FUNCTION IF EXISTS app.touch_updated_at();
DROP FUNCTION IF EXISTS app.uuid_v7();
DROP FUNCTION IF EXISTS app.enable_tenant_rls_partitioned(regclass);
DROP FUNCTION IF EXISTS app.enable_tenant_rls_nullable(regclass);
DROP FUNCTION IF EXISTS app.enable_tenant_rls(regclass);

DROP SCHEMA IF EXISTS app CASCADE;
DROP SCHEMA IF EXISTS notify CASCADE;
DROP SCHEMA IF EXISTS comment CASCADE;
DROP SCHEMA IF EXISTS campaign CASCADE;
DROP SCHEMA IF EXISTS report CASCADE;
DROP SCHEMA IF EXISTS normalize CASCADE;
DROP SCHEMA IF EXISTS scan CASCADE;
DROP SCHEMA IF EXISTS project CASCADE;
DROP SCHEMA IF EXISTS auth CASCADE;

-- The role is intentionally NOT dropped: other databases in the cluster may
-- use it, and DROP ROLE fails if any object anywhere still depends on it.
