-- +goose Up
-- ===========================================================================
-- The deadline reaper's cross-tenant sweep.
--
-- THE PROBLEM: the reaper must mark overdue jobs across EVERY tenant, but
-- scan.engine_runs has FORCE row-level security keyed on
-- app.current_tenant_id. An unscoped query raises
-- `unrecognized configuration parameter`, which is RLS failing closed exactly
-- as designed — and which makes a naive reaper impossible.
--
-- THE WRONG FIXES, and why:
--
--   * Give the reaper BYPASSRLS      -> disables every policy in the database
--                                       for that role, everywhere, forever.
--   * Connect as the owner            -> same, with extra steps.
--   * Enumerate tenants and loop      -> needs a cross-schema read of
--                                       auth.tenants (forbidden), and a tenant
--                                       added mid-sweep is missed.
--
-- THE FIX: one narrow SECURITY DEFINER function, following the precedent set by
-- migrations/auth/0002. It does exactly one thing — flip overdue rows to
-- `timeout` — and returns only the ids needed to recompute the affected scans.
-- It cannot read scan CONTENT, cannot be pointed at a tenant, and takes no
-- parameters, so there is no input that could widen it.
--
-- docs/05-SECURITY-MODEL.md §2
-- ===========================================================================

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION scan.reap_overdue_runs()
RETURNS TABLE (
    scan_id   uuid,
    tenant_id uuid,
    job_id    uuid,
    engine_id text
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = scan, pg_temp   -- pinned: a mutable search_path on a
                                  -- SECURITY DEFINER function is a privilege
                                  -- escalation vector
AS $fn$
    UPDATE scan.engine_runs
       SET status        = 'timeout',
           finished_at   = now(),
           error_code    = 'SCAN_JOB_DEADLINE_EXCEEDED',
           error_message = 'the job did not report a result before its deadline'
     WHERE status IN ('queued', 'running')
       AND deadline_at IS NOT NULL
       AND deadline_at < now()
    RETURNING scan_id, tenant_id, job_id, engine_id;
$fn$;
-- +goose StatementEnd

COMMENT ON FUNCTION scan.reap_overdue_runs() IS
'Cross-tenant deadline sweep. SECURITY DEFINER because RLS correctly refuses an
unscoped query, and the reaper must cover every tenant. Deliberately narrow:
takes no parameters, writes one status transition, and returns only ids — there
is no input that could widen it and no way to read scan content through it.';

-- Only the application role may call it; the tables stay protected.
GRANT EXECUTE ON FUNCTION scan.reap_overdue_runs() TO encorebom_app;

-- ---------------------------------------------------------------------------
-- Recomputing a scan's status after a reap is likewise cross-tenant.
--
-- Returns the DERIVED status rather than writing it, so the derivation stays in
-- one place in Go (events.DeriveScanStatus) rather than being duplicated in SQL
-- where the two copies would drift.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION scan.terminal_statuses_for(p_scan_id uuid)
RETURNS TABLE (status text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = scan, pg_temp
AS $fn$
    SELECT DISTINCT ON (engine_id) status
      FROM scan.engine_runs
     WHERE scan_id = p_scan_id
     ORDER BY engine_id,
              (status = 'failed') ASC,   -- prefer a non-failed attempt
              attempt DESC;
$fn$;
-- +goose StatementEnd

GRANT EXECUTE ON FUNCTION scan.terminal_statuses_for(uuid) TO encorebom_app;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION scan.set_scan_status(p_scan_id uuid, p_status text, p_terminal boolean)
RETURNS void
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = scan, pg_temp
AS $fn$
    UPDATE scan.scans
       SET status = p_status,
           finished_at = CASE WHEN p_terminal
                              THEN COALESCE(finished_at, now())
                              ELSE finished_at END
     WHERE id = p_scan_id;
$fn$;
-- +goose StatementEnd

COMMENT ON FUNCTION scan.set_scan_status(uuid, text, boolean) IS
'Used by the reaper only. Ordinary status updates go through the tenant-scoped
path in Go; this exists because a reaped scan has no tenant session to write in.';

GRANT EXECUTE ON FUNCTION scan.set_scan_status(uuid, text, boolean) TO encorebom_app;

-- +goose Down
DROP FUNCTION IF EXISTS scan.set_scan_status(uuid, text, boolean);
DROP FUNCTION IF EXISTS scan.terminal_statuses_for(uuid);
DROP FUNCTION IF EXISTS scan.reap_overdue_runs();
