-- +goose Up
-- ===========================================================================
-- The scheduler's cross-tenant read.
--
-- ⚠ A BACKGROUND SCHEDULER HAS NO TENANT TO SCOPE BY.
--
-- Every other query in the product runs inside app.current_tenant_id, set from
-- the request. A tick has no request: it must ask "which campaigns, across all
-- tenants, are due?" — the same pre-tenant problem login and share links have,
-- and it gets the same answer rather than a new one.
--
-- The wrong answers, and why:
--
--   BYPASSRLS on the app role — one flag that disables tenancy for every query
--   the application makes, forever, to solve one query. The blast radius is the
--   entire product.
--
--   A superuser connection for the scheduler — same thing wearing a hat. Any
--   SQL injection or logic bug in that process reads every tenant's data.
--
--   Looping over tenants and setting the GUC for each — O(tenants) round trips
--   every thirty seconds, and it silently stops working for a tenant created
--   between the list and the loop.
--
-- So: ONE narrow SECURITY DEFINER function, returning SCHEDULING COLUMNS ONLY.
-- It cannot reach a component, a finding, a report or a name a customer would
-- consider confidential — the worst it can leak is that a campaign exists and
-- when it next runs. Everything the scheduler does after this call runs inside
-- WithTenant using the tenant_id this function returned.
--
-- docs/05-SECURITY-MODEL.md §2, docs/ADR/0006-rls-tenancy.md
-- ===========================================================================

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION campaign.due_campaigns(p_now timestamptz, p_limit int)
RETURNS TABLE (
    id             uuid,
    tenant_id      uuid,
    name           text,
    cron_expr      text,
    timezone       text,
    project_ids    uuid[],
    bom_types      text[],
    report_levels  text[],
    standards      text[],
    formats        text[],
    next_run_at    timestamptz
)
LANGUAGE sql
SECURITY DEFINER
-- An empty search_path: a SECURITY DEFINER function that resolves unqualified
-- names against the CALLER's search_path is a privilege-escalation primitive.
-- Every identifier below is schema-qualified for the same reason.
SET search_path = ''
AS $$
    SELECT c.id, c.tenant_id, c.name, c.cron_expr, c.timezone,
           c.project_ids, c.bom_types, c.report_levels, c.standards, c.formats,
           c.next_run_at
    FROM campaign.campaigns AS c
    WHERE c.enabled = true
      AND c.next_run_at IS NOT NULL
      AND c.next_run_at <= p_now
    -- Oldest first: after downtime the campaign that has waited longest is
    -- dispatched first, so a batch limit degrades into fairness rather than
    -- starving whoever sorts last.
    ORDER BY c.next_run_at ASC
    LIMIT LEAST(GREATEST(p_limit, 1), 1000);
$$;
-- +goose StatementEnd

-- The app role may CALL it. It may not become its owner, and the function body
-- is fixed — which is what makes "narrow" mean something.
REVOKE ALL ON FUNCTION campaign.due_campaigns(timestamptz, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION campaign.due_campaigns(timestamptz, int) TO encorebom_app;

-- ---------------------------------------------------------------------------
-- next_run_at bootstrap
--
-- A campaign with a NULL next_run_at never becomes due. That is deliberate for
-- a disabled campaign and a bug for an enabled one, so the column is the
-- scheduler's cursor AND the enable path's responsibility: enabling computes
-- the next FUTURE occurrence, which is also why re-enabling cannot backfill.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS campaigns_next_run_idx
    ON campaign.campaigns (next_run_at ASC)
    WHERE enabled = true AND next_run_at IS NOT NULL;

-- +goose Down
DROP FUNCTION IF EXISTS campaign.due_campaigns(timestamptz, int);
DROP INDEX IF EXISTS campaign.campaigns_next_run_idx;
