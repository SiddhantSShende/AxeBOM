-- +goose Up
-- ===========================================================================
-- The delivery worker's cross-tenant claim.
--
-- ⚠ A BACKGROUND POLLER HAS NO TENANT TO SCOPE BY — the exact problem
-- migrations/campaign/0002's `due_campaigns` already solved for the
-- scheduler, and this is the same answer applied to the same shape of
-- problem: one narrow SECURITY DEFINER function, returning DELIVERY-SCHEDULING
-- COLUMNS ONLY, called via pool.Raw() from services/notification's poller.
-- Everything after this call runs inside WithTenant using the tenant_id this
-- function returned. See docs/05-SECURITY-MODEL.md §2, docs/ADR/0006.
--
-- The `payload` column IS safe to return here, unlike a hypothetical
-- `due_findings` or `due_components` would be: webhook.Payload (what this
-- column stores) is BY DESIGN ids/counts/status/url only — never component
-- or finding detail — so this function cannot leak anything the wire format
-- itself already refuses to carry.
--
-- ⚠ THE STATUS TRANSITION IS THE LOCK, same idiom as report.ClaimForRender
-- and campaign.ClaimRun's ON CONFLICT: `pending` -> `processing` in the same
-- statement that selects the row, so two poller ticks (or two replicas)
-- cannot both claim it. FOR UPDATE SKIP LOCKED is a second, redundant layer
-- for the same reason belt-and-suspenders is cheap here and a duplicate
-- webhook POST is not.
-- ===========================================================================

ALTER TABLE notify.deliveries
    DROP CONSTRAINT deliveries_status_check,
    ADD CONSTRAINT deliveries_status_check
        CHECK (status IN ('pending','processing','delivered','failed','dead_lettered'));

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION notify.claim_due_deliveries(p_now timestamptz, p_limit int)
RETURNS TABLE (
    id              uuid,
    tenant_id       uuid,
    subscription_id uuid,
    event_type      text,
    payload         jsonb,
    attempt         int
)
LANGUAGE plpgsql
SECURITY DEFINER
-- An empty search_path: a SECURITY DEFINER function that resolves unqualified
-- names against the CALLER's search_path is a privilege-escalation primitive.
-- Every identifier below is schema-qualified for the same reason.
SET search_path = ''
AS $fn$
BEGIN
    RETURN QUERY
    UPDATE notify.deliveries AS d
       SET status = 'processing'
     WHERE d.id IN (
               SELECT s.id
                 FROM notify.deliveries AS s
                WHERE s.status = 'pending'
                  AND (s.next_retry_at IS NULL OR s.next_retry_at <= p_now)
                -- Oldest-due first: after an outage, the delivery that has
                -- waited longest goes out first, so a batch limit degrades
                -- into fairness rather than starving whoever sorts last —
                -- the same reasoning campaign.due_campaigns already states.
                ORDER BY COALESCE(s.next_retry_at, s.created_at) ASC
                LIMIT LEAST(GREATEST(p_limit, 1), 1000)
                FOR UPDATE SKIP LOCKED
           )
     RETURNING d.id, d.tenant_id, d.subscription_id, d.event_type, d.payload, d.attempt;
END;
$fn$;
-- +goose StatementEnd

COMMENT ON FUNCTION notify.claim_due_deliveries(timestamptz, int) IS
'Pre-tenant claim for the notification delivery poller. SECURITY DEFINER
because a background tick has no tenant to scope by. Atomically transitions
pending -> processing so two ticks cannot both attempt the same delivery.
Returns only what webhook.Payload already permits on the wire: ids, counts,
status, url — never component or finding detail.';

GRANT EXECUTE ON FUNCTION notify.claim_due_deliveries(timestamptz, int) TO axebom_app;

-- +goose Down
DROP FUNCTION IF EXISTS notify.claim_due_deliveries(timestamptz, int);
ALTER TABLE notify.deliveries
    DROP CONSTRAINT deliveries_status_check,
    ADD CONSTRAINT deliveries_status_check
        CHECK (status IN ('pending','delivered','failed','dead_lettered'));
