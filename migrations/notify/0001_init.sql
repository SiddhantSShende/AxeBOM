-- +goose Up
-- ===========================================================================
-- notify — email and webhook delivery.
-- Implements docs/01-DATA-MODEL.md §9 (notify).
-- ===========================================================================

CREATE TABLE notify.subscriptions (
    id          uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id   uuid NOT NULL,

    kind        text NOT NULL CHECK (kind IN ('email','webhook')),
    target      text NOT NULL,
    events      text[] NOT NULL DEFAULT '{}',

    -- A VAULT PATH, never the HMAC secret itself.
    secret_ref  text,

    enabled     boolean NOT NULL DEFAULT true,
    created_by  uuid,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, kind, target)
);

CREATE INDEX subscriptions_tenant_idx ON notify.subscriptions (tenant_id)
    WHERE enabled = true;

CREATE TRIGGER touch_updated_at BEFORE UPDATE ON notify.subscriptions
    FOR EACH ROW EXECUTE FUNCTION app.touch_updated_at();

SELECT app.enable_tenant_rls('notify.subscriptions');

-- ---------------------------------------------------------------------------
-- deliveries
--
-- The payload carries IDS AND COUNTS, never component or finding detail. A
-- receiver may log the body, and BOM content is confidential under
-- CERT-In §5.3.
-- ---------------------------------------------------------------------------
CREATE TABLE notify.deliveries (
    id               uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id        uuid NOT NULL,
    subscription_id  uuid NOT NULL REFERENCES notify.subscriptions (id) ON DELETE CASCADE,

    event_type       text NOT NULL,
    payload          jsonb NOT NULL DEFAULT '{}'::jsonb,

    attempt          int NOT NULL DEFAULT 1 CHECK (attempt >= 1),
    status           text NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','delivered','failed','dead_lettered')),
    response_code    int,
    error            text,
    next_retry_at    timestamptz,

    created_at       timestamptz NOT NULL DEFAULT now(),
    delivered_at     timestamptz
);

CREATE INDEX deliveries_subscription_idx ON notify.deliveries (subscription_id, created_at DESC);
CREATE INDEX deliveries_tenant_idx       ON notify.deliveries (tenant_id);
CREATE INDEX deliveries_retry_idx        ON notify.deliveries (next_retry_at)
    WHERE status = 'pending';

SELECT app.enable_tenant_rls('notify.deliveries');

-- +goose Down
DROP TABLE IF EXISTS notify.deliveries;
DROP TABLE IF EXISTS notify.subscriptions;
