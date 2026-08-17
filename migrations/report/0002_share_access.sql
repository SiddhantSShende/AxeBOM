-- +goose Up
-- ===========================================================================
-- Share-link access: the audit trail, and an ATOMIC claim.
--
-- `/shared/:token` is UNAUTHENTICATED. The caller presents a token and nothing
-- else — no session, no tenant. That is the same pre-tenant problem Phase 3
-- solved for login, and it gets the same answer: one narrow SECURITY DEFINER
-- function taking a single token hash, rather than BYPASSRLS or an owner
-- connection.
--
-- docs/05-SECURITY-MODEL.md §2, docs/ADR/0006-rls-tenancy.md
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- share_access_log
--
-- Every access is recorded, granted or not. A share link is the one way report
-- data leaves the product without an authenticated identity attached, so the
-- IP and the outcome are the entire accountability story — and a REFUSED
-- attempt is the more interesting row: repeated refusals against a revoked
-- token mean somebody still holds it.
-- ---------------------------------------------------------------------------
CREATE TABLE report.share_access_log (
    id             uuid PRIMARY KEY DEFAULT app.uuid_v7(),
    tenant_id      uuid NOT NULL,
    share_link_id  uuid NOT NULL REFERENCES report.share_links (id) ON DELETE CASCADE,
    report_id      uuid NOT NULL,

    -- outcome mirrors the claim function's classification.
    outcome        text NOT NULL
                   CHECK (outcome IN ('granted','expired','revoked','exhausted')),

    -- ⚠ The token itself is NEVER stored, here or anywhere. This log would
    -- otherwise be a list of working links, which is a worse disclosure than
    -- the reports it protects.
    client_ip      inet,
    user_agent     text,
    accessed_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX share_access_log_link_idx ON report.share_access_log (share_link_id, accessed_at DESC);
CREATE INDEX share_access_log_tenant_idx ON report.share_access_log (tenant_id, accessed_at DESC);

SELECT app.enable_tenant_rls('report.share_access_log');

-- Append-only BY GRANT, not by convention. An audit trail an application can
-- edit is not an audit trail.
REVOKE UPDATE, DELETE ON report.share_access_log FROM encorebom_app;

-- ---------------------------------------------------------------------------
-- claim_share_download
--
-- ⚠ THE CHECK AND THE INCREMENT ARE ONE STATEMENT, AND THEY HAVE TO BE.
--
-- Read-then-write loses the download cap under concurrency: two requests both
-- read download_count = 4 against max_downloads = 5, both decide there is room,
-- and the link serves six downloads. A conditional UPDATE ... RETURNING
-- serializes on the row instead — the second request blocks, and under READ
-- COMMITTED Postgres re-evaluates the WHERE clause against the row the first
-- one committed, so the cap holds.
--
-- The outcome is classified rather than reduced to "no". A holder who was given
-- a link deserves to know whether it expired or was withdrawn; they already had
-- the token, so this discloses nothing a guesser could reach — a 256-bit token
-- is not enumerable.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION report.claim_share_download(p_token_hash text)
RETURNS TABLE (
    share_link_id  uuid,
    tenant_id      uuid,
    report_id      uuid,
    outcome        text,
    expires_at     timestamptz,
    max_downloads  int,
    download_count int
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = report, app, pg_temp
AS $fn$
DECLARE
    claimed record;
    existing record;
BEGIN
    UPDATE report.share_links AS s
       SET download_count = s.download_count + 1
     WHERE s.token_hash = p_token_hash
       AND s.revoked_at IS NULL
       AND (s.expires_at IS NULL OR s.expires_at > now())
       AND (s.max_downloads IS NULL OR s.download_count < s.max_downloads)
    RETURNING s.id, s.tenant_id, s.report_id, s.expires_at,
              s.max_downloads, s.download_count
      INTO claimed;

    IF FOUND THEN
        share_link_id  := claimed.id;
        tenant_id      := claimed.tenant_id;
        report_id      := claimed.report_id;
        outcome        := 'granted';
        expires_at     := claimed.expires_at;
        max_downloads  := claimed.max_downloads;
        download_count := claimed.download_count;
        RETURN NEXT;
        RETURN;
    END IF;

    -- Not claimable. Find out why — and return NOTHING for a token that does
    -- not exist, so an unknown token and a revoked one are distinguishable only
    -- to someone who already holds a real token.
    SELECT s.id, s.tenant_id, s.report_id, s.expires_at, s.revoked_at,
           s.max_downloads, s.download_count
      INTO existing
      FROM report.share_links AS s
     WHERE s.token_hash = p_token_hash;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    share_link_id  := existing.id;
    tenant_id      := existing.tenant_id;
    report_id      := existing.report_id;
    expires_at     := existing.expires_at;
    max_downloads  := existing.max_downloads;
    download_count := existing.download_count;

    -- ⚠ Revocation is checked FIRST. A revoked link that also happens to be
    -- expired must report `revoked`: revocation is a deliberate act by an
    -- operator, and reporting it as an expiry would hide that somebody withdrew
    -- access on purpose.
    IF existing.revoked_at IS NOT NULL THEN
        outcome := 'revoked';
    ELSIF existing.expires_at IS NOT NULL AND existing.expires_at <= now() THEN
        outcome := 'expired';
    ELSE
        outcome := 'exhausted';
    END IF;

    RETURN NEXT;
END;
$fn$;
-- +goose StatementEnd

COMMENT ON FUNCTION report.claim_share_download(text) IS
'Atomically claims one download against a share link, by token HASH. The check
and the increment are one statement so a concurrent pair cannot both pass a
download cap. Returns no row for an unknown token. Deliberately narrow: takes
one hash, touches one link. Do not widen it.';

GRANT EXECUTE ON FUNCTION report.claim_share_download(text) TO encorebom_app;

-- ---------------------------------------------------------------------------
-- record_share_access
--
-- The audit write needs the same pre-tenant exemption: at the moment of an
-- anonymous download there is no app.current_tenant_id to satisfy the policy,
-- and an access we could not record is an access that did not happen as far as
-- anybody reading the log later is concerned.
--
-- It takes ids the claim function just returned, so it cannot be used to write
-- a row against an arbitrary tenant.
-- ---------------------------------------------------------------------------
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION report.record_share_access(
    p_share_link_id uuid,
    p_outcome       text,
    p_client_ip     inet,
    p_user_agent    text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = report, app, pg_temp
AS $fn$
DECLARE
    link record;
    new_id uuid;
BEGIN
    SELECT s.id, s.tenant_id, s.report_id
      INTO link
      FROM report.share_links AS s
     WHERE s.id = p_share_link_id;

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    INSERT INTO report.share_access_log
        (tenant_id, share_link_id, report_id, outcome, client_ip, user_agent)
    VALUES
        (link.tenant_id, link.id, link.report_id, p_outcome, p_client_ip,
         -- Bounded: the User-Agent is attacker-controlled and unbounded, and an
         -- audit table is not a place to let a caller write megabytes.
         left(p_user_agent, 512))
    RETURNING id INTO new_id;

    RETURN new_id;
END;
$fn$;
-- +goose StatementEnd

COMMENT ON FUNCTION report.record_share_access(uuid, text, inet, text) IS
'Records one share-link access. SECURITY DEFINER because /shared/:token is
unauthenticated and has no tenant in scope. Derives the tenant from the link
rather than accepting one, so it cannot write into another tenant''s log.';

GRANT EXECUTE ON FUNCTION report.record_share_access(uuid, text, inet, text) TO encorebom_app;

-- +goose Down
DROP FUNCTION IF EXISTS report.record_share_access(uuid, text, inet, text);
DROP FUNCTION IF EXISTS report.claim_share_download(text);
DROP TABLE IF EXISTS report.share_access_log;
