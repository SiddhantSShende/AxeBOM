# Phase 14 — Campaigns and notifications

**Estimated: 2 weeks** · Depends on Phase 10.

## Read first

1. `docs/STATE.md`
2. `docs/01-DATA-MODEL.md` §9 (`campaign`, `notify`)
3. `docs/02-CONTRACTS.md` §11 (webhooks)
4. `docs/reference/certin-v2.0.yaml` → `certin.sbom.pp.frequency`, and `secure_distribution` §5.3.4

## Goal

Scheduled recurring scans that run unattended, generate reports, and notify the right people — closing the loop on the CERT-In "Frequency" practice and §5.3.4 (automated generation and updates).

## Preconditions

Scans and reports work end to end. Projects have practices, including `frequency`.

## Out of scope

Notification *content* design beyond the events listed, Slack/Teams integrations (webhooks make them possible), campaign analytics.

## Deliverables

```
services/campaign/
  handler/    CRUD, enable, run-now, runs
  scheduler/  leader election, tick, dispatch
  store/

services/notification/
  email/      templates
  webhook/    HMAC signing, retry, dead-letter
  subscription/

frontend/  campaigns list, schedule wizard, run history, notification settings
```

## Contracts to honour

- **Leader election via a Postgres advisory lock.** No etcd, no Consul, no ZooKeeper — the database is already there and already consistent.
- **`UNIQUE (campaign_id, scheduled_for)`** is what makes triggers idempotent across restarts and leader changes. It is the single most important line in this phase.
- `timezone` is an IANA name. **DST transitions are handled by the scheduler**, not by storing offsets.
- Webhooks are HMAC-signed with **the timestamp inside the signed payload**; reject deliveries older than 5 minutes.
- **Webhook payloads carry ids and counts, never component or finding detail.** A receiver may log the body, and BOM content is confidential under CERT-In §5.3.
- A campaign links to `project.practices.frequency` — the practice is the declaration, the campaign is the implementation.

## Steps

1. Campaign CRUD over multiple projects with the full dimension set: BOM types, levels, standards, formats.
2. Scheduler: acquire an advisory lock, tick every 30 s, find campaigns due, dispatch, release on shutdown. Only the leader dispatches.
3. **Idempotent dispatch.** Insert `campaign.runs` with `(campaign_id, scheduled_for)`; a unique violation means another instance already claimed it — that is success, not an error, and must be handled as such rather than logged as a failure.
4. **Missed-run handling.** After downtime, do not fire every missed occurrence — that is a thundering herd against the scan queue. Fire the most recent missed run once and record the skipped ones in run history so the gap is visible rather than silent.
5. DST: compute the next run in the campaign's timezone. A 02:30 daily run on a spring-forward day must not vanish, and must not fire twice in autumn. **Test both directions with real transition dates.**
6. Email templates: scan complete, new critical findings, campaign failure.
7. Webhooks: HMAC-SHA256, 5 attempts with exponential backoff to 1 h, then dead-letter with the delivery retained for inspection.
8. Subscriptions per tenant with event filters.
9. Frontend: schedule wizard using friendly presets over raw cron (showing and allowing the cron), run history with generated reports, notification settings.
10. Update `docs/STATE.md`.

## Test requirements

- A due campaign fires once, producing a scan.
- **Two scheduler instances → exactly one dispatch.** Kill the leader mid-tick; the other takes over without a duplicate or a gap.
- Restart during a tick does not double-fire (`UNIQUE` holds).
- Missed runs after downtime: one catch-up, the rest recorded as skipped.
- **DST spring-forward and autumn fall-back**, both directions, with real dates.
- Disabled campaign does not fire; re-enabling does not backfill.
- Webhook signature verifies; a replayed delivery older than 5 minutes is rejected; failures retry then dead-letter.
- **Webhook payload contains no component or finding detail** — assert this explicitly.
- Cross-tenant: campaigns of tenant B are invisible and un-triggerable from tenant A.

## Exit criteria

```
go test ./services/campaign/... ./services/notification/... -v
go test ./services/campaign/scheduler -run TestLeaderElection -v
go test ./services/campaign/scheduler -run TestDST -v
task verify
```

Manual: create a campaign at a near-future time → confirm it fires unattended → reports generated → email in Mailpit → webhook delivered and verifiable → run history correct.

## Before you finish

Update `docs/STATE.md`: campaigns working, scheduler tick interval, missed-run policy as implemented, and which notification events are live.
