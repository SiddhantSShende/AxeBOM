# Phase 6 — Scan orchestration

**Estimated: 2 weeks** · Depends on Phase 5.

## Read first

1. `docs/STATE.md`
2. **`docs/02-CONTRACTS.md` §2–§7 — in full.** This phase implements them.
3. `docs/01-DATA-MODEL.md` §3 (schema `scan`)
4. `docs/ADR/0004-one-engine-per-job.md`

## Goal

Create scans, fan out one job per engine, track lifecycle, stream progress, and handle failure honestly. **No engines run yet** — a mock engine proves the machinery.

## Preconditions

Sandbox and fetcher work; the escape suite passes.

## Out of scope

Real adapters (Phase 7), normalization (Phase 8), reports (Phase 9).

## Deliverables

```
services/scan-orchestrator/
  handler/     create, get, cancel, engine-runs, WS progress
  orchestr/    fanout, lifecycle, aggregate, reaper
  policy/      engine resolution from families + engine_policy table

libs/go-shared/bus/     JetStream publish/subscribe, typed envelopes
libs/go-shared/events/  ScanJobV1, ScanEventV1, ScanResultV1
proto/schemas/*.json    published JSON Schemas

workers/_mock/          a mock engine: sleeps, emits progress, returns fixed output
```

## Contracts to honour

- **One engine per job.** `ScanJobV1.engine` is a single id.
- **`partial` is a first-class status**, not an error.
- **Scan status derives mechanically** — never hand-set. All succeeded → `completed`; ≥1 succeeded and ≥1 not → `completed_with_errors`; zero → `failed`.
- **Idempotency on `job_id`.** A worker's first action is `HEAD <output.prefix>manifest.json`; present → re-emit and ack.
- Output keys embed `job_id`, so a retry never overwrites a prior attempt's artifacts.
- **Events are advisory and lossy-tolerant. The database is the source of truth.**
- `engine_db_version` is **required** for vulnerability engines.
- **Invalid engine/source combinations are rejected at create time with a 422** enumerating every offending pair.

## Steps

1. Define the three envelopes in `libs/go-shared/events`; generate JSON Schemas into `proto/schemas/`; validate on publish and consume.
2. JetStream streams and consumers per `02-CONTRACTS.md §2`: `max_deliver=4`, `ack_wait=30m`, backoff 30s/2m/8m, DLQ.
3. `POST /scans`: validate the combination against the engine registry, **reject early with the full list of offending pairs**, persist, publish one fetch job.
4. On fetch result: fan out one job per resolved engine, each pointing at the same archive.
5. On each engine result: upsert `scan.engine_runs` on `(scan_id, engine)`, taking the highest `attempt` with `status != failed`; recompute scan status mechanically.
6. WebSocket: **send a snapshot on connect**, then stream events. The snapshot is what makes a lossy stream acceptable — a reconnecting client must be immediately correct.
7. Deadline reaper, leader-elected via a **Postgres advisory lock**. No etcd, no Consul.
8. Retry classification: infra → retryable; bad input, unsupported source kind, engine unavailable, config-schema violation → **ack immediately**, publish `failed`, do not burn retries.
9. Populate `scan.ecosystems_detected` including `engine_available = false` rows — the honest denominator that feeds Engine Coverage.
10. Mock engine to exercise all of it. Update `docs/STATE.md`.

## Test requirements

- **Kill a worker mid-job** → redelivered → **zero duplicate artifacts** (this is the idempotency proof, and it is the one that matters).
- Replaying a completed `job_id` re-emits the stored result without re-running.
- Scan status derivation: all-succeeded, mixed, all-failed, and the `partial`-only case.
- A job past `deadline_at` is reaped as `timeout` within a minute; killing the leader lets another instance take the advisory lock.
- Non-retryable failure acks immediately and does not consume `max_deliver`.
- Poison message reaches the DLQ after 4 attempts.
- WebSocket: snapshot on connect; drop and reconnect mid-scan yields correct state; out-of-order `seq` reorders; a gap does not corrupt display.
- **Invalid combination is a 422 listing every offending pair**, not a partial scan discovered later.
- Envelopes validate against the published schemas; an unknown field is ignored, not fatal.
- Cross-tenant: scans of tenant B are invisible and un-cancellable from tenant A.

## Exit criteria

```
go test ./services/scan-orchestrator/... -v
go test ./libs/go-shared/{bus,events} -v
task verify
```

Manual: create a scan with the mock engine → watch live per-engine progress → kill a worker → confirm redelivery and a single artifact set → confirm status is `completed_with_errors` when one mock engine fails.

## Before you finish

Update `docs/STATE.md`: envelopes frozen, schema paths, and any contract detail that changed (update `02-CONTRACTS.md` too — it is the SSOT).
