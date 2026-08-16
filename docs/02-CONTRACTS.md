# 02 — Contracts

> **⚑ SSOT for anything crossing a process boundary.** NATS subjects, job/event/result envelopes, REST conventions, the error taxonomy, WebSocket protocol, webhooks. If two processes exchange it, it is defined here and nowhere else.

**Related:** persisted shapes in `01-DATA-MODEL.md`. Engine capabilities in `04-OSINT-INTEGRATION.md`. Machine-readable JSON Schemas live in `proto/schemas/` and are generated from this document — the schemas are the enforcement, this is the explanation.

---

## 1. Versioning

Every envelope carries `schema_version` as `<name>/v<N>`. Rules:

- **Additive changes** (new optional field) do not bump the version. Consumers must ignore unknown fields.
- **Breaking changes** bump `v<N>` and both versions are consumed in parallel for at least one release.
- Producers write one version. Consumers accept a set.
- Never reuse a field name with a different meaning. Add a new one and deprecate the old.

---

## 2. NATS JetStream topology

| Stream | Subjects | Retention | Consumer | Notes |
|---|---|---|---|---|
| `SCAN_JOBS` | `scan.job.<family>` | WorkQueue | pull, `max_deliver=4`, `ack_wait=30m` | backoff 30s / 2m / 8m; failures land in `scan.dlq.<family>` |
| `SCAN_EVENTS` | `scan.event.<scan_id>` | Limits, 24 h | push, ephemeral | **advisory only** |
| `SCAN_RESULTS` | `scan.result.<family>` | WorkQueue | pull, normalizer | |
| `SCAN_DLQ` | `scan.dlq.<family>` | Limits, 30 d | manual | poison messages, retained for diagnosis |
| `NOTIFY` | `notify.<event_type>` | WorkQueue | notification-svc | |

`<family>` ∈ `fetch`, `sbom`, `cbom`, `qbom`, `aibom`, `hbom`.

> **`SCAN_EVENTS` is advisory and lossy-tolerant. The database is the source of truth.** If the WebSocket drops or an event is lost, a page refresh reads state from Postgres and is correct. **No event is ever required for correctness** — building progress logic that depends on receiving every event is a bug.

`ack_wait=30m` matches the sandbox wall-clock ceiling. A job that exceeds it is redelivered, which is safe because jobs are idempotent (§4).

> **A WorkQueue stream permits exactly ONE consumer per filter subject.** NATS refuses a second with `filtered consumer not unique on workqueue stream`. This dictates the deployment shape: every worker for a family shares ONE durable name and NATS distributes between them. Giving each worker instance its own durable is rejected at startup — which is the constraint surfacing early, where it should.

> **Retry backoff requires `NakWithDelay`, not `Nak`.** The consumer's `BackOff` setting governs `ack_wait` EXPIRY — a worker that died silently — not an explicit nak. A bare `Nak()` redelivers immediately, so a failing job spins as fast as the consumer can loop and burns all four delivery attempts in milliseconds. Measured at 0.05s against a schedule whose first step is 30 seconds.

---

## 3. Scan lifecycle

```
POST /scans
   │
   ├─ validate: engines resolve, combinations legal ──► 422 with the offending pairs
   │                                                    (never discovered 20 min into a scan)
   ├─ persist scan (status=queued)
   │
   ├─ publish ONE fetch job ──► fetcher
   │        clones/downloads INSIDE the sandbox
   │        records commit_sha  ← written exactly once
   │        uploads content-addressed archive
   │        publishes fetch result
   │
   ├─ orchestrator fans out ONE JOB PER ENGINE
   │        every engine reads THE SAME archive
   │        engines hold NO credentials
   │
   ├─ each engine publishes ScanResultV1 ──► normalizer
   │
   └─ derive scan status mechanically, render reports async
```

Two structural decisions, both load-bearing:

**One engine per job.** Retry, timeout, partial failure and progress all become per-engine. The alternative — one job per family running all its tools — makes partial failure ambiguous and forces re-running Syft because Dependency-Check timed out.

**The fetcher materializes source exactly once.** Six engines cloning the same branch independently can land on **six different commits in one report**, describing a codebase that never existed. Fetching once also means only the fetcher needs git credentials, so every component that runs a third-party scanner over untrusted code holds zero secrets. See ADR-0008.

---

## 4. `ScanJobV1`

```jsonc
{
  "schema_version": "scan.job/v1",
  "job_id":     "uuid",              // idempotency key AND artifact path segment
  "scan_id":    "uuid",
  "tenant_id":  "uuid",
  "project_id": "uuid",

  "family": "sbom",                  // fetch | sbom | cbom | qbom | aibom | hbom
  "engine": "syft",                  // EXACTLY ONE
  "engine_version_constraint": "1.19.x",

  "attempt":    1,
  "issued_at":  "2026-08-16T09:14:22Z",
  "deadline_at":"2026-08-16T09:29:22Z",

  "workspace": {
    "artifact_uri": "s3://encorebom/workspaces/<scan_id>/source.tar.zst",
    "sha256":       "…",
    "size_bytes":   0,
    "root_subpath": ""
  },
  "source_meta": {
    "kind":         "git",           // git | upload | image
    "commit_sha":   "…",             // pinned by the fetcher
    "image_digest": null
  },

  "engine_config": {},               // validated against the engine's JSON Schema AT ENQUEUE

  "limits": {
    "wall_clock_sec": 900,
    "cpu_millis":     2000,
    "memory_mb":      4096,
    "disk_mb":        20480,
    "pids_max":       512,
    "max_output_bytes": 268435456
  },
  "output": { "prefix": "s3://encorebom/scans/<scan_id>/raw/<engine>/<job_id>/" },
  "trace":  { "traceparent": "00-…", "correlation_id": "…" }
}
```

> **There is no credential field, and there never will be.** This is deliberate and load-bearing. If you find yourself needing to add one, the design has gone wrong — route the work through the fetcher instead.

`engine_config` is validated against the per-engine JSON Schema **at enqueue time**, not at worker time.

### Idempotency and retry

- `job_id` is the key. A worker's **first action** is `HEAD <output.prefix>manifest.json`. Present and complete → re-emit the stored result, ack, exit.
- Output keys embed `job_id`, so a retry never overwrites a prior attempt's artifacts.
- `scan.engine_runs` has `UNIQUE(job_id)`. The normalizer upserts on `(scan_id, engine)`, taking the highest `attempt` with `status != failed`.

| Class | Examples | Action |
|---|---|---|
| **Retryable** | network, S3 5xx, OOM-kill, undocumented crash | nak with backoff |
| **Non-retryable** | corrupt archive, unsupported source kind, engine unavailable, config schema violation | **ack immediately**, publish `failed`, do not burn retries |

The deadline reaper marks jobs past `deadline_at` as `timeout`. It is leader-elected via a **Postgres advisory lock** — no etcd, no Consul.

---

## 5. `ScanEventV1`

```jsonc
{
  "schema_version": "scan.event/v1",
  "event_id": "uuid",
  "scan_id":  "uuid",
  "job_id":   "uuid",
  "tenant_id":"uuid",
  "engine":   "syft",
  "seq":      7,                     // monotonic PER job_id — gaps are detectable
  "ts":       "2026-08-16T09:15:03Z",
  "phase":    "running",             // queued|fetching|preparing|running|parsing|uploading|done|failed
  "pct":      42,
  "message":  "cataloguing npm packages",   // <=200 chars
  "metrics":  { "components_found": 512 }
}
```

Rules:

- Consumers **reorder by `seq`** and tolerate gaps.
- `message` **never contains a user path, a repository URL, or anything from the scanned code.** Event streams reach browsers and logs; treat them as public.
- Overall scan percentage is a weighted mean over engines using `scan.engine_runs.weight`, computed by the orchestrator — not by the client.

---

## 6. `ScanResultV1`

```jsonc
{
  "schema_version": "scan.result/v1",
  "job_id": "uuid", "scan_id": "uuid", "tenant_id": "uuid",

  "engine": "grype",
  "engine_version": "0.87.0",
  "engine_db_version": "grype-db v5 2026-08-15T00:00:00Z",   // REQUIRED for vuln engines

  "invocation": {
    "argv_redacted": ["grype", "sbom:…", "-o", "json"],
    "image_digest":  "sha256:…",
    "started_at": "…", "finished_at": "…", "duration_ms": 41211, "exit_code": 0
  },

  "status": "partial",   // succeeded | partial | failed | timeout | unavailable | skipped

  "artifacts": [{
    "role": "native_output",
    "uri":  "s3://…/grype.json",
    "media_type": "application/vnd.cyclonedx+json; version=1.6",
    "sha256": "…", "size_bytes": 918273
  }],

  "ecosystems_covered": ["npm", "pypi", "golang"],

  "summary": { "components": 1421, "vulnerabilities": 88, "licenses": 34, "crypto_assets": 0 },

  "diagnostics": [{
    "severity": "warn",
    "code": "ENGINE_PARTIAL_ECOSYSTEM",
    "ecosystem": "maven",
    "message": "pom.xml at services/api failed to parse",
    "hint": "malformed XML at line 44"
  }],

  "error": null
}
```

### Status semantics

`partial` is a **first-class status, not an error** — Grype covered 11 of 12 ecosystems because one lockfile was malformed. That is useful output plus a known gap, and both must survive into the report.

Scan status derives mechanically, never by hand:

| Engine runs | Scan status |
|---|---|
| all `succeeded` | `completed` |
| ≥1 succeeded **and** ≥1 failed / partial / timeout / unavailable | `completed_with_errors` |
| zero succeeded | `failed` |

**`engine_db_version` is required for every vulnerability engine.** Without it a finding cannot be dated, and a compliance report that cannot say "matched against vulnerability data as of X" is not defensible.

### The Engine Coverage guarantee

Every generated report carries a mandatory **Engine Coverage** section: each requested engine, its terminal status, the ecosystems it covered, and ecosystems detected with **no available engine**.

> An SBOM that silently omits an ecosystem is worse than no SBOM: it converts an unknown into a false negative the customer trusts. This section is not optional and may not be suppressed by a report template.

---

## 7. Engine registry

Adapters are keyed on a stable `engine_id`. **The unit is (tool, mode), not tool** — `trivy fs` and `trivy image` have different capabilities and different parsers, so they are different engines.

`syft` · `trivy-fs` · `trivy-image` · `grype` · `osv-scanner` · `dependency-check` · `cbomkit-theia` · `cbomkit` · `aibom-generator` · `ai-bom` · `hbom-csv`

Each declares:

```jsonc
{
  "engine_id": "trivy-fs",
  "families": ["sbom"],
  "source_kinds": ["git", "upload"],
  "ecosystems": ["npm","pypi","maven","golang","gem","cargo","nuget","deb","rpm","apk"],
  "produces": ["components","vulnerabilities","licenses","secrets"],
  "native_format": "cyclonedx-json-1.6",
  "requires": ["vuln_db"],
  "db_backed": true,
  "default_weight": 3,
  "graph_trust": { "npm": 2, "pypi": 2, "maven": 1 }   // higher wins; see 03-NORMALIZER-SPEC
}
```

Resolution: user picks families (plus optional per-scan overrides) → orchestrator resolves through the `engine_policy` **table**, so defaults are data, tenant-overridable, and changeable without a deploy.

Runtime availability: **container → local binary → `unavailable`**. A missing engine marks itself `unavailable` and is recorded; it **never fails the whole scan**.

**Invalid combinations are rejected at scan-create time with a 422 enumerating every offending pair.** Discovering at worker time that `cbomkit-theia` cannot process an `image` source, twenty minutes in, is a design failure.

---

## 8. REST conventions

Base `/api/v1`. JSON only. `Content-Type: application/json; charset=utf-8`.

**Auth.** `Authorization: Bearer <access_jwt>`. Access TTL 15 min, refresh 30 days rotating. The JWT carries `sub`, `tenant_id`, `role`, `exp`, `jti`. The gateway sets `app.current_tenant_id` from the **token**, never from a header or query parameter.

**Pagination.** Keyset only, never `OFFSET` — at 200k findings, `OFFSET` is a table scan.

```
GET /projects/{id}/dependencies?limit=100&cursor=<opaque>
→ { "items": [...], "next_cursor": "…" | null, "total_estimate": 14213 }
```

`total_estimate` is explicitly an estimate; an exact count over a partitioned table is too expensive to promise.

**Idempotency.** `POST` endpoints that create work accept `Idempotency-Key`. Replaying within 24 h returns the original response.

**Filtering.** `?filter[severity]=critical,high&filter[license]=GPL-3.0-only&filter[direct]=true`. Unknown filter keys are a 422, not silently ignored — silent ignoring produces a result set the user believes is filtered.

**Rate limits.** `X-RateLimit-Limit` / `-Remaining` / `-Reset`. 429 carries `Retry-After`.

### Surface

```
POST   /auth/register                POST /auth/login          POST /auth/refresh
GET    /auth/github/authorize        POST /auth/github/callback
POST   /auth/logout                  GET  /auth/me

GET    /projects                     POST /projects
GET    /projects/:id                 PATCH /projects/:id       DELETE /projects/:id
PUT    /projects/:id/practices                                 # CERT-In Table 5 cat. 3
POST   /projects/:id/connect-repo    GET  /integrations/github/repos
POST   /projects/:id/uploads

POST   /projects/:id/scans           GET  /scans/:id           POST /scans/:id/cancel
GET    /scans/:id/engine-runs        WS   /scans/:id/progress

GET    /projects/:id/dependencies    GET  /components/:id
GET    /projects/:id/findings        GET  /findings/:id

GET    /reports/:id                  GET  /reports/:id/download
POST   /reports/:id/share            DELETE /shares/:token
GET    /shared/:token                                          # unauthenticated, token-gated
GET    /reports/:id/comments         POST /reports/:id/comments

POST   /projects/:id/vex             PATCH /vex/:id            GET /vex/:id/history
GET    /vex/:id/csaf

GET    /campaigns                    POST /campaigns
PATCH  /campaigns/:id                POST /campaigns/:id/run-now
GET    /campaigns/:id/runs
```

Every scan-creation request carries `bom_types[]`, `report_levels[]`, `standards[]`, `formats[]`, and optionally `engines[]`.

---

## 9. Error taxonomy

Every error returns the same shape. **Never a bare string.**

```jsonc
{
  "error": {
    "code": "SCAN_ENGINE_COMBINATION_INVALID",
    "message": "cbomkit-theia cannot process source kind 'image' for this project",
    "details": [{ "engine": "cbomkit-theia", "source_kind": "image" }],
    "request_id": "01J…",
    "docs": "https://docs.encorebom.io/errors/SCAN_ENGINE_COMBINATION_INVALID"
  }
}
```

Codes are `SCREAMING_SNAKE`, stable forever, and grouped by prefix. `message` is human-facing and may change; **`code` is the API contract** and clients branch on it.

| Prefix | HTTP | Examples |
|---|---|---|
| `AUTH_` | 401 | `AUTH_TOKEN_EXPIRED`, `AUTH_INVALID_CREDENTIALS`, `AUTH_MFA_REQUIRED` |
| `PERM_` | 403 | `PERM_ROLE_INSUFFICIENT`, `PERM_REPORT_PRIVATE` |
| `NOTFOUND_` | 404 | `NOTFOUND_PROJECT`, `NOTFOUND_REPORT` |
| `VALIDATION_` | 422 | `VALIDATION_FIELD_REQUIRED`, `VALIDATION_FILTER_UNKNOWN` |
| `SCAN_` | 422 / 409 | `SCAN_ENGINE_COMBINATION_INVALID`, `SCAN_ALREADY_RUNNING`, `SCAN_SOURCE_UNREACHABLE` |
| `FETCH_` | 422 | `FETCH_URL_SCHEME_FORBIDDEN`, `FETCH_PRIVATE_ADDRESS_BLOCKED`, `FETCH_ARCHIVE_TOO_LARGE`, `FETCH_INFLATION_RATIO_EXCEEDED` |
| `ENGINE_` | — | `ENGINE_UNAVAILABLE`, `ENGINE_PARTIAL_ECOSYSTEM`, `ENGINE_TIMEOUT`, `ENGINE_DB_STALE` |
| `NORMALIZE_` | — | `NORMALIZE_IDENTITY_OPAQUE`, `NORMALIZE_ALIAS_CLUSTER_OVERSIZE`, `NORMALIZE_LICENSE_AMBIGUOUS`, `NORMALIZE_NO_VERSION_COMPARATOR` |
| `REPORT_` | 422 / 500 | `REPORT_TOO_LARGE_FOR_PDF`, `REPORT_RENDER_FAILED`, `REPORT_SIGNATURE_FAILED` |
| `RATE_` | 429 | `RATE_LIMIT_EXCEEDED` |
| `INTERNAL_` | 500 | `INTERNAL_UNEXPECTED` |

**Cross-tenant access returns `NOTFOUND_*` with 404, never 403.** A 403 confirms the resource exists, which is itself a leak.

`ENGINE_*` and `NORMALIZE_*` codes are usually **diagnostics attached to a result**, not HTTP responses. They surface in the report rather than failing a request.

---

## 10. WebSocket

`WS /api/v1/scans/:id/progress`, authenticated by the same bearer token via `Sec-WebSocket-Protocol` (never a query parameter — query strings land in access logs).

Server→client frames are `ScanEventV1` plus one snapshot on connect:

```jsonc
{ "schema_version": "scan.snapshot/v1", "scan_id": "…", "status": "running",
  "overall_pct": 38,
  "engines": [ { "engine": "syft", "status": "succeeded", "pct": 100 },
               { "engine": "grype", "status": "running",  "pct": 41 } ] }
```

The snapshot is why the stream can be lossy: a client that reconnects is immediately correct. Heartbeat ping every 30 s; the client reconnects with exponential backoff and re-reads the snapshot. Client→server frames are ignored other than `pong`.

---

## 11. Webhooks

`POST` to the subscriber URL with:

```
X-EncoreBOM-Event: scan.completed
X-EncoreBOM-Delivery: <uuid>
X-EncoreBOM-Signature: t=<unix>,v1=<hex hmac-sha256 of "t.body">
```

The timestamp is inside the signed payload to prevent replay; reject deliveries older than 5 minutes. Retries: 5 attempts, exponential backoff to 1 h, then dead-letter.

Events: `scan.completed`, `scan.failed`, `report.ready`, `finding.critical.new`, `campaign.run.completed`, `vex.updated`.

Payloads carry **ids and counts, never component or finding detail** — a webhook body may be logged by the receiver, and BOM content is confidential under CERT-In §5.3.

---

## 12. Internal gRPC

Service-to-service calls use gRPC with proto in `proto/`. Every RPC carries `tenant_id` and `traceparent` in metadata; the receiving interceptor sets `app.current_tenant_id` from metadata and **rejects any RPC without it**.

Deadlines are mandatory and propagated. Retries only on `UNAVAILABLE` and `DEADLINE_EXCEEDED`, with jitter, capped at 3.

Contract tests live beside each service and run in CI: a change to a proto that breaks a consumer fails the build, which is the mechanical guard that replaces the coherence a monolith would give for free.
