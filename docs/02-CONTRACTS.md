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
| `NOTIFY` | `notify.<event_type>` | WorkQueue | notification-svc | envelope: `events`' `NotifyEventV1` (§11) |
| `NORMALIZE_JOBS` | `scan.normalize.<family>` | WorkQueue | pull, the normalize consumer | envelope: `NormalizeTriggerV1` (§6a). **Deliberately a separate stream from `SCAN_JOBS`**: normalization is CPU-bound in-process work finishing in seconds–minutes, not a sandboxed container run — sharing `SCAN_JOBS`'s 30-minute `ack_wait` would hold a stuck normalization message hostage far longer than the work ever legitimately takes |

`<family>` ∈ `fetch`, `webrecon`, `sbom`, `cbom`, `qbom`, `aibom`, `hbom`.

> **`webrecon` is `fetch`'s sibling, not a variant of it.** `CreateScan` publishes `scan.job.webrecon` INSTEAD of `scan.job.fetch` when `source_kind == url` — services/webrecon (subdomain discovery + JS fingerprinting, project-registration plan Milestone 5) materializes a url source's input the way the fetcher materializes a git/upload source's, but produces a native discovery document instead of a source archive. Both are "producer" families: `ScanJobV1.Validate` exempts only these two from requiring `workspace.artifact_uri`/`workspace.native_sbom_ref` to already be set on THEIR OWN job.

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
   ├─ each engine publishes ScanResultV1 ──► scan-orchestrator records it,
   │        derives scan status mechanically
   │
   ├─ once every engine dispatched for one family reaches a terminal state,
   │  scan-orchestrator publishes ONE NormalizeTriggerV1 ──► normalize consumer
   │        (§6a; currently wired for the sbom family only)
   │
   └─ normalize consumer writes normalize.bom_documents + children; reports
      render from there async
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
    "artifact_uri": "s3://axebom/workspaces/<scan_id>/source.tar.zst",
    "sha256":       "…",
    "size_bytes":   0,
    "root_subpath": "",
    "native_sbom_ref": null             // set only for github-dependency-graph-sbom; see §7
  },
  "source_meta": {
    "kind":         "git",           // git | upload | image | url
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
  "output": { "prefix": "s3://axebom/scans/<scan_id>/raw/<engine>/<job_id>/" },
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

## 6a. `NormalizeTriggerV1`

Published by scan-orchestrator once every engine job dispatched for one `(scan, family)` pair has reached a terminal state — a genuinely new envelope, not a `ScanJobV1` disguised as one, because there is no engine to run here, only a normalization pass to trigger.

```jsonc
{
  "schema_version": "scan.normalize/v1",
  "trigger_id": "uuid",           // the scan.normalize_triggers row's id; also the Nats-Msg-Id dedup key
  "scan_id": "uuid", "tenant_id": "uuid", "project_id": "uuid",

  "family": "sbom",
  "normalization_version": 1,

  "source_commit_sha": "…",              // from scan.scans, pinned once by the fetcher
  "workspace_archive_sha256": "…",

  "ecosystems_without_engine": ["cargo"],  // from scan.ecosystems_detected, the honest gap

  "issued_at": "…",

  "engines": [{
    "engine_id": "syft",
    "engine_version": "1.51.0",
    "engine_db_version": "",
    "status": "succeeded",
    "artifacts": [{ "role": "native_output", "uri": "…", "media_type": "…", "sha256": "…", "size_bytes": 0 }],
    "ecosystems_covered": ["npm"]
  }]
}
```

The envelope is deliberately self-contained: it carries every artifact URI and engine status the consumer needs, so the normalize consumer never has to query `scan.*` — it only ever needs a `normalize`-schema-scoped credential (see below).

**Fired exactly once per `(scan_id, family)`.** `scan.normalize_triggers` is the write-once guard: `INSERT ... ON CONFLICT (scan_id, family) DO NOTHING`, mirroring `SetSourceOnce`'s idiom. A redelivered `ScanResultV1` that re-triggers `RecomputeScanStatus` after normalization has already fired writes no second row and publishes nothing.

**Readiness is derived from the same `scan.engine_runs` rows `RecomputeScanStatus` already reads**, filtered to the engines actually dispatched for this family (not a hardcoded engine count — a scan with no container target never dispatches `trivy-image`, and readiness must not wait on an engine that was never queued).

**Currently wired for the `sbom` family only**, via an explicit guard in scan-orchestrator — CBOM/AIBOM triggers are a straightforward extension of the same mechanism, not a redesign.

### The one deliberate credential exception

The normalize consumer is the **only** worker-side process that holds a Postgres credential — everywhere else, "workers hold no credentials" (`axebom_shared.config`'s docstring) is a hard rule, because scan/CBOM/AIBOM workers run third-party scanners over untrusted user code. The normalize consumer never runs a scanner and never touches a scanned repository's contents directly; it only reads already-stored, already-validated raw artifacts and writes canonical rows. Its credential is scoped to the `normalize` Postgres schema only, `SELECT`/`INSERT` (append-only, per CLAUDE.md invariant 10) plus one narrow column-level `UPDATE` on `normalize.vuln_clusters` — see `migrations/normalize/0006_alias_snapshot.sql`.

---

## 7. Engine registry

Adapters are keyed on a stable `engine_id`. **The unit is (tool, mode), not tool** — `trivy fs` and `trivy image` have different capabilities and different parsers, so they are different engines.

`syft` · `trivy-fs` · `trivy-image` · `grype` · `osv-scanner` · `dependency-check` · `github-dependency-graph-sbom` · `cbomkit-theia` · `cbomkit` · `aibom-generator` · `ai-bom` · `hbom-csv`

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

**`qbom` cannot be requested as a scan family.** `qbom-derive` (`derived`) is the only engine registered for it, and `workers/qbom` deliberately has no runner — a QBOM is derived from CBOM discovery plus a Table 8 device form, not scanned. `POST /v1/scans` rejects `families: ["qbom"]` — alone or mixed with other, scannable families, naming only the actual offender — and any explicit `engines: [...]` entry naming `qbom-derive` directly, with `SCAN_FAMILY_NOT_DIRECTLY_SCANNABLE` (§9) at create time — never by publishing a job nothing consumes and letting the scan sit unconsumed until the reaper times it out. QBOM becomes available automatically once a CBOM report exists for the project.

> ⚠ **This paragraph used to say `hbom` too, and that stopped being true.** It asserted that `hbom-csv` was the only engine registered for the family and that `workers/hbom` has no runner. Both are false: `hbom-ecad` (git, upload) and `hbom-cdxgen-host` (upload) are registered, `workers/hbom/runner.py` exists, and `hbom-worker` is a live service in `deploy/compose/docker-compose.app.yml`. HBOM was removed from `familyRedirect` when `hbom-ecad` shipped. The refusal rule itself never changed — a family is refused only when *every* engine in it is import-only or derived — which is exactly why the code needed no edit and this prose did.
>
> `hbom-csv` and `hbom-form` remain import paths (`/v1/hbom/*`) and declare no source kind, so they are never dispatched; that is what keeps them out of fan-out while `hbom-ecad` makes the family scannable.

**`github-dependency-graph-sbom` also sets `requires_import` but is NOT excluded the way `hbom-csv`/`qbom-derive` are.** The exclusion above fires only when *every* engine registered for a family is import-only or derived — `sbom` also has syft, grype, trivy-fs, and so on, so `ValidateCombination` never rejects it, and a normal `scan.job.sbom` is published and consumed by `workers/sbom` exactly like any other SBOM engine's job. It additionally sets `consumes_native_sbom` (a second flag, orthogonal to `requires_import`): FanOut populates `Workspace.NativeSBOMRef` on this one engine's job from whatever the fetcher staged under `scan.raw_artifacts` role `native_output`, engine `fetcher` — empty, and therefore `unavailable`, on every scan where the fetcher found nothing to stage.

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

> ⚠ **This block is the DESIGN surface and has drifted from the code.** The
> authoritative list is each service's `routes.go`, which
> `TestEveryRouteIsGuardedOrDeliberatelyPublic` parses and
> `TestEveryRoutePatternRegistersWithoutConflict` actually mounts. Known
> divergences left as-is rather than silently "corrected": several paths here
> are the pre-implementation shape (`/projects/:id/connect-repo` is
> `/projects/:id/connections`; `/projects/:id/scans` is `POST /v1/scans` with a
> `project_id` in the body). The pre-ZITADEL local-JWT routes have been REMOVED
> from this list because they were removed from the service — see
> `services/auth/routes.go`.

```
GET    /auth/config                                            # unauthenticated, OIDC bootstrap for the SPA
POST   /auth/signup                                            # unauthenticated, creates an organisation + its Owner in ZITADEL

GET    /auth/github/connect/authorize   GET /auth/github/connect/callback   # repo-scoped, see below

GET    /projects                     POST /projects
GET    /projects/:id                 PATCH /projects/:id       DELETE /projects/:id
PUT    /projects/:id/practices                                 # CERT-In Table 5 cat. 3
POST   /projects/:id/connect-repo    GET  /integrations/github/repos
POST   /projects/:id/uploads
POST   /projects/:id/web-sources     GET  /projects/:id/web-sources

POST   /projects/:id/scans           GET  /scans/:id           POST /scans/:id/cancel
GET    /scans/:id/engine-runs        WS   /scans/:id/progress

GET    /projects/:id/dependencies    GET  /components/:id
GET    /projects/:id/findings        GET  /findings/:id

GET    /reports/:id                  GET  /reports/:id/download
POST   /reports/:id/share            DELETE /shares/:token
GET    /shared/:token                                          # unauthenticated, token-gated
GET    /comments?report_id=:id       POST /comments
PUT    /comments/:id                 DELETE /comments/:id

GET    /hbom/:projectId              POST /hbom/:projectId/components
POST   /hbom/headers                 GET  /hbom/component-form
POST   /hbom/preview                 POST /hbom/:projectId/import    # and /hbom/import (compat)
GET    /hbom/:projectId/devices      POST /hbom/:projectId/devices
GET    /hbom/:projectId/devices/:deviceId
PUT    /hbom/:projectId/devices/:deviceId    DELETE /hbom/:projectId/devices/:deviceId

POST   /projects/:id/vex             PATCH /vex/:id            GET /vex/:id/history
GET    /vex/:id/csaf

GET    /campaigns                    POST /campaigns
PATCH  /campaigns/:id                POST /campaigns/:id/run-now
GET    /campaigns/:id/runs
```

**The GitHub "connect" flow is not sign-in, and returns a token, not a session.**
`GET /auth/github/authorize`/`callback` resolves or creates an AxeBOM user and
sets the refresh cookie — that is account sign-in, scope `read:user
user:email`. `GET /auth/github/connect/authorize`/`callback` is a second,
independent OAuth round trip on the *same* GitHub OAuth App (a second
registered callback URL — GitHub OAuth Apps support more than one), scope
`repo`, triggered from a popup the project wizard opens. Its callback sets no
cookie and creates no user; it redirects the popup to
`{frontend}/projects/github-connect#access_token=…` — the token in the URL
**fragment**, exactly like the login callback's `#access_token=…`, so it never
reaches a server log, a proxy log or a `Referer` header. The popup relays it to
the tab that opened it via `postMessage` (origin-checked both ways) and
closes. That token is then supplied to `GET /github/repos` and, if the caller
picks a repository, to `POST /projects/:id/connections` — it is never
persisted by the SPA and never touches Postgres; only Vault ever stores it,
via the connections endpoint exactly as any other repository credential does.

**`POST/GET /projects/:id/web-sources`** attaches/lists a project's `url`
source (`project.web_sources`, `01-DATA-MODEL.md` §2). No credential path —
unlike the connections and uploads endpoints, there is nothing to store in
Vault. `source_kind: "url"` is a valid, schema- and orchestrator-accepted
scan source as of this milestone, but `CreateScan` currently resolves it to
`SCAN_NO_ENGINES_AVAILABLE`: the fetcher stages the one root page as a raw
artifact, and no engine yet consumes it. That gap closes with `services/
webrecon` (subdomain discovery + JS fingerprinting) — until then, a
url-sourced project can be registered but not scanned, and the wizard says so.

Every scan-creation request (`POST /v1/scans`) carries `project_id`,
`source_kind` and `families[]`, and optionally `engines[]` — `families` is
which engine groups run (`sbom`, `cbom`, …), lowercase, matching
`events.Family`.

**`families[]` may never contain `qbom`** — see §7. It is a valid value of
`events.Family` (`scan.engine_policy` still keys tenant overrides by it) but it
is not something an engine scans; requesting it, or naming `qbom-derive` in
`engines[]` directly, is refused at create time with
`SCAN_FAMILY_NOT_DIRECTLY_SCANNABLE` (§9), not resolved into a job that nothing
consumes. Naming `hbom-csv` or `hbom-form` directly is refused the same way —
both declare no source kind — while the `hbom` FAMILY is scannable through
`hbom-ecad`.

> ⚠ **This used to say `hbom` too.** It stopped being true when `hbom-ecad`
> shipped; see the note in §7.

**`POST /auth/signup`** takes `{organisation_name, email, password, given_name,
family_name}` and returns `201 {organisation_name, email}` — no ZITADEL or
AxeBOM id, because the `auth.tenants`/`auth.users` projection for the new
organisation is created lazily on the visitor's first sign-in
(`auth.identity_for`, `migrations/auth/0003_zitadel_identity.sql`), not by
this call. It creates the organisation and its first user, as Owner, in
ZITADEL — see `services/gateway/internal/signup` for why this exists
alongside ZITADEL's own (deliberately disabled) self-registration. A taken
organisation name or email answers `AUTH_ORG_NAME_TAKEN` /
`AUTH_EMAIL_TAKEN` (§9), never by silently attaching the visitor to the
existing one.

**`GET`/`PUT`/`DELETE /v1/github/connection` are tenant-scoped, not project-scoped.**
The organisation connects GitHub once; every project then picks a repository
with no further authorisation. `GET` answers `200 {connected: false}` rather
than 404 when there is none — that is the state every tenant starts in, not a
missing resource — and no response ever carries the token or its Vault path.
`PUT` (not `POST`) replaces the single connection, because reconnecting is the
normal repair for an expired authorisation.

`GET /v1/github/repos` now prefers that stored credential and treats
`X-GitHub-Token` as a fallback for the connect flow itself. Previously the
header was mandatory, which meant the browser held a GitHub token and sent it
back out on every keystroke of a repository search.

**`GET /v1/projects/options` publishes registration sources PER BOM TYPE, not as
one flat list.** Each entry in `bom_types[]` carries `sources[]` — the project
`source_type` values that BOM type can actually be registered from — alongside
`requires_import` and `is_derived`. The top-level `source_types[]` remains as
the union of those lists and is derived from them, never written independently.

⚠ **The per-type list is the contract; the flat one is a convenience.** They
were one list for all five types, so a client could offer, and the server would
accept, an AIBOM project registered from a `url` — a source no AIBOM engine
reads, producing an empty AIBOM forever with nothing said. `POST /v1/projects`
and `PATCH /v1/projects/{id}` now refuse any classification whose `sources[]`
excludes the project's source type (`VALIDATION_FIELD_INVALID`, §9). A client
that renders from the flat list alone will therefore offer combinations the
server refuses.

Each `bom_types[]` entry also carries `depends_on[]` and `requirements[]`.
`depends_on` names the BOM types this one derives from — QBOM derives from CBOM,
and a project classified for QBOM alone produces device metadata with an empty
readiness section, which the registration screen now states rather than leaving
to be discovered from a report. `requirements[]` is what the type still needs
once the project exists (`id`, `title`, `detail`, `at_registration`,
`required`); an empty list is an answer, and SBOM and CBOM have one.

The lists are generated from the engine registry and held to it by
`TestRegistrationSourcesAgreeWithTheEngineRegistry`; `manual` is the one entry
with no engine behind it and is asserted separately, because it is the path
where the customer supplies the BOM and no engine runs at all.

**`bom_types[]`, `report_levels[]`, `standards[]` and `formats[]` belong to
report creation, not scan creation.** A report is one rendered document —
`POST /v1/reports` takes one `scan_id` plus one `bom_type` / `level` /
`format` (see §6 of `01-DATA-MODEL.md` for `report.reports`, one row per
combination) — so a client requesting N report types × levels × formats
sends N separate `POST /v1/reports` calls after the scan exists, not one
call carrying all four dimensions. `standard` is optional and derived from
`format` server-side (`spdx`→SPDX, `cyclonedx`→CycloneDX, everything
else→`native`) — sending a mismatched one is refused, not corrected.

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
    "docs": "https://docs.axebom.io/errors/SCAN_ENGINE_COMBINATION_INVALID"
  }
}
```

Codes are `SCREAMING_SNAKE`, stable forever, and grouped by prefix. `message` is human-facing and may change; **`code` is the API contract** and clients branch on it.

| Prefix | HTTP | Examples |
|---|---|---|
| `AUTH_` | 401 / 409 | `AUTH_TOKEN_EXPIRED`, `AUTH_INVALID_CREDENTIALS`, `AUTH_MFA_REQUIRED`, `AUTH_ORG_AMBIGUOUS` (409), `AUTH_ORG_NAME_TAKEN` (409), `AUTH_EMAIL_TAKEN` (409) |
| `PERM_` | 403 | `PERM_ROLE_INSUFFICIENT`, `PERM_REPORT_PRIVATE`, `PERM_COMMENT_NOT_OWNER` |
| `NOTFOUND_` | 404 | `NOTFOUND_PROJECT`, `NOTFOUND_REPORT` |
| `VALIDATION_` | 422 | `VALIDATION_FIELD_REQUIRED`, `VALIDATION_FILTER_UNKNOWN` |
| `PROJECT_` | 409 | `PROJECT_DEVICE_IDENTIFIER_TAKEN`, `PROJECT_NOT_CLASSIFIED` |
| `SCAN_` | 422 / 409 | `SCAN_ENGINE_COMBINATION_INVALID`, `SCAN_ALREADY_RUNNING`, `SCAN_SOURCE_UNREACHABLE`, `SCAN_FAMILY_NOT_DIRECTLY_SCANNABLE` |
| `FETCH_` | 422 | `FETCH_URL_SCHEME_FORBIDDEN`, `FETCH_PRIVATE_ADDRESS_BLOCKED`, `FETCH_ARCHIVE_TOO_LARGE`, `FETCH_INFLATION_RATIO_EXCEEDED` |
| `ENGINE_` | — | `ENGINE_UNAVAILABLE`, `ENGINE_PARTIAL_ECOSYSTEM`, `ENGINE_TIMEOUT`, `ENGINE_DB_STALE` |
| `NORMALIZE_` | — | `NORMALIZE_IDENTITY_OPAQUE`, `NORMALIZE_ALIAS_CLUSTER_OVERSIZE`, `NORMALIZE_LICENSE_AMBIGUOUS`, `NORMALIZE_NO_VERSION_COMPARATOR` |
| `REPORT_` | 422 / 500 | `REPORT_TOO_LARGE_FOR_PDF`, `REPORT_TOO_LARGE_FOR_XLSX`, `REPORT_RENDER_FAILED`, `REPORT_SIGNATURE_FAILED` |
| `RATE_` | 429 | `RATE_LIMIT_EXCEEDED` |
| `INTERNAL_` | 500 | `INTERNAL_UNEXPECTED` |

**Cross-tenant access returns `NOTFOUND_*` with 404, never 403.** A 403 confirms the resource exists, which is itself a leak.

**`PERM_COMMENT_NOT_OWNER`** (403) is the one legitimate same-tenant 403 in this
taxonomy that is not a role check. `comment:update` / `comment:delete` are
granted to every Viewer in the authz matrix — anyone may edit or delete their
*own* comment — so the matrix cannot express "not this row"; the comment
service's handler checks authorship itself and returns this code when a
same-tenant caller who can see a comment is not the one who wrote it. This is
distinct from cross-tenant access (`NOTFOUND_RESOURCE`, above): RLS already
makes another tenant's comment invisible before ownership is ever checked.

**`PROJECT_NOT_CLASSIFIED`** (409) — an operation belonging to one BOM type was
attempted on a project not classified for that type: registering a hardware
device, importing a hardware parts file, or saving Table 8 quantum metadata
against a project that produces only an SBOM.

409 rather than 422 because the body is well-formed and every field in it is
legal — what is wrong is the state of the target, so telling the caller to fix a
field would send them looking in the wrong place. 409 rather than 404 because
the project exists and the caller may see it; a 404 would send them hunting for
a project that is right there. That is the opposite of the cross-tenant case
above, where 404 is *required* precisely because the caller must not learn the
resource exists.

The rule applies to **creation only**. Editing or deleting data that already
exists is never refused on this ground: a project's classifications are
editable, so refusing the edit paths too would trap data a customer could then
neither correct nor remove.

`ENGINE_*` and `NORMALIZE_*` codes are usually **diagnostics attached to a result**, not HTTP responses. They surface in the report rather than failing a request.

**`SCAN_FAMILY_NOT_DIRECTLY_SCANNABLE`** (422) — `families[]` named `qbom`, or
an explicit `engines[]` entry named `qbom-derive`, `hbom-csv` or `hbom-form`
(§7, §8). Every offending family and engine is listed in `details`, not just the
first:

```jsonc
{
  "error": {
    "code": "SCAN_FAMILY_NOT_DIRECTLY_SCANNABLE",
    "message": "1 BOM family(s) cannot be requested as a scan: qbom. Every offending family and engine is listed in the error details, so one correction fixes all of them.",
    "details": [
      { "family": "qbom", "reason": "QBOM is derived from CBOM discovery; run a CBOM scan and record the Table 8 device metadata via /v1/qbom/*." }
    ],
    "request_id": "01J…",
    "docs": "https://docs.axebom.io/errors/SCAN_FAMILY_NOT_DIRECTLY_SCANNABLE"
  }
}
```

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
X-AxeBOM-Event: scan.completed
X-AxeBOM-Delivery: <uuid>
X-AxeBOM-Signature: t=<unix>,v1=<hex hmac-sha256 of "t.body">
```

The timestamp is inside the signed payload to prevent replay; reject deliveries older than 5 minutes. Retries: 5 attempts, exponential backoff to 1 h, then dead-letter.

Events: `scan.completed`, `findings.new_critical`, `campaign.failed`, `report.ready` — `services/notification/internal/webhook`'s `Event` type has these four values, and is the SSOT for this list. (An earlier draft of this section named six events under different spellings — `scan.failed`, `finding.critical.new`, `campaign.run.completed`, `vex.updated` — before the webhook package was actually built and tested; those four extra/renamed entries were never implemented and are not planned work, just a stale draft corrected here.)

Payloads carry **ids and counts, never component or finding detail** — a webhook body may be logged by the receiver, and BOM content is confidential under CERT-In §5.3. See `webhook.Payload`'s own doc comment for the exact field list.

### The internal event that produces a webhook delivery

A webhook delivery is downstream of an internal event published to `notify.<event>` on the `NOTIFY` stream (§2) — `libs/go-shared/events`'s `NotifyEventV1`, consumed only by `services/notification`. It is deliberately RICHER than `webhook.Payload` above: an internal message between our own services never reaches a third party, so it may carry what the EMAIL channel needs to render a human-readable message (a project name, a campaign name, a failure cause) that a webhook body must not. `services/notification` derives the narrower `webhook.Payload` from this envelope at delivery time.

Publishers today: `services/report`'s render worker, for `report.ready`, once per finished render, deduplicated on the report id. `scan.completed`, `campaign.failed` and `findings.new_critical` have no publisher yet — the event type and its delivery mechanism (retry, backoff, both channels) are fully built and tested; only the "something happened, publish it" call at the point each thing happens remains.

---

## 12. Internal gRPC

Service-to-service calls use gRPC with proto in `proto/`. Every RPC carries `tenant_id` and `traceparent` in metadata; the receiving interceptor sets `app.current_tenant_id` from metadata and **rejects any RPC without it**.

Deadlines are mandatory and propagated. Retries only on `UNAVAILABLE` and `DEADLINE_EXCEEDED`, with jitter, capped at 3.

Contract tests live beside each service and run in CI: a change to a proto that breaks a consumer fails the build, which is the mechanical guard that replaces the coherence a monolith would give for free.
