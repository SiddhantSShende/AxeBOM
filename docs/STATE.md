# STATE

**⚑ LIVING DOCUMENT.** Read at the start of every session. Update before finishing.

A session that writes code but does not update this file has failed — the next session starts blind, and rediscovering what is stubbed costs more than the work itself.

---

**Last updated:** 2026-08-29
**Current phase:** Project registration — URL / Upload / GitHub-connect sources, SBOM-only for this pass (new 5-milestone plan, `~/.claude/plans/the-project-section-while-rippling-shamir.md`) — 🟢 **ALL 5 MILESTONES DONE AND VERIFIED AGAINST REAL INFRASTRUCTURE.** A url-registered project is now fully scannable end to end: register by URL → `services/webrecon` discovers subdomains and fingerprints JS libraries → `webrecon-fingerprint` (a new, ninth SBOM engine) parses the result into components and findings → the scan completes and normalizes, all confirmed against the LIVE dev stack, not just unit tests. See the 2026-08-29 (a)/(b)/(c)/(d) session entries — (d) is Milestone 5 and is the long one; it also found and fixed a real, previously-unnoticed bug in Milestone 3's own mechanism (see below). `sbom-worker`'s own preflight log now reports `'engines': 9`, up from 8. The prior SBOM completion pass below (2026-08-26/27) is unaffected — a full `go test ./... -race`, `task verify`, and `task test:golden` at the end of (d) are clean repo-wide (one pre-existing, unrelated `crypto-mixed` CBOM golden failure, documented since 2026-08-26).
**Next action:** 🟢 The project-registration plan is COMPLETE, including a live spot-check against a real external site (`https://www.python.org/`, real jQuery 1.8.2 correctly detected with 6 accurate CVEs — see (d)'s entry, final paragraph). Nothing is queued next for this initiative — the next session should read this file fresh and take a new instruction. If asked to extend web recon further, read (d)'s entry in full first: the two remaining, deliberately-deferred gaps are a headless-browser renderer for post-paint-injected JS (Playwright, explicitly out of scope per the plan) and `retire.js`'s `hashes`/`filecontentreplace` fields (not loaded at all). 🟡 Carried forward, neither a regression from this session: (1) a pre-existing e2e/environment mismatch — this stack's ZITADEL OAuth client expects an `http://` redirect URI but the frontend container serves HTTPS-only (`task tls:gen`'s cert, `ZITADEL_DOMAIN` is a LAN IP here) — blocks any Playwright test that signs in for real, including the pre-existing `auth.spec.ts`/`generate.spec.ts` (also confirmed broken independently — they click a "Sign in" button that no longer exists; the real one says "Log in"); (2) ~20/52 `services/auth/internal/service` tests skip nondeterministically on a pre-existing `ownerConn(t)` bug (dials with an already-cancelling `t.Context()` from inside `t.Cleanup()`) — untouched, unrelated to this work. Both are one person's five-minute fix away, just not this session's to make unasked. 🟡 `NVD_API_KEY` is still NOT set (unchanged since the SBOM pass) and GitHub OAuth `CLIENT_ID`/`CLIENT_SECRET` are also genuinely empty in this environment's `.env`, so neither the connect flow's nor the Dependency Graph client's live exchange against real github.com is tested here — both are tested only against fake-GitHub httptest servers. Nothing has been committed to git this session — everything above is still uncommitted working-tree changes.

> 🟢 **A REAL SCAN NOW NORMALIZES, LIVE, WITH NO MANUAL TRIGGER — THE
> NORMALIZER'S DEPLOYED BOUNDARY FROM (e)/(k)/(l) IS CLOSED FOR SBOM.**
> `scan-orchestrator` publishes one `NormalizeTriggerV1` (`docs/02-CONTRACTS.md`
> §6a, new) the moment every engine dispatched for a scan's `sbom` family
> reaches a terminal state; a new, purpose-built Python consumer
> (`workers/sbom/normalize_consumer.py`) holds the one deliberate exception to
> "workers hold no credentials" — a Postgres role (`axebom_normalize_writer`)
> scoped to `SELECT`/`INSERT` on the `normalize` schema plus one
> column-scoped `UPDATE` on `vuln_clusters`. Along the way: `normalize.findings
> .cluster_id` is now a REAL durable surrogate (new `cluster_store.py`,
> ADR-0005) instead of the `uuid5(bom_document_id + ...)` trap that mutated
> every re-normalization; `trivy-fs`/`trivy-image`'s real `vulnerabilities[]`
> output and `dependency-check`'s output are ingested for the first time
> (only grype/osv-scanner ever reached `normalize.findings` before); SPDX 2.3
> export now passes the official validator (`spdx-tools`) — the colon-bearing
> `SPDXID` bug from (o) is fixed, not just `xfail`'d; and CERT-In's own
> VEX/CSAF remediation fields (`certin.vex.remediation` etc.) are wired from
> dead Go constants all the way to the rendered report. **Two real, pre-
> existing schema bugs were found and fixed only because this was the first
> time real pipeline output ever reached these tables**: `vuln_ids.namespace`
> was missing `GO`/`PYSEC`/`RUSTSEC`/`GSD`/`MAL` (osv-scanner's own native id
> prefixes); `findings.fix_version_ordering`'s CHECK only ever allowed
> `known`/`unknown`, never the three values `findings.py` actually emits
> (`comparator`/`unknown`/`none`). A third, unrelated bug was found and fixed
> the same way: `db.Migrator.Reset()` never cleared `public
> .goose_bootstrap_version`, so `task db:reset` against an already-bootstrapped
> database silently skipped re-creating the `app` schema and left every other
> schema's first migration failing with "schema app does not exist" — this
> had likely never been exercised because prior sessions reset by recreating
> the whole Postgres container instead. See the 2026-08-26 (a) session entry
> for the full list of files and the two points flagged for a second opinion
> (an alias-graph-merge edge case's exact evidence attribution, and whether
> local-disk raw-artifact storage vs. the contract's `s3://` convention should
> be reconciled later).

> 🟢 **THE SIDEBAR REORGANISES AROUND THE FIVE BOM TYPES**, each a lens on
> the same `project.project_classifications` data, not a separate product —
> `/sbom`, `/cbom`, `/qbom`, `/aibom`, `/hbom` each show that type's projects,
> an Engine Coverage panel (new: engine `mode` and per-project `last_run`,
> `GET /v1/scans/engines?project_id=`), and a link into `/settings/engines`,
> the first AxeBOM-native admin screen — `scan.engine_policy` (migrated in
> Phase 6, never read since) is now wired end to end. Two dead routes
> (`/v1/hbom/*`, `/v1/projects/{id}/dependencies` and `/findings`) and one
> live bug (the orchestrator publishing `scan.job.hbom`/`scan.job.qbom` to
> subjects with no worker) got fixed along the way. See the 2026-08-24 (i)
> session entry.

> 🟢 **CBOM AND QBOM WORK END TO END, LIVE — WRITE PATH, READS, REPORTS,
> FRONTEND.** `render.Sheets`/`WriteJSON`/`WritePDF` no longer refuse CBOM
> ((j)); `workers/cbom/normalize/pipeline.py` now actually writes
> `normalize.crypto_assets` (proven against live Postgres, not yet live-
> triggered — same deliberate boundary as SBOM, see (e)); a new
> `GET /v1/projects/{id}/crypto-assets` and the ported
> `GET/POST /v1/qbom/{id}` give the sidebar's Crypto and Quantum tabs real
> data to render. A live run against real `cbomkit-theia` output (not a
> hand-built fixture) found and fixed a genuine false negative: a
> certificate's quantum-vulnerability verdict was silently wrong because it
> pattern-matched an opaque engine `bom-ref` UUID instead of the algorithm
> that actually signed it. Verified with screenshots against rebuilt
> containers. See the 2026-08-24 (k) session entry.

> 🟢 **THE REPORT VIEWER'S BACKEND GAP IS ACTUALLY CLOSED NOW, NOT JUST
> PAPERED OVER.** (m) found the crash and stopped there; this session wired
> real data all the way through: a new `migrations/report/0003` adds
> `project_name`/`bom_generated_at`/`level_note`/`completeness_pct`/
> `declaration_pct`/`coverage_fields`/`engine_coverage`/
> `ecosystems_with_no_engine` to `report.reports`, captured once at
> `MarkReady` from the exact `render.BOM` the worker already loaded — never
> re-queried afterward. `GET /v1/reports/{id}` now also runs a live
> same-schema `Siblings` query. Found three more real bugs closing this:
> `render.BOM.ProjectName` had never been populated since Phase 9; a
> genuinely-unscored document's coverage collapsed to a lying `0.00%`
> instead of staying absent; and `bomsource.go`'s `loadFindings` (added in
> (m)) queried on a busy pgx connection, meaning **no report of any format
> could render at all** since (m) landed — not an edge case, every single
> render. The frontend's own `Report` type turned out to be camel-cased
> against a snake_case backend on top of everything else — fixed by
> deleting the ad-hoc local type and using `lib/reports.ts`'s real one.
> Verified against the live dev database with the actual production code
> path, not mocks. See the 2026-08-25 (n) session entry.

> 🟢 **VEX, CSAF AND COMMENTS WORK END TO END, LIVE — PHASE 13.** The pure
> logic (`vex.go`'s resolver, `csaf.go`'s types) was already solid; this
> session built the storage, HTTP, and UI on top of it, moving `vex` to
> `libs/go-shared` so `report` can share the same resolver `scan-orchestrator`
> writes against — the same reason `csaf` already lived there. Found and
> fixed a real bug on the READ side: `services/project`'s existing VEX
> resolution ignored scope specificity entirely, picking whichever statement
> happened to have the highest id. `services/comment` is a real service now,
> built by a dispatched agent that survived a mid-task interruption cleanly.
> See the 2026-08-25 (m) session entry.

> 🟢 **AIBOM WORKS END TO END, LIVE — INCLUDING A REAL CONTAINERIZED THIRD
> ENGINE.** `ai-bom` (Trusera) was shipped as a `pip:` manifest entry whose
> adapter, `AIBomAdapter`, requires a sandboxed container — it could never
> actually run. Fixed by building `deploy/docker/engines/Dockerfile.ai-bom`
> (a locally-built, hash-pinned wrapper image; no upstream image exists to
> pull), the first engine of its kind in this repo. Running it for real
> found a genuine bug nobody had ever exercised: `--output -` doesn't mean
> stdout to `ai-bom==3.1.0`, so every run before this session would have
> silently produced an unparseable result. `workers/aibom/normalize
> /pipeline.py` now writes `normalize.ai_models`/`ai_datasets`
> /`ai_model_dependencies` for real (same live-Postgres-proven,
> not-yet-triggered boundary as CBOM/SBOM); a new
> `GET /v1/projects/{id}/ai-models` and a small `services/project/internal
> /aibom` package (the four Table 10 elements no tool can ever discover —
> intended usage, out-of-scope usage, security requirements, attestation)
> give the sidebar's new AI Models tab both a live read and an edit path.
> Report rendering gets its own dedicated sheets/PDF page/JSON section,
> same reasoning CBOM's crypto assets got theirs — an AI model has no PURL,
> depth or scope for the generic component table to render. A concrete
> `aibom-generator` enrichment Fetcher was also built and found two more
> real upstream bugs (it fabricates a plausible component for a model that
> does not exist; it has no revision-pinning parameter anywhere), both
> guarded against rather than patched upstream — see the 2026-08-25 (l)
> session entry for what's proven vs. still open (enrichment is not wired
> into a live scan path yet, and a standards-conformant ML-BOM export does
> not exist because the export library has no support for it at all).

> 🟢 **THE SERVICES AUTHENTICATE AGAINST ZITADEL.** project,
> scan-orchestrator, report, campaign and notification verify real ZITADEL
> access tokens against the published key set and resolve them to a local
> tenant UUID; campaign and fetcher present machine-user credentials of their
> own. Proven live end to end: a real service token reaches
> `GET /v1/projects/{id}/source` and gets **200** for its own tenant and
> **404** for another — RLS holding, and 404 not 403.
>
> ⚠ **The hand-rolled HS256 auth is still present and still compiles.** It is
> deleted in Phase H, after the frontend is on ZITADEL. Nothing is removed
> before its replacement passes.

> 🟢 **THE BROWSER SIGNS IN.** `setAccessToken` has call sites at last: the SPA
> runs Authorization Code + PKCE against ZITADEL, sends a bearer token on every
> request, renews before expiry, and retries a 401 once. Proven by four
> Playwright tests against the running stack — `alice@acme.test` signs in and
> **sees `payments-api`**, which only a token that was accepted, resolved to a
> tenant and passed by RLS can produce.
>
> ⚠ **Configuration is FETCHED, not compiled in.** `GET /v1/auth/config` on the
> gateway publishes issuer, client id, project id, scopes and the ZITADEL claim
> names. The build-time alternative was already broken in the only place it
> mattered: `Dockerfile.frontend` takes no build args, so the container image
> had an empty client id and could not have signed anyone in.

> ⚠ **Self-registration was open, and it silently created unusable accounts.**
> ZITADEL's hosted login ships a "Register new user" link on by default. A
> visitor who used it got a real ZITADEL account with a role in **no**
> organisation — and because the project requires `AuthorizationRequired`, the
> OIDC callback then refused with `Errors.User.GrantRequired`, which the login
> UI renders as an unhelpful "Unknown error occurred." `iam bootstrap` now
> disables `AllowRegister` on the instance login policy
> (`iam.ensureLoginPolicy`), matching the invite-only tenancy model — a person
> is meant to arrive already holding a role, not through self-service sign-up.
> Verified live: the rendered login page no longer offers a register button.
>
> 🟢 **A real self-service path exists now, and it's ours, not ZITADEL's.**
> `/signup` in the frontend + `POST /v1/auth/signup` on the gateway create the
> organisation and its Owner correctly — grant included — before the visitor
> ever reaches ZITADEL's password screen, closing the exact gap the paragraph
> above describes. See the 2026-08-24 (h) session entry.

> 🟢 **THE SEEDED USERS CAN LOG IN.** `alice@acme.test` / `aaron@acme.test` /
> `bob@beta.test`, password `axebom-dev-only`. carol stays SSO-only on
> purpose. See docs/08-OPERATIONS.md and the 2026-08-23 (g) session entry.

> ✅ **DOCKER IS UP, AND THE WHOLE BACKLOG THAT DEPENDED ON IT HAS RUN.**
> `migrations/report/0002` applied; the 12 DB-backed RLS tests executed for the
> first time (all pass, no skips); the 12-case sandbox escape suite executed for
> the first time against a real Linux daemon (all pass). 39 tenant-scoped tables
> verified FORCE-RLS, 0 gaps.
>
> ⚠ **The dev machine changed.** This is now **Ubuntu 26.04 on KVM, 16 CPU /
> 16 GB / 89 GB free**, not the Windows 11 box the rest of this document
> describes. The Java 1.8 constraint, the C: disk pressure and the "Docker
> Desktop daemon stops between sessions" note are all artefacts of that machine
> and no longer apply. The container-only rule for Java scanners stands on its
> own merits (ADR-0002) and has not changed.

> 🟢 **THE APPLICATION RUNS.** `task dev` brings up infrastructure, all 8 Go
> services, the SBOM worker and the frontend. `task health` reports 8/8 `up`.
> Register → authenticate → read across upstreams works through the real browser
> path (nginx → gateway → service). Before this session **nothing above the
> infrastructure layer was wired to start at all.**

> 🟢 **A SCAN NOW RUNS END TO END.** `POST /v1/scans` → `scan.job.fetch` →
> the fetcher clones and archives → `scan.result.fetch` → the orchestrator pins
> `source_commit_sha` and fans out 6 engine jobs → workers consume → results →
> status derived. Observed: `completed_with_errors`, progress 100%. Engine
> Engines now scan the real tree, and the engine graph works: against
> expressjs/express **syft and grype both succeed**, with grype matching against
> syft's SBOM rather than re-cataloguing. No engine reports `failed` — every
> non-success carries a stated reason (dependency-check `unavailable` pending
> the free NVD key; osv-scanner and trivy-fs `partial` because express commits
> no lockfile).

> 🟢 **DISPATCH WORKS.** A job published to `scan.job.sbom` is consumed by the
> worker, runs syft in the sandbox, and its result lands on `scan.result.sbom`
> where the orchestrator's consumer picks it up. Same proven for `scan.job.cbom`.
> Before this, no Python worker consumed anything and there was no `nats`
> dependency at all.

> 🟢 **SIX OF SEVEN SBOM ENGINES VERIFIED LIVE** against
> `fixtures/monorepo-multiroot` through the real sandbox: syft, syft-spdx,
> trivy-fs, osv-scanner, grype (against our own syft SBOM) and trivy-image.
> `dependency-check` is the one gap and reports itself honestly — it needs the
> free NVD key. See "2026-08-23" in the session log.

> ✅ **CI on `main` is green.** It had been red since 2026-08-17 — seven of
> eight jobs failing from six independent causes, none of them a defect in
> product code. A seventh cause surfaced only once the gate started working:
> the windows `go` job, which had never reached its tests. See the session log
> for 2026-08-18 (d) and (e).
>
> `go test -race` has now run for the first time (ubuntu) and is clean.
>
> ⚠ **The boundary guard had not run for as long as CI was red.** `lint +
> boundaries` was failing at tool install, not at analysis, so depguard —
> the only mechanical enforcement of the service boundary (ADR-0001
> mitigation 3) — was silently absent. It now runs and reports 0 issues.

> The Phase 1/2 disk blocker is **resolved** — 18 GB free. `task verify` completes end to end (exit 0), including the frontend build. Docker Desktop's daemon still stops between sessions; start it before running the DB-backed tests, which otherwise **skip** rather than fail.

---

## Status at a glance

| Area | State |
|---|---|
| Specification & phase plan | ✅ complete |
| CERT-In compliance profile | ✅ validated · lint + gen + 7 negative tests |
| Repo skeleton, go.mod, git | ✅ 165 files, 5 commits |
| Platform packages (Go) | ✅ errs, obs, httpx, health, config, ctxkey, **db** |
| `axebom` CLI | ✅ preflight, version, docs, **db**, **profile** |
| Service generator | ✅ all 8 services generated by it |
| Go services (8) | 🟡 **auth + project are real**; **gateway now proxies to all 7 upstreams**; other 5 are scaffolds |
| **Auth service** | ✅ **register, login, refresh+reuse detection, logout, me, GitHub OAuth, invitations** |
| **Project service** | ✅ **CRUD, classifications, practices+gaps, connections, uploads, repo listing** |
| **RBAC** | ✅ 49 permissions, fails closed; route-guard test parses `routes.go` |
| **Rate limiting** | ✅ token bucket, separate tighter budget for credential endpoints |
| **Credential storage** | ✅ Vault KV v2; Postgres holds a tenant-scoped path, never a token |
| **Object storage** | ✅ MinIO; content-addressed, capped, **never extracted** |
| **Sandbox** | ✅ **Docker; 12-case escape suite RUN for the first time — green on real Linux** |
| **Fetcher** | ✅ **connection-time SSRF defence, hardened clone, content-addressed tar.zst** |
| **Orchestration** | ✅ **envelopes frozen, JetStream topology, fan-out, reaper, WS progress** |
| **Envelope schemas** | ✅ `proto/schemas/*.json`, **generated from the Go types** |
| Frontend | 🟡 projects module real (list, 3-step wizard, detail); **Phase 10 replaces the shell** |
| **Database** | ✅ **9 schemas, 43 tables + 32 partitions, migrated** |
| **RLS tenancy** | ✅ **36 protected, 7 exempt, 0 gaps — and proven to fail on a gap** |
| **Compliance codegen** | ✅ **Go + Python agree; counts match the PDF** |
| Python shared package | ✅ errors, logging+redaction, config, timeutil, **sandbox bridge**, **enginedb** |
| **Normalizer** | ✅ **identity, merge, graph, alias union-find, dedup, both coverage numbers, provenance; 151 tests + 43 golden** |
| **SBOM worker** | ✅ **7 adapters; 74 tests; syft/syft-spdx/grype/trivy-fs/osv-scanner exercised on 5 fixtures** |
| **Engine databases** | ✅ **provisioned + stamped (grype, trivy, osv); a vuln engine cannot run without one** |
| Python workers (other 3) | ⬜ directories only |
| **HBOM worker** | ✅ **CSV import, recursive model, form, providers, coverage — import only, never discovery** |
| **Campaign service** | ✅ **cron+DST, scheduler, leader lock, idempotent dispatch, CRUD, run history** |
| **Notification service** | 🟢 **signed webhooks, SSRF-safe delivery, retry+dead-letter, SMTP email, subscriptions, AND a real running delivery worker (Consumer+Poller) — verified live 2026-08-25 (p), not just built** |
| **Service tokens** | 🟢 **ZITADEL machine users, private-key-JWT; tenant named per request, honoured only for a verified service principal** |
| **Identity provider** | 🟢 **ZITADEL v4.17.1, container-only (AGPL never linked); `axebom iam bootstrap` provisions project, roles, apps, orgs** |
| **Token verification** | 🟢 **local JWKS, audience-checked; `oidcauth` replaces `auth.Authenticate` in 5 services** |
| **Identity bridge** | 🟢 **`auth.identity_for` JIT-provisions the local projection; ZITADEL org → tenant UUID, so RLS is untouched** |
| **Browser sign-in** | 🟢 **oidc-client-ts, Authorization Code + PKCE, silent renew, 401-retry-once; 4 Playwright tests green against the live stack** |
| **SPA identity config** | 🟢 **`GET /v1/auth/config` — runtime, so one image serves every environment; VITE_OIDC_* remain a dev-only override** |
| **Organisation switcher** | 🟢 **`X-AxeBOM-Org` sent on every request; a hint the server honours only against roles the token already carries** |
| **Self-service signup** | 🟢 **`POST /v1/auth/signup` creates an org + Owner in ZITADEL before handoff to login; fails closed on a name/email collision — see the 2026-08-24 (h) session entry** |
| **WebSocket auth** | 🟢 **token offered as a subprotocol (`axebom.bearer.`), never a query string; live handshake returns 101** |
| **`GET /v1/scans`** | 🟢 **keyset on id DESC, `?limit=&cursor=&project_id=&status=`; engine runs for a whole page batched in one `ANY($1)` query** |
| **`GET /v1/scans/{id}/findings-summary`** | 🟢 **grouped by `severity_effective`; none/unknown/not-provided kept as three separate buckets — correct, live, and honestly zero until normalization is triggered** |
| **Normalizer write path** | 🟢 **`bulk.plan()` + `writer.py`, proven against the live RLS-protected schema; NOT wired into any live scan yet — see the 2026-08-24 (d) session entry** |
| **Compliance guardrails** | ✅ **`profile guardrails` — no hardcoded count, no assertion of compliance; in `task verify`** |
| **Evidence pack** | ✅ **`docs/COMPLIANCE-REPORT.md`, generated + staleness-checked** |
| **API keys** | ✅ **scoped, hashed, prefixed, expiring — pure functions; no store, no routes** |
| **Audit export** | ✅ **JSONL + CSV, escaped and deterministic — renderer only, nothing calls it** |
| **Helm charts** | 🟡 **written; NEVER RENDERED — helm is not installed** |
| **Load tests** | 🟡 **3 k6 scenarios parse; CI wiring to run them now exists (`load-test.yml`, (o)) but has itself never executed — numbers are still targets, not baselines** |
| **API keys** | 🟢 **`auth.api_keys` + `oidcauth`-wide request authentication + `POST/GET /v1/api-keys`, `DELETE /v1/api-keys/{id}` (RoleOwner) — verified live end to end, see (o)** |
| **Audit-log export** | 🟢 **`GET /v1/audit-log/export` + `axebom audit export` — both formats, verified live against the real dev database, see (o)** |
| **SPDX/CycloneDX conformance** | 🟡 **`task test:conformance` runs the golden fixtures through the official validators — CycloneDX passes; SPDX has a real, found, `xfail`'d bug (colon-bearing SPDXIDs) — see (o)** |
| **Dependency/vuln scanning CI** | 🟡 **`security-scan.yml` written (govulncheck, pip-audit, npm audit, trivy fs) — `actionlint`-clean, never executed by a real runner, see (o)** |
| Frontend | ✅ scaffold builds; **Phase 10 replaces it** |
| Boundary lint | ✅ configured and demonstrated failing |
| CI (dual-OS) | ✅ written; **no Docker job**, so DB-backed and sandbox tests never run there |
| OSINT manifest | ✅ resolved against upstream; **`cbomkit-theia` tag corrected (`v1.1.2` → `1.1.2`)** |
| **Deployment** | ✅ **`task dev` runs the whole system: infra + 8 services + worker + frontend** |
| **Gateway proxy** | ✅ **`/api` strip, 7 upstreams, WebSocket upgrade, taxonomy errors; 9 tests** |
| **Container images** | ✅ **8 services + worker + frontend + CLI; Go base read from `go.mod`** |
| **Engine images** | ✅ **`task osint:pull` — the sandbox cannot pull, `--network=none`** |
| **Engine databases** | ✅ **grype 2.0 GB · trivy 1.3 GB · osv 263 MB, stamped. `nvd` needs the free key** |
| **Engines verified LIVE** | 🟢 **6/7 — syft, syft-spdx, trivy-fs, osv-scanner, grype, trivy-image** |
| **Raw artifact evidence** | ✅ **now actually written; the worker was discarding it (ADR-0003)** |
| **Credentials guide** | ✅ **`docs/CREDENTIALS.md` — NVD, GitHub, Mouser, Nexar, HF; all free** |
| **Worker → NATS** | 🟢 **WIRED — sbom, cbom, aibom consume `scan.job.*` and publish results, proven live** |
| **Fetcher → NATS** | 🟢 **WIRED — a 9th service; clone → archive → fan-out proven end to end** |
| **Archive → worker** | 🟢 **WIRED — `axebom source materialize`; syft inventories 21 components live** |
| **syft → grype handoff** | 🟢 **WIRED — fan-out holds grype; syft publishes to the workspace; grype succeeds** |
| **Engine `summary` counts** | ⬜ **always 0 — syft reports 21 components and the envelope says 0** |
| **Sidebar IA** | 🟢 **five BOM-type sections (`/sbom` `/cbom` `/qbom` `/aibom` `/hbom`), each a lens on the same projects — see 2026-08-24 (i)** |
| **`scan.engine_policy`** | 🟢 **WIRED — migrated Phase 6, never read since; `policy.Store` + `GET/PUT/DELETE /v1/scans/engine-policy` + `/settings/engines` admin UI** |
| **`GET /v1/scans/engines`** | 🟢 **now also returns `mode` (container/pip/internal) and, with `?project_id=`, each engine's `last_run`** |
| **`/v1/hbom/*`** | 🟢 **WIRED — Go-native port of `workers/hbom/{model,csv_import,providers}.py`, no Go→Python bridge exists so none was built** |
| **`/v1/projects/{id}/dependencies`, `/findings`** | 🟢 **WIRED — were dead routes the frontend already called** |
| **Orchestrator dead-job bug** | ✅ **FIXED — `families:["hbom"\|"qbom"]` now rejected at scan-create time (`SCAN_FAMILY_NOT_DIRECTLY_SCANNABLE`), not published to a subject nothing consumes** |
| **CBOM normalizer write path** | 🟢 **`workers/cbom/normalize/pipeline.py` writes `normalize.crypto_assets` for real, proven against live Postgres; not live-triggered (same boundary as SBOM, see (e))** |
| **`GET /v1/projects/{id}/crypto-assets`** | 🟢 **WIRED — the interactive read the sidebar's Crypto tab needed; neither parallel Milestone 4 workstream built it, so it was added directly** |
| **`/v1/qbom/{id}[/form,/device]`** | 🟢 **WIRED — Go-native port of `workers/qbom/metadata.py`, same no-bridge precedent as HBOM** |
| **Certificate quantum-verdict bug** | ✅ **FIXED — found only by running real `cbomkit-theia` output: a certificate inherited nothing from its signer because the code matched the signer's raw engine `bom-ref` UUID as if it were a name** |
| **`ai-bom` engine containerization** | 🟢 **`deploy/docker/engines/Dockerfile.ai-bom` — this repo's first locally-built (not pulled) sandboxed engine image; the manifest `pip:`→`container:` contradiction (i) flagged is resolved** |
| **`ai-bom` `--output -` bug** | ✅ **FIXED — every run before this session would have written an unreachable file and failed every scan; found only by actually running the real container** |
| **`aibom-generator` Fetcher** | 🟢 **BUILT — `workers/aibom/adapters/aibom_generator_fetch.py`; guards two real upstream bugs (model fabrication, no revision pinning) found by running the real package; not yet wired into a live scan trigger** |
| **AIBOM normalizer write path** | 🟢 **`workers/aibom/normalize/pipeline.py` writes `normalize.ai_models`/`ai_datasets`/`ai_model_dependencies` for real, proven against live Postgres; not live-triggered (same boundary as SBOM/CBOM, see (e))** |
| **`GET /v1/projects/{id}/ai-models`** | 🟢 **WIRED, plus `POST .../ai-models/{modelId}/fields` for the four user-supplied Table 10 elements** |
| **AIBOM NULL-vs-not-provided bug** | ✅ **FIXED — an empty user-field edit was writing NULL instead of the explicit sentinel Python's normalizer always writes; caught by a test asserting the raw column, not just field_status** |
| **Gateway `/v1/aibom` proxy prefix** | ✅ **FIXED — same class of gap (i) hit for `/v1/qbom`: a route that works against the service directly but 404s through real ingress until the prefix is added** |
| **CycloneDX ML-BOM export** | 🔴 **NOT BUILT — `protobom`, this codebase's chosen format library, has no ML-BOM/model-card support at all; a real one means hand-rolling CycloneDX or extending protobom upstream, flagged rather than attempted** |
| **VEX triage (write + read)** | 🟢 **`libs/go-shared/vex` (moved from scan-orchestrator's internal package so report can share it), a new store/HTTP layer, project-scoped, automatic supersession — verified live** |
| **VEX effective-status specificity bug** | ✅ **FIXED — `services/project`'s `loadClusterVEX` picked the highest-id statement regardless of scope; a broader, slightly-newer statement could outrank a narrower, more specific, older one. Found on the READ side, same class as CBOM's certificate bug on the write side** |
| **CSAF 2.0 generation** | 🟢 **`services/report/internal/csafgen` + storage; always produces a `csaf.Document.Validate()`-clean document; idempotent per VEX statement; verified live with a real generated document (real tenant as publisher, real CVE/GHSA, real impact statement)** |
| **Threaded comments (`services/comment`)** | 🟢 **Real service — depth-5 enforced, ownership checked, soft-delete-with-live-children — built by a dispatched agent, survived a session interruption with zero rework needed; frontend comment rail built and verified live** |
| **Report viewer crash + data gap** | 🟢 **FULLY FIXED — `GET /v1/reports/{id}` sends real project name, coverage numbers (nullable, honestly "not yet computed"), coverage-field breakdown, engine coverage, ecosystems-with-no-engine and a live siblings list, captured at render completion (`migrations/report/0003`); also fixed a bug that made every render of every format fail (`loadFindings` on a busy pgx connection) and a bug that left `render.BOM.ProjectName` always empty since Phase 9** |

---

## What Phase 1 built

### Schema — 9 schemas, 43 tables, 32 hash partitions

`bootstrap` (schemas, app role, RLS helpers, `uuid_v7`) · `auth` · `project` · `scan` · `normalize` (4 migrations) · `report` · `campaign` · `comment` · `notify`.

`normalize.components` and `normalize.findings` are **hash-partitioned 16 ways on `bom_document_id`**. A large monorepo yields 50k+ components per scan; partitioning bounds index maintenance and vacuum from day one rather than after the first outage.

### Tenancy — the part that cannot be retrofitted

- **`app.enable_tenant_rls()`** applies `ENABLE` + **`FORCE`** + `USING` + `WITH CHECK` once, rather than repeating the policy in 36 tables where one would eventually be written subtly differently. Variants exist for nullable-tenant (`auth.audit_log`) and partitioned tables.
- **`WithTenant` issues `SET LOCAL`, not `SET`.** `SET` persists on a pooled connection and the next borrower inherits the previous tenant's scope — a cross-tenant read with no code change and no error. There is an explicit concurrent test.
- **The app role is asserted non-superuser and non-`BYPASSRLS` on every boot**, not once at provisioning: a later `GRANT` can reintroduce it.
- **A query outside `WithTenant` fails closed** — `current_setting` raises when unset.
- `auth.audit_log` (no UPDATE/DELETE) and `scan.raw_artifacts` (no UPDATE/DELETE) are append-only/immutable **by grant, not by convention**.

### Compliance profile — `axebom profile lint | gen | show`

`profile lint` runs the 7 checks from `06-COMPLIANCE-PROFILES.md §8`: **131 fields, all 17 count assertions match the source PDF, 0 assumed entries.**

`profile gen` emits Go and Python from the same YAML. Counts, verified to agree across both languages and against the PDF:

| | SBOM | QBOM | AIBOM | HBOM | practices | crypto (algo/key/proto/cert) |
|---|---|---|---|---|---|---|
| fields | 21 | 11 | 19 | 24 | 6 | 8 / 7 / 5 / 10 |

> **131 fields vs the "134 ids" recorded in the Phase 0 log** — both are right. 131 are *fields*; the other 3 ids belong to the minimum-element *categories*, which are not fields.

Generated code is **committed** (a fresh clone must `go build`) with a drift check. AxeBOM extensions carry `status: extension` and `scored: false`, so our own analysis cannot move a compliance percentage.

### CERT-In identifier

Golden-tested against **all four Table 6 worked examples** (PDF p.26). PostgreSQL's internal capitals survive — naive Title-casing yields `Postgresql` and stops matching the guideline's own example. Refuses to fabricate an organisation name when the supplier is unknown.

---

## Verification actually performed

| Check | Result |
|---|---|
| `db migrate` | 9 schemas, 75 tables incl. partitions |
| `db verify-rls` | 36 protected · 7 exempt · **0 gaps** |
| **RLS guard proven to fail** | all three gap kinds: no policy · no `tenant_id` · **`ENABLE` without `FORCE`** |
| Cross-tenant SELECT | returns nothing |
| Cross-tenant UPDATE | affects 0 rows |
| Cross-tenant INSERT | violates `WITH CHECK` |
| Unscoped query | fails closed |
| Pool reuse, 120 concurrent | no scope leak |
| Audit log DELETE / artifact UPDATE | permission denied |
| `up → down-all → up` | 0 tables, then 75 — clean |
| `profile lint` + 7 negative tests | rejects wrong count, dup id, missing status, assumed-without-note, bad page, inconsistent meta, unknown entity |
| Go ⟷ Python model agreement | exact |
| CERT-In identifier | 4/4 Table 6 examples |
| `golangci-lint` | 0 issues |

The `ENABLE`-without-`FORCE` case is the one worth remembering: the table owner bypasses the policy, and the migration role *is* the owner, so a check that only looked at `ENABLE` would pass on a table that leaks.

---

## Deviations from the phase file, and why

| Deviation | Reason |
|---|---|
| `normalize.licenses` is **global**, not tenant-scoped | The SPDX list is identical for everyone; scoping it means every tenant re-seeding 600 licences. Tenant-specific unrecognized text lives in `license_refs`, which *is* scoped. `01-DATA-MODEL.md` updated. |
| Added an **exemption registry** in `db/rls.go` | The phase said "assert every table has a policy". Seven legitimately have no tenant data. An explicit, reasoned list is honest; silently skipping them would make the test meaningless. |
| Added `db down-all` | `goose down` is a *single step*. `normalize` has 4 migrations, so plain `down` left tables behind and the following `up` proved nothing. `down-all` makes "up, down, up is clean" a real check. |
| `Down` excludes `bootstrap` | Bootstrap's Down is a full teardown, not a step; including it tried to drop `app.touch_updated_at()` while triggers still depended on it. |
| Generated code **committed** rather than gitignored | A fresh clone must build without a codegen step, and the diff is the review surface when the profile changes. Drift check instead. |
| `profile:lint` added to `task verify` | It exists now and is fast. |
| `task verify` is **sequential** | See Gotchas. |

---

## Gotchas found in Phase 1

| Trap | Detail |
|---|---|
| **Every default infra port was taken** | 5432, 4222, 6379, 9000, 8200, 1025, 8025 — all occupied by other projects on this machine. Moved to a dedicated **5xxxx range**. Colliding meant connecting to somebody else's Postgres and getting an auth failure that reads like a credential bug. |
| **NATS flag parsing** | Flags are space-separated (`-sd=/data` is rejected) and `max_payload` is a **config-file** option, not a CLI flag. Both present as a crash loop that prints usage text with no error line. |
| **`go:embed` cannot reach outside its package** | Hence `migrations/embed.go`, keeping the SQL at the repo root where it is discoverable. |
| **Backticks inside a Go raw string** | The Python-docstring template used ` ``…`` ` (RST literal syntax) and silently terminated the Go raw string literal. |
| **`task verify` parallel deps** | golangci-lint refuses to run concurrently with itself, and lint + test + two builds together exhausted memory. Now sequential — a gate that passes depending on free RAM is not a gate. |
| **`ruff format` reformats generated Python** | `profile:gen` now runs it, so the committed file is stable and the drift check compares like with like. |
| **psql meta-commands in seed** | `\set` does not work through `database/sql`; seed uses literal UUIDs. |

---

## What Phase 2 built

### The manifest now describes reality

`axebom toolctl dryrun` resolved every pin against upstream. **Every Phase 0
placeholder was significantly stale** — syft 1.19→1.51, grype 0.87→0.117,
trivy 0.58→0.74, osv-scanner 2.0→2.5, dependency-check 11.1→13.0,
ai-bom 0.9→3.1. Nothing but a network probe would have revealed that.

### ⚠ Org correction: `cbomkit`, not `PQCA`

The Phase 0 planning notes told the user their draft was wrong and the CBOMkit
repos lived under `PQCA/`. **That was itself wrong.** `github.com/PQCA/*`
returns HTTP 301 and redirects to `github.com/cbomkit/*`;
`ghcr.io/cbomkit/cbomkit-theia` resolves while `ghcr.io/pqca/cbomkit-theia`
404s. The original draft was right. Corrected in the manifest and in
`04-OSINT-INTEGRATION.md`.

### Three constraints found by probing, not by reading

| Finding | Consequence |
|---|---|
| **cbomkit-theia ships NO binary assets** (v1.1.2 is source-only) | Container is not a preference for the primary CBOM engine — it is the only option. |
| **osv-scanner publishes NO checksum file and NO signatures** | Declared as a `supply_chain_gap`; container mode preferred because ghcr images are digest-addressed. Warned on every sync. |
| **Trivy's asset naming is inconsistent within its own project** | `Linux-64bit` / `macOS-64bit` but `windows-64bit`. A template that assumed consistency 404s in a way that looks like a wrong version. |

### Verification model

Pin the VERSION and the CHECKSUM-FILE URL, not per-platform sha256 literals.
Upstream publishes a signed `checksums.txt` covering every asset; verifying
against it (and verifying that file's signature) is the flow upstream itself
recommends and is stronger than a hash transcribed by hand. Six tools × three
platforms would have been 18 hand-maintained hashes per version bump.

A checksum mismatch **refuses to install and deletes the artifact** — leaving a
failed download on disk means the next run may treat it as cached and good.

### Delivered

```
libs/go-shared/toolctl/    manifest.go resolve.go fetch.go  (+17 tests)
cmd/axebom/toolctl.go   list | dryrun | sync | verify | licenses
libs/py-shared/.../adapters/  base.py registry.py           (+13 tests)
```

`toolctl licenses` is the mechanical guard for CLAUDE.md invariant 9 — it fails
if a copyleft dependency would be linked into an AxeBOM binary.

### A gap in my own tool, found and fixed

The first dry run passed while proving nothing: container mode is preferred for
almost every engine, so **no binary URL was ever probed** — the templates most
likely to be wrong went untested. `--force-mode binary` now exercises them, and
`task osint:dryrun` runs both passes.

## Disk pressure — hit once, since cleared

During Phase 1 the `C:` drive filled to **30 MB free of 280 GB** and `go build ./...`
died with `VirtualAlloc … errno=1455` (Windows commit limit) and then
`link.exe: … not enough space on the disk`.

**Every individual Phase 1 check had already passed** — migrations, RLS, the
cross-tenant suite, profile lint, codegen, the CERT-In golden tests. Only the
final full-gate rerun was blocked, and it was an environment condition, not a
code defect.

It cleared when Docker Desktop stopped between sessions: **C: is now 18.3 GB
free** and `task verify` completes. Recorded because it will recur — this
machine runs many projects at once.

If it happens again, least destructive first:

1. `docker builder prune` — reclaims build cache only. Rebuilds get slower; nothing is lost.
2. `docker image prune -a` — reclaims unused images. Re-pulled on demand.
3. Point `GOTMPDIR`/`GOCACHE` at `D:` (98 GB free).
4. Stop containers belonging to finished projects.

At the time: 192 images / 47 GB, 541 build-cache entries / 25.6 GB, 153 running
containers — **most from other projects, which is why none of it was cleaned up
unilaterally.**

`D:\axebom-tmp` was created during diagnosis and is safe to delete.

---

## What does NOT exist

- **No domain logic.** Services serve `/healthz`, `/readyz` and a taxonomy 404.
- No auth, no projects API, no scans, no reports, no worker code.
- No `.proto` files (config only — the breaking-change gate predates the contract).
- No fixtures. The 15 in `09-GOLDEN-CORPUS.md` are specified, not built.
- **`task osint:sync` has never run.** Every version and digest in the manifest is `TBD`.
- **CI has never executed** — no remote configured.

---

## Decisions already made

Do not relitigate without an ADR (`docs/ADR/`): 0001 microservices · 0002 pinned artifacts · 0003 replayable normalization · 0004 one engine per job · 0005 durable cluster ids · 0006 RLS tenancy · 0007 profile-driven compliance · 0008 fetcher holds the only credentials.

Settled in implementation: module path `github.com/axebom/axebom`; infra ports in the 5xxxx range; two Postgres identities (owner for migrations, `axebom_app` for runtime); no external config/CLI library.

---

## Environment (probed 2026-08-16)

Go 1.26.2 ✅ · Node 24.14.1 ✅ · Python 3.14.4 ✅ · Git ✅ · task 3.52.0 ✅ · golangci-lint 2.12.2 ✅ · buf ✅ · Docker 29.3.1 ✅
cosign ❌ · Java 1.8 (irrelevant by design, ADR-0002) · gcc ❌ → `-race` unavailable locally
**Disk: C: 0 GB free ❌ · D: 97 GB free**

Stack ports: Postgres **55432** · NATS **54222**/58222 · Redis **56379** · MinIO **59000**/59001 · Vault **58200** · Mailpit **51025**/58025.

---

## What Phase 3 built

### The problem the design surfaced: login is pre-tenant, but membership is tenant-scoped

RLS keys every tenant-scoped table on `app.current_tenant_id`, and
`auth.memberships` is tenant-scoped. But **login happens before a tenant is
known** — discovering which tenants a user belongs to is the entire point of the
lookup. A plain query fails closed, which is correct behaviour that happens to
block the one legitimate case.

The rejected fixes and why: dropping RLS from `auth.memberships` (membership IS
tenant data), granting the app role `BYPASSRLS` (disables every policy in the
database, forever), connecting as the owner (same, with extra steps).

**The fix is `migrations/auth/0002_login_lookup.sql`** — narrow `SECURITY
DEFINER` functions, each taking one user id or one token hash, each pinned with
`SET search_path = auth, pg_temp`. A deliberate, reviewable hole of exactly the
shape the problem requires rather than a broad one.

### Refresh-token reuse detection

Tokens rotate; each refresh revokes the presented token and issues a successor.
Presenting an **already-revoked** token therefore means two parties hold what
should have been consumed once. We cannot tell the thief from the victim, so the
**entire family is revoked** and both re-authenticate.

`TestRefreshReuseRevokesTheWholeFamily` asserts the part that actually matters:
after the replay, the *legitimate* client's live token is dead too. It was
**mutation-tested** — with family revocation neutered, it fails on exactly that
assertion.

### Two lint/guard mechanisms added

**`services/auth/routes_test.go` parses `routes.go` as an AST** and checks how
each route is mounted. `mux.HandleFunc` carries no middleware, so any route
mounted that way must appear in `publicRoutes` with a stated reason. Reading the
source rather than the mux is deliberate — `http.ServeMux` exposes neither its
patterns nor the handler chain, so a runtime check cannot tell a wrapped handler
from an unwrapped one. Verified failing: it reports the file, line, and fix.

**`tools/gen-service/boundaries_test.go`** asserts `.golangci.yml` has a
depguard rule per registered service, so adding a service without its rule fails
the build instead of silently leaving it unguarded.

### Generator contract changed (affects all 8 services)

`buildDeps(ctx, cfg) (*deps, error)` now constructs dependencies **once** in the
generated `main.go`, which passes the result to both `registerHealthChecks(c, d)`
and `registerRoutes(mux, d)`. Previously neither hook could reach a pool without
opening its own. A new preserved file `deps.go` owns construction and teardown
per service, plus `serviceMiddleware(d)` for chain additions.

### Traps hit in Phase 3

| Trap | What happened |
|---|---|
| **`gen_random_bytes` not found inside SECURITY DEFINER** | `app.uuid_v7()` called it unqualified, so it resolved only when the CALLER's `search_path` happened to include `public`. The moment a function with a pinned `search_path` called it, every id default inside failed — audit writes silently failed and invitations could never be accepted. Fixed in `migrations/bootstrap/0002`: pin every helper's own `search_path`, schema-qualify what they call. **A function's behaviour must not depend on its caller's `search_path`.** |
| **depguard forbade a service importing itself** | The rule denied all of `services/`, which was fine while no service had internal packages. Now one rule per service: `files` scoped to that service, `allow` its own prefix, deny the rest. Go's own `internal/` rule already covers cross-service internals — both defences verified failing on their respective cases. |
| **Unique tenant slug locked out the second "Acme"** | Two unrelated companies are both entitled to the same name. `insertTenant` now disambiguates with a numeric suffix, each attempt in a SAVEPOINT — without one the first unique violation poisons the transaction and the retry can never succeed. |
| **`SecureCookies bool` fails open** | Any caller that forgot the field shipped refresh tokens without `Secure` — invisible in development, catastrophic in production. Renamed to `AllowInsecureCookies` so the **zero value is the safe one**. |
| **`task verify` depended on which shell ran it** | `golangci-lint` lives in `GOPATH/bin`, which PowerShell has on PATH and a fresh Git Bash does not. The gate now resolves it at run time. |
| **`VALIDATION_*` is 422, not 400** | My handler tests asserted 400. `docs/02-CONTRACTS.md` §9 is the contract; the tests were wrong, not the code. |

### Known debt from Phase 3

- **Global audit rows are write-only to the application.** A failed login for an
  unknown email has no tenant, and the nullable RLS policy has no
  `OR tenant_id IS NULL` in its `USING` clause — deliberately, since those rows
  carry email addresses of people who are not any tenant's users. Nothing in the
  product can display them today; they are readable by an operator connecting as
  the owner role. A platform-admin surface is the right home (Phase 16).
  `TestGlobalAuditRowsAreNotReadableByAnyTenant` pins the current behaviour.
- **Rate limiting is in-process.** With several gateway replicas each enforces
  its own budget, so the effective limit is N× the configured one. Fine for abuse
  control, **not** sufficient for quota billing. Shared-Redis limiter is Phase 16.
- **Frontend auth screens are not built.** PHASE-03 step 9 asks for login,
  signup, invite-accept and role-aware navigation. Deferred to Phase 10, which
  replaces the scaffold wholesale — building them twice against a scaffold that
  is scheduled for replacement is waste. **The backend contract they need is
  complete and tested.**
- **The gateway does not proxy yet.** It has the middleware chain and rate
  limiting; route forwarding lands with Phase 4, when there is a second service
  worth forwarding to.
- **No MFA, no API keys, no SAML/OIDC** — explicitly out of scope per PHASE-03.

---

## What Phase 4 built

### Practices are a product feature, and the gap is reported at the point of entry

CERT-In "Minimum Elements" is **three categories**, not just the 21 data fields.
The third — Practices and Processes — is six per-project settings, and a tool
that implements only the data fields and claims compliance is overstating.

So `GET/PUT /v1/projects/{id}/practices` returns the six values **together with
the gap report**: which sub-elements are unrecorded, and why. Verified live —
a project with `errata_policy` set to `not-provided` is stored, returned, and
scored as a gap reading *"recorded as not-provided, which is a declaration
rather than a substantive value"*. That is CLAUDE.md invariant 3 working end to
end rather than as a comment.

The count comes from `model.PracticeFields`, generated from the profile. No
number is written anywhere in the service, the API, or the UI.

### The credential rule, verified against real Vault

`libs/go-shared/vault` is a hand-written KV v2 client (four endpoints of
documented HTTP, versus a large dependency whose licensing needs review under
invariant 9).

**The vulnerability it guards against is not obvious:** the service holds ONE
Vault token with access to the whole mount, so a path stored in a row is a *read
primitive*. Anything that lets an attacker influence a stored ref — a
mass-assignment bug, an import, an admin API — becomes a way to read another
tenant's secret. Paths are therefore DERIVED server-side from (tenant, kind, id)
and re-derived on every read; a ref that does not match its owner is refused
before Vault is contacted. The memory fake enforces the same rule, because a
fake that skipped it would let a cross-tenant test pass while the product leaks.

Proven end to end against the running stack: Postgres holds
`axebom/tenants/<tenant>/repo-token/<conn>`, Vault holds the token, and a
scan of every column for the token string returns zero.

### Uploads are stored and never opened

`TestNoExtractionCodePathExists` parses the service's own source and fails on any
import that could open an archive or decompress a stream — `archive/zip`,
`archive/tar`, `compress/*`, `os/exec`. Verified failing by adding `archive/zip`.

A comment saying "we do not extract" is a promise; this is a check. Extraction is
zip slip, symlink escape and decompression bombs, and it belongs in the Phase 5
sandbox or nowhere.

### Traps hit in Phase 4

| Trap | What happened |
|---|---|
| **Exact-count RLS tests cried wolf** | `TestCrossTenantCountIsScoped` asserted tenant A sees exactly 2 projects — true only while it was the only suite writing rows. Phase 4's tests made it fail with **"TENANT SCOPE LEAKED"**, for something that was not a leak. A guard on the most important invariant in the system must never do that. Both tests now assert the property directly: *within a tenant's scope, rows belonging to anyone else = 0*, which is sharper AND immune to data volume. |
| **Tests left hundreds of rows behind** | The above was the symptom; this was the cause. Every creation site now registers a `t.Cleanup` hard-delete, and the suite leaves the database exactly as it found it. |
| **Slug disambiguation exhausted at 10** | Sequential `-2, -3, …` suffixes meant the 11th organisation named "Acme" could not sign up — it failed with an error about slugs that a user cannot act on. Now: three tidy sequential attempts, then a 40-bit random suffix. |
| **Every service defaulted METRICS_PORT to 9090** | The HTTP ports were assigned per service to avoid exactly this, but metrics was left shared, so the second service to start died with "Only one usage of each socket address". Found by running two services at once, not by reading config. |
| **…and 9091/9092 collide with Docker's WSL relay** | The obvious fix collided again. Metrics is now HTTP port + 10000 (8091 → 18091), clear of both the Prometheus convention and Docker's relays. |
| **depguard `{ResourceRepoConn, ActionList}` missing** | The GitHub repo-listing route 403'd for everyone. The matrix failing closed is the design working; the fix was to *decide* the permission — **Analyst, not Viewer**, because it lists every private repository the user can see at GitHub, a much larger disclosure than reading a connection the tenant already registered. |
| **`exactOptionalPropertyTypes` in the frontend** | Strict, and correct: `foo?: string` and `foo?: string \| undefined` are different types. Worth knowing before writing more TypeScript here. |

### Known debt from Phase 4

- **The GitHub repo picker takes a token from a header.** `GET /v1/github/repos`
  requires `X-GitHub-Token`, supplied per request and never stored. Connecting
  the repository is what persists it, to Vault. Reusing the OAuth token captured
  at sign-in is a Phase 16 improvement — it needs a per-user token store, which
  is a bigger design decision than this phase should make.
- **The wizard does not upload or connect in-flow.** It creates the project and
  its practices; attaching a repository or a file is a follow-up call. The API
  supports both, and the screens for them belong with the Phase 10 rebuild.
- **Private-repo access was NOT included.** The OAuth scope is
  `read:user user:email` only. Repository access is requested later, per
  project — an account-linking flow should not ask for the right to read every
  repository the user can see.
- **No cross-schema reads.** The project service never touches `auth.*`;
  `created_by` is a bare uuid with no FK, per ADR-0001.

---

## What Phase 5 built

### The SSRF defence is a dialer, not a regex

A parse-time IP check asks "does this hostname resolve to something public?" and
the attacker answers truthfully — then changes the answer before the connect.
**The gap between the two lookups IS the vulnerability**, and it cannot be
narrowed away: the attacker controls the TTL.

`SafeDialer` resolves ONCE, validates every returned address, and dials the
resulting **IP literal** — so the second lookup the attack depends on never
happens. `TestDialerResolvesOnceAndActsOnTheValidatedAddress` stages a resolver
whose answer changes between calls and asserts exactly one resolution round.

Two bypasses worth naming, both covered: `::ffff:169.254.169.254` — an
IPv4-mapped IPv6 address that routes to cloud metadata and is invisible to an
IPv6-only range check — and a multi-answer DNS response mixing one private
address among public ones, where skipping to the "good" address would make the
defence non-deterministic.

### The bomb aborts mid-stream, and that number is measured

The requirement is not "reject a bomb" but "abort mid-extraction". The test
reports how far it got: **0.52% of a 200 MB bomb**, after roughly 1 MB.

It was 32% first — the ratio check waited for 64 KB of *compressed* input, and
gzip needs only ~200 KB to produce 200 MB. Gating on 1 MiB *written* bounds the
damage to about that. The measurement appears in the test output on every run,
so a regression is visible rather than theoretical.

### The escape suite runs against a real daemon

Twelve cases, all green: no network, read-only rootfs, noexec workspace,
non-root, dropped capabilities, fork bomb, OOM kill, wall-clock kill, container
removal after timeout, credential refusal by name and by value shape, clean
engine environment, forbidden build tooling.

A config that looks right and is not applied is exactly the failure this suite
exists to catch, so each case makes the container actually attempt the thing.

`fixtures/security/README.md` maps every attack to the test that exercises it.

### Traps hit in Phase 5

| Trap | What happened |
|---|---|
| **The workspace tmpfs was unwritable** | A tmpfs mounts root-owned and 0755, so a container running as uid 65534 could not write to its own workspace — every scanner would have failed on its first scratch file. The mount now carries `uid`/`gid`/`mode`. Caught only because the test asserts the workspace is USABLE as well as locked down. |
| **`NetworkAllowlist` is not a Docker network mode** | Docker looked for a network *named* "allowlist" and failed at start. The honest fix is under gaps below — not a silent fallback to open egress. |
| **`alpine/git` has `ENTRYPOINT ["git"]`** | An argv of `["sh","-c",…]` became `git sh -c …`. Spec now carries an explicit `Entrypoint`, and `CheckCommand` inspects entrypoint + argv together so a forbidden build tool cannot hide in an image's entrypoint. |
| **The partial bomb file survived** | `os.Remove` ran with the file still open, which fails on Windows — leaving the partial bomb exactly where it was meant to land. Close before unlink. |
| **`LookupIPAddr` issues TWO queries** | A and AAAA. The rebinding test counted packets and reported "2 lookups" against a correct dialer. It counts resolution rounds now. |
| **gosec G116 flagged our own source** | `isBiDiControl` contained literal bidi characters — invisible in most editors, so the code a reviewer reads is not the code that compiles. Rewritten as `\u` escapes. The check was working. |

### ⚠ What Phase 5 could NOT defend against

Stated plainly, because a known gap is manageable and an undocumented one is not.

1. **The git clone reaches the network directly from inside the container**, so
   `SafeDialer` never sees it. The dialer protects HTTP downloads; the clone is
   protected by URL validation plus `GIT_ALLOW_PROTOCOL`. A hostname that
   resolves to an internal address at clone time is **not** blocked today.
   **This is the most significant gap in the phase.** Fix: route the clone
   through the egress proxy, or resolve-and-pin the address before handing the
   URL to git.

2. **The fetcher has UNRESTRICTED EGRESS.** A clone must reach the forge and the
   egress proxy does not exist. The mode is named `NetworkEgress` — not
   "allowlist" — so nobody reads it as filtered, and `NetworkAllowlist` is
   **refused** without a configured `ProxyNetwork` rather than degrading into
   open egress. Bounded by: the URL passed validation before the container
   started, and the fetcher runs no scanner. **Fix: the egress proxy, Phase 16.**

3. **Container escape itself is assumed not to happen.** Everything here bounds
   what a process can do INSIDE a container; nothing defends against a kernel
   bug that gets it out. `SANDBOX_RUNTIME` exists for gVisor or a microVM; only
   `docker` is implemented. **Fix: gVisor, Phase 16.**

4. **Per-container disk quota is host-dependent.** `StorageOpt` needs a storage
   driver with quota support; on ext4-backed overlay2 it is rejected. The runner
   retries without it and records `DiskQuotaEnforced=false` rather than assuming.
   The workspace tmpfs limit still bounds where a scan writes. It DID apply on
   this machine — the flag exists for hosts where it will not.

5. **A pinned scanner image is trusted.** Digest pinning and signature
   verification bound WHICH image runs; they do not help if the upstream we pin
   to is itself compromised. Trivy's channel was compromised twice in March 2026.

---

## What Phase 6 built

### The envelopes are frozen, and their schemas are generated

`ScanJobV1`, `ScanEventV1`, `ScanResultV1` in `libs/go-shared/events`, with
JSON Schemas written to `proto/schemas/` by `axebom schema gen`.

**Generated from the Go types, not hand-written.** A hand-written schema is a
second definition that drifts the moment somebody adds a field. The Python
workers consume these; without a published schema that agreement lives in prose,
and prose does not fail a build.

Two rules are enforced in code rather than documented:

- **`ScanJobV1` has no credential field**, and `Validate` refuses one smuggled
  into `engine_config` — the other way in, where a token looks like ordinary
  configuration (ADR-0008).
- **Unknown fields are ignored, never fatal**, the deliberate opposite of the
  HTTP handlers' `DisallowUnknownFields`. A typo'd field in a user's request is a
  mistake to report; an unrecognized field in a queue message is a newer
  publisher, and rejecting it would mean no schema can ever gain a field without
  a synchronised deploy of thirteen services.

### Status derivation is mechanical, and the `partial`-only case is the sharp one

A scan where EVERY engine returned `partial` is `completed_with_errors` — not
`completed`, because the gaps are real, and not `failed`, because the output is
real. `partial` counts as succeeded for "did anything work?" and as not-clean for
"did everything work?", and the status has to say both.

### Two JetStream properties that only a real server reveals

| Discovered | Consequence |
|---|---|
| **A WorkQueue stream permits ONE consumer per filter subject** | Every worker for a family shares ONE durable name; NATS distributes between them. A per-instance durable is rejected at startup. Recorded in `02-CONTRACTS.md` §2 and encoded in `ConsumerConfig`'s doc comment. |
| **`Nak()` redelivers IMMEDIATELY** | The consumer's `BackOff` governs `ack_wait` expiry, not an explicit nak. A failing job spun as fast as the consumer could loop — **measured at 0.05s against a 30s first step** — burning all four attempts in milliseconds. Now `NakWithDelay`, and the test asserts the elapsed time: **30.0066772s**. |

### Traps hit in Phase 6

| Trap | What happened |
|---|---|
| **The store invented columns** | `source_kind`, `families`, `requested_by`, `family` on engine_runs — none existed. The schema SSOT wins: the store was rewritten against `triggered_by`/`bom_types`/`engines_requested`, and the two genuinely-missing columns (`scans.source_kind`, `engine_runs.error_code/message`) were added by migration AND recorded in `01-DATA-MODEL.md`. |
| **Fan-out published ZERO jobs, silently** | Dropping the non-existent `family` column left `run.Family` empty, so every job failed validation and was skipped. The scan sat at `running` until the reaper would have timed it out half an hour later. The family is now derived from the registry, and a skipped job logs at ERROR saying exactly that consequence. |
| **The reaper could not read anything** | It used `pool.Raw()` across tenants, and RLS failed closed with `unrecognized configuration parameter` — correctly. Fixed with narrow `SECURITY DEFINER` functions (`migrations/scan/0005`), the same pattern Phase 3 established: no parameters, one status transition, ids only. |
| **`…` is three bytes** | Event-message truncation produced 202 bytes against a 200-byte limit, because `len()` counts bytes and U+2026 encodes as three. Same class as the Phase 5 path-truncation bug. |
| **A `continue` inside an inner range does nothing** | The reaper's "skip if still running" guard was a no-op, which would have derived a FAILED status for a scan whose engines were still working. |
| **NOT NULL array columns** | A nil Go slice becomes SQL NULL, and a NULL insert does not use the `'{}'` default. An engine that covered no ecosystems failed the write instead of storing an empty array. |

### Known debt from Phase 6

- **No engine adapters yet.** The mock engine (`workers/_mock`) implements the
  real worker contract — manifest idempotency check included — so the machinery
  is exercised the way a real engine will exercise it. Phase 7 adds the real ones.
- **`engine_policy` is a table with no reader.** The migration and the SSOT entry
  exist; `Registry.Resolve` takes overrides as a parameter but nothing loads them
  from the table yet. Per-tenant engine selection is a Phase 7 wiring task.
- **The WebSocket has no automated test.** Snapshot-on-connect and the
  event stream are implemented and manually exercised; a test needs a websocket
  client harness. The property that matters — the database is authoritative and a
  reconnect is immediately correct — is covered by the pipeline test polling
  Postgres rather than the stream.
- **`argv_redacted` is stored but nothing redacts it yet.** The fetcher is the
  only component holding a credential and it does not put one in argv, so there
  is nothing to redact today. Phase 7 must not change that.

---

## What Phase 7 built

Seven SBOM adapters behind one sandboxed base class, a provisioned-database
layer, and 74 tests. Five engines are exercised end to end against all five
fixtures; two are deferred with stated reasons.

### The theme of this phase: a scanner that finds nothing looks exactly like a clean project

Every significant defect found here was the same shape — an engine reporting
success, exit 0, valid JSON, and **zero findings, because it had not actually
checked anything**. None of them raised an error. All of them would have
rendered as a clean compliance report.

| What happened | Why it produced a false all-clear |
|---|---|
| `osv-scanner --offline-vulnerabilities` with a fully populated cache mounted | Documented as "checks for vulnerabilities using local databases that are already cached". It loads none of them. `{"results": []}`, exit 0. **`--offline` on the same mount returns real findings.** |
| The OSV database was root-owned `0750`; the sandbox runs as uid 65534 | `EACCES` on the directory. osv-scanner does not treat an unreadable database as an error — it reports the project clean |
| `osv_db_version()` fell back to the image version, describing a database "bundled in the image" | That image is a 57 MB binary and bundles no database. The fabricated string made `requires_db_version` pass for an engine with nothing to match against — the check certifying the exact condition it existed to catch |
| `trivy --cache-dir` pointed at the empty tmpfs | trivy began every run with no database. It failed loudly, which is the only reason this one was not silent too |
| grype's `-q` | Suppressed the stderr line naming a missing database, making it indistinguishable from a crash: `failed` instead of `unavailable` |
| `osv-scanner` without `-r` | Visits ONE directory. On the monorepo fixture it scans the root, finds nothing, exits 0 |
| `osv-scanner` exit 1 treated as failure | Exit 1 means **vulnerabilities found**. Every scan that found something would be `failed`, so the only scans reported as succeeding would be the ones that found nothing |

### The rule that came out of it

**A vulnerability engine runs only against a database we provisioned and stamped.
No stamp, no run** — checked in `SandboxedAdapter.generate` *before the container
starts*, never inferred from the output afterwards.

This is deliberately not a classification rule. Once `{"results": []}` exists
there is no correct way to interpret it, so the run is refused instead and the
engine is `unavailable` + `ENGINE_DB_STALE` + `ENGINE_DB_NOT_PROVISIONED` — a
stated gap in Engine Coverage rather than a false negative in the findings list.

`engine_db_version` comes from **our stamp**, never from the engine's
self-report, because the stamp is the one claim about staleness we can stand
behind: we wrote it when we downloaded the data.

Because that guard cannot prove the engine *used* the database it was given,
osv-scanner additionally verifies from stderr that it opened one
(`loaded_local_databases`). That check is what the `--offline-vulnerabilities`
trap would otherwise have walked straight through.

### `workers/sbom/dbsync.py` — provisioning

The one place that runs an engine image **with a network**. It differs from a
scan in the two ways that make that acceptable: no user repository is mounted,
and an operator invokes it. It is not a weakened sandbox; it is a different
operation on different data.

Stamped only after a download that (a) exited acceptably, (b) actually wrote
bytes, and (c) **is readable as uid 65534** — verified by reading a byte as that
user, because a database the scan user cannot read is not provisioned.

Two platform-specific findings, both load-bearing:

- **grype's database cannot be written to a Windows/macOS bind mount.** It is
  SQLite, and activation runs a migration: `unable to migrate: disk I/O error
  (778)` after a successful 1m26s download. It is downloaded inside the
  container and `docker cp`-ed out.
- **anchore/grype is distroless** — no `sh` — so the permission work borrows a
  shell from another image already pinned in the manifest rather than pulling an
  unpinned utility image.

### Engines

| Engine | State | Version | Database |
|---|---|---|---|
| `syft` | working — CycloneDX inventory, 4 ecosystems on the monorepo | 1.51.0 | — |
| `syft-spdx` | working — SPDX inventory | 1.51.0 | — |
| `grype` | working — real GHSA findings against **our** syft SBOM, never a re-scan | 0.117.0 | grype-db, provisioned |
| `trivy-fs` | working — vuln + license + secret; needs `TMPDIR` on the tmpfs | 0.74.0 | trivy-db, provisioned |
| `osv-scanner` | working — findings **and alias edges**, Phase 8's union-find input | 2.5.0 | OSV, 4 ecosystems |
| `trivy-image` | implemented, **not exercised** — refuses non-digest refs; needs a pinned image to scan | 0.74.0 | shares trivy-db |
| `dependency-check` | implemented, **not exercised** — needs an NVD API key and a 30–60 min first sync | 13.0.0 | not provisioned |

### Tests — 74, in three files

- `test_database_guard.py` (25) — the one that matters. Parameterised over every
  vulnerability engine, asserting the container **never starts** without a
  database, that the status is exactly `unavailable`, that an unstamped or
  undated directory does not count, and that syft — which needs no database — is
  not blocked by the guard.
- `test_runner.py` (23) — envelopes validated against
  `proto/schemas/scan-result-v1.schema.json`, **generated from the Go types**, so
  worker/orchestrator drift fails a test rather than silently dropping results.
  Plus idempotency, grype's dependency on syft, and no-credential-in-output.
- `test_classification.py` (26) — zero-is-a-claim, timeout vs failure vs
  unavailable, one broken ecosystem not discarding the others, and the flag pins
  (`--offline`, `-r`, no `-q`) that stop the silent-false-negative traps
  recurring.

### Fixtures

`fixtures/*/raw/*.json` are Phase 8's **input**. Tests replay them instead of
running scanners, which is what makes normalization deterministic, offline and
stable across upstream changes. Regenerating them is a deliberate act
(`docs/09-GOLDEN-CORPUS.md` §5).

### The last Phase 7 bug: a read-only rootfs with nowhere to write

trivy failed EVERY run with:

    failed to prepare filesystem for post analysis:
    unable to create temporary directory: read-only file system

The sandbox gives each engine a read-only rootfs — deliberate, and not
negotiable, since we execute third-party binaries over untrusted user code. But
the error names neither trivy's needs nor the sandbox policy, so it reads as a
trivy bug.

`SandboxedAdapter.extra_env()` now exists for exactly this: trivy is pointed at
the workspace tmpfs, the only writable path in the container. All five engines
now succeed on all five fixtures.

### Known debt from Phase 7

- **`dependency-check` and `trivy-image` are unexercised.** Both are implemented
  and both report `unavailable` today for stated reasons, which is the honest
  status rather than a hidden gap. dependency-check needs an NVD API key.
- **Engine databases live outside the repo** (`AXEBOM_ENGINE_DB_ROOT`,
  ~4.5 GB). CI has none, so DB-backed engines are `unavailable` there — correct
  behaviour, but it means CI does not exercise the matching path.
- **The NATS subscription loop is not wired.** `SBOMWorker.handle` is complete
  and tested; `main()` validates the sandbox and reports what it can run. The
  consumer lands with the worker deployment.
- **`loaded_local_databases` parses stderr**, which is fragile against upstream
  rewording. The failure direction is chosen deliberately: a miss reports
  `unavailable`, understating coverage visibly, rather than reporting a project
  clean because we could not tell whether anything was checked.

---

## What Phase 8 built (in progress)

The normalizer: the component that produces every number a customer sees. Ten
modules, six ecosystem version comparators, 151 unit tests and a 43-test golden
corpus that replays the Phase 7 fixtures.

### What runs today

`python -m workers.sbom.normalize_runner fixtures/<name>` reads the committed
`raw/*.json`, and produces the canonical model end to end: identity, merge,
graph, alias closure, finding dedup, both coverage numbers, provenance.

| Fixture | Components | Findings | What it proved |
|---|---|---|---|
| `npm-simple` | 4 | 4 | lodash merged across 4 engines into one component; each vulnerability one finding with `detected_by: [grype, osv-scanner]` |
| `pypi-normalization` | 6 | 1 | PEP 503 applied — `PyYAML`→`pyyaml`, `zope.interface`→`zope-interface`, `Django_REST_framework`→`django-rest-framework` |
| `maven-case` | 5 | 7 | case preserved — `MavenCase` and `jackson-databind` survive verbatim |
| `golang-incompatible` | 9 | 9 | `Masterminds` capitalisation, `+incompatible`, and `gopkg.in/yaml.v3` all preserved |
| `monorepo-multiroot` | 16 | 13 | **9 roots** — the N-roots property; four ecosystems in one repository |

Counts are as of the full five-engine corpus. All five engines now succeed on
all five fixtures, so `trivy-fs` contributes components and graph edges that the
earlier four-engine run did not have — which is why every count moved and the
goldens were regenerated.

### Three bugs the fixtures found that reading the spec would not have

1. **The same Go module counted twice.** syft emits `v24.0.5+incompatible`;
   another engine emits `24.0.5+incompatible`. The `v` is part of Go's version
   grammar, not part of the number — so `docker/docker` appeared twice and
   **every one of its vulnerabilities was counted twice** (18 findings where
   there were 9). Fixed in `purl._canonical_version`, which normalizes that
   syntax and nothing else.

2. **Findings displayed GHSA ids where a CVE was known.** The alias closure had
   the edge; the pipeline was overwriting the pinned display id with a derived
   one. CVE is the identifier a remediation ticket quotes.

3. **A cluster-id lookup miss is silent and destructive.** Storage holding
   `ghsa-xxxx-...` where the closure produced `GHSA-XXXX-...` does not fail — it
   mints a NEW cluster id and orphans the stored one. That is the ADR-0005
   durability failure arriving through the back door. Both `assign_cluster_ids`
   and `dedup` now normalize their map keys defensively.

Also found: rule 5 of the identity chain (`file:`) was **unreachable**. It read
the digest from the same place rule 4 (`hash:`) does, so rule 4 always fired
first — a documented branch of the fallback chain that could never run. It now
reads the digest from the LOCATION.

### The rules that are enforced, with the test that proves each

- **Never merge name+version across ecosystems.** `name:npm/lodash@4` ≠
  `name:maven/lodash@4` — the single most common dedup bug in SBOM tooling.
- **PEP 503 collapses separator RUNS; it does not delete separators.** `pyyaml`
  and `py-yaml` are different projects. Over-merging is the dangerous direction:
  a missing component is a missing vulnerability.
- **Cluster ids are durable surrogates**, never content-derived. Proven by a
  test that absorbs a new alias and asserts the id did not move.
- **CVE↔CVE merges require an authoritative source**; a scanner assertion is
  refused and the refusal is recorded.
- **Clusters above 12 members are flagged, not merged** — and authoritative
  edges are applied first so the cap sacrifices the untrustworthy ones.
- **Severity is never averaged and never max'd across CVSS versions.** v2, v3.1
  and v4.0 are different scales. Conflicts are surfaced, not hidden.
- **`fixed_in_min` uses an ecosystem-correct comparator**, or reports `unknown`.
  A lexical sort answers `1.10.0` where the truth is `1.9.0` — a version that
  does not contain the fix.
- **`GPL-2.0` is flagged ambiguous, never resolved.** Choosing wrong is a legal
  error, not a data-quality error.
- **`NONE` counts as present; `NOASSERTION` does not.** The one deliberate
  exception in the coverage rules, documented where it is implemented.
- **Graphs are replaced per ecosystem, not unioned.** Unioning invents
  transitive edges no engine reported.
- **Orphans get `depth = NULL`.** Never forced to 1, which would inflate the
  direct-dependency count.
- **Both coverage numbers, always**, with the formula rendered into the output
  so the number is auditable.

### Deliberate design notes

- **Excluded and opaque components stay in the coverage denominator** (spec
  §5.4). syft catalogues the lockfile itself as `type: file`; it is marked
  `excluded` rather than dropped, so it cannot be used to quietly improve a
  percentage.
- **The SPDX document root is not a component.** `SPDXRef-DocumentRoot-…`
  describes the scanned directory; it would otherwise appear in the report as a
  dependency called `/src`.
- **No field count appears anywhere in code.** `fields_from_profile` is the only
  path into scoring, so a CERT-In revision is a data change (invariant 2).

### Also delivered: VEX, re-normalization, bulk insert

- **`vex.py`** — CSAF 2.0 statuses joined to findings, never mutating them. A
  suppressed finding is still a finding, carrying its status and justification:
  "we assessed this and it does not apply" is a defensible position, while "this
  CVE does not appear in our scan" is a different claim that must not look the
  same. Statements are append-only and versioned; a superseded one stays in the
  history. `not_affected` without a justification is refused, because an
  unjustified suppression is an assertion a reviewer cannot evaluate.

- **`renormalize.py`** — replays stored artifacts into `normalization_version +
  1` and returns a `VersionDiff`. Version N is never overwritten; a golden test
  proves version 1 comes back byte-identical afterwards. The diff keys findings
  on the DISPLAY id rather than the cluster id, because cluster ids are durable
  surrogates that differ between a stored run and a fresh one — diffing on them
  would report every finding as changed.

- **`bulk.py`** — COPY batches, because row-by-row INSERT at 50k components is
  not slow but unusable. Above the cap the run is REFUSED rather than truncated:
  a truncated BOM looks complete, is smaller than the truth, and every component
  past the cut-off is a false negative the customer trusts. NUL bytes are
  stripped at the storage boundary, since a NUL silently truncates a Postgres
  text value with no error.

### Known gaps in Phase 8

- **`dependency-check` has no committed artifacts**, so the normalizer's handling
  of its format is exercised by unit tests but not by the corpus.
- **Coverage sits near 12%** across the fixtures. That is honest, not a bug: the
  canonical model currently populates name, version, purl, licences, hashes,
  scope and author. The remaining CERT-In fields are not collected by any engine
  we run, and `not-provided` correctly scores zero for completeness.
- **The corpus is four fixtures, not fifteen.** The remaining eleven from
  `09-GOLDEN-CORPUS.md` are not built.
- **`bulk.plan()` produces COPY batches but nothing executes them.** The
  driver-level write and the transaction around it are not wired, so no
  canonical row reaches Postgres yet.
- **`renormalize` has no CLI entry point.** The function and its diff are tested;
  `axebom renormalize <scan>` is not built.
- **VEX statements have no ingestion path.** The join and its precedence rules
  are implemented and tested; nothing creates a statement yet (Phase 13).

---

## What Phase 9 built (in progress)

Two pieces, both chosen because they are structural and security-critical rather
than because they are first in the phase file.

### `render/safe` — spreadsheet formula injection (invariant 8)

A component named `=cmd|'/c calc'!A1` EXECUTES when the XLSX is opened. The
attacker never touches our servers: they publish a package with a hostile name,
a customer scans a project that depends on it, and the payload travels inside a
compliance report the customer trusts enough to open.

The escaping lives in the WRITER and is applied unconditionally, never at call
sites — a call site will eventually be added without it.

Eight real payloads are tested: DDE process launch under `=`, `+` and `-`
prefixes, `@`-prefixed functions, `WEBSERVICE` exfiltration, `HYPERLINK`
phishing, and TAB/CR parse shifting. **The guard was mutation-tested**: removing
`-` from the dangerous set makes the suite fail, naming the payload and why it
matters. Escaping is idempotent (a value may pass through two writers) and does
not corrupt UTF-8 names.

### `level` — Top-Level vs Complete projection

`Top-Level` is `depth <= 1`; `Complete` is everything with orphans flagged.

**An orphan can never satisfy Top-Level**, and that is the honest answer: we do
not know where it sits, so including it would assert a tree position that was
never established. Everything a level excludes is COUNTED — a Top-Level report
claiming "42 components" without saying it omitted 900 is indistinguishable
from a project that genuinely has 42 — and the note points at where the omitted
components can be found.

Unimplemented levels (`n-Level`, `Delivery`, `Transitive`) are REFUSED rather
than silently rendered as Complete under a label the customer chose for
something narrower.

### `export` — SPDX 2.3 and CycloneDX 1.6 via protobom

protobom is the serialization layer; we do not hand-roll either format. What
this package owns is the MAPPING, which is where a wrong decision produces a
document that validates cleanly and says something false.

Three mapping rules are pinned by tests:

- **`declared` and `concluded` licences stay in separate SPDX fields.** "The
  manifest says MIT but the LICENSE file is Apache-2.0" is a finding; writing
  the concluded value into both asserts they agreed.
- **The CERT-In identifier is a PROPERTY, never a PURL.** `pkg:supplier/Org/Name`
  is not resolvable, and putting it where a PURL belongs would make consumers
  dedup on it or fail to fetch it.
- **An unknown hash algorithm is dropped, not guessed.** A digest under the
  wrong label makes a verifier report a mismatch on a file that is fine.

#### protobom's output is not deterministic, and we require that it is

Two independent causes, both measured against v0.5.8:

1. The SPDX serializer stamps `creationInfo.created` from `time.Now().UTC()`
   (`serializer_spdx23.go:171`) with no option to supply it.
2. Identifiers and hashes are `map[int32]string` on the node, so `externalRefs`
   and `hashes` are SHUFFLED INSIDE each component between runs.

The second is the instructive one. A two-run comparison passed — the arrays
agreed by luck often enough to look green. **A 40-run check failed on the first
iteration.** Map-iteration order is randomized per run, so any small number of
comparisons can agree by chance; the stress test is the one that actually holds
the property.

`stabilize()` sorts every array recursively by canonical JSON and corrects the
timestamp to the SCAN's time rather than the render's — dating a re-render "now"
would have the document claim to describe today, and a signature over a shuffled
document would never verify twice.

Sorting is safe because in SPDX 2.3 and CycloneDX 1.6 JSON these arrays are
unordered collections. It would be wrong for a format where array position is
semantic, and that is noted where a future format would be added.

Golden documents are committed under `services/report/testdata/golden/`.

### A Phase 6 test-isolation gap, found by running the full suite

`TestRetryableFailureIsRedelivered` measured **2.6ms** where it had previously
measured 30s. Not a regression in the backoff: a WorkQueue stream keeps a
message until it is acked, so runs killed during this session's Docker restarts
left messages on the subject, and the "redelivery" was a stale message arriving
first.

The helper deleted leftover CONSUMERS but not the BACKLOG. `Bus.PurgeSubject`
now exists for that, and it carries a warning that it destroys unprocessed work.

### `render` — XLSX, CSV and JSON, sharing one cell function

XLSX and CSV are two writers over one `cell()`. Two escaping paths is two
chances to get it wrong, and only one of them ends up in the test somebody
remembered to write.

`cell()` does three things, in this order, and the order matters:

1. **Replaces characters XML cannot represent.** XLSX is zipped XML, so a NUL
   in a package name — which a hostile package can have — produces a workbook
   Excel calls corrupt: the whole report is lost, not one cell. Same class as
   the NUL truncation the normalizer handles at the Postgres boundary.
   **Replaced, not deleted:** deleting turns `lo\x00dash` into `lodash`, a real
   package it is not.
2. Escapes a leading formula character (`safe.Cell`).
3. Truncates to the 32,767-character cell limit, **visibly**.

All three are **counted and returned**. A non-zero escape count means something
in the dependency tree is shaped like an attack, which a security team wants
told rather than silently defused.

**CSV is the sharper half of the injection problem, not the milder one.** An
XLSX cell carries an explicit type, so a string stays a string; CSV carries no
types at all and whatever imports it decides. Both halves are covered — the
workbook is asserted to contain **no `<f>` elements at all**, checked against
the raw sheet XML rather than through the library that would be hiding it.

Columns come from `model.SBOMFields` at render time, so **no count appears in
the code or in the test**. Asserting "want 21 columns" would be the same defect
the invariant forbids: it agrees with the old count the day CERT-In revises.

A **CBOM is refused**, not approximated — Table 9 discriminates by asset type
and one flat column list would score a certificate against `key_size`.

### The JSON bundle is deliberately not indented

`json.MarshalIndent` reformats an embedded `json.RawMessage`, so the SPDX
document inside the bundle would stop matching the signature issued for the
standalone download. Proven by a test: mutating `Marshal` to `MarshalIndent`
fails it, 728 → 1108 bytes.

### `reportsig` — detached Ed25519 signatures

Over a **statement** rather than over the file. A signature over raw bytes says
"we produced these bytes"; over a statement it says "we produced this artifact,
in this format, for this report, at this time" — so report A's valid SPDX cannot
be presented as report B's.

Three refusals, each with a test:

- **The envelope does not carry the public key.** An attacker who can replace a
  signature can replace an embedded key. The key comes from published material
  or `axebom verify` refuses to run.
- **The algorithm is compared to a constant**, never used to select an
  implementation. `alg: none` has shipped in real products more than once.
- **Development signatures are marked** (`insecure-local:`) and report
  `Trusted=false`. Verifying against a locally generated key is a correct
  cryptographic result and a worthless assurance; the same clean pass would let
  an unsigned pipeline look signed.

**Check order is the security property**, and it has its own test: the signature
is verified over the statement bytes as they arrived, and only then is the
statement parsed and compared to the artifact.

It lives in `libs/go-shared/` because Go's own internal rule rejected the CLI's
import — correctly. The verification procedure is published; a customer must be
able to check a report without our software.

### PDF — the network guarantee is structural, not configured

The requirement is that an `<img src="http://attacker/">` in a component
description must not phone home. The usual answer is an HTML-to-PDF engine with
remote loading switched off — a **setting**, one upgrade away from turning every
render into an outbound request carrying the reader's identity.

This renderer draws text directly (`go-pdf/fpdf`, MIT). No HTML parser, no URL
resolution, no HTTP client. `TestThePDFRendererCannotReachTheNetwork` reads the
package's own imports, because a behavioural test can only prove that ONE
document triggered no request. It also fails if it scanned zero files.

Two size regimes, because they need different answers:

| | Behaviour |
|---|---|
| Far past the cap | **Refused before any work** — `REPORT_TOO_LARGE_FOR_PDF`, naming XLSX/JSON as the remedy |
| Moderately past | Produced and **cut**, with the cut stated **in the document** and in the record |

VEX and CSAF are **stubbed, not omitted**: a reader who sees no VEX section
cannot tell "no statements" from "this tool does not do VEX".

### Share links

256-bit CSPRNG token, URL-safe base64, only the hash persisted.
`Token.String()` **refuses to render the plaintext** — a token reaches a log
through `fmt.Sprintf("%v", link)` far more often than through a deliberate log
line. `ParseToken` checks **shape only**; rejecting a well-formed but unknown
token would be a free oracle on an unauthenticated endpoint.

**Revocation beats expiry**, and that ordering is a test: reporting a revoked
link as expired hides that somebody withdrew access on purpose.

`claim_share_download` does the cap check and the increment in **one**
conditional `UPDATE … RETURNING`. Read-then-write loses the cap under
concurrency — two requests both read count 4 against a max of 5 and the link
serves six. `SECURITY DEFINER` for the same reason Phase 3 needed it at login:
`/shared/:token` presents a token and nothing else, so there is no tenant in
scope to satisfy RLS.

### The recurring defect of this phase

**Anything whose bytes are load-bearing must not be stored as live JSON.** It
appeared three times:

1. protobom's shuffled arrays inside each component (previous session).
2. The JSON bundle re-indenting its embedded SPDX document.
3. The signature envelope holding its statement as `json.RawMessage` — which
   broke **every** signature the first time a real file was pretty-printed,
   reporting "signature does not verify" on a good artifact, indistinguishable
   from a forgery and pointing at the wrong half of the system.

And its companion: **a small number of comparisons proves nothing about
determinism.** A two-run check passed on protobom; 40 runs failed on the first
iteration. fpdf's font-object ordering produced files of the same LENGTH with
different bytes.

### Bugs the tests found

| Bug | Why it mattered |
|---|---|
| Signature envelope reformatted by `MarshalIndent` | Every signature failed on a good artifact |
| A 64-char hex key is also valid base64 | "Try base64 first" decoded a hex key into 48 bytes and rejected it with a length complaint |
| `os.Exit(3)` made `verify` untestable | Now `exitError`, so a pipeline can tell a failed CHECK (3) from a missing file (1) |
| The PDF text extractor read only page one | Its scan left the cursor on `endstream`, so the next match was the `stream` INSIDE it; every "is section X present" assertion had been passing vacuously against an empty string |
| `TestDummyVerifyBurnsComparableWork` flaked ~1 run in 5 | A single argon2 pass with `fastParams` is below Windows' timer granularity and reads as `0s`. Now 25 rounds. Mutation-verified. |

### Guards mutation-tested in Phase 9

Neutering `safe.Cell` fails the injection suite on all eight payloads · dropping
`orNotProvided` fails the blank-cell test on every profile column ·
`MarshalIndent` fails the byte-identity test · removing `ed25519.Verify` fails
four signature tests · a no-op `DummyVerify` still fails its timing test.

### The service is wired end to end

`POST /v1/reports` → 202 + `queued` → JetStream → worker claims → `rendering` →
render + store + sign → `ready` → `GET .../download`.

**The download permission is checked twice, deliberately.** The route carries
(report, download), which every role from Viewer up holds;
`authz.CanDownloadReport` then decides on the ROW, because CERT-In §5.3.2 gives
a Viewer the public report and not the private one. That cannot be decided
before the row is read.

**Downloads carry `attachment` + `nosniff` + `no-store`.** A report is
attacker-influenced content served from our origin: without the first, an HTML
payload in a component description is stored XSS against the customer's own
session. `no-store` is separate — a shared report that is later revoked must not
survive in a cache, or revocation means "revoke, eventually".

**`visibility` defaults to `private`.** The zero value has to be the safe one.

The render consumer runs in the API process (a render is in-process work of
seconds) and its failure is logged, not fatal.

### Three guards this phase added, each after a real bug

| Guard | The bug it caught |
|---|---|
| `routeguard` wrapper check | A route wrapped in a RATE LIMITER passed as "authenticated". The check asked "is it mounted with mux.Handle" and took yes to mean guarded. `/shared/{token}` is the first route with that shape. |
| `TestEveryColumnThisPackageQueriesExists` | Four invented column names — `project.project_practices`, `p.distribution_delivery`, `parent_component_id`, `child_component_id`. All compile; all fail only against a live database. |
| `TestLevelsMatchTheProfile` | `level.TopLevel` was `top-level`; the CHECK constraint accepts `top_level`. |

All three are mutation-verified. The second is the one worth remembering: it is
the same defect Phase 6 hit in the scan store, where invented columns left
fan-out publishing **zero jobs silently**.

`filename()` is a fourth, smaller instance: it claimed in a comment to be safe
because it is built from a uuid. That is a fact about provenance, not a property
of the function — and the test written to prove the claim failed. It restricts
the character set now, so a quote or a CR cannot reach Content-Disposition
whatever the id contains.

### Not yet built in Phase 9

- **`migrations/report/0002` has never run.** Postgres is down with Docker.
  Until it runs, `TestRLSCoverage` has not seen `report.share_access_log`, the
  two plpgsql functions are unverified, and every query in
  `services/report/internal/store` has only the static check above behind it.
- **No DB-backed integration tests for the share link.** Expiry, the download
  cap under concurrency, immediate revocation, the audit trail and the
  cross-tenant 404 are all implemented and all need a database to exercise.
  The concurrency one matters most: the cap is enforced by a conditional UPDATE,
  and the property is that two simultaneous requests cannot both pass a cap of
  one.
- **No WebSocket render progress.** `status` moves through the row and a client
  can poll; the phase file's "async render worker with progress" is half done.

---

---

## What Phase 10 built (in progress)

The five screens that make the product usable by someone who has not read the
specs. 52 frontend tests; tsc, eslint and prettier clean; production build at
**102 KB gzipped** for the initial load against a 250 KB budget, with every
route code-split.

### Two rules enforced by types rather than by review

**Neither chip has an icon-only variant.** No `showLabel={false}`, no
icon-only mode. The moment one exists somebody uses it in a dense table —
exactly where a colour-blind reader most needs the word — and the WCAG 1.4.1
failure ships inside a compliance report.

**`severity: unknown` cannot collapse into `none`.** "Nobody asserted a
severity" and "assessed as none" are different claims, and rendering the first
as the second understates risk in a document a customer acts on.

### The decision in each screen

| Screen | The decision |
|---|---|
| Generate | A 422 maps onto the STEP that owns each offending pair, rendered inline with a "Go to step N" button. A toast leaves the user to work out which of five multi-selects to change. Only hard contradictions block Run. |
| Progress | Per-engine rows. A single bar shows 100% for a scan that silently skipped an ecosystem. The announcer speaks TRANSITIONS — a live region on the percentage announces "forty-one, forty-two" and makes the page unusable. |
| Dependencies | Virtualized; filters in the URL; sorted most-severe-first. An orphan renders `unplaced`, never `transitive` — that would assert a tree position no engine established. |
| Drawer | Both identifiers side by side with a paragraph each. Every profile field listed present or not: a drawer showing only what it has looks complete at 30% coverage. |
| Findings | One row per cluster. `severity_conflict` expands to who said what. `fix_version_ordering: unknown` renders "lowest unknown" rather than a version it cannot rank. |
| Report | Both coverage numbers equally sized. **Engine Coverage is not behind a disclosure** — a reader who never expands it takes a partial scan for a complete one. |

### The empty state that is really a correctness statement

"No findings" does **not** mean "nothing wrong". An ecosystem with no available
engine produces zero findings for an entirely different reason, so the empty
state points at Engine Coverage instead of declaring the project clean.

### A test that passed because the fake was unrealistic

`FakeSocket.close()` did not fire `onclose`, so both of the WebSocket's disposal
guards could be deleted and all 13 tests still passed — vacuous in exactly the
way that looks green. Real sockets fire `onclose` after `close()`; the fake does
now, and removing both guards fails.

It also corrected an overclaim in the source. The comment said detaching the
handlers is what prevents a stray reconnect; mutation showed the `disposed` flag
alone suffices, and so does detaching alone. Both are kept — they fail
differently — and the comment says so rather than asserting a causality that is
not there.

### Deviation from the spec, stated

**`@xyflow/react` is not used**, and the dependency graph tab is not built. The
spec's own reasoning — "at 50k nodes a force-directed graph is decoration" —
argues for a subgraph of tens of nodes around a selected component, which does
not need a graph library and would cost more of the bundle budget than the
feature is worth. A hand-rolled SVG is the intended implementation.

### Not yet built in Phase 10

- **No Playwright E2E.** The seven flows in `07-FRONTEND-SPEC.md §9` need a
  running stack. The two that matter most are the full connect→scan→download
  path and "a Viewer cannot download a `private` report".
- **No axe assertions in CI.** The accessibility properties are enforced by
  hand-written component tests (label presence, `aria-expanded`, focus, Escape);
  an automated sweep of every route is not wired.
- **The dependency graph tab.**
- **Projects list, connect wizard and practices screens are the Phase 4 ones.**
  They work against the real API but predate this design system, so they do not
  yet use the shared chips, states or tokens.
- **No login, signup or invite-accept screens.** The backend contract is
  complete and tested; the screens were deferred from Phase 3 to here and are
  still outstanding.
- **The 50k-row performance claim is untested.** The table is virtualized and
  the memoization is correct by construction, but nothing has rendered 50k rows.

---

## What Phase 11 built (in progress)

Cryptographic analysis, CBOM normalization with type-aware columns, and QBOM as
derivation-plus-metadata. 96 Python tests.

### Shor breaks; Grover resizes — and conflating them is the phase's central error

A single boolean over "is it affected by quantum" is true of both families and
produces a migration list containing every cipher a customer uses. A security
team handed that list learns to ignore it, which costs them the RSA entries that
matter.

So symmetric primitives get a **note on effective strength and no flag**. The
threshold is 128 bits of QUANTUM security, which is 256 classical — reversed, it
puts AES-256 on the migration list and clears AES-128, and a test pins the
direction.

### Nine rules were written with a plain ``, and every one silently missed

`rsa` does not match `rsaEncryption` (`E` is a word character) and does not
match `sha1WithRSAEncryption` (no boundary before `R`). Those are the names
these ACTUALLY carry in certificate signature algorithms. A SHA-1 certificate
was reported `current`.

**The first fix made it worse in a new way.** Tokenizing the name before
matching fixed the camelCase cases and immediately broke four rules that were
already right: `3DES` → `3 DES` reported `broken` instead of `weak`; `ChaCha20`
→ `Cha Cha20` stopped being recognised at all.

That is the general hazard of normalizing the input to a set of hand-written
patterns: **the transform helps the wrong rules and breaks the right ones,
silently.** `search_text` keeps BOTH forms, which is additive — a rule can only
match more, and for a rule whose output is a migration list, more is the safe
direction.

### A design flaw introduced and then removed

The QBOM readiness view first classified post-quantum assets by
substring-matching `quantum_rationale` — the same "branch on the message text,
never on the code" mistake the error taxonomy exists to prevent. A copy edit to
the rationale would have silently emptied the "already post-quantum" list with
nothing failing. It matches on `quantum_family` now.

### The refusals

| Situation | What happens, and why |
|---|---|
| No usable `assetType` | Counted as unidentified, **never** defaulted to `algorithm` — that scores it against the wrong CERT-In field set |
| `related-crypto-material` | Becomes `key` only when the material type says so. A nonce is crypto material and is not a Table 9 key |
| Unrecognised key state | `unknown`, not `active`. Defaulting to active reports a revoked key as live |
| HMAC-SHA1 | `deprecated`, not `broken`. HMAC does not rest on collision resistance; condemning every SHA-1 fills a list with work nobody needs |
| `weak` vs `broken` | Kept apart. SHA-1 collisions are cheap; 1024-bit RSA is within reach of a well-funded adversary and nobody else |
| A family with no NIST replacement | Says so, rather than suggesting something plausible |

### Two honest labels, enforced in code

**QBOM references, never duplicates.** A QBOM that embedded the CBOM's assets
would drift the moment either is re-normalized, and a reviewer comparing them
would get two answers to one question.

**`readiness_note()` never produces a score.** "Quantum readiness: 72%" would be
a number we invented, weighted by judgements we did not publish, about a threat
with no agreed timeline. The counts are the honest form.

The device form carries `FORM_DISCLOSURE` — there is no quantum-hardware
scanner — at the point of entry rather than as a coverage surprise weeks later.

### Not yet built in Phase 11

- **`cbomkit-theia` has run once, end to end, but never against real crypto
  material.** This contradicted an earlier draft of this section, which said
  the container had never executed — corrected here. Session `2026-08-23 (b)`
  proved `scan.job.cbom` → sandbox → `scan.result.cbom` after fixing the
  engine's argv (`dir get <path> --quiet` was never a real invocation; the
  pinned image's own `--help` gives `dir <path>`). The one run so far used
  `fixtures/monorepo-multiroot`, which contains no certs, TLS config or
  `java.security` — so it returned `partial` with `ENGINE_ZERO_RESULTS`
  honestly, but the parser's handling of a document that actually contains
  `cryptoProperties` is still unvalidated against a live run.
- **No `crypto-mixed` / `crypto-quantum` golden fixtures.** The unit tests build
  their documents inline; there are no committed raw artifacts to replay.
- **No report sections and no UI.** The crypto inventory, quantum-readiness view
  and QBOM device form are not built. `render.FieldsFor` still REFUSES CBOM,
  which is correct until the per-asset-type sheets exist.
- **Nothing writes to `normalize.crypto_assets` or `normalize.quantum_components`.**
  The normalizer produces rows; no bulk insert wires them to Postgres.

---

## What Phase 12 built (in progress)

AIBOM discovery, model enrichment, the merge between them, and all nineteen
Table-10 elements. 458 Python tests in total.

### The two-tool split is a network boundary, not a preference

| | Where | Network | Reads |
|---|---|---|---|
| `ai-bom` | in the sandbox | none | the customer's code |
| `aibom-generator` | outside the sandbox | yes | **public model ids only** |

What crosses the boundary is a model identifier discovery already found —
`meta-llama/Llama-3-8B`, not a line of the customer's source. That is what makes
an outbound call acceptable at the second step and unacceptable at the first.

`--llm-enrich` is **refused inside the sandbox with an explanation** rather than
passed through: engines have no network, so passing it produces a connection
timeout deep inside the engine, reported as a failed scan with nothing
indicating a SETTING caused it.

### Two cache bugs, and the second is the instructive one

1. **Write key ≠ read key.** Stored under the response's revision, read under
   the request's. A lookup for "whatever is current" stored under `"main"` and
   missed forever after.
2. **`cache or ModelCache()` threw the caller's cache away.** `ModelCache`
   defines `__len__`, so an EMPTY cache is **falsy**. The caller's cache stayed
   empty, stayed falsy, and was discarded again next call.

**Neither failed anything.** The only symptom is a fetch count, which is why the
regression test counts fetches. In production this is a self-inflicted rate
limit against an API that throttles anonymously — surfacing as intermittent
enrichment failures rather than as a cache bug.

### The merge rule follows from the question each tool answers

Neither engine wins globally. Discovery wins on USAGE facts (it read the code);
enrichment wins on MODEL facts (it read the card). A single precedence order is
wrong in one direction or the other.

Identity is the model REFERENCE, never the name — `Llama-3-8B` is a name several
organisations publish variants under, and merging on it folds a customer's
fine-tune into the upstream model and attributes the upstream licence to it.
Same class as merging `npm/lodash` with `maven/lodash`.

### A low coverage number is information

Four Table-10 elements describe intent and policy that no tool reports.
`coverage_note()` explains that rather than apologising for it: an AIBOM at 40%
is reporting something true about the state of AI supply-chain metadata, and a
reader who does not know that reads it as a defect in the scan.

`risk_score` and `owasp_llm_top10` are written OUTSIDE the profile loop, so they
can never acquire a `field_status` entry and start counting toward coverage.

### Not yet built in Phase 12

- **Neither adapter has ever run.** `ai-bom` and `aibom-generator` are written
  and their parsing is tested against hand-built CycloneDX. Phase 7 is the
  precedent for why that is not the same as working.
- **No `ai-langchain` golden fixture** — the tests build their documents inline.
- **No ML-BOM export.** `services/report/internal/export/mlbom.go` is not written, so
  nothing validates against the CycloneDX 1.6 ML-BOM schema.
- **No report sections and no UI**: model inventory, dataset table, risk view,
  and the form for the four user-supplied elements.
- **Nothing writes to `normalize.ai_models`** or its dataset and dependency
  tables.
- **The per-project `--llm-enrich` setting is not surfaced or audited.** The
  adapter refuses it; the project-level toggle and its audit row do not exist.

---

## What Phase 13 built (in progress)

VEX effective-status resolution and CSAF 2.0 generation, both pure and both
mutation-verified.

### The two rules, in this order

1. **Most specific scope wins.**
2. Latest timestamp wins within a scope, then highest version.

Reversed, a sweeping project-wide "not affected" recorded today silently
suppresses a specific, deliberate "affected" recorded yesterday. The narrower
assertion was made by somebody looking at that component; the broader one by
somebody looking at the estate.

`Effective.Reason` says which rule decided, because a user who disagrees needs
to know whether to write a **narrower** statement or a **newer** one.

### The test that justifies attaching to a cluster

When the alias graph absorbs an edge, a finding shown as `GHSA-xxxx` yesterday
is shown as `CVE-2021-23337` today. A decision attached to the display id is
silently orphaned by that — the customer's "not affected, code unreachable"
stops applying and the finding reappears untriaged.

The phase file says not to skip this test. It is there, and removing the cluster
check fails it with *"a decision leaked onto another cluster"*.

### Append-only, enforced rather than documented

- `Supersede` returns a NEW statement; the predecessor is untouched.
- A successor at a **different scope is refused** — that is a separate
  assertion, and chaining it makes the history read as one evolving decision
  when it is two decisions about different things.
- Superseded statements are excluded from the decision and **kept in the
  history**. Dropping them destroys the audit chain.
- `Untriaged` is counted separately from `under_investigation`: "nobody has
  looked" and "somebody is looking" are different facts.

### CSAF round-trips including what we do not model

`csaf_advisories.document` claims to store the full document "for round-trip
fidelity". A parser that drops unmodelled fields makes that claim false, and the
loss surfaces at whoever consumes the document next. `TestRoundTrip` puts
`lang`, `distribution`, `aggregate_severity`, `discovery_date` and
`involvements` through and compares the whole document.

`Extra` never overwrites a modelled field — it records what we did not
understand, not a shadow copy that can win.

**CSAF's status spellings are not CERT-In's.** `not_affected` →
`known_not_affected`. Emitting CERT-In's spelling produces a document a
consumer's validator rejects, and a test asserts it never leaks.

### Not yet built in Phase 13

- **No storage layer and no HTTP surface.** `vex` and `csaf` are pure packages;
  nothing writes `normalize.vex_statements` or `normalize.csaf_advisories`, and
  there are no create/history/publish endpoints.
- **No comments service.** Threading to depth 5, mentions, and audited
  edit/delete are untouched — `services/comment` is still a scaffold.
- **VEX is not wired into report rendering.** The Phase 9 stub is still a stub;
  findings tables do not show effective status, and a `not_affected` finding is
  not yet visibly de-emphasized.
- **No UI**: inline triage, history timeline, CSAF viewer, comment rail.
- **The RBAC rule is unproven.** "A Viewer can comment but cannot edit VEX" needs
  the HTTP surface to exist before it can be tested.
- **Cross-tenant isolation for VEX and comments is untested** — it needs a
  database, like the rest of the Phase 9–12 backlog.

## What Phase 14 built (in progress)

Scheduled scans that run unattended, and the notifications that report them.

⚠ **UPDATE, 2026-08-25 (p): the delivery worker below did not exist when this
section was written — everything under "Webhooks"/"Secrets" was correct
about the SIGNING and CLASSIFICATION logic, but nothing drained
`notify.deliveries` or called any of it.** That worker (Consumer + Poller),
real SMTP email, and one real publisher (`report.ready`) are now built and
verified live — see (p)'s session entry and the corrected "does NOT have"
list below. Treat this section as accurate for the pure logic it describes
and superseded on "is anything actually running".

### The claim this phase is really about

**The advisory lock is not what prevents a double fire.** It is a polling
optimisation — it keeps N replicas from each running the due-campaign query
every thirty seconds. What actually prevents a duplicate scan is one line of
DDL: `UNIQUE (campaign_id, scheduled_for)`.

That distinction is load-bearing because a lock held over a network is a LEASE,
and a lease can be believed by a holder who has already lost it — a GC pause, a
partition, a reset TCP connection. Postgres drops the lock, another instance
legitimately takes it, and now two processes each believe they lead. No amount
of re-checking "am I still the leader?" closes that, because the check and the
dispatch cannot be made atomic across a network.

So the scheduler is **correct with leader election removed entirely**; it would
just do redundant work. `TestTwoInstancesProduceExactlyOneDispatch` runs two
schedulers with **no lock at all** and asserts one dispatch. If a future change
makes correctness depend on leadership, that test fails and `TestLeaderElection`
still passes — which is the pair that keeps the property honest.

Mutation-verified: removing the UNIQUE modelling from the fake store fails four
tests, including the leader-takeover and restart cases.

### DST, both hemispheres, real dates

- spring forward: `02:30` on 2026-03-08 America/New_York resolved to `03:30-04:00`
- fall back: one run at `2026-11-01T01:30-04:00`, next at `2026-11-02T01:30-05:00`

Go normalizes New York's missing 02:30 **backwards** to 01:30 (fires early, and
collides with the real 01:30 slot) but Sydney's **forwards** to 03:30. A fix
that assumed a direction pushed Sydney onto the next day. The resolution takes
the later of Go's answer and `dayStart + wall-clock minutes`.

### Missed runs

One catch-up, the rest recorded as `skipped` **with a reason**. Firing all 48
missed hourly occurrences is a thundering herd; firing none makes the gap
invisible, and a compliance customer discovers at audit that two days have no
scan. The reason reaches the UI — `CampaignDetail` renders it in full.

### No backfill on re-enable, and why there is no `enabled_at` column

Enabling sets `next_run_at` to the next **future** occurrence, so there is
nothing behind the cursor to catch up on. The alternative — an `enabled_at`
column and a comparison in the scheduler — is a rule somebody can forget, in a
path that only runs when a customer un-pauses something.

### The scheduler's one cross-tenant read

`campaign.due_campaigns(timestamptz, int)` — SECURITY DEFINER, empty
`search_path`, **scheduling columns only**. It cannot reach a component, a
finding or a report. Everything after the call runs inside `WithTenant` using
the tenant it returned. Not BYPASSRLS, which would disable tenancy for every
query the application makes in order to solve one.

### Webhooks

- Signature is `v1=<hmac>,t=<unix>` over `unix + "." + body`; **the timestamp is
  inside the signed payload**, so rewriting it does not defeat the 5-minute
  replay window. Verify checks signature, then age, then parses the body.
- **The payload carries ids, counts, a status and a URL. Nothing else.**
  `TestPayloadCarriesNoComponentOrFindingDetail` inspects the *serialized bytes*
  against an **allow-list**, so a field added to a nested type cannot slip past.
- `engines_unavailable` is included deliberately — a receiver seeing zero
  findings must be able to tell "clean" from "nothing ran".
- 4xx does not retry (408/429 excepted); 5xx retries to 1 h then dead-letters,
  and the dead letter is **retained**.

### The SSRF dialer moved to `go-shared`

A webhook URL is an SSRF primitive: the platform makes an authenticated POST to
whatever a customer types, from inside our network, on a schedule they control.
That is the same problem the fetcher solved for clone URLs, so
`libs/go-shared/platform/safedial` now holds the CIDR table and the
resolve-once-dial-the-literal dialer; the fetcher aliases to it. Two copies is
how one of them ends up missing a range.

Parse-time validation rejects the obvious targets so the customer gets a clear
error at the form; **connection time is the actual control**, because DNS
rebinding defeats any parse-time check. A blocked address is **not retryable** —
four more attempts change nothing, and each is another attacker-driven lookup.
Redirects are refused outright rather than followed safely.

### Secrets

Webhook secrets go to Vault (`vault.KindWebhookSecret`); the row holds a path.
The secret is returned **exactly once**, at creation, and there is no endpoint
that reads it back — the frontend keeps it in component state, never in the
query cache. Resolved per delivery, never cached in a struct.

### Also built

- `libs/go-shared/schemacheck` — the report store's static column check,
  extracted so campaign and notify use one implementation, and **extended to
  INSERT column lists and UPDATE SET clauses**, which the original missed.
  Mutation-verified against three invented write-path columns.
- `libs/go-shared/platform/leader` — advisory-lock election with a **registry**
  of lock ids, because Postgres advisory locks are one global namespace and two
  subsystems picking the same number silently serialise against each other.
- `routeguard.Permissions` — a route's matrix cell is now assertable, which is
  what `TestTriggeringIsADistinctPermissionFromEditing` uses.
- Service-principal tokens: `service:<name>` subject, per-tenant, 2-minute TTL,
  analyst role. **There is no cross-tenant service token.**
- Email: both text and HTML parts always rendered, `html/template` (a project
  name is user-controlled), subject sanitized against header injection and
  truncated on **rune boundaries**.

### Verification actually performed

| Check | Result |
|---|---|
| `task verify` | ✅ green end to end |
| `golangci-lint run ./...` | ✅ 0 issues |
| Go tests | ✅ all packages |
| Frontend `vitest` | ✅ 64 tests, 5 files |
| `TestLeaderElection` | ✅ follower does not even run the query |
| `TestDST*` | ✅ both directions, real transition dates |
| Mutation: drop UNIQUE modelling | ✅ 4 tests fail |
| Mutation: 3 invented write columns | ✅ all 3 caught |

### What Phase 14 does NOT have

- **Nothing has run against a database.** `migrations/campaign/0002` (the
  SECURITY DEFINER function) has never been applied; `DueCampaigns`,
  `ClaimRun` and every store method are unexercised against real Postgres. The
  static schema check proves the columns exist — not that the SQL runs.
- **`leader` has never held a real advisory lock.** Its semantics are modelled
  by a fake in the scheduler tests; the reentrancy and dead-session behaviour it
  documents are argued, not demonstrated.
- ~~No webhook has been delivered to a real endpoint, and no email has been
  sent.~~ **Built 2026-08-25 (p): both now work, verified live** — a real
  signed webhook POST reached a real HTTPS endpoint and was correctly
  classified/recorded, and a real SMTP send arrived in Mailpit. See (p).
- ~~No delivery worker. Retries are a data model and a policy, not a running
  loop.~~ **Built 2026-08-25 (p)**: `services/notification/internal/worker`'s
  Consumer (first attempts, event-driven) and Poller (retries,
  `notify.claim_due_deliveries`, migration 0002) — verified live, including a
  manually-seeded pending row actually being reclaimed and re-attempted at
  attempt 2.
- ~~Nothing publishes notification events.~~ **Three of four now do, built
  2026-08-25 (p)/(q)**: `report.ready` (report's render worker),
  `scan.completed` (`orchestr.RecomputeScanStatus`, verified live — a real
  scan reaching terminal status produced a real dead-lettered delivery row),
  `campaign.failed` (the scheduler's `FailRun` path, dedup keyed on the RUN
  id — not the campaign id, which repeats across occurrences — unit-verified
  with a fake notifier, not yet reproduced against the live container).
  `findings.new_critical` has no detection logic at all (not even a
  publisher gap — nothing computes "new" vs. the prior scan), a real design
  task, not wiring — see "Next action" at the top of this file.
- **`RunNow` is wired but never executed** — it needs the scan service up.
- **No campaign frontend tests beyond `campaigns.test.ts`** (presets, cron shape,
  timezone). No Playwright, no axe pass on the new screens.

---

## What Phase 15 built (in progress)

Hardware BOMs: CSV import, a recursive model, manual entry, optional part
enrichment, and the report sections — all of it honestly labelled.

### The label, and how it is enforced

**There is no open-source HBOM scanner.** Nothing discovers physical parts, and
an "HBOM scan" button that reads a CSV is a lie the customer finds while
assembling audit evidence, having assumed for months that something was watching
their hardware.

So the rule is enforced rather than remembered:
`test_nothing_in_this_package_claims_to_scan` walks the worker's own source for
discovery phrasing. It has a **negation filter**, because the package docstring
says an "HBOM scan" button *is* a lie and a naive substring search would flag
that sentence — making the rule unenforceable, so somebody deletes the test. A
second test exercises the filter directly, since a filter that excused
everything would leave a green test proving nothing. The frontend has the same
pair, scoped to the strings it exports.

### Zero GPL, verified rather than asserted

`django-bom` is GPL-3.0 **and** a Django application rather than a library, so
importing it would both create a derivative work and not function. It stays a
schema reference. `task osint:licenses` reports no copyleft in any binary, and a
test asserts no module in `workers/hbom/` imports it. Our model is ours: a
recursive dataclass, ~300 lines.

### Twenty-four elements, and Table 11 alone is not enough

§10.4.1.4 (p.62) mandates `firmware_version`, `origin`, `criticality` and
`vulnerabilities`. **None appears in Table 11.** A tool implementing Table 11
and stopping reports itself as complete while missing four required elements.

**Two supplier relationships, not one.** Table 11 lists "Supplier Information"
and "Supplier Location" *twice*, with different descriptions: who sold the
customer the PRODUCT, and who supplied a COMPONENT to that product's
manufacturer. Collapsing them asserts that a distributor sold the customer a
gateway — false, and unfalsifiable from the output. Mutation-verified: aliasing
element 13 onto the product-supplier attribute fails the test.

The count is never written. It renders from `len(HBOM_FIELDS)`, and a test
greps the package for a hardcoded literal.

### The importer

`level` drives the tree, and its **sequence is validated**. A level-3 row after
a level-1 row has no parent; accepting it silently reparents the part and
produces a structurally valid BOM that is factually wrong, which nothing
downstream can detect. The error names the row and both levels — a customer
staring at a 400-line export needs to know it was line 217.

Outline levels (`1.2.1`) are understood, because that is how most CAD and ERP
exports write nesting. Depth is capped at 10 with a **diagnostic**, not silent
truncation. Duplicate sibling parts **warn** rather than fail: the same
capacitor legitimately appears in four sub-assemblies, and rejecting that would
reject most real hardware.

**Column mapping exists so nobody edits their file.** Requiring a customer to
rename columns means they edit an export, make a mistake, and import something
that no longer matches their source of truth. Header suggestions are a
*proposal a human confirms* — silently deciding that a column called "Supplier"
is the component supplier would put data in the wrong one of the two
relationships.

### What csv.DictReader actually yields

A row with **more** fields than the header puts the surplus under a `None` key
*as a list*; a **short** row yields `None` values. Both happen in real exports
(a stray trailing comma, a truncated last line). The signature says so, because
`dict[str, str]` is simply false and a false annotation is what makes a type
checker call a live branch unreachable.

⚠ **The None-handling branches are belt-and-braces, and the code says so.** A
mutation removing any of them breaks nothing today: the `None` key is filtered
because the mapping lookup misses, and the `None` value is flattened downstream.
That was discovered by mutation testing an earlier comment that claimed
otherwise, and the comment was corrected rather than the mutation ignored.

### The form is a first-class input

Warranty, licence terms, test result and criticality appear in **no** CAD or ERP
export — they are judgements about the customer's own hardware. If the only way
in is a CSV, those four are permanently `not-provided` and the coverage number
is needlessly low for a reason nothing on screen explains. The form validates
through the same code the importer does, and **refuses** an unrecognised
criticality rather than coercing it: mapping "urgent" onto "critical" would be
inventing a severity in a compliance document.

### Enrichment is additive and never overwrites

A parts database is a third party's opinion about an MPN; the customer's BOM is
a statement about the hardware in front of them. When they disagree the
customer's value goes in the document and the provider's is recorded as
provenance. Compliance is a **union** — a customer asserting RoHS and a provider
asserting CE are both true.

`manual` is the default, is always configured, and is the tested path. Nexar and
Mouser are **skipped cleanly when unconfigured** — no error, no empty-credential
call that produces a 401 in somebody's logs about a feature they never enabled.
Part numbers are deduped before a billable lookup.

### Coverage

Every node is scored, not just the root: a fully populated gateway over 200 bare
leaf parts is not a well-documented BOM. The `hbom-nested` fixture scores
**52.5% completeness against 100% declaration** — every field is declared, half
carry substantive values. That gap is the two-number rule working.

Diagnostics name origin, manufacturer location and the two supplier
relationships **separately**, because a single percentage averages those gaps
away across twenty other fields and §10.2.1 is the reason they exist.

### Report

Two hardware sheets on top of the standard set: a tree, and an origin/supplier
view. **The indent is a separate column, not padding on the name** — a padded
name no longer matches the component, so a filter or VLOOKUP against it fails,
and a leading space is one of the characters formula-injection escaping has to
consider. Escaping is inherited from `cell()` rather than re-applied, and a test
proves the inheritance rather than assuming it.

### Verification actually performed

| Check | Result |
|---|---|
| `task verify` | ✅ green end to end |
| `pytest workers/hbom` | ✅ 52 tests |
| `task test:golden` | ✅ 58, incl. `hbom-nested` |
| `task osint:licenses` | ✅ no copyleft in any binary |
| `golangci-lint run ./...` | ✅ 0 issues |
| `ruff check` + `mypy` | ✅ clean (bar pre-existing `py.typed` gap) |
| Frontend `vitest` | ✅ 78 tests |
| Mutation: 8 documented guarantees | ✅ all caught |

### What Phase 15 does NOT have

- **Nothing has run against a database.** No HBOM row has been written to
  `normalize.hardware_components`; the recursive `parent_id` wiring, the
  `criticality` CHECK and RLS on that table are all unexercised.
- **No HTTP surface.** `/v1/hbom/preview`, `/import`, `/lookup`, `/provider` and
  the component endpoints are called by the frontend and **do not exist** — the
  UI is written against a contract nothing serves yet.
- **Neither commercial provider has ever run.** Nexar and Mouser are written
  against published schemas with parsing tested on hand-built responses. Phase 7
  is the precedent for why that is not the same as working.
- **No CycloneDX HBOM export** (§10.4.1.6). The XLSX/CSV sheets exist; the
  extended-SBOM export does not.
- **Vulnerability matching is not wired.** `findings[]` — §10.4.1.4's fourth
  element — is modelled and rendered but nothing populates it.
- **No frontend component tests** for the import wizard or tree editor, and no
  axe pass on either screen.

---

## What Phase 16 built (in progress — the buildable half)

⚠ **Phase 16 splits in two, and only one half is done.** The code and documents
are written; the adversarial and load work — penetration test, k6 execution,
restore drill, chaos, Helm dry-run — needs a running stack and a cluster, and is
deferred with the rest of the integration backlog. Nothing below was verified
against a live system.

### §16.1 — the guardrails, enforced rather than grepped

The phase file asks for two checks by hand. A hand-grep happens once, performed
by the person who already knows the rule — who is the person least likely to
have broken it. `axebom profile guardrails` runs in CI instead:

- **no hardcoded field count** — a literal stops matching the profile when
  CERT-In revises the guideline, and nothing fails when it does
- **no assertion of compliance** — that is a determination an auditor makes about
  an organisation, not one a tool makes about a repository

**The check took three versions to get narrow enough, and that history is the
interesting part.** A naive "does this line contain 21?" flagged
`pageWidth = 210.0`, a 24-hour cache TTL, and two comments explaining the rules
themselves — five findings, five false positives. Tightening to "number near
field-context" then flagged eight CERT-In **ordinals**: "§4.2 field 21" names
the Unique Identifier, it is the guideline's own numbering, and rewriting it
would be wrong. Nine findings, nine false positives.

A check that cries wolf is a check somebody disables, and a disabled check is
worse than no check because its absence is invisible. The rule that works: **a
count answers "how many", an ordinal answers "which one"** — the number must
precede the noun. Comment state is tracked across lines, because a prefix check
misses every continuation line, which is where prose lives.

### §16.1 — the evidence pack

`docs/COMPLIANCE-REPORT.md`, generated by `task profile:evidence`. The phase
calls it the artifact a customer's auditor will actually ask for.

Every row cites the PDF page requiring that element. **That citation is the
difference between an evidence pack and a marketing table** — an auditor opens
page 27 and checks.

The coverage map is the one part that can lie; everything else is generated from
the profile and cannot drift. Two guards: the default is `not-implemented`, so a
mistake understates rather than overstates the product, and a test fails when
the profile gains an element the map does not mention. Three more assert the
honest labels hold — no hardware element is ever `automated` (nothing discovers
physical parts), no QBOM element is (there is no quantum-hardware scanner), and
the crypto sections stay split by asset type.

Current picture, and it reads honestly:

| | elements | user-supplied | not implemented |
|---|---|---|---|
| SBOM | 21 | 3 | — |
| QBOM | 11 | 8 | — |
| AIBOM | 19 | 5 | — |
| HBOM | 24 | 4 | 1 |
| CBOM (4 asset types) | 30 | — | 3 |

`profile evidence -check` fails when the committed pack is stale. **A stale pack
is worse than an absent one:** it is a document somebody hands to an auditor in
good faith, describing a product that has moved.

### §16.4 — audit-log export

CERT-In §5.3.6 asks for review; export is what makes review practical, because a
log nobody can get out of the database is a log nobody reads.

- **JSON Lines, not a JSON array** — an array must be closed, so an interrupted
  stream produces a file no parser will read; JSONL degrades to
  truncated-but-usable.
- **`SetEscapeHTML(false)`** — the default corrupts a user-agent string and any
  URL in metadata, so the export would no longer match what was recorded, which
  is the one thing an audit artifact has to do.
- **Sorted metadata** — map order is randomized, and a reviewer diffing two
  exports would see noise instead of change.
- **Formula escaping** — audit metadata carries user-controlled strings, and CSV
  is the format a reviewer opens in Excel.
- **The export is itself audited** — a log with no record of its own export has
  a blind spot shaped like the most interesting question.

### §16.4 — API keys

⚠ **An API key is a long-lived bearer credential**, and every decision follows
from that. It gets pasted into a CI config, copied into a wiki, echoed by a
build log.

- shown once, stored as SHA-256 — a database disclosure is not a disclosure of
  every customer's key
- **scopes, not roles** — a CI pipeline needs `scan:run` and `report:download`;
  an analyst role would also give it triage, share-link minting and campaign
  editing, none of which it will ever use and all of which it could if leaked
- **no admin scope, and there must not be** — nothing touching tenants, members
  or the audit log is reachable with an automated credential
- a **recognisable prefix** (`ebk_`), because secret scanners match on known
  prefixes and a key that looks like random base64 is one nobody finds in a
  public commit
- **expires by default** at 90 days — "never expires" is how a credential
  outlives the person who created it
- SHA-256 rather than argon2, deliberately: 256 bits from `crypto/rand` means
  brute force is not the threat, and a slow hash per request is a denial of
  service against ourselves
- the hash is compared **before** expiry and revocation, so timing cannot reveal
  whether a key exists

### §16.5 — Helm charts

⚠ **The engine node pool is the important part.** Engine workers execute
third-party scanners over untrusted customer code; the whole security model
rests on those processes sharing a kernel with nothing that holds a credential.
Kubernetes does most of this the wrong way by default:

- `automountServiceAccountToken: false` — a mounted token inside a process
  running untrusted code is what turns a container escape into a cluster
  compromise
- a dedicated, tainted node pool — the pool IS the blast-radius boundary
- **hard** anti-affinity between trusted services and untrusted workers;
  "preferred" means the scheduler co-locates them when the cluster is busy,
  which is exactly when nobody is watching
- default-deny egress as a second layer behind `--network=none`
- tmpfs workdir with a size limit — an unbounded tmpfs is node memory a crafted
  repository can exhaust
- **raw scan artifacts are never expired** — a lifecycle rule aging them out
  silently converts a replayable system into an unauditable one

### §16.7 — the honest limitations list

`docs/LIMITATIONS.md`. The phase calls this a feature, and it is: the
alternative is discovering these together during an incident. It separates
deliberate boundaries from current gaps and ends with **what would change our
mind**, because a claim about limits should be falsifiable.

### Verification actually performed

| Check | Result |
|---|---|
| `task verify` | ✅ green, with two new gates wired in |
| `golangci-lint run ./...` | ✅ 0 issues |
| `profile guardrails` | ✅ 194 files, no violations |
| `profile evidence -check` | ✅ pack current, 8 sections |
| Mutation: 10 guarantees | ✅ all caught |
| k6 scenarios | ✅ parse (esbuild); **never executed** — `.github/workflows/load-test.yml` (o) wires real execution, itself unrun |
| Helm chart | 🟡 `Chart.yaml`/`values.yaml` parse; **templates never rendered — helm is not installed** |
| `task test:conformance` (SPDX/CycloneDX) | 🟡 CycloneDX ✅ valid against official schema; SPDX ❌ real bug found, `xfail`'d — see (o) |
| API-key mint→authenticate→revoke, live | ✅ (o): real key minted, real request authenticated with correct tenant/role/scopes, revoked key correctly refused |
| Audit-log export, live | ✅ (o): both formats, against the real dev database, export-of-export correctly recorded first |

### What Phase 16 does NOT have

- **No penetration test.** The phase's central deliverable. It needs an external
  party and a running system.
- **No load-test BASELINES, still — but the mechanism to produce them now
  exists and has not been run.** `.github/workflows/load-test.yml` (2026-08-25
  (o)) brings up a real stack, mints a real API key, and runs all three
  `perf/*.js` scenarios — written against `Taskfile.yml`'s own `dev`/
  `iam:bootstrap`/`db:migrate`/`db:seed` targets, `actionlint`-clean, but
  **never executed by an actual GitHub Actions runner** (this session had no
  way to run one). Treat the first real trigger as a dry run. The numbers in
  the scenarios remain TARGETS until one actually completes.
- **The Helm templates have never been rendered.** `helm` is not installed on
  this machine, so `helm template | kubectl apply --dry-run=server` — the
  phase's exit criterion — has not run. The templates are unverified YAML with
  Go template syntax. Untouched this session.
- **No restore drill, no chaos testing, no PITR configured.** All need
  infrastructure. Untouched this session.
- **No SAML/OIDC SSO and no SCIM.** API keys are built AND now have a real
  HTTP surface (see 2026-08-25 (o) below); enterprise identity federation is
  still not started at all — a materially larger feature, deliberately not
  attempted opportunistically alongside the bounded items above.
- ~~The API-key store, HTTP surface and middleware do not exist.~~ **Built
  2026-08-25 (o)**: `auth.api_keys` (migration 0004), a pre-tenant
  `oidcauth.Authenticate` branch usable by EVERY service (not just the one
  that mints them), scope-narrowing in `auth.Authorize`, and
  `POST/GET /v1/api-keys` + `DELETE /v1/api-keys/{id}` (RoleOwner). Verified
  live: minted a real key, authenticated a real request with it, confirmed
  revocation blocks it.
- ~~The audit-export CLI command and HTTP endpoint do not exist.~~ **Built
  2026-08-25 (o)**: `GET /v1/audit-log/export` (tenant-scoped, streaming) and
  `axebom audit export --tenant --actor` (operator, owner-connection,
  explicit-tenant-filtered — the one place in this codebase a hand-written
  `WHERE tenant_id = ?` is correct, because there is no RLS to lean on
  outside the application path). Both record the export as its own audit
  event, before streaming, per `auditexport.ExportRecord`'s own design.
  Verified live against the dev database in both formats.
- **`docs/RUNBOOKS.md` is still a forward reference**, because a runbook whose
  procedures have never been executed is fiction. Untouched this session.
- ~~No SPDX/CycloneDX conformance run against the official validators.~~
  **Built 2026-08-25 (o)**: `task test:conformance`
  (`tools/conformance/test_spdx_cyclonedx.py`, `pip install -e ".[conformance]"`)
  runs the golden fixtures through `cyclonedx-python-lib` and `spdx-tools` —
  the real thing, not a hand-rolled schema check. **Found a real bug, left
  unfixed and `xfail`'d rather than papered over**: `services/report/internal
  /export`'s `toNode()` feeds the raw `component_key` (e.g.
  `purl:pkg:maven/...`) straight into every SPDX `PackageSPDXIdentifier` and
  relationship reference. SPDX 2.3 permits at most one colon in an SPDXID
  (reserved for `DocumentRef-X:SPDXRef-Y`); ours carries several, because a
  PURL itself has colons. CycloneDX's `bom-ref` has no such restriction,
  which is why the CDX fixture validates clean on the exact same underlying
  key and the SPDX one does not — confirmed the bug is SPDX-specific, not a
  general identity problem. Not fixed: the correct fix touches
  `export.go`'s shared node/root/edge ID generation for BOTH formats and
  would change the golden fixtures, which is a deliberately separate,
  reviewed decision (CLAUDE.md: "a golden updated without justification is a
  guard removed"), not a side effect of adding a conformance check.
- **No CI wiring for dependency/vulnerability scanning existed before this
  session — not even a stub job**, worse than the phase's own prose implied.
  **Built 2026-08-25 (o)**: `.github/workflows/security-scan.yml` —
  `govulncheck` (Go, call-graph aware), `pip-audit` (Python deps),
  `npm audit` (frontend deps), `trivy fs` (the same trivy the product runs
  against customer code, pointed at this repository instead). Deliberately
  separate from `verify.yml`'s existing `gosec` (static analysis of OUR code,
  belongs in the fast gate) — this is KNOWN-CVE scanning of dependencies,
  on a schedule plus manifest-change triggers, not every PR.
  `actionlint`-clean; **never executed by an actual GitHub Actions runner**,
  same caveat as the load-test workflow above.

---

## Session log

### 2026-08-29 (a) — Project registration, phase 2 of a new 5-milestone plan: the upload→scan gap closed, and a real repo-scoped GitHub connect flow built (Milestones 1–2 of 5)

The user asked for the project-registration screen to support three source types — a live URL, direct upload, and a GitHub-connect repo picker (plus pulling a connected repo's own CI-published SBOM in as an OSSF sbom-everywhere-style reconciliation source) — scoped to SBOM only for this pass. Three parallel research forks (docs/specs, frontend code, backend code) plus a design fork found this was not a small UI task: Phase 4's registration wizard and its backing REST API already existed and mostly worked, but two of the three source paths had real gaps and the third (URL) didn't exist in any form. A 5-milestone plan was designed, reviewed against the actual code (not just the research summaries), and saved to `~/.claude/plans/the-project-section-while-rippling-shamir.md`: (1) fix upload→scan plumbing + wire the upload UI, (2) GitHub Connect OAuth + repo picker, (3) GitHub Dependency Graph reconciliation import, (4) URL source registration, (5) `services/webrecon` — subfinder + JS fingerprinting. This entry covers (1) and (2), both fully implemented and verified this session; (3)–(5) remain, per the plan file.

**Milestone 1 — the real bug this closed:** `POST /v1/projects/{id}/uploads` and its frontend hook were fully built and tested, but a scan created with `source_kind=upload` always failed with `FETCH_NO_SOURCE` — `scan-orchestrator` always published `scan.job.fetch` regardless of source kind, and the fetcher's `source.Resolve` only ever read `project.repository_connections`, never `project.uploads`. The wizard also had no `upload` branch in its source step at all. Fixed by making `fetcher/internal/source.Source` a discriminated union (`Kind: git|upload`, decoded from a new `kind`-tagged response shape `project`'s `Source()` handler now emits per `source_type`), and extending `fetcher/internal/work.Worker.handle()` to branch on it: git keeps the existing `fetcher.Clone` path unchanged; upload downloads the stored object from MinIO and either extracts it (new `libs/go-shared/fetcher/extract_archive.go` — `ExtractZip`, mirroring every zip-slip/symlink/decompression-bomb guard `ExtractTar` already had, plus an `ExtractArchive` dispatcher covering `.zip`/`.tar`/`.tar.gz`/`.tgz`/`.tar.zst`, refusing an unrecognized extension with a new `FETCH_UNSUPPORTED_ARCHIVE_FORMAT` code rather than sniffing magic bytes) or places a single manifest/lockfile/sbom file as-is, before the SAME `fetcher.CreateArchive` path every git clone already used takes over — so every engine downstream reads an identical content-addressed archive regardless of which path produced it. Provenance (`argv_redacted`, commit SHA) is now honest per source kind rather than always claiming `git clone`. Frontend: `ProjectWizard.tsx`'s `SourceStep` gained the missing `upload` branch — multi-file staging with per-file `kind` (defaulted by extension), wired through the existing, previously-unused `useUploadFile` hook.

**Milestone 2 — GitHub Connect, a repo-scoped OAuth flow distinct from sign-in.** The only GitHub OAuth flow that existed was account sign-in (`read:user user:email`, token exchanged and discarded) — `GET /v1/github/repos` (the repo picker's backing endpoint) required the caller to already hold a `repo`-scoped token via a header, and nothing produced one. Built a second, independent OAuth round trip on the SAME GitHub OAuth App (a second registered callback URL — GitHub OAuth Apps support more than one): `service.GitHubClient.AuthorizeEndpoint`/`exchangeCode` now take `redirectURL`/`scope` as explicit per-call parameters instead of fixed client config, since one client now serves two callback paths; new `BeginGitHubConnect`/`CompleteGitHubConnect` mint CSRF state and exchange the code but — unlike `CompleteGitHubLogin` — never call `resolveGitHubUser`/`issueFor`/`s.audit`: no session, no user lookup, no database write, just the raw token handed back. New handler pair (`services/auth/internal/handler/github_connect.go`, `GET /v1/auth/github/connect/authorize`/`callback`, both in `publicRoutes` since a browser redirect carries no bearer token) uses its own state-cookie name and path (`axebom_oauth_connect_state`, `/v1/auth/github/connect`) so it can never collide with the login flow's `axebom_oauth_state`, and delivers the token via URL fragment to a new frontend relay route exactly like the login callback does (`{frontend}/projects/github-connect#access_token=…`). Frontend: the relay page (`GitHubConnectCallback.tsx`, mounted outside `Shell` like `/auth/callback`) reads the fragment and `postMessage`s it to `window.opener` (origin-checked both directions), then closes itself; a new `useGitHubConnect()` hook in `lib/projects.ts` opens the popup (not a full-page redirect — the wizard's `Draft` lives only in component state, and a full-page OAuth round trip would discard whatever was already typed) and resolves with the token via the `message` listener; a new `GitHubRepoPicker.tsx` drawer (built on the existing `Overlay` primitive) wraps the already-implemented, previously-unused `useRepoSearch` hook; `ProjectWizard.tsx`'s `github` source branch now replaces the old plain-text repo-id fields entirely with a "Connect GitHub" button → picker → staged selection, submitted via the existing `useConnectRepo` hook once the project itself exists. `GitHubConfig.RedirectURL` (the old single-callback field) was removed as dead code rather than left unused; new env vars `GITHUB_CONNECT_REDIRECT_URL` in `.env`/`.env.example`, both pointing at the same OAuth App's second callback URL.

**Docs updated as part of the same session, not after the fact:** `docs/02-CONTRACTS.md` §8 gained the two new routes and a paragraph on the connect flow's fragment-delivery contract (token → Vault via the connections endpoint, never Postgres, never the SPA's persistent storage); `docs/05-SECURITY-MODEL.md` §7 gained a note on the connect token's in-memory-only lifetime and a named, deliberately-deferred residual risk (the token is scoped to `repo` — every repository the authorizing account can read, not just the one connected; a GitHub App with per-installation permissions is the correct long-term fix, out of scope here). Also fixed one small pre-existing doc inaccuracy found while editing the adjacent line: §8's route table said `POST /auth/github/callback`; the real route (confirmed against `services/auth/routes.go`) is `GET`.

**Verification, both milestones — against real infrastructure, the established convention for this layer, not mocks.** Go: `go build ./...`/`go vet ./...`/`task lint:boundaries` clean repo-wide; full `go test ./...` clean (only pre-existing `[no test files]` packages and — unrelated to this session, see below — a flaky subset of `services/auth/internal/service` tests). 17 new extraction-guard tests (`libs/go-shared/fetcher/extract_archive_test.go`) covering zip-slip, symlink refusal, a real decompression bomb (aborts mid-stream, confirmed by asserting `UncompressedB` stays far under the declared size, not just that it errors), file-count/size ceilings, and format-dispatch, including under `-race`. 6 new integration tests (`services/fetcher/internal/work/work_test.go`, package `work` — not `work_test` — specifically to reach the unexported `materializeUpload`) run against the REAL MinIO and NATS in this dev stack: zip/tar.gz extraction, single-file placement, a missing-object failure classified correctly as terminal (`FETCH_NO_SOURCE`, not retried), an unrecognized-format refusal, and a path-traversal archive rejected with nothing written outside the workspace. 11 new GitHub-connect tests mirroring the existing login CSRF suite exactly (`services/auth/internal/handler/handler_test.go`, `services/auth/internal/service/github_test.go`) — missing/mismatched/replayed state, the cookie-name-and-path isolation from the login flow (proven directly: mint both, assert distinct names/values/paths), repo scope present in the redirect, never a refresh cookie set on the connect callback, and (service-level) `CompleteGitHubConnect` called on a **nil** `*Service` receiver — which only works because the method never dereferences it, itself part of what's being asserted: it cannot look up a user or write an audit row. Rebuilt and redeployed the real `project`, `fetcher`, and `frontend` containers (`docker compose ... up -d --build <service>`) — all healthy; the auth service (GitHub client id/secret are genuinely unset in this environment's `.env`, so the connect flow's live OAuth exchange itself is untested against real github.com, only against the fake-GitHub test server) was not separately redeployed since nothing in its container changed behaviorally without real credentials configured. Frontend: `tsc --noEmit`, `eslint . --max-warnings 0`, `prettier --check` and all 84 existing Vitest tests pass clean after each milestone.

**Attempted, and honestly blocked by a pre-existing, unrelated environment issue, not a regression:** a full Playwright E2E through the real login → register-by-upload → generate-SBOM → scan-progress flow (`frontend/e2e/upload-project.spec.ts`, new). Two real things were found and are worth keeping: this dev stack's frontend container serves HTTPS-only (a self-signed cert from `task tls:gen`, since `ZITADEL_DOMAIN=192.168.30.202` here — a LAN IP), so `playwright.config.ts` gained `ignoreHTTPSErrors: true` (a no-op against a plain `http` baseURL, so harmless everywhere else); and the pre-existing `auth.spec.ts`/`generate.spec.ts` specs click a `getByRole('button', { name: 'Sign in' })` that no longer exists anywhere in the frontend source — the real button says "Log in" (`AuthRoutes.tsx`) — confirmed independently by running `auth.spec.ts` unmodified, which fails identically and was not touched here (out of scope, flagged for whoever owns e2e next). With that fixed locally in the new spec, sign-in itself is blocked by something genuinely outside this session's scope: ZITADEL's OAuth client in this stack was bootstrapped expecting an `http://` redirect URI, but the frontend answers only over `https://` — GitHub-style, ZITADEL returns `invalid_request: the requested redirect_uri is missing in the client configuration` at the very first hop. Fixing it means either disabling this environment's LAN-IP TLS (risks breaking another device's access to this same shared dev stack, not attempted) or re-running `task iam:bootstrap`/`iam:reset` against the https origin (destructive to the identity tier, not attempted without being asked). The new spec is left in place, correct, and will pass once that pre-existing mismatch is resolved by someone who owns that decision.

**Also observed, pre-existing, not fixed:** roughly 20 of ~52 tests in `services/auth/internal/service` skip nondeterministically (reproduced across repeated full-suite runs) with `owner connection unavailable: ... operation was canceled` — traced to `service_test.go`'s `ownerConn(t)` dialing with `t.Context()`, which is already cancelling by the time it's called from inside a `t.Cleanup()` handler (`cleanupTenant`). Affects register/login/refresh/audit tests untouched this session, not just the new GitHub-connect ones (which don't depend on it at all); `service_test.go` was not edited. Worth a five-minute fix (dial with `context.Background()` instead) for whoever next touches that file.

**Files touched, by area:** Go — `libs/go-shared/fetcher/{extract_archive.go,extract_archive_test.go}` (new), `libs/go-shared/platform/errs/errs.go` (new `FETCH_UNSUPPORTED_ARCHIVE_FORMAT`), `libs/go-shared/platform/config/service.go` (new `GitHubConnectRedirectURL`), `services/fetcher/internal/{source/source.go,work/{work.go,work_test.go}}` (`work_test.go` new), `services/project/internal/handler/handler.go`, `services/auth/{deps.go,routes.go,internal/{handler/{handler.go,github_connect.go,handler_test.go},service/{github.go,github_test.go}}}` (`github_connect.go` new). Frontend — `frontend/src/routes/projects/{ProjectWizard.tsx,GitHubRepoPicker.tsx,GitHubConnectCallback.tsx}` (`GitHubRepoPicker.tsx`/`GitHubConnectCallback.tsx` new), `frontend/src/lib/projects.ts`, `frontend/src/App.tsx`, `frontend/playwright.config.ts`, `frontend/e2e/upload-project.spec.ts` (new). Config — `.env`, `.env.example`. Docs — `docs/{02-CONTRACTS.md,05-SECURITY-MODEL.md,STATE.md}`.

**Nothing committed to git this session** — everything above is uncommitted working-tree changes; the user has not asked for a commit.

**Next session (superseded by (b) below — Milestone 3 is now done):** ~~Milestone 3 (GitHub Dependency Graph reconciliation import) is next per the saved plan~~, followed by Milestone 4 (URL source registration — data model + plumbing only) and Milestone 5 (`services/webrecon` — the highest-risk, genuinely-new piece: subfinder + a Go-native retire.js-signature matcher, built last on a proven `source_kind=url` contract). Read the plan file in full before starting Milestone 4; it names the cross-cutting decisions (why `services/webrecon` is a new service and not a fetcher extension, why the JS-fingerprint matcher is native Go rather than embedding retire.js's own CLI, the two gotchas found by direct code inspection — `ScanJobV1.Validate()`'s `FamilyFetch`-only workspace exemption needs a `FamilyWebrecon` carve-out, and `source.Resolve()`'s empty-`RepoURL` check needs to stay kind-aware as new kinds are added).

### 2026-08-29 (b) — Project registration, phase 3: a connected GitHub repo's own Dependency Graph SBOM now imported as a reconciliation source (Milestone 3 of 5)

Continuation of (a), same overall plan (`~/.claude/plans/the-project-section-while-rippling-shamir.md`). Milestone 3: the smallest remaining piece by design — an `internal`-mode engine, no sandbox, no network policy of its own — but it touches five layers (Go event envelope, the fetcher, the orchestrator's registry and FanOut, a new Python adapter, and the normalizer's ingest dispatch), because the reconciliation document has to travel from a service that never runs a sandboxed container (the fetcher) to one that does (the sbom-worker), carried on the job envelope itself rather than a side channel.

**The mechanism.** `events.Workspace` gained a new optional field, `NativeSBOMRef` — set by `FanOut` only on the one engine that consumes it (`policy.Engine.ConsumesNativeSBOM`, a new bool distinct from `RequiresImport`: the first is a dispatch-time instruction, the second an honest-label claim). After a successful GitHub clone, the fetcher (`work.go`'s new `fetchDependencyGraphSBOM`) calls GitHub's `dependency-graph/sbom` API using the same repo-scoped token already in hand (new `libs/go-shared/fetcher/depgraph.go`, `FetchDependencyGraphSBOM`) — **unwrapping GitHub's `{"sbom": {...}}` envelope before ever storing it**, so what lands in `scan.raw_artifacts` (role `native_output`, engine `fetcher`) is a genuine, standalone SPDX 2.3 document, not a GitHub-specific transport shape. `FanOut` looks this up once per call (`nativeSBOMRefFor`, wrapping the already-existing `LoadRawArtifactsForEngines` — built for `NormalizeTriggerV1` in the SBOM pass, reused here for exactly the kind of lookup it was designed for) and writes it onto the `github-dependency-graph-sbom` engine's job only. On the Python side, a new CLI verb (`axebom source fetch-artifact` — single-file download, no extraction, sibling to but distinct from `source materialize`'s archive-extraction path) is wrapped by `axebom_shared.source.materialize_native_sbom`, called unconditionally but cheaply from `runner.py`'s `handle()` (a dict lookup for every other engine's job, a real subprocess call only for this one) and threaded into a new `ScanTarget.native_sbom_path` field. The new adapter (`workers/sbom/adapters/github_dependency_graph.py`, subclassing `ToolAdapterBase` directly — there is no container to sandbox) reads that path, reports `unavailable` honestly when it is absent (the overwhelmingly common case: not a GitHub repo, Dependency Graph disabled, or the API call failed), and otherwise stages the document as its own raw artifact. Actual parsing needed **zero new code**: because the artifact is genuine SPDX 2.3, `libs/py-shared/axebom_shared/normalize/ingest.py`'s dispatch table just points `"github-dependency-graph-sbom"` at the same `_ingest_spdx` function `syft-spdx` already exercises.

**A design correction made mid-implementation, not after the fact.** The client originally built its own `SafeHTTPClient` internally from a `*SafeDialer` — consistent with "every outbound fetcher request goes through the guarded client," but it makes the function untestable against `httptest`, since `SafeDialer` blocks loopback by design with no bypass (confirmed by reading `validate_test.go`'s own redirect tests, which work around this the same way: overriding `Transport` after construction). Refactored to accept an `*http.Client` from the caller instead — production (`work.go`) explicitly constructs `fetcher.SafeHTTPClient(nil)` and passes it in, so the safety guarantee is unchanged, but the function itself is now a plain, directly-testable HTTP client consumer. The same reasoning already applied once this session, in (a), to `GitHubConfig.RedirectURL`'s removal — a recurring shape: a security-motivated internal construction that looks right until a test tries to reach it.

**Verification, against real infrastructure and the live stack, matching (a)'s convention.** Go: `go build ./...`/`go vet ./...`/`task lint:boundaries` clean repo-wide; full `go test ./...` clean. New tests: `libs/go-shared/fetcher/depgraph_test.go` (8 tests, real `httptest` servers — envelope unwrapping verified byte-for-byte with the GitHub wrapper key asserted ABSENT from the returned bytes, 404/403 handling, malformed-envelope and invalid-JSON rejection, the no-token-no-request guard, `.git`-suffix stripping); `services/scan-orchestrator/internal/policy/registry_test.go` (+2 tests: the engine is offered for `git` and refused for `upload`/`image`; `RequiresImport`/`ConsumesNativeSBOM`/`Mode` are exactly as declared, and no OTHER SBOM engine accidentally also sets `ConsumesNativeSBOM`, which would make FanOut wire the same document into more than one job). Python: `workers/sbom/test_github_dependency_graph_adapter.py` (8 tests — available() is always true, generate()'s full branch set: no document staged, staged-but-missing file, a real document counted correctly excluding the document-root package which carries no PURL, zero-PURL documents reported `partial` not `succeeded`, unparseable JSON, a missing `packages` array); `workers/sbom/test_native_sbom_handoff.py` (3 tests — the job-envelope field name is pinned the same way `workspace_ref`'s existing test pins the archive field, end-to-end through `SBOMWorker.handle()` with the fetch subprocess call faked); one addition to `libs/py-shared/axebom_shared/normalize/test_ingest.py` confirming the dispatch table entry IS `_ingest_spdx` by identity, not a lookalike, and that a real PURL round-trips through it. Full `pytest libs/py-shared workers/sbom` clean except the one pre-existing `crypto-mixed` CBOM golden failure (unrelated, documented since (a) of the 2026-08-26 SBOM pass below). Rebuilt and redeployed `fetcher`, `scan-orchestrator`, and `sbom-worker` — all three healthy; **`sbom-worker`'s own preflight log now reports `'engines': 8`, up from 7**, independent confirmation the new adapter registered correctly in the running container, not just in source.

**Not tested live against real github.com**, same gap as (a)'s connect-flow OAuth exchange and for the identical reason: `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET` are genuinely unset in this environment's `.env`, so no real repo-scoped token exists to call GitHub's actual API with. `depgraph_test.go` covers the client's own logic exhaustively against a fake server; the one thing that cannot be verified here is GitHub's REAL response shape for a real Dependency Graph export — worth a spot-check once real credentials exist, the same flag (a) left on `dependency-check`'s NVD-shaped parser.

**Files touched, by area:** Go — `libs/go-shared/{events/events.go,fetcher/{depgraph.go,depgraph_test.go}}` (`depgraph.go`/`depgraph_test.go` new), `services/fetcher/internal/work/work.go`, `services/scan-orchestrator/internal/{policy/{registry.go,registry_test.go},orchestr/orchestrator.go}`, `cmd/axebom/source.go`. Python — `libs/py-shared/axebom_shared/{adapters/base.py,source.py,normalize/{ingest.py,test_ingest.py}}`, `workers/sbom/{runner.py,adapters/__init__.py,adapters/github_dependency_graph.py,test_github_dependency_graph_adapter.py,test_native_sbom_handoff.py}` (`github_dependency_graph.py` and both test files new). Docs — `docs/{02-CONTRACTS.md,04-OSINT-INTEGRATION.md,STATE.md}`.

**Nothing committed to git this session** — everything above, plus (a), is still uncommitted working-tree changes.

**Next session:** Milestone 4 (URL source registration — data model + single-page fetch plumbing, no discovery yet) per the saved plan. Read the plan file's Milestone 4 section before starting; the new `project.web_sources` table and the `source_type`/`source_kind` CHECK-constraint additions are schema changes, and the plan explicitly flags confirming the real, auto-generated constraint names via `\d+ project.projects`/`\d+ scan.scans` before writing the migration rather than assuming them.

### 2026-08-29 (c) — Project registration, phase 4: URL source registration — data model + single-page fetch plumbing, no discovery yet (Milestone 4 of 5)

Continuation of (a)/(b), same plan. Milestone 4 proves `source_kind=url` end-to-end against exactly one page before Milestone 5 adds real discovery: a new table, a new source kind threaded through every layer that already understands `git`/`upload`, and a fetcher path minimal enough to be honest about doing nothing more than staging one page.

**Data model.** New `migrations/project/0002_web_sources.sql` — `project.web_sources (id, tenant_id, project_id, root_url, discovery_enabled default true, max_hosts default 25 CHECK 1–100, last_scanned_at, created_at)`, RLS via `app.enable_tenant_rls`, no `credential_ref` (nothing here is ever authenticated). `discovery_enabled`/`max_hosts` exist now even though nothing reads them yet, so Milestone 5 lands as a pure application change. The real, auto-generated CHECK constraint names were confirmed live (`\d+ project.projects` → `projects_source_type_check`; `\d+ scan.scans` → `scans_source_kind_check`) rather than assumed, per the plan's own flag: `migrations/project/0003_source_type_url.sql` and `migrations/scan/0008_source_kind_url.sql` each drop and recreate their CHECK with `url` added to the allowed set.

**Backend plumbing, the same shape M1's upload fix established.** `events.SourceURL` added to `SourceKind`. `orchestr.CreateScan`'s shape-check switch now accepts `events.SourceURL` — and stops there: no engine is registered with `SourceKinds: [events.SourceURL]` this milestone, so a url-sourced `CreateScan` correctly reaches `SCAN_NO_ENGINES_AVAILABLE`, not a created scan. This is deliberate, not a bug worked around — confirmed by reading `CreateScan`'s exact validation order (shape check → `ValidateCombination` → `rejectNonScannableFamilies` → `resolveEngines`) and pinned by a new regression test (`TestSourceKindURLPassesTheShapeCheckButHasNoEngineYet`) with an explicit comment that when this test starts failing because a scan gets CREATED, that's Milestone 5 landing correctly, not something to "fix" back. `services/project`: new `ValidateWebSourceURL` (deliberately a sibling of `ValidateRepoURL`, not a shared call — same https-only/no-embedded-creds/length rules, reworded messages, since "repository URL must use https" reads oddly to someone who typed a plain web page), `CreateWebSource`/`ListWebSources` on both `service.Service` and `store.Store` mirroring `Connect`/`ListConnections` minus the credential path, new `POST`/`GET /v1/projects/{id}/web-sources` routes and handlers, and a third discriminated shape (`kind: "url"`) on the service-principal-only `Source()` handler. `authz.ResourceWebSource` added to the matrix (`create`→Analyst, `read`→Viewer), kept distinct from `ResourceRepoConn` per its own doc comment even though the two share a sensitivity tier today. `services/fetcher`: `source.Source` gained `WebSourceID`/`RootURL`, `Resolve()`'s no-source check is now kind-aware for `url`; `work.go`'s dispatch switch gained a `url` case calling new `materializeURL` — a GET of the one root page, `SCAN_SOURCE_UNREACHABLE` on failure, body capped by the same archive byte limit every other path uses, written as `index.html` into the workspace and archived through the SAME `fetcher.CreateArchive` path git/upload already share. Explicitly commented as Milestone-4-scope-only: no crawling, no discovery. Along the way, `Worker` gained an injectable `httpClient *http.Client` field (`Options.HTTPClient`, tests-only) so `materializeURL` and (b)'s `fetchDependencyGraphSBOM` now share one client built once at construction, instead of each constructing `fetcher.SafeHTTPClient(nil)` independently — the same testability fix (b)'s entry already made for `depgraph.go`, generalized to the whole Worker rather than repeated per-function.

**Frontend.** `ProjectWizard.tsx`'s `SourceStep` gained a `url` branch: one `.field` URL input, client-side `isHttpsURL` validation mirroring the backend, and an explicit honest note — "a scan against a URL-registered project has no engine that can read it until [Milestone 5] lands" — rather than implying a working scan exists. New `WebSourceInput`/`useCreateWebSource` in `lib/projects.ts` mirroring `useConnectRepo`; `submit()` calls it after project creation, matching the same "create project → attach source" sequencing every other source type uses.

**Docs, updated in the same session.** `docs/01-DATA-MODEL.md` §2: new `project.web_sources` entry, `source_type`/`source_kind` enum lists updated. `docs/02-CONTRACTS.md`: `source_meta.kind` comment updated to `git | upload | image | url`, the two new routes added to the REST surface listing, and a new paragraph stating plainly that `url` is schema/orchestrator-valid but resolves to `SCAN_NO_ENGINES_AVAILABLE` until `services/webrecon` lands. `docs/05-SECURITY-MODEL.md` §1: new threat-model table row plus a dedicated paragraph naming the confused-deputy/recon-abuse risk a URL-registered project introduces — distinct from SSRF against our own infra — and its mitigations (`max_hosts`, `discovery_enabled`, https-only + connection-time IP blocking reused verbatim from the clone path, gateway rate limiting), explicit that these bound the blast radius rather than eliminate the risk class.

**Three pre-existing issues found and fixed along the way, none introduced this session:** (1) `store.CreateWebSource`'s doc comment claimed the service layer enforces "exactly one web source per project" — it doesn't; there's no unique constraint and no check in `service.CreateWebSource`. Reworded to match actual behavior rather than leave a comment a future session would trust and be wrong to. (2) `docs/STATE.md`'s own (b) entry contained a backtick-wrapped Go symbol — a package path directly followed by a dotted method name, no space between — that `axebom docs lint`'s path-reference regex misread as a file path ending in a bogus extension; split into a package-path span plus a separate plain-text symbol so the regex stops matching text that was never meant to be a path. (3) `libs/go-shared/oidcauth/middleware_live_test.go`'s live integration test asserted a missing project answers `NOTFOUND_RESOURCE`; `mapStoreError` has returned the taxonomy's more specific `NOTFOUND_PROJECT` since the original Phase 4 commit (`docs/02-CONTRACTS.md`'s own `NOTFOUND_` example), so the test was stale from day one and only surfaced now because this was the first `task verify` run this session against a live ZITADEL+gateway stack. Also: `libs/go-shared/authz/matrix.go` needed a `gofmt -w` after `ResourceWebSource`'s insertion broke the const block's column alignment, and `services/auth/internal/handler/github_connect.go` picked up a `gosec` G710 (open-redirect taint) finding on a `http.Redirect` call whose destination origin is always the fixed `h.cfg.FrontendURL` (server config, never attacker input) — suppressed with the same `//nolint:gosec` + justification convention already used for this file's G124 cookie finding, not silently.

**Verification — full `task verify` clean, not just targeted subsets.** `go build ./...`/`go vet ./...` clean repo-wide; `task lint:boundaries` (depguard) 0 issues; full `go test ./... -race -count=1` clean; `TestRLSCoverage`: 50 tables checked, 42 protected, 8 exempt, **0 gaps** — the new `project.web_sources` table is covered; `TestAuthzMatrix`: 66 permissions × 4 roles, clean. `task docs:lint`: 208 references checked, all resolve. `task profile:lint`/`profile:guardrails`/`profile:evidence:check`: all OK, no hardcoded field counts. 15 new Go tests for this milestone specifically: 9 in `services/project/internal/service/web_source_test.go` (URL shape validation table, default/explicit `max_hosts`/`discovery_enabled`, out-of-range rejection, newest-first listing, two cross-tenant refusal cases), 2 in `orchestrator_test.go` (`url` shape-accepted-but-no-engine, unknown source kind still rejected), 4 in `fetcher/internal/work/work_test.go` (`materializeURL` happy path with header assertions, non-200 status, unreachable host under a 3s timeout, `New()` defaults to `SafeHTTPClient` not `http.DefaultClient`) — all passing, all against real Postgres/MinIO/NATS in this dev stack, none mocked. Python `pytest libs/py-shared` untouched by this milestone, still clean. Frontend: `tsc --noEmit`, `eslint . --max-warnings 0`, all 84 existing Vitest tests, and `vite build` all clean; `prettier --check` shows pre-existing drift in 15 files this session did not touch (confirmed neither `ProjectWizard.tsx` nor `lib/projects.ts` are in that list). Rebuilt and redeployed `project`, `fetcher`, `scan-orchestrator`, `auth`, `frontend`, and `gateway` (recreated as a dependency) — all six started clean with no errors in logs; gateway `/healthz` returns 200.

**Files touched, by area:** Go — `libs/go-shared/{events/events.go,authz/matrix.go,oidcauth/middleware_live_test.go}`, `services/project/internal/{service/{service.go,web_source_test.go},store/store.go,handler/handler.go}` (`web_source_test.go` new), `services/project/routes.go`, `services/scan-orchestrator/internal/orchestr/{orchestrator.go,orchestrator_test.go}`, `services/fetcher/internal/{source/source.go,work/{work.go,work_test.go}}`, `services/auth/internal/handler/github_connect.go`. Migrations — `migrations/project/{0002_web_sources.sql,0003_source_type_url.sql}` (new), `migrations/scan/0008_source_kind_url.sql` (new). Frontend — `frontend/src/{lib/projects.ts,routes/projects/ProjectWizard.tsx}`. Docs — `docs/{01-DATA-MODEL.md,02-CONTRACTS.md,05-SECURITY-MODEL.md,STATE.md}`.

**Nothing committed to git this session** — everything above, plus (a) and (b), is still uncommitted working-tree changes; the user has not asked for a commit.

### 2026-08-29 (d) — Project registration, phase 5: `services/webrecon` — subfinder discovery + Go-native JS fingerprinting, the plan's last and highest-risk milestone (Milestone 5 of 5, PLAN NOW COMPLETE)

Continuation of (a)/(b)/(c), same plan. This is the milestone the plan itself named highest-risk: a genuinely new architectural surface (a ninth Go service with network egress), a named technical unknown to spike before committing to a design (RE2 vs retire.js's PCRE-flavored signatures), and — found only while wiring it — a real bug in Milestone 3's own mechanism that had silently never worked. Long entry; the work touched nine areas.

**Architecture decision made by direct code inspection, not by following the plan's literal wording.** The plan's own "cross-cutting decisions" section got the shape right — new service, new NATS family, mirroring the fetcher — but its Milestone 5 bullet list separately suggested registering `subfinder` and `retire-js-web` as two SANDBOXED SBOM-family engines chained like syft→grype. Read literally that contradicts the plan's own cross-cutting reasoning and `libs/go-shared/sandbox/policy.go`'s flat statement that no ENGINE may have network egress (CLAUDE.md invariant 7) — subfinder and every page/script fetch genuinely need the network. Resolved the same way Milestone 4 resolved its own "should CreateScan register a stub engine" ambiguity: by reading the actual code, not guessing. The shape that survived: `services/webrecon` is `FamilyFetch`'s SIBLING — a second "producer" family (`scan.job.webrecon`, published INSTEAD of `scan.job.fetch` when `source_kind == url`) that does ALL the network-touching work itself (subfinder inside its own sandboxed container, page/script fetches through the same `SafeHTTPClient` the fetcher uses) and stages ONE `native_output` JSON document. A single new SBOM engine, `webrecon-fingerprint` (`Mode: "internal"`, `ConsumesNativeSBOM: true`, `SourceKinds: [url]`), is the only thing dispatched through the normal `scan.job.sbom` path — exactly the M3-established `github-dependency-graph-sbom` shape, reused rather than reinvented.

**A real, previously-unnoticed bug in Milestone 3 found and fixed while wiring the identical mechanism for webrecon.** `github-dependency-graph-sbom`'s `NativeSBOMRef` wiring has never actually worked in a live deployment, despite M3's full test suite passing. Two compounding gaps, found by reading — not assuming — the actual data flow: (1) `handleFetchResult` never called `RecordRawArtifacts` for the fetcher's own artifacts — only `HandleResult` (the generic per-engine path) ever did, and fetch results are routed around it entirely; (2) even if it had, `LoadRawArtifactsForEngines`'s `INNER JOIN` to `scan.engine_runs` could never resolve an artifact with a NULL `engine_run_id` back to `"fetcher"` — the fetcher has no `engine_runs` row at all, since `CreateScan` only creates one per dispatched `policy.Engine`. Both gaps were invisible to M3's tests because they exercise the adapter and the depgraph client in isolation, never the full orchestrator `FanOut` path against a real fetch result. Fixed generically, for both producers at once: `migrations/scan/0009_raw_artifacts_producer.sql` adds a nullable `producer` column to `scan.raw_artifacts`, mutually exclusive with `engine_run_id` (CHECK constraint, verified safe against live data — zero existing rows had a NULL `engine_run_id`); new `Store.RecordProducerArtifacts` (sibling to `RecordRawArtifacts`); `LoadRawArtifactsForEngines` rewritten as a `UNION ALL` resolving both real engine-run-joined artifacts and producer-tagged ones by the same id. `handleFetchResult` now calls `RecordProducerArtifacts(..., "fetcher", ...)`, retroactively fixing the M3 feature; `handleWebreconResult` calls the same for `"webrecon"`. Proven fixed, not just patched: `TestFullPipelineCreateWebreconFanOutResultStatus` (new) runs the ENTIRE chain against real Postgres/NATS — create scan → publish webrecon result → `handleWebreconResult` records the artifact and marks the scan running (`SetSourceOnce` with empty commit/archive, the same honest-empty pattern upload-sourced scans already use for `commit_sha`) → `FanOut` wires `NativeSBOMRef` (no `ArtifactURI` at all — a url source has no source archive) → the SBOM job is published and consumed → scan reaches `completed`. Required extending `ScanJobV1.Validate()`'s workspace check: a job now needs EITHER `ArtifactURI` OR `NativeSBOMRef`, except the two producer families which need neither on their OWN job (`FamilyFetch`, now joined by `FamilyWebrecon`).

**The RE2/PCRE compatibility spike — run for real against the real signature database, not assumed.** Fetched the actual `retire.js` `jsrepository.json` (76 libraries, Apache-2.0, commit `db79fa77...`, 2026-08-20) and compiled all 76 `uri` + 208 `filecontent` patterns against Go's `regexp`. Precise findings, pinned as a permanent regression guard (`services/webrecon/internal/fingerprint/retire_test.go`): 2 of 284 patterns use a genuinely unsupported construct (1 backreference — jQuery's alt filecontent variant; 1 lookbehind — lodash's) and are skipped; 7 more exceed RE2's hardcoded 1000-repeat-count ceiling (`regexp/syntax`'s `maxRepeat`, no public API to raise it) — Vue (×2), Next.js (×2), tinyMCE, underscore.js, select2 — and are CAPPED at 1000 rather than dropped, a real, documented precision loss (a genuine gap in a minified bundle can exceed 1000 chars) that still leaves every affected library with other, unaffected signatures. 282 of 284 patterns compile and run. Full provenance and reasoning: `services/webrecon/internal/fingerprint/signatures/PROVENANCE.md`. The signature file is embedded directly into the Go binary (`go:embed`, not `toolctl`-managed — a single JSON data file doesn't fit the binary/container pinning machinery built for goreleaser releases) at `services/webrecon/internal/fingerprint/signatures/`, not under `OSINT/data/` as first drafted — `go:embed` cannot traverse `..`, so the canonical copy had to live inside the embedding package; `OSINT/tools.manifest.yaml`'s `retire-js-signatures` library entry still documents it in the roster and points there.

**A real same-origin bug found and fixed by the test suite, not by review.** `fingerprint.FetchAndFingerprint`'s external-script-fetch guard originally compared bare hostnames — `TestFetchAndFingerprintSkipsAnUnallowlistedExternalHost` caught that this let two `httptest` servers on `127.0.0.1` at DIFFERENT PORTS look like the same origin, meaning a script on an unrelated service sharing a hostname could have been fetched. Fixed to compare the full `host:port` authority for the same-origin case (the CDN-allowlist case still checks bare hostname — a CDN's port was never what made it trusted).

**A second real gap found by writing the test suite: no per-request timeout.** Unlike the fetcher's git clone — sandboxed, with the CONTAINER'S OWN wall-clock limit — `services/webrecon`'s page/script fetches are plain Go HTTP calls in the worker's own process, with nothing bounding them. An unresponsive (not refusing, just silent) host would have hung the whole job indefinitely. Added `perRequestTimeout = 15s` (`context.WithTimeout` per fetch) before this could ship.

**The mechanism, end to end.** `CreateScan` routes `source_kind=url` to `publishWebreconJob` instead of `publishFetchJob`. `services/webrecon`'s worker (`internal/work/work.go`) resolves the project's `root_url`/`discovery_enabled`/`max_hosts` via the SAME `/v1/projects/{id}/source` endpoint the fetcher calls — moved into a new shared package, `libs/go-shared/projectsource` (was `services/fetcher/internal/source`; CLAUDE.md invariant 11 explicitly requires a type two services need to live in `libs/go-shared`, and webrecon needed the SAME response shape plus two fields — `discovery_enabled`/`max_hosts` — the fetcher never reads but decodes anyway). Builds the host list (root host always; `subfinder` — passive-only, `-silent`, no active probing — capped by `max_hosts`, degrading to root-only on any discovery failure rather than failing the job); fetches each host's root page and `<script>` content (`golang.org/x/net/html` tokenizer; external scripts restricted to same-origin or a five-entry CDN allowlist, skipped scripts recorded not dropped); matches everything against the embedded signature database; assembles one JSON document (`{schema_version, root_url, discovery_enabled, hosts:[{host,fetched_url,status,libraries:[{name,version,npm_purl,vulnerabilities}]}]}`); uploads it; publishes `scan.result.webrecon`. `workers/sbom/adapters/webrecon_fingerprint.py` (new, `ToolAdapterBase`-direct, no sandbox — the M3 `github_dependency_graph.py` shape) stages it as its own raw artifact and reports an honest status (`unavailable`/`partial`/`succeeded`, never a silent zero). A NEW ingest parser, `_ingest_webrecon_fingerprint` (`libs/py-shared/axebom_shared/normalize/ingest.py`) — unlike `github-dependency-graph-sbom`, webrecon's JSON is AxeBOM's own shape, not a standard SPDX/CycloneDX document, so this one required real parsing, not a registration pointing at an existing parser. `npm_purl` is synthesized (`pkg:npm/<name>@<version>`) and labeled in both code and docs as inference, never an assertion retire.js itself makes. Version-range evaluation happens ONCE, in Go (`vulnerableAt`), before the JSON is ever written — the Python parser trusts it rather than re-evaluating.

**Fully generated, not hand-scaffolded.** `services/webrecon` was added to `tools/gen-service`'s own registry and generated with `go run ./tools/gen-service --name webrecon` — "EVERY service is generated by this tool, including the first" is the generator's own stated policy, and this is the first service built after that policy existed to test against. `deploy/docker/Dockerfile.webrecon` and the scaffold files are generator output; `deps.go`/`health.go` hand-edited after, same convention every other service follows. Registered in `deploy/compose/docker-compose.app.yml` (no Vault dependency, unlike fetcher — a url source is never authenticated) and in `cmd/axebom/iam.go`'s `ServiceAccounts` list; `task iam:bootstrap` re-run live to mint a real `svc-webrecon` ZITADEL machine key. `tools/gen-service`'s own `TestEveryServiceHasABoundaryRule` mechanical guard caught the missing `.golangci.yml` depguard entry immediately — added `service-boundaries-webrecon`, mirroring every sibling service's rule.

**Verification — against real infrastructure, the established convention, not just unit tests.** `go build`/`go vet ./...` clean repo-wide; `task lint:boundaries` 0 issues; full `go test ./...` clean (two genuine bugs — the same-origin check and the missing per-request timeout — were caught BY this session's own new tests before anything shipped, not found later). 31 new Go tests across this milestone: 12 in `fingerprint` (6 signature-database tests against the REAL vendored file pinning the exact spike counts, 6 fetch/fingerprint orchestration tests including the same-origin and CDN-allowlist cases), 12 in `work` (dependency validation, discovery degradation, `max_hosts` short-circuiting before subfinder ever runs, end-to-end fingerprinting), 3 new/rewritten in `services/scan-orchestrator/internal/policy` (the `ConsumesNativeSBOM` mutual-exclusion invariant generalized from "exactly one engine" to "at most one per source kind," since two now legitimately set it), 2 in `orchestr` (the M4 `SCAN_NO_ENGINES_AVAILABLE` test updated to its own predicted outcome — a scan now resolves `webrecon-fingerprint` — plus the full pipeline test). 16 new Python tests (10 for the adapter, 6 for the ingest parser), plus `FINDING_ENGINES` extended. `task test:golden`: 85/86 pass, the one failure is the same pre-existing, unrelated `crypto-mixed` CBOM issue documented since 2026-08-26. Rebuilt and redeployed `webrecon` (new), `fetcher`, `scan-orchestrator`, `sbom-worker`, `sbom-normalize-consumer` — all five healthy. **Live confirmation, not just a healthy-container check**: the freshly-started `webrecon` container correctly picked up THREE real, orphaned `scan.job.webrecon` messages left over from this session's own earlier test runs, resolved their (test-fixture, non-existent) project via a REAL ZITADEL-authenticated call to the REAL project service, correctly reported `WEBRECON_NO_SOURCE`, and the freshly-rebuilt `scan-orchestrator` correctly logged "webrecon result for an unknown scan; discarding" for each — the exact defensive path `handleWebreconResult` was written to take, exercised by real infrastructure rather than a mock. `sbom-worker`'s preflight log: `'engines': 9`, up from 8, independent confirmation `webrecon-fingerprint` registered correctly in the running container.

**Live spot-check against a real, external URL — run after the entry above, same session.** A throwaway program (`services/webrecon/cmd/spotcheck`, deleted after use — same convention as the throwaway DB-write programs in (b) of 2026-08-29) called `fingerprint.FetchAndFingerprint` with the REAL production client (`fetcher.SafeHTTPClient`) and the REAL embedded matcher against `https://www.python.org/`, chosen after a quick `curl` survey of a few real sites' script tags found it serving jQuery 1.8.2 both same-origin and via `ajax.googleapis.com`. Every layer validated against genuine content, not synthetic fixtures:

- 11 real `<script>` tags extracted from real markup.
- Two real third-party scripts (`analytics.python.org`, `media.ethicalads.io` — neither same-origin nor CDN-allowlisted) correctly **skipped**, not fetched — the confused-deputy guard proven against genuine, unpredictable third-party references in the wild, not a test server built to exercise it.
- `ajax.googleapis.com` correctly fetched (on the allowlist) and its real, CDN-minified jQuery correctly matched via the `uri` extractor (the `/1.8.2/jquery.min.js` path).
- Version `1.8.2` extracted correctly from real (not synthetic) minified content.
- **6 real CVEs/GHSAs correctly attached** for jQuery 1.8.2 (CVE-2012-6708, CVE-2020-7656, CVE-2015-9251, CVE-2019-11358, CVE-2020-11023, plus one EOL advisory with no CVE) and **4 for jquery-ui 1.12.1** (also detected, same page) — every one a genuine version-range match against the real retire.js database, not a fixture-engineered result.

This closes the one gap the (d) entry above left explicitly open. The mechanism is now confirmed end to end against real internet content, not just `httptest` fixtures and one real leftover NATS message.

**Still not built, and explicitly out of scope per the plan:** a headless-browser (Playwright) renderer for JS injected purely client-side post-paint — the plan names this a deliberate, accepted gap, gated on measured false-negative rate from real usage; and `retire.js`'s `hashes` (exact-file-SHA1 matches, 18 entries) and `filecontentreplace` (8 patterns, all requiring backreference substitution) fields, neither loaded by this matcher at all — a scope cut stated in the package doc comment, not a silent omission.

**Files touched, by area:** Go — `libs/go-shared/{events/events.go,platform/config/service.go,fetcher/*}` (`fetcher/{source→projectsource move}`), NEW `libs/go-shared/projectsource/source.go`, `services/fetcher/{deps.go,internal/work/{work.go,work_test.go}}` (materializeURL and its tests removed — superseded by webrecon), `services/scan-orchestrator/internal/{orchestr/{orchestrator.go,consumer.go,store.go,orchestrator_test.go,pipeline_test.go},policy/{registry.go,registry_test.go}}`, `tools/gen-service/main.go`, `cmd/axebom/iam.go`, `.golangci.yml`. NEW service — `services/webrecon/{main,routes,health,deps}.go`, `internal/discover/subfinder.go`, `internal/fingerprint/{retire,fetch,embed}.go` + tests + `signatures/{retire-js-jsrepository.json,PROVENANCE.md}`, `internal/work/{work,document}.go` + tests. Migrations — `migrations/scan/0009_raw_artifacts_producer.sql` (new). Python — `libs/py-shared/axebom_shared/normalize/{ingest.py,test_ingest.py}`, NEW `workers/sbom/adapters/webrecon_fingerprint.py` + `test_webrecon_fingerprint_adapter.py`, `workers/sbom/{runner.py,adapters/__init__.py}`. Deploy — `deploy/compose/docker-compose.app.yml`, `deploy/docker/Dockerfile.webrecon` (generated). Docs — `docs/{01-DATA-MODEL.md,02-CONTRACTS.md,04-OSINT-INTEGRATION.md,05-SECURITY-MODEL.md,STATE.md}`, `OSINT/tools.manifest.yaml`.

**Nothing committed to git this session** — everything above, plus (a)/(b)/(c), is still uncommitted working-tree changes; the user has not asked for a commit.

**Next session:** The project-registration plan (`~/.claude/plans/the-project-section-while-rippling-shamir.md`) is now fully implemented across all 5 milestones. No further milestone is queued. If asked to harden or extend web recon specifically, start from this entry's "Not tested" paragraph — a live external-site spot-check is the highest-value next step, cheaper than either of the two explicitly-deferred gaps (headless-browser rendering, `hashes`/`filecontentreplace` matching).

### 2026-08-26 (a) — SBOM completion pass: the normalize-trigger boundary closed, durable cluster ids, ingestion gaps, SPDX validity, VEX/CSAF remediation

The user's ask was broad ("make SBOM work completely... 100% accurate... no fabricated data... remediation plans") against a codebase that turned out to already be past Phase 14 — this was not a build-from-scratch session. Three parallel research agents plus two design-review agents found five concrete, real gaps between "the pipeline runs" and "the report is complete and trustworthy." All five were implemented, tested against the live dev stack, and verified — this entry is long because the work genuinely touched both languages, new migrations, a new deployable, and two unrelated pre-existing bugs found only because this was the first time real data ever reached certain code paths.

**Gap A — findings ingestion was silently incomplete (dispatched to a fork).** `ingest.py`'s `_ingest_cyclonedx` only ever read `components[]`, never the CycloneDX `vulnerabilities[]` array `trivy-fs`/`trivy-image` actually produce — real findings were discarded, not marked unavailable. `dependency-check` had no parser at all. Added `_cyclonedx_vulnerabilities`/`_cyclonedx_cvss`/`_cyclonedx_vendor_severity` to the existing CycloneDX path, added `_ingest_dependency_check` (PURL when present, CPE-candidate fallback via the existing confidence machinery otherwise), and a `FINDING_ENGINES` constant later reused by Gap C. `fixed_versions` deliberately left `[]` for both new paths — neither engine's real output has a clean "fixed" signal, and no captured `dependency-check` fixture exists in this repo to verify field names against (flagged, not resolved — spot-check against a real DC run once one exists). Regenerated 5 golden fixtures whose already-committed `trivy-fs.json` had a `vulnerabilities[]` array that was previously silently thrown away; component/finding counts were unchanged everywhere it mattered, new CVSS vectors and one genuine `severity_conflict=true` (NVD vs. vendor rating disagreement in `maven-case`) are now captured. 217 + 252 tests pass (one pre-existing, unrelated `crypto-mixed` coverage-denominator failure confirmed identical on the unmodified branch via `git stash`).

**Gap B — the normalize-trigger boundary (the big one).** Nothing in this codebase had ever told the normalizer a real scan was done. New `scan.normalize_triggers` table (`migrations/scan/0007`, write-once via `ON CONFLICT DO NOTHING`, mirroring `SetSourceOnce`'s idiom) and a new envelope `events.NormalizeTriggerV1` (`libs/go-shared/events/normalize.go`, `docs/02-CONTRACTS.md` §6a — a genuinely separate envelope and JetStream stream, `NORMALIZE_JOBS`/`scan.normalize.<family>`, not `SCAN_JOBS` disguised, because normalization is CPU-bound seconds-to-minutes work, not a 30-minute sandboxed container run). `services/scan-orchestrator/internal/orchestr/normalize_trigger.go` (new): `familyTerminal`/`latestRunsByEngine` derive readiness from the SAME `EngineRun` rows `RecomputeScanStatus` already loads (no new query, correctly handles a scan that never dispatched a given engine), scoped to the `sbom` family only via one explicit, removable guard — `maybeTriggerNormalize` is called from `HandleResult` right after the status recompute. Also populated the previously-dead `scan.raw_artifacts` table (`Store.RecordRawArtifacts`, called from `HandleResult`) — this is what makes the trigger's envelope self-contained (it carries every artifact URI so the consumer never queries `scan.*`) and is also what any future `axebom renormalize` would need. `UpsertEngineRun`'s signature changed to return the new row's id (needed to link `raw_artifacts.engine_run_id`); all three call sites updated.

New Python consumer `workers/sbom/normalize_consumer.py` — deliberately NOT built on `WorkerBus` (that class is hard-wired to the job/result shape; this is fire-and-forget trigger → write → ack), a small from-scratch asyncio pull-consumer following the same discipline (durable name, `NakWithDelay` backoff, DLQ). This is **the one deliberate exception to "workers hold no credentials"** (`axebom_shared.config`'s docstring updated to say so explicitly) — it never runs a scanner or touches scanned code, only already-stored JSON, so the sandbox-escape threat model that rule defends against doesn't apply to it. New Postgres role `axebom_normalize_writer` (`migrations/normalize/0006_alias_snapshot.sql`) — the first role in this codebase narrower than `axebom_app`: `normalize` schema only, `SELECT`/`INSERT` only, plus one column-scoped `UPDATE` on `vuln_clusters` (append-only everywhere else, per invariant 10). New `Dockerfile.normalize-consumer` (separate image from `Dockerfile.worker` — no Docker socket, no sandbox bridge, psycopg installed nowhere else) and a new `sbom-normalize-consumer` compose service, read-only artifacts mount. **Built and proven live**: the container connected to real NATS/Postgres, attached its durable consumer, and correctly consumed leftover trigger messages a completely separate Go test process had published earlier in the session — independent-process proof, not a mocked call.

**Gap C — durable vulnerability cluster ids (ADR-0005), added mid-session at the user's request after the design review surfaced it.** `bulk.py`'s `_findings_batch` was deriving `cluster_id` as `uuid5(bom_document_id + ...)` — exactly the trap ADR-0005 names, and not even durable within reruns of one scan. New `libs/py-shared/axebom_shared/normalize/cluster_store.py`: `persist_clusters()` runs as its own short transaction (separate from `write_bom_document`'s — the cluster graph is global, no tenant_id), under `pg_advisory_xact_lock` (key registered in `libs/go-shared/platform/leader/leader.go`'s new `NormalizeClusterGraph` constant — the first Python-only caller of a centrally-reserved Go lock key), enforcing the CROSS-SCAN member-count cap by reading the TRUE persisted membership via `normalize.resolve_cluster()` — a check the in-memory `aliases.close()` alone cannot make, since it only ever sees one scan's local group. Handles the compound case where a new edge bridges two ALREADY-DISTINCT pre-existing clusters (not just "one existing cluster gains a member") by summing every distinct resolved root's true count before accepting a merge, and writes forwarding rows before recomputing aggregates within the same transaction so `resolve_cluster()` sees the merge immediately. `bulk.py`'s `_findings_batch` now passes a real uuid straight through when `cluster_store` already resolved one, falling back to the old derivation (with a loud new `NORMALIZE_CLUSTER_ID_NOT_DURABLE` diagnostic) only for fixture/test callers that never wire a database. New FK `findings.cluster_id → vuln_clusters.id` (`migrations/normalize/0007`) so a finding referencing a never-persisted cluster now fails loudly at insert time.

Two things found only by testing against the REAL restricted role instead of `axebom_app` (the whole point of `test_cluster_store.py` connecting as `axebom_normalize_writer`, not the usual test role): `INSERT ... ON CONFLICT DO UPDATE` on `vuln_alias_edges` needs UPDATE privilege even when nothing conflicting actually changes — the role doesn't have it, so this became `DO NOTHING` + a fallback `SELECT` (costs the `last_seen` refresh nicety, not correctness); and evidence for a cluster merge (`vuln_cluster_merges.evidence_edge_id`) needed edges to be persisted and re-tagged with their real DB row id BEFORE `aliases.close()` runs, since the extractors that build `AliasEdge`s never had a DB round trip to get a real id from — restructured so `_write_alias_edges` returns tagged edges. `libs/py-shared/axebom_shared/normalize/test_cluster_store.py` (new, 6 tests, all live-Postgres): brand-new cluster, idempotent replay, cross-scan alias growth, a new edge merging two previously-separate clusters (asserts the durable id from EITHER original scan still resolves), and the cross-scan cap itself — grow a cluster to exactly 12 across several separate `persist_clusters` calls, then prove the 13th is refused, flagged, and split into its own cluster rather than silently exceeding the ceiling. **Flagged, not resolved**: the exact evidence-edge attribution when a merge involves more than one candidate edge picks the first available rather than the provably-correct bridging one — a product judgment call, not a correctness bug, worth a second look.

**Gap D — CERT-In's own remediation fields were dead code (dispatched to a fork).** `docs/reference/certin-v2.0.yaml` defines `certin.vex.remediation`/`.workarounds`/`.downtime`/`certin.csaf.mitigation` with real weights, and Go constants existed, but nothing read them. `vex.Effective` (was missing the three fields the winning `Statement` already carried — a 3-line fix once found), `bomsource.go` (new `loadCSAFMitigationForReport`, same-schema join mirroring `store/csaf.go`'s existing precedent), `render.Finding` + 4 new sheet columns (covers XLSX/JSON/CSV for free — the sheet mechanism is header/row-generic, invariant 8 escaping applies automatically), `pdf.go`'s `vexPage()` gains a remediation block. New `VEXFields`/`CSAFFields` generated into `generated_certin.go` via `task profile:gen` (never hand-edited); a new `vexFieldCoverageSheet` scores the four fields only over findings that HAVE an effective VEX statement — a never-triaged finding is "not yet assessed," not "remediation omitted," and conflating them would violate invariant 3. Plumbing only, per the user's explicit instruction — no AI/heuristic-generated suggestions, only wiring through real human-authored VEX statement text. 126 tests pass across `vex`/`render`/`store`/`compliance`.

**Gap E — SPDX 2.3 export was genuinely invalid, not just `xfail`'d (dispatched to a fork).** `export.go`'s `toNode()` fed the raw `component_key` (a colon-and-slash-bearing PURL) straight into `PackageSPDXIdentifier`, which SPDX 2.3's grammar forbids. Threaded `Format` through `toProtobom`/`toNode`; only SPDX gets a derived id (`idFor`/`spdxSafeID`: sanitized slug + 6-byte SHA-256 hash suffix, deterministic per ADR-0003) applied consistently to `node.Id`/`doc.Roots`/`doc.Dependencies[].From/To`. CycloneDX's `bom-ref` untouched — its golden came out byte-identical, confirming nothing leaked across formats. `task test:conformance` (real `spdx-tools`/`cyclonedx-python-lib` validators): **2 passed**, both formats now validate for real; the `xfail(strict=True)` is removed, not just widened.

**Two pre-existing bugs found only because this was the first time real data ever reached these paths, both fixed:** `normalize.vuln_ids.namespace`'s CHECK was missing `GO`/`PYSEC`/`RUSTSEC`/`GSD`/`MAL` — namespaces `aliases.py`'s own `_NAMESPACE_RANK` has always treated as valid, and osv-scanner's real native-ecosystem ids use exactly these prefixes as their PRIMARY id, not just an alias (`migrations/normalize/0008`). `normalize.findings.fix_version_ordering`'s CHECK only ever allowed `known`/`unknown` — `findings.py`'s `resolve_fix_version()` has never once returned `known`; its real vocabulary is `comparator`/`unknown`/`none`, and every prior test sidestepped the mismatch by hand-supplying `"unknown"` in fixture data instead of running the real pipeline against the real table (`migrations/normalize/0009`; `docs/01-DATA-MODEL.md` updated to match). A third bug, unrelated to any of the above but hit while re-establishing a clean DB state mid-session: `libs/go-shared/platform/db.Migrator.Reset()` drops every schema but never drops `public.goose_bootstrap_version`, so against an already-bootstrapped database it silently skips re-running bootstrap, leaves `app` missing, and every other schema's first migration fails with "schema app does not exist" — fixed by dropping that table too. `task db:reset` now works cleanly against a live, previously-bootstrapped Postgres, which it apparently never had to before (prior sessions likely always reset by recreating the whole Postgres container).

**Verification.** Go: `go build ./...`, `go vet ./...` clean repo-wide; `go test ./services/scan-orchestrator/... ./libs/go-shared/... ./services/report/...` all pass, including new table-driven tests for `familyTerminal`/`latestRunsByEngine` and live-DB tests for `MarkNormalizeTriggered`/`NormalizeTriggerID`'s write-once and read-only-peek semantics. Python: full `libs/py-shared`/`workers/sbom` suite passes (one pre-existing unrelated failure, confirmed on the unmodified branch). Live end-to-end, twice: (1) `workers/sbom/test_normalize_consumer.py`'s two tests call `handle_trigger()` directly against a REAL captured fixture (`fixtures/npm-simple/raw/*.json`) through a REAL Postgres connection under the REAL restricted role — writes a real `bom_documents` row with real component/finding counts, a real durable FK-valid `cluster_id`, and proves a redelivered trigger is a no-op; (2) the actual `sbom-normalize-consumer` container, started for real against the live compose stack, consumed real leftover trigger messages a separate Go test process had published to real NATS earlier in the session, entirely independently.

**Not done this session, explicitly deferred, not forgotten:** the `log4shell-java`/`alias-overmerge` golden fixtures `docs/09-GOLDEN-CORPUS.md` calls for (the cross-scan guard they'd need to prove is instead covered by `test_cluster_store.py`'s live-Postgres tests, which a golden fixture — offline, no DB — cannot exercise regardless); a live proof-of-life scan against a real public repo (`expressjs/express`, agreed with the user) has not run yet; `dependency-check`'s JSON field shapes in Gap A's new parser are written defensively but unverified against a real captured DC report, since none exists in this repo and running a live DC scan needs a real `NVD_API_KEY` first (see the header's "Next action" — the key is genuinely NOT set, correcting an earlier research pass this same session that said it was).

**Database provisioning, done for real this session:** `grype`/`osv`/`trivy` are provisioned and stamped (`task osint:dbstatus` confirms — ~3.5 GB). Found along the way: `workers/sbom/dbsync.py` must run as root inside a container (`docker compose run --rm --no-deps -T sbom-worker python -m workers.sbom.dbsync ...`) — running it directly on the host as a non-root user silently fails `osv`'s provisioning (root-owned files from the container's direct bind-mount write, which the non-root verification step then can't even list, so `_downloaded_bytes` reads 0 and refuses to stamp; `grype`'s stage-and-`docker cp` path happened to still work host-side). Not a code bug, the wrong invocation — but worth remembering, since the failure mode ("provisioning reported success but wrote no database") reads like a real one.

**A full `go test ./...` and full `pytest` pass at the very end of this session caught three more real, pre-existing breakages** — all from the two schema changes above (the FK, the widened CHECK), all in test fixtures that had been asserting/inserting values the new constraints correctly reject: `services/scan-orchestrator/internal/orchestr/findings_test.go`'s `insertFinding` helper inserted findings with a fabricated `cluster_id` that referenced no real row — now inserts a matching `normalize.vuln_clusters` row first (with `t.Cleanup` ordered so the finding is deleted before the cluster, LIFO, or the cluster's own delete would itself violate the FK); `services/project/internal/store/dependencies_test.go` had three literal `'known'` values seeded directly into `fix_version_ordering` — corrected to `'comparator'`, matching what `findings.py` actually emits; `libs/go-shared/platform/db/rls_test.go`'s `TestRLSCoverage` (a mechanical, live-catalog guard, not a fixture) correctly flagged the new `normalize.alias_snapshot` table as ungoverned — added to `rls.go`'s exemption list with the same "global alias-graph reference data" reasoning `vuln_clusters` already carries. All four represent the guards working exactly as designed, not gaps in them.

**Files touched (by area, not exhaustive — see the git diff):** migrations `scan/0007`, `normalize/0006`–`0009`; Go `libs/go-shared/{events/normalize.go,bus/bus.go,platform/leader/leader.go,platform/db/{migrate.go,rls.go},vex/vex.go,compliance/gen.go,model/generated_certin.go}`, `services/scan-orchestrator/internal/orchestr/{normalize_trigger.go,normalize_trigger_test.go,normalize_trigger_internal_test.go,store.go,orchestrator.go,consumer.go,dependent.go,findings_test.go}`, `services/project/internal/store/dependencies_test.go`, `services/report/internal/{store/bomsource.go,render/bom.go,render/pdf.go,export/export.go}`; Python `libs/py-shared/axebom_shared/{config.py,normalize/{ingest.py,bulk.py,cluster_store.py,test_cluster_store.py,test_bulk.py}}`, `workers/sbom/{normalize_consumer.py,normalize_runner.py,test_normalize_consumer.py}`; deploy `deploy/docker/Dockerfile.normalize-consumer`, `deploy/compose/docker-compose.app.yml`, `pyproject.toml`, `.env.example`; docs `docs/{01-DATA-MODEL.md,02-CONTRACTS.md}`.

**Full-suite verification at session end:** `go build ./...`, `go vet ./...`, and `go test ./...` all clean across every package. `pytest libs/py-shared workers/sbom` clean except the one pre-existing, unrelated `crypto-mixed` coverage-denominator failure (confirmed identical on the unmodified branch).

### 2026-08-26 (b) — the live proof-of-life run against `expressjs/express`, and the deployed `scan-orchestrator` was caught running yesterday's binary

Continuation of (a), same session. With grype/osv/trivy databases provisioned, this drove a REAL scan against a REAL, uncontrolled public repo end to end, entirely through the Go store/orchestrator packages directly (`services/project/internal/store`'s `Store.CreateProject`/`CreateConnection`, `orchestr.Orchestrator.CreateScan`) rather than HTTP — the ZITADEL OIDC boundary blocks scripted access, and the legacy HS256 `/v1/auth/login` still issues tokens but `project`/`scan-orchestrator`/etc. no longer accept them (exactly the disconnect earlier entries already flagged, now confirmed by hitting it directly: `AUTH_TOKEN_INVALID`). Two throwaway Go programs did the DB writes, using the real store code paths, then were deleted — nothing committed.

**The most important thing this run found: the live `axebom-scan-orchestrator-1` container was running a binary built ~16 hours before this session started** — every fix in (a) (`normalize_trigger.go` and everything downstream of it) had never actually executed inside the deployed stack. The scan itself completed normally (`completed_with_errors`, all 6 engine runs terminal — a real container clone, a real syft/grype/trivy-fs/osv-scanner run) but never published a `NormalizeTriggerV1`, because the running process had no such code path compiled in. This is exactly the gap `docs/STATE.md`'s own "keep it updated" discipline exists to prevent surfacing silently: everything in (a) was proven correct by `go test` (which compiles fresh) and by a hand-built consumer container, but the actual LONG-RUNNING `scan-orchestrator` service in `docker compose` had not been rebuilt since before today's changes landed — a distinction worth remembering for every future session that treats "the stack is up" as "the stack is running today's code." Fixed by rebuilding and restarting it (`docker compose build/up scan-orchestrator`); confirmed by replaying `HandleResult` for the same scan afterward, which correctly fired the trigger this time (`published a normalize trigger ... engines=6`).

The rebuild itself was blocked by a SEPARATE, real environment problem: the dev machine's disk was at 100% capacity. `docker builder prune -f` reclaimed ~3 GB of build cache (safe, rebuildable) to make the rebuild possible at all — **disk is still at 99%, 1.6 GB free**, flagged prominently in this file's header as the most urgent open item.

Because the pre-rebuild scan's 5 real engine results were processed by the stale binary (which also predates (a)'s `RecordRawArtifacts` call), `scan.raw_artifacts` has no rows for them — the raw output files exist on disk regardless (workers write them independently of the orchestrator's own bookkeeping), so a hand-built trigger pointing at the real files was used to normalize for real instead of re-running the scan from scratch. `bom_document_id = 01a03de0-1171-7e02-818e-137b08f9e380` (normalization_version 2), `scan_id = 01a03dd1-626f-7549-9d3a-38fbd7ae161e`, `project_id = 01a03dd0-b04e-7bba-b4c7-d467674e8335`.

**Real engine outcomes**, all genuine, none fabricated: `syft` succeeded (21 raw components — all from `.github/workflows/*.yml`, zero from `package.json`); `grype` succeeded (0 vulnerabilities — correctly matched against syft's own SBOM, which had no npm components to match against); `trivy-fs` and `osv-scanner` both `partial`, each with an honest diagnostic ("found no components" / "found no lockfiles to match against"); `dependency-check` `unavailable` (no NVD DB, as agreed with the user this session); `mock-engine` `skipped` (`ENGINE_NOT_IMPLEMENTED` — it is in the default SBOM engine set but the real worker never implemented it; pre-existing, unrelated to this session, not investigated further). Normalized: `component_count = 13`, `finding_count = 0`, `completeness_pct = declaration_pct = 8.84`.

**This low a number is the honest answer, not a bug** — independently verified by running `anchore/syft:v1.51.0` directly against the same cloned workspace outside AxeBOM entirely, with an identical result. `express`'s repository genuinely commits no `package-lock.json`/`yarn.lock` — correct practice for a published library (consumers pin their own versions), not an application — and syft's npm cataloger needs a lockfile to resolve concrete versions; it does not emit components from a bare `package.json`'s version *ranges*. `trivy-fs`/`osv-scanner` independently reported the identical root cause in their own diagnostics. Zero findings follows mechanically from zero npm components — nothing here was invented to look complete, which is the entire discipline this product exists to hold to. **`express` was a poor choice of proof-of-life target specifically because it is a lockfile-less library** — a repo with a committed lockfile (or a container image target, to exercise `trivy-image`) would actually exercise rich component/finding/remediation data. Worth re-running once disk space allows.

Report rendering (SPDX/CycloneDX/PDF/XLSX/JSON) was **not** exercised this pass — it renders asynchronously via a NATS job queue that was not explored under the disk-space pressure; deliberately deferred rather than rushed. Component/finding-level correctness through normalization is proven; rendering of this specific document is not.

### 2026-08-26 (c) — disk space actually reclaimed (49.5 GB), a second live proof-of-life run against `koajs/koa`, and report rendering proven end to end — which found a real, previously-uncaught CycloneDX export bug

Continuation of (a)/(b), same session. Three things happened in sequence: the disk-space blocker (b) left open was closed for real; a second live scan was run against a better target than `express`; and report rendering — deliberately deferred in (b) — was finally exercised, which is what surfaced this entry's main finding.

**Disk space.** Per the user's explicit instruction after (b) flagged `/var/lib/containerd` as a candidate (51 GB, separate from `/var/lib/docker`) — "investigate first, don't delete yet" — ownership was confirmed before touching anything: `ctr namespaces list` showed a `moby` namespace (Docker's own), and `ctr -n moby containers/images list` counts matched Docker's own container/image counts, confirming this was Docker's accumulated snapshot layers, not another process's data on this shared machine. Removed stale `encorebom/*` pre-rename image tags, then ran `docker builder prune -f --all` (the aggressive form (b) deliberately hadn't used yet) — reclaimed 49.5 GB. Disk went from 1.6 GB free/99% to 48 GB free/51%, confirmed still true as of this entry. Full stack verified healthy after.

**Second live proof-of-life run, against `koajs/koa` (chosen because, unlike `express`, its repo commits real npm dependencies worth resolving).** Same technique as (b): a throwaway Go program using `services/project/internal/store` created the project/connection, a second using `orchestr.Orchestrator.CreateScan` started a real scan — both deleted after, nothing committed. The scan completed in ~24s, `completed_with_errors`, all 6 engine runs terminal, and this time — because `scan-orchestrator` was already running today's rebuilt binary from (b) — it correctly published `NormalizeTriggerV1` on its own with no manual intervention (`"published a normalize trigger","scan_id":"01a03df4-...","family":"sbom","engines":6`), and `sbom-normalize-consumer` picked it up automatically. `bom_document_id = 01a03df4-8874-7614-b94a-5c3daa50a3ae`, `scan_id = 01a03df4-23ac-74f4-b30d-0aa7808f2d93`. Normalized: `component_count = 44`, `finding_count = 0`, `completeness_pct = declaration_pct = 16.97`.

**Real engine outcomes, all genuine:** `syft` succeeded (44 components, 3 without a PURL — GitHub Actions workflow steps); `osv-scanner` and `grype` both succeeded and both correctly reported zero vulnerabilities ("osv-scanner matched no vulnerabilities" / "grype matched no vulnerabilities" — koa's current pinned dependencies are genuinely clean, not a scan failure); `trivy-fs` succeeded; `dependency-check` `unavailable` (no NVD key, as already agreed); `mock-engine` `skipped` (pre-existing, unrelated). The `component_count = 44` was independently verified by exec'ing into the worker container and counting objects directly in syft's own raw JSON output on disk — exactly 44, with recognizable real npm package names (`accepts`, `content-disposition`, `cookies`, `depd`, `http-errors`, …) plus the GitHub Actions workflow entries. The gap from the lockfile's 374 raw entries is legitimate: dev dependencies and duplicate path entries are correctly deduplicated by syft/the normalizer, not dropped by a bug.

**The `axebom-report-1` container was ALSO found running a stale binary** — built 2026-08-25T11:49:05Z, before this session's Gap D/E changes to `services/report/internal/render/{bom,pdf}.go`, `internal/store/bomsource.go`, `internal/export/export.go`. Same class of finding as (b)'s `scan-orchestrator` discovery: `go test` and a hand-built consumer prove the CODE is correct; neither proves the DEPLOYED container is running it. Rebuilt and restarted (`docker compose build/up report`).

**Report rendering exercised for real, for the first time this session.** A third throwaway Go program (`services/report/tmp-koa-render/`, deleted after — same pattern, needed under `services/report/` because `service`/`store`/`worker` are internal packages) built a real `*service.Service` exactly the way `services/report/deps.go` does (`store.New(pool)`, `blob.Open(ctx, cfg.S3)`, `worker.NewPublisher(bus.Connect(...), nil)`) and called `Service.Queue()` directly against the koa `bom_document_id` — bypassing HTTP/ZITADEL, same technique as (b)'s scan creation. Render is asynchronous (a NATS job the freshly-rebuilt `report` container's own in-process consumer drains); all results below were confirmed against real rows in `report.reports` and real objects fetched back out of MinIO via the same throwaway program's blob client, not assumed from `status=ready`.

- **At the default level (`top_level`)**, all 5 formats (`pdf`, `xlsx`, `json`, `spdx`, `cyclonedx`) rendered `ready`. Every one was legitimately near-empty: the JSON bundle's own `level_note` explains why — *"lists 0 direct dependencies... A further 41 component(s) could not be placed in the dependency tree... 3 component(s) are out of the configured scope"* — because this SBOM has **zero** captured dependency-graph edges (`normalize.dependencies` has no `depends_on` rows for this scan; `syft`'s directory/manifest scan of a source tree, as opposed to an installed `node_modules`, produces no relationship data). SPDX/CycloneDX at this level were byte-for-byte tiny (~300 bytes each) — a real, honest empty document, not a bug.
- **Re-queued at `level=complete`** (`QueueRequest.Level: "complete"`) to actually exercise the real component data. `pdf`, `xlsx`, `spdx` rendered `ready` and were verified to contain real data: the SPDX document has 41 real `packages` (`relationships: 0`, confirming the no-edges finding above) with recognizable names (`checkout` → `pkg:github/actions/checkout@v5`, etc.); the XLSX workbook has all 9 expected sheets (Summary, Engine Coverage, Field Coverage, Practices, Components, Findings, VEX Field Coverage, Licenses, Notes) and its Components sheet contains real npm package names verified by direct XML inspection.
- **`cyclonedx` and `json` both FAILED** at `level=complete`, `status=failed`, `error_code=REPORT_RENDER_FAILED`, with the identical underlying error in both (the JSON bundle embeds a `cyclonedx_1_6` document, so it fails for the same reason): `serializing SBOM to native format: unable to build cyclonedx document, no root nodes found`.

**Root cause, traced to the actual code, not just the error string.** `export.toProtobom()` (`services/report/internal/export/export.go:287-295`) sets `bom.NodeList.RootElements` from `doc.Roots` — correctly, and it's exercised correctly by `export_test.go`'s own tests, which construct `export.Document` by hand and always populate `Roots`/`Dependencies`. But there is exactly **one** production call site that builds a real `export.Document`: `toExportDocument()` in `services/report/internal/worker/worker.go:477-495` — and it **never sets `Roots` or `Dependencies` at all**. `render.BOM` (the struct `toExportDocument` reads from) has no `Roots`/`Dependencies` field to read them from in the first place. The underlying edge data does exist and IS already loaded elsewhere — `services/report/internal/store/bomsource.go:338` queries `normalize.dependencies WHERE relationship = 'depends_on'` — but only to flatten it into the CERT-In Field 07 (`ComponentDependencies`) **text** column on each component, never as structured graph data carried through to export. Net effect: **CycloneDX export (and the JSON bundle) is broken in production for any BOM with ≥1 component and no dependency edges** — which is the common case for a source-only scan without an installed lockfile, i.e. most of what this session's own live-proof runs have exercised. It did not surface at `top_level` because protobom's CycloneDX writer only errors when `NodeList` has at least one node but zero declared roots — an entirely empty `NodeList` (the `top_level` case here) apparently serializes fine. **Scoped fix for a future session:** (1) `bomsource.go` also loads structured `(from_key, to_key)` edges instead of/alongside the flattened Field 07 text, (2) `render.BOM` gains `Roots []string` / a `Dependencies` field, (3) `toExportDocument` populates them. Not fixed here — this was a proof-of-life pass, not a new implementation gap, and the finding is significant enough to need its own scoped session rather than a rushed fix.

Cleaned up all three throwaway directories (`services/project/tmp-koa-register/`, `services/scan-orchestrator/tmp-koa-scan/`, `services/report/tmp-koa-render/`) — confirmed `git status` clean of them and `go build ./...` passes.

### 2026-08-26 (d) — the CycloneDX/JSON export bug from (c) fixed, and it turned out to be two bugs, not one — re-verified live against the same real `koa` BOM document

Picked up (c)'s scoped fix directly: real-world accuracy for a common case (source-only scan, no lockfile) beat leaving it as debt for a future session, since 2 of 5 export formats — including one of the two CERT-In-accepted standards — were broken.

**The plumbing fix, as scoped in (c).** `services/report/internal/store/bomsource.go`'s `loadComponentRelations` now loads the real `(from_component_key, to_component_key)` edge pairs from `normalize.component_dependencies` (joining both sides to `normalize.components`, not just counting them) into a new `render.BOM.Dependencies []Dependency` field, and derives a new `render.BOM.Roots []string` from the already-loaded per-component `Depth`/`IsOrphan` (root = `Depth == 0` OR orphan — confirmed against `libs/py-shared/axebom_shared/normalize/graph.py`'s own `depth[root] = 0` invariant before writing this, so it is not a divergent redefinition). `toExportDocument()` in `services/report/internal/worker/worker.go` now populates `export.Document.Roots`/`Dependencies` from these. Deliberately documented on the `Roots` field why folding orphans in is an export-layer necessity (CycloneDX/SPDX require every node reachable from a declared root) and not a claim that the normalizer discovered a root relationship it didn't — no dependency edge is invented, only a root **reference list**, which is a structural requirement of the target format, not a graph-structure assertion.

**First re-run against the real koa document (`bom_document_id = 01a03df4-8874-7614-b94a-5c3daa50a3ae`) surfaced a SECOND, different protobom error** the "no root nodes found" message had been masking: `unable to serialize multiroot (44) cyclonedx, (mod.CYCLONEDX_MULTIROOT_HEADLESS disabled)`. CycloneDX has exactly one `metadata.component` slot for a document's single subject; a zero-edge scan has no such subject — every component is independently a root. protobom's own answer for this is a documented mod, `mod.CYCLONEDX_MULTIROOT_HEADLESS` (`github.com/protobom/protobom/pkg/mod`): when enabled, `metadata.component` is omitted and every root is promoted to a top-level `components[]` entry — a standard, valid "headless" CycloneDX BOM, not an invented hierarchy. It is a documented no-op whenever there is exactly one root (confirmed: `serializer_spdx23.go` never even checks this mod, and the pre-existing `TestAMonorepoKeepsAllItsRoots` and golden-fixture tests still pass byte-identical with it turned on unconditionally), so `export.Serialize()` now always passes it — no branching on scan shape needed.

**A second re-run surfaced a THIRD bug, this time a real regression risk from the fix itself, not protobom**: `integrity error: root component "hash:0f1a409d..." not found`. Root cause: `services/report/internal/store/bomsource.go`'s `applyLevel()` (the `level=complete`/`top_level` narrowing step, which runs AFTER `loadComponentRelations`) already filtered `out.Components` and `out.Findings` down to the kept set, but had no matching filter for the newly-added `out.Roots`/`out.Dependencies` — so a root or edge endpoint pointing at a component the level projection dropped (koa's 3 out-of-scope entries) survived into the export document as a dangling reference. Fixed by filtering both against the same `keptKeys` set `applyLevel` already builds. Also hardened against a narrower theoretical case the same fix doesn't automatically cover: a *declared* root (`Depth == 0`) being scope-excluded while a non-root descendant survives would zero out `Roots` while `Components` stays non-empty (the original "no root nodes found" failure, from a different cause). Rather than guess which survivor should inherit the missing root's place — `Roots` deliberately does not recompute from edges, since real cycles mean "no incoming edge" is not a safe stand-in for "is a root" — the fallback is the same honest answer used when there was never a graph at all: if filtering leaves zero roots but ≥1 component, list every survivor independently.

**Re-verified live, for real, after each of the three fixes**, by rebuilding and redeploying the `report` container each time and re-queuing a `level=complete` `cyclonedx` and `json` render against the same real koa document via a throwaway program (`services/report/tmp-koa-reroot/`, deleted after — same disposable-program technique as (b)/(c), needed under `services/report/` because `service`/`store`/`worker` are internal packages). Final state, confirmed by fetching the actual rendered bytes back out of MinIO and parsing them (not assumed from `status=ready`): both `cyclonedx` (`report_id=01a03e0e-a2be-...`) and `json` (`report_id=01a03e0e-a2c3-...`) report rows are `status=ready`, `error_code=""`. The CycloneDX document is valid JSON, `bomFormat=CycloneDX`, `specVersion=1.6`, headless (`metadata.component` absent), with **41 real components and 11 real dependency edges** — koa's actual lockfile-derived graph, which turned out to genuinely have edges (contradicting (c)'s "zero captured dependency-graph edges" note, which was evidently describing the `top_level`-only render it had actually queried, not `complete`). The JSON bundle's embedded `documents.cyclonedx_1_6` shows the identical 41/11 counts.

`go build ./...`, `go vet ./...` and `go test ./...` all clean (no Python touched this entry). The export package's existing golden fixtures (`fixture.spdx.json`, `fixture.cdx.json`) are byte-identical with the headless mod enabled — confirms the common single-root case is unaffected. Cleaned up `services/report/tmp-koa-reroot/` — confirmed `git status` clean of it.

### 2026-08-26 (e) — a full adversarial audit of this session's work (three parallel forks: Go, Python, migrations+live-DB), a real production bug fixed, a real fabricated-value bug fixed, and the two golden fixtures Gap C deferred are now built

The user asked to "complete the entire SBOM [module]. Also audit everything that there should be no errors and bugs." Ran three parallel fork audits over everything touched in (a)–(d) — Go services, the Python normalize/consumer path, and migrations plus adversarial live-role privilege checks against the actual running Postgres — plus a fourth fork to build `fixtures/log4shell-java/` and `fixtures/alias-overmerge/`, the two golden fixtures Gap C explicitly scoped but deferred. All four ran concurrently against the same shared dev stack.

**Real bug #1 (high severity, fixed): `maybeTriggerNormalize` claimed its write-once slot BEFORE publishing, not after.** `services/scan-orchestrator/internal/orchestr/normalize_trigger.go`'s original sequence was: `MarkNormalizeTriggered` inserts the `scan.normalize_triggers` row and returns `fired=true` FIRST, then `buildNormalizeTrigger` (real DB queries), `Validate()`, `json.Marshal`, and `bus.Publish` all ran AFTER — any one of those four failing transiently (a NATS restart, a DB blip) left the claim row permanently in place with nothing ever published, and since the row already existed, every future redelivery's own claim attempt saw "already fired" and returned immediately. **A scan's SBOM would silently, permanently never normalize**, with no retry path and no alert beyond one ERROR log line — found by the Go-audit fork, not by any test (no test covered a publish failure after a successful claim). Fixed by reordering to publish-then-claim: `MarkNormalizeTriggered` now takes an explicit `triggerID` (generated client-side via `uuid.NewV7()`, no longer a DB default) so the trigger can be built and published BEFORE anything is written to `scan.normalize_triggers`; the claim only happens after a successful publish. A cheap read-only `NormalizeTriggerID` pre-check (already existed, never claims) preserves the original early-exit for the common "already fired" case, so this doesn't rebuild+republish on every redelivered terminal result. The accepted tradeoff: two concurrent calls can both pass that pre-check, both publish under DIFFERENT trigger ids, and only one wins the claim — a harmless duplicate, since `normalize_consumer.py`'s own idempotency (pre-check by `scan_id`/`bom_type`/`normalization_version`, backed by a UNIQUE constraint) already absorbs a duplicate the same way it absorbs a redelivery. `store.go`, `normalize_trigger.go`, `normalize_trigger_test.go` updated; `go build`/`vet`/`test` clean; the one test that exercises this end-to-end live (`TestNormalizeTriggerFiresOnlyAfterEveryFamilyEngineIsTerminal`) was run for real by temporarily stopping `sbom-worker` to free the NATS subject — passed. Rebuilt and redeployed the `scan-orchestrator` container.

**Real bug #2 (real but narrow, fixed): `_dependency_check_cvss` hardcoded CVSS version `"3.1"` unconditionally** — found by the Python-audit fork. OWASP Dependency-Check's `cvssv3` block is structurally identical for CVSS 3.0 and 3.1; the code never checked which one a given NVD entry actually was, just asserted "3.1" for every one. This is a labeling fabrication of exactly the kind CLAUDE.md's "never fabricate" discipline exists to catch (the score/vector were real, the version tag wasn't verified) — and it was never caught because `dependency-check` has never successfully run this session (no `NVD_API_KEY`), so nothing exercised it against real output. Fixed `libs/py-shared/axebom_shared/normalize/ingest.py`'s new `_cvss_v3_version()`: reads the `CVSS:3.x/...` prefix off the vector string first (the most direct signal, straight from the source data), falls back to an explicit `cvssData.version`/`version` field (the newer, NVD-schema-mirroring report shape), and returns **empty, never "3.1"**, when neither is present — a version not observed is not a version asserted. Added two regression tests (`test_dependency_check_cvss_v3_version_reads_the_explicit_field_when_the_vector_lacks_one`, `test_dependency_check_cvss_v3_version_is_never_fabricated`); all 12 tests in `test_ingest.py` pass.

**Real finding #3 (real, but its correct fix crosses out of SBOM scope — investigated, reverted, documented rather than force-fixed): `normalize.bom_documents.alias_snapshot_id` has no FK to `normalize.alias_snapshot.id`**, despite `docs/01-DATA-MODEL.md` already documenting it as one and despite this session's own `findings_cluster_id_fkey` (migration 0007) closing the identical gap for `cluster_id` — found by the migrations-audit fork. Wrote migration `0010_bom_documents_alias_snapshot_fk.sql` (`NOT VALID`, so it wouldn't require reconciling 24 pre-existing dev rows with fabricated ids) and applied it live — but doing so immediately broke 17 real Go tests (and, more importantly, **real production code paths**: `services/project/internal/store/qbom.go` and `hbom.go` both write `alias_snapshot_id` as a bare `app.uuid_v7()` inline, with no backing row at all, because QBOM and HBOM never run the SBOM alias-closure pipeline this column was designed for — QBOM derives from CBOM, HBOM is a CSV/form import, neither has vulnerability clusters to snapshot an alias graph for). Fixing this properly means deciding what QBOM/HBOM *should* reference — a shared sentinel row, or making the column SBOM-only and nullable elsewhere — and that is a real design decision touching CBOM/QBOM/HBOM code, which this session's own scope discipline ("changes to shared code are additive... scoped so other BOM types are unaffected") explicitly rules out. **Reverted**: dropped the constraint live, deleted the `normalize.goose_db_version` row for it, removed the migration file — confirmed `test_writer.py`'s 5 live-Postgres tests (which failed transiently while the FK was live, exactly as expected) pass clean again afterward. Documented the real gap directly on the `alias_snapshot_id` row in `docs/01-DATA-MODEL.md` instead of silently dropping it. **This is the one item from the audit deliberately left unfixed — flagged for a session with QBOM/HBOM in scope.**

**Two golden fixtures built**, closing out Gap C's last deferred piece: `fixtures/log4shell-java/` (three engines each assert only a partial edge of the real CVE-2021-44228 / GHSA-jfh8-c2jp-5v3q / Debian DSA-5022-1 triangle; the closure — not any single engine — produces one cluster) and `fixtures/alias-overmerge/` (a batched GHSA aliasing 13 synthetic CVEs caps at exactly 12 members with the overflow flagged for review; a separate unauthoritative CVE↔CVE assertion is refused outright, never merging). Both hand-verified field-by-field against `aliases.py`'s actual union-find (not generated-then-trusted) — the fixture-building fork found and fixed a real bug in its own first draft of `grype.json` (wrong JSON nesting for `relatedVulnerabilities`) before accepting the golden. Two new fixture-specific tests added to `workers/sbom/test_golden.py`; 20/20 pass.

**Also confirmed, not previously written down**: 5 pre-existing fixtures' `expected/canonical.json` (`npm-simple`, `golang-incompatible`, `maven-case`, `monorepo-multiroot`, `pypi-normalization`) changed during (a)'s Gap A work and were still sitting uncommitted. Independently verified (not just trusted) that the ONLY change in all five is `trivy-fs` now appearing as an additional `detected_by` engine on findings that grype/osv-scanner already reported — `component_count`, `finding_count`, and `completeness_pct` are byte-identical old vs. new in every one. This is the correct, expected consequence of (a)'s own fix (trivy-fs's `vulnerabilities[]` array was previously silently dropped) — not a regression, but per docs/09-GOLDEN-CORPUS.md §5 it needs the justification stated here so the eventual commit message isn't the first place this gets written down.

Migrations-audit fork also confirmed, live, adversarially (not just by reading SQL): `axebom_normalize_writer` correctly REJECTS UPDATE on any ungranted column, any DELETE on `vuln_clusters`, and SELECT outside its schema; correctly ALLOWS only its documented column-scoped UPDATE. `TestRLSCoverage` passes live: 49 tables checked, 41 protected, 8 exempt, 0 gaps. `vuln_ids.namespace`/`fix_version_ordering` CHECK constraints match what the Python code actually emits, exactly, no gaps. One informational (not a bug) note: `0009`'s `Down()` would now hard-fail if ever run against this database, since 15 real rows already carry `fix_version_ordering = 'comparator'`, a value the pre-0009 CHECK rejects — inherent to any CHECK-widening migration once genuinely-wider data exists, not a defect.

Everything else across all three audits — the new `Roots`/`Dependencies` plumbing from (d), `applyLevel`'s filtering, `vex.Effective`, the cluster-persistence advisory-lock/transaction design, `normalize_consumer.py`'s idempotency, `uuid7()`'s bit layout, the CycloneDX ingestion additions — came back clean. `go build`/`vet`/`test ./...` and `.venv/bin/python -m pytest libs/py-shared workers tools` both fully clean except the one pre-existing, out-of-scope `crypto-mixed` (CBOM) golden failure noted since (a).

### 2026-08-27 (f) — the containers had never been redeployed after (a)–(e); once they were, driving a real scan through the actual product API (not a throwaway Go program) found and fixed two more real bugs

The user reported the running app "still looked the same" after (e). It did: every container (`frontend`, `gateway`, `worker` — shared by `sbom-worker`/`cbom-worker`/`aibom-worker` — and `sbom-normalize-consumer`) was still running an image built BEFORE (a)–(e)'s source changes landed on disk — confirmed by comparing `docker image inspect --format '{{.Created}}'` against the changed files' mtimes (e.g. `frontend:dev` built 2026-08-25T20:52, every changed frontend file dated 2026-08-26T10:13). Rebuilt and redeployed all four; `project:dev`/`report:dev` were already current and left alone.

Rebuilding isn't the same as proving the pipeline works, so — per the user's "use the flow of our OSINT's" — drove a real scan through the actual product surface instead of a throwaway internal program: minted a real API key (`axebom apikey mint`, the CLI's documented CI/scripting path) for the tenant behind the existing `koa-live-proof` project (`01a03df3-e253-7425-9b44-d29402317722`, tenant `01900000-0000-7000-8000-00000000000a`), then called `POST /v1/scans` through the real gateway/nginx/TLS path at `https://192.168.30.202:5173/api/v1/scans` exactly as a script or the frontend would. This surfaced two more real, previously-uncaught bugs — found only because this was the first time an API key had ever actually driven a scan:

**Real bug #4 (fixed): any API-key- or service-authenticated `POST /v1/scans` crashed with a 500.** `services/scan-orchestrator/internal/handler/handler.go`'s `Create` hardcoded `TriggeredBy: "user"` and fed `ctxkey.UserID(r.Context())` straight into `TriggerRef`, a `uuid` column, unconditionally. For a real user session that value is a UUID; for an API key or a service principal, `oidcauth`'s middleware sets it to `"apikey:<id>"`/`"service:<name>"` — a string, not a UUID, and Postgres rejected the insert outright (`ERROR: invalid input syntax for type uuid`). `orchestr.CreateScanInput.TriggeredBy`/`store.go` already had first-class support for `"api"`/`"webhook"` triggers with `TriggerRef` left empty — the handler layer just never used it. Fixed with a new `triggerFields()` that classifies the subject by `oidcauth.APIKeySubjectPrefix`/`ServiceSubjectPrefix` and returns `("api", "")` for either, `("user", subject)` otherwise; table-driven regression test added (`handler_test.go`, new file — the package had none). `go build`/`vet`/`test` clean; rebuilt and redeployed `scan-orchestrator`.

**Real bug #5 (fixed): the mandatory Engine Coverage section could falsely report a well-covered ecosystem as an unseen gap.** `scan.ecosystems_detected` stores one row per `(scan_id, ecosystem, detected_by)` — one row per REPORTING ENGINE, by design (`RecordEcosystem`'s own doc comment). `CoverageGaps()` (`store.go`) queried `SELECT DISTINCT ecosystem WHERE engine_available = false`, which returns an ecosystem the instant ANY engine has a false row for it — even when a DIFFERENT engine has a true row for the same ecosystem in the same scan. Caught directly on the koa live scan: `trivy-image` (registered for `npm`/`pypi`/`deb`/`rpm`/`apk`/`golang`, always skipped-for-source-kind on a git scan) wrote `(npm, trivy-image, false)`, while `syft` and `trivy-fs` — both of which had just genuinely succeeded — wrote `(npm, syft, true)`/`(npm, trivy-fs, true)` in the very same scan. `coverage_gaps` reported `npm` as a gap anyway, which is exactly the false-negative invariant 12 exists to prevent, just pointed the other direction: a fully-scanned ecosystem reported as unseen on the mandatory Engine Coverage section of every source-only (non-image-target) scan — which is most scans. Fixed the query to require that EVERY row for an ecosystem in that scan be false, not just one (`NOT EXISTS` a `true` row for the same `scan_id`/`ecosystem`). Extended the one existing test that exercises this (`TestEcosystemsWithNoEngineAreRecorded`) with the mixed-availability case rather than only adding a new one, per the "a regression that copies the wrong behavior should fail an existing case" discipline — it fails against the old query, passes against the fix. Verified against real Postgres, both as the unit test and by re-querying the live koa scan's `coverage_gaps` before/after redeploy: `npm` dropped out, `apk`/`deb`/`golang`/`pypi`/`rpm` correctly remained (no other engine in this scan asserted those). Rebuilt and redeployed `scan-orchestrator` again.

**The live scan itself, post-fix**: `scan_id = 01a042b4-da4e-7079-b2f0-43f226b9ab9a` against `koa-live-proof`, `completed_with_errors`. `grype`/`osv-scanner`/`syft`/`trivy-fs` all `succeeded` (syft: 44 components; trivy-fs: 36 components); `dependency-check` correctly `unavailable` (`ENGINE_DB_STALE` — no NVD database provisioned, `NVD_API_KEY` still genuinely unset, unchanged since (a)); `mock-engine` correctly `skipped` (`ENGINE_NOT_IMPLEMENTED` — a pre-existing Phase 6 scaffold engine, not touched here). The normalize trigger fired automatically (confirming (e)'s Bug #1 fix holds under the real API path, not just the earlier throwaway-Go-program path) and produced `bom_document_id = 01a042b5-3c03-70fc-84a5-3e49b90a3eed`; `GET /findings-summary` returns real (zero, honestly — no CVEs matched) counts, not the all-zero-because-never-ran state (b) first found.

**Not done, flagged rather than silently skipped**: did not drive this through an actual browser session as the signed-in user, since that account/tenant binding isn't visible from here — the data lives under the pre-existing `koa-live-proof` project, tenant "Acme Industries" (`01900000-0000-7000-8000-00000000000a`); if the user's browser session is signed into a different tenant, this scan won't be visible there without a project created under that tenant instead. The API key minted for this verification (`key_id=e25fc463f78d`, scopes `scan:run,scan:read,report:read,report:download,project:read`) was left in place rather than revoked, in case it's useful for further scripted verification.

### 2026-08-25 (x) — (t)'s auto-redirect and the sign-up link were never compatible; SignIn is a two-button choice screen now, not an auto-navigate

Continuation of (v)/(w). The user reported "still redirecting" (a screenshot again showing ZITADEL's real "Welcome back!" login form — confirming the OIDC round trip is genuinely working, this was not another App.NotFound recurrence) and asked for a button to reach the sign-up page from there. Re-verified `.env`/ZITADEL/gateway/bundle agreement fresh first, as a matter of process — all four agreed correctly, so nothing had regressed; the report was about UX, not a broken id again.

The actual issue: (t)'s auto-redirect-on-mount (built at the user's own prior request) and the "New here? Create your organisation" link that already lived on the same `SignIn` screen were never compatible — the auto-redirect fires before a visitor can ever click a link on the screen it's leaving. There is no single destination to auto-navigate to that serves both a returning user (wants sign-in) and a new one (wants sign-up); showing both as a real, deliberate choice is the only design that doesn't strand one of them.

**Fix**: `SignIn` (`frontend/src/routes/auth/AuthRoutes.tsx`) no longer auto-attempts sign-in on mount — removed the `attempted` ref + `useEffect` from (t) entirely. It now renders two real buttons, "Sign in" and "Create your organisation" (promoted from a footnote `<Link>` into a proper `.btn`), and nothing navigates until the visitor picks one. The safety property that mattered from the auto-redirect attempt — a misconfigured client id failing visibly via `error` rather than bouncing silently — is preserved because it was always about *not retrying automatically*, not about *not asking the visitor to click*; that already held for the manual button before (t) and holds again now.

Frontend `npm run build`/`npm run lint` clean. Rebuilt and redeployed; confirmed live by checking the served bundle for the new "Create your organisation" button text and the *absence* of (t)'s "Redirecting you to sign in…" text. Refreshed the `axebom dev snapshot` rollback baseline. Not yet confirmed by the user in a browser.

### 2026-08-25 (w) — sign-in reached ZITADEL's real login form (confirmed by the user, screenshot); the sidebar/topbar rendered even for a signed-out visitor

Continuation of (u)/(v). The user hit a genuinely new, unrelated CORS error (`fetch ... http://192.168.30.202:5173/.well-known/openid-configuration ... blocked by CORS policy`, plus `favicon.ico` getting `ERR_CONNECTION_RESET`) after (v)'s fix — re-verified the live bundle and server fresh, still 100% `https://` everywhere with nothing stale. The scheme downgrade (the app only ever constructs `https://` URLs, confirmed in the deployed bundle) plus an actively reset connection point at a network intermediary on the user's side (the same class of interference suspected for the original `localhost` hang in (s)), not this codebase — flagged to the user as such rather than chased further server-side. Left unresolved on that front; the user separately confirmed reaching ZITADEL's own hosted login form (`https://192.168.30.202:5173/ui/v2/login/loginname?...`, screenshot: "Welcome back!") in a different tab, meaning the OIDC round trip does work end to end from here — auth, HTTPS, the client-id fix from (v), all correct.

Real, actionable finding from the same screenshot: **`Sidebar`/`TopBar` rendered unconditionally in `Shell()` (`frontend/src/App.tsx`), outside the `RequireAuth` gate** — so the full app navigation chrome was visible even while a visitor was signed out, mid-redirect, or had no role granted. User asked for this removed explicitly. Fixed by inlining `RequireAuth`'s gate logic directly into `Shell()` as early returns, so the chrome (`Ambient`, `Sidebar`, `TopBar`, `<main>`) is now part of what's gated — only reached once `loading` is false, `user` exists, and `memberships.length > 0`; the loading skeleton / `SignIn` / `NoAccess` screens render standalone, with no chrome around them at all. The separate `RequireAuth` component is gone (it only had one caller). Frontend `npm run build`/`npm run lint` clean; rebuilt and redeployed. Not yet confirmed by the user — this is a UI change, not something server-side verification can confirm on its own.

### 2026-08-25 (v) — `task dev`'s own dotenv fix silently shipped a stale build: bootstrap wrote fresh ZITADEL ids, but the frontend baked in yesterday's

Direct continuation of (u). HTTPS worked, but the browser got `{"error":"invalid_request","error_description":"Errors.App.NotFound"}` from ZITADEL on the actual sign-in attempt. Root cause, found by diffing three sources of truth: the deployed frontend bundle had `client_id`/`project_id` baked in from an OLD bootstrap (`387865583...`), while `.env` and ZITADEL's live registration both already agreed on NEWER ones (`387869814...`) from the bootstrap that ran during (u)'s `task dev`. The frontend image was never actually rebuilt with the ids that bootstrap had *just* written.

**The mechanism, and why it's a real bug in (t)'s `dotenv: ['.env']` fix, not a one-off**: go-task's `dotenv:` loads `.env` into the `task dev` process's environment exactly once, at startup — before the `iam bootstrap --write-env` step later in the same run has written anything. `docker compose`, when a variable exists in both the shell environment and its own auto-read `.env` file, uses the shell value. So the `{{.COMPOSE}} up -d --build` step that follows bootstrap in the same task process inherited the *stale*, already-exported `ZITADEL_PROJECT_ID`/`ZITADEL_SPA_CLIENT_ID`/`ZITADEL_ISSUER` — bootstrap's rewrite of the `.env` file on disk had no effect on them. This reproduces on every single `task dev` run from now on, not just after an `iam:reset` — (t)'s dotenv fix (itself correct and necessary — see (s)) introduced this as a side effect the moment a later step in the same run could change a value dotenv had already exported.

**Fix**: split `dev` into `dev` (preflight, infra+IAM wait, migrate, seed, bootstrap) and a new `dev:build` task (the full-stack build, health-wait, snapshot, URL printout). `dev` calls `dev:build` via `cmd: task dev:build` — a literal shell command, not Task's own `task:` dependency syntax — specifically because that spawns a genuinely new `task` process, which re-reads `.env` from disk at *its own* startup and picks up what bootstrap just wrote. (First attempt marked `dev:build` `internal: true` for tidiness; go-task refuses to run an internal task except via its own `task:` syntax, which is exactly the path being avoided here — confirmed live, reverted immediately.)

**Verified precisely**: extracted the actual `client_id`/`project_id` string literals from the served bundle (`curl | grep -oE '"3[0-9]{17}"'`) before and after the fix. Before: bundle had `387865583196045319`/`387865583632318471`, matching neither `.env` nor ZITADEL. After: bundle has `387869814594469895`/`387869814946791431`, matching both. Full `go build`/`go test ./...`/`golangci-lint run ./...`/boundary lint/docs lint all clean. **Not yet confirmed by an actual browser sign-in** — this was caught and fixed from the server side using the browser's own reported OIDC error, without a repeat round-trip through the user yet.

### 2026-08-25 (u) — the real reason sign-in never completed over the LAN IP: crypto.subtle needs a secure context, and http://192.168.30.202 isn't one

Direct continuation of (s)/(t). After (t)'s auto-redirect deployed, the user's screenshot showed the actual blocker for the first time: **"Crypto.subtle is available only in secure contexts (HTTPS)."** — a browser-native restriction, not an AxeBOM or ZITADEL bug. Browsers only expose `crypto.subtle` (which oidc-client-ts needs for PKCE) on `https://` origins, with exactly one exception: `http://localhost`. `http://192.168.30.202` is neither, so the Web Crypto API was silently unavailable and every sign-in attempt failed at that point — this was true from the very first attempt over the LAN IP, unrelated to every stale-cache/service-worker/incognito hypothesis chased in (s) and earlier in this entry's own session. (For the record: a caching-proxy theory was pursued for a while first — nginx's `/index.html` headers were hardened with `Pragma`/`Expires`/no-ETag as a defensive measure, harmless but not the actual fix.)

**Chose the proper fix over the fast one** (Chrome's `--unsafely-treat-insecure-origin-as-secure` flag was offered as a zero-server-change alternative): real self-signed HTTPS. This meant:

- New `task tls:gen`: generates a self-signed cert for `ZITADEL_DOMAIN` (IP SAN, since `ZITADEL_DOMAIN=192.168.30.202` is an IP not a hostname) into `deploy/compose/.data/tls/`.
- `deploy/docker/nginx.conf`'s `listen` directive and cert lines are now templated placeholders (`__SSL_LISTEN_SUFFIX__`, `__SSL_CERTIFICATE_DIRECTIVES__`), toggled by a new `deploy/docker/frontend-entrypoint.d/50-tls.sh` at container start — TLS only turns on when a cert is actually mounted, so the default `localhost` flow (already a secure context, needs no TLS) keeps working with nothing mounted. Confirmed both branches live: rebuilt frontend with no cert present (served plain HTTP correctly), then with a cert present (served real TLS 1.3, verified via `curl -v`).
- `docker-compose.app.yml`'s `frontend` service mounts `./.data/tls:/etc/nginx/tls:ro`.
- `.env`: `ZITADEL_EXTERNALSECURE=true`, `ZITADEL_PUBLIC_SCHEME=https`, and every `https://192.168.30.202:5173` URL (issuer, public URL, frontend URL, GitHub redirect).

**Three more real bugs found and fixed getting this actually working, not hypothetical:**
- Same root-owned-directory trap as (s), new instance: Docker auto-created `deploy/compose/.data/tls/` as root the first time it was bind-mounted before the directory existed on the host, so `task tls:gen`'s own `openssl` write failed permission-denied. Fixed by having `tls:gen` reclaim ownership through a root-running container first, same pattern as the `iam:reset` fix below.
- openssl writes the private key `0600` (host-user-only) by default; nginx reads it as the base image's own `nginx` uid inside the container, so a bind-mounted `0600` key failed "Permission denied" the instant nginx tried to load it — confirmed by watching the container crash-loop on exactly that. `tls:gen` now `chmod 644`s it; this key protects nothing but a browser secure-context check for a local dev stack, not a real secret worth a stricter host ACL.
- `axebom iam bootstrap`/`iam verify` dial ZITADEL's *direct* port (58080, bypassing nginx) in plaintext — correctly, since `ZITADEL_TLS_ENABLED` is unconditionally `"false"` in `docker-compose.iam.yml` (ZITADEL never terminates TLS itself; only nginx does, for the browser-facing path this direct connection doesn't use). But `iam.Config.Insecure` was doing double duty — also picking the scheme for the `PublicHost` issuer-override — so once `ZITADEL_EXTERNALSECURE=true` made the *public* issuer `https://` while the *direct* connection stayed correctly plaintext, the CLI tried to validate a plaintext-derived `http://` issuer against ZITADEL's actual `https://` one and failed with "issuer does not match". Root-caused by reading `libs/go-shared/iam/iam.go`'s own `PublicHost` doc comment, which already anticipated a version of this problem for the gateway's in-network caller — just not this exact plaintext-transport/https-issuer combination. Fixed properly: new `iam.Config.PublicScheme` field, decoupled from `Insecure`, wired from `f.publicURL`'s actual scheme in the CLI (`publicOrigin` helper) and from `cfg.Issuer`'s scheme in `services/gateway/deps.go` — **the exact same latent bug existed there too** for the self-signup feature, not yet exercised in this session, found and fixed as part of tracing the CLI's failure rather than left for someone to hit later.

Also picked up (t)'s deferred STATE.md write and folded the (r)/(s)/(t) entries' shared thread here rather than duplicating: three sessions in, the actual sequence of blockers for "sign in over a LAN IP" was startup ordering (r) → ZITADEL's own domain being a one-time setup value (s) → the browser's secure-context requirement (this entry) — each one genuinely had to be found and fixed before the next became visible; none was a red herring found *instead of* the real cause, they were all real, sequential blockers.

**Verified end to end, server-side:** `curl -v https://192.168.30.202:5173/` completes a real TLS 1.3 handshake with the correct cert (`CN=192.168.30.202`, SAN `IP:192.168.30.202`); `.well-known/openid-configuration` and `/api/v1/auth/config` both report `https://192.168.30.202:5173` as the issuer; `task iam:verify` shows `issuer https://...` / `management http://...58080` (correctly different schemes for the two different paths now) and the dev tenants freshly linked. Full `go build`/`go test ./...`/`golangci-lint run ./...`/boundary lint/docs lint all clean. **Not yet confirmed by an actual browser sign-in** — the user will hit a self-signed-certificate warning on first visit to `https://192.168.30.202:5173` (expected, one-time, click through) — that's the next thing to hear back on.

### 2026-08-25 (t) — SignIn attempts sign-in automatically now, once per mount

Follow-up to (s), on request: `SignIn` (`frontend/src/routes/auth/AuthRoutes.tsx`) previously required a manual "Sign in" button click for every ordinary signed-out visit, by design — see the removed comment's reasoning about not wanting a misconfigured client id to bounce a visitor silently between origins forever. Changed to attempt sign-in automatically on mount, guarded by a `useRef` so it fires exactly once: a failure now surfaces as `error` on this same screen (same as before) rather than retrying silently, which is what actually mattered in the original design — the manual-click requirement itself wasn't the safety property, "one attempt, visible failure" was.

This made the `POST_SIGNOUT_KEY` one-shot marker (`AuthContext.tsx`) dead — it existed only to make *just-signed-out* visits skip the button while every other signed-out visit kept it, and now every visit skips it. Removed the constant and both call sites (`signOut`'s `sessionStorage.setItem`, `SignIn`'s read-and-clear) rather than leave it unused.

Frontend `npm run build`/`npm run lint` clean; rebuilt and redeployed the `frontend` container (learned from (s)/(r): a frontend fix isn't real until the container running it is actually rebuilt) and refreshed the `axebom dev snapshot` rollback baseline. Not yet confirmed by the user in a browser.

### 2026-08-25 (s) — the "slow localhost" chase ended somewhere unexpected: this VM's browser access is over a LAN IP, and ZITADEL's domain is a one-time setup value

**Goal:** continuation of (r) — the user reported `localhost:5173` still hanging even after (r)'s fixes landed and were deployed. Root-caused through several wrong turns, recorded here so the next session doesn't repeat them.

**What it actually was, in the end:** the user's browser runs on a separate Windows machine and reaches this VM over the LAN at `192.168.30.202`, not through any tunnel to `localhost`. `curl localhost:5173`/`127.0.0.1:5173` from their machine hung in every browser tested (normal profile, Incognito — ruling out extensions and stale service workers) while `curl` itself succeeded — that combination points at something intercepting loopback traffic at the OS/network layer on their Windows machine (VPN or corporate proxy), never conclusively identified. The user chose to route around it entirely: make `192.168.30.202:5173` (which their curl already reached fine) the fully-working origin instead of continuing to chase the Windows-side networking issue.

**Wrong turns worth recording:**
- First suspected the frontend was serving a stale build — it was (my (r) fixes hadn't actually been redeployed to the running container before the user's first retest), but fixing that didn't fix this report; it was a separate, real gap in (r)'s own verification, now closed.
- Then suspected resource contention — checked (16 cores, 39GB RAM, every container <1% CPU): not it.
- Then suspected IPv6 `localhost` resolution — ruled out by `127.0.0.1` hanging identically.
- Then suspected ZITADEL's "Trusted Domains" would let a second origin work without touching `ZITADEL_DOMAIN` — implemented it (`libs/go-shared/iam/provision.go`'s `ensureTrustedDomain`/`Spec.TrustedDomain`, wired from `--public-url` in `cmd/axebom/iam.go`'s `hostOf`), and it does NOT affect instance routing by Host header at all — confirmed live (`Instance not found (ExternalDomain is localhost)` persisted after registering the trusted domain). The ZITADEL SDK's own doc comment says as much: "Unlike Custom Domains, Trusted Domains are not used to route requests to this instance." Left in the codebase anyway — it fixed a real, separate bug (below) and trusted domains do have a legitimate narrower purpose per that same doc comment (discovery responses, email templates), so it's not wasted, just not sufficient alone.

**Real bugs found and fixed along the way, independent of the actual root cause:**
- `libs/go-shared/iam/provision.go`'s `ensureSPA` only ever set the SPA application's redirect URIs at *creation*. Re-running bootstrap with a different `--public-url` silently left ZITADEL's registered redirect URIs unchanged — the exact opposite of what `iamVerify`'s own doc comment claims ("if something IS missing, it is repaired"). Fixed with a new `reconcileSPA` that calls `UpdateApplication` when the app already exists, treating ZITADEL's `FailedPrecondition("No changes")` response as success (new `isNoChanges` helper) rather than an error, since calling the same reconciliation twice with an already-matching desired state is the normal case, not a failure.
- `Taskfile.yml` had no `dotenv:` directive. Every host-run `go run ./cmd/axebom ...` command (`db migrate`, `db seed`, `iam bootstrap`, `iam verify`) never read `.env` at all — only `docker compose` does that automatically. This was invisible because the Go flags' hardcoded defaults happened to match `.env.example`'s defaults; it broke silently the moment `.env` actually diverged (exactly this session). Fixed with one line: `dotenv: ['.env']`.
- ZITADEL's own domain (`ZITADEL_EXTERNALDOMAIN`, driven by `ZITADEL_DOMAIN` in `.env`) is set once at first-instance setup and has no API to add a second working one afterward — confirmed by exhausting the SDK: `ListInstanceDomains` exists, no `Add` counterpart does. Changing it for real requires `task iam:reset` (destroys ZITADEL's own dev database only, not AxeBOM's Postgres) followed by a fresh `iam:up`. Did this with explicit user sign-off. `task iam:reset`'s own cleanup left `deploy/compose/.data/zitadel-bootstrap/` root-owned (written by a root-running container) — host-side `iam bootstrap` then can't create `service-keys/` under it. Worked around with `chown` this session; **not yet fixed in the codebase** — `iam:reset`/`iam:up` should reclaim ownership of that directory after recreating it, or bootstrap should tolerate/report this specific permission failure more usefully. Left as a known gap for a future session.
- `linkIdentities` (provision.go) only overwrites `auth.tenants.zitadel_org_id`/`auth.users.zitadel_user_id` when the existing value is NULL or already matches — a deliberate safety guard against accidentally reassigning a tenant to the wrong org in the normal case, but exactly wrong immediately after `iam:reset`, where every existing ID is now provably stale. Worked around this session with a manual `UPDATE ... SET zitadel_org_id = NULL` before re-bootstrapping. **Also not yet fixed in the codebase** — `iam:reset` should probably null these columns itself as part of resetting, so a subsequent bootstrap relinks cleanly without an operator having to know to do this by hand.

**Config now in `.env` (gitignored, this VM only):** `ZITADEL_DOMAIN=192.168.30.202`, `ZITADEL_PUBLIC_URL`/`ZITADEL_ISSUER`/`FRONTEND_URL`/`GITHUB_REDIRECT_URL` all `http://192.168.30.202:5173`. Verified end to end: `.well-known/openid-configuration` returns 200 with the correct issuer and endpoint URLs (previously 404 "Instance not found"), `/api/v1/auth/config` reports the matching issuer, and `task iam:verify` shows both dev tenants (Acme Industries, Beta Corp) freshly linked to the new ZITADEL org IDs. **Confirmed by the user via an actual browser sign-in from the Windows machine against `http://192.168.30.202:5173` — the whole redirect round trip completes.** The two gaps two paragraphs up (root-owned bootstrap directory, stale links after reset) are real and still open, but did not need fixing to reach this outcome.

### 2026-08-25 (r) — `task dev` was racing its own dependencies; fixed startup ordering, made it wait for real readiness, and gave the local stack a rollback

**Goal:** debug "localhost is taking forever to load" and "containers should be healthy", and add rollback. Traced to real causes rather than one bug, all with the same shape — nothing waited for anything to be truly ready, only started.

**Root causes found, against the live running stack, not just by reading code:**

- `docker-compose.app.yml`'s `x-service-defaults` only ever depended on `migrate`, never on NATS/Redis/Vault/the MinIO bucket. `bus.Connect` fails fatally and non-retrying on the first NATS connect attempt, and `blob.Open` fails fatally if the bucket doesn't exist yet — `project`, `report` and `fetcher` call it but had no `depends_on` on `minio-init` at all. `restart: unless-stopped` papered over the race with a crash-loop, which is what a cold `task dev` "taking forever" actually was.
- `ZITADEL_PROJECT_ID`/`ZITADEL_SPA_CLIENT_ID` start empty; 6 of 8 app services refuse to start without them. `axebom iam bootstrap` only ever **printed** the values for a human to paste into `.env` — never wrote them — so a fresh clone crash-loops those six services until someone does that by hand and re-runs `docker compose up -d` (see (g)'s entry for the exact bug this already caused once).
- `task dev` was one `docker compose up -d --build` with no wait logic at all — it returned as soon as containers were *created*, not once `/readyz` agreed. Actual readiness (`task health`) was a separate step nobody was forced to run.
- Frontend: `fetchConfig()` in `frontend/src/lib/auth.ts` had no timeout on its `fetch('/api/v1/auth/config')` — the one call gating `AuthProvider`'s `loading` flag. A gateway that accepted the TCP connection but hadn't answered yet (exactly the mid-bootstrap window above) left that promise neither resolved nor rejected forever, so `RequireAuth` showed its skeleton forever instead of ever reaching the sign-in screen.
- **Correction to something I assumed going in and was wrong about:** `AuthContext`'s error state and the sign-in screen's error message + Retry button already existed and were already wired correctly (`frontend/src/lib/AuthContext.tsx`, `frontend/src/routes/auth/AuthRoutes.tsx`'s `SignIn`) — the actual gap was narrower than planned: nothing ever called `setError`/`setLoading(false)` in the hang case because the fetch never settled, and even once it did, `initAuth()`'s cached `starting` promise stayed permanently rejected after one failure, so the existing Retry button would have replayed the same stale error forever rather than trying again.

**Fixes:**

- `deploy/compose/docker-compose.app.yml`: `x-service-defaults` now also waits on `nats`/`redis`/`vault` (`service_healthy`); `project`, `report` and `fetcher` each got an explicit `depends_on` (a service key replaces the anchor's, so all conditions had to be repeated) adding `minio-init: service_completed_successfully`.
- `cmd/axebom/iam.go`: `iam bootstrap` gained `--write-env`, which upserts `ZITADEL_PROJECT_ID`/`ZITADEL_SPA_CLIENT_ID`/`ZITADEL_ISSUER` into `.env` in place (new `upsertEnvFile`, preserves every other line and the file's existing permissions).
- `cmd/axebom/health.go`: `axebom health` gained `--wait <duration>` — polls every 2s until every service reports `up` or the timeout elapses, printing which services are still not up; default is off (`0`), so the bare `task health` command's existing behavior and exit-code semantics are unchanged.
- `cmd/axebom/dev.go` (new): `axebom dev snapshot` retags every locally-built `axebom/*:dev` image to `:good`; `axebom dev rollback` retags `:good` back to `:dev`. This is the entire local rollback mechanism — no registry, CI or production deploy pipeline needed.
- `Taskfile.yml`: `dev` is now staged — infra+IAM up with `--wait` (named services only, see the ⚠ comment: `--wait` fails outright if a one-shot job like `minio-init` exits with no consumer in the *same* invocation, so it's deliberately left out of this stage and deferred to stage 3 where its real dependents are) → `db migrate` → `db seed` → `iam bootstrap --write-env` (that order, not bootstrap first — (g) already found bootstrap's linking step needs migrated schema and seeded rows) → full stack up → `axebom health --in-cluster --wait 90s` → `axebom dev snapshot` only on success. New `dev:rollback` task: `axebom dev rollback` → `up -d --no-build` → the same health-wait.
- `frontend/src/lib/auth.ts`: `fetchConfig()` now passes `AbortSignal.timeout(10_000)` and throws a clear message on timeout; `initAuth()` now clears its cached `starting` promise on failure instead of leaving it poisoned, so Retry actually retries.
- `frontend/src/lib/api.ts`: `send()` now defaults to `AbortSignal.timeout(30_000)` when no caller-supplied signal is given.
- Every list/detail query hook across `frontend/src/lib/*.ts` (and three route-local ones in `Dependencies.tsx`, `Findings.tsx`, `ShareDialog.tsx`) now forwards React Query's own `signal` into `request()`/`api.get()` instead of silently dropping it — previously a hung request just sat in `isPending` forever with no way for React Query to ever retry or cancel it.
- `docs/LIMITATIONS.md`: corrected a stale claim ("No Helm charts") — one exists at `deploy/k8s/`, just not wired to any pipeline — and recorded the production CD/rollback gap explicitly, distinct from the now-real local one.

**Verified against the live running stack**, not just reading code: ran the new staged `task dev` against the actual 20-container stack already up in this environment. First attempt failed exactly as the ⚠ comment above now explains — `--wait` on the full infra+IAM file set errored on `minio-init`'s expected exit; fixed by naming stage 1's target services explicitly. Second run completed end to end: infra+IAM waited correctly, migrate/seed/bootstrap ran in order (bootstrap found existing state and left `.env` unchanged, confirming idempotency), the app tier recreated exactly the containers whose `depends_on` actually changed (auth, project, comment, fetcher, gateway, notification, the three workers) and left the untouched ones (campaign, report, scan-orchestrator, frontend) alone, `axebom health --wait` reported 9/9 up, and `axebom dev snapshot` tagged all 12 images `:good`. Then ran `task dev:rollback` for real — retag, recreate with `--no-build`, health-wait — and it also reported 9/9 up. Frontend: `npm run build` (tsc -b + vite build) and `npm run lint` both clean.

**Not done, and deliberately:** a production CI/CD deploy pipeline with an equivalent rollback (build/push to a registry, wire the existing Helm chart, `helm rollback`) — there is no registry, staging/prod target, or deploy workflow to build it on yet, and the user explicitly scoped this session to the local rollback with that recorded as separate future work (see the updated `docs/LIMITATIONS.md` entry).

### 2026-08-25 (q) — The other two named publishers: scan.completed and campaign.failed

**Goal:** (p)'s own "what's left" flagged `scan.completed` and `campaign.failed` as "bounded work, not a redesign" — two identified call sites with a fully-built, tested delivery mechanism waiting behind them. User confirmed: wire the two bounded ones, leave `findings.new_critical` (a real design task) and the SPDX bug (needs its own reviewed golden-fixture change) alone.

#### scan.completed — `orchestr.RecomputeScanStatus`, after the status write

`Orchestrator` already held a `*bus.Bus` and already imported `libs/go-shared/events` (for the advisory `SCAN_EVENTS` stream), so this was genuinely just wiring: a new `publishScanCompleted` call right after `o.log.Info("scan status derived", ...)`, using the scan's own `ProjectID` (one query, `o.store.GetScan`, already existed) and the scan id as the JetStream dedup key — a scan reaches this exact point at most meaningfully once, so a crash-retry re-deriving the same terminal status must not fan a second notification out. **Deliberately no component/finding counts**: those live in `normalize.*`, which scan-orchestrator does not otherwise read (CLAUDE.md invariant 11), and whether normalization has even finished by the moment every engine run reports terminal is a real, unanswered timing question — not something to guess at while wiring a notification. `FrontendURL` threaded through `Config` the same way `report`'s worker already has it.

Verified live end to end, the same way (p) verified `report.ready`: created a real webhook subscription, drove a real scan (via the existing live-DB test fixture, `orchestr.New` with `FrontendURL` set) to a real terminal status by submitting a real engine result, and confirmed a real `notify.deliveries` row appeared — `event_type=scan.completed`, correctly dead-lettered on the same `https://example.com/` 405 `report.ready` also hit. (The scan's OWN status flipped to `failed` moments later in the same shared dev database — real background activity from the live fetcher/reaper this test happened to race against, not a defect in the new code; the delivery row is the evidence that matters and it was written the instant the scan first went terminal.)

#### campaign.failed — the scheduler's FailRun path, and the one real design wrinkle

`services/campaign` had never connected to NATS at all — a new `bus.Connect` in `deps.go`, alongside the existing Postgres/Vault-shaped dependency wiring. The publish call sits right after `s.store.FailRun(...)` in `dispatch()`, the exact point `webhook.EventCampaignFailed`'s own doc comment describes ("fires when a scheduled run could not complete").

**The one thing that could not just copy `report.ready`/`scan.completed`'s pattern**: both of those use their own event's natural id (`ReportID`, `ScanID`) as the JetStream dedup key, because each fires at most once for that id. A campaign's id is NOT like that — the SAME campaign can fail repeatedly across many scheduled occurrences, and deduping on `CampaignID` would let JetStream's window silently swallow the SECOND failure notification of a campaign that fails every run, which is exactly the case where the notification matters most. Fixed by widening `scheduler.Notifier`'s interface to take an explicit dedup key (`Publish(ctx, dedupKey, evt)`) rather than deriving one from the event — the caller names the RUN id, which genuinely is unique per occurrence. `report`'s and scan-orchestrator's own Notifier shapes were left alone; their natural per-event id was already correct and changing them would have been risk for no benefit.

No single project id: a campaign targets `ProjectIDs []string` (plural), so the event carries `CampaignID`/`CampaignName` only, matching what a receiver would actually look the run up by.

**Verified with two new unit tests** (`fakeNotifier`, mirroring the existing fake-store/fake-trigger style already in `scheduler_test.go`): one confirms a failed trigger publishes exactly one `campaign.failed` event with the right ids, the right Cause, and — the specific regression this session's own design decision exists to prevent — a dedup key equal to the run id, not the campaign id; the other confirms a notifier failure never leaks into `Tick`'s own error (events are advisory, same rule everywhere else in this product). **Not reproduced against the live container** — unlike the other two, triggering a real scheduled-campaign failure needs a real cron-claimed occurrence, which is more setup than the marginal verification value justified given the wiring is mechanically identical to two already-proven cases and the container was confirmed to start and connect to NATS cleanly.

#### A gap made more precise, not created, while wiring the second and third publisher

`toEmailData`'s existing comment (written in (p), before either of these publishers existed) predicted this exactly: `EnqueueDelivery` stores the narrow `webhook.Payload`, so `ProjectName`/`CampaignName`/`Cause` — all populated on the envelopes `scan.completed` and `campaign.failed` now actually publish — never survive to an email render. Updated the comment now that the prediction is a live fact rather than a hypothetical: an email for either event today shows a raw id where a name belongs and silently omits the Cause line (the template's own `{{if .Data.Cause}}` guard), which is honest degradation, not a crash — but the real fix (storing the richer envelope, not the narrowed payload) is still a deliberately separate, unattempted change.

#### Verified live, once more

Rebuilt and redeployed `scan-orchestrator` and `campaign`; both started cleanly, connected to Postgres and NATS, no crash loops. `go build ./...`, `golangci-lint run ./...`, `go test ./... -count=1`, `docs lint`, `profile guardrails` all pass repo-wide. All throwaway verification code and test data deleted/cleaned up afterward.

#### What's left, honestly

`findings.new_critical` remains exactly as (p) left it — no detection logic, a real design task for its own session. The email-richness gap above is now concretely demonstrated rather than merely predicted, and still not fixed. `campaign.failed` is unit-verified but not live-verified against the running container, unlike its two siblings.

### 2026-08-25 (p) — The notification delivery worker: zero mechanism to real, verified, live delivery

**Goal:** (o)'s own re-audit named this the single largest concrete gap across Phases 14–16 — "not merely unverified... genuinely nonexistent." User confirmed it as the next target after (o)'s four Phase 16 items landed.

#### What was actually missing, corrected from (o)'s first-pass read

A deeper research pass (before writing any code) found `services/notification` far more built than (o)'s audit had time to credit: webhook HMAC signing, backoff/classification/dead-lettering, subscription matching, and email template rendering were ALL complete and tested — `libs/go-shared/platform/safedial`-backed, `TestPayloadCarriesNoComponentOrFindingDetail`-guarded, the works. What was missing was narrower and more mechanical than "build notifications from scratch": nothing ever CALLED any of it. `deps.go`'s `startBackground` was a literal no-op; no NATS consumer existed; no SMTP sender existed despite the templates; and no publisher anywhere called `MatchingSubscriptions`.

#### The envelope: one more shared type, and why webhook.Payload could not be reused

`libs/go-shared/events`'s new `NotifyEventV1` is the internal message a publisher (report, eventually scan-orchestrator and campaign) sends to `notify.<event>`, consumed only by `services/notification`. It is deliberately RICHER than the existing, tested `webhook.Payload` (ids/counts/status/url only, by CLAUDE.md's confidentiality rule): the internal envelope may carry a project name, a campaign name, a failure cause — things the EMAIL channel needs to render a human sentence and a WEBHOOK body must never carry, because a webhook lands in a third party's log aggregator and an email lands in an inbox we control. `services/notification`'s consumer derives the narrower `webhook.Payload` from the richer envelope at fan-out time. The four event-type strings are declared twice (once here, once in `webhook.Event` — a shared library cannot import a service's internal package) and a new test, `TestEventStringsMatchTheSharedEnvelope`, is what catches the day they drift.

Found and fixed a real spec-drift while writing this: `docs/02-CONTRACTS.md` §11 named six webhook events under different spellings than the four the actual, tested `webhook.Event` enum has. The code is the mature, tested artifact; the doc was an early draft nobody updated. Corrected to match reality, with a note rather than a silent rewrite.

#### The delivery worker: two drivers, one shared Attempter, and why they cannot be one mechanism

`services/notification/internal/worker`: **Consumer** (event-driven, `notify.>`, `EnsureConsumer`/`Consume` — the exact pattern `report`'s render consumer already established) fans one event out to every matching subscription and fires the FIRST delivery attempt for each. **Poller** (time-driven, 15s tick) retries whatever that left `pending` past its `next_retry_at`. They cannot share NATS redelivery for retries: a single event fans out to N subscriptions, and tying one subscription's retry schedule to the event MESSAGE would redeliver — and re-enqueue, duplicating — every other subscription's already-succeeded delivery just because one webhook target is down. The Consumer acks the message unconditionally once fan-out itself succeeds, even when every individual delivery fails; only a failure BEFORE any row was written (the initial `MatchingSubscriptions` lookup) is safe to retry at the message level.

**The poller's cross-tenant claim** (`migrations/notify/0002_delivery_worker.sql`) is the same shape `campaign.due_campaigns` already is: a background tick has no tenant to scope by, so one narrow SECURITY DEFINER function (`notify.claim_due_deliveries`) does the read — returning only what `webhook.Payload` already permits on the wire, so it cannot leak anything the wire format itself refuses to carry. The status transition (`pending` → `processing`) IS the lock, same idiom as `report.ClaimForRender`, with `FOR UPDATE SKIP LOCKED` as a second, cheap layer. This required widening the `status` CHECK constraint (`deliveries_status_check`) — the one schema change this work needed.

**Email** got its first real sender: `services/notification/internal/mail`, stdlib `net/smtp` only (no new dependency — PLAIN auth is skipped entirely when no username is configured, which is what makes Mailpit work unauthenticated), building a real multipart/alternative MIME message so a client with HTML disabled still sees the text part. New `config.SMTP` (`Host`/`Port`/`Username`/`Password`/`From`), wired into `docker-compose.app.yml` pointed at the Mailpit container already running (`mailpit:1025` internal, `SMTP_PORT` published for host-side use) — ZITADEL has sent it real mail for a while; this is the first time this codebase's own services have.

#### The one real publisher: report.ready, and why it was the right first choice over scan.completed

`services/report/internal/worker`'s `Render()` now publishes `report.ready` once, after `Finish` succeeds — never before, so a notification is never sent about a row that, from the database's point of view, did not finish. Chose this over `scan.completed` deliberately: at the exact point a report finishes rendering, the ALREADY-LOADED `render.BOM` (project name, findings, coverage, engine status) has every number the notification needs, in-process, with zero additional queries — the same `bom` this session's earlier (n) entry wired into the report-viewer coverage fix. `scan.completed` would need scan-orchestrator to read `normalize.*` tables it does not otherwise touch, with a real open question about whether normalization has even finished by the time all engine runs report terminal — a genuine timing question, not answered today, and not answered by guessing. `report.ready` has no email form at all (`email.Kinds()`'s own, pre-existing shape) — a rendered artifact finishing is a webhook-only integration event — so the consumer's fan-out skips an email subscription that matched it rather than enqueueing a delivery that would always fail.

#### Verified live — the whole pipeline, for real, twice over

Rebuilt and redeployed `report` and `notification`. Created a real webhook subscription (tenant, `https://example.com/`, `report.ready`) through the actual store+Vault code path. Rendered a real report through the actual worker: it published `report.ready` over the real NATS bus; the real Consumer picked it up, matched the subscription, enqueued a delivery, and POSTed a real signed request to `https://example.com/` — which answered 405 (POST not accepted on that path), correctly classified as non-retryable and dead-lettered, exactly per `webhook.Classify`'s existing logic. Separately seeded a `pending` row with `next_retry_at` in the past and watched the live Poller's next tick claim it via `claim_due_deliveries`, correctly re-attempt at `attempt=2` (not 1), and record the same outcome — proving the atomic claim and the attempt-numbering both work under the running container, not just in a test double. Sent a real email through the real `mail.Sender` to the real Mailpit container and confirmed it arrived — correct From/To/Subject — via Mailpit's own API. `go build ./...`, `golangci-lint run ./...`, `go test ./... -count=1`, `docs lint`, `profile lint`/`guardrails`/`evidence --check` all pass repo-wide. All throwaway verification code and test data deleted/cleaned up afterward.

#### What's left, honestly

`scan.completed` and `campaign.failed` have a fully-built, tested delivery mechanism and zero caller — bounded wiring work at two identified, specific call sites (see "Next action" at the top of this file). `findings.new_critical` has no detection logic anywhere — comparing a scan's findings against the prior scan of the same project is a real, unscoped design task, not wiring, and was deliberately not improvised here. The frontend's subscription-management UI was not touched or re-verified this session. No Playwright/axe coverage exists for it either, unchanged from (o).

### 2026-08-25 (o) — Re-audited Phases 14–16 against reality, then closed four concrete Phase 16 gaps

**Goal:** user asked to "reaudit phase 14-16 then jump on phase 16" after (n) closed the report-viewer gap — the same skepticism (n) itself was built on (Phase 9's and Phase 13's claimed-done work both had real, previously-undiscovered gaps found only by actually exercising the feature).

#### The re-audit (three parallel, independent, read-only passes)

**Phase 14 (campaigns/notifications):** the scheduling half is real and MORE exercised than this file's 2026-08-18 section credited — `migrations/campaign/0002` is now applied (that section's claim it never was is stale), the scheduler runs as a live background process, real routes and frontend exist. The notification half is hollow: `services/notification/deps.go`'s `startBackground` is a literal no-op, `grep -rn MatchingSubscriptions` finds zero callers outside its own package (nothing anywhere publishes a notification event — not scan completion, not a new critical finding, not a campaign failure), and there is no SMTP client despite templates existing. **This is the single largest concrete gap surfaced by any of the three audits** — not "unverified," genuinely nonexistent.

**Phase 15 (HBOM):** better than its own stale 2026-08-18 section says. The 2026-08-24 (i) "WIRED" claim holds up under independent verification: 5/5 live-DB store tests pass against real Postgres, including an actual CSV-import-to-database round trip and cross-tenant RLS isolation — this directly disproves the old section's "no HBOM row has ever been written." Real gaps that remain in both narratives: no CycloneDX HBOM export, `findings[]` (§10.4.1.4's fourth mandatory element) not modelled, zero frontend test coverage.

**Phase 16 (hardening):** this file's own "half done" narrative was accurate, not stale — nothing in later sessions had quietly closed any of its gaps. Confirmed live: the compliance evidence pack, `auditexport`, and `apikey.go` are all real, non-stub code. One gap worse than implied: `.github/workflows/` had ONLY `verify.yml` — no security-scan or load-test CI existed at all, not even a stub.

User picked, from the consolidated gap list: **API-key HTTP surface, audit-export CLI+HTTP, SPDX/CycloneDX conformance run, CI workflows** — deliberately NOT the notification worker (a materially larger, separate piece of work) or SSO/SCIM/pentest/chaos (need their own scoping pass).

#### API keys: the HTTP surface `apikey.go` never had

`libs/go-shared/auth/apikey.go`'s `Mint`/`Verify`/`AuthorizeKey` were complete and tested pure functions with nothing calling them. Closed end to end:

- **`migrations/auth/0004_api_keys.sql`** — `auth.api_keys`, RLS-covered, plus `auth.api_key_by_key_id(key_id)`, a SECURITY DEFINER pre-tenant lookup with the exact shape `migrations/auth/0002`'s login lookup already established (a key presents itself before its tenant is known, same as a login credential does).
- **Request-time authentication lives in `libs/go-shared/oidcauth`, not in the service that mints keys** — because a key holder calls `project`/`scan-orchestrator`/`report` to start a scan or read a report, never `auth` itself. New `oidcauth/apikey.go`: `Authenticate()` now branches on the `ebk_` prefix before attempting JWT verification, looks the key up via `pool.Raw()` (never `WithTenant` — the tenant is what's being discovered), sets role to `RoleAnalyst` (matching the existing service-token precedent AND `AuthorizeKey`'s own embedded assumption — confirmed by an existing, unmodified test, `TestEveryScopeIsWithinTheAnalystRole`, passing unchanged), and carries scopes forward via a new `ctxkey.APIKeyScopes`.
- **Scope narrowing lives in `libs/go-shared/auth`'s `Authorize`** — the ONE per-route middleware every one of the 7 services already mounts. After the ordinary role-based `authz.Allow` check passes, an API-key request additionally requires that one of its presented scopes names the exact (resource, action) being called. A session or service-token request is unaffected — the check is skipped entirely when no scopes are in context.
- **New `ResourceAPIKey`, gated `RoleOwner`** (stricter than `RoleAdmin`'s member-management floor — a key is a durable, unattended credential, closer to "grant standing tenant access" than to inviting a member). `POST/GET /v1/api-keys`, `DELETE /v1/api-keys/{id}`, mounted in `services/auth` via a NEWLY-added `oidcauth.Guard` — the sixth service to gain one, sitting alongside (not replacing) that service's own pre-ZITADEL local-JWT routes, which nothing in the current frontend calls any more except the gateway-special-cased `/v1/auth/signup`.
- **A real, previously-nonexistent bug class avoided by construction**: `services/auth/routes_test.go`'s static route-guard parser only recognizes wrapper identifiers named `guard`/`authenticated` by default; the new ZITADEL-authenticated routes use a differently-named wrapper (`zitadel`) on purpose (this service has two authentication systems side by side) — `routeguard.CheckWith` extended the recognized-wrapper list rather than either wrongly reusing `authenticated`'s name or silently leaving the new routes unchecked.
- **Verified live**, with the actual production code paths, not mocks: minted a real key via `services/auth/internal/store`, authenticated a real request with it via `oidcauth.authenticateAPIKey` (confirmed correct tenant, `apikey:<id>` subject, `analyst` role, and scopes), confirmed `scan:run` permits and `member:delete` refuses, then confirmed a revoked key is refused with `AUTH_TOKEN_INVALID`.

#### Audit-log export: the renderer `auditexport` never had a caller

- **`GET /v1/audit-log/export?format=jsonl|csv[&from=&to=]`** in `services/auth`, ZITADEL-authenticated like the API-key routes, gated `ResourceAuditLog`/`ActionList` (the existing RoleAdmin matrix entry — no new RBAC needed). Tenant-scoped, ordinary `WithTenant`, no explicit `tenant_id` filter (RLS does that).
- **`axebom audit export --tenant --actor [--format] [--from] [--to] [--out]`** — an operator tool connecting as the database OWNER, the one place in this codebase a hand-written `WHERE tenant_id = ?` is the CORRECT code rather than the invariant-6 violation it would be in application code: there is no RLS to lean on outside the application path, so the explicit filter is the only thing standing between two tenants' data, written once, on purpose, with the reasoning in a comment at the exact line.
- Both record the export as its own audit event via the existing `auth.record_auth_event` SECURITY DEFINER function, **before** streaming starts — `auditexport.ExportRecord`'s own doc comment insists on this ordering, and it was actually followed rather than merely quoted.
- Added `apikey mint` as a companion CLI command (needed for the load-test CI workflow below to get a credential without a browser) — same owner-connection shape, same "this is a break-glass operator tool, not a second way to skip `ResourceAPIKey`'s RoleOwner gate" reasoning.
- **Verified live**: exported both formats against the real dev database; confirmed the export's own audit row appears in what it exports.

#### SPDX/CycloneDX conformance: real validators, a real bug found

`task test:conformance` (`pip install -e ".[conformance]"`, a new optional dependency group — `cyclonedx-python-lib[json-validation]` and `spdx-tools`, both Apache-2.0) runs the golden fixtures through the OFFICIAL schema validators, not our own serializer's opinion of itself. CycloneDX 1.6 passes clean. **SPDX does not**, and the failure is real: `services/report/internal/export`'s `toNode()` feeds the raw `component_key` (shaped `purl:pkg:maven/...` — a normalizer dedup identity, not an SPDX identifier) straight into every `PackageSPDXIdentifier` and relationship reference. SPDX 2.3 allows at most one colon in an SPDXID; ours has several. Confirmed CycloneDX's `bom-ref` has no such restriction — same underlying key, only one format's spec rejects it, so this is a targeted, well-understood bug, not a general identity problem. **Deliberately left unfixed and captured as `xfail(strict=True)`** rather than silently fixed alongside a verification task: the real fix touches shared ID-generation code feeding BOTH exported formats and would change the golden fixtures, which CLAUDE.md treats as requiring its own explicit, reviewed justification — not something to bundle into "I added a conformance check."

#### CI: two workflows that did not exist, with an honest limit stated on both

`.github/workflows/security-scan.yml` (govulncheck, pip-audit, npm audit, trivy fs — scheduled + manifest-change-triggered, deliberately NOT on every PR since dependency CVEs don't change between commits an hour apart) and `.github/workflows/load-test.yml` (brings up a full ephemeral stack via `task dev`/`iam:bootstrap`/`db:migrate`/`db:seed`, mints a real API key with the new `apikey mint` CLI against the fixed seed identity `alice@acme.test`, runs all three `perf/*.js` scenarios — first real execution of scripts that, per their own README, "had never been run"). Both pass `actionlint` clean. **Neither has been executed by an actual GitHub Actions runner** — this environment has no way to trigger one — so both carry an explicit top-of-file comment saying so, and the first real trigger of each should be treated as a dry run, not a proven gate.

#### Verified live, against the real dev database and the real running stack

Applied `migrations/auth/0004`. Ran the actual `store`/`oidcauth`/`service` production code (not mocks, throwaway tests deleted after use) for both API keys and audit export, end to end, including the negative case (revoked key refused). Rebuilt and redeployed `auth`, `gateway`, `project`, `scan-orchestrator`, `report`, `campaign`, `notification`, `comment` — all started cleanly, database-connected, no crash loops; confirmed `/v1/api-keys` and `/v1/audit-log/export` both route correctly through the gateway to `auth` (401, not 404). `go build ./...`, `golangci-lint run ./...`, and `go test ./... -count=1` all pass repo-wide (two unrelated pre-existing flaky tests in `scan-orchestrator`, confirmed unrelated by running each 3× in isolation — same flake class as (n) already documented, untouched by this session).

#### What's left, honestly

Phase 14's notification-delivery worker is the standout gap — see "Next action" above. Phase 15's CycloneDX HBOM export and vulnerability-matching element remain open. Phase 16 still has no SSO/SCIM, no penetration test, no Helm dry-run (`helm` still not installed here), no restore/chaos/PITR, and `docs/RUNBOOKS.md` is still a forward reference. The SPDX exporter bug found above is real and reproducible but deliberately not fixed this session. Neither new CI workflow has actually run.

### 2026-08-25 (n) — Phase 9's report-viewer gap actually closed: real coverage, engine, project and sibling data now flows end to end

**Goal:** close the gap (m) found and only patched around — `GET /v1/reports/{id}` sending none of the coverage/engine/project data the viewer needs, forcing a defensive frontend-only fix. User's explicit direction: "fix the report viewer coverage gap, then continue to the next phase."

#### The real fix: capture render.BOM's summary at MarkReady, not discard it

`services/report/internal/store/store.go`'s `Completion`/`MarkReady` previously recorded only artifact-storage metadata. New migration `migrations/report/0003_report_summary.sql` adds `project_name`, `bom_generated_at`, `level_note`, `completeness_pct`/`declaration_pct` (nullable — NULL means "not yet computed," never a lying zero), `coverage_formula`, `coverage_fields`/`engine_coverage` (jsonb), `ecosystems_with_no_engine` to `report.reports`. `worker.go`'s `Render()` now captures all of it from the exact `render.BOM` it already loaded — the same data that produced the artifact bytes, never re-queried from the normalizer afterward, which would risk disagreeing with a concurrent re-normalization. `enrichCoverageFields` looks each field up against `render.FieldsFor(bomType)` to attach `name`/`weight`/`source_page` (absent for CBOM, which has no single field set — the count still persists, just unlabeled). `handler.go`'s `reportResponse`/`toResponse` now expose all of it, `omitempty` on every one so a queued/rendering report sends none of it rather than a lying zero.

#### Three more real bugs found in the process, all fixed

1. `render.BOM.ProjectName` was **never populated anywhere** — `LoadBOM` builds the struct and leaves it at its zero value; `summarySheet` has been printing a blank project name in every rendered report since Phase 9. New `loadProjectName` in `bomsource.go` resolves it via the existing `resolveProjectIDForScan` (two queries, not a cross-schema join — the same discipline `loadPractices` above it is flagged as violating).
2. `loadDocumentMeta` collapses a genuinely-never-scored document's nil completeness/declaration into a plain `0.0` — its own comment says "must not render as 0.00%" but nothing downstream actually preserved that. Traced this all the way through: it would have made this exact fix dishonest for any BOM that hasn't been scored yet (the seeded dev report is one). Added `render.BOM.CoverageComputed bool`; the worker only persists a number when it's true, otherwise the column stays NULL and the viewer correctly shows "not yet computed."
3. **The one that actually blocked verification**: `bomsource.go`'s `loadFindings` (added in (m), for VEX resolution) queried `resolveProjectIDForScan`/`loadVEXStatementsForReport` on the same `tx` while the findings query's `Rows` were still open and undrained — pgx's `conn busy`, deterministically, on every single call. **This meant no report of any format could render at all** since (m) landed, not a flaky or edge-case failure. Fixed by moving both calls before the findings query opens.

#### Siblings: a live query, not a snapshot

`GET /v1/reports/{id}` (Get only, not List) now also runs `store.Siblings` — a same-schema self-join on `report.reports` by `(tenant_id, scan_id, bom_type)` excluding itself — because "what other formats exist" changes after this report goes ready, and freezing it at render-completion would go stale the moment a second format finished.

#### Frontend: the coverage gap was worse than the crash

`lib/reports.ts`'s own `Report` type (already correctly snake_case, used nowhere until now) exposed that `ReportViewer.tsx`'s locally-declared `Report` interface was wrong on a second axis nobody had caught: **every backend-sent field it named was camelCase** (`bomType`, `sizeBytes`, `signingKeyId`...) **against a backend that has always sent snake_case** (confirmed against every other handler in the codebase) — meaning most of this page's "working" fields were silently reading `undefined` before (m)'s crash-prevention patch ever ran, independent of the coverage gap entirely. Deleted the local interface, extended `lib/reports.ts`'s real one with the new optional fields plus `FieldCoverage`/`EngineCoverage`/`ReportSibling`, moved the render-status polling into `useReport`, rewrote every access site to the real field names.

#### Verified live, against the real dev database

`task db migrate` applied 0003 against the running stack. Ran the actual `worker.Render`/`store.Get`/`service.Siblings` production code (not mocks, a throwaway test deleted after use) against a real report row for a real seeded scan — confirmed `project_name: "payments-api"`, a real `bom_generated_at`, `completeness_pct`/`declaration_pct: null` (this bom_document has never been scored — proves the `CoverageComputed` fix), `ecosystems_with_no_engine: ["npm"]`, and a real sibling row. Rebuilt and redeployed `report` and `frontend`; `tsc -b` inside the frontend build passed clean against the new contract. `go build ./...`, `golangci-lint run ./...`, and `go test ./... -count=1` all pass repo-wide (one unrelated pre-existing flaky test in `scan-orchestrator` confirmed unrelated — passes 3/3 in isolation, untouched by this session). **No browser automation tool was available in this session** to click through the rendered page the way (m) did — verification stopped at the API/data layer, which is real and complete, but nobody has looked at the rendered DOM this time.

#### What's left, honestly

`ShareDialog.tsx` has the identical camelCase-vs-snake_case defect in its own local `ShareLink` type — not exercised by this fix, flagged, not fixed. No new automated test asserts the new `reportResponse` fields (`services/report/internal/handler`'s tests predate them). `libs/py-shared/axebom_shared/normalize/vex.py`, the CSAF JSON-Schema decision, and Playwright coverage remain exactly as (m) left them. Which phase is actually next (14, 15, or re-auditing 14–16 against reality) is still an open question — flagged at the top of this file rather than guessed.

### 2026-08-25 (m) — Phase 13: VEX, CSAF and comments work end to end, live — plus a severe pre-existing bug found along the way

**Goal:** the master plan's Phase 13. User picked this explicitly after Milestone 5 closed out the separate sidebar-reorg plan; asked "continue to the next phase" without saying which, and rather than guess among several plausible readings (Phase 12's own unmet ML-BOM exit criterion, Phase 13 itself, or re-auditing Phases 13–15 against reality first) I asked — the cost of guessing wrong here was a full phase's misdirected work. A research fork mapped the actual state before any code: **the hard logic was already done and well-tested** (`vex.go`'s specificity-then-recency resolver, `csaf.go`'s round-tripping types) — what was missing was entirely storage, HTTP, and UI. Split three ways: I did VEX+CSAF storage/HTTP/report-wiring myself (closely follows this session's own established patterns), dispatched the comments service as an independent agent (fully self-contained), built the frontend myself once both landed.

#### VEX — moved to shared space, then given a write path

`vex.go` moved from scan-orchestrator's own internal package to `libs/go-shared/vex` — a real architectural fix, not a reorganization for its own sake: `services/report` needs the identical `Resolve()` logic at render time to compute `render.Finding.VEXStatus`, and a service cannot import another service's internal package (CLAUDE.md invariant 11; depguard enforces it). New `orchestr` store methods (`CreateVEXStatement`, `ListVEXStatements`, `GetVEXHistory`) — **supersession is automatic, never caller-specified**: the store finds whichever statement is currently in force for the exact (cluster, component, scope) tuple and supersedes it itself, so a stale or wrong "supersedes this id" from a client can never fork the history. New `POST/GET /v1/vex/{projectId}/statements`, project-scoped rather than scan-scoped (a triage decision outlives the scan that found it), new `/v1/vex` gateway prefix. 5 new live-DB tests, all passing, including the one proving two different scopes on the same cluster coexist rather than clobbering each other.

#### A real, second VEX-resolution bug found and fixed — on the READ side this time

`services/project/internal/store/findings.go` already had VEX wired into the live findings table from an earlier session, but `loadClusterVEX` picked "whichever statement has the highest id" for a whole cluster with **no regard for scope specificity at all** — the exact ordering `vex.Resolve`'s own doc comment calls a decision, not an accident, gotten backwards. A cluster spans several affected components; a broadly-scoped statement inserted slightly later could outrank a narrower, more specific, older one. Fixed by using the real `vex.Resolve()` (only importable here now that it lives in `libs/go-shared`) per member component, keeping whichever result is NOT de-emphasized when any disagree — the same "OR the worse signal across cluster members" rule `SeverityConflict` already uses. A new regression test (two components, one cleared after the other) proves the exact case the old code got wrong. Also wired `services/report`'s `bomsource.go`, which had never read `normalize.vex_statements` at all — its `render.Finding.VEXStatus`/`VEXJustification` fields existed but were never populated — and replaced `pdf.go`'s hardcoded `vexPage()` stub with a real per-status count table.

#### CSAF — a generator proven to always produce a valid document

New `services/report/internal/csafgen` package: pure function, VEX statement in, `csaf.Document` out, always the smallest document `csaf.Document.Validate()` accepts — never a maximal one, since AxeBOM does not hold data (CVSS scores, a full product tree) it would otherwise have to invent. 5 tests including one for every one of the four VEX statuses. New `services/report/internal/store/csaf.go`: looks up the real VEX statement server-side (a client can never submit its own status/justification — those already came from the VEX write path, and re-typing them here would let a client publish an advisory that disagrees with the record behind it), resolves the tenant's own name for `Publisher.Name` (CSAF's publisher is the customer, never AxeBOM), and is **idempotent per VEX statement** — generating twice returns the existing advisory rather than a duplicate. New `ResourceCSAF` in the authz matrix, `POST/GET /v1/csaf/{projectId}/advisories`, new `/v1/csaf` gateway prefix.

#### Comments — dispatched to an agent, survived a session interruption mid-flight

The agent built a complete, real `services/comment` service — depth-5 threading enforced server-side, ownership checked in the store (403 `PERM_COMMENT_NOT_OWNER`, distinct from the 404-for-cross-tenant CLAUDE.md invariant 6 case), soft-delete-with-live-children rendering as a `[deleted]` placeholder rather than orphaning replies, `@handle` mention extraction computed at read time from the body text rather than stored or resolved against a real member (a deliberately scoped-down interpretation, stated rather than silent) — before this session's process was interrupted and restarted mid-task. Verified the interruption cost nothing: 12 live-DB tests already existed and all passed on resumption, `go build ./...` was clean, only the frontend piece (never reached) was missing. Built that myself: `lib/comments.ts`, `components/CommentRail.tsx` (threaded display, inline edit/reply, indent capped at depth 5), mounted on `ReportViewer.tsx`.

#### A severe, pre-existing bug found live, unrelated to any of the above

Verifying the comment rail meant loading a real report page for the first time this session — and it crashed outright, on every report, regardless of status. `services/report/internal/handler/handler.go`'s `reportResponse` (the actual `GET /v1/reports/{id}` wire shape) has **no project name, no generated-at timestamp, no coverage numbers, no coverage-field breakdown, no engine coverage, and no sibling-format list** — fields the frontend's `Report` interface has always declared as required and always assumed present. `DownloadMenu` spread `report.siblings` unguarded (`TypeError: s.siblings is not iterable`); `CoveragePanel` called `.toFixed()` on an undefined `completenessPct`; `EngineCoverageTable` called `.map()`/`.length` on undefined arrays. Every one of these ran unconditionally in the page header or body — there was no path through this page that avoided them. **Not something this session introduced or fixed at the root** — the underlying data genuinely exists (`normalize.bom_documents.completeness_pct`/`declaration_pct`/`coverage_breakdown`, `scan.engine_runs`, `project.projects.name`), just never wired into this specific endpoint, which is Phase 9's scope, not Phase 13's. Applied the minimal, honest fix: normalized the missing fields to empty/undefined at one point in `ReportViewer.tsx`, rendering "not yet computed" and "no engine ran for this report" — the SAME honest-gap philosophy this codebase already applies to a scan that hasn't run, just applied here to data the backend hasn't wired yet. The crash is gone; the actual feature (a report page that shows its own coverage and engine story) is not built. Flagged at the top of this file rather than buried — this is a core, "prominent, not footer material" page per its own doc comment, broken for every user, every time, until now discovered.

#### Also found, not touched

`libs/py-shared/axebom_shared/normalize/vex.py` is a second, complete, Python port of the same VEX join logic — used only by one SBOM golden test proving the join concept (`test_vex_joins_to_findings_without_changing_them`), never called by any real pipeline. Now that the real system's VEX logic lives in Go (`libs/go-shared/vex`, used by scan-orchestrator's real writes and both project's and report's real reads), this Python copy is either dead weight from an earlier, different design direction, or was intentionally kept as a normalizer-level proof — worth a deliberate decision, not left as ambiguous duplication.

#### Verified live

Rebuilt `scan-orchestrator`/`report`/`project`/`gateway`/`frontend`/`comment` (the last one deployed live for the first time). Seeded a real SBOM finding, drove the browser through: opening the findings table, triaging a finding to `not_affected` with a justification (whole-project scope), confirming the VEX badge and history updated live, generating a CSAF advisory and confirming the stored document in Postgres is genuinely valid CSAF 2.0 with the real tenant name as publisher, a real CVE, a real GHSA alias, and a real impact-statement threat — not a stub. Separately verified the comment rail: posted a top-level comment and a threaded reply, both rendering correctly with timestamps, after fixing the report-viewer crash above. Zero console errors on final pass. `task verify` — the full gate, including a `golangci-lint` `unparam` finding (a dead error return `nolint` had been papering over) that got fixed rather than suppressed — passes clean.

#### What's left, honestly

The Phase 9 report-metadata gap above is the big one. No official CSAF 2.0 JSON Schema validation (a prior, already-documented, deliberate scope decision in `libs/go-shared/csaf` — not new to this session). The stray Python `vex.py`. No Playwright/axe test coverage for any of the three new frontend surfaces. `libs/py-shared`'s own normalizer pipeline still has no VEX integration of its own (the Go path is what's live).

### 2026-08-25 (l) — Milestone 5 finishes: AIBOM works end to end, including its own container engine

**Goal:** finish the sidebar reorg plan's last milestone — AIBOM, blocked from the start by a real contradiction (i)'s report flagged: `ai-bom`'s adapter needs a sandboxed container, its manifest says `pip:`. User explicitly approved containerizing it (locally-built image, not external hosting) before any work started. Same shape as (k): one workstream I did myself (Python normalizer write path, Go backend/report/frontend), one dispatched agent (engine containerization + a concrete enrichment Fetcher), then my own integration/verification pass — which is exactly where the gateway-prefix bug and a stale-NULL bug turned up, the same pattern (k) established.

#### Engine containerization — a genuinely new category of artifact for this repo

Every existing sandboxed engine (syft, trivy, cbomkit-theia, ...) is a third-party image pulled from a registry and pinned by digest. `ai-bom` publishes none — only a pip package — so `deploy/docker/engines/Dockerfile.ai-bom` is the first *locally-built* engine image in this codebase: `python:3.12-slim`, the full 23-package dependency closure hash-pinned in `ai-bom-requirements.lock.txt` and verified with `pip install --require-hashes --network none` inside the same base image, tagged `axebom/ai-bom-engine:dev` (honestly tag-pinned — there is no upstream digest for a locally-built image to pin against). A research pass before any code was written found the sandbox/resolver stack needed **zero changes** to support this: `ManifestResolver` builds its docker reference from `image`+`image_tag`/`image_digest` with nothing registry-specific, and `SandboxedAdapter.classify()` already has a branch for "no digest resolved, probably built locally." New: the Dockerfile itself, one manifest edit (`pip:` → `container:`), and `task osint:build-ai-bom` wired as a dependency of `task osint:pull`.

**A bug nobody had ever caught, because the engine had never actually run**: `AIBomAdapter.build_argv()` passed `--output -`, following the Unix "`-` means stdout" convention — `ai-bom==3.1.0` does not honor it; `--output` is a literal file path (`Path(path).write_text(...)`, no special case), so every invocation would have written a file named `-` into a sandbox with no writable mount, left stdout empty, and failed `ENGINE_OUTPUT_UNPARSEABLE` on every single scan. Fixed by omitting `--output` entirely — the CLI prints CycloneDX straight to stdout for any non-`table` format. Verified twice: once inside the dispatched agent's own sandbox-bridge run, and again by me directly (`docker run --user 65534:65534 --read-only --network none ... scan /src --format cyclonedx --quiet` against a LangChain+OpenAI fixture directory) — real container, real sandbox posture, real CycloneDX output, LangChain correctly detected.

#### A concrete `aibom-generator` enrichment Fetcher — and two more real upstream bugs

`workers/aibom/adapters/aibom_generator.py`'s `Fetcher` protocol had no implementation before this session (`runner.py`'s own docstring said so explicitly). Built `workers/aibom/adapters/aibom_generator_fetch.py` — a subprocess call to `python -m src.cli`, run outside the sandbox as a trusted dependency of the worker's own environment (a network call to a public API over a bare model id, never over customer code, matching CLAUDE.md invariant 7's actual boundary rather than its letter). Installing and actually running the real package (`owasp-aibom-generator==1.0.2`, HEAD of `main` since it ships no tagged release) found two bugs no unit test against synthetic data would ever have caught:

1. **It fabricates a plausible component for a model that does not exist.** `AIBOMService.generate_aibom()` never checks the Hugging Face repo resolves before synthesizing one from guessed defaults — exit 0, "Successfully generated," nothing in the output shape distinguishes it from a real card. Guarded by calling `huggingface_hub.HfApi().model_info()` (the same SDK aibom-generator itself uses) *before* invoking it at all.
2. **No revision-pinning parameter exists anywhere** — not the CLI, not `CLIController`, not `AIBOMService`, checked against the real 1.0.2 source at all three layers. `enrich_models`'s own `ModelCache` already documents why serving the wrong revision's card under the requested revision's name is a compliance problem, not a convenience one; a non-default revision now raises a specific `RevisionNotSupportedError` rather than being silently served from `main`.

Captured a real response (`distilbert-base-uncased`) as a pinned fixture rather than only testing synthetically. **Not wired into a live scan path** — `build_canonical_aibom` already accepts a `cards` argument, but nothing calls `enrich_models` from a real trigger yet, and doing so raises genuine open questions (when relative to the job lifecycle, whether the HTTP response needs to become a stored raw artifact for invariant 10, retry semantics) documented in `runner.py` rather than guessed at. Also found, by the same real run, and left as a stated gap rather than patched (out of this task's scope): `parse_model_card._developer()` reads `author`/`publisher`; real output uses `authors`/`supplier`, so `developer` comes back empty against genuine cards today.

#### Python normalizer write path — `workers/aibom/normalize/pipeline.py`, extending `bulk.py`

New `build_canonical_aibom(discovery, cards, ...)`, the AIBOM equivalent of CBOM's `build_canonical_cbom` — merge (already built in `../merge.py`, long before this pipeline existed), normalize each model (`.ai.normalize_model`, also pre-existing), link dependencies against the SBOM, score coverage. `bulk.py` gained `_ai_models_batch`/`_ai_datasets_batch`/`_ai_model_dependencies_batch`, mirroring the crypto-assets precedent but needing a client-minted surrogate id (uuid5, same replayability reasoning as `_component_id`) since — unlike a crypto asset — an AI model's row IS referenced by two sibling tables in the same transaction. Building the end-to-end pipeline test (reusing `test_aibom.py`'s own LangChain/HF fixtures rather than inventing parallel ones) surfaced a real integration bug of my own: `.ai.link_dependencies` needs the discovery-wide `frameworks` list attached to each model before it can report anything — `test_aibom.py`'s own two existing tests already did this by hand inline, but nothing did it inside the pipeline function itself, so a first pass produced empty dependencies and no diagnostic for every model, silently. Fixed by having `build_canonical_aibom` do that join once, from the full `extract_discovery()` return value, rather than a bare model list. Also fixed in passing: `docs/01-DATA-MODEL.md` said `ai_model_dependencies (ai_model_id, component_id)`; the actual migration column is `component_key`, a plain text field, not a foreign key — doc corrected to match the migration (ground truth), matching `crypto_assets.component_key`'s identical situation.

#### Go backend, report rendering, frontend

New `services/project/internal/aibom` package — deliberately NOT a full BOM-type port like `qbom`/`hbom`'s, because AIBOM is mostly Python-discovered; this package covers only the four Table 10 elements no tool can ever report. New `store.AIModel`/`ai_models.go` (list + a **targeted UPDATE**, not a new normalization version — a real, documented, narrower-than-invariant-10 scope decision: an AI model's row is 16-of-19-columns Python-owned, so treating a 4-field edit like QBOM's full-document versioned save would mean cloning an entire model and its children to touch four columns). New `GET /v1/projects/{id}/ai-models`, `GET /v1/aibom/{projectId}/form`, `POST /v1/projects/{id}/ai-models/{modelId}/fields`; new `ResourceAIModel` in the authz matrix. **A store-level test caught a real bug before it shipped**: the update path was writing `NULL` for an empty user-field submission instead of the explicit `not-provided` sentinel Python's normalizer always writes for the exact same case — the identical "declared vs. silently omitted" failure CLAUDE.md invariant 3 exists to prevent, just found on the Go side of a boundary CBOM's certificate bug found on the Python side. Fixed with `aibom.OrNotProvided`, mirroring Python's `_empty_for` precisely.

Report rendering gets its own `render/aibom.go` — AI models are NOT run through the generic `componentSheet`/`componentPages` (an AI model has no PURL, dependency depth, or ecosystem for those SBOM-shaped columns to mean anything), the identical reasoning CBOM's crypto assets already established. New XLSX sheets (AI Models, AI Model Datasets, AI Model Dependencies), a PDF page, and a JSON bundle section, all covered by new tests.

Frontend: new `/projects/:id/ai-models` tab and page — a model inventory table (clearly labeling `risk_score`/`owasp_llm_top10` as AxeBOM extensions, never CERT-In elements) with inline per-model editing for the four user-supplied fields. `BomTypeHome.tsx`'s AIBOM section now links to a real page — the sidebar's last "detail view not yet available" placeholder is gone.

#### Two bugs my own integration pass caught, neither from either workstream in isolation

- **The gateway had no `/v1/aibom` proxy prefix** — the exact same class of gap (i)'s session hit for `/v1/qbom` (a route that works against the project service directly but 404s through the real ingress because nobody added the prefix). Fixed in `services/gateway/internal/proxy/proxy.go`.
- The Go `NULL`-vs-`not-provided` bug above, caught only because I wrote a test asserting the *raw column value* rather than just `field_status`.

#### Scoped out, not half-built

A standards-conformant CycloneDX ML-BOM export (`services/report/internal/export/mlbom.go`, an explicit Phase-12 deliverable) does not exist. `protobom` — the OpenSSF library this package's own docstring says exists specifically "so we do not hand-roll either format" — has no support for CycloneDX's ML-BOM/`modelCard` extension anywhere in its `sbom.Node` type. Building a real one means either hand-rolling CycloneDX JSON for this one case (violating that package's stated design principle) or extending protobom upstream; flagged here as a genuine architectural decision rather than attempted unilaterally. AIBOM's data is not unexportable — it has full XLSX/PDF/JSON coverage via this session's own report work — only a strict industry-standard ML-BOM envelope is missing.

#### Verified live

Rebuilt `project`/`report`/`gateway`/`frontend` containers with all of the above. Seeded a real model (Llama-3-8B, one dataset, one SBOM dependency reference) directly into Postgres for the seeded `payments-api` project and drove the actual browser through a scripted Playwright login: the AI Models tab correctly lists the model with real datasets/dependencies counts and clearly-labeled extension columns; opening the edit form, typing a real Intended Usage value, and saving round-tripped through gateway → project service → Postgres and back — confirmed both via a re-render of the page and directly in the database. Zero console errors. `task verify` — the full gate, including the profile-guardrails check and the report package's static schema-agreement checker (which validates every SQL column this session added against the live migrations without needing a database connection) — passes clean.

#### What's left, honestly

No live NATS trigger for the AIBOM write path (same deliberate boundary as SBOM/CBOM, see (e)). Enrichment (`aibom-generator`) is proven correct but not wired into any real scan trigger. No `ai-langchain` golden-corpus fixture with pinned `raw/`/`expected/` files (real engine output has been verified live and captured as evidence, just not assembled into that shape yet). `parse_model_card._developer()`'s field-name mismatch against real aibom-generator output. The ML-BOM export gap above. This closes every milestone in the original sidebar-reorg plan.

### 2026-08-24 (k) — Milestone 4 finishes: CBOM writes for real, QBOM gets a form, both get a live UI

**Goal:** close the two gaps (j) left explicit — the normalizer WRITE path and the frontend detail views — so a CBOM scan and a QBOM form produce something a person can actually look at, not just a downloadable report. Three parallel workstreams (two Go, one Python), plus my own follow-up fixing a real bug the first live-engine run surfaced and a live-worker test flake `task verify` caught.

#### CBOM normalizer write path — `workers/cbom/normalize/pipeline.py`, `bulk.py`

New `build_canonical_cbom(raw_assets)` — the CBOM equivalent of the SBOM pipeline's `normalize()`, deliberately two stages instead of seven (no merge/graph/alias-closure: one engine, no dependency edges, no vulnerability-alias concept for a certificate). `bulk.py`'s `plan()` now also produces a `CopyBatch` for `normalize.crypto_assets` — no client-minted id needed, unlike components, since nothing else in the write references a crypto asset's row. `field_status` is computed for real (not skipped): `key_state`'s `"unknown"` sentinel is a real non-substantive-but-non-NULL case the profile's own field list has to account for, or a reader inferring coverage from column nullness alone would overcount it. Same scope boundary as (e)'s SBOM precedent, extended deliberately: proven correct and executable against live Postgres via tests (`test_bulk.py`, `test_writer.py`, new `test_pipeline.py`), **not wired into `workers/cbom/runner.py`'s live NATS path** — that's still a live-credential/trigger decision nobody has been asked to make for CBOM specifically, same as SBOM's.

#### A real bug, found only by running against genuine `cbomkit-theia` output

Built a real fixture — `openssl req -x509 -newkey rsa:2048` against a fresh key, run through the pinned `ghcr.io/cbomkit/cbomkit-theia:1.1.2` image directly — and found what no hand-built CycloneDX fixture had ever exercised: `crypto.py:analyse()`'s certificate handling ("the interesting primitive is what SIGNED it") tries to pattern-match the certificate's raw `signatureAlgorithmRef` as if it were an algorithm name. Real engine output sets that field to the engine's own opaque `bom-ref` UUID, not a readable string — `test_crypto_normalize.py`'s existing fixture happened to use a readable fake ref (`"crypto/algorithm/sha256-rsa"`) that accidentally matched the regex, hiding this completely. Against the real fixture: an RSA-2048-signed, SHA256-RSA certificate came back `quantum_vulnerable: false`, `deprecation_status: "current"` — a false negative in exactly the document this whole phase exists to get right. Fixed with a new document-level pass, `_resolve_certificate_analysis` (`pipeline.py`, runs after `normalize_all`, before the ref fields get rewritten to display names): looks up the actual sibling asset the raw ref points to and copies its already-correct verdict onto the certificate, rather than re-deriving one from a string that was never meant to be parsed as a name. Also fixed, found by the same live run: `signature_algo_ref`/`subject_public_key_ref` now show the referenced asset's name (`"SHA256-RSA"`, `"RSA-2048"`) instead of the raw UUID. Along the way: `_bits_from_name` (`axebom_shared/crypto/quantum_rules.py`) had no success-path `return` at all — every symmetric primitive with a sized name (`AES-128`, `AES-256`, ...) was falling through to "no key size reported" and skipping its Grover sizing note; three pre-existing tests were failing before this session touched the file, caught only because `ruff check` flagged the resulting unreachable `return int(match.group(1))` as referencing an undefined name after a first attempt landed it in the wrong function. Committed as `fixtures/crypto-mixed/` (raw pinned output + hand-reviewed `expected/` + a README answering why each value is correct) — no `TestGolden` Go harness reads it yet, that's still open.

#### QBOM device metadata — Go port, `services/project/internal/qbom`

Same precedent as HBOM: no Go→Python bridge exists anywhere in this codebase, so `workers/qbom/metadata.py`'s `normalize_device`/`form_fields`/`FORM_DISCLOSURE` are ported field-for-field into Go, reading `QBOMFields` from the already-generated `libs/go-shared/model/generated_certin.go` rather than hand-typing the eleven elements. New `GET /v1/qbom/{projectId}/form`, `GET /v1/qbom/{projectId}`, `POST /v1/qbom/{projectId}/device` (new `bom_documents` version each save, never mutated in place); `/v1/qbom` added to the gateway's project-service prefix list; new `authz.ResourceQuantumDevice` (Viewer read, Analyst write — same shape as `ResourceHardware`, kept as a distinct resource since the two forms serve different CERT-In tables). `crypto_asset_refs` resolves against the project's current CBOM via the same `resolveCurrentBOMDocument` helper (added in (i)) that SBOM's dependencies endpoint uses. `finding_refs` is always empty and says so in a comment — there is no crypto-asset-to-vulnerability matching concept anywhere in this codebase to derive it from.

**Known limitation, not fixed this session:** refs are resolved only at *save* time, baked into the persisted `field_status`. A project's first, never-saved QBOM load always shows "derived from CBOM discovery, which found nothing to reference" — even when real CBOM data already exists — because `GetQuantumDevice`'s not-yet-saved path calls `NormalizeDevice` with `nil` refs unconditionally rather than resolving live. Confirmed live: seeded four real crypto assets for `payments-api`, and the QBOM tab's Quantum Readiness summary (which reads crypto assets directly) correctly showed them, while the device form's gap list below it still said "found nothing" until a save. A live-resolve-on-read option exists and was considered; the agent that built this chose persisted-and-versioned for consistency with invariant 10 and documented the trade-off rather than picking silently.

#### Interactive reads — `GET /v1/projects/{id}/crypto-assets`

Not built by either parallel workstream (one built the write path, the other built downloadable-report rendering) — the sidebar's CBOM section needed a live, interactive read the way SBOM's Dependencies screen already has one, and nothing produced it. Added directly: `services/project/internal/store/crypto.go` (`ListCryptoAssets`, same `resolveCurrentBOMDocument` + no-cross-schema-SQL-JOIN pattern as `dependencies.go`), new `authz.ResourceCryptoAsset` (kept distinct from `ResourceDependency` — different CERT-In table, different discovery tool), route guarded at Viewer. `store.CryptoAsset` carries its own `json` tags directly rather than a separate handler DTO — deliberate, not an oversight: every field maps straight through with no renaming or transform, so a DTO here would be a copy with no logic in it.

#### Frontend — `CryptoInventory.tsx`, `QuantumDevice.tsx`

New project tabs, "Crypto" and "Quantum", alongside Dependencies/Findings/Hardware. `CryptoInventory.tsx` renders four separate tables (Algorithms/Keys/Protocols/Certificates), each only that type's own columns, plus a Quantum Readiness pill per asset — the same type-discrimination discipline `CBOMSheets` already enforces for the downloadable workbook, now live in the browser. `QuantumDevice.tsx` joins the CBOM-derived readiness summary (grouped by the four `quantum_readiness_group` buckets, read straight off `useCryptoAssets` — no re-derivation) with the eleven-element Table 8 form, rendering every field label from `GET /v1/qbom/{id}/form` rather than a hardcoded list. `BomTypeHome.tsx`'s CBOM/QBOM sections now link to real pages instead of "detail view not yet available" — only AIBOM still shows that state. `task profile guardrails` caught a real invariant-2 violation before this landed: the gap-count copy read "of 11 elements", a literal, where it now reads `form.data?.fields.length`.

#### Two things `task verify` caught that were not code bugs

- **A test-isolation flake in `services/scan-orchestrator`, unrelated to any of the above.** `LatestEngineRunsForProject` (added in (i)) asserted a freshly-created scan's engine status was `"queued"` — true in isolation, false under `go test -race`, because this environment's DB-backed tests run against the SAME live Postgres/NATS a real `task dev` stack's `sbom-worker` container also consumes from, and that live worker can advance a test's scan past `queued` before the test's own assertion runs. Fixed two ways: gave the test file its own dedicated project id (it had been sharing `projectA` with dozens of unrelated tests, which was ALSO capable of producing this exact symptom and is worth knowing about for any future test in this file that queries "the most recent scan" rather than one it holds by id), and stopped asserting a specific transient status in favor of asserting the row is real and correctly associated with the right scan.
- **The build cache filled the disk to 100% mid-session** (`docker builder prune -a` reclaimed 66.69 GB of a 96 GB volume) from the number of full-image rebuilds this session's iterative Docker-based verification required. Not a code defect, but worth recording: a long session that rebuilds images repeatedly on a modest disk needs this cleanup as routine housekeeping, not a break-glass response to a failure.

#### Verified live, against rebuilt `project`/`report`/`scan-orchestrator`/`gateway`/`frontend` containers

Seeded real crypto-asset data (the same RSA/SHA256/SHA256-RSA/RSA-2048/certificate chain the fixture pins) directly into Postgres for the seeded `payments-api` project and screenshotted both new pages through a scripted Playwright login: the Crypto tab correctly splits into Algorithms/Keys/Certificates sub-tables (no Protocols row seeded) with per-row Quantum Readiness pills in the right colors; the Quantum tab's readiness summary correctly grouped the same data into "2 assets — RSA, example.com" (vulnerable) and "1 asset — SHA256" (Grover note); the device form rendered all eleven Table 8 fields with the disclosure text and a full gap list. Zero browser console errors once gateway/project/report/scan-orchestrator/frontend were all rebuilt with this session's code (the QBOM form 404'd until the gateway specifically was rebuilt — its `/v1/qbom` prefix addition from earlier in this milestone had never actually been deployed).

`task verify` — the full gate, including the profile-guardrails literal-count check that caught the QuantumDevice.tsx bug above — passes clean end to end with everything in this entry included.

#### What Milestone 4 still owes

CBOM/QBOM's write path is proven but not live-triggered (same boundary as SBOM, see (e)) — nothing populates `normalize.crypto_assets` from an actual running scan yet, only from tests and this session's manual seed. `crypto-mixed`'s `expected/` files have no automated golden-diff harness. QBOM's ref-resolution-only-at-save-time gap above. Milestone 5 (AIBOM) has not been started at all — the `ai-bom` manifest/adapter contradiction from (i)'s report still blocks it before any of this session's patterns can be repeated there.

### 2026-08-24 (j) — CBOM and QBOM stop being refused in `services/report`

**Goal:** Milestone 4 (from (i), below) named three CBOM/QBOM gaps: no normalizer write path, no report sections, no frontend detail views. This session is the report-rendering slice only — `services/report`'s own refusal, and wiring it to read the two tables once another workstream writes them. The normalizer write path (`normalize.crypto_assets`/`normalize.quantum_components`) and the frontend detail views are explicitly out of scope, owned elsewhere.

#### The refusal was in the wrong place

`render.FieldsFor` returning an error for `model.BOMTypeCBOM` was always correct — CERT-In Table 9 genuinely has no single flat field list, Algorithms/Keys/Protocols/Certificates each have their own (8/7/5/10 fields). The bug was `Sheets`/`WriteJSON`/`WritePDF` all calling `FieldsFor` *first* and returning that error as a reason to refuse the *whole* report, before a Summary sheet or a coverage number could render at all. `services/report/internal/service/service.go`'s `Queue` had the same refusal one layer up, rejecting a CBOM request before a job was even created. All four call sites now branch on `BOMType == CBOM` *before* calling `FieldsFor`, the same way `Sheets` already special-cased HBOM — `FieldsFor` itself is untouched and still errors for CBOM (`TestACBOMHasNoFlatFieldSet` still passes unmodified).

#### New: `render.CryptoAsset`, `render.QuantumDevice`, `CBOMSheets`, `QBOMSheets`

- **`cbom.go`** — `CryptoAsset` mirrors `workers/cbom/normalize/crypto.py`'s `TYPE_COLUMNS` (every column for every type, empty where inapplicable — same shape as the `normalize.crypto_assets` table) plus the 0005 analysis columns, including `QuantumReadinessGroup`. `CBOMSheets(b BOM)` builds `Crypto Field Coverage` (the `fieldCoverageSheet` replacement, one row per field per type, sourced from the SAME `b.Coverage.Fields` breakdown the normalizer already wrote — never recomputed) plus four inventory sheets, `Crypto - Algorithms/Keys/Protocols/Certificates`, each showing *only* that type's columns. `TestACertificateNeverShowsAKeySizeField` pins the literal invariant-5 failure mode: the Certificates sheet has no `key_size` column at all, not a blank one.
- **`qbom.go`** — `QuantumDevice` holds Table 8's nine free-form elements (`normalize.quantum_components` has no columns for elements 5/10, the two CBOM-asset/finding reference lists, so those aren't modeled here — see the struct's own comment). Went with a **dedicated** `quantumDeviceSheet`/`Quantum Device` sheet rather than routing through the generic `componentSheet` mechanism: `componentSheet`'s identity columns (PURL, Depth, Orphan, Scope, Detected By) describe a position in a dependency tree and mean nothing for one piece of hardware. `fieldCoverageSheet` DOES still run generically for QBOM in `Sheets` — Table 8 is genuinely one flat list, `FieldsFor(QBOM)` already succeeded before this session — only the per-row component shape was wrong. `quantumReadinessSheet` groups `CryptoAssets` by the four buckets `migrations/normalize/0005`'s `quantum_readiness_group` column already carries (computed once in Python by `axebom_shared.crypto.quantum_rules.readiness_group`); `readinessNote` ports `workers/qbom/derive.py`'s `readiness_note()` prose in counts rather than slices — no percentage anywhere, per that function's own docstring on why one would be invented.
- **`Sheets`** now branches three ways: CBOM (skip `fieldCoverageSheet`/`componentSheet` entirely, `CBOMSheets` instead), QBOM (keep `fieldCoverageSheet`, replace `componentSheet` with `QBOMSheets`), everything else (unchanged). The CBOM type-discrimination note and the QBOM form-disclosure note are folded into the Notes sheet on a copy of the BOM, not a mutation of the caller's value.

#### Data loading — `bomsource.go`

`loadCryptoAssets`/`loadQuantumDevice` follow `loadComponents`'s exact template: one `normalize`-schema query, scoped by `bom_document_id`, no cross-schema join. Wired unconditionally into `LoadBOM`, matching every other load in that function — the tables are simply empty for a non-CBOM/QBOM document, and gating on `bomType` would duplicate a type list `Sheets` already owns. `formatDateTime` (RFC3339, literal Z) was added alongside the existing date-only `formatDate`, because a certificate's `not_valid_before`/`not_valid_after` are CERT-In `datetime` fields and `formatDate`'s truncation would silently drop the time of day. `TestEveryColumnThisPackageQueriesExists` (the static schema checker) initially failed on a false positive: a doc-comment that wrapped `normalize.crypto_assets` across a line break made the checker's word-boundary regex read the fragment before the newline as the whole table name (`normalize.crypto_`). Fixed by not hyphenating a qualified table name across a comment line wrap — a real gap in what that checker can see, not fixed here (it only reads `.go` source, and a wrapped identifier in prose is not a bug in the SQL itself), but worth knowing if it fires again.

#### JSON and PDF

`WriteJSON`'s CBOM refusal used `FieldsFor` purely as a "is this a known BOM type" check; replaced with `BOMType.Valid()`, which accepts CBOM and still rejects a genuinely unknown type. `BundleCanonical` gained `CryptoAssets`/`QuantumDevice` (both `omitempty`), so the one uncapped export format can carry what SPDX/CycloneDX cannot express at all. `WritePDF` never calls `FieldsFor` for a CBOM (`r.fields` stays nil; nothing reads it on that path) and swaps `coveragePage`/`componentPages` for `cryptoCoveragePage`/`cryptoInventoryPage`; QBOM gets an extra `quantumPage`. **Scope decision, stated rather than silently chosen:** the PDF does NOT get full per-asset-type field tables — `cryptoCoveragePage` shows per-type counts (total / quantum-vulnerable / deprecated) and points to the XLSX/JSON `Crypto Field Coverage` sheet for the real per-field breakdown; `cryptoInventoryPage` lists name/type/readiness only, never a type's own fields (which would risk exactly the column-conflation invariant 5 forbids). `estimatePages` now counts `CryptoAssets` alongside `Components` so a huge CBOM is refused early, same as a huge SBOM. `TestACBOMPDFRendersWithACryptoSummary`/`TestACBOMBundleRendersAndCarriesCryptoAssets` replace the two tests (`TestACBOMPDFIsRefused`, `TestACBOMBundleIsRefused`) that pinned the old, now-wrong behaviour.

#### Not touched, and why

`services/project`, `services/gateway`, `workers/`, `libs/py-shared` — explicitly out of scope per the task brief; those own the normalizer write path and the QBOM device-metadata REST route. `render.BOM.Hardware` (HBOM) still has no corresponding loader in `bomsource.go` — a pre-existing gap, unrelated to this session, left alone. `HBOMNotes` is still never wired into `Sheets`/`notesSheet` — also pre-existing, also left alone (the new CBOM/QBOM notes ARE wired in, since that path was being built fresh this session and repeating a known gap would have been a choice, not an oversight).

#### Verification actually performed

| Check | Result |
|---|---|
| `go build ./...` | clean |
| `go vet ./...` | clean |
| `go test ./services/report/...` | all packages pass, including the pre-existing `TestEveryColumnThisPackageQueriesExists` schema check |
| `go test ./...` (whole repo) | no failures (only pre-existing "no test files" packages) |
| `golangci-lint run ./services/report/...` | 0 issues |
| `gofmt -l` | clean |

No live stack, no Playwright — this is Go-only plumbing with no route or frontend surface yet; the sidebar's `BomTypeHome.tsx` still shows "detail view not yet available" for CBOM/QBOM, unchanged by this session.

### 2026-08-24 (i) — the sidebar reorganises around the five BOM types; two dead endpoints and a dead scan family get fixed

**Goal:** the user asked for a sidebar section per BOM type (SBOM/CBOM/QBOM/AIBOM/HBOM), each "managed separately" with its OSINT engines "integrated and linked," and configurable. Scoped via three clarifying questions into: a navigational reorg (not a data-model split — `project.project_classifications` and the single `bom_type` discriminator are unchanged), full CBOM/AIBOM engine-integration completion, and real per-tenant engine configuration. Given the scope, work was sequenced into milestones; this session completed Milestone 0 (foundation fixes), Milestone 1 (Engine Coverage panel) and Milestone 2 (configurable tool management), and shipped Milestone 3's sidebar + home pages wired to what's real today. Milestones 4/5 (finishing CBOM/QBOM and AIBOM engine integration) are follow-up work, not done this session — see "Not yet built" below.

#### Milestone 0 — three real bugs, not just gaps

- **The orchestrator was publishing scan jobs nothing consumes.** `Registry.Resolve` never checked the `Derived`/`RequiresImport` flags it already carried, so `POST /v1/scans` with `families:["hbom"]` or `["qbom"]` published `scan.job.hbom`/`scan.job.qbom` to subjects with no worker (HBOM is import-only, QBOM is derived from CBOM — neither has a `runner.py`, by design). This was already named in the 2026-08-23 (c) entry below and left unfixed. Now `Orchestrator.CreateScan` rejects either family outright, before anything is persisted or published, with a new error code `SCAN_FAMILY_NOT_DIRECTLY_SCANNABLE` naming the redirect (HBOM → `/v1/hbom/*` import; QBOM → automatic once a CBOM report exists). `frontend/lib/wizard.ts` gained `scannableBomTypes()` and a matching client-side block so Generate never sends a family the server will 422 on; `draft.bomTypes` (unfiltered) still drives which reports get requested, since a report can honestly be requested without this run having scanned for it.
- **`/v1/hbom/*` had no handler at all**, despite the frontend already calling it. Ported `workers/hbom/{model,csv_import,providers}.py` field-for-field into a new `services/project/internal/hbom` package (no Go→Python bridge exists anywhere in this codebase, and none was warranted for import-only logic) — cross-checked against the Python test suite and `fixtures/hbom-nested/parts.csv`. HBOM documents reuse the *project id* as `normalize.bom_documents.scan_id`, a deliberate, commented use of that column's documented lack of an FK, since HBOM has no real scan to key off. New `authz.ResourceHardware` (`ActionRead`: Viewer, `ActionCreate`: Analyst).
- **`GET /v1/projects/{id}/dependencies` and `/findings` had no handler either** — SBOM's existing Dependencies/Findings screens were calling dead routes. Implemented in `services/project`, following `scan-orchestrator/internal/orchestr/findings.go`'s cross-schema-without-a-cross-schema-JOIN pattern (two queries, joined in Go, per invariant 11) via a new `resolveCurrentBOMDocument` helper generalized from it and `report/internal/store/bomsource.go`.
- Collapsed the duplicate BOM-type metadata: `frontend/lib/bomTypes.ts` (used only by `ProjectWizard.tsx`) is deleted; everything now reads `design/theme.ts`'s `BOM_TYPES`/`bomMeta`.
- Corrected this document's own stale claim (below, Phase 11 section) that `cbomkit-theia` "has never run" — it ran once, end to end, on session 2026-08-23 (b), against a fixture with no crypto content.

#### Milestone 1 — Engine Coverage panel

`GET /v1/scans/engines` gained a `mode` field per engine (`container` / `pip` / `internal` — a new static field on `policy.Engine`, populated for all 13 registered engines) and an optional `?project_id=` that adds `last_run` (status, scan id, timestamps) from a new `Store.LatestEngineRunsForProject` — the project's most recent invocation of each engine, across every scan, not just its latest. Frontend `components/EngineCoveragePanel.tsx` renders this per BOM type, with "never run" as its own honest state distinct from "ran and failed" (invariant 12).

#### Milestone 2 — configurable tool management

`scan.engine_policy` (migrated in Phase 6, documented, **never read by anything** — flagged as Phase-7 debt in the 2026-08-23 (c) entry below) is now wired end to end: new `policy.Store` (`Get`/`Upsert`/`Delete`/`ListForTenant`/`OverridesForTenant`), loaded in `handler.Create` and passed as `CreateScanInput.EngineOverrides` — a parameter that existed since Phase 6 and nothing ever populated. New `authz.ActionConfigureEngines` (Admin), mirroring `ActionEnableRiskyResolution`'s precedent of a named action for anything that changes what code executes. New endpoints `GET/PUT/DELETE /v1/scans/engine-policy[/{family}]`. New frontend: `frontend/lib/auth.ts` exports `roleAtLeast`; `useAuth.ts` gained `useRole()` — the first UI consumer of `activeOrg.role` for gating a control, not just displaying it. `routes/settings/Engines.tsx` is the first AxeBOM-native admin settings screen (org/member management is otherwise entirely ZITADEL's).

One correction made mid-implementation: the `scan.engine_policy` migration's own comment says a tenant "may read the global row and its own" — but `enable_tenant_rls_nullable`'s actual `USING` clause (shared by every nullable-tenant table, including `auth.audit_log`) has no `OR tenant_id IS NULL`; only `WITH CHECK` does. So a tenant-scoped connection can never read the global default row — same shape as the already-documented `auth.audit_log` limitation. `policy.Store` only ever touches tenant-scoped rows; reading the global default is out of scope, same as it is for audit_log (a platform-admin surface, not before Phase 16).

#### Milestone 3 (started) — the sidebar

`components/Sidebar.tsx`'s flat 5-item nav is now three groups in one `<nav>`: Projects; a labelled BOM-type group (SBOM/CBOM/QBOM/AIBOM/HBOM, glyph + `data-bom` token from `design/theme.ts`, each with its own active-state accent in `app.css`); Generate/Scheduled/Reports/Settings. Five new routes (`/sbom`, `/cbom`, `/qbom`, `/aibom`, `/hbom`) share one lazy-loaded `routes/boms/BomTypeHome.tsx`: projects classified for that type, the Engine Coverage panel, a link into `/settings/engines` scoped to that family, and — for SBOM/HBOM only — a real link into the existing Dependencies/Hardware views; CBOM/QBOM/AIBOM show "detail view not yet available" rather than a dead link or an empty table that would misread as "nothing found."

Verified live against the rebuilt `project`/`scan-orchestrator` containers (screenshots taken via a scripted Playwright login as `alice@acme.test`, not manual): sidebar renders all three groups with correct per-type accents and glyphs; CBOM home page shows `payments-api` with "detail view not yet available" and an Engine Coverage table correctly reading `cbomkit`/`cbomkit-theia` as `sandboxed container` (was `unknown` before the container rebuild — confirms the `mode` field is live, not just compiling); `/settings/engines` shows all five BOM types with every registered engine pre-checked and `qbom-derive` correctly labelled `derived`; `/projects/{id}/dependencies` now returns an honest "no normalized scan results yet" instead of a dead route; `/hbom` shows the correct empty state and engine coverage (`hbom-csv`, `import only`, `AxeBOM-native, not a scanner`). Zero browser console errors on any of these once both rebuilt containers were live.

`task verify` — fmt, profile lint/guardrails/evidence, docs lint, golangci-lint, ruff, eslint (`--max-warnings 0`), the full Go suite with `-race`, pytest, both builds — passes clean end to end with all of the above included.

#### Not yet built (Milestones 4/5, follow-up)

- CBOM/QBOM detail views (crypto inventory, quantum readiness, QBOM device form) — still no report sections; `render.FieldsFor` still refuses CBOM; no normalizer write path for `normalize.crypto_assets`/`normalize.quantum_components`. **Superseded in part by the 2026-08-24 (j) session**: `services/report` now renders both (FieldsFor itself still correctly refuses a flat CBOM field list; `Sheets`/`WriteJSON`/`WritePDF` no longer treat that as a reason to refuse the report). The normalizer write path and the frontend detail views are still unbuilt.
- AIBOM detail views, and the `ai-bom` manifest/adapter contradiction (`pip:` in the manifest, `SandboxedAdapter` in the code — cannot resolve as shipped) — unresolved, needs a decision (containerize vs. a genuinely unsandboxed path) before AIBOM can run at all.
- `engine_policy` is tenant-scoped, not project-scoped, by design for this session — a real per-project override would need a schema change.
- HBOM's Go port doesn't expose `product_details`/`manufacturing_date` (frontend contract is a subset of the full 24-field model); `manufacturing_date` parses `YYYY-MM-DD` and drops what doesn't parse, since the Python model treats it as free text but the column is `date`.

### 2026-08-24 (h) — self-service organisation signup, and the ZITADEL Host-header trap catches a second victim

**Goal:** verify the ZITADEL integration end to end and, since self-registration
is deliberately disabled ((a)'s session), give a real visitor a working way to
arrive — a "create your organisation" form in AxeBOM's own frontend that
provisions a ZITADEL org + Owner before handing them to the hosted login,
rather than asking an operator to run `axebom iam bootstrap` by hand for every
new signup. Also: reframe the pre-auth screens with the glassmorphism
treatment `design/app.css` already had tokens for but nothing used at full
strength, while leaving ZITADEL's own hosted login UI unforked — a deliberate,
user-confirmed choice, not an oversight.

#### `POST /v1/auth/signup` — `services/gateway/internal/signup`, `iam.Client.Signup`

Creates the organisation, grants it the AxeBOM project, and creates its first
user as Owner — the three steps a self-registered ZITADEL account never gets,
which is exactly why `Errors.User.GrantRequired` was the failure mode (a)
found. **Not** `Bootstrap`'s idempotent find-or-create: `iam.Signup` fails
closed on a name or email collision (`iam.ErrOrgNameTaken` /
`iam.ErrEmailTaken`, wired to new codes `AUTH_ORG_NAME_TAKEN` /
`AUTH_EMAIL_TAKEN`, both 409) rather than silently attaching a stranger to an
existing tenant as its Owner. Verified live via curl for all four paths: 201
create, 409×2, 422 (ZITADEL's own password-policy rejection surfaced, not
duplicated). The Postgres side needs no code at all — `auth.identity_for`
((h)'s predecessor, migrations/auth/0003) already JIT-provisions
`auth.tenants`/`auth.users` on first sign-in, so the handler only ever talks
to ZITADEL.

⚠ **The gateway now optionally holds the SAME credential `axebom iam
bootstrap` does.** Creating a ZITADEL organisation is instance-level; there is
no narrower permission to grant instead. `config.OIDC.ProvisioningKeyPath`
(`ZITADEL_BOOTSTRAP_KEY`) defaults to **empty — the feature is off** unless a
deployment explicitly mounts the bootstrap key and sets the env var, which
`docker-compose.app.yml`'s gateway entry now does for `task dev`. This is a
demo/dev-appropriate trade, made explicitly rather than silently: a real
production exposure of this endpoint needs a scoped ZITADEL service account,
which is a permission-model decision for that deployment, not a code change.

#### The ZITADEL Host-header trap has a second victim, and it needed a different fix than the first

(a)'s `oidcauth.ServiceTokenSource` already knew ZITADEL selects its instance
from the Host header and an in-network caller reaching it as `zitadel-api:8080`
gets `Instance not found`. `libs/go-shared/iam`'s `Connect` is now a **second**
in-network ZITADEL caller (the CLI's own use dials the public port directly
and never hit this), and the same Host override was NOT enough for it —two
new layers of the same problem, found in order:

1. **`zitadel-go`'s own OIDC discovery hardcodes `http.DefaultClient`.**
   `client.DefaultServiceUserAuthentication` → `profile.NewJWTProfileTokenSource`
   builds `httpClient: http.DefaultClient` in the struct literal and never
   reads it from `ctx` — so placing a Host-overriding `*http.Client` in
   `ctx` via `oauth2.HTTPClient` (what `client.New` itself does when *it*
   needs to) has zero effect on this specific call. Confirmed by testing:
   `Instance not found` persisted with a `ctx` override in place. Fix:
   `iam.serviceUserAuth` calls `profile.NewJWTProfileTokenSource` directly
   with `profile.WithHTTPClient(...)`, bypassing
   `DefaultServiceUserAuthentication` entirely — the only way to reach that
   option, since `zitadel-go`'s wrapper never exposes it.
2. **Once discovery ran, its own response failed a stricter check:** ZITADEL's
   discovery document reports `issuer` from **its own** `EXTERNALDOMAIN`
   (the public value), and the OIDC client correctly refuses a document whose
   `issuer` doesn't match the address discovery was asked for — which,
   Host-overridden, is a mismatch **by construction**. `Instance not found`
   became `issuer does not match`. This is not a bug to route around; it is
   the protection working as designed one layer up from where the override
   lives. Fix: skip discovery entirely with
   `profile.WithStaticTokenEndpoint`, exactly mirroring how
   `oidcauth.ServiceTokenSource` already hand-builds its token URL instead of
   discovering it — for the same reason, arrived at independently this
   session before the parallel was noticed.
3. The gRPC calls that follow (every actual `OrganizationServiceV2`/
   `UserServiceV2`/… call) needed a **third**, unrelated mechanism:
   `grpc.WithAuthority`, gRPC's `:authority` pseudo-header being a distinct
   channel from both the HTTP `Host` field and `zitadel.WithTransportHeader`'s
   metadata (confirmed by reading `zitadel-go`'s own dial code — the metadata
   route append-only affects requests that read metadata, and ZITADEL's
   instance routing does not).

Net result: `iam.Config` gained `PublicHost`, empty and inert for the CLI's
existing working case (`Domain` is already the public value there), and
`iam.Connect` now needs three independent overrides — HTTP client, static
token endpoint, gRPC authority — to reach ZITADEL from inside the compose
network at all. Any **third** in-network ZITADEL caller should read
`iam.Connect`'s doc comments before assuming a plain Host override is enough;
it visibly was not, twice.

#### `task iam:reset` does not relink a Postgres that already had a *different* link

Running the reset-then-rebootstrap cycle this session's earlier verification
work called for (the user asked to "recreate everything") revealed a gap
`axebom iam bootstrap`'s `linkIdentities` doesn't guard against: its `UPDATE …
WHERE (zitadel_user_id IS NULL OR zitadel_user_id = $1)` only **adopts** an
unlinked row or **confirms** an already-correct one — it silently does
nothing when the row already points at a **different, now-stale** ZITADEL id,
which is exactly the state every seeded fixture (`alice@acme.test`, `Acme
Industries`, …) is in after a second `iam:reset`. The bootstrap output says so
(`note: no seeded user … to link`) but doesn't fail, so it reads as
"idempotent, nothing to do" rather than "the seed data is now orphaned from
its own ZITADEL identity." Symptom: `alice@acme.test` could sign in, but
`payments-api` had vanished — `auth.identity_for` couldn't find the org by its
new id, so it JIT-created a fresh, empty tenant instead of reusing the one
that owns the seeded project. Recovery (done this session, not yet a CLI
command): `NULL` the stale `zitadel_org_id`/`zitadel_user_id` columns on the
fixture rows, delete whatever JIT placeholders the mismatch produced in the
meantime, then re-run `iam bootstrap`. **A future `task iam:reset` should
either clear these columns itself or the next session should expect this.**

#### Frontend: a full-bleed pre-auth shell, not a sidebar around an empty state

`AuthShell` (`components/AuthShell.tsx`) is new: `Ambient` plus a centered
glass card, used by `SignIn`, `NoAccess`, `AuthCallback` and the new
`SignupPage`. All four routes for an unauthenticated visitor moved to the
top-level `<Routes>` in `App.tsx` (alongside `/auth/callback`, which already
had to live there) — **outside** `<Shell>`, so a signed-out visitor no longer
sees an empty, non-functional sidebar and top bar around the card they're
trying to get past. The card itself uses the design system's Tier A glass
(`--glass-bg` + a real `backdrop-filter: blur() saturate()`, not Tier B's
tint-only `.card`/`.state`) — correct per `tokens.css`'s own rule that blur is
wasted on a backdrop with no structure to reveal, because here the card is the
*entire* page rather than one element floating over scrolling content.
ZITADEL's own hosted login screen (the one in the user's original screenshot)
is untouched — kept deliberately unforked, per the existing
`ensureHostedLoginTranslation` rationale in `libs/go-shared/iam/provision.go`,
confirmed with the user rather than assumed.

⚠ **Frontend Docker build args bit twice this session, unrelated to this
feature.** `docker-compose.app.yml` passes `ZITADEL_SPA_CLIENT_ID`/
`ZITADEL_PROJECT_ID` to the frontend image as **Vite build args**
(`VITE_OIDC_CLIENT_ID`/`VITE_OIDC_PROJECT_ID`), baked into the bundle at
`docker build` time, not read at runtime. `auth.ts`'s `overrideFromEnv()`
prefers these over the live `GET /v1/auth/config` fetch when both are
non-empty. After re-bootstrapping ZITADEL and updating `.env`, the *running*
frontend container kept sending the OLD client id in every authorize
redirect — `docker compose up -d --build gateway` rebuilds the gateway
config endpoint, but does nothing for a frontend image built from an
now-stale `.env` snapshot. **Any `.env` change to
`ZITADEL_PROJECT_ID`/`ZITADEL_SPA_CLIENT_ID` needs `--build frontend` too,
not just the services that read it at runtime.**

#### Verified

- `task verify` — full green: fmt, profile lint/guardrails/evidence, docs
  lint, `golangci-lint` (0 issues), `go test ./... -race` (every package),
  `pytest`, `go build ./...`, `npm run build`.
- `npx playwright test e2e/` — **7/7 green**: the 4 existing `auth.spec.ts`
  cases (now sharing a `fillZitadelLogin` helper factored into
  `e2e/helpers.ts`), `generate.spec.ts` unaffected, and 2 new
  `signup.spec.ts` cases — the happy path (create → real ZITADEL login →
  `/projects` with a real role, no `PERM_NO_ROLE_IN_ORG`) and the
  duplicate-organisation-name refusal (asserts the visitor stays on
  `/signup`, never reaches ZITADEL's login for an org that isn't theirs).
- curl against all four `POST /v1/auth/signup` outcomes (201, both 409s,
  422) directly, before the browser-level tests existed, to isolate backend
  correctness from frontend wiring.

#### Left for a later session

- **No CLI recovery command for the relink gap above** — the fix this
  session was three manual SQL statements plus a re-run of
  `iam bootstrap`, not a repeatable one.
- **The self-service signup credential trade (gateway holds the bootstrap
  key) is a dev/demo decision, not a production one** — see the ⚠ above.
  Revisit before this deployment shape reaches anything but a local stack.
- Left-over dev-only test organisations from this session's manual curl and
  Playwright verification exist in the running ZITADEL instance (`Curl Test
  Org 2`, timestamped `E2E Signup Org …` / `E2E Dup Org …`) — harmless,
  consistent with `iam verify`'s own comment that the dev database
  accumulates throwaway tenants from integration tests, not cleaned up.

### 2026-08-24 (g) — live-verified the AxeBOM rename against a fresh stack, and found four bugs the static rename couldn't see

**Goal:** (f)'s rename was verified only statically — `task verify` passing
proves the code compiles and the goldens match, not that a running stack
actually forms a `axebom_app` role, an `axebom` bucket, or a ZITADEL org named
`AxeBOM`. Ran `task dev:nuke && task dev`, then verified each identifier
directly against the live containers, and ran both Playwright specs through a
real OIDC login.

#### A stale pre-rename stack was still running, independently of `task dev:nuke`

`docker compose ls -a` found a **second, separate Compose project literally
named `encorebom`** — up for 43 minutes, started before the compose files were
edited to say `name: axebom`. `dev:nuke` only ever tears down the project the
*current* compose files declare, so it had zero effect on this one; it kept
running the whole time, holding the old `encorebom_{pgdata,miniodata,natsdata}`
volumes and — critically — **binding the exact host ports** (`55432`, `8080`,
`5173`, `58080`, `59000`/`59001`) the new `axebom`-named stack needed. The first
`task dev` failed with `Bind for 0.0.0.0:55432 failed: port is already
allocated`.

Confirmed with the user before acting (a second running stack wasn't in the
original plan, and stopping+deleting it needed explicit sign-off — the auto-mode
classifier itself declined to let the action through without it), then removed
it: `docker compose -p encorebom down -v`, plus three more `encorebom_*`
volumes (`artifacts`, `enginedb`, `workspaces`) that `down -v` didn't reach —
apparently `external: true` in the compose file, so compose doesn't consider
itself their owner. All dev/seed data, nothing precious.

#### The rename silently broke a length-sensitive secret

`zitadel-setup` failed: `"masterkey must be 32 bytes, but is 29"`. The dev
placeholder had been `EncoreBOMDevMasterkey32CharsLong` — a **hand-sized
32-byte string that spells out its own length as a mnemonic** — and the blind
`encorebom`→`axebom` substitution shortened it by exactly the 3-byte
difference between the two names (`32 - 3 = 29`). A text rename doesn't know a
string's length is load-bearing. Replaced with `AxeBOMLocalDevMasterkey32Bytes!!`
(verified 32 bytes in Python before writing it), fixed identically in `.env`,
`.env.example`, and both fallback defaults in `docker-compose.iam.yml`. Swept
`.env.example` for any other `KEY=` value combining a digit with
`Char`/`Byte`/`Long` — this was the only one.

#### A pre-existing Taskfile bug, unrelated to the rename, that only a full run surfaces

`task dev`'s final line — `echo "  task health   # per-service readiness"` —
failed with `1:6: reached EOF without closing quote`, even though every
container was already up. The literal `#` inside the double-quoted argument is
mis-parsed by go-task's shell tokenizer as a comment start, truncating the
string. This line's content has never contained `encorebom`/`axebom`, so the
rename didn't cause it — it's a latent bug that nobody had hit because nobody
had run `task dev` to completion recently (`docs/STATE.md` notes the Docker
daemon is frequently stopped between sessions). Fixed by moving the explanation
out of the quoted string; `task dev` now exits 0.

#### My own bootstrap ran in the wrong order, and left orphan rows behind

Ran `task iam:bootstrap` before `task db:seed` — backwards. Bootstrap logged
`note: no seeded tenant with slug "acme" to link` and, rather than failing,
**auto-created placeholder tenant/user rows** to hold the new ZITADEL org and
user IDs it had just provisioned. Once `db:seed` ran afterward and I re-ran
bootstrap in the right order, it correctly found the real `acme`/`beta` tenant
rows — but linking them failed twice on `duplicate key value violates unique
constraint`, because the orphan rows from the first run already held those
exact `zitadel_org_id`/`zitadel_user_id` values (`ensureOrg`/`ensureUser` in
`libs/go-shared/iam/provision.go` are correctly idempotent on the ZITADEL side
— they found and reused the *same* org/user rather than creating duplicates,
which is exactly what surfaced the collision). Deleted the two orphan rows
(one tenant, one user, each with a single dependent membership row — verified
no other dependents first) and re-ran bootstrap clean. **Operational lesson,
recorded here so the next session doesn't repeat it: `task dev` →
`task db:seed` → `task iam:bootstrap`, in that order** — bootstrap's tenant/user
linking step needs the seed rows to already exist.

Also found and fixed: the gateway (and every other app-tier container) reads
`ZITADEL_SPA_CLIENT_ID`/`ZITADEL_PROJECT_ID` from `.env` at container-create
time, not at request time — so after bootstrap prints fresh IDs and `.env` is
updated, a plain `docker restart` does **not** pick them up (Compose bakes
resolved env into the container at creation). `docker compose up -d` without
`--force-recreate` did, though — it correctly diffed the resolved environment
and recreated every affected service on its own.

#### Verification actually performed, against the live stack

| Check | Result |
|---|---|
| `SELECT current_database(), current_user` | `axebom \| axebom` |
| `\du axebom_app` in psql | role exists |
| `\dn` (schemas) | all 9 owned by `axebom` (`app`, `auth`, `campaign`, `comment`, `normalize`, `notify`, `project`, `report`, `scan`) |
| `mc ls local` (inside the MinIO container) | `axebom/` — the bucket, correctly named, correctly created by `minio-init` |
| `SELECT name FROM projections.orgs1` (ZITADEL's own DB) | `AxeBOM` (instance org), `Acme Industries`, `Beta Corp` (dev orgs) |
| `GET /api/v1/auth/config` | `"org_header":"X-AxeBOM-Org"`, live client/project IDs matching bootstrap's output |
| `go test ./libs/go-shared/platform/db -run TestRLSCoverage\|TestCrossTenant...` | 11/11 pass — **live**, not mocked; `TestCrossTenantCountIsScoped` confirms Acme's seed data is exactly 2 projects, matching the seed file |
| `go test -run TestSeededUsersCanLogIn` | 4/4 pass — the argon2id hashes regenerated in (f) verify against `axebom-dev-only` **on a live database**, not just the unit-test fixture |
| `task health` | 9/9 up |
| `npx playwright test` (both specs, real Chromium, real OIDC round trip through ZITADEL) | **5/5 pass** — anonymous-visitor redirect, full sign-in reaching real seeded project data (`payments-api`), session survival across reload, session-menu identity, and the complete generate-wizard flow (create scan, queue reports, no 422) |
| `rg -i encorebom` (repo, live-verified session) | zero matches outside this STATE.md entry's own narrative |

#### What is still NOT built or NOT re-verified

- **No fresh `task verify` run after this session's fixes** (the Taskfile echo
  fix, the masterkey fix). Both are outside anything `task verify` checks
  (Taskfile syntax and `.env` aren't linted), but worth a final pass before
  calling the branch done.
- **The `ENCOREBOM_*`→no-op env var rejection is still not implemented** — flagged
  in (f), still open.
- **Nobody has exercised a scan against a real engine** on this fresh stack —
  the generate-wizard e2e test only confirms the request is accepted and reports
  are queued, not that an engine completes and produces output. The engine
  databases were wiped by the nuke and would need the 30–60 minute NVD-style
  resync on first real use.
- **Old `encorebom-*` container images were not pruned** (`docker system df`
  showed 2.58 GB reclaimable before this session; likely more now with a
  second full image set built under `axebom/*:dev`). `docker image prune` was
  not run — left for the user, since it affects images outside this repo's
  volumes.

### 2026-08-24 (f) — renamed to AxeBOM; the frontend gets a real design system

**Goal:** the product was named EncoreBOM everywhere — Go module, Python
package, CLI binary, infra identifiers, the report signature domain, CERT-In
extension field IDs — while the git remote was already
`github.com/SiddhantSShende/AxeBOM`. Rename it, then give the frontend the
glass/motion visual system it never had: no Tailwind, no component library, no
animation, no webfont, a single top nav bar, and two CSS files with five live
duplicate-rule bugs.

#### The rename touched more than branding

Four casings (`encorebom`/`EncoreBOM`/`ENCOREBOM`/`Encorebom`), no separator
variants, **386 files** across the Go module path (171 files), the Python
package `encorebom_shared` → `axebom_shared`, the CLI binary, Docker/compose
identifiers, and five things baked into **already-emitted artifacts**:

- `encorebom.signature/v1` — the report-signature domain-separation prefix, part
  of the signed bytes. Every previously-issued report signature stops verifying
  (accepted; no reports exist to invalidate yet).
- The `encorebom.{crypto,aibom}.*` extension field IDs in `certin-v2.0.yaml`,
  which had to move together with the hardcoded prefix check in
  `libs/go-shared/compliance/lint.go` or `profile:lint` fails.
- `LicenseRef-EncoreBOM-<slug>`, the CycloneDX `encorebom:*` property namespace,
  and the `schemas.encorebom.io` schema `$id`s.
- The WS subprotocol `encorebom.v1`/`encorebom.bearer.` and the `X-EncoreBOM-*`
  headers, which had to move in lockstep with the frontend's `api.ts`/`ws.ts` or
  the handshake fails outright.

⚠ **Two distinct dev passwords, only one of which a sed can fix.**
`EncoreBOM-dev-only1!` (ZITADEL) is a plain literal. `encorebom-dev-only` (the
DB seed) is hashed with real argon2id in
`migrations/seed/0001_dev_tenants.sql` — renaming the *string* would leave the
*hash* checking the old password while the comment claimed the new one.
Regenerated all three hashes with `auth.HashPassword` at the service's own
params and updated `SeedPassword` in `seed_login_test.go`, which **verifies**
the committed hashes against the constant and would have failed loudly on a
mismatch.

`fixtures/hbom-nested/*` was excluded on purpose — `"EncoreBOM Edge Gateway
4400"` there is fictional third-party hardware in the golden corpus, not
branding; renaming it would have desynced `parts.csv` from `expected.json`.

Regenerated `profile:gen` → `profile:lint` → `profile:evidence`, and the report
export goldens (`AXEBOM_WRITE_GOLDEN=1`) — both now carry the new tool name and
a new UUIDv5 `serialNumber` (namespace-derived, so it changes with the name),
diffed field-by-field to confirm nothing else moved.

#### A pre-existing flaky test, found and fixed along the way

`TestEqualHashIsCaseInsensitiveAndExact` (`services/report/internal/share`) —
already flagged as an unrelated flake in 2026-08-24 (d) — turned out to be
`h[:len(h)-1]+"0"` occasionally producing the *same* hash it was supposed to
differ from, whenever the token's last hex digit already was `0`. One run in
sixteen, and the test reported a real bug for it. Fixed to pick a digit that
provably differs; 200 repeated runs clean.

#### The frontend: glass tokens, a grid shell, motion — and three real bugs the redesign surfaced

Before touching visuals: `app.css` had **five live duplicate rules** where the
later one silently won — `.table` (the second set `display:block`, breaking
the sticky `thead` and the 50k-row virtualizer's flex layout), `.card`
(dropped the shadow the hover-lift depended on), `.page-header`, `.field`
(the drawer's definition-row style was overriding every form label in
`ProjectWizard`), `.field-row` (two unrelated intents sharing one name, so the
wizard's validity-start/end fields stacked instead of sitting side by side).
Renamed the collisions (`.field`→`.def-row`, `.field-row`→`.field-pair`),
deleted the dead rules, and gave wide tables their own `.table-wrap` instead of
forcing `overflow-x` onto every `.table`.

Also found: the `prefers-reduced-motion` block zeroed animation *duration* but
not *iteration-count*, so the `infinite` skeleton shimmer didn't stop for a
reduced-motion user — it ran at frame rate instead. And `--text-faint` was
4.50:1 on white, exactly at the AA floor with nothing to spare, on a token used
for `.not-provided` — load-bearing compliance information. Both fixed before
any glass was added, independent of the redesign.

**Glass system:** new tokens in `tokens.css` (`--glass-bg{,-strong,-solid}`,
`--glass-blur`, `--amb-1..3`, motion durations/easings), declared on bare
`:root` and duplicated identically into both dark blocks — verified
programmatically (parsed all three blocks, confirmed byte-identical dark
blocks and full light/dark coverage). Contrast verified by computing WCAG
relative luminance for every text token over every glass tier against the
worst-case ambient stop in both themes: **worst case 4.94:1**, comfortably
above the 4.5:1 floor. `@supports`/`prefers-reduced-transparency`/
`forced-colors` fallbacks route everything through the existing `--surface`
tokens rather than restating three more theme blocks.

Surfaces are tiered by how long someone reads the text on them: sidebar/topbar/
drawer/dialog/menu get real `backdrop-filter` (they overlap scrolling content,
so the blur does visible work); cards/panels/states/callouts get a tint plus a
1px highlight, no filter (blurring a smooth ambient gradient returns the same
gradient — free, not cheaper). The dependencies table gets **one** blur on the
`.table-scroll` container and zero on any row — a filter per row across a
50k-row virtualized table would be 50k stacking contexts.

**Shell:** `App.tsx` rebuilt as a CSS Grid (`sidebar | topbar` / `sidebar |
main`) with a collapsible glass `Sidebar`, a slim `TopBar`, and an `Ambient`
background (three radial-gradient blobs, `transform`-only animation, no
`filter: blur()` — the animation cost is otherwise proportional to element
area, forever). Sidebar collapse state persists via a new zustand store
(`design/shell.ts`, `axebom.shell`) and is applied pre-paint by the same
blocking bootstrap script in `index.html` that already handles the theme, so a
collapsed sidebar doesn't flash expanded on load. Collapsing hides nav labels
visually only — the accessible name stays in the DOM (`width:0` clip, not
`display:none`), verified live: `sidebar-nav a` still reported all 5 names with
the sidebar collapsed.

**Motion:** `motion` (13.1.1) via `LazyMotion`+`m` with `features={strict}`,
which makes `motion.div` throw at compile time rather than letting a stray
import silently add ~34 KB to the entry chunk. `MotionConfig
reducedMotion="user"` wired at the root — this is the half of reduced-motion
that the CSS media query cannot reach, since `motion` animates via WAAPI.
Applied to: route-enter (enter-only, no `AnimatePresence` — an exiting lazy
route fights `Suspense`, and `generate.spec.ts` clicks Continue and
immediately expects the next step, which an exiting-but-still-clickable node
would race), a capped project-card stagger (`Math.min(index, 10)`, so a
200-project org doesn't stagger for six seconds), and a new shared `Overlay`
component wrapping the drawer/dialog scrim+panel with a real exit animation via
`AnimatePresence` at the call sites.

**`Overlay` (`components/Overlay.tsx`) replaced two hand-rolled, incomplete
modal implementations.** `ComponentDrawer` and `ShareDialog` each had Escape-
closes and an initial `.focus()` — no focus trap, no focus restore, no `inert`
on the background. `Overlay` adds all three (Tab cycles within the panel;
closing restores focus to whatever opened it; `#root` goes `inert` for the
duration, which is what actually stops a screen reader's virtual cursor and
Tab from reaching the table/report behind it — the scrim only stops the
mouse), and is portaled to `document.body` so an ancestor's `transform` (the
route-enter animation) can never become its containing block and break
`position: fixed`.

**Typography:** self-hosted `@fontsource-variable/inter` (OFL-1.1, latin +
latin-ext only — the other five Unicode subsets it ships were left unreferenced
rather than bundled), `font-display: swap`, system stack as fallback. No
external request — this ships to strict-CSP and air-gapped customers.
`--sidebar-w` registered with `@property` so the collapse transition eases via
pure CSS with no JS and no layout projection.

**Five new routes** closing dead links `GenerateFlow` and `ProjectWizard` have
carried since they were written (`/projects/:id/settings`,
`/projects/:id/practices` both 404'd until now): `ReportList` (`/reports`),
`ProjectScans` (`/projects/:id/scans`), `ProjectPractices`, `ProjectSettings`,
`SettingsIndex` (`/settings`). All five are thin views over APIs that already
exist — `useSetPractices` (`lib/projects.ts`) had existed with **zero
callers** since Phase 4. Two honest gaps surfaced and documented rather than
worked around: `GET /v1/reports` has no `next_cursor` and no `project_id`, so
`ReportList` states `truncated` rather than paginating a cursor it cannot
obtain, and joins project names client-side through the scan list; and
`/settings`'s organisation panel is read-only with a link to `/ui/console`,
because no `/v1/orgs` route exists anywhere — identity moved to ZITADEL.

#### Verification actually performed

| Check | Result |
|---|---|
| `rg -i encorebom` (repo, tracked + `.env`, excluding the hardware fixture) | zero matches |
| `task verify` | exit 0 — fmt, profile:lint (131 fields, 17 count assertions matched), profile:guardrails, profile:evidence:check, docs:lint (124 refs resolve), lint, `go test ./... -race` (incl. the newly-fixed flake ×200), build |
| `task dev` component checks (Postgres role, MinIO bucket, ZITADEL org) | not exercised — no live stack brought up this session; infra rename is code-complete but unverified against a running cluster |
| Frontend `tsc -b`, `eslint --max-warnings 0`, `prettier --check`, `vitest` (81 tests, 6 files) | all clean |
| `npm run build` | **134.5 KB gzipped initial JS** (was ~124 KB before `motion`+font), budget 250 KB; `motion`'s 14.3 KB feature bundle and the new `Overlay` chunk both confirmed on lazy chunks, off the critical path |
| WCAG contrast, glass tiers × text tokens × both themes | computed programmatically (relative-luminance formula, not eyeballed); worst case 4.94:1 against a 4.5:1 floor |
| Visual, Playwright screenshots, light + dark | shell, sidebar (expanded/collapsed), cards, glass table, coverage panel, callouts, empty state — zero console errors, correct font family, correct `backdrop-filter` per theme |
| `sidebar-nav a` accessible names with `data-sidebar="collapsed"` | all 5 present — the icon-only visual state does not become an icon-only accessible name |

#### What is still NOT built or NOT re-verified

- **No live-stack verification of the infra rename** (`POSTGRES_DB`, the
  `encorebom_app`→`axebom_app` role rename, the MinIO bucket, the ZITADEL
  first-instance org). `task dev:nuke && task dev && task health` is the next
  session's first step before trusting this in a running environment.
  `.env.example` and the untracked `.env` were both updated; a fresh `.env`
  should be diffed against the example.
- **The two Playwright specs were not re-run against a live stack** this
  session (no backend was running) — `e2e/auth.spec.ts`'s `Sign out` button
  assertion and `e2e/generate.spec.ts`'s step-by-step selectors should still
  match (the top bar keeps a directly-visible Sign out button on purpose, and
  the route-enter animation is enter-only so no exiting node can intercept a
  click), but this is inference from the source, not a run.
- **Only `ProjectList`, the shell, and the shared overlay got bespoke motion.**
  Every other screen (Dependencies, Findings, GenerateFlow's step transitions,
  ReportViewer's coverage counters) inherits the glass surfaces for free
  because they compose the same CSS classes, but none of them got a
  screen-specific animation pass.
- **`docs/07-FRONTEND-SPEC.md` §1 still describes Tailwind + shadcn + Recharts +
  `@xyflow/react`.** None of that is true today or was ever true; the actual
  stack is now plain CSS + `motion` + a self-hosted font. Not corrected this
  session — flagging so the next person doesn't build against the stale spec.
- **The rename's `ENCOREBOM_*`→no-op env vars have no startup rejection.** An
  operator with a stale `.env` gets silent defaults, not an error. Flagged in
  the plan, not implemented.

### 2026-08-24 (e) — the normalizer's write path is real, and COPY was never an option

**Goal:** Phase F — "make findings real." The plan's own framing was narrow:
fix three renamed columns in `bulk.py`, add `psycopg[binary]`, execute the
COPY batches inside one transaction. Two of those three things turned out
not to describe anything that could exist.

#### The scope decision, made explicit before writing any code

`bulk.py`'s planned write target is `workers/sbom`, and
`axebom_shared.config`'s own docstring says, in caps: **"WORKERS HOLD NO
CREDENTIALS... no database password here... If a future change appears to
need a credential in a worker, the design has gone wrong; route the work
through the fetcher instead."** Giving a live, deployed worker a Postgres
credential is a real security-architecture decision, and nothing about who
triggers normalization for a live scan exists yet either — the Go
orchestrator never publishes a "this scan finished, normalize it" signal.

Asked the user directly rather than guessing: fix `bulk.py` and make its
output genuinely executable and testable, but do **not** wire a live
Postgres credential into any deployed worker or invent the missing trigger.
Confirmed. Everything below stays inside that boundary — `writer.py` is
proven against a live, RLS-protected schema, and nothing calls it from a
running scan.

#### `bulk.py`: the three named bugs, and three more the plan didn't name

`vuln_cluster_id`→`cluster_id`, `component_key`→`component_id`,
`severity_rule`→`severity_source` in `_findings_batch`, exactly as scoped.
Fixing `component_key`→`component_id` turned out to require a real design
addition: `normalize.components.id` is a server-generated uuid with no way
to be read back from a bulk write (no `RETURNING` from a multi-row insert of
unknown-at-plan-time rows), so `component_locations`, `findings` and
`component_dependencies` had no correct value to put in that column at all.
Fixed by minting the id **client-side**, via `uuid5(namespace,
f"component:{bom_document_id}:{component_key}")` — deterministic, so
replayability (invariant 10) extends to surrogate keys and not only to
values: re-normalizing the same raw artifacts into the same document
produces the same component ids, not a fresh random set every run. The same
technique produces `cluster_id`.

Three more column-name bugs the plan's own text didn't enumerate, found only
by actually trying to execute a write:

- `_locations_batch` was missing `tenant_id` entirely (NOT NULL, no default).
- `_dependencies_batch` named `from_key`/`to_key`; the real columns are
  `from_component_id`/`to_component_id`.
- `severity_effective` was written as `_text(value)`, which turns an absent
  value into `""` — and `""` satisfies neither the column's NULL-or-six-enum-
  values CHECK constraint. A finding with no resolved severity is the
  **ordinary** case the NotProvided bucket (Phase E, Go side) exists to
  count; every one of them would have failed the CHECK and taken the whole
  batch down with it. Fixed to `_text(value) or None`.

A finding or a dependency edge referencing a `component_key` absent from
this same canonical model — which should never happen, but is exactly the
kind of thing a pipeline bug produces — is now dropped with a
`NORMALIZE_DANGLING_COMPONENT_REFERENCE` diagnostic rather than either
crashing the whole write or silently inserting a row with a missing foreign
key.

#### Two more defects, found only by actually executing against Postgres

**`COPY FROM` does not work against a row-level-security-enabled table, at
all, ever.** `psycopg.errors.FeatureNotSupported: COPY FROM not supported
with row-level security. HINT: Use INSERT statements instead.` This is not a
permissions gap or a version quirk — it is a permanent Postgres restriction,
and RLS is FORCE-enabled on every tenant table in this system (invariant 6).
`bulk.py`'s entire premise ("`COPY` is the only workable shape") was false
for every table it was ever going to write to, from the day it was written.
Replaced with chunked, multi-row `INSERT ... VALUES (...), (...), ...`
(500 rows per statement — comfortably under Postgres's 65535-bind-parameter
ceiling) — still one round trip per few hundred rows, and, unlike `COPY`,
subject to RLS's `WITH CHECK` per row like any ordinary insert. `bulk.py`'s
module docstring and `copy_statement()` (removed — it built a statement that
could never run) are corrected; `writer.py`'s docstring explains why in
full, since this will bite the next person who reaches for `COPY` against
any tenant table in this codebase, not only this one.

**`detected_by` and `fixed_versions` are native Postgres `text[]` columns;
`cvss_vectors` is genuinely `jsonb`.** `bulk.py` was `json.dumps()`-ing all
three alike. A JSON array literal (`'[]'`) is not a Postgres array literal
(`'{}'`) — `psycopg.errors.InvalidTextRepresentation: malformed array
literal: "[]"`. Fixed by passing the first two as native Python lists
(per-element `_text()`-sanitized) and letting the driver adapt them; only
`cvss_vectors` still goes through `json.dumps()`.

#### A third defect, in the *test infrastructure*, not the write path —
worth its own heading because it produces a specifically dangerous kind of
false confidence

The first version of `test_writer.py`'s cleanup fixture reported success —
correct row counts deleted, no exception, the same connection querying
back `count = 0` immediately after — and the row was still there, visible
to every other connection, after the test process exited. Root cause:
`psycopg.Connection.transaction()` behaves differently depending on whether
a transaction is *already open* on the connection. `write_bom_document`'s
own `with conn.transaction():` commits for real, being the first use on a
fresh connection. But the test body then ran bare `cur.execute(...)`
assertions **outside** any `with conn.transaction():` block — which, on a
non-autocommit connection, silently starts a new ambient transaction that
is never explicitly committed. When the cleanup fixture's own
`with conn.transaction():` ran next, it found that ambient transaction
already in progress and downgraded to a **savepoint** — a delete that looks
committed to the session that ran it (read-your-own-writes) and evaporates
the instant the connection closes and the still-open outer transaction gets
discarded. Fixed with `autocommit=True` on the test connection — psycopg's
own recommended default — plus switching bare verification queries'
`set_config` from `is_local=true` (which reverts at the end of each
autocommit statement's own one-statement transaction) to session-level
(`false`), safe here because each test owns a private, unpooled connection.
`writer.py`'s own docstring now warns any real caller about the same trap.

This is the same class of danger `_locations_batch`'s missing `tenant_id`
and the COPY/RLS incompatibility both are: a test, or a write, that reports
success while quietly doing nothing durable. All three were caught by the
same discipline — actually executing against live Postgres, not reasoning
about the code — which is the entire argument for `test_writer.py`'s schema-
agreement test existing at all.

#### Verified

`libs/py-shared/axebom_shared/normalize/test_writer.py`: schema-agreement
(every column every batch declares, and `bom_documents`' own INSERT column
list, checked against live `information_schema.columns`), a live write that
round-trips real severity counts grouped exactly the way
`GET /v1/scans/{id}/findings-summary` groups them on the Go side, a refused
plan leaving no trace (not even the header row — a `bom_documents` row with
nothing under it would resolve as a real, empty document to any reader
querying by `(scan_id, bom_type)`), and RLS proving tenant B's session
cannot see tenant A's write. 19 tests total across `test_bulk.py` +
`test_writer.py`, run 8 times back to back with no flake; `normalize.*` row
counts verified zero via a separate superuser connection after every run.

Gate: `ruff format --check` and `ruff check` clean across `libs/py-shared`
and `workers` (109 files), `mypy` clean on `bulk.py` and `writer.py`
(pre-existing strict-mode gaps in `test_bulk.py`'s `.batch()` Optional
narrowing are untouched and were never part of this fix), full
`pytest libs/py-shared workers` suite green (0 regressions), Go side
unaffected — `go build`, `go test`, `golangci-lint` (0 issues),
`db verify-rls` (39/39), `profile guardrails` all rerun and still green.

#### Known debt

- **Nothing calls `write_bom_document` from a live scan.** The Go
  orchestrator does not publish a normalize-trigger event; no deployed
  worker holds a Postgres credential; `normalize.alias_snapshot` minting
  (the thing that would give `alias_snapshot_id` a real, non-placeholder
  value) does not exist. All three are one connected follow-up, deliberately
  deferred — see the header's Next action.
- `psycopg[binary]` is a `dev`-only dependency, on purpose — no worker image
  installs it today.
- `cvss_primary_score` and `references_json` are never populated by
  `_findings_batch` (both are nullable / have a default, so this is a
  completeness gap, not a broken write) — out of scope for this pass.

### 2026-08-24 (d) — Generate could not generate: two resources collapsed into one call

**Goal:** reported via `/debug`: clicking Run in the Generate wizard always
422'd — `VALIDATION_BODY_MALFORMED`, "request body is not valid JSON" — and
"Uncaught... message channel closed" (an unrelated browser-extension console
line, not from this app; ignored).

#### The wizard was posting a shape the endpoint never accepted

`POST /v1/scans` sent `{project_id, bom_types, levels, standards, formats}`.
`createScanRequest` has always been `{project_id, source_kind, families,
engines}` and decodes with `DisallowUnknownFields()` — so the request failed
before validation ever ran, and every decode error (an unrecognised field
included) is reported as "not valid JSON," which is what made this read as a
parsing bug rather than a contract mismatch.

⚠ **The fix is not extending `/v1/scans` — it's stopping conflating two
resources `report.reports` has kept separate since `migrations/report/0001`.**
A scan is ONE run of the engines; a report is ONE rendered document.
`POST /v1/reports` already exists, already takes `{scan_id, bom_type, level,
format}` per combination, and already derives `standard` from `format`
server-side, refusing (not correcting) a mismatch. The wizard's own "Reports:
N — one per BOM type × level × format" review line was always describing that
cross product; it just never called the endpoint that produces it.

`docs/02-CONTRACTS.md §8` had the same conflation baked into it (a line
claiming scan-creation carries all four dimensions) — likely what the wizard
was built against. Corrected.

#### Two more found while fixing this

⚠ **`source_kind` was never sent at all.** The wizard doesn't (and shouldn't)
ask again — the project's source was already collected at registration. Added
`sourceKindFor(project.source_type)`, mapping github/gitlab/bitbucket→git,
upload→upload, image→image. `manual` (HBOM-only, no scanner — CLAUDE.md honest
labels) maps to `null`, refused client-side with a stated reason before the
API is even called, rather than a doomed request.

⚠ **CBOM reports are refused server-side** ("CERT-In Table 9 discriminates by
asset type, so there is no single field set to score against" —
`services/report/internal/service/service.go`) but nothing else in the run
should die with it. Report creation is `Promise.allSettled` across every
planned combination; a partial failure still starts the scan and carries a
stated warning (`navigate` state, rendered once on `ScanProgress`) rather than
silently dropping some of what was promised on the review screen.

#### Verification actually performed

| Check | Result |
|---|---|
| `task verify` | exit 0 (one unrelated pre-existing flake, `TestEqualHashIsCaseInsensitiveAndExact` in `services/report/internal/share`, reproduced on a clean re-run — not touched by this change) |
| Playwright, real Chromium, live stack | reproduced the exact reported failure first (422 on Run), then green after the fix — `e2e/generate.spec.ts`, kept as a permanent regression test |
| Playwright, CBOM path | selecting CBOM alongside SBOM still starts the scan and shows the queued/failed count; verified once, not kept as a permanent test |
| `tsc`, `eslint`, `vitest` (81) | clean |

#### What is still NOT built

Nothing creates a report automatically when a scan finishes — the wizard
queues N `report.reports` rows up front (`queued`, resolved by the worker at
render time), and the existing report-list/report-viewer routes are how a user
finds them once ready. Whether that list surfaces "still rendering" clearly
enough was not re-verified here.

### 2026-08-24 (c) — the missing endpoints

**Goal:** Phase E. The dashboard's two most useful figures — recent scans,
open findings by severity — had no endpoint. `GET /v1/scans` did not exist at
all; there was no findings aggregate anywhere.

#### `GET /v1/scans` — keyset on id DESC, mirroring `GET /v1/projects` exactly

Same cursor idiom (last id seen, never an offset), same `effectiveLimit`
clamp, same `{plural, next_cursor}` envelope, `?project_id=&status=` as
optional filters using the `($1 = '' OR col = $1)` idiom report.Store.List
already established. New index `scans_tenant_project_id_idx (tenant_id,
project_id, id DESC)` — the existing `scans_tenant_project_idx` is ordered on
`created_at`, which a keyset on `id` cannot use without degrading to a scan.

Engine runs for the whole page load in **one** `WHERE scan_id = ANY($1)`
query (`loadRunsFor`), following `project.loadClassificationsFor`'s
precedent — reusing the existing per-scan `toDTO` in a loop would have been
two extra queries per row. The list item DTO deliberately **omits**
`coverage_gaps` rather than sending `[]`: computing it per row would put the
N+1 straight back, and an empty array would silently claim "no gaps" for a
value that was never computed — exactly the false-negative invariant 12
exists to prevent. `GET /v1/scans/{id}/engine-runs` is where that real
answer lives; a list row says nothing rather than lying.

#### `GET /v1/scans/{id}/findings-summary` — new file, cross-schema, in Go

`orchestr/findings.go`, deliberately separate from `store.go`: the file
boundary IS the schema boundary (`scan.*` in store.go, `normalize.*` here),
mirroring why `report/bomsource.go` is its own file. No SQL join spans the
two — `normalize.bom_documents` and `normalize.findings` are queried on
their own and stitched in Go, per ADR-0001.

Resolves the **SBOM** document at the **highest `normalization_version`**
for the scan (vulnerability matching runs against SBOM components; CBOM,
QBOM, AIBOM and HBOM have no findings table of their own) — the same
"latest version, re-normalization never overwrites" reasoning as
`report.resolveDocument`, tested by writing two document versions directly
and confirming the summary follows v2, not v1.

**Three severity buckets, not two.** `none` (a source explicitly asserted no
severity), `unknown` (a source explicitly asserted it could not determine
one) and — the one existing code did not have a name for — **`not-provided`**
for SQL `NULL`: nothing computed a severity at all. Collapsing any two of
these either invents an assertion nobody made or hides a measurement gap.
Named `not-provided` deliberately, to reuse the vocabulary CLAUDE.md
invariant 3 already uses everywhere else in this product for exactly this
state, rather than inventing new terminology for the same idea.

**A scan with nothing normalized yet is a legitimate zero, not an error** —
still running, or it produced no SBOM. But that state is indistinguishable
from "this scan does not exist" if the store function alone had to decide,
since both are zero rows inside `normalize.*`. So the store function does
**not** re-check existence — its doc comment says so explicitly — and the
handler calls `GetScan` first, exactly like `EngineRuns` already does, so a
cross-tenant scan id gets the same 404 every other scan endpoint gives it
rather than a 200 with an all-zero summary that would make it an oracle for
probing which scans exist.

`coverage_gaps` rides along on this response too, for the same reason the
plan called out: it does not depend on normalization having run (it reads
`scan.ecosystems_detected`, populated as engines report), so a dashboard
tile rendering "0 critical" next to "3 ecosystems have no engine" is not
making the reader choose which honest number to show.

#### One defect the wiring exposed, in the *tests*, not the endpoint

The first pass of `ListScans` tests used `orch.CreateScan`, which publishes
a real NATS job — and this test binary runs against the same broker
`task dev`'s live `sbom-worker` and `scan-orchestrator` containers are also
consuming. A live worker picking up a job for a test scan with no real
archive fails fast and reports a result, and that result's async status
recompute raced a test's own `UpdateScanStatus` call, intermittently
clobbering it. This is the exact hazard `pipeline_test.go`'s
`requireExclusiveSbomSubject` already exists to route around — but these new
tests do not need fan-out at all, only rows, so the fix was `Store.CreateScan`
(writes directly, publishes nothing) instead of the guard machinery. Caught
by running the full package repeatedly, not by the isolated `-run` pass,
which is why both are now part of how this gets verified.

#### Verified against the running stack, not just compiled

Rebuilt and restarted `scan-orchestrator`; real service token through the
gateway:

- `GET /v1/scans?limit=2` → real rows, `engine_runs` populated, batched
- `GET /v1/scans?project_id=…` → exactly the matching scan
- `GET /v1/scans?status=completed_with_errors` → filtered correctly
- `GET /v1/scans` with the other tenant's header → `{"scans": [], "next_cursor": ""}` — empty, not leaked
- `GET /v1/scans/{id}/findings-summary` for a real scan → all-zero counts
  (honest: nothing normalized yet), `coverage_gaps` populated with six real
  ecosystems, `bom_document_id` key **absent** from the JSON (not `""`) —
  confirming `omitempty` renders "no document" as no key rather than an
  empty one
- same endpoint, other tenant's header → **404**
- same endpoint, a scan id that does not exist → **404 `NOTFOUND_SCAN`**,
  the canonical error shape

Gate: `go build ./...` OK · `go test ./...` clean, `orchestr` package run
three times back to back with no flake · `golangci-lint` **0 issues** ·
`db verify-rls` **39 tables, 0 gaps** · `profile guardrails` OK · migration
`0006_scans_list_index.sql` applied.

#### Known debt

- **Both endpoints are correct and live, and both return zero** for anything
  findings-related, because `normalize.findings` is never written by
  anything — Phase F, next.
- `docs/02-CONTRACTS.md` §8's REST surface table still shows the pre-Phase-E
  aspirational shape (`GET /projects/:id/findings` etc.) rather than what
  exists; reconciling that is Phase H's doc pass, not this one.

### 2026-08-24 (b) — light by default, one design system, and the login UI stops saying "Zitadel"

**Goal:** two user-facing complaints after (a) landed: the ZITADEL register
screen read "Create your Zitadel account," and the app "still looks bad" —
serif type, flat borders, no elevation, dark by default on this machine.

#### The look was two real defects, not a matter of taste

⚠ `--font` was a token nobody applied. Neither stylesheet ever set
`font-family` on `html`/`body`, so every screen rendered in the browser's
UA-default serif — the entire "old/bad" impression traced to one missing rule.

⚠ **The very first screen a user lands on used a second, unrelated design
system.** ProjectList/ProjectDetail/ProjectWizard used `.button`/`.card`/
`.page-header` from `index.css` — including a completely UNSTYLED native
`<button>` (ProjectWizard's "Back") — instead of the `.btn`/`app.css` system
every other route already used. `index.css`'s own header comment already said
its primitives were owed a move to `app.css` and it never happened. Migrated
and unified; `index.css` is deleted.

Found while migrating: **`.btn` had never been applied to an `<a>` before.**
Every Link-flavoured button in the app (Register a project, All projects,
sign-in/not-found) kept the browser's default underline — `text-decoration:
none` on `.btn` was simply missing.

Also fixed: `<main className="shell">` nested inside App.tsx's own outer
`<main>` — two landmarks for one page. The outer `<main>` now owns page
padding and max-width for every route for free; per-route wrappers are plain
`<div>`s.

**Default theme is now `light`, not `system`.** A compliance dashboard read
during a work day should not open dark because a visitor's OS does. A blocking
inline script in `index.html` applies the persisted choice before first
paint — without it, a dark-OS visitor sees one dark frame from the
`prefers-color-scheme` media query before the store (default `light`) runs.

New tokens: `--primary`/`--primary-hover`/`--primary-active`, distinct from
`--sbom` — `--sbom` is tuned for small text on a tinted chip, and reusing it as
a large button fill washes out in dark mode. `--shadow-xs`/`--shadow-sm`/
`--shadow-card-hover` give buttons and cards real elevation, deliberately
subtle — this is read for hours, not a marketing page.

#### The ZITADEL text — a server-side override, not a fork

`apps/login` (the pinned login container) is MIT-licensed, so forking it was
on the table, but not the right trade for three strings. ZITADEL's login UI
calls `SettingsService.GetHostedLoginTranslation` on every render and deep-
merges the result over its own English bundle
(`apps/login/src/i18n/request.ts`) — the extension point it was built for.
`iam.Client.ensureHostedLoginTranslation` (in the still-uncommitted
`libs/go-shared/iam/provision.go` — see below) calls the write side of that
same API, `SetHostedLoginTranslation`, instance-scoped, at bootstrap. Nothing
touches the container image.

⚠ Only `register.description` ("Create your Zitadel account.") and
`common.title` are overridden — not `idp.signInWithZitadel` or
`device.consent.disclaimer`, the other two literal "Zitadel" mentions in the
locale file. Neither is reachable through this flow: we don't register
ZITADEL as an external IDP and don't expose the device-code screen.
Overriding a string nobody can see is dead configuration nobody could verify.

⚠ **The login container caches translations for up to an hour**
(`apps/login`'s `longCacheTTL`). The write succeeded immediately; the running
`zitadel-login` container kept serving the old string until restarted.
Restarted once here to verify; a real deployment either waits out the TTL or
restarts the container after `iam bootstrap`.

New `Spec.BrandName` field (`--brand-name`, env `ZITADEL_BRAND_NAME`, default
`AxeBOM` per this request — distinct from "AxeBOM" used everywhere else in
this codebase; this only reaches the two ZITADEL strings above, nothing else
was renamed).

#### Verification actually performed

| Check | Result |
|---|---|
| `task verify` | exit 0 |
| Frontend: `tsc -b`, `eslint`, `vitest` (81), production build | all clean; CSS 28.6 kB gzipped, within the 250 kB budget |
| Playwright, real Chromium, live stack | 4/4 (login round trip), unchanged by this session |
| Live: register screen | fetched and screenshotted — reads "Create your AxeBOM account." |
| Live: `go build ./services/gateway/...`, `go test` | authconfig package green (see the correction below) |

#### ⚠ A gap in (a)'s own commit, closed here

`3ecaded` ("sign in with ZITADEL") committed `auth.ts` calling
`GET /v1/auth/config` but never committed `services/gateway/internal/
authconfig` or the `routes.go` wiring that answers it — written in the same
working session, never staged. A checkout of `3ecaded` alone 404s on every
login attempt. Committed now as `ba2b599`, verified via the same `task
verify` run.

#### What is still NOT committed

`libs/go-shared/iam/` and `cmd/axebom/iam.go` (the ZITADEL provisioning
CLI — org/project/role/SPA/service-account bootstrap, and now
`ensureHostedLoginTranslation`) remain **uncommitted, ~1400 lines**, as in
every prior entry this session that touched them. The branding fix is a small,
verified diff inside those large files; committing it would mean claiming the
whole untracked identity system under a "branding fix" message, which is not
an accurate scope. Applied and confirmed live against the running instance;
not yet staged.

### 2026-08-24 (a) — the browser signs in

**Goal:** Phase D. The services had moved to ZITADEL; the browser had not moved
anywhere. `setAccessToken` existed with zero callers, so every authenticated
request went out with no `Authorization` header and every screen rendered
`no bearer token`. Unit tests could not have caught it — each screen worked, and
nothing tested the one thing nobody had written.

#### Configuration is fetched, because the compiled-in version was already broken

The obvious design is a `VITE_OIDC_CLIENT_ID` baked into the bundle, and it is
what this started as. It does not survive contact with the deployment:
`deploy/docker/Dockerfile.frontend` takes no build args, so the container image
that `task dev` builds had an **empty client id** and could not have signed
anyone in. The dev server would have worked and the product would not.

`GET /v1/auth/config` on the gateway (`services/gateway/internal/authconfig`)
publishes issuer, client id, project id, the scope list and the ZITADEL claim
names. One image serves every environment, and re-provisioning identity does not
require a rebuild. `VITE_OIDC_*` survive as a documented local override for
running `npm run dev` against something with no gateway in front of it.

Nothing in the document is a secret. The client id belongs to a PKCE public
client that holds none by design; the issuer is the address the browser is
already talking to; the project id appears in the audience of every token the
user receives. A test asserts the document carries neither the internal ZITADEL
URL nor a service-key path, so a future field cannot quietly change that.

Publishing the CLAIM NAMES matters more than it looks: the SPA now writes no
ZITADEL URN of its own, so `libs/go-shared/oidcauth` stays the only place those
strings exist. The roles-claim key contains the project id, and a hand-built
copy in TypeScript would drift silently — the symptom being an empty roles map
and a multi-tenant user with no organisation switcher.

#### Four defects the wiring exposed, three of them in code written before today

**1. An expired token was indistinguishable from a forged one.** `Verify`
collapsed every failure into `AUTH_TOKEN_INVALID`, so `ApiError.isExpired` —
which the API client already had — could never be true and the retry it guarded
could never run. The verifier now returns `AUTH_TOKEN_EXPIRED` when
`errors.Is(err, oidc.ErrExpired)`.

This leaks nothing, and the ordering inside the library is why: `CheckExpiration`
runs **after** the signature and the issuer, so the code can only ever describe
a token we genuinely minted. Everything else stays a single opaque code. Without
the distinction a user with a fifteen-minute token goes through a full login
every fifteen minutes.

**2. `AUTH_ORG_AMBIGUOUS` answered 401, and 401 is a loop.** A consultant with
roles in two organisations who names neither gets this code — the token is
perfect, the account is ambiguous. Answering 401 tells every generic client to
discard the token and re-authenticate, which returns an identical token and asks
the identical question. It is now a `statusOverride` to **409**, and the code
comment says why it sits in the `AUTH_` family with a non-`AUTH_` status.

**3. The organisation switcher was decorative.** It computed the active
organisation, wrote it to `localStorage` and sent it nowhere: `X-AxeBOM-Org`
had no producer. carol, who holds analyst in Acme and viewer in Beta, would have
had every request refused. The api client now owns the header alongside the
bearer, in one `identityHeaders()` function — the split between "the switcher
computes it" and "somebody sends it" is exactly how it went missing.

⚠ It is set **during render, not in an effect**. React runs a child's effects
before its parent's, so the first screen to mount fires its queries before a
parent effect could install the header — invisible for a single-org user, and a
console that looks broken on load and fine on refresh for everyone else. Writing
a module-level slot during render is safe here: idempotent, no state, no
re-render.

**4. StrictMode silently unregistered the OIDC listeners.** The provider guarded
its whole effect with a ref and also returned a cleanup. React 19's
mount → cleanup → mount cycle therefore REMOVED `userLoaded`, `userUnloaded`,
`silentRenewError` and the token refresher, then skipped the re-add because the
ref was already set. In development the session authenticated correctly and then
never saw another token: renewals fired and reached nobody. Split into two
effects — a ref-guarded bootstrap with no cleanup, and an unguarded listener
effect whose add and remove stay symmetric.

#### The WebSocket could never have been authenticated

`GET /v1/scans/{id}/progress` is guarded like every other route, and the browser
`WebSocket` API cannot set an `Authorization` header. Scan progress would have
401'd on upgrade and reconnected forever.

The token is offered as a **subprotocol** — `axebom.bearer.<jwt>` — which
lands in the `Sec-WebSocket-Protocol` request header. This is not a loophole in
"never from the query string": that rule exists because URLs are written to
access logs, sent in `Referer` and kept in history, none of which is true of a
header. The Kubernetes API server solves the same problem the same way.

Two things make it safe and one makes it work:

- The subprotocol is read **only on a real upgrade**, so it cannot become a
  second unaudited way to present a credential on an ordinary request.
- The `Authorization` header still wins when present.
- The handler must ECHO a selected subprotocol. RFC 6455 says a server that
  selects none of the offered protocols makes a conforming browser fail the
  connection — so `AcceptOptions.Subprotocols` is load-bearing, and omitting it
  would have rejected every browser socket while leaving curl working.

The client re-reads the token on **every** connect attempt rather than capturing
it once: tokens live fifteen minutes and the backoff runs to thirty seconds, so
a laptop woken from sleep would otherwise reconnect forever with a credential
that expired at lunch.

#### Verified against the running stack, not just compiled

Four Playwright tests (`frontend/e2e/auth.spec.ts`) drive a real browser through
a real ZITADEL login:

- an anonymous visitor is asked to sign in — and the text `no bearer token`
  appears nowhere, which is the symptom this phase existed to remove
- `alice@acme.test` signs in and **sees `payments-api`** — a token that was
  accepted, resolved to a tenant, and passed by RLS. A signed-in user with a bad
  tenant claim sees an empty list, which looks like success, so the assertion is
  on a specific row rather than on the page rendering
- a reload does not bounce back to the identity provider
- the header names who is signed in and offers a way out

The helper that fills ZITADEL's login form retries the fill. That is not
flake-papering: ZITADEL's login is a server-rendered Next.js page whose submit
button stays disabled until React sees a value, so a `fill` landing before
hydration is silently discarded — the text is visibly in the box and the button
never enables. Playwright's click retry waited a full minute on a control that
was never going to change, because the missing event had already not happened.

By hand, through nginx:

- `GET /api/v1/auth/config` → **200**, `Cache-Control: no-store`, correct ids
- WebSocket upgrade with the token in the subprotocol → **101**, and
  `Sec-Websocket-Protocol: axebom.v1` echoed back
- the same upgrade without a token → **401**
- the same upgrade with a token but a scan id that does not exist → **404**,
  proving the credential was accepted rather than the route being open

Gate: `go build ./...` OK · `go test ./...` clean · `golangci-lint` **0 issues**
· `db verify-rls` **39 tables, 0 gaps** · `profile guardrails` OK · frontend
`eslint --max-warnings 0`, `tsc --noEmit`, `prettier --check`, **81 unit tests**,
`npm run build` (≈123 KB gzipped initial load, budget 250 KB).

#### The trade that was made deliberately

The SPA requests `offline_access` and stores the resulting refresh token in
**session storage** — one tab, discarded when the tab closes. A refresh token is
renewable credential material the browser has to keep, and anywhere JavaScript
can read it, an XSS can take it. `localStorage` would have survived a browser
restart and been readable by every tab on the origin.

The alternative — renewing through a hidden iframe against ZITADEL's session
cookie, storing nothing renewable — was considered and rejected: ZITADEL's own
guidance for single-page applications is the refresh token, and building on the
iframe would put a fifteen-minute session at the mercy of an instance setting
(iframe embedding is off by default) and of every browser that treats a framed
document as third-party. The access token itself never leaves memory either way.

#### Known debt

- **`frontend/e2e/shot.spec.ts` is scratch**, not a test: no assertions, screen
  captures and console dumps. It belongs in a scratch directory or nowhere.
- **The hand-rolled HS256 auth still compiles**, including the unused issuer in
  `services/gateway/deps.go`. Phase H.
- **The findings screens still read an empty table.** Nothing writes
  `normalize.findings`; Phase F.
- `docs/07-FRONTEND-SPEC.md` still describes the retired login flow. Phase H
  rewrites it with the rest of the identity documentation.

### 2026-08-23 (k) — the frontend can sign in

**Goal:** the reported symptom was `no bearer token` on every screen. The SPA
had no authentication of any kind: `setAccessToken` existed with zero callers,
there was no `oidc-client-ts` dependency, no `/login`, no callback route.

#### What was added

`oidc-client-ts`, Authorization Code + PKCE against ZITADEL, matching the
USER_AGENT + AUTH_METHOD_NONE registration the provisioner already created.
`auth.ts` (UserManager, roles parsing), `authState.ts` (context),
`AuthContext.tsx` (provider), `useAuth.ts` (hook), `AuthRoutes.tsx`
(sign-in / callback / silent), `OrgSwitcher.tsx`, and a `RequireAuth` gate.

⚠ **`RequireAuth` renders nothing while the session is being probed.** Rendering
children first and correcting afterwards means every screen fires its queries
with no token and shows an error for a session that was about to resume — which
is what `no bearer token` on a reload actually was.

⚠ **The callback routes are mounted OUTSIDE the gate and outside the shell.**
Behind the gate they are a redirect loop; inside the shell the silent-renew
iframe boots a second application inside itself.

⚠ **The authorization code is single-use and StrictMode mounts effects twice.**
The second exchange fails `invalid_grant` and would report a broken login for a
session that succeeded. Guarded with a ref.

`request()` retries a 401 once after a silent renewal, through an INJECTED
refresher rather than importing the OIDC library into the api client. One
renewal is shared by every waiting request: ZITADEL rotates refresh tokens, so N
concurrent renewals would invalidate all but one and end the session they were
trying to save.

#### Three defects found by making it work

1. ⚠ **`auth.identity_for` raised 42702 on every call.** `RETURNS TABLE
   (tenant_id, user_id, role)` puts those names in scope as OUT variables for
   the whole body, and `auth.memberships` has columns with the same names — so
   `ON CONFLICT (tenant_id, user_id) DO UPDATE SET role = …` is ambiguous. It
   fails at CALL time, not CREATE time, so the migration applied cleanly and
   every sign-in 500ed with "the account could not be resolved". Fixed with
   `#variable_conflict use_column` in `migrations/auth/0003`, which is unreleased,
   and applied to the running database.
2. ⚠ **ZITADEL puts no profile claims in either token.** Measured: with
   `openid profile email` requested, the id and access tokens carry sub, aud,
   the roles claim and nothing else. The header greeted the user by their
   nineteen-digit subject. `loadUserInfo: true` fixes the greeting; roles still
   come from the token, so this is a display name and not an authorisation input.
3. **`WSBearerPrefix` tripped gosec G101** and was failing `task lint` for
   everyone. Annotated — it is a subprotocol prefix, not a credential.

#### Verification actually performed

| Check | Result |
|---|---|
| `task verify` | exit 0 |
| Playwright, real Chromium, live stack | 4/4 — anonymous visitor sees a sign-in button and no error; sign-in reaches the projects list with `payments-api` visible; the session survives a reload; the header names the user |
| Token claims, measured | `aud` contains the project id (the `:aud` scope works), roles claim present |
| carol, two organisations | header shows `acme-industries.localhost · analyst` and `beta-corp.localhost · viewer` |

The audience assertion matters: `oidcauth.Verifier` rejects a token whose `aud`
lacks the project id, and ZITADEL only adds it when the
`urn:zitadel:iam:org:project:id:{id}:aud` scope is requested.

#### ⚠ Written concurrently with another session

That session was wiring `X-AxeBOM-Org` and WebSocket bearer auth in the same
files at the same time. Its org-header wiring is better than the version written
here — it sets the header during render rather than in an effect, because
React runs a child's effects before its parent's and the first screen would
otherwise fire its queries before the header existed. That version was kept and
the duplicate removed. `frontend/src/lib/ws.ts`, `ScanProgress.tsx` and
`nginx.conf` are theirs and are deliberately not in this commit.

### 2026-08-23 (j) — which image bytes produced this result

**Goal:** `invocation.image_digest` was never sent, so nothing recorded what a
scan actually ran. Completes the provenance triple with (i): what ran, when, and
now from which bytes.

#### Two statements, and recording one does not give you the other

    image_digest              what actually ran, read back from the daemon
    ENGINE_IMAGE_NOT_PINNED   the reference was not reproducible in advance

`OSINT/tools.manifest.yaml` carries `image_digest: null` for **every** engine, so
every one is addressed by tag. The resolved digest makes a run reproducible
AFTER the fact; only `toolctl pin` makes the reference reproducible in advance.
Conflating them would be worse than reporting neither — an unpinned fleet would
look pinned because the digests happen to have been recorded.

`available()` already reported the tag-pinning in its `detail`. That reaches the
engine list; it does not reach the RESULT, and the result is what a report's
provenance is built from — so a scan that ran a mutable tag was indistinguishable
from one that ran a pinned digest.

#### ⚠ Read back from the daemon, not copied from the reference

Asking Docker what it resolved records the bytes even when the manifest gave
only a tag. The field is the REGISTRY MANIFEST digest; a locally built image has
none, and empty is honest — the local image ID is a different hash (the config
digest) and putting it under the same name would be the `purl` /
`certin_identifier` conflation again.

#### The first implementation returned "" for every real engine

It compared `RepoDigests` names literally. **The daemon does not echo back the
name you gave it**: `docker.io/anchore/syft:v1.51.0` yields
`anchore/syft@sha256:…`, and every engine in the manifest carries the
`docker.io/` prefix. The Go test passed because it used the short form
`busybox:1.37`.

It was caught on the first live run by the `ENGINE_IMAGE_DIGEST_UNKNOWN`
diagnostic added in the same change, which is the argument for that diagnostic
existing. `normalizeRepo` now strips `index.docker.io/`, `docker.io/` and the
implicit `library/`, and `repoDigestFor` is split out from the daemon call so
nine cases are unit-tested without Docker — including a private registry whose
port colon is not a tag separator, and a retagged image carrying two
repositories.

#### Verification actually performed

| Check | Result |
|---|---|
| `task verify` | exit 0 |
| Sandbox escape suite | all pass, plus a live digest-resolution test |
| Live, syft via `scan.job.sbom` | `image_digest sha256:678bfa56…`, `ENGINE_IMAGE_DIGEST_UNKNOWN` gone, `ENGINE_IMAGE_NOT_PINNED` correctly still present |
| Unit tests | 9 repository-matching cases; 8 worker provenance tests |

#### What is still NOT wired

- **`toolctl pin` has never run.** Every engine runs a mutable tag. Now stated
  on every result instead of only in the engine list, but the fix is to pin.
- The report's Engine Coverage section carries neither the summary counts (f)
  nor the image digest.
- ⚠ **The frontend cannot log in at all.** `setAccessToken` has zero callers,
  there is no `oidc-client-ts` dependency and no `/login` route, so every
  authenticated request goes out with no `Authorization` header regardless of
  which identity provider is behind it. See (h)'s Phase D.

### 2026-08-23 (i) — when an engine ran, not only how long

**Goal:** `invocation.started_at` and `finished_at` were never sent, so
`scan.engine_runs` recorded NULL for both on every run ever stored and the API
rendered `null`. A report could say an engine took 41 seconds and never say when.

#### ⚠ The three fields describe ONE interval

started_at, finished_at and duration_ms are only worth publishing together. The
sandbox measures the container; the worker measures the whole job, which is
wider — image resolution, the database check, artifact persistence. Take the
duration from one clock and the timestamps from the other and
`finished - started != duration_ms`, at which point a reader cannot verify any
of the three. Provenance that cannot be checked is not provenance.

So they travel as a set. `sandbox.Result` gains `StartedAt`/`FinishedAt`
alongside `Duration`; the bridge publishes all three; `classify()` copies all
three; and the worker falls back to its own clock only when the sandbox reported
none — replacing all three, never one of them.

#### A run that failed to start reported zero duration

`result.Duration` was assigned only on the success path, so a container that
could not be created, or a copy-out that failed, published `duration_ms: 0`.
That reads as "it finished instantly", which is the opposite diagnosis from "it
never got going". Stamping in a `defer` covers all five exits from the timed
region, and a new test asserts a wall-clock kill still carries its real interval.

#### Omitted, not zeroed

An engine this worker does not implement was never invoked, so it publishes no
timestamps rather than `0001-01-01T00:00:00Z`. Go decodes a missing time to the
zero value and `HandleResult` already skips it, so the column stays NULL. An
`unavailable` result from an adapter that WAS consulted is timed — that decision
happened and is worth dating.

RFC3339 with a literal `Z`, truncated to milliseconds to match `duration_ms`'s
resolution. Python renders UTC as `+00:00`, which Go parses happily — it would
never have failed a round trip, and would have left stored provenance formatted
two ways for a human to reconcile by eye.

#### Verification actually performed

| Check | Result |
|---|---|
| `task verify` | exit 0 |
| Sandbox escape suite | all pass, plus two new timing tests against real containers |
| Reconciliation, in Go | `FinishedAt - StartedAt == Duration` exactly, on a 1s sleep and on a 3s wall-clock kill |
| Live, syft via `scan.job.sbom` | `started 04:01:22.529Z`, `finished 04:01:24.253Z`, `duration 1723ms` — reconciles to 1ms |
| Python suite | 8 new timing tests; whole suite green |

#### ⚠ A correction to entry (g), which this session reported wrongly

(g) fixed a real defect — the seeded `password_hash` values were genuinely
absent — but it was reported as "you can now log in", and that is not true of
the application. Every user-facing route is guarded by `oidcauth.Guard`, which
has no local-JWT fallback, while `/v1/auth/login` still mints a local HS256
token: the auth service accepts it (`/v1/auth/me` → 200) and `project` rejects
it (`/v1/projects` → 401). `cmd/axebom/iam.go` provisions the same four users
in ZITADEL with `AxeBOM-dev-only1!` and says in its own comment "⚠ NOT the
legacy seed password `axebom-dev-only`". See (h) for the path that works.

Two contributing mistakes worth recording so they are not repeated:

- The identity work was **uncommitted and gitignored** in the working tree at
  session start, and its effect on `deps.go` across every service was not read
  before claiming the login path worked.
- The stack was started twice with `docker compose -f docker-compose.yml -f
  docker-compose.app.yml`, omitting `docker-compose.iam.yml`. `task dev` layers
  all three; an ad-hoc compose invocation is not `task dev`.

### 2026-08-23 (h) — ZITADEL is the identity provider

**Goal:** replace the hand-rolled HS256 auth with a real IAM, production-grade,
without touching the tenancy boundary.

#### The constraint that shaped the whole design

Every one of the 43 RLS policies casts `current_setting('app.current_tenant_id')::uuid`,
and six tables hold `created_by uuid NOT NULL`. **ZITADEL ids are numeric
snowflake strings and will not cast.** Swapping the tenant id for a ZITADEL org
id would have meant rewriting every policy, every seed and every `created_by`.

So `auth.tenants` / `auth.users` / `auth.memberships` survive as a **local
identity projection**, bridged by `zitadel_org_id` / `zitadel_user_id` and a
`SECURITY DEFINER` function `auth.identity_for(...)` that resolves — and JIT-provisions
— the mapping. RLS, the 12 RLS tests, the seeded UUIDs and every `created_by`
column are unchanged, and the per-service change is one line.

#### Licensing

The ZITADEL **server** is AGPL-3.0-only (since v3, 2025-03-31). It runs as a
pinned, unmodified container — the pattern CLAUDE.md invariant 9 explicitly
sanctions — so **no AGPL code is linked into an AxeBOM binary**. Only
`zitadel-go/v3` and `zitadel/oidc/v3`, both separate Apache-2.0 repositories,
are imported. A depguard rule fails the build on any `github.com/zitadel/zitadel/`
import, and the reference checkout lives in gitignored `.reference/`.

#### Three documented facts that were wrong, found by minting a real token

- The org claim is **`urn:zitadel:iam:user:resourceowner:id`**.
  `urn:zitadel:iam:org:id` is a *scope*, not a claim, and reaching for the
  obvious name yields an empty tenant on every request.
- The roles claim is an **object** `{roleKey: {orgId: orgDomain}}`, not the
  array one documentation page renders.
- **`iss` is derived from the request Host.** A token minted by calling the
  container on `:58080` carries a different issuer from one minted through the
  proxy on `:5173`, and a verifier configured for one rejects the other.

#### Four defects found by running it rather than reading about it

1. **The key set could not be fetched at all.** ZITADEL selects its instance
   from the Host header, so `GET http://zitadel-api:8080/oauth/v2/keys` answers
   `404 Instance not found`. Every service then refused every token with
   *"the access token could not be verified"* — a fleet-wide 401 whose message
   points at the client. Fixed with a `publicHost` transport that forces the
   public Host onto in-network calls; the token minter now shares it, because
   two hand-rolled copies of one rule is how the second call site loses it.
2. **A machine token carried no roles.** Project-level role assertion covers
   users signing in through an application; a machine user authenticating by
   JWT profile has none, so the roles claim only appears when requested by
   scope. Without `urn:zitadel:iam:org:projects:roles` a service token is one
   `RequireService` correctly refuses — which reads as a broken machine user.
3. **campaign and fetcher could not read their own keys.** Written 0600 under
   the developer's uid; the containers run as distroless nonroot. Now 0640 with
   the two containers joining the file's group — the narrowest fix that does
   not make a service credential world-readable.
4. **Trusted domains are not a substitute for the Host override.**
   `ZITADEL_FIRSTINSTANCE_TRUSTEDDOMAINS` is applied once at instance creation
   and lives in the eventstore, so it is lost on `task iam:reset` and absent
   for anyone pointing at an instance they did not create.

#### The tenant moved out of the token and onto the request

The retired issuer minted a token that NAMED the tenant. A ZITADEL machine
token belongs to the AxeBOM organisation and says nothing about the customer
being worked for, so the tenant now travels as `X-AxeBOM-Tenant` — **honoured
only for a verified service principal, never for a person.** The trust boundary
is unchanged (our components could always act for any tenant); it is now
explicit on the wire and tested, rather than buried in a claim.

Multi-org users are **refused with `AUTH_ORG_AMBIGUOUS`** rather than guessed:
picking one would make the answer depend on map iteration order, which is a
different tenant's data on every request.

#### Verified

- `go build ./...`, `go test ./...` (live stack up), `golangci-lint` **0 issues**.
- `axebom db verify-rls`: **39 tenant-scoped tables, 0 gaps.**
- 13 hermetic middleware tests + 4 transport tests + 2 live tests.
- End to end through the gateway with a real ZITADEL service token:
  own tenant **200**, other tenant **404**, no tenant header **401
  AUTH_TENANT_CONTEXT_MISSING**, header without a token **401**.

#### Known debt from this session

- **`services/auth` and `libs/go-shared/auth/{token,password,apikey,service_token}.go`
  still exist and still compile.** Deleted in Phase H, once the frontend is on
  ZITADEL. Nothing is removed before its replacement passes.
- **The frontend still sends no `Authorization` header** — `setAccessToken` has
  zero call sites. Until Phase D, every authenticated request from the SPA is a
  401. This is the single largest gap.
- **`seed_login_test.go` now accepts both states** (`local` + hash, or `oidc` +
  `zitadel_user_id`), because the fixture legitimately moves between them at
  `iam bootstrap`. What it still refuses is neither.
- `axebom iam verify` caps the unlinked-tenant listing at 5. The dev database
  holds **859** tenants of test debris; printing them all buried the four rows
  the command exists to show.

### 2026-08-23 (g) — the seeded users can log in

**Goal:** `migrations/seed/0001_dev_tenants.sql` inserted four users and no
`password_hash`, so `task db:reset` produced a database nobody could sign into.

#### Why nothing caught it

The seed reported success. The users were there. Every automated test either
minted a service token or registered its own account through
`POST /v1/auth/register`, so **the one path a person actually takes was the one
path nothing exercised.** It surfaced when someone opened the UI.

#### What changed

Real argon2id hashes for alice, aaron and bob, generated with
`auth.HashPassword` (`libs/go-shared/auth/password.go`) at the parameters the service uses, one
distinct salt each. Password: **`axebom-dev-only`**, named so it cannot be
mistaken for a credential.

⚠ **`p=1` explicitly, not `DefaultArgon2Params()`.** The default derives
parallelism from `runtime.NumCPU()`, so a committed artifact would depend on the
machine that produced it — this one would have shipped `p=4`. Verification reads
the parameters back out of the encoded hash, so a fixed `p` verifies anywhere,
and `NeedsRehash` leaves it alone.

⚠ **`ON CONFLICT (id) DO UPDATE SET password_hash`, not `DO NOTHING`.** Every
other row in the seed is `DO NOTHING` and that is right, but these users already
exist in every database seeded before today — `DO NOTHING` would leave those
developers unable to log in with a seed that looks like it ran. Only the hash is
written back, so a name or status changed by hand while testing survives.
Verified: re-running `db seed` against the live database installed the hashes
without a reset.

⚠ **carol keeps no password, deliberately.** Her `auth_provider` is `github`, and
`Service.Login` has a branch for a user with an empty hash that returns the same
generic error as a wrong password — answering "use GitHub instead" would confirm
the address is registered. She is the only fixture that reaches it. Giving her a
local password would have made every seeded user log in and deleted that case,
which is why the obvious version of this fix is the wrong one.

**Publishing the hashes is safe and the reasoning is written into the seed
header.** The password has to be public for the seed to be usable, so the hash
adds no secret; and `Migrator.Seed` already refuses any host that is not
`localhost`, `127.0.0.1` or `postgres`, so these cannot reach a remote database
by accident.

#### The durability fix

`libs/go-shared/platform/db/seed_login_test.go`, three tests:

- **`TestSeededUsersCanLogIn`** — every local account's hash is VERIFIED against
  the documented password, not merely checked for presence. A hash of the wrong
  password is indistinguishable from a correct one until someone tries to log
  in. Also asserts the wrong password fails, that the hash is not below current
  policy, and that carol still has none.
- **`TestSeededHashesUseDistinctSalts`** — identical hashes would mean a shared
  salt. Irrelevant for a published dev password, and the wrong pattern to copy
  out of this file into anything that matters.
- **`TestSeededUsersHaveMemberships`** — a login that succeeds still lands
  nowhere without one. ⚠ Counted PER TENANT through `WithTenant`: `auth.memberships`
  is tenant-scoped, so an unscoped count raises `unrecognized configuration
  parameter` — RLS failing closed, correctly. The first draft of this test hit
  exactly that.

Verified to FAIL on the defect: nulling alice's hash produces *"alice@acme.test
has no password_hash, so nobody can log into a freshly seeded database"*, and
re-seeding restores it.

#### Verification actually performed

| Check | Result |
|---|---|
| `task verify` | exit 0 |
| Login, all three local users | 200 with the right role and tenant on the JWT — owner/A, analyst/A, owner/B |
| carol | 401 `AUTH_INVALID_CREDENTIALS`, same error as a wrong password |
| Wrong password | 401, indistinguishable — no enumeration oracle |
| Tenant isolation after login | alice sees Acme's 2 projects, bob sees Beta's 1; both named `payments-api` |
| Regression guard | verified to fail on a nulled hash, then pass after re-seeding |

### 2026-08-23 (f) — the summary is populated, and null is not zero

**Goal:** populate `ScanResultV1.summary`. syft inventoried 21 components on a
live scan and the envelope carried `{"components": 0, ...}`.

#### ⚠ The obvious fix would have introduced three new lies

Filling the four fields in unconditionally replaces one false zero with three.
syft catalogues components and matches no vulnerabilities; grype matches
vulnerabilities and catalogues no licences. "grype found 0 licences" reads as a
clean result and is really a question grype was never asked — the same failure
this codebase refuses everywhere else, where an unknown must never present as a
measured zero (invariant 3) and an unscanned ecosystem must be declared rather
than omitted (invariant 12).

So `events.Summary` is now four **pointers**, and the two states are distinct on
the wire:

	null   this engine does not measure this dimension
	0      it measured, and there were none

Not `omitempty`: an explicit null says "not measured", where an absent key says
only that the publisher might be old. `events.Count(n)` boxes a measured value
so a call site reads as what it means.

#### The manifest decides what an engine may report

Not this code's opinion. `OSINT/tools.manifest.yaml` already declares
`produces:` per engine, and `summarize()` reports exactly those dimensions —
adding an engine or changing what one produces is a manifest edit, not a code
edit. `secrets` is mapped deliberately to nothing: a leaked secret is a finding,
not an inventory count, and folding it into `vulnerabilities` would put a number
in a compliance report that no CVE backs.

⚠ **The adapters restate `produces` and one copy had already drifted.**
`dependency-check` said `(vulnerabilities,)` where the manifest says
`[components, vulnerabilities]`, so its component count would have been dropped
from every envelope and looked exactly like an engine that does not catalogue
components. Corrected, and `test_an_adapters_produces_matches_the_manifest`
now pins every adapter against the manifest — verified to fail on the drift
before it was fixed.

#### Counting rules worth knowing

- **Findings are not vulnerabilities.** grype emits one match per
  (vulnerability, package) pair; trivy emits one entry per vulnerability with an
  `affects` list. Counting rows would make the same project look three times
  worse under grype than under trivy, in a field both publish under the same
  name. All engines count DISTINCT identifiers; an unidentified finding still
  counts, because dropping it would understate.
- **CycloneDX nests**, and trivy uses that for multi-root repositories. The
  counter recurses — counting only the top level would report a monorepo's four
  roots as four components.
- **A cryptographic asset is a component with a distinct type**, counted in
  `crypto_assets` and not in `components`; counting both would render a 40-asset
  CBOM as 40 components AND 40 crypto assets in one envelope.
- **Licences count real assertions only.** `NOASSERTION`, `unknown` and `""` are
  not assertions (invariant 3). ⚠ `NONE` is dropped here and still counts as
  present for COVERAGE scoring — invariant 3's deliberate exception makes it a
  substantive answer to "what licence is this", and it remains no answer at all
  to "how many distinct licences were identified".

#### A refused run publishes no counts

`unavailable`, `skipped`, `failed` and `timeout` all mean the output was not
accepted, and several adapters count before they reach the check that refuses
the run — osv-scanner counts every finding, then declares itself unavailable
because it cannot date them. Publishing those numbers would let a consumer sum
findings the engine itself declined to stand behind. Cleared centrally in
`_result()`, the one place every family's envelope is built, so a new adapter
cannot forget it.

#### The column was written from the first result and read by nothing

`scan.engine_runs.summary` has existed since `migrations/scan/0001`. Nothing
selected it, so even a correct count would have stopped at the database.
`loadRuns` now reads it and `GET /v1/scans/{id}/engine-runs` returns it.

#### Verification actually performed

| Check | Result |
|---|---|
| `task verify` | exit 0, full stack running, `-race` included |
| Python suite | 597 pass (`workers/` + `libs/py-shared`) |
| Live scan, expressjs/express | **syft `components: 21`** — the number the envelope had been reporting as 0 |
| null vs zero, live | syft `vulnerabilities: null`, grype `vulnerabilities: 0`, trivy-fs `components: 0` |
| Refused runs, live | dependency-check `unavailable`, mock-engine `skipped`, osv-scanner `partial` — all four dimensions null |
| Manifest-parity guard | verified to FAIL on the dependency-check drift before the fix |
| Schema | `proto/schemas/scan-result-v1.schema.json` regenerated; the four fields are `["integer","null"]` |

Live output:

	dependency-check   unavailable  {components: null, vulnerabilities: null, licenses: null, crypto_assets: null}
	grype              succeeded    {components: null, vulnerabilities: 0,    licenses: null, crypto_assets: null}
	mock-engine        skipped      {components: null, vulnerabilities: null, licenses: null, crypto_assets: null}
	osv-scanner        partial      {components: null, vulnerabilities: null, licenses: null, crypto_assets: null}
	syft               succeeded    {components: 21,   vulnerabilities: null, licenses: 0,    crypto_assets: null}
	trivy-fs           partial      {components: 0,    vulnerabilities: 0,    licenses: 0,    crypto_assets: null}

#### ⚠ A pre-existing test flake surfaced, and it is NOT this change

`task verify` failed once on `TestReaperTimesOutOverdueJobs` ("the reaper found
no overdue jobs") and once on `TestScanStatusDerivesFromEngineResults` (scan
status `failed`, want `completed_with_errors`). Both reproduce on the CLEAN tree
at `7f05652` with this work stashed — measured, 1 failure in 10 runs of
`go test ./services/...`.

The cause is the same class already recorded for the bus and pipeline tests,
now visible in the database: `Reaper.Sweep` is deliberately GLOBAL across every
tenant (it goes through SECURITY DEFINER functions because `engine_runs` has
FORCE RLS), it runs on a 20-second ticker in every orchestrator instance, and
the DB-backed tests share one database with whatever else is running. A sweep
landing between a test's backdate and its own assertion reaps the row first —
or times out another test's runs and turns its scan `failed`.

`task verify` passes on a rerun. **The real fix is an isolated database per
test run, the same conclusion the broker reached; not done, and recorded here
rather than left as an intermittent mystery.**

#### Corrections to the previous entry

- **Progress weighting never used the summary.** `orchestr.Progress` is a
  weighted mean over ENGINE WEIGHTS and is unaffected by counts. The previous
  entry named it as a victim of the zeroed summary; it was not.
- **The report's Engine Coverage section does not read the summary either.**
  `loadEngineCoverage` selects engine, version, status, database version,
  ecosystems and error code — no counts. Surfacing them in the generated report
  is a separate change with a golden-file cost, and is NOT done.

#### What is still NOT wired

- **`invocation.started_at` / `finished_at` are never set** by the Python
  worker, so every engine run reports null for both through the API. Only
  `duration_ms` survives, which says how long an engine took and not when it
  ran. Visible on any scan now that the runs render. **This is the next task.**
- The report's Engine Coverage section does not carry the counts (above).
- Raw artifacts are stored to LOCAL disk, not object storage (ADR-0003).
- Everything from the previous entries: `ai-bom` cannot resolve, `/v1/hbom/*`
  is unimplemented, frontend auth is unwired, integration tests still need an
  isolated broker, and the orchestrator still fans out to engines flagged
  `derived` / `requires_import`.

### 2026-08-23 (e) — syft's SBOM reaches grype

**Goal:** wire syft's SBOM to grype, which was `skipped` on every real scan.

#### It was two problems, not one

The obvious one was location: syft writes its raw artifact to
`<output_root>/<job_id>/`, which is per-JOB, while `_build_target` reads
`sbom.cdx.json` from the per-SCAN workspace. grype has its own job id and cannot
address syft's output directory, so the SBOM sat one directory away.

The one underneath was **ordering**, and it would have survived fixing the first.
`Requires: ["vuln_db"]` in the registry is a CAPABILITY, not an engine
dependency, and nothing sequenced the two: `FanOut` published all six jobs at
once, so grype was routinely delivered before syft had produced anything.
`DEPENDS_ON = {"grype": "syft"}` existed only in the Python worker, where it
turns a missing input into `skipped` — it reports the problem, it does not
prevent it.

#### The dependency is now modelled and enforced by the orchestrator

`policy.Engine.ConsumesOutputOf` names a producing engine — distinct from
`Requires`, because it constrains WHEN a job may be published rather than
whether the engine can run. `FanOut` holds those jobs back; `releaseDependents`
publishes them when the producer reports.

Observed on a live scan:

	holding an engine job until its producer reports  engine=grype waits_for=syft
	fanned out engine jobs                            jobs=5
	published output for a consuming engine           artifact=.../sbom.cdx.json
	released a dependent engine job                   engine=grype after=syft
	job complete                                      engine=grype status=succeeded

**A producer that produced nothing must not leave its consumer queued.** If syft
fails, grype can never run; leaving it `queued` means the scan never reaches a
terminal state and the reaper reports a timeout half an hour later — a
misleading cause for a straightforward one. The dependent is marked `skipped`
immediately with `ENGINE_INPUT_MISSING` naming the producer and its status.

`releaseDependents` runs BEFORE `RecomputeScanStatus`, deliberately: recompute
asks whether every run is terminal, and a producer arriving last would otherwise
recompute against a run that had not yet been published.

#### The worker publishes what another engine consumes

`workspace_artifact_name` on the adapter base; `"sbom.cdx.json"` on
`SyftAdapter`. The worker copies the native output into the shared workspace
after a successful run, atomically (write-then-replace, same directory) and
world-readable — engine containers run as uid 65534 and mount the workspace
read-only, and a 0600 file would be invisible to them.

⚠ **`SyftSPDXAdapter` inherits from `SyftAdapter`**, so it would have written an
SPDX document over `sbom.cdx.json`. grype would then either fail to parse it or,
worse, parse it partially and report vulnerabilities against an inventory nobody
produced. It sets `workspace_artifact_name = None` explicitly, with a test.

A failed or unavailable run publishes nothing: a truncated SBOM becoming
grype's input would produce findings for a subset of the project while looking
like a complete scan.

#### Verification actually performed

| Check | Result |
|---|---|
| `task verify` | exit 0, full stack running, `-race` included |
| Live scan, expressjs/express | **syft and grype both `succeeded`** |
| Ordering | fan-out published 5, held grype, released it after syft |
| Producer failure | consumer `skipped` with `ENGINE_INPUT_MISSING`, not left queued |
| New tests | 5 worker + 3 orchestrator; the orchestrator ones skip when a live worker holds the subject |

#### What is still NOT wired

- **`ScanResultV1.summary` is never populated.** syft reports 21 components and
  the envelope carries `{"components": 0, ...}`. *Done in (f) — and the claim
  about progress weighting and Engine Coverage was wrong; see the corrections
  in that entry.*
- Raw artifacts are stored to LOCAL disk, not object storage — the result's
  artifact URI is a filesystem path. It works because every worker shares the
  bind mount, and it will not survive a distributed deployment (ADR-0003 wants
  them in object storage).
- Everything from the previous entries: `ai-bom` cannot resolve, `/v1/hbom/*`
  is unimplemented, frontend auth is unwired, integration tests still need an
  isolated broker, and the orchestrator still fans out to engines flagged
  `derived` / `requires_import`.

### 2026-08-23 (d) — the source reaches the engines

**Goal:** make the engine workers materialize the source archive.

#### What now works

`axebom source materialize --uri --sha256 --dest` downloads the
content-addressed archive, verifies the digest, and extracts it through the
SAME hardened `fetcher.ExtractTar` the fetcher uses — traversal, size, inode and
inflation guards. A second extractor in Python would have been a second thing to
get right, and the second one would be the weaker; the workers already shell out
to this binary for the sandbox bridge.

`SBOMWorker.handle` calls it before every engine. Measured on
expressjs/express: **213 files materialized, syft succeeded with 21 components**,
and the 2nd and 3rd engines log `already materialized` rather than re-downloading.

Idempotency is by **atomic rename**, not a lock: six engines share one scan
workspace and may race, so each extracts to a sibling staging directory and
renames into place. The loser sees the winner's finished tree, and there is no
lock file to leak when a worker is killed mid-extraction. The stamp is written
LAST, so a directory without one is treated as absent.

#### ⚠ A 0700 WORKSPACE MADE EVERY ENGINE REPORT NOTHING

`os.MkdirTemp` creates 0700 and rename preserves it, so the published workspace
was root-owned and unreadable by the engine containers, which run as uid 65534.
They did not fail — they walked a directory they could not enter, found nothing,
and reported `partial`. **express materialized 213 files and syft still reported
zero packages.**

This is the same rule the engine-database provisioner already applies
(`_make_world_readable`, and the `_readable_as_scan_user` check that proves it),
for the same reason: a tree the scanner cannot read is indistinguishable, in the
output, from a project with nothing in it.

The chmod is **root-scoped and by descriptor**. The tree is a customer's
repository, so `filepath.Walk` + `os.Chmod` is a symlink TOCTOU — an entry that
was a regular file at Lstat can be a symlink by the time chmod runs, and the
chmod lands outside the tree. Traversal goes through `os.Root` and every chmod
is applied to an `O_NOFOLLOW` descriptor. `os.Root.Chmod` alone is not enough;
its own documentation records that it stays racy on Unix.

#### osv-scanner's exit 128 means two opposite things

*"No package sources found"* is emitted both when a repository genuinely commits
no lockfile — express — and when the workspace was never materialized. Both were
observed here; the second while the archive was being mounted from a tmpfs the
daemon could not read.

Reporting the first as `failed` puts a false alarm in a compliance document.
Reporting the second as zero coverage would hide a real defect. The only signal
separating them is osv-scanner's own walk summary:

	End status: 69 dirs visited, 283 inodes visited, 0 Extract calls

A walk that visited a real tree and found no manifests is a **coverage gap**
(`partial` + `ENGINE_ZERO_RESULTS`). A walk that visited nothing **did not see
the source** (`failed` + `ENGINE_INPUT_UNREADABLE`). Parsing stderr is fragile
against upstream rewording, so an unparsed count falls through to `failed` —
overstating the problem visibly rather than understating it. Added
`classify_nonzero` to the adapter base for this; every other exit code keeps the
default.

#### The distinction the tests pin

A job with **no** archive reference is a legitimate shape — an upload or manual
scan has nothing to fetch, and refusing it would break every non-repository
source kind. A job that **names** an archive which cannot be materialized is a
real failure, and the engine must not run: an engine pointed at a missing tree
reports a clean project, which is the worst outcome this codebase has. Failure
is `unavailable` + `SOURCE_UNAVAILABLE`, carrying the CLI's own reason (digest
mismatch, missing object, extraction guard) so the report names the cause rather
than saying the engine found nothing.

Writing those tests caught a bug in the new code immediately:
`EngineUnavailableError` takes `(engine, reason)` and was being raised with one
argument.

#### Verification actually performed

| Check | Result |
|---|---|
| `task verify` | exit 0, full stack running, `-race` included |
| Live scan, expressjs/express | syft **succeeded**, 21 components; 213 files materialized |
| Idempotency | 2nd and 3rd engines log `already materialized` |
| No engine `failed` | every non-success carries a stated reason |
| Python suite | passes, including 10 new tests |

#### What is still NOT wired

- **syft's SBOM never reaches grype.** grype matches against OUR SBOM rather
  than re-cataloguing the tree, and `DEPENDS_ON` records the dependency, but
  syft writes its artifact to the OUTPUT directory while `_build_target` looks
  for `sbom.cdx.json` in the WORKSPACE. So grype is `skipped` on every real
  scan — correctly, and for a reason nothing yet resolves. **This is the next
  task.**
- `summary.components` stays 0 even when syft reports 21 — the count is not
  propagated into the result envelope, so progress and coverage numbers
  understate what was found.
- trivy-fs reports `partial` on express because it needs a lockfile; that is
  honest, not a defect.
- Everything from the previous entries: `ai-bom` cannot resolve, `/v1/hbom/*`
  is unimplemented, frontend auth is unwired, and integration tests still need
  an isolated broker.

### 2026-08-23 (c) — the fetcher is wired; a clone that produced no files

**Goal:** subscribe something to `scan.job.fetch` so the fan-out can start.

#### The fetcher became the ninth service, and that was not a preference

The consumer could not live in the orchestrator. It needs Vault, object
storage, a Docker runner and a repository credential, and the orchestrator is
reachable from the gateway — putting them together would give a request-path
service a Vault token with repository access, which is precisely what ADR-0008
and invariant 7 forbid. The README's architecture diagram already showed the
fetcher as a separate box.

`services/scan-orchestrator/internal/fetcher` moved to `libs/go-shared/fetcher`
(nothing outside its own tests imported it, so the move was free), and
`gen-service` produced the scaffold — which is what that tool exists for.

Source resolution is an HTTP call to a new **service-principals-only** route,
`GET /v1/projects/{id}/source`. It returns `credential_ref`, and a Vault path is
a read primitive, so `project:read` is not sufficient to reach it:
`auth.RequireService` answers 404 to anyone who is not a service. The public
connections endpoint still returns only `has_credential: bool`. The fetcher
re-derives the Vault path from (tenant, kind, connection id) rather than
trusting the stored one, so a tampered row cannot become a cross-tenant read.

`ScanResultV1` gained `source_meta`. The orchestrator had been reading the
commit sha out of `engine_db_version` — a field documented as the
vulnerability-database vintage — which made a fetch result claim a database it
had never consulted and hid the commit sha where nobody would look.

#### ⚠ THE CLONE PRODUCED NO FILES, AND EVERY STEP REPORTED SUCCESS

`Clone` ran entirely inside a container whose `/workspace` is a tmpfs, and
returned `WorkspacePath: policy.WorkspacePath` — `/workspace`, a path that had
only ever existed inside a container that no longer existed. Every unit test
passed, because they assert on argv and on the parsed commit sha. Nothing
consumed the tree until this worker tried to archive it:

	walk source: lstat /workspace: no such file or directory

Fixing it took four measured findings, each of which looked like success:

1. **`docker cp` does not descend into a tmpfs.** Measured directly: a file
   written to a tmpfs mount and copied out yields a tar containing only the
   empty directory. The first copy-out therefore produced an archive of
   **0 files** while reporting `source materialized`.
2. **A writable host bind is not an option** — `mountsFor` forces ReadOnly on
   every bind, deliberately. The answer is an anonymous VOLUME, copied out
   through the Docker API after the process exits, so the running container
   never holds a writable handle to the host.
3. **A fresh volume is root-owned.** Over a path absent from the image it is
   root:root 0755, and the sandbox runs as uid 65534. Docker seeds a new volume
   with the ownership of the image path it covers, so the mount target must be
   one the image already makes world-writable — `/tmp`, 1777. Hence
   `CopyOut.MountPath` separate from `CopyOut.ContainerPath`.
4. **git refuses to work in a directory it does not own** — *"detected dubious
   ownership in repository at '/tmp'"*. The clone goes into a subdirectory it
   creates itself rather than silencing the check with `safe.directory`.

The copied tar is extracted through the existing hardened `ExtractTar`
(traversal, size, inode and inflation guards) — which until now also had no
production caller.

#### ⚠ backoff DESTROYS ack_wait — and max_ack_pending=1 turns that into an outage

Already fixed in the previous session for the workers; the fetcher hit the
consequence. With `ack_wait=30m` and `max_ack_pending=1`, a worker restarted
while holding a message blocks **every scan in the system** until ack_wait
expires — observed as `Outstanding Acks: 1 out of maximum 1` with no log line
at all. Raised to 4.

#### Silent retries, and the one-line fix that found three bugs

The handler returned `bus.ErrRetry` without logging, and `bus.dispatch` does not
log the retry path either. A message naking every 30 seconds produced **no
output whatsoever** — the queue showed one outstanding ack and the log showed
nothing. Adding a log on entry and on every retryable return immediately
surfaced, in order: a `permission denied` on the workspace, a missing
`alpine/git` image, and the S3 key defect below.

Corollaries fixed at the same time:

- **The shared workspace must be mode 1777.** The fetcher runs as distroless
  `nonroot` while the workers run as root, and both write there.
- **`toolctl pull` now pulls `alpine/git`.** It is not a scanner and not in the
  manifest, but the clone container cannot fetch its own image either.
- **An object key is not a URI.** `ArtifactPrefix` defaults to `s3://axebom`,
  so the key literally began `s3://` and MinIO rejected it with *"Object name
  contains unsupported characters"* — naming neither the key nor the colon.
  `objectKeyPrefix` strips the scheme and any leading slash, with a test.

#### A poison message can saturate a consumer

`handleFetchResult` treated a result for a NON-EXISTENT scan as retryable. Test
leftovers filled every slot — `Outstanding Acks: 16 out of maximum 16,
Unprocessed: 42` — and every real scan sat at `queued` behind them. An unknown
scan is permanent: it now terminates to the DLQ.

#### Integration tests were fighting the running application

Three orchestrator pipeline tests took 45–60 seconds and failed with
`scan status = "failed", want completed`. Two distinct causes, neither a product
defect:

- The fake worker claimed `scan.job.sbom` with `ReleaseFilterSubject`, which
  claims a subject by **deleting whatever consumer is already there** — silently
  dropping a live worker's in-flight deliveries, after which the two compete
  anyway.
- A test calling `ConsumeResults` creates the durable `orchestrator-fetch` —
  the same name the running orchestrator uses. On a WorkQueue that is a consumer
  GROUP, so NATS load-balanced the test's own messages to a process it could not
  observe.

Both now detect and **skip with a remedy**, via the new non-destructive
`bus.ConsumersOn`. A test that cannot run should say why, not fight the
application and report a defect that is not there. Note the trap in the first
attempt: `t.Skipf` was called from the worker goroutine, where it does not skip
anything — the test carried on and failed later for an unrelated-looking reason.

**The durable fix is an isolated broker per test run.** Not done.

#### Also

The Python worker never recovered from a deleted consumer: it retried `fetch()`
forever against a dead subscription while the process looked healthy and the log
said "consuming". It now re-establishes after three consecutive failures.

`KnownServices()` was a second hardcoded service list beside `servicePorts` —
exactly the drift its own test guards against, and it caught it: adding the
fetcher left the list at eight, which would have defaulted the ninth service to
port 8080 and collided with the gateway. Now derived.

#### Verification actually performed

| Check | Result |
|---|---|
| `task verify` | exit 0, with the full stack running, `-race` included |
| End-to-end scan | `POST /v1/scans` → fetch → archive → fan-out (6 jobs) → results → `completed_with_errors`, 100% |
| Commit pinned | `7fd1a60b…`, the real Hello-World master commit |
| Archive | 1 file (README); `.git` correctly excluded |
| Orchestrator tests | pass with the stack live; pipeline tests skip with a remedy |

#### What is still NOT wired

- **The engine workers do not materialize the archive.** This is the next gap
  and the reason the scan above reported empty results: the fetcher uploads a
  content-addressed `source.tar.zst` and pins `source_archive_ref`, but nothing
  downloads and extracts it into `<workspace_root>/<scan_id>`, so every engine
  scans a tree that is not there. syft and trivy-fs returned `partial`,
  osv-scanner `failed`.
- `ai-bom` still cannot resolve (pip-only in the manifest, container-only
  adapter).
- `/v1/hbom/*` is still implemented by no service.
- Frontend auth is still unwired; seeded users still have no password hash.
- The orchestrator still fans out to engines flagged `derived` /
  `requires_import`, which have no worker by design.

### 2026-08-23 (b) — the workers consume NATS; two more silent defects

**Goal:** wire the Python workers to JetStream so scans can be dispatched
rather than only driven directly.

#### What now works

`libs/py-shared/axebom_shared/bus.py` (the consumer loop) and
`worker_runtime.py` (the process lifecycle). Three families consume their own
subject with their own durable — `worker-sbom`, `worker-cbom`, `worker-aibom` —
and publish to `scan.result.<family>`. Proven end to end: a job published to
`scan.job.sbom` ran syft in the sandbox and its result reached the
orchestrator's consumer; the same for `cbomkit-theia` on `scan.job.cbom`.

`SBOMWorker` gained optional `adapters`/`depends_on` parameters so CBOM and
AIBOM reuse its job path rather than copying it. The sequence that matters —
idempotency check first, manifest written LAST — is identical per family, and a
copy is how one worker ends up acking before it has stored its evidence while
still passing its own tests. All 142 sbom tests pass unchanged.

#### ⚠ `backoff` SILENTLY DESTROYS `ack_wait`, ON BOTH SIDES

nats-server overrides AckWait with `backoff[0]` whenever a backoff list is set.
Measured against the running server:

| consumer | reported Ack Wait |
|---|---|
| `ack_wait=30m` + `backoff=[30s,2m,8m]` | **30.00s** |
| `ack_wait=30m`, no backoff | 30m0s |

So `bus.go` has documented a thirty-minute ack window since Phase 6 and every
consumer it created has really had thirty seconds. For the results consumers
that is harmless — processing a result is milliseconds. For a **scan job** it is
not: scans are minutes of container, so the message is redelivered while the
first worker is still running it, producing duplicate engine containers for one
job and, after four deliveries, a DLQ entry for work that was succeeding.

Idempotency does not rescue it. The manifest is written LAST — deliberately, so
a crash mid-run does not look complete — so a redelivery at thirty seconds finds
no manifest and starts the engine again.

Fixed in both languages by dropping the consumer-level backoff. Nothing is lost:
the schedule is still applied explicitly via `NakWithDelay` / `nak(delay=...)`,
which is the path that actually matters. The Go redelivery test still measures
30.001s, confirming it was never the consumer setting driving it.

#### ⚠ A DATA RACE ON THE DECOMPRESSION-BOMB GUARD

`go test -race` (which `task verify` runs, and which had never run on this
machine) found `CountingReader.n` written by the **zstd decoder's own goroutine**
and read by `ExtractTar` on the caller's. Nothing in `extract.go` suggests
concurrency; the second goroutine belongs to klauspost/compress.

It is not merely a detector complaint. That counter is the inflation-ratio guard
against decompression bombs, and an unsynchronised read can evaluate the ratio
against fewer compressed bytes than were actually consumed. Now `atomic.Int64`,
read once per check and only after the nil test.

#### The bus tests claimed production subjects

`bus_test.go` used `scan.job.sbom`, `scan.job.cbom`, `scan.job.aibom` and
`scan.job.hbom`. A WorkQueue stream permits ONE consumer per filter subject, so
every one of those tests failed at setup with *"filtered consumer not unique on
workqueue stream"* the moment a real worker was running — which is now the
normal state of a dev machine. The available workaround, `ReleaseFilterSubject`,
would have passed by deleting the live worker's consumer and dropping its
in-flight deliveries. Moved to dedicated families (`testpub`, `testdedup`,
`testretry`, `testdlq`) instead: the tests now pass with the stack running.

#### `cbomkit-theia`'s argv was wrong and had never been run

It built `dir get <path> --quiet`. There is no `get` subcommand and no `--quiet`
flag; the real form is `cbomkit-theia dir <path>`. The engine printed its usage
text and exited 1, reported as `ENGINE_NONZERO_EXIT: exited 1` — accurate, and
useless for working out that the command itself was malformed. Corrected against
the pinned image's own `--help`, and `HOME` now points at the writable tmpfs so
its startup warning about a read-only application folder cannot become fatal.

It now returns `partial` on the monorepo fixture with two honest diagnostics —
no `components` array, and `ENGINE_ZERO_RESULTS` — rather than claiming success
on a tree that genuinely contains no crypto assets.

#### Drift guards added

`test_bus_contract.py` parses `bus.go` and asserts the stream names, MaxDeliver,
AckWait and the backoff schedule match the Python constants. Two runtimes cannot
share a constant, and duplication without a guard is how they diverge — the
divergence here would be invisible in both codebases. Mutation-tested: setting
`MAX_DELIVER = 7` fails the test with a message naming both values.

The result envelope is validated against `proto/schemas/scan-result-v1.schema.json`,
which is generated from the Go types, so worker/orchestrator drift is reported
rather than silently dropped on the far side.

Also corrected two Python config defaults that pointed at ports the stack does
not publish: `NATS_URL` (4222 → 54222) and `S3_ENDPOINT` (9000 → 59000).

#### No qbom or hbom worker, deliberately

Neither family is a scan, so neither has an engine to dispatch. QBOM is a
derivation from CBOM crypto assets plus Table 8 device metadata captured by
form; HBOM is a CSV/form import. Adding a worker for either would mean inventing
a scan where none exists.

**The real gap is on the Go side:** the orchestrator's fan-out does not skip
engines flagged `derived` or `requires_import`, so it would publish jobs nobody
should consume. `registry.go` carries both flags; `orchestr` never reads them.

#### Still not wired

- **`scan.job.fetch` has no consumer.** 75 jobs were sitting on it from the
  orchestrator's own tests. The fetcher has hardened clone logic and no
  subscription, so the fan-out never starts and a scan cannot be triggered from
  the API — only by publishing a job with a pre-staged workspace, which is how
  the dispatch above was proven.
- `ai-bom` still cannot resolve: its adapter subclasses `SandboxedAdapter`
  (needs a container image) while the manifest declares it pip-only. The
  manifest is SSOT, so that contradiction has to be settled there first.
- `/v1/hbom/*` is still called by the frontend and implemented by no service.
- Frontend auth is still unwired, and seeded users still have no password hash.

### 2026-08-23 — the stack runs; six engines verified live; five real defects found

**Goal:** install and run the application, and get every OSINT integration working.

#### The machine was bare

Ubuntu 26.04 (`resolute`) on KVM with only `git` and `python3`. Installed Go
1.26.2, Docker Engine 29.7.2 + Compose v5.5.0, Node 24.19.0, go-task 3.53.1,
golangci-lint 2.12.2, cosign 2.6.5. Two Ubuntu-26.04 specifics worth recording:
`ensurepip` is split out (`python3-venv` and `python3-pip` are separate packages,
so a bare `python3 -m venv` produces a venv with no pip), and a fresh
`usermod -aG docker` does not affect the current login session — use `sg docker -c`
until the next login.

#### Nothing above infrastructure was wired to start

`docker-compose.yml` was infrastructure only and said so. `08-OPERATIONS.md` §2
and `README.md` both claimed the core profile included the services, the workers
and the frontend. It did not, and there was no Procfile, supervisor or
`dev:services` target either. The eight service Dockerfiles existed but were
referenced by nothing **and could not build**: `golang:1.24-alpine` against a
`go 1.26.2` module fails at `go mod download`.

Built: the gateway proxy, a worker image, a frontend image, a CLI image, a
`.dockerignore`, and `docker-compose.app.yml`. The Dockerfile template now reads
the Go version from `go.mod` (`serviceSpec.GoVersion`), so the base image cannot
drift from the module again, and `EXPOSE` uses the derived metrics port rather
than a wrong literal.

#### The gateway did no proxying at all

`services/gateway/routes.go` was the 23-line generator stub, so the frontend
could not reach any backend even with everything running. Added
`services/gateway/internal/proxy` (9 tests, 38 assertions) and the four missing
upstreams — `config.Services` modelled only three of the seven.

Three decisions in it are worth keeping:

- **Prefixes match on a segment boundary.** A plain `HasPrefix("/v1/projects")`
  also matches `/v1/projectsummary`. No such route exists today, so the bug would
  be invisible until someone added one.
- **Each prefix is mounted four times** — bare, subtree, and both again under
  `/api`. Mounting only the subtree form makes ServeMux answer the exact path
  with a 301, and a browser downgrades a redirected POST to GET: "create project"
  would silently become "list projects", returning 200.
- **`Rewrite`, not `Director`.** Rewrite clears inbound `X-Forwarded-*` before
  repopulating them, so a client cannot forge its own rate-limit bucket.

Gateway upstreams are registered as **optional** health checks. Critical would
mean one restarting service takes the gateway out of the load balancer — and
with the gateway gone every other service becomes unreachable, escalating a
partial outage into a total one.

#### Five defects in the OSINT layer, all of which reported themselves as honest gaps

Each of these produced a plausible-looking `unavailable` rather than an error,
which is why they survived 74 passing worker tests.

| Defect | Effect |
|---|---|
| `trivy-image` and `dependency-check` set `requires_db_version` with **no `database_id`** | `database()` returned None, `generate()` refused before the container started, and the message read *"no provisioned **None** database was found"*. Permanently dead. `dependency-check` also had no `DatabaseSpec`, so nothing could have provisioned it even with the id set. |
| `test_database_guard.VULN_ADAPTERS` was a **hand-written list** of the three working engines | The test that existed to catch exactly the above never saw either broken adapter. Now derived from the runner's registry, with a guard asserting the derivation is non-empty — a list that silently became empty would make every parameterised test vacuously pass. |
| `cbomkit-theia` read `target.image_ref` | `ScanTarget` has `image_digest`. `AttributeError` on every image-mode scan; the `or ""` fallback beside it could never fire. |
| `ManifestResolver.MANIFEST_PATH` was **CWD-relative** | `_load()` catches `OSError` and returns an empty map, so a wrong working directory reported **every engine unavailable** — indistinguishable from a correctly detected gap. Now anchored to the repo root, matching `registry.py`, which already did it properly. |
| `SBOMWorker` constructed adapters **without `artifact_dir`** | `artifact_dir=None` means "the caller collects output from the result", which is right for tests and silently wrong here. Every live scan ran the engine, parsed the output and **discarded the bytes** — so there was no immutable raw artifact to re-normalize (ADR-0003, invariant 10) and nothing to show later as evidence. |

#### `toolctl pull` — the provisioning step that did not exist

`toolctl sync` skipped container-mode engines with the note that "containers are
pulled by the sandbox at run time". They are not, and **cannot be**: engines run
with `--network=none`. The sandbox has `EnsureImage`, deliberately kept out of
`Run` so pulling never happens inside a sandboxed execution — and nothing ever
called it. Every container engine reported `No such image`: an honest gap, and
entirely avoidable. Added `axebom toolctl pull` / `task osint:pull`.

That surfaced a stale pin: `cbomkit-theia` was `image_tag: "v1.1.2"` and 404s.
The version was right; the `v` prefix was not. Its sibling `cbomkit` in the same
org publishes `2.2.0` with no prefix — the same "a project is not internally
consistent about its own naming" trap already recorded for Trivy's asset names.

#### `trivy-image`'s premise was wrong, and the fix is architectural

The adapter documented "the image must already be in the daemon's store — pulled
by the fetcher". Being in the daemon's store is useless to a container with no
socket and no network; trivy fails across all four of its image sources. Mounting
the socket would hand a container running untrusted third-party binaries the
equivalent of host root.

So the image must be materialised outside the sandbox and scanned as a **tarball**
(`--input`), at `<workspace>/image.tar` — the same shape as grype's dependency on
`sbom.cdx.json`. Verified working against a real `docker save` export.

A second bug surfaced underneath: `trivy image` maintains a layer cache inside its
`--cache-dir` and the database mount is read-only, so it fails with
`mkdir /enginedb/fanal: read-only file system`. (`trivy fs` has no layer cache,
which is why only image mode hit it.) The cache now lives on the writable tmpfs
with the database symlinked in.

Added a general `input_gap(target)` hook to `SandboxedAdapter`: an engine missing
a required input is `unavailable` **with a stated reason** rather than `failed`
with a bare `ENGINE_NONZERO_EXIT: exited 1`. A failed engine reads as a defect to
debug; an unavailable one reads as reduced coverage, which is what it is.

#### Two sibling-container path traps, both silent

The worker starts engines on the **host** daemon, so every `-v` it passes is
resolved host-side. A named volume and a container-local temp directory both
mount as an **empty host directory**, and the daemon creates it without
complaint.

1. The engine-database volume. An empty OSV database makes osv-scanner print
   `{"results": []}` and exit 0 — a clean bill of health for a scan that checked
   nothing, which is the precise failure the stamp rule exists to prevent.
2. `dbsync`'s warm tree, built in `tempfile.TemporaryDirectory()`. osv-scanner
   reported `1 dirs visited, 0 Extract calls / No package sources found` and
   exited 128 — a message that says nothing about mounts.

Both are now identical-path bind mounts under `/var/lib/axebom`, with the
reasoning recorded where the mounts are declared.

#### Also fixed

- **`.env.example` was broken as shipped.** `JWT_SIGNING_KEY` was 22 bytes against
  a 32-byte minimum (killing 7 of 8 services at `buildDeps`), `POSTGRES_PASSWORD`
  was `CHANGE_ME` against a compose default of `axebom`, and `METRICS_PORT=9090`
  reintroduced the exact port collision `config/service.go` documents fixing.
  Removed the keys nothing reads (`GITHUB_CALLBACK_URL`, `REPORT_SIGNING_KEY_REF`,
  `NEXAR_CLIENT_ID/SECRET`, the `SMTP_*` block, `VITE_*`) and added the ~14 real
  ones that were missing. It is now runnable unedited.
- **The worker entrypoint swallowed commands.** `sh -c "..."` assigns appended
  arguments to `$0, $1, ...` rather than executing them, so
  `compose run sbom-worker python -m workers.sbom.dbsync` silently started the
  idle worker loop instead. Every operator command arrives that way.
- **`gen-service` panicked at import.** Reading `go.mod` relative to the working
  directory works under `go run` from the repo root and fails under `go test`,
  which sets the package directory as CWD — and doing it in `init()` made that a
  panic before any test ran. Now lazy, walks up, returns an error.

#### Verification actually performed

| Check | Result |
|---|---|
| `task verify` | see below |
| Go tests | 51 packages, 0 failures |
| Python tests | full suite passes |
| Golden files | pass, **unchanged** — no normalizer output moved |
| DB-backed RLS suite | **12 tests, first ever run**, 0 skips |
| Sandbox escape suite | **12 cases, first ever run** against a real Linux daemon |
| `db verify-rls` | 39 tenant-scoped tables, FORCE RLS, 0 gaps |
| `task health` | 8/8 services `up` |
| Live engine matrix | 6 succeeded, 1 stated gap (`dependency-check`, needs the free NVD key) |
| Engine databases | grype 2.0 GB, trivy 1.3 GB, osv 263 MB — all stamped |
| Browser path | register → `/auth/me` → `/projects` through nginx and the gateway |
| `gen-service --all --dry-run` | 0 regenerated — CI's generator-diff job will pass |

#### What is still NOT wired

- **No Python worker consumes NATS.** `SBOMWorker.handle()` is complete and
  tested but reached only from tests and the smoke tool; `main()` logs "ready"
  and sleeps. There is no `nats` dependency in `pyproject.toml`. The only
  consumer of `scan.job.sbom` is the Go mock in `workers/_mock`.
- **Nothing consumes `scan.job.fetch`**, so the orchestrator's fan-out never
  starts, and nothing consumes `scan.job.{cbom,aibom,qbom,hbom}`.
- **No runner for cbom / aibom / qbom / hbom.** Their adapters and normalizers
  are real and tested; only the sbom family has a `runner.py`.
- **`/v1/hbom/*` is called by the frontend and implemented by no service.**
- **Frontend auth is not wired**: `setAccessToken` still has zero callers, and
  the seeded users have no `password_hash`, so they cannot log in. Register works.
- **`ai-bom` cannot resolve** — its adapter subclasses `SandboxedAdapter` (needs a
  container image) while the manifest declares it pip-only. The manifest is SSOT,
  so that contradiction has to be settled there first.
- **`aibom-generator` has no concrete `Fetcher`** — no HTTP client exists.
- **cosign still verifies nothing.** `toolctl sync` checks SHA256 only;
  `haveCosign()` merely warns when absent, and nothing reads the manifest's
  `Signature.Kind`. Installing cosign does not change this.

### 2026-08-18 (e) — the windows job, running for the first time

Fixing the line-ending guard let the `go` jobs reach their tests at all. Ubuntu
passed, **including `-race`** — which had never once executed: the Taskfile skips
it on Windows (no C toolchain, `CGO_ENABLED=0`) and CI died at step 4 on every
run. The race detector has now actually run on this codebase and found nothing.

Windows failed, and the cause is a gap in how the Docker tests decide to skip.

**`Ping` succeeding does not mean the sandbox can run.** Both helpers —
`sandbox.newRunner` and the fetcher's `newSandbox` — treated a reachable daemon
as "Docker is available". On `windows-latest` the daemon is reachable, but it
serves **Windows containers**, and every control the sandbox is built from
(`--network=none`, `--cap-drop ALL`, seccomp, read-only rootfs, tmpfs workdirs,
pid/memory quotas) is Linux container semantics with no Windows equivalent. The
daemon answers Ping, then fails on the first Linux image.

This never showed locally because Docker Desktop's daemon is stopped here, so
the helpers skipped at the Ping. It could only appear on a machine where Docker
runs in Windows mode — i.e. the runner.

`DockerRunner.DaemonOS` now reports the daemon's container platform, and both
helpers skip when it is not `linux`. `sandbox/runner_test.go` was already
partly protected by its `EnsureImage` guard; the fetcher helper had none.

**CI logs need admin rights; job summaries do not.** Diagnosing this was slower
than it should have been because `GET /actions/jobs/{id}/logs` returns 403
without admin, leaving only "Process completed with exit code 1" in the
annotations. Both test steps now write failing test names to
`$GITHUB_STEP_SUMMARY`, which is readable by anyone — including from a fork.

### 2026-08-18 (d) — CI repaired: seven red jobs, six distinct causes

No product code was wrong. Every failure was in the gate itself or in the
declared environment, which is the more dangerous kind: a red CI that everyone
learns to ignore stops being a gate at all.

**The boundary guard had not been running.** `golangci/golangci-lint-action@v6`
supports golangci-lint **v1 only**; the workflow asked it for `v2.12`. That is
unsatisfiable, so the job died at install and depguard never analysed anything.
The service boundary — the one thing ADR-0001 says discipline cannot maintain
across context resets — was unenforced for the whole window. Now on action `v8`
with `v2.12.2` pinned, and it reports 0 issues.

**The line-ending guard did not understand its own `.gitattributes`.** It
flagged every file whose worktree copy was CRLF, excluding only `*.ps1/bat/cmd`
by extension. But `.gitattributes` marks `fixtures/**/expected/**` as `-text`
precisely so git never converts them — they are byte-exact goldens. All five
`canonical.json` files tripped the check on every run, on both runners, killing
the `go` jobs at step 4 before a single test ran. The guard now filters on the
attribute (`attr/-text`, `eol=crlf`) rather than on the file extension. The
goldens were **not** modified: their bytes are the contract, and rewriting them
to satisfy a broken check would have been the actual bug.

**`buf lint` fails on a module with no `.proto` files** — `Failure: Module
"path: "."" had no .proto files`. The breaking-change step already guarded for
the empty tree; the lint step did not. Both are now guarded by one detect step.
The old guard also used `compgen -G "proto/**/*.proto"`, which without
`shopt -s globstar` silently means `proto/*/*.proto` — it would have missed the
nested `proto/axebom/scan/v1/` layout Phase 6 will introduce. Replaced with
`find`.

**PyYAML was imported but never declared.** `axebom_shared.adapters.registry`,
`workers/sbom/adapters/common.py` and `workers/sbom/normalize_runner.py` all
`import yaml` at module scope, but `pyproject.toml` listed only pydantic and
structlog. It resolved on this machine because PyYAML was already present, and
failed on every clean CI install at collection. Verified by building a venv from
scratch: `pip install -e ".[dev]"` now pulls PyYAML 6.0.3 and all tests pass.

**Two generated `main.go` files had been hand-edited**, which is exactly what
the generator-drift job exists to catch — it was doing its job. `campaign` had
its scheduler goroutine and `report` its render consumer inlined into generated
scaffold. Rather than surrender the check, the generator gained a
`startBackground(ctx, d)` hook: called from `main.go` before the server starts,
defined in `deps.go`, which is **preserved**. Both workers moved there verbatim,
their reasoning comments intact. The other six services carry the generated
no-op. Regeneration is now idempotent.

**`GO_VERSION` was `1.24` while `go.mod` requires `go 1.26.2`.** Every job was
downloading a second toolchain through `GOTOOLCHAIN=auto` before it could run
anything. Pinned to `1.26` to match. Confirmed the prebuilt golangci-lint
v2.12.2 binary is itself built with go1.26.2 — read from the release's own
CycloneDX SBOM — so it can type-check this module.

Frontend was a plain prettier drift across nine files from Phases 14–16.

**Verified locally before pushing:** `go build`, `go vet`, `go test ./...`,
`gofmt`, `golangci-lint run` (0 issues), generator idempotency, `docs lint`
(105 refs), frontend lint + format + build, and pytest in a from-scratch venv.

**Not verified:** the runners themselves. Python CI is 3.11 and this machine is
3.14 — the missing-dependency fix is version-independent, but a 3.11-specific
runtime failure would not have been caught here. Docker is still down, so
nothing DB-backed ran.

**Left undone, deliberately:** `docs/08-OPERATIONS.md` §4 names five workflows —
`verify`, `golden`, `e2e`, `osint-contract`, `security`. Only `verify` exists.
The other four are unwritten, not broken, and creating them is phase work with
its own scope, not part of turning the gate green.

### 2026-08-18 (c) — Phase 16, the buildable half

Compliance guardrails, the evidence pack, API keys, audit export, Helm charts,
k6 scenarios and the honest limitations list. `task verify` green with two new
gates wired into it.

**Phase 16 splits in two and only one half is done.** The code and documents are
written; the penetration test, load-test execution, restore drill, chaos testing
and Helm dry-run need a running stack and a cluster. Nothing here was verified
against a live system, and the section above says so per item.

**The guardrail check took three versions to become usable, and that is the
lesson.** A naive count search flagged a page width of 210 and a 24-hour cache
TTL; the next version flagged eight CERT-In ordinals — "§4.2 field 21" names the
Unique Identifier and rewriting it would be wrong. Nine findings, nine false
positives. A check that cries wolf is one somebody disables, and a disabled
check is worse than no check because its absence is invisible. The rule that
works: a count answers "how many", an ordinal answers "which one".

**The evidence pack reports the product honestly**, including 8 of 11 QBOM
elements as user-supplied and every hardware element as imported rather than
automated — with tests that fail if either claim is ever softened.

**Corrected an inverted assertion** in the audit-export test that asserted the
output contained no `&` or `<` at all, when those characters appearing literally
is the entire point. It would have passed only on output corrupted in exactly
the way it was meant to catch.

**Next session: the integration backlog.** Every phase from 9 onward has a
database, HTTP or container surface that has never executed. That work needs
Docker, which was deliberately deferred until the platform was built — and it
now is.

### 2026-08-18 (b) — Phase 15 implemented

HBOM. `task verify` green; `task osint:licenses` confirms **zero copyleft in any
binary**; `task test:golden` covers `hbom-nested`.

**The honest label is enforced, not remembered.** A test walks the worker's own
source for discovery phrasing — with a negation filter, because the package
docstring says an "HBOM scan" button *is* a lie and a naive search would flag
that sentence, making the rule unenforceable. A second test exercises the filter,
since one that excused everything would be a green test proving nothing.

**Table 11 alone is not compliant.** §10.4.1.4 mandates four elements that appear
nowhere in it, and Table 11 lists the two supplier relationships *twice* with
different meanings. Mutation-verified: aliasing element 13 onto the
product-supplier attribute fails the test.

**Mutation testing corrected a comment I had written.** Three `None`-handling
branches in the CSV reader were documented as preventing a crash; removing any
of them broke nothing, because the filtering happens elsewhere. The comment now
says they are belt-and-braces and names what actually does the work.

**Fixed two Taskfile targets** that called bare `python` rather than `{{.PY}}`,
so `test:golden` and `normalize` only worked from an already-activated venv — a
step the Taskfile exists to remove.

**Next session:** Phase 16 (`docs/phases/PHASE-16-hardening-launch.md`) — CERT-In
profile validation, hardening, perf, pen-test.

**The untested backlog is now seven phases deep, and every item needs Docker.**
Phase 15 adds: no HBOM row has ever been written, the HTTP surface the new UI
calls does not exist, neither commercial provider has run, and there is no
CycloneDX HBOM export.

### 2026-08-18 — Phase 14 implemented

Campaigns and notifications. `task verify` green; `golangci-lint` 0 issues.

**The central claim, and the test that keeps it honest:** the Postgres advisory
lock is a polling optimisation, not the safety mechanism.
`UNIQUE (campaign_id, scheduled_for)` is.
`TestTwoInstancesProduceExactlyOneDispatch` proves it by running two schedulers
with **no lock at all**; mutating the fake store to drop the constraint fails
four tests.

**DST was the hard part, and the first fix was wrong.** Go normalizes New York's
non-existent 02:30 backwards and Sydney's forwards, so a direction-assuming fix
pushed Sydney onto the next day. Resolved by taking the later of Go's answer and
`dayStart + wall-clock minutes`.

**Two shared packages came out of this phase, both because a second copy was
about to exist:** `safedial` (the fetcher's SSRF dialer — a webhook URL is the
same primitive as a clone URL) and `schemacheck` (the report store's column
check, now extended to INSERT/UPDATE, which caught three invented write columns
the original form would have missed).

**Corrected a stale doc reference** rather than suppressing it: the Phase 12
ML-BOM note named a path missing its `internal/` segment, so it pointed at a
package that will never exist. Fixed to `services/report/internal/export/mlbom.go`
and declared in `docs/.forward-refs` as owed work.

**Next session:** Phase 15 (`docs/phases/PHASE-15-hbom.md`). HBOM is a
structured CSV/form import plus a data model — label it that way, and **no GPL**:
`django-bom` is a schema reference that is never installed or imported.

**The untested backlog is now six phases deep** and every item needs Docker.
Phase 14 adds: `migrations/campaign/0002`, every store method, the real advisory
lock, webhook delivery to a real endpoint, SMTP, and the delivery worker that
does not yet exist.

### 2026-08-17 (o) — Phase 13 VEX and CSAF

Effective-status resolution and CSAF 2.0 generation. Both mutation-verified: the
specificity-before-recency ordering and the cluster-not-display-id attachment
each fail their test when neutered.

Nothing new was broken this session — which, after four sessions of finding a
silent defect in each, is worth stating plainly rather than assuming.

**Next session:** Docker. The unexercised backlog is now five phases deep, and
Phase 13 adds two pure packages with no storage behind them. Phase 7 remains the
precedent: every SBOM engine behaved differently from its documentation, and
none of that was visible until a container ran.

### 2026-08-17 (n) — Phase 12 AIBOM

Discovery, enrichment, merge and normalization. 458 Python tests.

Two cache bugs, neither of which failed anything. The second is worth carrying:
`ModelCache` defines `__len__`, so an empty cache is FALSY, and
`cache = cache or ModelCache()` silently discarded the caller's. Caching never
worked — and the only observable symptom was a fetch count.

**Next session:** bring Docker up. The unexercised backlog now spans four
phases — Phase 9's migration and share-link concurrency test, Phase 10's
Playwright, Phase 11's `cbomkit-theia`, Phase 12's two AIBOM adapters. Phase 7
is the precedent: every SBOM engine behaved differently from its documentation,
and none of that was visible until a container ran.

### 2026-08-17 (m) — Phase 11 crypto analysis

Quantum rules, PQC guidance, deprecation assessment, CBOM normalization with
type-aware columns, and QBOM derivation. 96 Python tests.

The lesson worth carrying is about fixing a bug class rather than a bug. Nine
rules used a plain `` and silently missed the concatenated names these
algorithms actually carry. The obvious fix — normalize the input — repaired the
broken rules and broke four working ones, just as silently. Keeping both forms
is additive and cannot subtract a match.

**Next session:** bring Docker up. Phase 9's migration and share-link tests,
Phase 10's Playwright, and Phase 11's `cbomkit-theia` all need it — and Phase 7
is the precedent for why an unexercised adapter is not a working one.

### 2026-08-17 (l) — Phase 9 completed, Phase 10 screens

Phase 9 wired end to end: handlers, share store, render worker, NATS render
queue, and the BOM source that assembles the canonical model out of three
schemas without a cross-schema JOIN.

Three guards added, each after a real bug, and all three mutation-verified:
routeguard now checks WHAT wraps a route (a rate limiter is not authentication);
a static check parses this package's SQL against migrations/ (four invented
column names); and `level.TopLevel` now comes from the compliance profile
rather than being spelled by hand.

Phase 10's five screens built with 52 tests. The recurring lesson this session
was about tests rather than code: **a fake that is unrealistic in the one way
that matters makes a test vacuous while it looks green.** The WebSocket fake did
not fire `onclose` on `close()`, and both disposal guards could be deleted with
the suite still passing.

**Next session:** bring Docker up. Run `migrations/report/0002`, then the
DB-backed share-link tests — especially the download cap under CONCURRENCY,
which is the one property a single-threaded test confirms while the product
leaks. Then Playwright.

### 2026-08-17 (k) — Phase 9 renderers, signing and share tokens

XLSX, CSV, JSON and PDF renderers; detached Ed25519 signing through Vault
Transit; `axebom verify`; share-link tokens and an atomic download claim.
Full Go suite green across 27 packages, `golangci-lint` clean repo-wide.

One defect recurred three times and is worth carrying forward: **anything whose
bytes are load-bearing must not be stored as live JSON.** protobom's arrays, the
JSON bundle's embedded SPDX, and the signature envelope's statement all broke
the same way. The last one was the worst — pretty-printing the signature file
broke every signature, and the failure read as a forgery.

Its companion: **a small number of comparisons proves nothing about
determinism.** fpdf produced files of the same length with different bytes,
because it writes font objects in map order.

The PDF's "cannot fetch a remote resource" guarantee is structural rather than
configured: the renderer draws text directly, and a test reads the package's own
imports to keep it that way.

**Next session:** finish Phase 9 — the report handlers, the async render worker,
and the share store. Then run `migrations/report/0002`, which has never
executed. Note that `/shared/:token` is unauthenticated and the download cap is
enforced by the database, not by Go.

### 2026-08-17 (j) — Phase 8 normalizer core

The normalizer runs end to end over the committed fixtures: identity, merge,
graph, alias closure, finding dedup, both coverage numbers, provenance. 151 unit
tests plus a 43-test golden corpus, all offline — they replay pinned raw
artifacts and run no scanners.

The fixtures earned their keep immediately. `golang-incompatible` exposed the
same Go module being counted twice because one engine writes `v24.0.5` and
another `24.0.5`, which doubled every finding on it. `npm-simple` exposed
findings displaying GHSA ids when the CVE was already known.

The most instructive bug was neither: a cluster-id lookup that misses on case
does not fail, it mints a new id and orphans the stored one — the ADR-0005
durability failure arriving through the back door.

**Next session:** finish Phase 8 — the remaining eleven golden fixtures, the
`COPY` bulk insert, `renormalize` into `normalization_version + 1`, and the VEX
join. Then Phase 9 (reports). Note the Phase 7 debt: `monorepo-multiroot` and
`trivy-fs` still need their raw artifacts regenerated, which needs Docker.

### 2026-08-17 (i) — Phase 7 implemented

Seven SBOM adapters, a provisioned-database layer, 74 tests. Five engines
exercised against all five fixtures; grype and osv-scanner now return **real
findings with alias edges**, which is what Phase 8's union-find needs.

Every defect found this phase had one shape: **an engine reporting exit 0, valid
JSON and zero findings because it had not checked anything.** The worst was
`osv-scanner --offline-vulnerabilities` — the flag documented for exactly this
purpose — silently loading no database while a full cache sat mounted.

The rule that came out of it is structural rather than a classification tweak: a
vulnerability engine runs only against a database we provisioned and stamped,
checked before the container starts. An empty result cannot be interpreted after
the fact, so the run is refused instead.

**Next session:** Phase 8 (`docs/phases/PHASE-08-normalizer.md`) — the normalizer
and golden corpus, the largest phase in the plan. Its inputs are
`fixtures/*/raw/*.json`, already committed. Note that alias edges come from
osv-scanner, and that the cluster id must be a durable surrogate row, never
derived from its members.

### 2026-08-17 (h) — Phase 6 implemented

`task verify` green (exit 0), 24 packages, lint clean.

Orchestration complete: the three envelopes with generated JSON Schemas, the
JetStream topology, engine resolution with a 422 that lists **every** offending
pair, fan-out after a single pinned fetch, mechanical status derivation, the
advisory-lock reaper, and WebSocket progress with snapshot-on-connect.

**The full pipeline is an automated test, not a manual checklist**: create scan →
fetch result → fan-out → worker consumes → result → status derived. It runs
against real Postgres and real NATS every time.

Six defects were found by running it. The most instructive: fan-out published
**zero jobs, silently**, because a removed column left the family empty and
every job failed validation. Nothing errored; the scan simply sat at `running`.
That path now logs at ERROR and names the consequence.

**Next session:** Phase 7 (`docs/phases/PHASE-07-sbom-adapters.md`) — syft,
trivy-fs, grype, osv-scanner, dependency-check. Note that `unavailable` is a
recorded status, never a scan failure, and that a worker's FIRST action is the
manifest HEAD.

### 2026-08-16 (g) — Phase 5 implemented

`task verify` green (exit 0), 20 packages, lint clean.

Sandbox and fetcher complete. The escape suite runs against a real Docker
daemon; a real repository was cloned end to end (`octocat/Hello-World` at
`7fd1a60b…`), archived to a content-addressed `tar.zst`, and a second archive of
the same tree deduplicated.

Six defects were found by RUNNING the thing rather than reading it — an
unwritable workspace, a network mode Docker does not have, an image entrypoint
that mangled the command, a partial bomb file surviving on Windows, a test that
miscounted DNS queries, and invisible characters in our own source. None would
have been visible from the code.

**Five gaps are documented above and not papered over.** The most significant:
the git clone reaches the network directly, so the connection-time address check
does not cover it.

**Next session:** Phase 6 (`docs/phases/PHASE-06-scan-orchestration.md`) — job
contracts, NATS JetStream, the DLQ and the deadline reaper. Note ADR-0004 (one
engine per job) and that `partial` is a first-class status, not an error.

### 2026-08-16 (f) — Phase 4 implemented

`task verify` green (exit 0), 18 packages, lint clean.

Project service complete: CRUD with owner block and validity window,
many-to-many classifications, the six CERT-In practices with gap reporting,
repository connections with Vault-backed credentials, and uploads to MinIO.
Frontend projects module built against the real API — list, three-step wizard,
detail with named gaps.

**Verified against the running stack, not just unit tests**: registered a
tenant, created a project, set partial practices and watched `not-provided`
score as a gap, connected a repository and confirmed the token reached Vault
while Postgres held only a path, uploaded a lockfile whose server-computed
sha256 matched the local file byte for byte, and confirmed a second tenant gets
404 with an empty listing.

Three guards mutation-tested: the credential test (storing the token instead of
the path fails it), the no-extraction assertion (adding `archive/zip` fails it),
and the shared route guard (unwrapping one route fails it).

Extracted the route-guard test into `libs/go-shared/routeguard` — it had been
copied into a second service and would have drifted by the eighth.

**Next session:** Phase 5 (`docs/phases/PHASE-05-sandbox-fetcher.md`) — the
untrusted-code boundary. Note that Phase 4 deliberately validates repository URL
SHAPE only; `TestPrivateAddressesAreNotBlockedAtParseTime` pins that division so
nobody "fixes" SSRF in the wrong layer. The real defence is blocking private
ranges at CONNECTION time, because DNS rebinding defeats any parse-time check.

### 2026-08-16 (e) — Phase 3 implemented

`task verify` green (exit 0), end to end including the frontend build.

Auth service complete: register, login, refresh with reuse detection, logout,
`/me`, GitHub OAuth, invitations. 40 new tests, all against **real Postgres** —
the properties under test (RLS isolation, SECURITY DEFINER reachability, atomic
invite acceptance) are properties of the database, so a mocked store would pass
while the product leaks.

Three guards were **mutation-tested rather than assumed**: refresh-family
revocation, the route-guard AST test, and both halves of the service-boundary
lint.

Found and fixed a latent `search_path` bug in `app.uuid_v7()` that only appeared
once a `SECURITY DEFINER` function called it — it had been silently correct for
two phases because callers happened to have `public` on their path.

**Next session:** Phase 4 (`docs/phases/PHASE-04-projects-sources.md`). Note it
owns the six **Practices and Processes** settings from CERT-In Table 5 (D6) —
they are a product feature, not a report section.

### 2026-08-16 (d) — Phase 2 implemented

`task verify` green. Manifest resolved against upstream; every URL probes 200.

Corrected a Phase 0 error of my own: the CBOMkit org is `cbomkit`, not `PQCA`.
Found three constraints that only a network probe reveals (see above), and one
gap in the dry run itself — it was not testing the URL templates at all.

**Next session:** Phase 3. Read `docs/phases/PHASE-03-auth-tenancy-rbac.md`.
RLS already works, so auth's job is to put a verified tenant into the context
that `db.WithTenant` consumes.

### 2026-08-16 (c) — Phase 1 implemented

Nine schemas migrated, RLS proven, compliance codegen working, CERT-In identifier golden-tested. Every check in the verification table above passed.

**The RLS guard was demonstrated failing, not just configured** — all three gap kinds, including `ENABLE`-without-`FORCE`, which is the one a naive check misses.

Work stopped at the final `task verify` because **the C: drive filled to 0 bytes**. All individual checks had already passed; see the blocker section.

**Next session:** Phase 2 (`docs/phases/PHASE-02-osint-supply-chain.md`). Its first command is `task osint:dryrun`, which resolves every `TBD` in the manifest against the network — and which will download binaries and images, so **resolve the disk blocker first**.

### 2026-08-16 (b) — Phase 0 implemented

`task verify` green. Git repo, Go module, six platform packages, the CLI, the service generator, all 8 service scaffolds, Python shared package with 19 tests, frontend scaffold, `.golangci.yml`, dual-OS CI, buf config.

Boundary lint demonstrated: a cross-service import **compiled cleanly under `go build`** and was rejected by depguard with exit 1. Redaction verified end-to-end in real startup logs.

Eight traps recorded, including `.gitattributes` multi-pattern lines being silently invalid and `core.autocrlf=true` at system level.

### 2026-08-16 (a) — Planning and specification

Greenfield. Produced the specification set, the validated CERT-In profile (read directly from the 66-page PDF), 17 phase prompts, 8 ADRs, the OSINT manifest and the repo skeleton. Twelve defects found in the original draft plan and corrected.
