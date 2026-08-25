# 08 — Operations

Local development, the compose stack, CI, observability, and runbooks.

---

## 1. Local development

### Prerequisites

| Tool | Version | Why |
|---|---|---|
| Go | **1.26+** | services, CLI — must satisfy the `go` directive in `go.mod` |
| Node | 20+ | frontend |
| Python | 3.11+ | workers |
| Docker | current | scanners and infra; **WSL2 backend on Windows** |
| go-task | 3.x | `go install github.com/go-task/task/v3/cmd/task@latest` |

Roughly 8 GB RAM for the running stack, plus **~5 GB disk** for the vulnerability
databases (grype ≈ 2.0 GB, trivy ≈ 1.3 GB, OSV ≈ 0.3 GB, NVD if enabled).

**Java is deliberately not required.** Every Java-based scanner — Dependency-Check, cbomkit, SonarQube — runs container-only. This is a design decision (ADR-0002), not a convenience: the primary dev machine has Java 1.8, and Dependency-Check needs 11+, cbomkit needs 17+. Do not add a local-JDK code path.

`task preflight` reports what is present and what is missing, with install instructions. It does not fail on missing optional tooling — it tells you what you lose.

### First run

```
git clone … && cd AxeBOM
cp .env.example .env          # runnable as-is; every credential is optional
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

task preflight                # what is installed, what is missing
task dev                      # infra + 8 services + workers + frontend
task health                   # per-service readiness

task osint:pull               # pre-pull engine images   ← REQUIRED before scanning
task osint:dbsync -- grype osv trivy    # ~3.5 GB, one-off
task osint:dbstatus           # confirm each database is stamped

task verify                   # the gate
```

`task dev` runs migrations automatically: the `migrate` service applies them once
and every other service waits for it to exit 0. Run `task db:reset` only when you
want the seed data (two tenants) or a clean slate.

> ⚠ **`task osint:pull` is not optional.** Engines run with `--network=none`, so a
> container cannot fetch its own image. Skip this and every container engine reports
> `unavailable — No such image`: an honest gap, and an entirely avoidable one.

Frontend at `localhost:5173`, API at `localhost:8080`, MinIO console at
`localhost:59001`, Mailpit at `localhost:58025`. Infrastructure uses a dedicated
5xxxx port range — see the compose file for why.

**Credentials are optional and all free.** See `docs/CREDENTIALS.md`. Without them,
`dependency-check` and the HBOM enrichment providers report `unavailable` with a
stated reason; nothing is silently omitted.

**The seed creates two tenants deliberately.** Isolation bugs are invisible with one. Every manual test should be performed as a user of tenant A while tenant B's data exists.

#### Signing in to a seeded database

Every seeded account uses the same password, **`axebom-dev-only`**. It is
named so it cannot be mistaken for a credential, and the seed loader refuses any
host that is not local, so these hashes cannot reach a remote database by
accident (`libs/go-shared/platform/db/seed.go`).

| Email | Password | Tenant | Role |
|---|---|---|---|
| `alice@acme.test` | `axebom-dev-only` | Acme Industries | owner |
| `aaron@acme.test` | `axebom-dev-only` | Acme Industries | analyst |
| `bob@beta.test` | `axebom-dev-only` | Beta Corp | owner |
| `carol@both.test` | — **SSO only** | Acme *and* Beta | analyst / viewer |

⚠ **carol has no password on purpose.** She is the only fixture that reaches
`Service.Login`'s empty-hash branch, which returns the same generic error as a
wrong password rather than "use GitHub instead" — saying so would confirm the
address is registered. She reaches her two tenants through the OAuth path.

Sign in as **alice** to see Acme's two projects, then as **bob** to see Beta's
one. Both tenants have a project called `payments-api`, so a cross-tenant leak
shows up as a duplicate rather than as nothing.

`TestSeededUsersCanLogIn` verifies each hash against that password on every run.
The seed shipped with no `password_hash` at all for a long time and nothing
caught it: every automated test used a service token or registered its own
account, so the one path a person actually takes was the one nothing exercised.

### Windows notes

- Work inside the repository on the **Windows filesystem**, with Docker using the WSL2 backend. Crossing the 9p filesystem boundary in the other direction (repo in WSL, tooling on Windows) is where the pathological I/O slowness lives.
- `.gitattributes` normalizes to LF and marks goldens `-text -diff`. **Do not set `core.autocrlf=true`** — it will corrupt golden files and produce failures that look like normalizer bugs.
- Long paths are enabled on this machine; `node_modules` and Go build caches still get deep. If you hit a path-length error, check `git config --system core.longpaths`.
- If `task dev` reports the Docker daemon unreachable, start Docker Desktop or `wsl -d docker-desktop`. Both WSL2 distros idle to `Stopped`.

---

## 2. Compose stack

Two profiles, because the full stack does not fit comfortably on a laptop.

### `core` — the default

Two files, layered:

| File | Contents |
|---|---|
| `docker-compose.yml` | Postgres 16 · NATS JetStream · Redis 7 · MinIO · Vault (dev mode) · Mailpit |
| `docker-compose.app.yml` | the `migrate` one-shot · 8 Go services · the SBOM worker · the frontend |

`task dev` starts both; `task dev:infra` starts only the first, which is what you
want when running services from an IDE against real backing stores.

**~4 GB RAM.** CI runs neither — it has no Docker job, so the DB-backed tests and
the sandbox escape suite only ever run locally.

> **Only the gateway is published to the host.** The other seven services are
> reachable only inside the compose network: a service that cannot be addressed
> directly cannot have its authentication bypassed by addressing it directly. That
> is also why `task health` runs *inside* the network — from outside, the other
> seven would read as unreachable while being perfectly healthy.

> **`docker compose ps` reports "Up", never "healthy", for the Go services.** They
> run on distroless/static — no shell, no curl — so a container-level HEALTHCHECK
> has nothing to execute. Readiness lives at `/readyz`; use `task health`.

### `heavy` — opt-in

```
task dev:heavy
```

Adds **Dependency-Track** (apiserver + frontend) and **SonarQube**.

> Dependency-Track needs **4 GB heap minimum**; its own docs recommend 8–12 GB. Combined with the core stack that is ~12–16 GB. It is an optional **export target**, not a scanner (`04-OSINT-INTEGRATION.md §2`), so nothing in the core product depends on it. Off by default for good reason.

### Volumes

`pgdata`, `miniodata`, `natsdata`, and — importantly — **`depcheck-data`**, which caches the NVD database. The first Dependency-Check sync takes 30–60 minutes; losing that volume means paying it again. `task dev:nuke` deletes it and prompts before doing so.

---

## 3. Migrations

`goose`, one directory per schema: `migrations/<schema>/NNNN_description.sql`.

```
task db:migrate     # apply pending
task db:reset       # drop + migrate + seed (prompts)
```

Rules:

1. Forward-only in production; reversible in development.
2. **A migration adding a tenant-scoped table without an RLS policy is incomplete.** `TestRLSCoverage` fails on it.
3. Never add a cross-schema foreign key — it is a JOIN dependency that blocks extracting the service later.
4. Data backfills go in a separate migration from schema changes, so a slow backfill never blocks a deploy.
5. Additive first: add column → deploy → backfill → deploy code that reads it → drop the old column in a later release. Never a breaking schema change in the same deploy as the code that needs it.

---

## 4. CI

GitHub Actions, on **windows-latest and ubuntu-latest** from Phase 0.

Running both from the start is not thoroughness for its own sake — it is the only way platform drift surfaces the day it appears rather than in month four, when it is a week of archaeology. Path separators, line endings, case-sensitivity and container behaviour all differ, and each is cheap to fix immediately and expensive to fix late.

| Workflow | Trigger | Runs |
|---|---|---|
| `verify` | PR, push | `task verify` — fmt, lint, **boundary lint**, profile lint, test, build |
| `golden` | PR touching `workers/**` or `libs/**` | `task test:golden` |
| `e2e` | PR to main | compose up + Playwright |
| `osint-contract` | **nightly** | each pinned tool against a fixture; failure opens an issue |
| `security` | PR + weekly | `govulncheck`, `npm audit`, image scan, secret scan |

**The nightly contract test matters more than it looks.** Upstream tools change on their own schedule, not ours. A grype DB schema bump or an osv-scanner CLI change will break a parser between one PR and the next, and a failing contract test auto-marks that engine `unavailable` rather than letting it feed garbage into a compliance report.

---

## 5. Observability

**Logs** — structured JSON, one line per event. Always: `request_id`, `tenant_id`, `service`, `trace_id`. **Never**: secrets, tokens, full request bodies, or component/finding detail (BOM content is confidential under CERT-In §5.3). A redaction filter keyed on field name and value shape sits in the logger, not at call sites.

**Metrics** — Prometheus at `:9090/metrics`.

| Metric | Why it is the one you want |
|---|---|
| `scan_duration_seconds{engine,status}` | per-engine, so a slow engine is visible without correlation |
| `scan_engine_status_total{engine,status}` | **`unavailable` and `partial` rates are the product health signal** — silent coverage loss is the failure mode that matters |
| `normalize_duration_seconds{phase}` | identity / alias / license / graph |
| `alias_cluster_size` histogram | a rising tail means over-merge |
| `report_render_duration_seconds{format}` | PDF is the one that will hurt |
| `job_retry_total{engine,reason}` | |
| `dlq_depth` | alert on any sustained non-zero |

**Traces** — OpenTelemetry, `traceparent` propagated through HTTP, gRPC and NATS headers. One trace spans API → orchestrator → fetch → N engine jobs → normalize → render, which is the only practical way to answer "why did this scan take 40 minutes."

**Alerts:** DLQ non-empty > 5 min · engine `unavailable` rate > 10% over 1 h · scan p95 > 30 min · report render failures > 1% · **any cross-tenant access attempt** (should be exactly zero; a single occurrence is an incident) · Postgres connections > 80% · Dependency-Check DB older than 7 days.

---

## 6. Runbooks

### Scan stuck in `running`

Check `scan.engine_runs` for a job past `deadline_at`. The reaper (leader-elected via Postgres advisory lock) should mark it `timeout` within a minute. If not, the leader is dead — check the advisory lock holder. Jobs are idempotent, so a redelivery is safe; `job_id` prevents duplicate artifacts.

### Engine suddenly `unavailable` everywhere

Almost always a version or DB mismatch after an upstream release. Check the nightly contract test, then `task osint:verify`. Do not "fix" it by unpinning — pin to a known-good version, reproduce, and update the manifest deliberately.

### Vulnerability counts jumped

First question: did the alias graph change? Compare `alias_snapshot_id` between the two scans. A cluster that split will double-count; a cluster that over-merged will under-count. `normalize.vuln_cluster_merges` records every merge with its evidence edge — that is the audit trail this scenario exists for.

Fix is a **re-normalization**, not a re-scan: raw artifacts are immutable and the corrected ruleset applies retroactively to every historical scan.

### Report render OOM

A Complete BOM of 50k components is 3000+ PDF pages. Expected behaviour is `REPORT_TOO_LARGE_FOR_PDF` with an explicit truncation note pointing to XLSX/JSON — not an OOM. If it OOMs, the page cap is not being enforced; check the renderer's streaming path.

### Suspected cross-tenant access

Treat as an incident, not a bug. Capture the `request_id` and `trace_id`; the audit log is append-only and is the evidence. Verify the app role is still non-superuser and non-`BYPASSRLS` (a privilege grant silently disables every policy), and that `SET LOCAL` is being issued per transaction. Run `TestRLSCoverage` against production schema.

---

## 7. Production

Kubernetes via Helm (`deploy/k8s`). Services scale horizontally and are stateless.

**Engine workers are the exception and need their own node pool** — they execute untrusted code and should not share a kernel with anything holding credentials. gVisor or Firecracker where available; at minimum a dedicated pool with strict network policy and no service-account token mounted.

Backups: Postgres PITR with a 30-day window; object storage versioned with lifecycle rules. **Raw scan artifacts are never deleted** — they are the evidence that makes reports defensible and normalization replayable.

Deploy: rolling, with readiness probes gating traffic. Migrations run as a pre-deploy job, and because they are additive-first, a rollback of application code never requires a schema rollback.

Restore drill quarterly. An untested backup is not a backup.
