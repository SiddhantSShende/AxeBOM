# CLAUDE.md — EncoreBOM

Read this first, every session. It contains **invariants only**, not a plan.
The plan lives in `docs/00-MASTER-PLAN.md`. What has actually been built lives in `docs/STATE.md`.

---

## What EncoreBOM is

An enterprise Bill of Materials + Software Composition Analysis platform producing five BOM types — **SBOM, CBOM** (cryptographic), **QBOM** (quantum), **AIBOM**, **HBOM** (hardware) — against the **CERT-In Technical Guidelines v2.0 (09.07.2025)**. Go microservices, Python scan workers, React frontend, PostgreSQL, NATS JetStream, MinIO.

---

## Start-of-session ritual

1. Read `docs/STATE.md` — what exists, what is stubbed, what is owed.
2. Read the phase file you were asked to implement: `docs/phases/PHASE-NN-*.md`.
3. Read **only** the docs that phase's `Read first` block names. Do not read all of `docs/` — it will not fit and you do not need it.
4. Implement.
5. **Update `docs/STATE.md` before you finish.** A session that does not update STATE.md has failed, no matter what code it wrote.

---

## The invariants

These are not style preferences. Violating any of them produces a silently wrong compliance artifact, a security hole, or a legal problem. If a task seems to require breaking one, stop and ask.

### 1. The four contract documents are the single source of truth

| Document | Owns |
|---|---|
| `docs/01-DATA-MODEL.md` | Every table, column, type, enum. **No other document may define a column.** |
| `docs/02-CONTRACTS.md` | Anything crossing a process boundary — NATS subjects, job/event/result envelopes, REST conventions, error taxonomy. |
| `docs/03-NORMALIZER-SPEC.md` | Identity, dedup, alias closure, license resolution, graph merge, coverage. |
| `docs/04-OSINT-INTEGRATION.md` | What each scanner actually is, how it is invoked, how its output maps to canonical. |

**Never restate a spec in another file.** Reference it. Restated specs drift, and a future session will believe the wrong copy.

### 2. `docs/reference/certin-v2.0.yaml` is data, and field counts are never hardcoded

Every CERT-In field is defined once, there, with a page citation. Go structs, Python models, report field tables, and the coverage checker all generate from or validate against it.

**Never write a field count** — not `21`, not "the 21 data fields" — in code, UI copy, tests, or documentation. Render it from the profile. Hardcoding a count is exactly how a product ships a false compliance claim when the guideline is revised.

### 3. `not-provided` is reported, but never counts as covered

Unknown fields are stored explicitly as `not-provided` — never silently omitted, because omission hides the gap. But `not-provided`, `NOASSERTION`, `unknown`, `""` and `[]` all score **present = 0**.

Every report publishes **two numbers**:
- `completeness_pct` — substantive values only. The honest compliance signal.
- `declaration_pct` — any value including explicit `not-provided`. A representation check, not compliance.

Publishing only the second and calling it "coverage" is how tools produce misleading 100% scores. Both. Always.

*(One deliberate exception: license `NONE` counts as present. It is a substantive assertion — "we looked, there is no license." `NOASSERTION` is not. See `03-NORMALIZER-SPEC.md`.)*

### 4. `component.purl` and `component.certin_identifier` are different fields

- `component.purl` — canonical ecosystem Package URL (`pkg:maven/org.apache.tomcat/tomcat@9.0.71`). **This is the merge key.** Every scanner emits it; all dedup runs on it.
- `component.certin_identifier` — CERT-In's own form (`pkg:supplier/ApacheSoftwareFoundation/ApacheTomcat@9.0.71?...`). **Derived, render-only. Never a merge key.**

Conflating them breaks dedup and produces a non-compliant report. They are not the same syntax and never will be.

### 5. Coverage scoring is type-aware

CERT-In Table 9 is **type-discriminated**: Algorithms, Keys, Protocols and Certificates have *different* field sets. Score a crypto asset only against the field set for its `asset_type`. Scoring a certificate against `key_size` reports every CBOM at ~30% coverage — falsely, in a compliance document.

### 6. Multi-tenancy is enforced by Postgres RLS, not by WHERE clauses

Every tenant-scoped table has `tenant_id` and an RLS policy on `app.current_tenant_id`, set per-request by the connection wrapper in `libs/go-shared/platform/db`.

- **Never write `WHERE tenant_id = ?` by hand.** It will eventually be forgotten in exactly one query, and that query is the breach.
- **Never use a superuser or `BYPASSRLS` role** from application code.
- Cross-tenant fetch returns **404, not 403** — a 403 confirms the resource exists.
- Every new table needs an RLS policy in the same migration, and `TestRLSCoverage` enumerates all tables and fails on any without one.

### 7. Scanners run in the sandbox. Always. And they hold no credentials.

We execute third-party binaries over untrusted user code. That is remote code execution by design.

- The **fetcher** materializes source exactly once per scan, records `commit_sha`, uploads a content-addressed archive. Engines consume that archive. Six engines cloning independently can land on six different commits in one report.
- **Only the fetcher holds git credentials.** No component that runs a scanner has access to any secret.
- Engines run `--network=none` (DB-backed engines get an egress allowlist), read-only rootfs, `--cap-drop ALL`, non-root, tmpfs workdir, memory/pid/disk/wall-clock quotas, seccomp.
- **Never run package-manager resolution that executes user code.** No `npm install`, no `mvn`, no `gradle`, no `pip install`, no `setup.py`. Lockfile and manifest parsing only.
- Clone with `GIT_ALLOW_PROTOCOL=https` (git's `ext::` transport is arbitrary command execution), `--depth 1 --single-branch`, hooks disabled, size/file-count/inflation caps.
- Block private IP ranges **at connection time**, not at URL-parse time — DNS rebinding defeats parse-time checks.

### 8. Escape spreadsheet cells

A component named `=cmd|'/c calc'!A1` executes when the XLSX opens. Prefix any cell value beginning with `=`, `+`, `-`, `@`, TAB or CR with a single quote. This product's entire output surface is spreadsheets; this is a repeatedly-shipped vulnerability class.

### 9. No GPL code in our binaries

`django-bom` is GPL-3.0. **Never `pip install` it, never import it.** Use it as a schema reference only. The HBOM model is ours — it is a recursive tree of ~24 fields, roughly 300 lines.

Before adding any dependency, check its license. Copyleft goes in a subprocess or a separate service, or not at all.

### 10. Normalization is replayable; raw artifacts are immutable

Normalization is a deterministic pure function of *(raw artifacts + ruleset version + alias snapshot)*.

- Raw scanner output is written once to object storage and **never mutated or deleted**.
- Fixing a normalizer bug means **re-normalizing stored artifacts into a new version** — not re-running the scanners.
- Never overwrite normalized data in place. Version it.

This is what makes a report defensible six months later, makes dedup fixes retroactive, and turns any future CERT-In revision into a data change plus a re-normalization pass.

### 11. Service boundaries are enforced by the compiler and by lint

- **Schema-per-service** in one Postgres. **Never JOIN across a schema boundary in SQL.** Cross-domain joins happen in Go. This single discipline is what keeps services extractable; it costs nothing today and is impossible to retrofit.
- Cross-service calls go through generated clients only. Never import another service's internal packages — `depguard` fails the build if you do.
- Shared types live in `libs/go-shared`. If two services need a type, it belongs there or in `proto/`.

### 12. Every report states what it could not see

Every generated report carries a mandatory **Engine Coverage** section: each requested engine, its terminal status, the ecosystems it covered, and — critically — ecosystems detected with **no available engine**.

An SBOM that silently omits an ecosystem is worse than no SBOM: it converts an unknown into a false negative the customer trusts. `partial` is a first-class status, not an error.

---

## Conventions

**Time.** UTC, RFC3339, literal `Z`. No local time anywhere, ever.

**IDs.** UUIDv7 for entities (time-ordered). Job idempotency keys are UUIDv4.

**Errors.** Every error carries a stable machine code from the taxonomy in `docs/02-CONTRACTS.md`. Never return a bare string. Go: wrap with `platform/errs`. Never `panic` in a request or job path.

**Migrations.** `goose`, one directory per service schema, forward-only in production, reversible in development. A migration that adds a tenant-scoped table without an RLS policy is incomplete.

**Naming.** Go: `camelCase` locals, `PascalCase` exports, package names singular (`project`, not `projects`). SQL: `snake_case`, tables plural. TypeScript: `PascalCase` components, `camelCase` everything else. Event subjects: `scan.job.<family>`, dot-separated lowercase.

**Tests.** Table-driven in Go. Normalizer changes require a golden-file update, and changing a golden requires an explicit justification in the commit message — goldens are the guardrail against silently wrong output.

**No bash scripts.** `make` and `task` are not installed on the primary dev machine, and PowerShell 5.1 has no `&&`. Orchestration is `Taskfile.yml` (go-task, shell-independent) plus the `encorebom` Go CLI. Anything a script would do, the CLI does.

---

## Commands

```
task preflight      # what's installed, what's missing
task dev            # bring up the core stack
task verify         # fmt + lint + boundary-lint + test + build   ← the gate
task db:reset       # drop, migrate, seed
task profile:lint   # validate certin-v2.0.yaml counts + statuses
task osint:sync     # fetch + verify pinned scanner artifacts
task test:golden    # normalizer golden-file diff
```

---

## Known environment constraints

Probed on the primary dev machine (Windows 11), and the reason for two design choices:

- **Java is 1.8.** Dependency-Check needs 11+, cbomkit needs 17+. Therefore **all Java tools run container-only, never installed locally.** Do not add a local-JDK code path.
- **Docker Desktop is installed but its daemon may be stopped**, and both WSL2 distros idle. `task preflight` reports this; `task dev` fails with a clear message rather than a confusing timeout.
- **No `make`, no `task`, no `cosign` binary** initially. `task preflight` prints install instructions. Signature verification degrades to checksum-only with a loud warning — never silently.
- CI runs **windows-latest AND ubuntu-latest** from Phase 0, so platform drift surfaces the day it appears.

---

## Document index

| Path | Purpose |
|---|---|
| `docs/00-MASTER-PLAN.md` | Scope, architecture, 17 phases, MVP boundary, glossary |
| `docs/01-DATA-MODEL.md` | ⚑ SSOT — schema |
| `docs/02-CONTRACTS.md` | ⚑ SSOT — process boundaries |
| `docs/03-NORMALIZER-SPEC.md` | ⚑ SSOT — normalization behaviour |
| `docs/04-OSINT-INTEGRATION.md` | ⚑ SSOT — scanner engines |
| `docs/05-SECURITY-MODEL.md` | Tenancy, sandbox, threat model, RBAC matrix |
| `docs/06-COMPLIANCE-PROFILES.md` | How the profile mechanism works |
| `docs/07-FRONTEND-SPEC.md` | Routes, state, design system |
| `docs/08-OPERATIONS.md` | Local dev, compose, CI, runbooks |
| `docs/09-GOLDEN-CORPUS.md` | Test fixtures and what each proves |
| `docs/STATE.md` | ⚑ LIVING — read at start, update at end |
| `docs/LIMITATIONS.md` | What the product does NOT do — boundaries and known gaps |
| `docs/COMPLIANCE-REPORT.md` | Generated coverage evidence pack (`task profile:evidence`) |
| `docs/ADR/` | One file per irreversible decision |
| `docs/reference/certin-v2.0.yaml` | ⚑ The compliance profile |
| `docs/reference/CERT-In_BOM_Guidelines_v2.0.pdf` | The source document |

---

## Honest labels — do not oversell these in code, docs, or UI

- **There is no open-source HBOM scanner.** HBOM is a structured CSV/form import plus a data model. Label it that way in the UI. Never imply discovery.
- **QBOM is largely a derivation.** Crypto assets come from CBOM discovery with quantum-vulnerability rules applied; only Table 8's *device* metadata is separately captured. There is no quantum-hardware scanner.
- **EncoreBOM reports violations against a configured policy.** It never asserts "compliant." That word does not appear in generated output.
