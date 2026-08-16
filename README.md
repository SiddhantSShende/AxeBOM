# EncoreBOM

Enterprise Bill of Materials and Software Composition Analysis platform.

Generates **SBOM**, **CBOM** (cryptographic), **QBOM** (quantum), **AIBOM** and **HBOM** (hardware) inventories from connected repositories, normalizes the output of multiple open-source scanners into one canonical model, and renders compliance reports against the **CERT-In Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM, Version 2.0 (09.07.2025)**.

> **Status: pre-implementation.** This repository currently contains the specification and phase plan. No service logic exists yet. See `docs/STATE.md` for exactly what is and is not built.

---

## What it does

Connect a project via GitHub SSO or manual registration → classify it into one or more BOM types → run scans backed by pinned open-source engines → generate deep reports in SPDX and CycloneDX, at Top-Level or Complete depth, as PDF, XLSX or JSON. Reports are signed, shareable and commentable. Campaigns schedule recurring scans. A dependencies module gives full third-party visibility with per-engine provenance. VEX and CSAF carry vulnerability disclosure.

---

## Quick start

```bash
task preflight      # what's installed, what's missing
task dev            # bring up Postgres, NATS, Redis, MinIO, Vault-dev + services
task db:reset       # migrate and seed
task verify         # the gate: fmt + lint + boundary-lint + test + build
```

Install the task runner first — `winget install Task.Task`, or `go install github.com/go-task/task/v3/cmd/task@latest`.

**Requirements:** Go 1.24+, Node 20+, Python 3.11+, Docker Desktop (WSL2 backend on Windows), ~8 GB free RAM for the core stack. Java is *not* required locally — every Java-based scanner runs container-only, by design.

---

## Architecture

Eight Go services, five Python scan workers, a React frontend.

```
                    ┌──────────┐
  React SPA ───────▶│ gateway  │  authN/Z, routing, rate limit, WebSocket fan-out
                    └────┬─────┘
        ┌────────────────┼────────────────┬──────────────┬───────────┐
    auth-svc        project-svc     scan-orchestrator  report-svc  campaign-svc
                                          │                        comment-svc
                                          │                        notification-svc
                                    NATS JetStream
                                          │
                        ┌─────────────────┼──────────────────┐
                     fetcher         engine workers      normalizer
                  (holds the ONLY    (hold NO secrets,   (replayable over
                   git credentials;   run sandboxed)      immutable raw
                   materializes                           artifacts)
                   source ONCE)
```

Postgres (schema per service, RLS tenancy) · NATS JetStream (durable queues) · Redis (cache, rate limits) · MinIO/S3 (raw artifacts, reports) · Vault/KMS (secrets, signing keys).

Three structural choices worth knowing up front:

- **The fetcher materializes source exactly once per scan.** Engines cloning independently could land on different commits in a single report — a silent correctness bug in a compliance artifact. It also means no scanner-running component holds a credential.
- **One engine per job.** Retry, timeout and partial failure become per-engine, instead of re-running Syft because Dependency-Check timed out.
- **Normalization is replayable.** Raw scanner output is immutable; fixing a dedup bug re-normalizes stored artifacts rather than re-scanning. Reports stay defensible, and fixes apply retroactively.

---

## Repository layout

```
docs/            specifications, ADRs, per-phase build prompts, the CERT-In profile
services/        8 Go services
workers/         5 Python scan workers
libs/            go-shared, py-shared
proto/           gRPC + event contracts
frontend/        React + TypeScript + Vite
fixtures/        golden corpus — deliberately nasty test repositories
OSINT/           tools.manifest.yaml — pinned scanner versions, digests, checksums
deploy/          compose (core + heavy profiles), Dockerfiles, Helm
cmd/encorebom/   the CLI: preflight, toolctl, db, profile, docs, verify
```

---

## Documentation

Start with **`CLAUDE.md`** — the invariants. Then `docs/00-MASTER-PLAN.md` for scope and the phase plan, and `docs/STATE.md` for current reality.

Four documents are the single source of truth and may not be restated elsewhere: `01-DATA-MODEL.md` (schema), `02-CONTRACTS.md` (process boundaries), `03-NORMALIZER-SPEC.md` (normalization behaviour), `04-OSINT-INTEGRATION.md` (engines).

`docs/reference/certin-v2.0.yaml` encodes every CERT-In field once, with a page citation into the source PDF. Go structs, Python models, report tables and the coverage checker all generate from it. Field counts are never hardcoded anywhere.

---

## Building it

Work proceeds one phase per session. Open a session and say:

> Implement Phase 3 of EncoreBOM. Read `docs/phases/PHASE-03-auth-tenancy-rbac.md`.

Each phase file is self-contained: goal, exactly which docs to read, what is out of scope, a file manifest, contracts to honour, test requirements, and a machine-checkable exit criterion.

MVP is Phases 0–10 (≈24 engineer-weeks). All five BOM types is Phases 0–16 (≈40 weeks). These are honest numbers; see `docs/00-MASTER-PLAN.md §Effort`.

---

## Things we will not pretend

- **There is no open-source HBOM scanner.** HBOM is a structured CSV/form import plus a data model. The UI says so.
- **QBOM is largely a derivation** from CBOM crypto discovery plus device metadata captured by form. No tool discovers quantum hardware.
- **EncoreBOM reports violations against a configured policy.** It never asserts that something is "compliant" — that word does not appear in generated output.
- **Every report states what it could not see.** A mandatory Engine Coverage section lists each engine's status and any ecosystem detected with no available engine. An SBOM that silently omits an ecosystem is worse than no SBOM.

---

## Licensing

EncoreBOM invokes open-source scanners as subprocesses and services; it does not fork or relicense them. Each tool's license is recorded in `OSINT/tools.manifest.yaml` and tracked in EncoreBOM's own SBOM.

**No GPL code is linked into EncoreBOM binaries.** Notably `django-bom` (GPL-3.0) is used as a schema reference only — never imported. See `CLAUDE.md` invariant 9.
