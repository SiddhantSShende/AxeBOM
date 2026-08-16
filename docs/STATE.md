# STATE

**⚑ LIVING DOCUMENT.** Read at the start of every session. Update before finishing.

A session that writes code but does not update this file has failed — the next session starts blind, and rediscovering what is stubbed costs more than the work itself.

---

**Last updated:** 2026-08-16
**Current phase:** Phase 0 — not started
**Next action:** `Implement Phase 0 of EncoreBOM. Read docs/phases/PHASE-00-foundations.md.`

---

## Status at a glance

| Area | State |
|---|---|
| Specification & phase plan | ✅ complete |
| CERT-In compliance profile | ✅ complete, validated, 100% `verified` |
| Repo skeleton | ⬜ directories only, no code |
| Go services (8) | ⬜ not started |
| Python workers (5) | ⬜ not started |
| Frontend | ⬜ not started |
| Database | ⬜ no migrations |
| OSINT manifest | ✅ written · ⬜ never executed |
| CI | ⬜ not started |

Nothing has been built. **This repository currently contains a plan, not a product.**

---

## What exists

### Documentation — complete

| File | Purpose |
|---|---|
| `CLAUDE.md` | 12 invariants + doc index |
| `docs/00-MASTER-PLAN.md` | Scope, architecture, 17 phases, risks, effort |
| `docs/01-DATA-MODEL.md` | ⚑ SSOT — schema |
| `docs/02-CONTRACTS.md` | ⚑ SSOT — process boundaries |
| `docs/03-NORMALIZER-SPEC.md` | ⚑ SSOT — normalization |
| `docs/04-OSINT-INTEGRATION.md` | ⚑ SSOT — engines |
| `docs/05-SECURITY-MODEL.md` | Tenancy, sandbox, threat model, RBAC |
| `docs/06-COMPLIANCE-PROFILES.md` | Profile mechanism |
| `docs/07-FRONTEND-SPEC.md` | Routes, design system, screens |
| `docs/08-OPERATIONS.md` | Dev, compose, CI, runbooks |
| `docs/09-GOLDEN-CORPUS.md` | 15 fixtures and what each proves |
| `docs/ADR/0001–0008` | Irreversible decisions |
| `docs/phases/PHASE-00…16` | 17 build prompts |

### Compliance profile — complete and validated

`docs/reference/certin-v2.0.yaml`, transcribed directly from the 66-page source PDF at `docs/reference/CERT-In_BOM_Guidelines_v2.0.pdf`.

Validated: **134 unique field ids · all 17 expected counts match · zero `assumed` entries · SBOM ordinals contiguous 1–21.**

Covers: 3 minimum-element categories · 21 SBOM data fields · 6 Practices-and-Processes sub-elements · 5 levels · 6 SDLC classifications · 11 QBOM elements · 4 crypto asset types (8/7/5/10 fields) · 19 AIBOM elements · 24 HBOM elements · 4 VEX statuses · 7 secure-distribution controls.

### Repo skeleton — directories only

`docs/` `OSINT/` `proto/` `services/{8}` `workers/{5}` `libs/{go-shared,py-shared}` `frontend/` `fixtures/` `deploy/{compose,docker,k8s}` — all empty.

Root files present: `CLAUDE.md`, `README.md`, `Taskfile.yml`, `.gitattributes`, `.gitignore`, `.env.example`.

---

## What does NOT exist

Everything else. Explicitly, so no session assumes otherwise:

- No `go.mod`, no `package.json`, no `pyproject.toml`, no `Dockerfile`, no `docker-compose.yml`
- No `cmd/encorebom` CLI — **every `task` target referencing it will fail until Phase 0**
- No migrations, no database, no seed
- No service code, no worker code, no adapters, no frontend
- No CI workflows
- No fixtures — `fixtures/` is empty; the 15 in `09-GOLDEN-CORPUS.md` are specified, not built
- **`task osint:sync` has never been run.** The manifest's URLs and digests are unverified against the network. Phase 2's first job is `task osint:dryrun`.
- Not a git repository yet — `git init` is a Phase 0 step

---

## Decisions already made

Do not relitigate these without an ADR. Rationale is in `docs/ADR/`.

| # | Decision |
|---|---|
| 0001 | 8 Go services + 5 Python workers (user-confirmed over a modular monolith), with four mechanical mitigations |
| 0002 | Pinned release binaries and images; **no source builds**; Java tools container-only |
| 0003 | Replayable normalization over immutable raw artifacts |
| 0004 | One engine per job |
| 0005 | Durable surrogate vulnerability-cluster ids |
| 0006 | Postgres RLS for tenancy |
| 0007 | Profile-driven compliance; never hardcode field counts |
| 0008 | Fetcher materializes source exactly once and holds the only credentials |

Also settled: **SBOM deep first, then breadth** (build order); **Docker Desktop + WSL2** (dev environment).

---

## Known gaps and debt

| Item | Detail | Owner |
|---|---|---|
| OSINT manifest unverified | Written from upstream research; digests and URLs never resolved against the network | Phase 2 |
| `sonar-cryptography` deferred | Requires a running SonarQube server. `cbomkit-theia` covers directory and image discovery without it | post-MVP |
| Dependency-Track is an export target | Not a scanner. 4 GB heap minimum. Compose profile `heavy`, off by default | Phase 14+ |
| HBOM has no scanner | Structured import only — no OSS tool discovers physical parts. **Must be labelled honestly in the UI** | Phase 15 |
| QBOM is a derivation | Crypto assets from CBOM + quantum rules; only device metadata is separately captured | Phase 11 |
| Part enrichment optional | Nexar/Octopart is paid and quota-limited. `PartDataProvider` defaults to `manual` | Phase 15 |
| Java 8 on dev machine | Why Java tools are container-only. Do not add a local-JDK path | permanent |
| No `cosign` installed | Signature verification degrades to checksum-only **with a loud warning** | Phase 2 |

---

## Environment (probed 2026-08-16)

| | |
|---|---|
| Go | 1.26.2 ✅ |
| Node | 24.14.1 ✅ |
| Python | 3.14.4 ✅ (real interpreter, not the Store stub) |
| Git | ✅ |
| WSL2 | Ubuntu + docker-desktop, both **Stopped** |
| Docker daemon | **not reachable** — start Docker Desktop before `task dev` |
| Java | **1.8.0_481** — too old for Dependency-Check (11+) and cbomkit (17+) |
| `task` / `make` / `cosign` | **absent** — install go-task first |

---

## Session log

Newest first. One entry per session: what changed, what is now true, what the next session should know.

### 2026-08-16 — Planning and specification

Greenfield. Directory was empty.

**Produced:** the full specification set, the validated CERT-In profile, 17 phase prompts, 8 ADRs, the OSINT manifest, and the repo skeleton.

**Source verification:** the CERT-In PDF was located and read directly (66 pages). Tables 5, 6, 8, 9, 10, 11 and §§3.1, 3.2, 5.3, 6 extracted verbatim. All fifteen OSINT tool sources checked against upstream.

**Defects found in the original draft plan and corrected here:**

1. CBOMkit repos are under `PQCA/`, not `cbomkit/` — the draft's bootstrap would have failed at clone.
2. `django-bom` is **GPL-3.0**; the draft imported it into `hbom-worker`, which would have made that worker a GPL derivative.
3. Source builds are wrong for a compliance product — version metadata is injected at release, and provenance is the product.
4. No sandbox anywhere in the draft, despite executing third-party scanners over untrusted code.
5. Several tools misclassified: `protobom` is a Go library belonging to the report phase; `sonar-cryptography` needs a SonarQube server; Dependency-Track is a platform, not a scanner.
6. **"Minimum Elements" is three categories, not 21 fields** — the draft omitted Practices and Processes entirely.
7. **Table 9 is type-discriminated** — flattening it would report every CBOM at ~30% coverage, falsely.
8. **CERT-In's unique identifier is not a standard PURL** — the draft conflated two different identifiers into one field.
9. **HBOM §10.4.1.4 requires four fields absent from Table 11**, and Table 11 lists supplier twice at two different levels.
10. Independent per-engine cloning could put six different commits in one report.
11. The normalizer was one bullet inside the SBOM phase.
12. Security was deferred to a final "hardening" phase.

**Next session:** Phase 0. Nothing is built; start from `go mod init`.
