# 00 — Master Plan

The map, not the territory. Scope, architecture, the phase sequence, and the honest numbers.

For invariants read `CLAUDE.md`. For what is actually built read `STATE.md`. For anything schema-, contract-, normalization- or engine-shaped, read the four SSOT documents — this file deliberately does not restate them.

---

## 1. Product

EncoreBOM generates five bill-of-materials types — **SBOM**, **CBOM** (cryptographic), **QBOM** (quantum), **AIBOM**, **HBOM** (hardware) — against the **CERT-In Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM, Version 2.0 (09.07.2025)**.

**The flow.** Connect a project (GitHub SSO or manual registration/upload) → classify it into one or more BOM types → run scans backed by pinned open-source engines → generate reports in SPDX and/or CycloneDX, at Top-Level and/or Complete depth, as PDF, XLSX or JSON. Reports are signed, shareable and commentable. Campaigns schedule recurring scans. A dependencies module gives third-party visibility with per-engine provenance. VEX and CSAF carry vulnerability disclosure.

**Users** (CERT-In §2.2): Software Consumer, Software Developer, System Integrator/Reseller.

**The five-step generate flow** the dashboard exists to serve:

> select project → select classification(s) → report type (Top-Level / Complete / both) → BOM standard (SPDX / CycloneDX / both) → format(s) (PDF / XLSX / JSON / …, multi) → **Run**

Each step is multi-select where the guideline permits it. One `Scan` job carries every chosen dimension and fans out to the right engines.

---

## 2. What we will not pretend

Stated here because it shapes the phase plan, and because overselling any of these would burn a phase and produce something undemoable.

- **There is no open-source HBOM scanner.** No tool discovers physical parts. HBOM is a structured CSV/form import plus a data model. The UI says so.
- **QBOM is largely a derivation.** Crypto assets come from CBOM discovery with quantum-vulnerability rules applied; only Table 8's *device* metadata is separately captured. No tool discovers quantum hardware.
- **EncoreBOM reports violations against a configured policy.** It never asserts "compliant." That word does not appear in generated output.
- **Every report states what it could not see.** A mandatory Engine Coverage section lists each engine's status and every ecosystem detected with no available engine. An SBOM that silently omits an ecosystem is worse than no SBOM.

---

## 3. Architecture

Eight Go services, five Python workers, a React frontend. Postgres (schema per service, RLS tenancy), NATS JetStream, Redis, MinIO/S3, Vault/KMS.

| Service | Responsibility |
|---|---|
| `gateway` | AuthN/Z, routing, rate limiting, WebSocket fan-out |
| `auth-svc` | GitHub SSO, local accounts, JWT, RBAC, invites, audit |
| `project-svc` | Projects, owners, validity, classifications, practices, repo connections |
| `scan-orchestrator` | Job creation, fan-out, lifecycle, aggregation, progress |
| `report-svc` | SPDX/CycloneDX export, PDF/XLSX/JSON rendering, signing, sharing |
| `campaign-svc` | Cron scheduling, recurring triggers, run history |
| `comment-svc` | Threaded comments per report |
| `notification-svc` | Email and webhooks |

| Worker | Engines |
|---|---|
| `sbom-worker` | syft, grype, trivy-fs, trivy-image, osv-scanner, dependency-check |
| `cbom-worker` | cbomkit-theia (+ optional cbomkit service) |
| `qbom-worker` | crypto derivation + device-metadata capture |
| `aibom-worker` | ai-bom, aibom-generator |
| `hbom-worker` | CSV import, form, part-data enrichment |

### Three structural decisions

**The fetcher materializes source exactly once per scan.** Engines cloning independently could land on different commits, producing a report describing a codebase that never existed. Fetching once also means only the fetcher holds git credentials, so **no component that runs a third-party scanner over untrusted code holds any secret**. → ADR-0008.

**One engine per job.** Retry, timeout, partial failure and progress all become per-engine, instead of re-running syft because dependency-check timed out. → ADR-0004.

**Normalization is replayable over immutable raw artifacts.** A dedup bug is fixed by re-normalizing, not re-scanning: reports stay defensible, fixes apply retroactively, and a future CERT-In revision becomes a data change. → ADR-0003.

### Microservices: the choice and its cost

Eight services was chosen deliberately over a modular monolith. The cost is real and worth naming: roughly 3–4 additional weeks of plumbing, thirteen deployables, and — the sharper risk — **no compiler to enforce completeness on a cross-cutting change**. A change touching every service is a change across eight trees that an agent with fresh context each session must keep coherent by discipline rather than by `go build`.

Four mechanical mitigations, all landing in Phase 0 because they are worthless added later:

1. **Service generator** — adding a service is one command, not hand-written boilerplate.
2. **Schema-per-service, no cross-schema JOINs in SQL.** Cross-domain joins happen in Go. Costs nothing today; impossible to retrofit.
3. **Import-boundary lint (`depguard`) in CI.** Mechanical, fails the build, survives context loss. Disabling it is an ADR-level decision.
4. **CI on windows-latest and ubuntu-latest from day one**, so platform drift surfaces the day it appears rather than in month four.

→ ADR-0001.

---

## 4. Phases

Seventeen phases. Foundations are split by risk profile; the sandbox and the normalizer each get their own phase; security lands in the phase that introduces the risk rather than in a "hardening" phase at the end.

| # | Phase | Exit criterion (machine-checkable) | Wks |
|---|---|---|---|
| 0 | Repo skeleton, Taskfile, CI, service generator, boundary lint, error taxonomy, observability | `task verify` green on Windows **and** Ubuntu; boundary lint **fails** on a deliberate cross-domain import | 1.0 |
| 1 | Data model, migrations, schema-per-service, RLS, seed/fixtures, profile codegen | `task db:reset && task db:seed`; `TestRLSCoverage` enumerates every table; `task profile:lint` passes | 2.0 |
| 2 | OSINT supply chain: manifest, `toolctl sync`, availability probe, contract tests | `task osint:verify` resolves every engine; each adapter contract test green | 1.0 |
| 3 | Auth, tenancy, RBAC | authz matrix covers every (role, resource, action); cross-tenant fetch returns **404** | 1.5 |
| 4 | Projects & sources, incl. the six Practices-and-Processes settings | project CRUD + upload E2E; classifications and practices persist | 1.5 |
| 5 | **Sandbox + fetcher** — the untrusted-code boundary | SSRF / `ext::` / zip-slip / symlink-escape / decompression-bomb suite green | 2.0 |
| 6 | Scan orchestration, envelopes, WS progress, DLQ, deadline reaper | schemas published; kill-a-worker → redelivered, zero duplicate artifacts | 2.0 |
| 7 | SBOM engine adapters | all engines emit valid `ScanResultV1` across fixtures; `unavailable` path exercised | 2.5 |
| 8 | **Normalizer + golden corpus** | golden diff over 12–15 fixtures; alias union-find tests; coverage formula tests | 4.0 |
| 9 | Reports: SPDX + CycloneDX, PDF/XLSX/JSON, async render, signing, sharing | validators pass; **formula-injection test**; 50k-component render within cap | 3.5 |
| 10 | Dashboard, 5-step flow, dependency explorer, findings UI | Playwright E2E: connect → scan → live progress → download PDF | 3.0 |
| | **── MVP boundary ≈ 24 weeks ──** | | |
| 11 | CBOM + QBOM | crypto inventory with **type-aware coverage**; PQC migration status | 3.0 |
| 12 | AIBOM | all Table-10 elements; valid CycloneDX ML-BOM | 2.5 |
| 13 | VEX/CSAF + comments | CSAF 2.0 round-trip; effective-status resolution | 3.0 |
| 14 | Campaigns + notifications | weekly campaign runs unattended, idempotent across restarts | 2.0 |
| 15 | HBOM | recursive subcomponents; §10.4.1.4 fields; **zero GPL in the binary** | 2.5 |
| 16 | Profile validation, hardening, perf, pen-test | profile 100% verified; pen-test findings closed | 3.0 |

### Milestones

| | Phases | What you have |
|---|---|---|
| **M1** | 0–8 | Real multi-engine SBOM, normalized and deduped. Internal alpha. |
| **M2** | 9–10 | Downloadable signed SPDX/CycloneDX/PDF/XLSX, guided flow, dependencies. **← MVP** |
| **M3** | 11–12, 15 | All five BOM types |
| **M4** | 13–14, 16 | VEX/CSAF, campaigns, hardening. GA. |

---

## 5. Effort

**≈ 24 engineer-weeks to MVP (Phases 0–10). ≈ 40 weeks for all five BOM types.**

- Solo with Claude Code: **5.5–6 months to MVP**, **9–10 months** to the full suite.
- With 2–3 engineers: **3–4 months to MVP**.
- Add enterprise SSO beyond GitHub, admin console, billing, Kubernetes, backup/DR and UI iteration: **~12 months** total.

The microservices choice contributes roughly 3–4 weeks of the above.

> **This is not a 3-month build.** Anyone promising all five BOM types in three months is promising five thin CLI wrappers, not a compliance product. The honest pitch is a credible SBOM platform at ~6 months, CBOM/QBOM by month 8, the full suite by 10–12.

---

## 6. Risks

Ranked. Each has a mitigation that lives in a specific phase, not in a wish.

| # | Risk | Mitigation | Phase |
|---|---|---|---|
| 1 | **Running untrusted user code through third-party scanners.** RCE via build files; SSRF via clone URL (`ext::` transport is arbitrary command execution; `169.254.169.254` is cloud metadata); zip-slip; decompression bombs; credential exfiltration. **This is the risk that ends the company.** | Fetcher-only credentials; `https`-only with private-IP blocking at connection time; no package-manager resolution; `--network=none`; read-only rootfs; dropped caps; quotas. Escape-attempt test suite. | 5 |
| 2 | **Normalizer silently wrong.** A compliance product that under-reports converts unknowns into false negatives the customer trusts. | Golden corpus of deliberately nasty fixtures; changing a golden requires written justification; Engine Coverage makes gaps visible. | 8 |
| 3 | **Scope — five BOM types is 3–5× the product.** | SBOM-only MVP. CBOM second. HBOM honestly labelled as import. Sell the roadmap, not vapour. | plan |
| 4 | **OSINT tool fragility.** DB schema versions break pinned binaries; CLIs change across majors; cbomkit's output schema is early. | Exact version + digest pins; **nightly** contract tests; defensive parsers; a failing contract auto-marks the engine `unavailable`. | 2 |
| 5 | **Agent-session coherence drift.** Fresh context every session, thirteen deployables. | `CLAUDE.md` invariants; per-phase prompt files with do-not-touch lists; machine-checkable exits; ADRs; `STATE.md` updated every session. | 0 |
| 6 | **Windows dev friction.** Java 8, Docker daemon stopped, no task runner, CRLF corrupting goldens. | Taskfile + Go CLI, no bash; `.gitattributes` pins goldens to LF and `-diff`; Java tools container-only; CI on both OSes. | 0 |
| 7 | **PDF rendering of a Complete BOM.** 50k components is 3000 pages and will OOM a naive HTML→PDF path. | Async render job; page cap with an explicit truncation note; product rule — Top-Level → PDF, Complete → XLSX/JSON. | 9 |
| 8 | **Multi-tenancy leak.** | RLS with `FORCE`, non-superuser app role, repository layer that cannot build an unscoped query, `TestRLSCoverage` over every table. | 1, 3 |
| 9 | **Alias-graph recomputation cost.** | Incremental union-find with a merge log; recompute only affected clusters. | 8 |
| 10 | **Legal exposure from compliance claims.** | Never assert "compliant"; keep declared/concluded licenses distinct; flag ambiguous SPDX ids rather than resolving them; disclaimers on rendered reports. | 9 |

---

## 7. Glossary

**BOM** Bill of Materials. **SBOM/CBOM/QBOM/AIBOM/HBOM** software / cryptographic / quantum / AI / hardware variants.

**PURL** Package URL — `pkg:maven/org.apache.tomcat/tomcat@9.0.71`. The component merge key. **Not** the same as the *CERT-In identifier* (`pkg:supplier/Org/Name@ver`), which is derived and render-only.

**CPE** Common Platform Enumeration — NVD's identifier scheme, used by dependency-check. Lower-confidence than a PURL.

**SPDX / CycloneDX** The two BOM standards CERT-In accepts.

**VEX** Vulnerability Exploitability eXchange — four statuses: Not affected, Affected, Fixed, Under Investigation.

**CSAF** Common Security Advisory Framework — the structured advisory published after a VEX.

**Level** BOM depth: Top-Level, n-Level, Delivery, Transitive, Complete.

**Classification** SDLC stage: Design, Source, Build, Analyzed, Deployed, Runtime.

**Alias cluster** The connected component of the vulnerability alias graph — one real vulnerability across CVE/GHSA/OSV namespaces.

**Engine** A (tool, mode) pair — `trivy-fs` and `trivy-image` are different engines.

**`completeness_pct` / `declaration_pct`** The two coverage numbers. The first counts substantive values only and is the honest compliance signal; the second counts explicit `not-provided` too and is a representation check. Both, always.

**Golden corpus** Deliberately nasty fixture repositories with hand-reviewed expected output — the guard against silently wrong normalization.
