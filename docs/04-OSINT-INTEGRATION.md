# 04 — OSINT Integration

> **⚑ SSOT for scanner engines.** What each tool actually is, how it is acquired, how it is invoked, what it emits, how that maps to canonical, and where it fails.

**Related:** `OSINT/tools.manifest.yaml` is the machine-readable pin (versions, digests, checksums). `02-CONTRACTS.md §7` defines the engine registry shape. `03-NORMALIZER-SPEC.md` defines what happens to the output. `05-SECURITY-MODEL.md` defines the sandbox they run in.

---

## 1. Acquisition: pinned artifacts, never source builds

### The rule

**Download pinned release binaries and pinned container images, verified by checksum and signature. Do not `git clone` and build.** Source is cloned only where no binary distribution exists, and only into gitignored `OSINT/src/` for reference.

`encorebom toolctl sync` — a Go subcommand, cross-platform, no bash — reads `OSINT/tools.manifest.yaml` and populates gitignored `.encorebom/tools/<id>/<version>/`, verifying SHA256 and cosign signatures where upstream publishes them.

### Why not build from source

This is worth stating plainly because the instinct to vendor and build is strong and, here, wrong.

1. **Version metadata is injected by the release process.** `go build ./cmd/syft` yields a binary reporting version `unknown`, because syft and grype inject version via goreleaser `ldflags`. For grype this can break vulnerability-DB schema-compatibility checks outright.

2. **For a compliance product, provenance *is* the product.** You must be able to assert "this SBOM was produced by syft v1.19.1 against grype-db vintage 2026-08-15." A local source build off `main` cannot make that assertion credibly, and the assertion is the thing a customer is paying for.

3. **Heterogeneous toolchains.** Trivy builds via mage. Dependency-Check is Java/Maven. cbomkit is Java 17. On the primary dev machine — **Java 1.8** — several of these simply cannot build. Container-only for Java tools defuses this permanently.

4. **Nested git.** Cloning a dozen repositories into the working tree creates nested-repo ambiguity and an unclonable monorepo.

### Supply-chain verification is mandatory

**Trivy's distribution channel was compromised twice in a coordinated attack in March 2026.** Treat every scanner artifact as untrusted until verified:

- Pin container images **by digest**, never by tag. A tag is mutable.
- Verify SHA256 against the upstream checksum file for every binary.
- Verify cosign signatures where published.
- If `cosign` is absent, verification degrades to checksum-only **with a loud warning** — never silently. The warning appears in `toolctl sync` output and in `provenance_manifest`.

### Runtime resolution

**container → local binary → `unavailable`.**

A missing or unverifiable engine marks itself `unavailable`, is recorded in `scan.engine_runs`, and appears in the report's Engine Coverage section. It **never fails the whole scan**. Losing one engine should cost you that engine's coverage, visibly — not the entire scan.

---

## 2. Engine roster

The unit is **(tool, mode)**, not tool — see `02-CONTRACTS.md §7`.

### SBOM

| engine_id | Upstream | Mode | Role |
|---|---|---|---|
| `syft` | `anchore/syft` | binary / image | **Primary SBOM generator.** Emits CycloneDX and SPDX natively |
| `grype` | `anchore/grype` | binary / image | Vulnerability matching **against the syft SBOM** |
| `trivy-fs` | `aquasecurity/trivy` | binary / image | Filesystem scan: vulns + licenses + secrets |
| `trivy-image` | `aquasecurity/trivy` | image | Container image scan — different capability, different parser |
| `osv-scanner` | `google/osv-scanner` | binary / image | OSV database cross-check |
| `dependency-check` | `dependency-check/DependencyCheck` | **container only** | NVD/CPE matching. Enterprise-recognized |

### CBOM / QBOM

| engine_id | Upstream | Mode | Role |
|---|---|---|---|
| `cbomkit-theia` | **`cbomkit/cbomkit-theia`** | **container only** | **Primary CBOM discovery** — directories and container images; certs, keys, secrets, `java.security` |
| `cbomkit` | **`cbomkit/cbomkit`** | service, optional | Managed clone-and-scan with a viewer |
| `sonar-cryptography` | **`cbomkit/sonar-cryptography`** | **deferred** | Deepest Java/Python source crypto inventory — but see below |

> **CORRECTION (Phase 2, verified against the network).** An earlier planning note claimed these lived under `PQCA/` following the Post-Quantum Cryptography Alliance donation. They do not. `github.com/PQCA/*` returns **HTTP 301** and redirects to `github.com/cbomkit/*`, and `ghcr.io/cbomkit/cbomkit-theia` resolves while `ghcr.io/pqca/cbomkit-theia` 404s. The canonical org is **`cbomkit`**, which is what the original draft plan said.
>
> **`cbomkit-theia` ships NO binary assets** — v1.1.2 is a source-only release. The container is the only distributed artifact, so container mode is not a preference for this engine, it is the only option.

> **`sonar-cryptography` is a SonarQube plugin, not a CLI.** It requires a running SonarQube server — a hidden platform dependency that adds a heavyweight Java service to the stack. Deferred past MVP. `cbomkit-theia` covers directory and image discovery without it.

### AIBOM

| engine_id | Upstream | Mode | Role |
|---|---|---|---|
| `ai-bom` | `Trusera/ai-bom` | pip package | **Code-level AI discovery** — LLM providers, agent frameworks (LangChain, CrewAI, AutoGen, LlamaIndex, LangGraph), MCP servers, model references, AI containers |
| `aibom-generator` | `GenAI-Security-Project/aibom-generator` | pip / service | **Model-metadata AIBOM** from Hugging Face — model card, config, license, completeness score |

`ai-bom` is `pip install ai-bom` — no clone needed. Both emit CycloneDX 1.6, so merging is clean.

`--llm-enrich` on `ai-bom` resolves concrete model names but requires an LLM key **and sends code context to a third party**. Off by default; enabling it is a per-project decision surfaced in the UI.

### HBOM

| engine_id | Mode | Role |
|---|---|---|
| `hbom-csv` | internal | CSV/spreadsheet import (StockFlow-shaped or generic) |
| `hbom-form` | internal | Structured manual entry, recursive subcomponents |

Part enrichment sits behind a `PartDataProvider` interface: `nexar` (Octopart's current API, Altium), `mouser`, `manual`. **`manual` is the default**, so no paid quota-limited API is ever a hard dependency.

### Libraries, not engines

| Tool | Where it belongs |
|---|---|
| `protobom/protobom` | **Report phase.** An OpenSSF **Go library** for format-neutral BOM representation — this is the SPDX↔CycloneDX serialization layer, not an AIBOM generator |
| `bomctl/bomctl` | Optional CLI utility for merge/convert. Not a generator |

### Not engines at all

| Tool | Verdict |
|---|---|
| **Dependency-Track** | A full platform with its own database, API and UI that duplicates a large part of EncoreBOM. Integrated as an optional **export target** for portfolio monitoring — never as a scanner. Compose profile `heavy`; **4 GB heap minimum, docs recommend 8–12 GB.** Off by default. |
| **django-bom / IndaBOM** | **Django applications, not libraries** — cannot be embedded. And `django-bom` is **GPL-3.0**: importing it would make our worker a GPL derivative. **Schema reference only, never imported.** See `CLAUDE.md` invariant 9. |
| **StockFlow** | Hosted SaaS, no public source. Integrated as a **CSV import shape**. |
| **Octopart / Nexar** | Hosted commercial API requiring registration and paid quota. Optional enrichment, never required. |

---

## 3. Invocations

Representative commands. Exact argv is owned by each adapter and recorded, redacted, in `ScanResultV1.invocation.argv_redacted`.

```bash
# --- SBOM -----------------------------------------------------------------
syft <dir> -o cyclonedx-json=sbom.cdx.json -o spdx-json=sbom.spdx.json

grype sbom:sbom.cdx.json -o json                    # match against OUR sbom, not a re-scan

trivy fs --scanners vuln,license,secret \
         --format cyclonedx --output trivy.cdx.json <dir>
trivy image --format cyclonedx --output trivy.cdx.json <image@digest>

osv-scanner scan source --format json --output osv.json <dir>

# container-only; Java 11+ required, which the dev machine does not have locally
docker run --rm -v deps-data:/usr/share/dependency-check/data \
  owasp/dependency-check@sha256:… \
  --scan /src --format JSON --format SARIF --nvdApiKey "$NVD_API_KEY"

# --- CBOM -----------------------------------------------------------------
cbomkit-theia dir <path>          # → CycloneDX 1.6 with cryptoProperties
cbomkit-theia image <image@digest>

# --- AIBOM ----------------------------------------------------------------
ai-bom scan <path> --format cyclonedx -o aibom.cdx.json
python -m src.cli <hf-model-id> --output model.cdx.json
```

Two notes that matter:

- **`grype` runs against the syft SBOM, not the directory.** Re-scanning would produce a second, subtly different component inventory to reconcile — and reconciling two inventories is exactly the work the normalizer exists to avoid.
- **`dependency-check` needs a persistent data volume and an NVD API key.** The first database sync takes 30–60 minutes; without a key it is heavily throttled. Pre-warm the volume in CI and in the compose stack.

---

## 4. Output → canonical mapping

Where a tool emits CycloneDX or SPDX natively, **parse the standard document**. Screen-scraping tool-specific output is fragile and breaks on every upstream release.

### SBOM components (CERT-In §4.2 — see `reference/certin-v2.0.yaml`)

| Canonical | Source |
|---|---|
| `name` / `version_raw` / `description` | CycloneDX `components[].name/version/description` |
| `supplier` | CycloneDX `supplier`, `publisher`, or package namespace |
| `license_declared` | CycloneDX `licenses[]` |
| `license_concluded` | trivy license scan, SPDX `licenseConcluded` |
| `purl` | CycloneDX `purl`, **canonicalized per `03-NORMALIZER-SPEC.md §1.1`** |
| `certin_identifier` | **derived** — never taken from a tool |
| `hashes` | CycloneDX `hashes[]` |
| `dependencies` | CycloneDX `dependencies[]` — **replaced per ecosystem by trust order, not unioned** |
| findings | grype + osv-scanner + trivy + dependency-check, **merged by alias cluster** |
| `patch_status` | derived from `fixed_versions` vs `version_raw`, ecosystem comparator |
| `executable` / `archive` / `structured` | heuristics + CycloneDX component `type` |
| `author_of_sbom_data` / timestamp | scan provenance |
| everything else | explicit `not-provided` — **never silently omitted** |

### Crypto assets (CERT-In Table 9)

CycloneDX `cryptoProperties` maps almost directly: `oid`, `assetType`, `algorithmProperties.{primitive,mode,cryptoFunctions,classicalSecurityLevel}`, key `{state,size}`, protocol `{version,cipherSuites}`, certificate `{subjectName,issuerName,notValidBefore,notValidAfter,signatureAlgorithmRef,subjectPublicKeyRef,certificateFormat,certificateExtension}`.

> Remember the discriminator: `assetType` selects **which field set applies**, and coverage is scored against that set only. See `03-NORMALIZER-SPEC.md §5.3`.

`quantum_vulnerable` is EncoreBOM's derivation, not a tool output: true for RSA, ECC/ECDSA/ECDH, DH, DSA (Shor-vulnerable). Symmetric primitives get a Grover note on effective key strength, not a vulnerability flag.

### AI models (CERT-In Table 10)

CycloneDX ML-BOM `modelCard`, `component.properties`, and `data` components; plus Trusera risk properties (`risk_score`, OWASP LLM Top-10) which are **EncoreBOM extensions excluded from coverage scoring**.

### Hardware (CERT-In Table 11 + §10.4.1.4)

CSV/form fields plus optional `PartDataProvider` enrichment (manufacturer, MPN, lifecycle, compliance attributes). Recursion via `parent_id`, depth-capped at 10 with a diagnostic.

---

## 5. Known failure modes

Each of these has bitten real deployments. Adapters must handle them without emitting garbage into a compliance report.

| Failure | Handling |
|---|---|
| **grype/trivy DB schema version** outgrows a pinned binary | `ENGINE_DB_STALE` diagnostic; mark `unavailable` rather than emit stale matches |
| **osv-scanner CLI changed across majors** (`scan` subcommand, output shape) | Pin exactly; nightly contract test catches drift |
| **dependency-check first-run sync** takes 30–60 min | Pre-warmed volume; `ENGINE_TIMEOUT` if cold and over deadline |
| **dependency-check LOW-confidence CPEs** | Attach as candidate identity — **never merge** into a PURL component |
| **cbomkit output schema is early and moving** | Defensive parser; unknown fields ignored, missing fields → diagnostic |
| **trivy fs vs image differ** in scanners and parsers | Modelled as two engines |
| **syft reports Go modules, trivy sometimes packages** | Reconcile on module path only |
| **Engine finds zero components** | `partial` + diagnostic; not `succeeded`. Zero is a claim, and it needs to be an explicit one |

### Defensive parsing, always

Adapters **ignore unknown fields**, emit a diagnostic on missing expected fields, and **never panic**. A tool that changes its output shape should degrade to reduced coverage, loudly — not crash a worker or, worse, silently produce an empty inventory that renders as a clean report.

### Nightly contract tests

`task osint:contract` runs each pinned tool against a tiny fixture and asserts the parser still produces expected canonical output. This runs nightly in CI, not just on PRs, because upstream moves on its own schedule.

**A failing contract test auto-marks that engine `unavailable`** rather than letting it feed garbage into a compliance report. That is the fail-safe direction: reduced coverage, visibly, beats confident wrongness.

---

## 6. Licensing

EncoreBOM **invokes** these tools as subprocesses and services. It does not fork, embed, or relicense them. Every tool's license is recorded in `OSINT/tools.manifest.yaml` and tracked in EncoreBOM's own SBOM — a BOM platform that cannot produce its own BOM is not credible.

**Copyleft rule:** GPL/AGPL code runs as a **subprocess or separate service**, or not at all. It is never imported, linked, or vendored into an EncoreBOM binary. `django-bom` (GPL-3.0) is the concrete case: schema reference only.

Before adding any dependency or engine, check its license and record it in the manifest. This check is part of the phase handoff checklist, not an afterthought.
