# 04 — OSINT Integration

> **⚑ SSOT for scanner engines.** What each tool actually is, how it is acquired, how it is invoked, what it emits, how that maps to canonical, and where it fails.

**Related:** `OSINT/tools.manifest.yaml` is the machine-readable pin (versions, digests, checksums). `02-CONTRACTS.md §7` defines the engine registry shape. `03-NORMALIZER-SPEC.md` defines what happens to the output. `05-SECURITY-MODEL.md` defines the sandbox they run in.

---

## 1. Acquisition: pinned artifacts, never source builds

### The rule

**Download pinned release binaries and pinned container images, verified by checksum and signature. Do not `git clone` and build.** Source is cloned only where no binary distribution exists, and only into gitignored `OSINT/src/` for reference.

`axebom toolctl sync` — a Go subcommand, cross-platform, no bash — reads `OSINT/tools.manifest.yaml` and populates gitignored `.axebom/tools/<id>/<version>/`, verifying SHA256 and cosign signatures where upstream publishes them.

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
| `ai-bom` | `Trusera/ai-bom` | **container (built locally)** | **Code-level AI discovery** — LLM providers, agent frameworks (LangChain, CrewAI, AutoGen, LlamaIndex, LangGraph), MCP servers, model references, AI containers |
| `aibom-generator` | `GenAI-Security-Project/aibom-generator` | pip / service | **Model-metadata AIBOM** from Hugging Face — model card, config, license, completeness score |

> **`ai-bom` runs in the scan sandbox, over untrusted customer code** — its adapter (`workers/aibom/adapters/ai_bom.py`) subclasses `SandboxedAdapter`, exactly like syft or cbomkit-theia, per `CLAUDE.md` invariant 7. Upstream publishes it only as a pip package (`pip install ai-bom==3.1.0`), which gives `ManifestResolver` nothing to build a sandboxed container invocation from — so `deploy/docker/engines/Dockerfile.ai-bom` wraps that package into a container built **locally** (`task osint:build-ai-bom`, folded into `task osint:pull`), tagged `axebom/ai-bom-engine:dev`. There is no upstream image, so there is no upstream digest to pin against: `OSINT/tools.manifest.yaml` pins it by tag only (`image_tag: dev`), and `SandboxedAdapter.classify()` reports that honestly as `ENGINE_IMAGE_DIGEST_UNKNOWN` in Engine Coverage rather than claiming a digest pin it does not have. The full pip dependency closure (23 packages) is hash-pinned in `deploy/docker/engines/ai-bom-requirements.lock.txt`.
>
> `aibom-generator` (below) is the OTHER pip-based AIBOM engine, and it stays `pip` mode deliberately: it makes an outbound call to the Hugging Face API over a model id, not over customer code, so it runs **outside** the sandbox as a trusted dependency of the AIBOM worker's own Python environment — see `workers/aibom/adapters/aibom_generator.py` and `workers/aibom/adapters/aibom_generator_fetch.py`. The two engines' upstream distribution shape looks identical (both are "just a pip package") but what they run *against* is what decides whether they need the sandbox at all.

Both emit CycloneDX 1.6, so merging is clean.

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
| **Dependency-Track** | A full platform with its own database, API and UI that duplicates a large part of AxeBOM. Integrated as an optional **export target** for portfolio monitoring — never as a scanner. Compose profile `heavy`; **4 GB heap minimum, docs recommend 8–12 GB.** Off by default. |
| **django-bom / IndaBOM** | **Django applications, not libraries** — cannot be embedded. And `django-bom` is **GPL-3.0**: importing it would make our worker a GPL derivative. **Schema reference only, never imported.** See `CLAUDE.md` invariant 9. |
| **StockFlow** | Hosted SaaS, no public source. Integrated as a **CSV import shape**. |
| **Octopart / Nexar** | Hosted commercial API requiring registration and paid quota. Optional enrichment, never required. |

---

## 2a. Provisioned vulnerability databases

**A vulnerability engine runs only against a database we provisioned and stamped. No stamp, no run.**

This is enforced in `SandboxedAdapter.generate` *before the container starts*, not inferred from the output afterwards. The reason is that the failure it prevents is invisible in the output:

> osv-scanner with `--offline-vulnerabilities` and no cached database parses every lockfile, finds every package, matches against nothing, prints `{"results": []}` and **exits 0**.

Nothing in the exit code, stderr or output shape distinguishes that from a genuinely clean project. Once such a result exists there is no correct way to classify it, so the run is refused instead. grype and trivy happen to fail loudly today, but that is their choice, not a guarantee, and it has changed between releases — so the rule does not depend on any engine's behaviour.

An engine with no provisioned database is **`unavailable` + `ENGINE_DB_STALE` + `ENGINE_DB_NOT_PROVISIONED`**, which lands in Engine Coverage as a stated gap rather than in the findings list as a false all-clear.

| Database | Engine | Pointed at by | Notes |
|---|---|---|---|
| `osv` | osv-scanner | `XDG_CACHE_HOME` | No `--db-path` flag exists; it reads the OS cache dir. **One archive per ecosystem**, fetched lazily, so warming requires a tree containing every supported ecosystem |
| `grype` | grype | `GRYPE_DB_CACHE_DIR` | Also `GRYPE_DB_AUTO_UPDATE=false` and `GRYPE_DB_VALIDATE_AGE=false` — *we* decide what counts as stale, from the stamp |
| `trivy` | trivy-fs, trivy-image | `--cache-dir` | Previously pointed at the empty tmpfs, so trivy started with no database on every run |

Provisioning is `python -m workers.sbom.dbsync <id>`. It is **the one place that runs an engine image with a network**, and it differs from a scan in the two ways that make that acceptable: no user repository is mounted, and it is invoked by an operator rather than by a scan. It is not a weakened sandbox; it is a different operation on different data.

The stamp (`axebom-db.json`) is written by the provisioner **only after a successful download that produced bytes**, and carries the vintage that becomes `engine_db_version`. A directory with database files but no stamp is treated as absent — that is what a half-finished download leaves behind, and its vintage cannot be stated.

> ⚠ **`engine_db_version` comes from our stamp, never from the engine's self-report.** An earlier osv-scanner adapter derived it from the *image* version and described a database "bundled in the image". That image is a single 57 MB binary and bundles no database at all. The fabricated string made the `requires_db_version` check pass for an engine that had nothing to match against — the check certifying the exact condition it existed to catch.

**Exit codes are per-engine.** osv-scanner exits `1` when it *finds vulnerabilities*. Treating that as failure inverts the product: every scan that found something would be `failed`, so the only scans reported as succeeding would be the ones that found nothing. See `acceptable_exit_codes()`.

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
# NOT `-o aibom.cdx.json`. ai-bom==3.1.0's `--output` is a real file path with
# no "-" -> stdout special case (`Path(path).write_text(...)`, verbatim) — the
# sandbox has no writable host mount, so a file written inside the container is
# unreachable. Omit `--output`: for any non-`table` format ai-bom prints the
# rendered report straight to stdout, which is the one channel that exists.
ai-bom scan <path> --format cyclonedx --quiet
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

`quantum_vulnerable` is AxeBOM's derivation, not a tool output: true for RSA, ECC/ECDSA/ECDH, DH, DSA (Shor-vulnerable). Symmetric primitives get a Grover note on effective key strength, not a vulnerability flag.

### AI models (CERT-In Table 10)

CycloneDX ML-BOM `modelCard`, `component.properties`, and `data` components; plus Trusera risk properties (`risk_score`, OWASP LLM Top-10) which are **AxeBOM extensions excluded from coverage scoring**.

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
| **A vulnerability engine with no database reports a clean project, exit 0** | Refused before the container starts — see §2a. This is the only failure here that makes a customer *less* safe than having no scanner |
| **`osv-scanner` exits 1 when it finds vulnerabilities** | `acceptable_exit_codes()` per engine. Otherwise the only "successful" scans are the ones that found nothing |
| **A quiet flag hides the reason a run failed** | grype's `-q` suppressed the stderr naming a missing database, making it indistinguishable from a crash. Never suppress engine diagnostics to tidy output |
| **`osv-scanner` visits one directory without `-r`** | On a monorepo it scans the root, finds nothing, exits 0 — a clean report for a repository that was not scanned |
| **An engine needs scratch space, and the sandbox rootfs is read-only** | Point `TMPDIR` at the workspace tmpfs via `extra_env()`. trivy fails every run without it: *"unable to create temporary directory: read-only file system"* — an error naming neither trivy's needs nor the sandbox policy |

### Defensive parsing, always

Adapters **ignore unknown fields**, emit a diagnostic on missing expected fields, and **never panic**. A tool that changes its output shape should degrade to reduced coverage, loudly — not crash a worker or, worse, silently produce an empty inventory that renders as a clean report.

### Nightly contract tests

`task osint:contract` runs each pinned tool against a tiny fixture and asserts the parser still produces expected canonical output. This runs nightly in CI, not just on PRs, because upstream moves on its own schedule.

**A failing contract test auto-marks that engine `unavailable`** rather than letting it feed garbage into a compliance report. That is the fail-safe direction: reduced coverage, visibly, beats confident wrongness.

---

## 6. Licensing

AxeBOM **invokes** these tools as subprocesses and services. It does not fork, embed, or relicense them. Every tool's license is recorded in `OSINT/tools.manifest.yaml` and tracked in AxeBOM's own SBOM — a BOM platform that cannot produce its own BOM is not credible.

**Copyleft rule:** GPL/AGPL code runs as a **subprocess or separate service**, or not at all. It is never imported, linked, or vendored into an AxeBOM binary. `django-bom` (GPL-3.0) is the concrete case: schema reference only.

Before adding any dependency or engine, check its license and record it in the manifest. This check is part of the phase handoff checklist, not an afterthought.
