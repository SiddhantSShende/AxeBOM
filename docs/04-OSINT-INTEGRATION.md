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

> ⚠ **`axebom toolctl pin` does not exist, and that is why almost every `image_digest` is still `null`.** Every manifest entry says the field is filled by `toolctl pin`; the CLI offers `list|dryrun|pull|sync|verify|licenses` and never had a `pin`. So the rule above has been unenforced since it was written — engines run tag-addressed, and `SandboxedAdapter.classify()` reports `ENGINE_IMAGE_NOT_PINNED` honestly rather than claiming a pin it does not have. `cdxgen` is pinned by hand (digest read from the registry at pull time, cross-checked against the local daemon's `RepoDigest`); the rest await the command.
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
| `cdxgen` | `cdxgen/cdxgen` | container only | **Second, independent inventory.** Apache-2.0. Graph trust ranks BELOW syft in every shared ecosystem — the normalizer replaces a subgraph by trust rank rather than unioning, and syft is the engine actually run against real projects |
| `grype` | `anchore/grype` | binary / image | Vulnerability matching **against the syft SBOM** |
| `trivy-fs` | `aquasecurity/trivy` | binary / image | Filesystem scan: vulns + licenses + secrets |
| `trivy-image` | `aquasecurity/trivy` | image | Container image scan — different capability, different parser |
| `osv-scanner` | `google/osv-scanner` | binary / image | OSV database cross-check |
| `dependency-check` | `dependency-check/DependencyCheck` | **container only** | NVD/CPE matching. Enterprise-recognized |
| `github-dependency-graph-sbom` | GitHub's own `dependency-graph/sbom` API | **internal** | **Reconciliation source, not discovery.** Imports a connected GitHub repository's own CI-published SPDX 2.3 document; cross-checked against every other engine's output, never authoritative on its own |
| `subfinder` | `projectdiscovery/subfinder` | **container**, network egress | Passive subdomain enumeration for a **url-registered project only**. Never a directly-scannable engine — feeds `webrecon-fingerprint` below, never ingested on its own |
| `webrecon-fingerprint` | AxeBOM's own — `services/webrecon` | **internal** | **The only SBOM engine offered for a url source.** Parses the JSON document `services/webrecon` produced: discovered hosts, fetched pages, `<script>` content, retire.js signature matches |

> **`github-dependency-graph-sbom` is an OSSF sbom-everywhere-style integration.** The fetcher calls GitHub's Dependency Graph SBOM export API once per scan — using the same repo-scoped token already in hand for the clone — and stages the response (with GitHub's `{"sbom": {...}}` envelope unwrapped) as a second raw artifact alongside the source archive (`services/fetcher/internal/work/work.go`). It runs no sandbox and no container: `workers/sbom/adapters/github_dependency_graph.py` subclasses `ToolAdapterBase` directly and does local file I/O only, reading the artifact the fetcher already staged. Failure is always soft — a non-GitHub remote, Dependency Graph disabled, or an API error all report `unavailable` with a stated reason, never a scan failure. Because the fetcher's own unwrapping leaves a genuine, standalone SPDX 2.3 document, normalization reuses `_ingest_spdx` verbatim — the same parser `syft-spdx` already exercises — rather than a bespoke, unverified parser for a format this repo has no captured fixture for.

> **`subfinder` / `webrecon-fingerprint` are a two-step discovery pipeline, but NEITHER is dispatched the way syft→grype are.** `libs/go-shared/sandbox/policy.go` states flatly that no ENGINE may have network egress — CLAUDE.md invariant 7 — so subdomain discovery and live-page fetching cannot be a normal sandboxed `scan.job.sbom` job the way trivy or grype are. Instead: `services/webrecon` (a new service, mirroring `services/fetcher`'s shape — NATS-only, no HTTP surface, holds no credential because a url source is never authenticated) consumes its own producer family, `scan.job.webrecon`, published INSTEAD of `scan.job.fetch` for a url-sourced scan. It runs `subfinder` inside its own `sandbox.Runner` container (network-egress policy, the same posture the fetcher's git clone gets), capped by `project.web_sources.max_hosts`; fetches the root page plus every discovered host (`SafeHTTPClient`, connection-time IP blocking, same as the fetcher); extracts `<script>` tags via `golang.org/x/net/html`, restricting external script fetches to the same host plus a short, explicit CDN allowlist (cdnjs, unpkg, jsdelivr, googleapis, the jQuery CDN); and matches every script's content against the retire.js signature database with a Go-native regex engine — **not** retire.js's own Node CLI, which would mean embedding a Node runtime inside a network-enabled sandboxed container, roughly doubling that container's attack surface for no benefit. The result — one JSON document, never subfinder's or retire.js's raw output directly — is staged as a `native_output` raw artifact (`producer: webrecon`, `scan.raw_artifacts`, see `01-DATA-MODEL.md` §3) and wired into `webrecon-fingerprint`'s job via `Workspace.NativeSBOMRef`, exactly the mechanism `github-dependency-graph-sbom` already uses (`policy.Engine.ConsumesNativeSBOM`). `webrecon-fingerprint`'s own adapter (`workers/sbom/adapters/webrecon_fingerprint.py`) then does the ONLY parsing step that runs in Python, mirroring `github_dependency_graph.py`'s no-sandbox, local-I/O-only shape.
>
> **Go's `regexp` (RE2) cannot execute every retire.js signature regex verbatim** — spiked against the real signature database (76 libraries, 76 `uri` + 208 `filecontent` = 284 patterns loaded; `filecontentreplace` and `hashes` are deliberately not loaded at all) before committing to this design, not assumed. Two constructs are genuinely unsupported: a backreference (`\1`/`\2`/`\3` inside a pattern — 1 of the 284) and a lookbehind (`(?<=...)` — 1 of the 284); both are skipped, counted at load. A third issue is fixable rather than fundamental: RE2's hardcoded 1000-repeat-count cap rejects 7 patterns using bounds like `{0,8000}` (Vue ×2, Next.js ×2, lodash, tinyMCE, underscore.js, select2) — these are capped at 1000 rather than dropped, a real but honestly-documented precision loss (a real gap between two anchors in a minified bundle can exceed 1000 characters), and every affected library still has other, unaffected filecontent signatures. Full counts and per-pattern reasoning: `services/webrecon/internal/fingerprint/signatures/PROVENANCE.md`; the regression guard is `services/webrecon/internal/fingerprint/retire_test.go`.
>
> **`max_hosts` and the CDN allowlist are abuse guards, not incidental config.** A url-registered project auto-discovers and fetches from hosts the tenant never individually named — a confused-deputy/recon-abuse surface distinct from SSRF against AxeBOM's own infrastructure, not just a variant of it. See `05-SECURITY-MODEL.md` §1 and §3/§4 for the full threat-model treatment.

> **`syft-spdx` exists in the worker and is deliberately NOT in the dispatch registry.**
>
> `workers/sbom/adapters/syft.py` defines a second adapter that re-runs syft with `-o spdx-json`, it has a parser in `ingest._PARSERS`, and it has fixtures. It is absent from `policy.DefaultRegistry()`, so the orchestrator never fans out a job for it — which looked like an oversight and is now a decision.
>
> The reason to add it would be CERT-In's Automation Support element, which names SPDX **and** CycloneDX. But AxeBOM already emits both, from its own canonical model, through `services/report/internal/export` — it does not need a scanner to hand it an SPDX document. So `syft-spdx`'s only value is as a second reconciliation source for the *same tool's* view of the *same tree*, and the cost is doubling every SBOM scan's syft runtime.
>
> Two independent inventories are worth paying for — that is why `cdxgen` was added. Two runs of one tool are not. The adapter stays because re-parsing a stored SPDX artifact is still how a golden is replayed; the dispatch entry stays absent.

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

| engine_id | Mode | Source kinds | Role |
|---|---|---|---|
| `hbom-ecad` | internal | `git`, `upload` | Parses the customer's own hardware **design files** — KiCad `.kicad_sch`, KiCad netlist XML, and BOM exports from KiCad/Altium/OrCAD |
| `hbom-cdxgen-host` | internal | `upload` | Ingests a CycloneDX 1.7 **host inventory the customer generated themselves** with `cdxgen -t hbom` |
| `hbom-host-report` | internal | `upload` | The same import, widened to the tools people actually have: **`axebom collect hardware`**, `lshw --json`, `dmidecode`, `fwupdmgr get-devices --json`, PowerShell's CIM cmdlets, a Redfish service's JSON |
| `hbom-csv` | internal | *(none)* | The interactive REST import path, `POST /v1/hbom/{projectId}/import`. Not a scan job |
| `hbom-form` | internal | *(manual)* | Structured manual entry, recursive subcomponents. Not in the Go registry |

> **The honest label moved, and it is worth being precise about how far.**
>
> This section used to say flatly that no HBOM scanner exists. That was right while every HBOM document came from a CSV or a form. `hbom-ecad` changed it: parsing a KiCad schematic the customer committed is a real scan of a document they wrote — the same act as reading a committed lockfile for an SBOM, and it produces real jobs on `scan.job.hbom`.
>
> **What has not changed is the claim that would still be false: nothing here inspects PHYSICAL HARDWARE.** No open-source tool looks at a device and enumerates its parts. A schematic is a drawing of an intent; a cdxgen document is a report the customer's own machine produced. Neither is AxeBOM having examined hardware, and no UI string may say otherwise. `workers/hbom/test_hbom.py`'s discovery-claim guard enforces exactly that line — it stopped forbidding "HBOM scan" (now true) and started catching "scans your hardware", "inspects the device" and "discovers hardware" (still false).

> **`hbom-csv` declares no source kind, and that is load-bearing.** `policy.Registry.Resolve` filters candidates on `Supports(kind)` alone — it does not consult `RequiresImport` — so the moment `hbom-ecad` made the family scannable, a declared `upload` would have published `scan.job.hbom` for an engine no worker implements, leaving a permanent `skipped`/`ENGINE_NOT_IMPLEMENTED` row in the Engine Coverage section of every HBOM scan. Filtering `RequiresImport` inside `Resolve` was **not** the fix: `github-dependency-graph-sbom` carries that same flag and is dispatched on every git SBOM scan. `RequiresImport` is an honest label about where data came from; an empty `SourceKinds` is the statement about dispatch.
>
> The consequence to watch: `Resolve` records the skipped engine against the `hardware` ecosystem as *unavailable*, and `Store.CoverageGaps` only neutralises that when a matching *available* row exists. **`hbom-ecad` must therefore report `ecosystems_covered=["hardware"]` on success** — without it, every HBOM report grows a false "ecosystem `hardware` had no available engine" line, which is invariant 12 inverted.

**`hbom-ecad` groups placements into line items.** R1, R4 and R17 of the same 10 kΩ resistor are one row with quantity 3 and all three designators — because that is what gets ordered and what gets placed. Emitting three components would inflate the component count in a compliance document and produce a BOM nobody can order from. Grouping is by MPN where one exists, otherwise by **value *and* footprint together**, never value alone: a 10 kΩ 0402 and a 10 kΩ 0805 are different parts that cannot substitute.

**`hbom-host-report` is one engine with six parsers, and that is deliberate.** `policy.Registry.Resolve` fans out one job per engine, so six engines over one upload would leave five `unavailable` rows in the Engine Coverage section of a customer who ran one tool — reading as five broken things rather than one working one. `hbom-ecad` already dispatches internally to its KiCad and BOM-table parsers for the same reason. Selection is by **content, never filename**: an upload holding an lshw dump beside a dmidecode one is exactly what somebody documenting a server produces. Which parser matched is recorded as a diagnostic and on every row's `source_engine`.

> ⚠ **`lshw`, `dmidecode` and `fwupd` are GPL, and that is not a problem here.** Nothing invokes, links against or ships any of them — the **customer** runs one on their own machine and uploads the text. Reading a tool's output carries no licence obligation, for the same reason a CSV exported from Altium is not an Altium derivative work. Recorded as data in the manifest's `reads_output_of`, and printed by `task osint:licenses` under "Output PARSED from tools AxeBOM never runs, links against or ships" — so a legal reviewer sees the boundary stated instead of inferring it from silence. `CLAUDE.md` invariant 9 governs the case that *would* matter: importing their code into our binary.

**`axebom collect hardware` is ours, and it runs on the customer's machine.** A single static binary that reads what the kernel already publishes — `/sys/class/dmi/id`, `/proc/cpuinfo`, `/sys/block/*/device`, `/sys/class/net/*/device` — and writes an uploadable BOM. It exists because `lshw` and `dmidecode` may simply not be installed, and asking somebody to install a package on a production appliance in order to document it is a real barrier.

> ⚠ **It opens no network connection and runs no other program**, and both claims are asserted by a test over its import set (`TestTheCollectorOpensNoNetwork`) rather than left to a code comment. `os/exec` is forbidden there too: shelling out to `lshw` would make this a GPL *invocation* rather than a file read.
>
> ⚠ **It names what it could not read rather than leaving a blank.** SMBIOS serial numbers are root-readable only. `lshw` and `dmidecode` simply omit them when unprivileged, so a reader sees an empty field and concludes the machine has no serial — "nobody had permission to look" is fixed by re-running with `sudo`, and "there is no serial" is not. The two must not render the same, so the document carries an `unreadable` list and the parser turns it into a diagnostic.
>
> ⚠ **Firmware placeholders are rejected on both sides.** `Default string`, `To Be Filled By O.E.M.` and `System Serial Number` are what a board says when the manufacturer left the field blank, and they are burned into millions of units. Recorded as a serial, every one of those boards would collide on the uniqueness `project.hardware_devices` exists to enforce.
>
> It prints the file list before opening anything, and writes the output `0600` — the file can contain values that required privilege to read.

**`hbom-cdxgen-host` is an import, never an invocation.** `cdxgen -t hbom` inventories *the host it runs on*. Executed inside our sandbox it would document AxeBOM's own container host and present it as the customer's hardware, so it is never run here — the customer runs it on the device they want documented and uploads the result, and the raw artifact is their file byte for byte.

Part enrichment sits behind a `PartDataProvider` interface: `nexar` (Octopart's current API, Altium), `mouser`, `manual`. **`manual` is the default**, so no paid quota-limited API is ever a hard dependency.

> ⚠ **Nexar's free tier is a 100-matched-part *lifetime* cap, not a monthly quota** — verified 2026-09. It does not reset, so free-tier Nexar cannot enrich even one real assembly BOM twice. Paid self-serve tiers reset monthly (Standard 2,000, Pro 15,000). This is why `manual` is the default rather than a fallback.

**Hardware vulnerability matching (CERT-In element 24) is a lookup, not an engine.** `workers/hbom/vulnmatch.py` builds CPE candidates from a component's manufacturer and part number (`cpe.py`) and searches NVD's CVE API 2.0. It runs in the normalize consumer, never in the sandbox, and dispatches no container — there is nothing to execute.

> ⚠ **Every match is a string comparison between two vocabularies nobody reconciled**, so each finding stores the CPE it was searched with, the basis it matched on, and a confidence that is never above `medium`. A component's `vuln_match_status` records which of four things happened — `matched`, `no-match`, `no-cpe`, `not-attempted` — because an empty findings list cannot otherwise be told from a search that never ran. **`NVD_API_KEY` is required and set in no environment today**, so the shipping state is `not-attempted` everywhere, reported in words. `configured()` returning False when the key is absent follows the `nexar`/`mouser` rule above: an unconfigured provider is skipped cleanly, never called with an empty credential.
>
> A key is required rather than optional even though NVD serves anonymous traffic: keyless access is 5 requests per 30 seconds shared across the egress IP, so one 200-line parts list would take twenty minutes and rate-limit every other tenant scanning at the same time. See `docs/LIMITATIONS.md`.

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

# --- WEB RECON --------------------------------------------------------------
# subfinder runs INSIDE services/webrecon's own sandboxed container
# (network-egress policy) — passive sources only, never active probing.
subfinder -d example.com -silent -json -max-time 60

# The JS-fingerprint step is services/webrecon's own Go code, not a CLI —
# SafeHTTPClient GET of each discovered host's root page, <script> extraction,
# then match against the vendored retire.js signature database
# (services/webrecon/internal/fingerprint/signatures/retire-js-jsrepository.json).
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

**`webrecon-fingerprint` is the one exception to "parse the standard document"** — `services/webrecon` produces AxeBOM's own JSON shape (`{root_url, hosts: [{host, fetched_url, status, libraries: [{name, version, npm_purl, vulnerabilities}], scripts: [{src, skipped, matched}]}]}`), not a CycloneDX or SPDX document, because there is no such thing as a "native" format for a retire.js-style fingerprint result. `scripts` is diagnostic only — never read by the adapter below, which ignores unknown fields — recording every `<script src>` and `<link rel="modulepreload">` the host's page named, whether it was fetched or skipped (off-origin, not CDN-allowlisted), and whether it matched a signature, so a zero-library host is distinguishable as "nothing detectable" versus "everything was skipped" from the stored artifact alone. `workers/sbom/adapters/webrecon_fingerprint.py` does the real parsing this one time — a matched library becomes a component (`purl` synthesized as `pkg:npm/<name>@<version>`, honest because virtually every JS library retire.js signatures cover is npm-published, though this is inference, not a certainty the tool asserts), `Location.path` records the host + script URL it was found at, and a retire.js `vulnerabilities[]` entry whose version range matches becomes a `RawFinding` with the CVE/GHSA identifiers retire.js itself carries.

`extractScripts` (`services/webrecon/internal/fingerprint/fetch.go`) walks both `<script>` and `<link rel="modulepreload">` elements — the latter matters because a Vite/Rollup-bundled SPA typically has exactly one tiny `<script src>` (its module entry chunk) and references every real dependency bundle only via `<link rel="modulepreload" href="...">`, standard static, unexecuted HTML markup. Missing it is a real detection gap, not the headless-browser-rendering case this document's honest labels disclaim elsewhere.

### Crypto assets (CERT-In Table 9)

CycloneDX `cryptoProperties` maps almost directly: `oid`, `assetType`, `algorithmProperties.{primitive,mode,cryptoFunctions,classicalSecurityLevel}`, key `{state,size}`, protocol `{version,cipherSuites}`, certificate `{subjectName,issuerName,notValidBefore,notValidAfter,signatureAlgorithmRef,subjectPublicKeyRef,certificateFormat,certificateExtension}`.

> Remember the discriminator: `assetType` selects **which field set applies**, and coverage is scored against that set only. See `03-NORMALIZER-SPEC.md §5.3`.

`quantum_vulnerable` is AxeBOM's derivation, not a tool output: true for RSA, ECC/ECDSA/ECDH, DH, DSA (Shor-vulnerable). Symmetric primitives get a Grover note on effective key strength, not a vulnerability flag.

### AI models (CERT-In Table 10)

CycloneDX ML-BOM `modelCard`, `component.properties`, and `data` components; plus Trusera risk properties (`risk_score`, OWASP LLM Top-10) which are **AxeBOM extensions excluded from coverage scoring**.

### Hardware (CERT-In Table 11 + §10.4.1.4)

CSV/form fields plus optional `PartDataProvider` enrichment (manufacturer, MPN, lifecycle, compliance attributes). Recursion via `parent_id`, depth-capped at 10 with a diagnostic. Element 24's vulnerabilities come from the advisory NVD lookup above, stored in `normalize.hardware_findings` — **never merged into the software finding counts**, which are exact where these are inferred.

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
