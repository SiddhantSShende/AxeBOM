# What AxeBOM does not do

Phase 16 asks for this list, and calls it a feature. It is: the alternative is
discovering these together during an incident, or — worse — an audit.

Everything here is a deliberate boundary or a known gap. Nothing here is a
roadmap promise. Where something is planned, it says so and says what it depends
on.

---

## It never says you are compliant

AxeBOM reports **violations against a configured policy**. The word
"compliant" does not appear in generated output, and `task profile:guardrails`
fails the build if it ever does.

That is not modesty. Compliance is a determination an auditor makes about an
**organisation**, considering process, evidence and intent. A tool sees a
repository at one moment. If a report said "compliant", a customer would quote
it — in good faith — to somebody who would then hold them to it.

What the product does give you: two coverage numbers, a per-element table citing
the page of the guideline that requires each one, and an explicit statement of
what it could not see.

## Coverage numbers are about *declaration*, not correctness

`completeness_pct` counts elements with a substantive value. It does not, and
cannot, check that the value is **true**.

A component whose supplier field says "Acme Corp" scores the same whether or not
Acme wrote it. The BOM is an inventory, not an attestation. Where a value came
from a third-party parts database rather than from you, the report says so; that
is the closest thing to provenance the data supports.

## Nothing looks at your hardware

⚠ **This section used to say "HBOM is a structured CSV import plus a form", and that is no longer the whole picture — but the boundary it drew has not moved.**

A hardware BOM now reaches AxeBOM three ways, and every one of them is a document the customer produced:

- **their own design files** — KiCad schematics and netlists, BOM exports from KiCad, Altium and OrCAD, parsed out of an upload or a connected repository. This is a real scan, in exactly the sense that reading a committed lockfile is;
- **a host inventory their own machine reported** — `axebom collect hardware` (ours, offline, no network, no subprocess), `cdxgen -t hbom`, `lshw`, `dmidecode`, `fwupdmgr`, PowerShell's CIM cmdlets or a Redfish service's JSON — run by the operator on the device and uploaded. AxeBOM never reaches the device. ⚠ Such a report describes what an **operating system can see**: a part with no driver, no bus presence and no SMBIOS entry appears in none of these files, and its absence is not evidence. Serial numbers in SMBIOS are root-readable only, so an unprivileged run omits them — our own collector records *which* files it could not read, because "nobody had permission to look" and "there is no serial" are different facts;
- **a CSV or the structured form**, unchanged.

**No open-source tool inspects a physical device and enumerates its parts, and this product does not either.** A schematic is a drawing of an intent — it says what was designed, not what was built or what is currently fitted. A host inventory reports what an operating system can see, which is not the same as what is on the board. Neither is AxeBOM having examined hardware.

If you need the physical hardware inspected rather than its documents read, this product cannot do it,
and neither can any of the alternatives claiming to.

## Hardware vulnerability matching is advisory

CERT-In §10.4.1.4 element 24 asks a hardware BOM to carry vulnerability
information, and AxeBOM matches components against NVD to populate it. **Every
match is a guess, and the report says so beside each one.**

A software finding is keyed on a purl the ecosystem itself minted: `lodash@4.17.20`
is not an inference, it is the package's own name. A hardware component has no
such identifier. It has a manufacturer string somebody typed and a model number
off a datasheet, and NVD maintains its own vendor and product vocabulary that
was never reconciled with either — "STMicroelectronics", "ST Microelectronics"
and "stmicroelectronics" are one company and three CPE vendors. So each match is
a string comparison between two independently maintained naming schemes, and
every finding carries the CPE it was searched with, the basis it matched on, and
a confidence that is never higher than `medium`.

> ⚠ **`not-attempted` is not `no-match`.** An empty vulnerability column means
> nothing without the status beside it. Four outcomes are recorded and never
> collapsed — `matched`, `no-match` (searched and clear, the only reassuring
> one), `no-cpe` (the component states too little to look up) and
> `not-attempted` (no source configured, nobody looked). **No environment has an
> NVD key today, so the shipping state is `not-attempted` for every component**,
> and the report says that in words rather than leaving a blank cell to be read
> as a clean result.

**Element 24's score is counter-intuitive, because the guideline's field is.** It
asks whether the BOM *declares* vulnerability information, not whether a check
was run — so a component searched and found clean scores the same **zero** as one
nobody looked at, and a vulnerable component scores full marks. The report states
this next to the number rather than quietly "fixing" the arithmetic.

**These severities are never added to the counts a software report quotes.** One
blended figure, part fact and part guess, with nothing saying which, would be
worse than two honest numbers.

## QBOM is largely a derivation

Cryptographic assets come from CBOM discovery with quantum-vulnerability rules
applied — Shor's algorithm against asymmetric primitives, Grover's against
symmetric key sizes. **There is no quantum-hardware scanner.** Table 8's device
metadata (model, vendor, hardware, communication protocol, environmental impact)
is collected from a form.

The readiness assessment is a *note*, never a score. A number would imply a
precision the underlying data does not have.

## Web reconnaissance sees a static page, not a running browser

A URL-registered project's SBOM comes from `services/webrecon`: it fetches a
page's HTML and its `<script>` tags — same-host or from a short CDN allowlist
— and matches the content against a signature database of known JS
libraries. **It never runs a browser.** Nothing here executes JavaScript.

Consequence: a library loaded purely by client-side JavaScript after the
page paints — bundled and injected by a framework's own runtime, fetched
dynamically, assembled from chunks a static parser cannot follow — is
invisible. A headless-browser (Playwright) renderer would catch this class
and is a named, deliberately deferred fast-follow, not built because it is a
materially larger sandboxed surface (a Chromium binary and its own CVE
stream) for a gap whose real-world size has not yet been measured.

Detection itself is also necessarily approximate, not exhaustive: it is a
signature match against ~76 known libraries (`retire.js`'s database), not a
general-purpose dependency graph the way a lockfile-based SBOM engine
produces one. Unlike a missing ECOSYSTEM — which the Engine Coverage section
states explicitly, because a manifest or lockfile names what should have
been scanned — there is no manifest here to compare against. A library
outside the signature database, or a version string no signature matches,
simply contributes nothing, and nothing can name the gap by size. A scan
that matches nothing across every host it fetched is reported honestly at
the engine level (the adapter marks the run `partial`, not `succeeded`, in
that case — never a silent zero), but it cannot say *which* libraries it
might have missed on any given page, only that it found none of the ~76 it
knows to look for.

## Scanners see what scanners see

- **Lockfiles and manifests only.** AxeBOM never runs `npm install`, `mvn`,
  `gradle`, `pip install` or `setup.py` — package-manager resolution executes
  code from the repository being scanned, and that is not a thing to do inside a
  compliance product. Consequence: a project without a lockfile yields a less
  complete dependency graph, and the report says so.
- **Vendored and statically linked code is largely invisible.** A C++ project
  that vendors a library into its own tree looks like the project's own source.
- **Dynamic loading is invisible.** A plugin resolved at runtime is not in any
  manifest.
- **An ecosystem with no available engine is REPORTED, not silently omitted.**
  Every report carries an Engine Coverage section naming ecosystems detected
  with no engine. An SBOM that quietly drops an ecosystem is worse than no SBOM:
  it converts an unknown into a false negative you trust.

## What an AI BOM actually establishes, and what it does not

- **Discovery reads your source; it never runs your model.** Three engines
  (`ai-bom`, `airom`, `cdxgen-ai`) parse the repository for model references,
  prompts, vector stores, RAG pipelines and the inference services the code
  talks to. AxeBOM does not evaluate a model, test it for bias, audit it, or
  execute it. A model named in code that is never actually loaded still appears,
  because a reference is what the source establishes.
- **Enrichment asks a public API about a model IDENTIFIER.** `aibom-generator`
  and the Hugging Face Hub are asked about `meta-llama/Llama-3-8B`, never about a
  line of your code. A model that does not resolve on the Hub — private, gated,
  renamed, or hosted somewhere else entirely — keeps its enrichment-only
  elements as `not-provided`, and Engine Coverage says which and why.
- **`verified` means an engine confirmed the model resolves upstream.** It never
  defaults to true. It is not a statement that the model is safe, licensed for
  your use, or the one that will be loaded at runtime.
- **Two of the tool's own answers are not used, because they are wrong.**
  `owasp-aibom-generator` re-parses the rendered model card and returns the
  licence with the next word of the page glued on (`mit ---`) and "training
  datasets" that are English words lifted out of a sentence (`consisting`, `one`,
  `a`). Both fields are taken from the model card's structured front matter
  instead, and a diagnostic records every value declined. Anything else that tool
  reports — architecture, task, metrics, the revision-pinned purl — is used as
  given.
- **Prompts, vector stores, RAG pipelines and inference endpoints are inventory,
  not compliance.** CERT-In Table 10 has no element for any of them, so they are
  reported in their own section and scored into **neither** coverage number.
  Moving a compliance percentage with something the guideline never asked for
  would be the same mistake as omitting them.
- **Software dependencies are attributed per model only where an engine said
  so.** Where none did, a model's dependency list is the project's AI libraries,
  and the report states that scope rather than implying evidence it does not
  have.
- **`cisco-ai-defense/aibom` is registered and deliberately never run.** Its
  `analyze` command always requires `--llm-model`: it resolves ambiguous AI usage
  by sending your code to a third-party LLM, which needs egress and an API key
  that scan engines are not allowed to hold. It is listed with that reason
  attached rather than omitted, so you can tell "AxeBOM does not know about this
  tool" from "AxeBOM chose not to run it".
- **`--llm-enrich` and any other flag that ships code to a third party stays
  off.** Turning one on is a per-project decision, surfaced in the UI and
  audited — never a default discovered afterwards in an egress log. ⚠ And
  consenting does not currently turn anything on: scan engines run with no
  network and there is no egress allowlist, so AxeBOM records the decision and
  the engines stay off. The API says so (`effective: false`, with the blocker
  named) and no screen may imply otherwise.
- **AxeBOM does not verify a model signature; it records a verification you
  ran.** `model_signing verify` recomputes the digest of every model file, and
  AxeBOM never holds your model weights — the scan sandbox sees a source tree
  and the enrichment plane sees a model identifier. So attestation follows the
  same shape as a host hardware inventory: you run the verifier where the
  artifact is, and AxeBOM ingests and **parses** the result. That is worth more
  than the free-text field it replaces — `verified` is read rather than typed, a
  failure is recorded as a failure, and the signer identity and digest land on
  the record — and it is not AxeBOM having checked a signature. Whoever produced
  that output could have written anything in it; the record is evidence of a
  claim, at a moment, attributed to the person who uploaded it.
- **An EU AI Act tier, a NIST AI RMF function or an ISO 42001 category is
  something a named person declared.** AxeBOM never infers one. Whether a system
  is high-risk depends on what it is used for — the sector, the deployment
  context, whether a human is in the loop — and none of that is visible in a
  repository. `undetermined` is a real answer and is offered as one: "somebody
  looked and could not decide" is a different state from "nobody has looked".
  ISO/IEC 42001 is offered as Annex A **categories**, not numbered controls,
  because a control reference one digit wrong is a false citation and, unlike a
  missing value, a plausible wrong one is invisible to the reader.
- **The ML-BOM is downloadable; the SPDX 3.0 AI document is a converter you
  run.** `format: mlbom` produces a CycloneDX 1.6 ML-BOM with populated
  `modelCard` blocks, validated against CycloneDX's own schema. SPDX 3.0's AI
  profile is written by `spdx-tools`, which is Python, and the report service is
  a Go binary — so that one is
  `python -m workers.aibom.spdx3 --in <mlbom> --out <file>` today rather than a
  download. It writes SPDX **3.0.0**, not 3.0.1.
- **`mlbomdoc` is not wired in, deliberately.** It reads a finished ML-BOM and
  reformats it to console, markdown, JSON or PDF via `lib4sbom` and `sbom2doc`.
  AxeBOM already renders PDF, DOCX, XLSX and JSON for every BOM type from the
  **canonical model**, which carries strictly more than the ML-BOM does —
  coverage numbers, Engine Coverage, normalization diagnostics. Running it would
  take our own document, hand it back to us with less in it, and add a
  dependency chain to the report path to do so. It is cited as the reference for
  what an ML-BOM summary should contain.
- **The AI operational score is ours, not a standard's.** Alongside the two
  CERT-In percentages a report carries an "AI operational surface" number — how
  much of the AI system's shape the engines could see. It is scored, labelled,
  and contributes to **neither** compliance percentage. Nobody's regulator asks
  for it.

## Vulnerability data is only as current as its feed

Findings come from Grype, Trivy, OSV-Scanner and Dependency-Check against their
own databases. Every report records the **database vintage** for each engine.

A vulnerability disclosed after that vintage will not appear. A scan is a
statement about a moment, which is exactly why campaigns exist.

**Alias clustering can be wrong in both directions.** GHSA, CVE, OSV and distro
identifiers are merged by union-find over an alias graph; the product refuses
CVE↔CVE merges without an authoritative source, caps cluster size, and logs
every merge with its evidence. Over-merge under-reports; under-merge inflates
counts roughly threefold. Both are visible in the cluster-size metric, and
neither is fully preventable from the upstream data available.

## Deliberate non-goals

- **Not an ERP, and the boundary moved deliberately.** AxeBOM now RECORDS
  per-line unit price, currency and an extended price (`quantity x unit_price`,
  computed by Postgres as a generated column so it can never disagree with its
  own inputs), and reports a roll-up. That is a narrowing of this non-goal, not
  its deletion: there is still no purchasing, no stock level, no reorder point,
  no supplier quoting and no inventory of what you actually hold. The earlier
  wording — "the HBOM importer accepts a `unit_cost` column and ignores it" —
  described real behaviour that is now obsolete.
- **Not a SAST or DAST tool.** It inventories components and reports known
  vulnerabilities in them. It does not analyse your own code for defects.
- **Not a license-compliance decision engine.** It records `declared`,
  `concluded` and `observed` licenses separately and flags genuinely ambiguous
  cases — notably deprecated `GPL-2.0` where `-only` and `-or-later` cannot be
  distinguished. It **never silently resolves that ambiguity**, because choosing
  wrong is a legal error. A lawyer decides; the product surfaces the question.
- **Not a policy engine with automated enforcement.** It reports violations. It
  does not block a build, and it does not decide that a violation is acceptable.

## Known gaps at this point in the build

These are gaps, not boundaries. They are listed because a gap you know about is
manageable and a gap you do not is not.

See `docs/STATE.md` for the authoritative, per-phase version of this list —
it is updated every session and this summary is not.

| Area | Gap |
|---|---|
| Integration | **Nothing has been run against the full stack.** Every phase from 9 onward has a database, HTTP or container surface that has never executed. |
| CBOM | `cbomkit-theia` has never been run; its adapter is tested against hand-built output. |
| AIBOM | Both adapters are written and parse-tested, never executed. |
| HBOM | **Hardware vulnerability matching (element 24) has never run against the live NVD API.** It requires `NVD_API_KEY`, which is set in no environment today, so every component reports `not-attempted` — see "Hardware vulnerability matching is advisory" above. Parsing is tested against hand-built responses, per the `providers/nexar.py` precedent. |
| Notifications | Templates and signing exist; no SMTP client, and no worker drains the delivery queue. |
| Normalizer | **Two of the five writerless `normalize` tables now have writers, and two are deliberate.** `component_provenance` and `component_candidate_identities` are written (both had live readers returning empty for every component), and `license_refs` preserves the raw text of a licence that could not be mapped to SPDX. ⚠ **`raw_findings` and `licenses` are still empty, on purpose.** `raw_findings` would hold every engine's pre-dedup findings — real evidence, but unbounded in volume with no retention policy and no reader, so writing it is a design decision rather than a gap to close quietly. `normalize.licenses` would hold the SPDX licence list as reference data; the resolver uses an in-code list and nothing queries the table, so seeding it would duplicate the list into a place nothing reads. |
| Reports | **Every BOM type now exports in every format.** SPDX and CycloneDX used to emit a valid, EMPTY document for CBOM, AIBOM and QBOM — the export path read only software components and hardware, so a customer could download a conformant file asserting their project contained nothing. All six (format × type) cells are now covered by a matrix test rendering a populated fixture, and every committed export validates against the official `spdx-tools` and `cyclonedx-python-lib` schemas. ⚠ Two honest limits remain, both in the serializer rather than in our data: **CycloneDX's `cryptographic-asset` component type cannot be emitted at all** — protobom v0.5.8's `Purpose` enum has no member for it and its writer has no branch producing it, so a CBOM's assets serialize as `data` with the real type carried in `certin:crypto:asset_type`; and SPDX 2.3 has no purpose for a machine-learning model, so an AIBOM's models are `OTHER` with Table 10 riding as `certin:aibom:*` properties. **HBOM export (§10.4.1.6) exists** — SPDX 2.3 validates clean against `spdx-tools` with real `CONTAINS` relationships and `primaryPackagePurpose: DEVICE`/`FIRMWARE`; CycloneDX 1.6 emits `type: device`. ⚠ One honest limit: CycloneDX flattens containment to `dependsOn`, because protobom's serializer ignores the edge type and CycloneDX 1.6's dependency graph has no containment relationship. The fact is preserved as an explicit `axebom:hbom:parent` property. |
| Enterprise | No SAML/OIDC SSO, no SCIM, no API keys, no audit-log export. |
| Operations | **No production deploy pipeline of any kind.** No CI workflow builds or pushes an image to a registry, and nothing runs `helm upgrade`/`kubectl apply` anywhere. A Helm chart exists (`deploy/k8s/`) and is deliberately shaped for tag-based rollback — `values.yaml`'s `image.tag` is empty by default specifically so a moving `latest` tag never makes a rollback impossible to describe — but it is not wired to any pipeline yet, so that design intent is unexercised. `task dev`/`task dev:rollback` give the local Compose stack a real rollback (last build that passed health, retagged and redeployed without a rebuild); nothing equivalent exists past a developer's own machine. Also missing: load-test baselines, a restore drill, a penetration test. Migration rollback in production is a deliberate boundary, not a gap — see `docs/08-OPERATIONS.md` §7: forward-only, additive-first, so an application-code rollback never needs a schema rollback. |

## What would change our mind

This document is a claim about limits, and claims should be falsifiable. Any of
these would move an item out of the list:

- A hardware discovery tool with a workable licence and real coverage → HBOM
  stops being import-only.
- A quantum-hardware inventory standard with tooling → QBOM stops being a
  derivation.
- A safe way to resolve a dependency tree without executing repository code →
  lockfile-only stops being a limit.

Until then, the honest version is the one above.
