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
