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

## There is no hardware scanner

**No open-source tool inspects a physical device and enumerates its parts.** Not
ours, not anyone's. HBOM is a structured CSV import plus a form, and every label
in the product says "import" rather than "scan" — enforced by a test that walks
the source.

If you need hardware discovered rather than declared, this product cannot do it,
and neither can any of the alternatives claiming to.

## QBOM is largely a derivation

Cryptographic assets come from CBOM discovery with quantum-vulnerability rules
applied — Shor's algorithm against asymmetric primitives, Grover's against
symmetric key sizes. **There is no quantum-hardware scanner.** Table 8's device
metadata (model, vendor, hardware, communication protocol, environmental impact)
is collected from a form.

The readiness assessment is a *note*, never a score. A number would imply a
precision the underlying data does not have.

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

- **Not an ERP.** No inventory, purchasing, stock levels or cost roll-up. The
  HBOM importer accepts a `unit_cost` column and ignores it.
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
| HBOM | No hardware row has been written to the database; the HTTP surface the UI calls does not exist yet. |
| Notifications | Templates and signing exist; no SMTP client, and no worker drains the delivery queue. |
| Reports | No CycloneDX ML-BOM or HBOM export (§10.4.1.6). |
| Enterprise | No SAML/OIDC SSO, no SCIM, no API keys, no audit-log export. |
| Operations | No Helm charts, no load-test baselines, no restore drill, no penetration test. |

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
