# log4shell-java

## What failure mode does this fixture isolate?

Deduping vulnerability findings on their *primary* id inflates counts. Three
different pieces of evidence exist for exactly one real-world vulnerability —
Log4Shell — under three different identifiers, and **no single engine's
output asserts the whole triangle**:

- `grype` reports the vulnerability as `GHSA-jfh8-c2jp-5v3q`, and separately
  (non-authoritatively) notes it relates to `CVE-2021-44228`.
- `osv-scanner` reports `GHSA-jfh8-c2jp-5v3q` with an authoritative OSV.dev
  alias to the Debian security advisory `DSA-5022-1`, and *separately*
  reports `CVE-2021-44228` as its own record with no aliases of its own.

Neither engine, on its own, connects all three ids. A naive implementation
that dedupes by exact-id-match would report **three** findings against
`log4j-core` for what is one vulnerability. The alias closure
(`libs/py-shared/axebom_shared/normalize/aliases.py`) must instead compute the
transitive closure of the alias graph — `CVE-2021-44228 ↔ GHSA-jfh8-c2jp-5v3q`
(via grype, non-authoritative) and `GHSA-jfh8-c2jp-5v3q ↔ DSA-5022-1` (via
osv-scanner, authoritative) — and merge all three into **one** cluster via
the shared `GHSA` hub.

## Why is each expected value correct?

- **`CVE-2021-44228`** is Log4Shell's real, public CVE identifier
  ([nvd.nist.gov/vuln/detail/CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)).
- **`GHSA-jfh8-c2jp-5v3q`** is GitHub's real advisory id for the same
  vulnerability ([github.com/advisories/GHSA-jfh8-c2jp-5v3q](https://github.com/advisories/GHSA-jfh8-c2jp-5v3q)).
- **`DSA-5022-1`** is Debian's real security advisory for the same CVE
  ("log4j2 -- security update", published 2021-12-13,
  [lists.debian.org/debian-security-announce/2021/msg00345.html](https://lists.debian.org/debian-security-announce/2021/msg00345.html)).
  It is used here as the "distro-advisory-style" third identifier the plan
  called for. It never appears as its own `RawFinding` — only as an alias on
  `osv-scanner`'s `GHSA-jfh8-c2jp-5v3q` record — which is realistic:
  OSV.dev routinely aggregates distro advisories as aliases without
  publishing an independent record for each.
- **One cluster, three members, `display_id_at_render = "CVE-2021-44228"`**:
  `display_id()` in `aliases.py` picks the lowest `_NAMESPACE_RANK` member —
  `CVE` (rank 0) beats `GHSA` (rank 1) and `DSA` (rank 7) — which is also the
  identifier a remediation ticket would actually cite.
- **`fixed_in_min = "2.15.0"`**: the real fix version for CVE-2021-44228,
  taken verbatim from `osv-scanner`'s `ranges[].events[].fixed` — never
  guessed.
- **Only two of `aliases.py`'s two edge-producing adapters are exercised**
  (`edges_from_grype`, `edges_from_osv`) — those are the *only* two that
  exist in the codebase today (`edges_from_grype`/`edges_from_osv`;
  `dependency-check` and the CycloneDX vulnerabilities parser contribute
  `RawFinding`s but no alias *edges*). The plan's original wording described
  "three engines" contributing edges; the codebase truth is two edge-capable
  engines contributing two separate partial edges (one from each), which is
  what actually exercises "no single tool asserts the whole triangle" — see
  the judgment-call note at the bottom of this file.

## What would a wrong implementation produce instead?

- **No closure at all** (dedup by exact id string): three findings against
  `log4j-core` — `GHSA-jfh8-c2jp-5v3q`, `CVE-2021-44228`, and (if
  `DSA-5022-1` were even surfaced as a finding) a third — instead of one. A
  report would claim `log4j-core` has three vulnerabilities where it has one,
  inflating a remediation count threefold on the single most consequential
  Java CVE of the last decade.
- **Only following authoritative edges**: would merge `GHSA-jfh8-c2jp-5v3q`
  and `DSA-5022-1` (via osv-scanner's authoritative alias) but leave
  `CVE-2021-44228` in its own cluster, since grype's `relatedVulnerabilities`
  assertion is non-authoritative. `CVE-2021-44228` is not itself a CVE↔CVE
  edge, so Guard 1 (which only restricts CVE↔CVE merges) does not block it —
  a correct implementation *does* accept this non-authoritative GHSA↔CVE
  edge. A wrong implementation that treated "non-authoritative" as
  "never mergeable" would under-report by leaving two clusters instead of
  one.
- **Forcing the top-level project component's depth**: `roots = 2` in the
  generated canonical output (the `alias-overmerge`-style project component
  and the `/src/pom.xml` file entry, per `graph.py`'s "everything nothing
  depends on" fallback, since syft's `metadata.component` here points at a
  virtual `/src` node that is never itself walked as an inventory component —
  matching the same pattern `fixtures/maven-case` already uses). This is
  expected, not a defect in this fixture.

## Judgment call for a second reviewer

The original plan text asked for "three engines" each contributing one edge
of the triangle. `aliases.py` has exactly two edge-producing adapters
(`edges_from_grype`, `edges_from_osv`); there is no third. This fixture
instead uses **two edges from those two engines** — `grype`'s non-authoritative
GHSA↔CVE assertion, and `osv-scanner`'s authoritative GHSA↔DSA alias — which
still satisfies the real property being tested ("no single tool asserts the
whole triangle") since neither edge alone connects all three ids. If a future
session adds an edge-producing adapter for a third engine (e.g. trivy-fs),
this fixture could be extended to route the DSA edge through it instead, but
that is not required for the guard this fixture proves.

## Engine versions

`grype` 0.117.0, `osv-scanner` (schema only, no version field emitted),
`syft` 1.51.0 — versions recorded in the raw artifacts themselves, matching
the fixtures this session found already committed (`maven-case`,
`npm-simple`).
