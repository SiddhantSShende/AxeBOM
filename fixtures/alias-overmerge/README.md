# alias-overmerge

## What failure mode does this fixture isolate?

Unguarded union-find over the alias graph eventually merges unrelated
vulnerabilities into one giant "cluster" — which **under-reports**, the more
dangerous direction (`aliases.py`'s own module docstring, Trap B). Two
distinct over-merge paths exist and this fixture exercises both:

1. **The 12-member cap** (`MAX_CLUSTER_SIZE`, Guard 2): a single advisory
   that aliases more distinct CVEs than the cap allows must stop merging once
   the cap is hit, flag the touched clusters `flagged_for_review`, and never
   silently exceed the ceiling.
2. **The CVE↔CVE authoritative-only rule** (Guard 1): a scanner's own
   "related vulnerabilities" assertion between two CVE ids — as opposed to an
   authoritative OSV.dev/GHSA alias — must never merge them. Two entries in
   the CVE registry are two separately tracked vulnerabilities; a scanner
   guessing they are the same is usually a batched-advisory artefact.

## Why is each non-obvious expected value correct?

- **`osv-scanner` reports a synthetic advisory `GHSA-ovmg-test-0001` aliasing
  13 synthetic CVE ids** (`CVE-2024-90001` .. `CVE-2024-90013`). ⚠ **These are
  NOT real CVE/GHSA identifiers.** They are deliberately fabricated
  placeholders for stress-testing the cap — `docs/09-GOLDEN-CORPUS.md` §6
  requires this fixture to exceed `MAX_CLUSTER_SIZE=12` if merged
  unconditionally, and no real advisory conveniently aliases exactly the
  right number of CVEs to make that reproducible and reviewable. This is the
  one deliberate exception to "never fabricate data" in this fixture set: the
  ids are synthetic by design, not presented as real vulnerabilities, and are
  namespaced obviously enough (`GHSA-ovmg-test-...`, and every payload's
  `summary`/`description` field says "SYNTHETIC fixture id") that nobody
  reading a generated report from this fixture could mistake them for a real
  CVE.
- **The resulting cluster has exactly 12 members**
  (`GHSA-OVMG-TEST-0001` + `CVE-2024-90001` .. `CVE-2024-90011`), not 13 or
  14: `close()` in `aliases.py` sorts edges (authoritative first, then by
  key), and processes them in ascending `CVE-2024-900NN` order since all 13
  edges here are equally authoritative (`osv.dev/aliases`) and every edge is
  `(CVE-..., GHSA-...)` — CVE sorts before GHSA lexically, so `key()` orders
  purely by the CVE suffix. The union starting size is 1 (the GHSA alone);
  each successful union adds one CVE, so union *N* is only accepted while the
  pre-union size is ≤ 11 (`combined = 1 + size ≤ 12`). That holds for unions
  1–11 (`CVE-2024-90001` through `CVE-2024-90011`); union 12
  (`CVE-2024-90012`, pre-union size 12) would produce a 13-member cluster and
  is refused per Guard 2 — checked **before** the union, since undoing a
  union in a path-compressed structure is not possible.
- **`CVE-2024-90012` and `CVE-2024-90013` each end up as their own
  1-member, `flagged_for_review = true` clusters** — Guard 2 flags *both*
  sides of a refused edge (`flagged.add(uf.find(a)); flagged.add(uf.find(b))`
  in `aliases.py`), and since these two never successfully merge with
  anything, their own singleton root is what gets flagged.
- **`CVE-2024-99999` never merges with anything, and is `flagged_for_review
  = false`**: it is the standalone, genuinely-distinct vulnerability. The
  *only* edge that ever touches it is `grype`'s `relatedVulnerabilities`
  assertion linking it to `CVE-2024-90001` — a scanner's own guess, not an
  authoritative OSV.dev/GHSA alias. Since both ids normalize to namespace
  `CVE`, Guard 1 refuses the edge outright, before the size-cap logic ever
  runs, so it is never flagged by Guard 2 either — it is simply never
  touched. The `findings` array confirms this directly: `CVE-2024-99999`'s
  finding is `detected_by: ["osv-scanner"]` only, never joined with the
  batch cluster's finding (`detected_by: ["grype", "osv-scanner"]`).
- **`display_id_at_render` of the 12-member cluster is `CVE-2024-90001`**,
  not the GHSA id: same `_NAMESPACE_RANK` rule as every other fixture — `CVE`
  (rank 0) beats `GHSA` (rank 1).

## What would a wrong implementation produce instead?

- **No cap at all**: one 14-member cluster (`GHSA-OVMG-TEST-0001` + all 13
  CVEs), never flagged. A compliance report would show one "vulnerability"
  where a customer actually has (at minimum) evidence of several distinct
  ones batched together — precisely the under-reporting Trap B warns about.
- **A cap checked *after* the union instead of before**: since union-find
  with path compression cannot be undone, an implementation that unions
  first and checks the cap after would either (a) have already corrupted the
  structure by the time it notices, or (b) require rebuilding from scratch —
  a correctness bug waiting to happen under a naive "undo" attempt. This
  fixture's expected 12-member (not 13, not some other number depending on
  processing order) result is only reproducible with a check-before-union
  design.
- **Trusting a scanner's `relatedVulnerabilities` for CVE↔CVE merges**: would
  fold `CVE-2024-99999` into the batch cluster on the strength of `grype`'s
  own guess alone. The finding for `batch-pkg` would then read "1 finding,
  detected by 2 engines" instead of the correct "2 separate findings" — an
  under-report of exactly the kind Guard 1 exists to prevent, and one that is
  particularly dangerous because it looks *more* corroborated (two engines!)
  rather than less.

## Judgment call for a second reviewer

The synthetic CVE/GHSA ids in this fixture are fabricated on purpose (see
above) — flagging this explicitly per this session's "never fabricate real
data" discipline. A second reviewer should confirm the `SYNTHETIC` labeling
in every raw payload's `summary`/`description` field is prominent enough that
nobody could mistake `CVE-2024-90001`..`CVE-2024-90013` or
`GHSA-ovmg-test-0001` for real advisories if this fixture's raw JSON were
ever viewed out of context (e.g. copy-pasted into a bug report).

## Engine versions

`grype` 0.117.0, `osv-scanner` (schema only, no version field emitted),
`syft` 1.51.0.
