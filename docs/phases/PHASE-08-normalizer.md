# Phase 8 — Normalizer and golden corpus

**Estimated: 4 weeks** · Depends on Phase 7. **The longest and most important phase.**

> This produces every number a customer sees. A bug here does not crash anything — it quietly reports 240 vulnerabilities where there are 80, or 94% coverage where it is 61%. Budget the four weeks; do not compress this one.

## Read first

1. **`docs/03-NORMALIZER-SPEC.md` — in full, twice.** This phase is that document.
2. `docs/STATE.md`
3. `docs/09-GOLDEN-CORPUS.md`
4. `docs/01-DATA-MODEL.md` §4, §5
5. `docs/ADR/0003-replayable-normalization.md`, `docs/ADR/0005-durable-vuln-cluster-ids.md`

## Goal

Turn raw engine output into the canonical model: identity, alias closure, license resolution, graph merge, coverage, provenance. Plus the fifteen-fixture golden corpus that proves it.

## Preconditions

Phase 7's fixtures exist with committed `raw/` artifacts. Those are this phase's inputs — **tests replay pinned artifacts and never run scanners.**

## Out of scope

No exporters, no reports (Phase 9). Output is canonical rows in `normalize.*`.

## Deliverables

```
libs/py-shared/encorebom_shared/normalize/
  purl.py        canonicalization, per-ecosystem rules
  identity.py    the 7-rule fallback chain
  merge.py       component merge
  aliases.py     union-find over the global edge graph
  findings.py    dedup, severity precedence, fix ordering
  licenses.py    SPDX expressions, alias table, LicenseRef fallback
  graph.py       per-ecosystem replacement, BFS, cycles, orphans
  coverage.py    both numbers, type-aware
  provenance.py
  versions/      semver, pep440, maven, rpm_evr, deb, golang

workers/sbom/normalize_runner.py
cmd/encorebom/renormalize.go            re-run over stored artifacts
fixtures/**/expected/*.json             hand-reviewed
```

## Contracts to honour

Each of these is a specific trap documented in the spec. Read the reasoning there; do not just implement the rule.

- **Never merge name+version across ecosystems.** `npm/lodash@4` ≠ `maven/lodash@4`.
- **Never merge a LOW-confidence CPE into a PURL component** — attach as candidate identity.
- **Cluster ids are durable surrogates**, never derived from members. Merges write a forwarding row.
- **Guard over-merge**: no CVE↔CVE merge without an authoritative edge; flag clusters >12; **log every merge with its evidence**.
- **Never average severity**; never max across CVSS versions; surface conflicts.
- **Replace graph subgraphs per ecosystem, do not union.**
- **Cycles are real.** Orphans get `depth = NULL`, never forced to 1.
- **Two coverage numbers, always both.** `not-provided` scores 0 for completeness.
- **Type-aware crypto scoring.**
- **Determinism**: no `time.Now()`, no randomness, no network inside the normalizer.

## Steps

1. PURL canonicalization with the per-ecosystem table from the spec §1.1. Test each rule individually before composing.
2. Identity fallback chain, recording `identity_rule` and `identity_confidence`.
3. Component merge: union locations/hashes/licenses/CPEs; scope precedence; `observed_by[]`.
4. **The alias graph.** Global edge table, union-find, durable cluster ids, forwarding on merge, the three over-merge guards. Build `log4shell-java` and `alias-overmerge` fixtures **while writing this**, not after — they are how you know it works.
5. Finding dedup on `(cluster_id, component_key)`; severity precedence; `severity_conflict`.
6. Version comparators, one module per ecosystem. `fix_version_ordering = 'unknown'` where none exists — **do not guess an ordering**.
7. License pipeline; keep declared/concluded/observed separate; `NONE` present vs `NOASSERTION` absent; flag `GPL-2.0` ambiguity rather than resolving it.
8. Graph merge with per-ecosystem trust order; BFS with a visited set; N roots for a monorepo; `is_direct` stored explicitly.
9. Coverage: both numbers, weighted from the profile, type-aware for crypto, unidentified components kept in the denominator. Auto-populate `project.practices.known_unknowns` from ecosystems with no available engine.
10. Provenance on every entity; `provenance_manifest` on the scan.
11. `renormalize` command: replay stored artifacts into `normalization_version + 1`.
12. Build all fifteen fixtures with **hand-written** expectations and a README answering the three questions in `09-GOLDEN-CORPUS.md §3`.
13. Bulk-insert via `COPY`; cap at ~250k components with a loud diagnostic.
14. Update `docs/STATE.md`.

## Test requirements

Beyond the golden corpus, the unit list in `03-NORMALIZER-SPEC.md §9` in full. The ones most likely to be skipped and most costly to skip:

- Cluster id **stable across a subsequent merge** (the ADR-0005 trap).
- Non-authoritative CVE↔CVE edge **refused**.
- A >12-member cluster **flagged, not merged**.
- Connection-pool determinism: the same raw artifacts produce byte-identical canonical output across runs and across OSes.
- `renormalize` over an existing scan produces version 2 without touching version 1.

## Exit criteria

```
task test:golden               # all 15 fixtures
go test ./... -run TestNormalize -v
python -m pytest libs/py-shared/encorebom_shared/normalize -v
task verify
```

Manual: a real repo scanned with all six engines yields one deduped inventory; the same CVE from three engines is one finding with three `detected_by` entries; both coverage numbers are computed and differ.

## Before you finish

Update `docs/STATE.md`: `ruleset_version` in use, which fixtures exist, and **any known normalization gap**. Gaps here are the ones that matter most — an undocumented one becomes a customer-visible wrong number.
