# Phase 7 — SBOM engine adapters

**Estimated: 2.5 weeks** · Depends on Phases 5, 6.

## Read first

1. `docs/STATE.md`
2. **`docs/04-OSINT-INTEGRATION.md` §3 (invocations), §5 (failure modes)**
3. `docs/02-CONTRACTS.md` §4, §6 (`ScanJobV1`, `ScanResultV1`)
4. `docs/09-GOLDEN-CORPUS.md` §1, §6

## Goal

Six real engines produce real raw artifacts from real repositories. **Parsing to canonical is Phase 8** — this phase ends at "valid `ScanResultV1` plus raw output in object storage."

Separating these is deliberate: engine invocation fails for operational reasons (versions, timeouts, containers), parsing fails for semantic ones. Debugging them together is much harder.

## Preconditions

```
task osint:verify     # all six available
```

`depcheck-data` volume pre-warmed — a cold NVD sync is 30–60 minutes and will blow every deadline.

## Out of scope

No normalization, no dedup, no coverage. `parse()` may return raw structures; Phase 8 owns canonical mapping.

## Deliverables

```
workers/sbom/adapters/
  syft.py  grype.py  trivy_fs.py  trivy_image.py
  osv_scanner.py  dependency_check.py
workers/sbom/runner.py        subscribe, dispatch, publish

fixtures/{npm-simple,pypi-normalization,maven-case,golang-incompatible,monorepo-multiroot}/
  repo/  raw/<engine>.json
```

## Contracts to honour

- **`grype` runs against our syft SBOM**, not the directory. Re-scanning produces a second inventory to reconcile — exactly the work the normalizer exists to avoid.
- `trivy-fs` and `trivy-image` are **separate engines** with separate adapters.
- **`engine_db_version` is required** for grype, trivy, osv-scanner, dependency-check.
- Engines run **inside the Phase 5 sandbox** with `--network=none`. Vulnerability engines get a pre-warmed database, not egress.
- **Defensive parsing**: ignore unknown fields, diagnose missing ones, **never panic**.
- Zero components found is `partial` **with a diagnostic**, not `succeeded`. Zero is a claim and needs to be an explicit one.

## Steps

1. Adapter base: run in sandbox, capture stdout/stderr, upload artifacts, build `ScanResultV1`, redact argv.
2. `syft` → CycloneDX **and** SPDX in one invocation. Both to object storage.
3. `grype` consuming the syft CycloneDX. Record `grype-db` version; if the DB schema is incompatible with the pinned binary, emit `ENGINE_DB_STALE` and mark `unavailable` rather than emit stale matches.
4. `trivy-fs` with `--scanners vuln,license,secret`; `trivy-image` against a digest-pinned image.
5. `osv-scanner`. **Capture the `aliases` field carefully** — it is the authoritative input to Phase 8's union-find, and losing it there is expensive to notice later.
6. `dependency-check` in its container with the warm volume. **Preserve the CPE confidence field** — Phase 8 needs it to refuse LOW-confidence merges.
7. Per-engine ecosystem detection → `scan.ecosystems_detected`, including ecosystems with no available engine.
8. Partial handling: one malformed lockfile among twelve ecosystems → `partial` + `ENGINE_PARTIAL_ECOSYSTEM` naming the ecosystem, not a failed run.
9. Build the five fixtures; run each engine once; **commit `raw/`** — these are Phase 8's test inputs.
10. Update `docs/STATE.md`.

## Test requirements

- Each adapter emits a schema-valid `ScanResultV1` across all five fixtures.
- **`unavailable` path exercised**: stop a container, confirm the engine reports unavailable, the scan still completes, and Engine Coverage records it.
- Malformed lockfile → `partial` + diagnostic, not a crash.
- A tool emitting an unexpected field does not panic the adapter (test with a mutated fixture).
- Timeout → `timeout` status, container cleaned up.
- `engine_db_version` present on every vulnerability engine result.
- **No credential in any engine container** — environment, filesystem, or argv.
- `argv_redacted` contains no secrets.
- Raw artifacts land in object storage with correct sha256 and media type.

## Exit criteria

```
task osint:contract
go test ./workers/sbom/... -v
task verify
```

Manual: real repository → all six engines run → six raw artifact sets → scan reaches `completed` or `completed_with_errors` with per-engine detail visible.

## Before you finish

Update `docs/STATE.md`: engines working, engine versions used for the committed fixtures (Phase 8's expectations are only meaningful against known inputs), and any engine deferred with the reason.
