# Phase 2 — OSINT supply chain

**Estimated: 1 week** · Depends on Phase 0.

## Read first

1. `CLAUDE.md` — invariants 7, 9
2. `docs/STATE.md`
3. **`docs/04-OSINT-INTEGRATION.md` — in full**
4. `OSINT/tools.manifest.yaml`
5. `docs/ADR/0002-pinned-artifacts-no-source-builds.md`

## Goal

Acquire, verify and probe every scanner. **No scanning yet** — this phase proves the tools are real, fetchable, verifiable and runnable.

It is separate from Phase 0 because its failure modes are entirely different: network, upstream drift, checksum mismatches, licensing. Mixing those with repo scaffolding makes both harder to debug.

## Preconditions

```
task verify      # green
docker info      # daemon reachable
```

## The first task, before anything else

```
task osint:dryrun
```

> **Every version and digest in `tools.manifest.yaml` is an unverified placeholder** (`TBD`) written from upstream research and never resolved against the network. Resolve them all, expect zero 404s, and pin the real values.

If a URL 404s: check the release-asset naming (it changes between projects and sometimes between releases), and check the org. **CBOMkit is `PQCA/`, not `cbomkit/`** — the original plan had this wrong and it fails exactly here.

## Out of scope

No adapters that parse output (Phase 7), no sandbox (Phase 5), no scanning. This phase ends at "the tool runs and prints its version."

## Deliverables

```
cmd/encorebom/toolctl.go        sync | verify | list | dryrun
libs/go-shared/toolctl/
  manifest.go   parse + validate
  fetch.go      download, sha256, cosign
  resolve.go    container -> binary -> unavailable
  probe.go      availability check

libs/py-shared/encorebom_shared/adapters/
  base.py       ToolAdapter protocol: available() / generate() / parse()
  registry.py   engine_id -> adapter
  <one stub per engine — available() only>

workers/*/adapters/          engine stubs
.github/workflows/osint-contract.yml     NIGHTLY
OSINT/tools.manifest.yaml    updated with real versions + digests
```

## Contracts to honour

- **Adapter interface** — `04-OSINT-INTEGRATION.md`: `available()`, `generate()`, `parse()`. Every engine implements all three; `generate`/`parse` may raise `NotImplemented` until Phase 7.
- **Engine registry shape** — `02-CONTRACTS.md §7`. The unit is **(tool, mode)**: `trivy-fs` and `trivy-image` are separate entries.
- **Resolution order** — container → binary → `unavailable`. A missing engine is **recorded, never fatal**.
- **Java tools are container-only.** Do not add a local-JDK path; the dev machine has Java 1.8.

## Steps

1. `task osint:dryrun`, resolve every placeholder, update the manifest, set `verified_against_network: true`.
2. Implement `toolctl sync`: download to `.encorebom/tools/<id>/<version>/`, verify SHA256 against the upstream checksum file, verify cosign where `cosign: true`.
3. **Handle a missing `cosign` explicitly**: degrade to checksum-only, print a loud warning, and record the degradation in the provenance manifest. Never silently.
4. Implement `toolctl verify`: probe each engine, print `available` / `unavailable` with the reason.
5. Write adapter stubs. `available()` runs the tool's version command and parses the version — this is what catches a container that pulls but does not run.
6. Pre-warm the `depcheck-data` volume in a compose init job. A cold NVD sync takes 30–60 minutes and will otherwise blow every job deadline in Phase 7.
7. Nightly `osint-contract` workflow: run each pinned tool against a trivial fixture, assert it starts and reports the expected version. **Failure opens an issue.**
8. Record every tool's license in the manifest; add a check that fails on any GPL/AGPL entry outside `rejected:`.
9. Update `docs/STATE.md`.

## Test requirements

- Manifest parses; every enabled tool has a resolvable source.
- Checksum mismatch → **refuses to install** (test with a deliberately wrong sha).
- Missing cosign → warns, does not fail, records degradation.
- `available()` returns false cleanly for a deliberately-broken engine — no panic, no hang.
- Resolution falls back container → binary → unavailable, verifiably.
- License check fails on a GPL dependency added outside `rejected:`.

## Exit criteria

```
task osint:dryrun            # zero 404s, zero TBD in enabled tools
task osint:sync              # all verified
task osint:verify            # every enabled engine: available
task osint:contract          # green
task verify
```

## Before you finish

Update `docs/STATE.md`: the resolved versions, any upstream URL that had moved, and flip the "OSINT manifest unverified" gap to resolved. Note which engines are `unavailable` on this machine and why.
