"""cdxgen — a second, independent component inventory.

⚠ WHY A SECOND GENERATOR AT ALL, WHEN syft ALREADY CATALOGUES.

Because two independent inventories of the same tree is the input the
normalizer was built for. It reconciles them by identity rather than trusting
either (docs/03-NORMALIZER-SPEC.md), and a component only one engine saw is a
component the other missed — which is exactly the kind of gap a single-engine
SBOM cannot report. cdxgen's language coverage genuinely exceeds syft's in
several ecosystems, so the disagreements are informative rather than noise.

⚠ ITS GRAPH TRUST RANKS BELOW syft's EVERYWHERE THE TWO OVERLAP.

The normalizer REPLACES an ecosystem's dependency subgraph by trust rank rather
than unioning — unioning invents phantom transitive edges. syft is the engine
this codebase has actually run against real projects; cdxgen ranks above it in
nothing until it has. That is a deliberately conservative default, not a
judgement about the tool.

⚠ AND IT NEVER RESOLVES DEPENDENCIES BY EXECUTING ANYTHING.

cdxgen can install packages to deepen its analysis. That is forbidden here
(CLAUDE.md invariant 7) and enforced in the sandbox rather than by this
adapter's argv: `libs/go-shared/sandbox/policy.go`'s CheckCommand refuses
`npm install`, `mvn`, `gradle`, `pip install` and the rest for every engine.
`FETCH_LICENSE=false` and `--no-recurse`-style restraint here are the polite
half; the sandbox is the half that holds.
"""

from __future__ import annotations

from typing import Any

from axebom_shared.adapters.base import Capabilities, GenerateResult, ResultStatus, ScanTarget
from axebom_shared.adapters.summary import count_cyclonedx, summarize
from axebom_shared.sandbox import SandboxResult, WorkspaceLayout

from .common import SandboxedAdapter, ecosystems_from_purls

CAPABILITIES = Capabilities(
    engine_id="cdxgen",
    families=("sbom",),
    source_kinds=("git", "upload"),
    produces=("components", "licenses"),
    native_format="cyclonedx-json-1.6",
    ecosystems=(
        "npm",
        "pypi",
        "maven",
        "golang",
        "gem",
        "cargo",
        "nuget",
        "swift",
        "dart",
        "elixir",
        "php",
        "ruby",
    ),
    default_weight=3,
    graph_trust={"npm": 1, "pypi": 1, "maven": 1, "golang": 1},
)


class CdxgenAdapter(SandboxedAdapter):
    """Runs cdxgen over a source directory."""

    media_type = "application/vnd.cyclonedx+json; version=1.6"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(CAPABILITIES, **kwargs)

    def build_argv(self, target: ScanTarget, layout: WorkspaceLayout) -> list[str]:
        """Catalogue the source tree, writing CycloneDX to stdout.

        `-o /dev/stdout` rather than a path: every mount in the sandbox is
        read-only by design, so there is nowhere on the host to write. The
        `--spec-version 1.6` pin matters — cdxgen defaults to a newer spec than
        the rest of this pipeline reads, and a document in an unexpected
        version parses into silently fewer fields rather than failing.
        """
        return [
            "-r",
            layout.container_source,
            "-o",
            "/dev/stdout",
            "--spec-version",
            "1.6",
            "--no-banner",
            # ⚠ THE MOST IMPORTANT FLAG HERE, AND IT WAS MISSING.
            #
            # cdxgen's `--install-deps` DEFAULTS TO TRUE. Without this it runs
            #
            #     npm install --ignore-scripts --no-audit --no-bin-links …
            #
            # inside the sandbox, over the customer's source tree — observed
            # live on a real scan of expressjs/express.
            #
            # That is forbidden outright by CLAUDE.md invariant 7: "Never run
            # package-manager resolution that executes user code. No
            # `npm install`, no `mvn`, no `gradle`, no `pip install`, no
            # `setup.py`. Lockfile and manifest parsing only." `--ignore-scripts`
            # blocks the lifecycle-hook vector, which is why this was not a
            # breach — but the rule is a flat prohibition, not a risk
            # assessment, and a resolver still executes resolution logic over
            # attacker-controlled manifests.
            #
            # It also cannot work: the container runs `--network=none`, so the
            # install can never reach a registry. It retries and backs off
            # instead, and a scan of a 213-file repository sat in `running` for
            # over ten minutes with every engine still queued behind it.
            #
            # This is the identical failure FETCH_LICENSE=false already guards
            # against below, by the same mechanism, with the same symptom — a
            # network-reliant step stalling to its own timeout inside a network-
            # less sandbox. One was found; this one was not.
            "--no-install-deps",
        ]

    def extra_env(self, layout: WorkspaceLayout) -> dict[str, str]:
        """Keep cdxgen offline, and point every scratch path at the tmpfs.

        ⚠ TMPDIR ALONE IS NOT ENOUGH, AND THE FIRST LIVE RUN PROVED IT.

        cdxgen builds its scratch path from its OWN variables and falls back to
        a hardcoded `/tmp/cdxgen-temp`, not to TMPDIR. The sandbox rootfs is
        read-only, so the run died with

            errno: -30, code: 'EROFS', syscall: 'mkdtemp',
            path: '/tmp/cdxgen-temp/sbt-cache-XXXXXX'

        which names neither cdxgen's needs nor the sandbox policy — the same
        shape of failure trivy's adapter documents for the same reason. All
        three variables are set because cdxgen reads different ones on
        different code paths (CDXGEN_TEMP_DIR and CDXGEN_TMP_DIR both exist in
        the image), and setting only the one a given release happens to consult
        is how this breaks again on the next version bump.

        ⚠ FETCH_LICENSE=false IS NOT A PREFERENCE EITHER. The container runs
        `--network=none`; a tool that tries to enrich licences over the network
        stalls on every component until its own timeout, turning a 20-second
        scan into a wall-clock failure.
        """
        return {
            "FETCH_LICENSE": "false",
            "CDXGEN_DEBUG_MODE": "quiet",
            "TMPDIR": layout.container_scratch,
            # ⚠ A SUBDIRECTORY, NOT THE SCRATCH ROOT ITSELF, AND THE SECOND
            # LIVE RUN IS WHY.
            #
            # cdxgen OWNS its temp directory: `cleanupTmpDir` removes it after
            # generating. Handed the scratch root it tried to `rm /workspace` —
            # the tmpfs MOUNT POINT — and died with errno -4094 after the SBOM
            # had already been produced. Giving it a path underneath means the
            # directory it deletes is one it created.
            "CDXGEN_TEMP_DIR": f"{layout.container_scratch}/cdxgen-temp",
            "CDXGEN_TMP_DIR": f"{layout.container_scratch}/cdxgen-temp",
            # Its package cache would otherwise land under the read-only
            # rootfs too. A sibling directory, for the same reason.
            "CDXGEN_CACHE_DIR": f"{layout.container_scratch}/cdxgen-cache",
        }

    def interpret(
        self,
        target: ScanTarget,
        payload: Any,
        result: SandboxResult,
        base: GenerateResult,
    ) -> GenerateResult:
        """Turn cdxgen's CycloneDX into a summary and an ecosystem list.

        ⚠ ZERO COMPONENTS IS `partial`, NOT `succeeded`. A tree cdxgen did not
        understand and a tree with nothing in it produce the same empty
        document, and reporting the first as success turns an unknown into a
        false negative the customer trusts (invariant 12).
        """
        components = payload.get("components") if isinstance(payload, dict) else None
        count = len(components) if isinstance(components, list) else 0

        if count == 0:
            return GenerateResult(
                status=ResultStatus.PARTIAL,
                artifacts=base.artifacts,
                summary=summarize(self.capabilities, {"components": 0}),
                diagnostics=[
                    *base.diagnostics,
                    {
                        "severity": "warn",
                        "code": "ENGINE_ZERO_RESULTS",
                        "message": "cdxgen catalogued no components",
                        "hint": "reported as partial rather than succeeded: an "
                        "unrecognised project layout and an empty one produce the "
                        "same document",
                    },
                ],
                engine_version=base.engine_version,
                image_digest=base.image_digest,
                exit_code=base.exit_code,
                argv_redacted=base.argv_redacted,
            )

        purls = [
            c.get("purl", "")
            for c in components
            if isinstance(c, dict) and isinstance(c.get("purl"), str)
        ]
        return GenerateResult(
            status=ResultStatus.SUCCEEDED,
            artifacts=base.artifacts,
            ecosystems_covered=ecosystems_from_purls(purls),
            summary=summarize(self.capabilities, count_cyclonedx(payload)),
            diagnostics=base.diagnostics,
            engine_version=base.engine_version,
            image_digest=base.image_digest,
            exit_code=base.exit_code,
            argv_redacted=base.argv_redacted,
        )
