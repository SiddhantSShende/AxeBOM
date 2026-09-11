"""cdxgen `cbom` — cryptography used in JavaScript and TypeScript source.

⚠ THE SAME DIGEST-PINNED IMAGE AS `cdxgen` AND `cdxgen-ai`, A DIFFERENT ENGINE ID
AND ENTRYPOINT (`cbom`, cdxgen's CBOM preset). Nothing new is pulled; Engine
Coverage still reports it separately because it covers something different.

⚠ NARROW, AND SAID SO (measured 2026-09-11 against the pinned image):
  - it finds JS/TS call sites — node:crypto hashes, RSA, `jsonwebtoken.sign`,
    HMAC — with file, line and symbol;
  - it MISSES `crypto.createCipheriv` and WebCrypto, and found NO Java call site
    at all, so it runs for JS/TS only (cbomkit-action reads Java and Python);
  - it types every `.pem` file — private keys included — as a certificate, so
    those file findings are handed to cbomkit-theia, which reads and classifies
    key files correctly (normalize/extractors.py).

⚠ `-o -`, NEVER `-o /dev/stdout`. With the `cbom` preset, writing to /dev/stdout
blocked forever after "Post-processing BOM" at 0% CPU — one run was still alive
after eleven minutes. `-o -` exits in about fifteen seconds with the same
document.

⚠ `--no-install-deps` IS MANDATORY: the flag defaults to true and would run
`npm install` over customer source (invariant 7).
"""

from __future__ import annotations

from typing import Any

from axebom_shared.adapters.base import Capabilities, GenerateResult, ResultStatus, ScanTarget
from axebom_shared.adapters.summary import count_cyclonedx, summarize
from axebom_shared.sandbox import SandboxLimits, SandboxResult, WorkspaceLayout

from ...sbom.adapters.common import SandboxedAdapter
from ..normalize.extractors import EXTRACTORS
from ._source import source_coverage

SOURCE_SUFFIXES: dict[str, tuple[str, ...]] = {
    "js-source": (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"),
}

#: See `CdxgenCBOMAdapter.limits`.
_WALL_CLOCK_SEC = 300

CAPABILITIES = Capabilities(
    engine_id="cdxgen-cbom",
    families=("cbom",),
    source_kinds=("git", "upload"),
    produces=("crypto_assets",),
    native_format="cyclonedx-json-1.6",
    ecosystems=tuple(SOURCE_SUFFIXES),
    default_weight=2,
)


class CdxgenCBOMAdapter(SandboxedAdapter):
    """Runs cdxgen's `cbom` preset over a source tree."""

    media_type = "application/vnd.cyclonedx+json; version=1.6"
    requires_db_version = False

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(CAPABILITIES, **kwargs)

    def generate(self, target: ScanTarget) -> GenerateResult:
        """Not started at all when the tree holds no JavaScript or TypeScript.

        ⚠ ON A MAVEN JAVA REPOSITORY cdxgen `cbom` HANGS UNTIL KILLED. It writes
        its BOM in seconds, then builds an atom "reachables" slice — which the
        preset always does for crypto (`lib/evinser/evinser.js`:
        `if (options.withReachables || options.includeCrypto)`) — and on
        1MansiS/JavaCrypto that slice sat at 0% CPU until the 900 s wall clock
        killed it: a `timeout` on every Java repository, and every such scan
        `completed_with_errors` fifteen minutes later (live, 2026-09-11).
        `--no-deep`, plain `cdxgen --include-crypto`, and `--exclude-type java`
        all hang the same way (probed). This engine reads only JS/TS, so where
        there is none it has nothing to read and is not run.
        """
        present, uncovered = source_coverage(target.workspace, SOURCE_SUFFIXES)
        if present:
            return super().generate(target)
        availability = self.available()
        if not availability.available:
            # Still reported as what it is: an engine that could not run.
            return super().generate(target)
        return GenerateResult(
            status=ResultStatus.SUCCEEDED,
            ecosystems_uncovered=uncovered,
            engine_version=availability.version,
            diagnostics=[
                {
                    "severity": "info",
                    "code": "ENGINE_NO_SOURCE_FOR_ENGINE",
                    "message": (
                        "no JavaScript or TypeScript source in this tree; "
                        "cdxgen-cbom was not started"
                    ),
                }
            ],
        )

    def limits(self) -> SandboxLimits:
        """Five minutes, not fifteen. Measured runs take 15 s; a tree with JS/TS
        AND a Java build can still reach the reachables hang, and this bounds
        what it costs the scan."""
        return SandboxLimits(wall_clock_sec=_WALL_CLOCK_SEC)

    def entrypoint(self) -> list[str] | None:
        return ["cbom"]

    def build_argv(self, target: ScanTarget, layout: WorkspaceLayout) -> list[str]:
        return [
            "-r",
            layout.container_source,
            "-o",
            "-",
            "--spec-version",
            "1.6",
            "--no-banner",
            "--no-install-deps",
        ]

    def extra_env(self, layout: WorkspaceLayout) -> dict[str, str]:
        """The SBOM adapter's environment, plus no Maven Central lookups.

        Every variable in workers/sbom/adapters/cdxgen.py exists because a live
        run failed without it; `SEARCH_MAVEN_ORG=false` stops the lookup cdxgen
        otherwise attempts for a JAR without Maven metadata, which cannot work
        under --network=none.
        """
        scratch = layout.container_scratch
        return {
            "FETCH_LICENSE": "false",
            "CDXGEN_DEBUG_MODE": "quiet",
            "TMPDIR": scratch,
            "CDXGEN_TEMP_DIR": f"{scratch}/cdxgen-temp",
            "CDXGEN_TMP_DIR": f"{scratch}/cdxgen-temp",
            "CDXGEN_CACHE_DIR": f"{scratch}/cdxgen-cache",
            "SEARCH_MAVEN_ORG": "false",
        }

    def interpret(
        self,
        target: ScanTarget,
        payload: Any,
        result: SandboxResult,
        base: GenerateResult,
    ) -> GenerateResult:
        if not isinstance(payload, dict):
            base.status = ResultStatus.FAILED
            base.diagnostics.append(
                {
                    "severity": "error",
                    "code": "ENGINE_OUTPUT_UNEXPECTED",
                    "message": "cdxgen cbom returned a document that is not a JSON object",
                }
            )
            return base

        assets, diagnostics = EXTRACTORS["cdxgen-cbom"](payload)
        base.diagnostics.extend(diagnostics)
        base.summary = summarize(self.capabilities, count_cyclonedx(payload))

        present, uncovered = source_coverage(target.workspace, SOURCE_SUFFIXES)
        base.ecosystems_covered = present
        base.ecosystems_uncovered = uncovered

        if not assets:
            if present:
                base.status = ResultStatus.PARTIAL
                base.diagnostics.append(self.zero_result_diagnostic("cryptographic API calls"))
            else:
                base.status = ResultStatus.SUCCEEDED
                base.diagnostics.append(
                    {
                        "severity": "info",
                        "code": "ENGINE_NO_SOURCE_FOR_ENGINE",
                        "message": "no JavaScript or TypeScript source in this tree; nothing for cdxgen-cbom to read",
                    }
                )
            return base

        base.status = ResultStatus.SUCCEEDED
        return base
