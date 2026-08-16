"""syft — component cataloguing.

syft is the INVENTORY engine: it catalogues components and licenses and matches
no vulnerabilities, which is why it needs no ``engine_db_version``.

Its output is also grype's input. See grype.py for why that matters.
"""

from __future__ import annotations

from typing import Any

from encorebom_shared.adapters.base import Capabilities, GenerateResult, ResultStatus, ScanTarget
from encorebom_shared.sandbox import SandboxResult, WorkspaceLayout

from .common import SandboxedAdapter, ecosystems_from_purls

CAPABILITIES = Capabilities(
    engine_id="syft",
    families=("sbom",),
    source_kinds=("git", "upload", "image"),
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
        "deb",
        "rpm",
        "apk",
        "conan",
        "swift",
    ),
    default_weight=3,
    graph_trust={"golang": 3, "npm": 2, "pypi": 2, "maven": 2},
)


class SyftAdapter(SandboxedAdapter):
    """Runs syft over a directory."""

    media_type = "application/vnd.cyclonedx+json; version=1.6"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(CAPABILITIES, **kwargs)

    def build_argv(self, target: ScanTarget, layout: WorkspaceLayout) -> list[str]:
        """Catalogue the source tree.

        CycloneDX to STDOUT, because the sandbox has no writable host mount —
        every mount is read-only, deliberately.

        docs/04-OSINT-INTEGRATION.md §3 also asks for SPDX from the same
        invocation. syft cannot write two formats to stdout at once, so SPDX is
        a SECOND run. Producing one format and claiming both would be worse than
        an extra container start.
        """
        return [f"dir:{layout.container_source}", "-o", "cyclonedx-json", "-q"]

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
                    "message": "syft returned a document that is not a JSON object",
                }
            )
            return base

        # Defensive: a missing `components` key is a shape change, not a crash.
        components = payload.get("components")
        if components is None:
            base.diagnostics.append(
                {
                    "severity": "warn",
                    "code": "ENGINE_FIELD_MISSING",
                    "message": "syft output has no `components` array",
                    "hint": "treated as zero components; the output shape may have changed",
                }
            )
            components = []
        if not isinstance(components, list):
            components = []

        purls = [
            c.get("purl", "")
            for c in components
            if isinstance(c, dict) and isinstance(c.get("purl"), str)
        ]
        base.ecosystems_covered = ecosystems_from_purls(purls)

        if not components:
            # ⚠ ZERO IS A CLAIM. partial, not succeeded.
            base.status = ResultStatus.PARTIAL
            base.diagnostics.append(self.zero_result_diagnostic("components"))
            return base

        base.status = ResultStatus.SUCCEEDED

        # Components with no PURL cannot be merged on the canonical key, so
        # Phase 8 falls back to a weaker identity for them. Surfaced HERE, where
        # the count is known, rather than discovered as a dedup anomaly later.
        without_purl = len(components) - len(purls)
        if without_purl > 0:
            base.diagnostics.append(
                {
                    "severity": "info",
                    "code": "COMPONENT_WITHOUT_PURL",
                    "message": f"{without_purl} of {len(components)} components have no PURL",
                    "hint": "these fall back to a weaker identity during normalization",
                }
            )

        return base


class SyftSPDXAdapter(SyftAdapter):
    """The second syft pass, producing SPDX.

    A separate pass rather than a second output flag: syft writes one format to
    stdout, and the sandbox has no writable mount to collect a second file from.
    Both formats are required by CERT-In's Automation Support minimum element,
    so producing only one is not an option.
    """

    media_type = "application/spdx+json"

    def build_argv(self, target: ScanTarget, layout: WorkspaceLayout) -> list[str]:
        return [f"dir:{layout.container_source}", "-o", "spdx-json", "-q"]

    def interpret(
        self,
        target: ScanTarget,
        payload: Any,
        result: SandboxResult,
        base: GenerateResult,
    ) -> GenerateResult:
        if not isinstance(payload, dict):
            base.status = ResultStatus.FAILED
            return base

        packages = payload.get("packages")
        if not isinstance(packages, list):
            packages = []

        base.status = ResultStatus.SUCCEEDED if packages else ResultStatus.PARTIAL
        if not packages:
            base.diagnostics.append(self.zero_result_diagnostic("packages"))
        return base
