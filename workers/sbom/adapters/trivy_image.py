"""trivy-image — container image scanning.

A SEPARATE ENGINE from trivy-fs, not the same tool with a different flag:
different subcommand, different source kind, different scanners, and a different
output parser. See trivy_fs.py.

⚠ THE IMAGE MUST BE DIGEST-PINNED.

A tag is mutable. `acme/api:latest` scanned twice can be two different images,
and a compliance report naming a tag says nothing about what was examined. The
adapter refuses a tag rather than scanning something it cannot name precisely.
"""

from __future__ import annotations

from typing import Any

from encorebom_shared.adapters.base import Capabilities, GenerateResult, ResultStatus, ScanTarget
from encorebom_shared.sandbox import SandboxResult, WorkspaceLayout

from .common import SandboxedAdapter, ecosystems_from_purls
from .trivy_fs import trivy_db_version

CAPABILITIES = Capabilities(
    engine_id="trivy-image",
    families=("sbom",),
    source_kinds=("image",),
    produces=("components", "vulnerabilities", "licenses"),
    native_format="cyclonedx-json-1.6",
    ecosystems=("deb", "rpm", "apk", "npm", "pypi", "golang"),
    db_backed=True,
    default_weight=3,
)


class TrivyImageAdapter(SandboxedAdapter):
    """Runs `trivy image` against a digest-pinned reference."""

    media_type = "application/vnd.cyclonedx+json; version=1.6"
    requires_db_version = True

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(CAPABILITIES, **kwargs)

    def extra_env(self, layout: WorkspaceLayout) -> dict[str, str]:
        """Point trivy's scratch space at the writable tmpfs.

        ⚠ WITHOUT THIS, EVERY TRIVY RUN FAILS.

        trivy creates a temporary directory during post-analysis. The sandbox
        rootfs is read-only, so `/tmp` is not writable, and the failure reads:

            failed to prepare filesystem for post analysis:
            unable to create temporary directory: read-only file system

        which names neither trivy's needs nor the sandbox policy. The workspace
        tmpfs is the only writable path in the container.
        """
        return {"TMPDIR": layout.container_scratch}

    def build_argv(self, target: ScanTarget, layout: WorkspaceLayout) -> list[str]:
        """Scan a container image.

        ⚠ THIS ENGINE NEEDS THE IMAGE LOCALLY. The sandbox runs with
        `--network=none`, so trivy cannot pull. The image must already be in the
        daemon's store — pulled by the fetcher, which is the only component
        permitted to reach a registry.

        Refusing a tag is not pedantry: an unpinned reference makes the report
        unable to say what it scanned.
        """
        digest = target.image_digest
        if not digest:
            raise ValueError("trivy-image requires an image digest; none was supplied")
        if "@sha256:" not in digest:
            raise ValueError(
                f"trivy-image requires a DIGEST-pinned reference, got {digest!r}: "
                "a tag is mutable, and a report naming a tag says nothing about "
                "what was actually scanned"
            )

        return [
            "image",
            "--format",
            "cyclonedx",
            "--skip-db-update",
            "--skip-java-db-update",
            "--cache-dir",
            f"{layout.container_scratch}/trivy-cache",
            "--quiet",
            digest,
        ]

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
                    "message": "trivy-image returned a document that is not a JSON object",
                }
            )
            return base

        # The provisioner's stamp is already in place; only replace it when
        # trivy states something more precise. Assigning unconditionally would
        # overwrite dated provenance with an empty string whenever trivy chose
        # not to report — losing the one fact that makes a finding datable.
        reported = trivy_db_version(payload, result.stderr)
        if reported:
            base.engine_db_version = reported
        if not base.engine_db_version:
            base.status = ResultStatus.UNAVAILABLE
            base.diagnostics.append(
                self.db_stale_diagnostic("no vulnerability-database timestamp in the output")
            )
            return base

        components = payload.get("components")
        if not isinstance(components, list):
            components = []

        purls = [
            c.get("purl", "")
            for c in components
            if isinstance(c, dict) and isinstance(c.get("purl"), str)
        ]
        base.ecosystems_covered = ecosystems_from_purls(purls)

        if not components:
            base.status = ResultStatus.PARTIAL
            base.diagnostics.append(self.zero_result_diagnostic("components"))
            return base

        base.status = ResultStatus.SUCCEEDED
        return base
