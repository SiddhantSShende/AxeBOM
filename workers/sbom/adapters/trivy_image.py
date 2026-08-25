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

from axebom_shared.adapters.base import Capabilities, GenerateResult, ResultStatus, ScanTarget
from axebom_shared.adapters.summary import count_cyclonedx, summarize
from axebom_shared.sandbox import SandboxResult, WorkspaceLayout

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

    # SHARES trivy-fs's database. `trivy image` and `trivy fs` read the same
    # vulnerability DB; only the subcommand and the source kind differ.
    #
    # This was missing, and the omission made the adapter permanently dead in a
    # way that read as deliberate. SandboxedAdapter.database() returns None when
    # database_id is unset, and generate() short-circuits any adapter with
    # requires_db_version to UNAVAILABLE before starting the container. The
    # message it produced was "no provisioned None database was found" — the
    # word None being the only evidence that this was a bug rather than an
    # honest unprovisioned engine.
    database_id = "trivy"

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

    #: The fetcher writes the exported image here, inside the scan workspace.
    #: Same shape as grype's dependency on sbom.cdx.json: an engine that needs
    #: an artefact another step produces looks for it at a known name.
    TARBALL_NAME = "image.tar"

    def input_gap(self, target: ScanTarget) -> str | None:
        """trivy-image needs an EXPORTED TARBALL, not a reference.

        ⚠ THIS ADAPTER'S ORIGINAL PREMISE WAS WRONG.

        It documented "the image must already be in the daemon's store — pulled
        by the fetcher". Being in the daemon's store is of no use to the engine:
        it runs with --network=none and, deliberately, with no Docker socket, so
        it can reach none of trivy's four image sources. The real error is:

            unable to find the specified image in
            ["docker" "containerd" "podman" "remote"]
              * docker error:     ... dial unix /var/run/docker.sock: no such file
              * containerd error: ... socket not found
              * podman error:     ... no podman socket found
              * remote error:     ... network is unreachable

        Mounting the socket to fix this would hand a container that runs
        untrusted third-party binaries the equivalent of host root, which is the
        one thing the sandbox exists to prevent.

        So the image must be materialised OUTSIDE the sandbox — by the fetcher,
        the only component permitted to reach a registry — and scanned as a
        tarball. Until the fetcher does that, this is a stated gap rather than a
        failing engine.
        """
        if not target.image_digest:
            return "trivy-image needs a digest-pinned image reference; none was supplied"

        if "@sha256:" not in target.image_digest:
            return (
                f"trivy-image needs a DIGEST-pinned reference, got {target.image_digest!r}: "
                "a tag is mutable, so a report naming one cannot say what was examined"
            )

        tarball = target.workspace / self.TARBALL_NAME
        if not tarball.is_file():
            return (
                f"trivy-image needs an exported image tarball at {self.TARBALL_NAME}, which the "
                "fetcher has not produced. The engine cannot pull it itself: the sandbox has no "
                "network and no daemon socket, by design"
            )
        return None

    def build_argv(self, target: ScanTarget, layout: WorkspaceLayout) -> list[str]:
        """Scan the exported tarball.

        Two constraints shape this command, and both are load-bearing.

        ⚠ --input, NOT a reference. See input_gap.

        ⚠ THE DATABASE MOUNT IS READ-ONLY, AND trivy WRITES INTO ITS CACHE DIR.
        Pointing --cache-dir straight at /enginedb fails with

            unable to initialize fs cache: failed to create cache dir:
            mkdir /enginedb/fanal: read-only file system

        because `trivy image` maintains a layer cache alongside the database.
        (`trivy fs` does not, which is why only image mode hits this.) Making
        the mount writable is not an option — a writable host mount is how a
        container escape becomes host compromise.

        So the cache directory lives on the writable tmpfs and the database is
        symlinked into it: trivy writes fanal to tmpfs and reads db from the
        read-only mount.
        """
        cache = f"{layout.container_scratch}/trivy-cache"
        tarball = f"{layout.container_source}/{self.TARBALL_NAME}"

        return [
            "-c",
            (
                f"set -e; mkdir -p {cache}; "
                # -n so a retry inside the same workspace does not nest links.
                f"ln -sfn /enginedb/db {cache}/db; "
                f"exec trivy image --input {tarball} "
                f"--format cyclonedx --scanners vuln "
                f"--skip-db-update --skip-java-db-update "
                f"--cache-dir {cache} --quiet"
            ),
        ]

    def entrypoint(self) -> list[str] | None:
        # A shell, because the cache directory has to be prepared before trivy
        # starts. The trivy image is Alpine-based and has /bin/sh.
        return ["sh"]

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
        base.summary = summarize(self.capabilities, count_cyclonedx(payload))

        if not components:
            base.status = ResultStatus.PARTIAL
            base.diagnostics.append(self.zero_result_diagnostic("components"))
            return base

        base.status = ResultStatus.SUCCEEDED
        return base
