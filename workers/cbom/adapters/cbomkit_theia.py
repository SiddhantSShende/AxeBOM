"""cbomkit-theia — cryptographic material and configuration discovery.

⚠ IT DOES NOT READ SOURCE CODE. theia finds certificate files, key files,
secrets (its secrets plugin wraps gitleaks), OpenSSL configuration and
java.security policy, in directories and container images. Cryptography used
in code — `Cipher.getInstance`, `hashlib.md5` — is invisible to it; that is the
source engines' job. Its own README says so.

⚠ CONTAINER-ONLY, AND NOT AS A PREFERENCE.

v1.1.2 ships NO binary assets — the releases are source-only. The container is
the only distributed artifact, so there is no local-binary fallback to write
and none should be added (OSINT/tools.manifest.yaml, ADR-0002).

⚠ PARSING LIVES IN workers/cbom/normalize/cyclonedx_crypto.py, shared by every
engine that emits CycloneDX crypto components. The names it exports are
re-exported here so existing importers keep working.
"""

from __future__ import annotations

from typing import Any

from axebom_shared.adapters.base import Capabilities, GenerateResult, ResultStatus, ScanTarget
from axebom_shared.adapters.summary import count_cyclonedx, summarize
from axebom_shared.sandbox import SandboxResult, WorkspaceLayout

from ...sbom.adapters.common import SandboxedAdapter
from ..normalize.cyclonedx_crypto import KNOWN_ASSET_TYPES, map_asset_type
from ..normalize.extractors import EXTRACTORS
from ._source import source_coverage

__all__ = [
    "CAPABILITIES",
    "KNOWN_ASSET_TYPES",
    "CBOMkitTheiaAdapter",
    "extract_crypto_assets",
    "map_asset_type",
    "no_material_diagnostic",
    "plugins_run",
]

CAPABILITIES = Capabilities(
    engine_id="cbomkit-theia",
    families=("cbom", "qbom"),
    source_kinds=("git", "upload", "image"),
    produces=("crypto_assets",),
    native_format="cyclonedx-json-1.6",
    # ⚠ NOT PACKAGE ECOSYSTEMS. theia's "coverage" is a set of discovery
    # surfaces rather than the npm/pypi/maven vocabulary the SBOM engines use.
    # Reusing that vocabulary would make Engine Coverage claim theia covered
    # `npm`, which would be read as "it scanned the npm dependencies".
    ecosystems=("source", "certificates", "tls-config", "java-security"),
    default_weight=3,
)


def extract_crypto_assets(
    payload: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """theia's document through the same extractor the normalizer uses, so the
    counts this run reports and the assets written come from one parse — secret
    findings included, which are credentials and never crypto material."""
    return EXTRACTORS["cbomkit-theia"](payload)


#: Diagnostics that report something found in the source, never a problem with
#: the run itself.
_FINDING_CODES = frozenset({"CBOM_SECRET_IN_SOURCE"})


class CBOMkitTheiaAdapter(SandboxedAdapter):
    """Runs cbomkit-theia over a directory or an image."""

    media_type = "application/vnd.cyclonedx+json; version=1.6"
    #: No vulnerability database: theia discovers, it does not match advisories.
    requires_db_version = False

    #: The fetcher exports an image source here, inside the scan workspace — the
    #: same file trivy-image scans (workers/sbom/adapters/trivy_image.py).
    TARBALL_NAME = "image.tar"

    def __init__(self, mode: str = "auto", **kwargs: Any) -> None:
        # ⚠ "auto" IS THE DEFAULT, AND IMAGE MODE NEVER RAN UNTIL IT WAS. The
        # worker constructs every adapter with no arguments, so the old default of
        # "dir" meant an image source was scanned as a directory holding one
        # tarball. The mode now follows the target's source kind.
        if mode not in {"auto", "dir", "image"}:
            raise ValueError(f"cbomkit-theia mode must be auto, dir or image, not {mode!r}")
        self.mode = mode
        super().__init__(CAPABILITIES, **kwargs)

    def _image_mode(self, target: ScanTarget) -> bool:
        return self.mode == "image" or (self.mode == "auto" and target.kind == "image")

    def extra_env(self, layout: WorkspaceLayout) -> dict[str, str]:
        """Give the tool a writable HOME and TMPDIR on the tmpfs.

        cbomkit-theia creates an application folder under $HOME on startup; the
        rootfs is read-only and the engine runs as uid 65534, so the default
        resolves somewhere unwritable.

        ⚠ TMPDIR IS NOT OPTIONAL IN IMAGE MODE, AND ITS FAILURE IS SILENT. With the
        default, image mode logs `mkdir /tmp/stereoscope-…: read-only file system`
        and exits 0 with EMPTY stdout (measured against the pinned image,
        2026-09-11) — an image with no crypto and an image never read look the same.
        """
        return {"HOME": layout.container_scratch, "TMPDIR": layout.container_scratch}

    def input_gap(self, target: ScanTarget) -> str | None:
        """Image mode reads the fetcher's EXPORTED TARBALL, never a registry.

        A registry reference would need network, which the sandbox does not have
        (invariant 7). Same contract, and the same message shape, as trivy-image.
        """
        if not self._image_mode(target):
            return None
        if not target.image_digest or "@sha256:" not in target.image_digest:
            return (
                "cbomkit-theia image mode needs a DIGEST-pinned image reference: a tag is "
                "mutable, so a report naming one cannot say what was examined"
            )
        if not (target.workspace / self.TARBALL_NAME).is_file():
            return (
                f"cbomkit-theia image mode needs the exported image tarball at "
                f"{self.TARBALL_NAME}, which the fetcher has not produced; the engine cannot "
                "pull it itself — the sandbox has no network and no daemon socket, by design"
            )
        return None

    def build_argv(self, target: ScanTarget, layout: WorkspaceLayout) -> list[str]:
        """Discover crypto material and write CycloneDX to stdout.

        The sandbox has no writable host mount, so stdout is the only channel
        out; cbomkit-theia writes its CBOM to stdout natively.

        ⚠ THE ARGV WAS WRONG FOR v1.1.2 AND HAD NEVER BEEN RUN. It built
        ``dir get <path> --quiet``; the real form is ``cbomkit-theia dir <path>``.
        Image mode takes a `docker save` tarball path — verified offline against
        the pinned image with TMPDIR on the tmpfs.
        """
        if self._image_mode(target):
            return ["image", f"{layout.container_source}/{self.TARBALL_NAME}"]
        return ["dir", layout.container_source]

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
                    "message": "cbomkit-theia returned a document that is not a JSON object",
                }
            )
            return base

        assets, diagnostics = extract_crypto_assets(payload)
        base.diagnostics.extend(diagnostics)

        # Discovery surfaces, not package ecosystems.
        base.ecosystems_covered = sorted({a["surface"] for a in assets if a.get("surface")})
        # theia reads files, never code: every source language present is one it
        # did not read. A source engine in the same scan that did read it turns
        # the row into coverage (CoverageGaps), so this is a gap only when none did.
        _, base.ecosystems_uncovered = source_coverage(target.workspace, {})

        # Counted from the DOCUMENT, not from `assets`. The summary describes
        # the raw artifact, which is the immutable evidence (ADR-0003).
        base.summary = summarize(self.capabilities, count_cyclonedx(payload))

        if not assets:
            # ⚠ WHAT "NOTHING" MEANS DEPENDS ON WHAT KIND OF SCANNER SAID IT.
            #
            # This was `partial` unconditionally, on the reasoning that an empty
            # result is more often "theia could not read this layout" than "there
            # is no crypto here". That is right for a SOURCE engine and wrong for
            # this one. theia is a file-pattern scanner, and "this tree holds no
            # certificate, key or crypto-config files" is a true, checkable
            # negative that nearly every application repository states. Kept
            # `partial`, it made every such repo's CBOM scan
            # `completed_with_errors`, training a reader to ignore the status.
            #
            # So a CLEAN empty result succeeds, with an info diagnostic naming
            # what was examined — the zero is still an explicit claim. Anything
            # that went wrong on the way to nothing already left a warning and
            # stays `partial`.
            #
            # ⚠ A FINDING IS NOT A FAILURE. `CBOM_SECRET_IN_SOURCE` is a warning
            # about the SOURCE, not about the run: counted here, a repository
            # whose only theia hits were gitleaks strings in its README made the
            # run `partial` and the scan `completed_with_errors` (live, 2026-09-11).
            if any(
                d.get("severity") in ("warn", "error") and d.get("code") not in _FINDING_CODES
                for d in diagnostics
            ):
                base.status = ResultStatus.PARTIAL
                return base
            base.status = ResultStatus.SUCCEEDED
            base.diagnostics.append(no_material_diagnostic(payload))
            return base

        unknown = sum(1 for a in assets if a["asset_type"] not in KNOWN_ASSET_TYPES)
        base.status = ResultStatus.PARTIAL if unknown else ResultStatus.SUCCEEDED
        return base


def no_material_diagnostic(payload: dict[str, Any]) -> dict[str, Any]:
    """State what theia examined when it found nothing — the zero, made explicit.

    ⚠ IT SAYS NOTHING ABOUT CODE, AND SAYS SO. theia does not read source, so an
    empty theia result is no evidence that the code uses no cryptography; the
    hint carries that sentence so the negative cannot be read wider than it is.
    """
    plugins = plugins_run(payload)
    ran = (
        f"plugins run: {', '.join(plugins)}. "
        if plugins
        else "the engine did not report which plugins ran. "
    )
    return {
        "severity": "info",
        "code": "ENGINE_NO_CRYPTO_MATERIAL",
        "message": (
            "cbomkit-theia found no certificates, keys, secrets or crypto "
            "configuration files in this source"
        ),
        "hint": ran + "theia does not read source code, so this says nothing about "
        "cryptography used in the code itself",
    }


def plugins_run(payload: dict[str, Any]) -> list[str]:
    """The plugin names theia lists under `metadata.tools.services[].services[]`."""
    metadata = payload.get("metadata")
    tools = metadata.get("tools") if isinstance(metadata, dict) else None
    services = tools.get("services") if isinstance(tools, dict) else None
    names: set[str] = set()
    if isinstance(services, list):
        for service in services:
            inner = service.get("services") if isinstance(service, dict) else None
            if not isinstance(inner, list):
                continue
            for plugin in inner:
                name = plugin.get("name") if isinstance(plugin, dict) else None
                if isinstance(name, str) and name.strip():
                    names.add(name.strip())
    return sorted(names)
