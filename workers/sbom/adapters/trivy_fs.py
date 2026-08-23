"""trivy-fs — filesystem scanning.

⚠ trivy-fs AND trivy-image ARE DIFFERENT ENGINES, not one tool with a flag.

Different subcommand, different scanners, different source kinds, and — the part
that matters downstream — DIFFERENT OUTPUT PARSERS. Modelling them as one engine
would make the registry lie about what can scan what, and would put an
`image`-only result through a filesystem parser.
"""

from __future__ import annotations

from typing import Any

from encorebom_shared.adapters.base import Capabilities, GenerateResult, ResultStatus, ScanTarget
from encorebom_shared.adapters.summary import count_cyclonedx, summarize
from encorebom_shared.sandbox import SandboxResult, WorkspaceLayout

from .common import SandboxedAdapter, ecosystems_from_purls

CAPABILITIES = Capabilities(
    engine_id="trivy-fs",
    families=("sbom",),
    source_kinds=("git", "upload"),
    produces=("components", "vulnerabilities", "licenses", "secrets"),
    native_format="cyclonedx-json-1.6",
    ecosystems=("npm", "pypi", "maven", "golang", "gem", "cargo", "nuget", "deb", "rpm", "apk"),
    db_backed=True,
    default_weight=3,
    graph_trust={"npm": 2, "pypi": 2, "maven": 1},
)


class TrivyFSAdapter(SandboxedAdapter):
    """Runs `trivy fs` over a directory."""

    media_type = "application/vnd.cyclonedx+json; version=1.6"
    requires_db_version = True
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

    def build_argv(self, target: ScanTarget, layout: WorkspaceLayout) -> list[str]:
        """Scan the filesystem for components, vulnerabilities and secrets.

        ``--skip-db-update`` is not optional here: the sandbox runs with
        ``--network=none``, so an update attempt would fail after a long
        timeout rather than immediately. The database arrives pre-warmed by
        ``workers.sbom.dbsync``, and a stale one is reported rather than
        refreshed (docs/05-SECURITY-MODEL.md §3).

        ``--cache-dir`` points at the PROVISIONED database mount. It previously
        pointed at the container's empty tmpfs, which meant trivy started with
        no database on every run — it failed loudly, which is the only reason
        that did not become a silent all-clear.
        """
        return [
            "fs",
            "--scanners",
            "vuln,license,secret",
            "--format",
            "cyclonedx",
            "--skip-db-update",
            "--skip-java-db-update",
            "--cache-dir",
            self.database_target,
            "--quiet",
            layout.container_source,
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
                    "message": "trivy-fs returned a document that is not a JSON object",
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
            # trivy embeds its database vintage in CycloneDX metadata
            # properties, and the key has moved between releases. Without it a
            # finding cannot be dated.
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

        # ⚠ A PARTIAL ECOSYSTEM IS THE COMMON CASE, not an exception.
        #
        # One malformed pom.xml among twelve ecosystems is `partial` naming the
        # ecosystem — not a failed run that discards eleven good ones.
        partial = partial_ecosystems(result.stderr)
        for ecosystem, detail in partial.items():
            base.diagnostics.append(
                {
                    "severity": "warn",
                    "code": "ENGINE_PARTIAL_ECOSYSTEM",
                    "ecosystem": ecosystem,
                    "message": f"trivy-fs could not fully process {ecosystem}",
                    "hint": detail,
                }
            )

        if not components:
            base.status = ResultStatus.PARTIAL
            base.diagnostics.append(self.zero_result_diagnostic("components"))
            return base

        base.status = ResultStatus.PARTIAL if partial else ResultStatus.SUCCEEDED
        return base


def trivy_db_version(payload: dict[str, Any], stderr: str) -> str:
    """Find trivy's vulnerability-database vintage.

    Looked for in the CycloneDX metadata properties first, then stderr. Both are
    tried because trivy has moved it, and the alternative to finding it is
    reporting the engine unavailable — the safe direction, but a false negative
    if the value was there under a different key.
    """
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        for prop in metadata.get("properties", []) or []:
            if not isinstance(prop, dict):
                continue
            name = str(prop.get("name", "")).lower()
            if "db" in name and ("update" in name or "version" in name or "built" in name):
                value = prop.get("value")
                if value:
                    return f"trivy-db {value}"

        component = metadata.get("component")
        if isinstance(component, dict) and component.get("version"):
            return f"trivy {component['version']}"

    for line in stderr.splitlines():
        lowered = line.lower()
        if "vulnerability db" in lowered and ("updated" in lowered or "downloaded" in lowered):
            return f"trivy-db {line.strip()[:120]}"

    return ""


def partial_ecosystems(stderr: str) -> dict[str, str]:
    """Extract per-ecosystem failures from trivy's stderr.

    trivy reports a malformed manifest as a WARN line and carries on, which is
    the behaviour we want — but the warning is the only record that an ecosystem
    was skipped. Losing it converts a known gap into a silent one.
    """
    found: dict[str, str] = {}
    markers = {
        "pom.xml": "maven",
        "package-lock.json": "npm",
        "yarn.lock": "npm",
        "requirements.txt": "pypi",
        "poetry.lock": "pypi",
        "go.mod": "golang",
        "gemfile.lock": "gem",
        "cargo.lock": "cargo",
        "packages.lock.json": "nuget",
    }

    for line in stderr.splitlines():
        lowered = line.lower()
        if not any(w in lowered for w in ("warn", "error", "failed", "skip")):
            continue
        for marker, ecosystem in markers.items():
            if marker in lowered and ecosystem not in found:
                found[ecosystem] = line.strip()[:200]

    return found
