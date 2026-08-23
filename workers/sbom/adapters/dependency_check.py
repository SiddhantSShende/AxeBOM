"""dependency-check — CPE-based vulnerability matching.

⚠ THE CPE CONFIDENCE FIELD IS THE POINT OF THIS ADAPTER.

dependency-check identifies components by matching against CPE strings, which is
inherently fuzzy: it will report a LOW-confidence match between an unrelated
package and a CPE that shares a name. Phase 8 needs the confidence to refuse
those merges — a LOW-confidence CPE is attached as a CANDIDATE IDENTITY and
NEVER merged into a PURL-identified component.

Merging one would import dependency-check's false positives into a component
another engine identified precisely, and the resulting finding would look
authoritative.

Two operational facts shape the rest of this file:

    THE FIRST DATABASE SYNC TAKES 30-60 MINUTES. It must be pre-warmed; a cold
    start blows every deadline. With the sandbox at --network=none it cannot
    sync at all, so a cold volume is reported as unavailable rather than
    producing an empty result.

    JAVA 11+ IS REQUIRED, and the dev machine has Java 8. This engine is
    CONTAINER-ONLY and there is no local-JDK code path (CLAUDE.md, known
    environment constraints).
"""

from __future__ import annotations

from typing import Any

from encorebom_shared.adapters.base import Capabilities, GenerateResult, ResultStatus, ScanTarget
from encorebom_shared.sandbox import (
    SandboxLimits,
    SandboxResult,
    WorkspaceLayout,
    file_output_command,
)

from .common import SandboxedAdapter

CAPABILITIES = Capabilities(
    engine_id="dependency-check",
    families=("sbom",),
    source_kinds=("git", "upload"),
    produces=("vulnerabilities",),
    native_format="dependency-check-json",
    ecosystems=("maven", "npm", "nuget", "pypi", "golang"),
    db_backed=True,
    # Lower weight despite being the slowest: CPE identification is lower
    # confidence, so it contributes less to a merged result.
    default_weight=1,
)

#: Where dependency-check writes inside the container's tmpfs.
REPORT_DIR = "/workspace/dc-report"


class DependencyCheckAdapter(SandboxedAdapter):
    """Runs OWASP dependency-check in its container."""

    media_type = "application/json"
    requires_db_version = True

    # The NVD/CPE database, provisioned by `python -m workers.sbom.dbsync nvd`.
    #
    # This was missing, and its absence made the adapter permanently dead:
    # database() returns None without it, and generate() refuses any adapter
    # with requires_db_version before the container starts. The resulting
    # message read "no provisioned None database was found", which looks like an
    # unprovisioned engine rather than the bug it was. There was also no
    # DatabaseSpec for it in dbsync, so nothing could have provisioned it even
    # if the id had been set.
    database_id = "nvd"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(CAPABILITIES, **kwargs)

    def limits(self) -> SandboxLimits:
        """A longer wall clock and more memory than the other engines.

        dependency-check is a JVM application that walks the whole tree; the
        shared 15-minute default times it out on a large monorepo, and a
        timeout is indistinguishable from a hang to whoever reads the report.
        """
        return SandboxLimits(wall_clock_sec=1800, memory_mb=6144)

    def build_argv(self, target: ScanTarget, layout: WorkspaceLayout) -> list[str]:
        """Scan, then cat the report to stdout.

        dependency-check has NO stdout mode — it writes a report directory — and
        the sandbox has no writable host mount, so the report goes to the
        container's tmpfs and comes back through `cat`.

        ``--noupdate`` is required, not preferred: the sandbox is
        ``--network=none``, so an update attempt stalls until the wall clock
        rather than failing fast. The database must be pre-warmed into the image
        or a read-only volume.

        ⚠ NO NVD API KEY IS PASSED. A key would be a credential in an engine
        container, which ADR-0008 forbids — and with ``--noupdate`` there is
        nothing to authenticate. Pre-warming happens out of band.
        """
        tool = [
            "/usr/share/dependency-check/bin/dependency-check.sh",
            "--scan",
            layout.container_source,
            "--format",
            "JSON",
            "--out",
            REPORT_DIR,
            # Read the database we provisioned, mounted read-only at /enginedb.
            # Without this dependency-check looks in its image default
            # (/usr/share/dependency-check/data), which is empty, and then
            # --noupdate means it reports a clean project instead of failing.
            "--data",
            "/enginedb",
            "--noupdate",
            "--disableAssembly",
            "--prettyPrint",
        ]
        return file_output_command(tool, f"{REPORT_DIR}/dependency-check-report.json")

    def entrypoint(self) -> list[str] | None:
        # The image's entrypoint is the tool; the command is a shell pipeline.
        return ["sh"]

    def build_argv_for_shell(self, target: ScanTarget, layout: WorkspaceLayout) -> list[str]:
        """The argv minus the `sh` the entrypoint supplies."""
        return self.build_argv(target, layout)[1:]

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
                    "message": "dependency-check returned a document that is not a JSON object",
                }
            )
            return base

        info = payload.get("scanInfo")
        db_version = ""
        if isinstance(info, dict):
            for source in info.get("dataSource", []) or []:
                if not isinstance(source, dict):
                    continue
                name = str(source.get("name", ""))
                timestamp = source.get("timestamp")
                if "NVD" in name.upper() and timestamp:
                    db_version = f"NVD {timestamp}"
                    break

        if not db_version:
            # A cold or missing database. Reported as unavailable rather than
            # producing an empty result that reads as "no vulnerabilities".
            base.status = ResultStatus.UNAVAILABLE
            base.diagnostics.append(
                self.db_stale_diagnostic(
                    "no NVD data-source timestamp; the volume is probably cold. "
                    "The first sync takes 30-60 minutes and cannot happen inside "
                    "the sandbox, which runs with no network"
                )
            )
            return base
        base.engine_db_version = db_version

        dependencies = payload.get("dependencies")
        if not isinstance(dependencies, list):
            dependencies = []

        low_confidence = 0
        identified = 0
        for dep in dependencies:
            if not isinstance(dep, dict):
                continue
            packages = dep.get("packages") or []
            evidence = dep.get("evidenceCollected")
            confidence = highest_confidence(evidence)
            if packages or dep.get("vulnerabilities"):
                identified += 1
                if confidence in ("LOW", "MEDIUM"):
                    low_confidence += 1

        base.ecosystems_covered = list(CAPABILITIES.ecosystems)

        if not dependencies:
            base.status = ResultStatus.PARTIAL
            base.diagnostics.append(self.zero_result_diagnostic("dependencies"))
            return base

        base.status = ResultStatus.SUCCEEDED

        if low_confidence:
            # ⚠ THE DIAGNOSTIC PHASE 8 ACTS ON.
            base.diagnostics.append(
                {
                    "severity": "info",
                    "code": "CPE_LOW_CONFIDENCE",
                    "message": (
                        f"{low_confidence} of {identified} identified dependencies rest on "
                        f"LOW or MEDIUM confidence CPE matches"
                    ),
                    "hint": (
                        "these attach as CANDIDATE identities and are never merged into a "
                        "PURL-identified component; merging would import false positives "
                        "into a component another engine identified precisely"
                    ),
                }
            )

        return base


def highest_confidence(evidence: Any) -> str:
    """Return the strongest confidence level in an evidence collection.

    dependency-check nests confidence per evidence item, and the shape has
    changed between majors. Unknown shapes return "" rather than raising: an
    adapter that crashes on a shape change takes down a worker, while one that
    degrades reports reduced information.
    """
    if not isinstance(evidence, dict):
        return ""

    order = {"HIGHEST": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    best = ""
    best_rank = 0

    for items in evidence.values():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            level = str(item.get("confidence", "")).upper()
            rank = order.get(level, 0)
            if rank > best_rank:
                best, best_rank = level, rank

    return best
