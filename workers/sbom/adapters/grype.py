"""grype — vulnerability matching against OUR syft SBOM.

⚠ GRYPE RUNS AGAINST THE SYFT SBOM, NOT THE DIRECTORY.

Pointing grype at the source tree would make it catalogue components ITSELF,
producing a second, subtly different inventory to reconcile against syft's — and
reconciling two inventories is exactly the work the normalizer exists to avoid.
Matching against our own SBOM means every finding refers to a component that is
already in the BOM, under the same identity.

It is a vulnerability engine, so ``engine_db_version`` is REQUIRED: a finding
that cannot be dated is not defensible.
"""

from __future__ import annotations

from typing import Any

from encorebom_shared.adapters.base import Capabilities, GenerateResult, ResultStatus, ScanTarget
from encorebom_shared.adapters.summary import count_distinct_vulnerabilities, summarize
from encorebom_shared.sandbox import SandboxResult, WorkspaceLayout

from .common import SandboxedAdapter, ecosystems_from_purls

CAPABILITIES = Capabilities(
    engine_id="grype",
    families=("sbom",),
    source_kinds=("git", "upload", "image"),
    produces=("vulnerabilities",),
    native_format="grype-json",
    ecosystems=("npm", "pypi", "maven", "golang", "gem", "cargo", "nuget", "deb", "rpm", "apk"),
    db_backed=True,
    default_weight=3,
)


class GrypeAdapter(SandboxedAdapter):
    """Matches vulnerabilities against a supplied SBOM."""

    media_type = "application/json"
    requires_db_version = True
    database_id = "grype"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(CAPABILITIES, **kwargs)

    def database_env(self, database: Any) -> dict[str, str]:
        """Point grype at the provisioned database and forbid it updating.

        ``GRYPE_DB_AUTO_UPDATE=false`` matters even though the sandbox has no
        network: without it grype spends its startup budget on a connection that
        cannot succeed, and reports the timeout rather than the real state.

        ``GRYPE_DB_VALIDATE_AGE=false`` is set because WE decide what counts as
        stale, from the provisioner's stamp. grype's own age check would refuse
        to run at all, turning a reportable "database is N days old" into an
        opaque failure.
        """
        return {
            "GRYPE_DB_CACHE_DIR": self.database_target,
            "GRYPE_DB_AUTO_UPDATE": "false",
            "GRYPE_DB_VALIDATE_AGE": "false",
        }

    def build_argv(self, target: ScanTarget, layout: WorkspaceLayout) -> list[str]:
        """Match against the SBOM syft produced.

        ``target.sbom_path`` is set by the runner from syft's artifact. There is
        deliberately NO fallback to scanning the directory: that fallback would
        silently produce the second inventory this whole design avoids, and it
        would do so exactly when syft had failed and nobody was looking.
        """
        if target.sbom_path is None:
            raise ValueError(
                "grype requires the syft SBOM; scanning the directory would produce a "
                "second component inventory to reconcile (docs/04-OSINT-INTEGRATION.md §3)"
            )
        # ⚠ NO -q.
        #
        # grype's quiet flag suppresses the stderr lines that say WHY a run
        # failed — including "failed to load vulnerability db: database does not
        # exist", which is the difference between `unavailable` (no database)
        # and `failed` (something else). With -q, a missing database is
        # indistinguishable from a crash, and the classifier cannot tell a
        # reader which one happened.
        #
        # JSON still goes to stdout; the logs go to stderr, so the output is
        # unaffected.
        return [f"sbom:{layout.container_source}/{target.sbom_path.name}", "-o", "json"]

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
                    "message": "grype returned a document that is not a JSON object",
                }
            )
            return base

        # ⚠ THE DATABASE VERSION IS NOT OPTIONAL.
        db_version = db_version_of(payload)
        if not db_version:
            base.status = ResultStatus.UNAVAILABLE
            base.diagnostics.append(
                self.db_stale_diagnostic(
                    "grype reported no database version, so its findings cannot be dated"
                )
            )
            return base
        base.engine_db_version = db_version

        matches = payload.get("matches")
        if matches is None:
            base.diagnostics.append(
                {
                    "severity": "warn",
                    "code": "ENGINE_FIELD_MISSING",
                    "message": "grype output has no `matches` array",
                    "hint": "treated as zero findings; the output shape may have changed",
                }
            )
            matches = []
        if not isinstance(matches, list):
            matches = []

        purls: list[str] = []
        for m in matches:
            if not isinstance(m, dict):
                continue
            artifact = m.get("artifact")
            if isinstance(artifact, dict) and isinstance(artifact.get("purl"), str):
                purls.append(artifact["purl"])
        base.ecosystems_covered = ecosystems_from_purls(purls)

        # DISTINCT vulnerabilities, not matches. grype emits one match per
        # (vulnerability, package) pair, so one CVE across three packages is
        # three rows — and counting rows would make the same project look three
        # times worse under grype than under trivy, in a field named
        # `vulnerabilities`.
        base.summary = summarize(
            self.capabilities,
            {
                "vulnerabilities": count_distinct_vulnerabilities(
                    (m.get("vulnerability") or {}).get("id")
                    for m in matches
                    if isinstance(m, dict) and isinstance(m.get("vulnerability"), dict)
                )
            },
        )

        # ⚠ ZERO VULNERABILITIES IS LEGITIMATE HERE, unlike zero components from
        # a cataloguing engine. A patched project genuinely has none, and
        # calling that `partial` would cry wolf on every well-maintained
        # codebase — which is how a warning stops being read.
        base.status = ResultStatus.SUCCEEDED
        if not matches:
            base.diagnostics.append(
                {
                    "severity": "info",
                    "code": "ENGINE_ZERO_FINDINGS",
                    "message": "grype matched no vulnerabilities",
                    "hint": f"matched against {db_version}",
                }
            )
        return base


def db_version_of(payload: dict[str, Any]) -> str:
    """Extract the vulnerability-database vintage, defensively.

    grype has moved this field between releases, so several shapes are tried
    rather than assuming the current one. Returning "" — and therefore
    ``unavailable`` — is the safe direction: emitting UNDATED findings is worse
    than emitting none, because a reader cannot tell how stale they are.
    """
    descriptor = payload.get("descriptor")
    if not isinstance(descriptor, dict):
        return ""

    db = descriptor.get("db")
    if isinstance(db, dict):
        built = db.get("built") or db.get("buildTimestamp")
        schema = db.get("schemaVersion") or db.get("schema")
        if built and schema:
            return f"grype-db schema {schema} built {built}"
        if built:
            return f"grype-db built {built}"

    version = descriptor.get("version")
    if isinstance(version, str) and version:
        return f"grype {version}"
    return ""
