"""github-dependency-graph-sbom — the repository's own CI-published SBOM.

⚠ THIS IS AN IMPORT, NOT DISCOVERY.

GitHub's Dependency Graph SBOM export is the repository's own declaration of
its dependencies — closer in spirit to hbom-csv's CSV import than to syft's
independent inventory of the tree. It is ingested as ONE MORE cross-checked
input, never authoritative on its own: the normalizer's dedup-by-purl treats
this exactly like any other engine's components, with no special trust
weighting, and a repo can under- or over-declare its own graph just as easily
as any human-maintained manifest can.

⚠ NO SANDBOX, NO CONTAINER, NO NETWORK OF ITS OWN.

The fetcher already made the one call to GitHub's API this needs — using the
same repo-scoped credential already in hand for the clone — and staged the
result as a raw artifact (services/fetcher/internal/work/work.go's
fetchDependencyGraphSBOM). This adapter's only job is to read that file back
off local disk (fetched into the job's ScanTarget.native_sbom_path by
axebom_shared.source.materialize_native_sbom, wired into runner.py) and wrap
it as a raw artifact of its own. If the document was never staged — the repo
isn't on GitHub, Dependency Graph is disabled, the token lacked access, or the
API call failed — this reports `unavailable`, honestly, not `failed`: nothing
here was supposed to run and didn't, which is exactly what Engine Coverage
exists to say.

⚠ WHERE THE ACTUAL PARSING HAPPENS.

Unlike every SandboxedAdapter subclass, this class does not implement
`parse()` — nothing in the runtime pipeline calls it (ingestion runs from
`scan.raw_artifacts` directly, in `normalize_consumer.py`, dispatched by
`axebom_shared.normalize.ingest.ingest()`'s `_PARSERS` table). The staged
document is genuine, standalone SPDX 2.3 JSON — the fetcher unwraps GitHub's
`{"sbom": {...}}` envelope before ever storing it — so it is registered
against the SAME `_ingest_spdx` parser `syft-spdx` already uses, with no new
parsing code at all.
"""

from __future__ import annotations

import json
from typing import Any

from axebom_shared.adapters.base import (
    Availability,
    Capabilities,
    EngineMode,
    GenerateResult,
    RawArtifact,
    ResultStatus,
    ScanTarget,
    ToolAdapterBase,
)
from axebom_shared.adapters.summary import summarize

from .common import ArtifactWriter

CAPABILITIES = Capabilities(
    engine_id="github-dependency-graph-sbom",
    families=("sbom",),
    source_kinds=("git",),
    produces=("components",),
    native_format="spdx-json-2.3",
    ecosystems=("generic",),
    db_backed=False,
    default_weight=1,
)


class GitHubDependencyGraphAdapter(ToolAdapterBase):
    """Imports a GitHub repository's own Dependency Graph SBOM."""

    media_type = "application/spdx+json"

    def __init__(self, *, artifact_dir: Any = None, **_: Any) -> None:
        # `**_` absorbs `sandbox=...`, which runner.py passes to every adapter
        # uniformly — this one never touches it and never will, since there is
        # no container to invoke here.
        super().__init__(CAPABILITIES)
        self._artifact_dir = artifact_dir

    def available(self) -> Availability:
        """Environmentally, this engine is always usable — it is an API call
        the fetcher already made, not a locally-installed tool. Whether THIS
        job's document was actually staged is a per-job question, answered in
        generate(), not here — exactly the split SandboxedAdapter's own
        `available()` (environment) vs. `input_gap()` (per-target) draws.
        """
        return Availability(available=True, mode=EngineMode.INTERNAL)

    def generate(self, target: ScanTarget) -> GenerateResult:
        """Read the staged document and wrap it as a raw artifact.

        Never raises: every failure mode here — no document staged, an
        unreadable file, invalid JSON, an unexpected shape — becomes a status
        plus a diagnostic, matching the contract every adapter in this
        codebase honors.
        """
        if target.native_sbom_path is None or not target.native_sbom_path.is_file():
            return GenerateResult(
                status=ResultStatus.UNAVAILABLE,
                diagnostics=[
                    {
                        "severity": "warn",
                        "code": "ENGINE_INPUT_MISSING",
                        "message": "no GitHub Dependency Graph SBOM was staged for this scan",
                        "hint": (
                            "the connected repository may not be on GitHub, may not have "
                            "Dependency Graph enabled, or the fetcher's API call may have "
                            "failed — this is a stated coverage gap, not a scan failure"
                        ),
                    }
                ],
            )

        try:
            raw = target.native_sbom_path.read_bytes()
        except OSError as exc:
            return GenerateResult(
                status=ResultStatus.UNAVAILABLE,
                diagnostics=[
                    {
                        "severity": "error",
                        "code": "ENGINE_INPUT_MISSING",
                        "message": f"the staged document could not be read: {exc}",
                    }
                ],
            )

        artifact = self._write_artifact(raw)

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            return GenerateResult(
                status=ResultStatus.FAILED,
                artifacts=[artifact] if artifact else [],
                diagnostics=[
                    {
                        "severity": "error",
                        "code": "ENGINE_OUTPUT_UNPARSEABLE",
                        "message": f"the staged document is not valid JSON: {exc}",
                    }
                ],
            )

        if not isinstance(payload, dict):
            return GenerateResult(
                status=ResultStatus.FAILED,
                artifacts=[artifact] if artifact else [],
                diagnostics=[
                    {
                        "severity": "error",
                        "code": "ENGINE_OUTPUT_UNEXPECTED",
                        "message": "the staged document is not a JSON object",
                    }
                ],
            )

        packages = payload.get("packages")
        if not isinstance(packages, list):
            return GenerateResult(
                status=ResultStatus.PARTIAL,
                artifacts=[artifact] if artifact else [],
                summary=summarize(self.capabilities, {"components": 0}),
                diagnostics=[
                    {
                        "severity": "warn",
                        "code": "ENGINE_FIELD_MISSING",
                        "message": "the staged document has no SPDX 'packages' array",
                    }
                ],
            )

        # A real SPDX document names its own scan target as a package too
        # (the document root) alongside its actual dependencies — that entry
        # carries no PURL. Excluded from the count so this engine's
        # `components` figure means what every other SBOM engine's means:
        # dependencies, not the project describing itself.
        components = [p for p in packages if isinstance(p, dict) and _has_purl(p)]

        if not components:
            return GenerateResult(
                status=ResultStatus.PARTIAL,
                artifacts=[artifact] if artifact else [],
                summary=summarize(self.capabilities, {"components": 0}),
                diagnostics=[
                    {
                        "severity": "warn",
                        "code": "ENGINE_ZERO_RESULTS",
                        "message": "github-dependency-graph-sbom found no packages with a PURL",
                        "hint": (
                            "reported as partial rather than succeeded: zero is a claim, and "
                            "a silent zero is indistinguishable from a project with nothing "
                            "declared"
                        ),
                    }
                ],
            )

        return GenerateResult(
            status=ResultStatus.SUCCEEDED,
            artifacts=[artifact] if artifact else [],
            summary=summarize(self.capabilities, {"components": len(components)}),
        )

    def _write_artifact(self, raw: bytes) -> RawArtifact | None:
        if self._artifact_dir is None:
            return None
        try:
            return ArtifactWriter(output_dir=self._artifact_dir).write(
                "github-dependency-graph-sbom.json", raw, self.media_type
            )
        except OSError:
            # Not fatal: the components below are still reported. Without the
            # artifact this run cannot be re-normalized later without
            # re-fetching, which is a real but survivable loss — the same
            # tradeoff SandboxedAdapter.generate() makes for the same reason.
            return None


def _has_purl(package: dict[str, Any]) -> bool:
    for ref in package.get("externalRefs", []) or []:
        if isinstance(ref, dict) and str(ref.get("referenceType", "")).lower() == "purl":
            return True
    return False
