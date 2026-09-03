"""webrecon-fingerprint — the only SBOM engine offered for a url source.

⚠ THIS IS REAL DISCOVERY, NOT AN IMPORT.

Unlike github-dependency-graph-sbom (which imports a document GitHub already
published), services/webrecon actually performed subdomain discovery and
JS-library fingerprinting itself — over network egress that engine
containers are never granted (CLAUDE.md invariant 7), which is exactly why
that work happened in a separate service rather than a normal sandboxed
`scan.job.sbom` job. RequiresImport is deliberately False for this engine
(services/scan-orchestrator/internal/policy/registry.go) for that reason.

⚠ NO SANDBOX, NO CONTAINER, NO NETWORK OF ITS OWN.

services/webrecon already did every network-touching step: it ran subfinder
inside its own sandboxed container, fetched every discovered host's root
page and scripts through its SSRF-hardened client, matched everything
against the retire.js signature database, and staged the JSON result as a
raw artifact. This adapter's only job is to read that file back off local
disk (fetched into the job's ScanTarget.native_sbom_path by
axebom_shared.source.materialize_native_sbom, wired into runner.py — the
SAME generic mechanism github_dependency_graph.py already uses) and wrap it
as a raw artifact of its own.

⚠ WHERE THE ACTUAL PARSING HAPPENS.

Unlike every SandboxedAdapter subclass, this class does not implement
`parse()` — nothing in the runtime pipeline calls it (ingestion runs from
`scan.raw_artifacts` directly, in `normalize_consumer.py`, dispatched by
`axebom_shared.normalize.ingest.ingest()`'s `_PARSERS` table). Unlike
github-dependency-graph-sbom, this DOES need a bespoke parser
(`_ingest_webrecon_fingerprint`) — services/webrecon's JSON is AxeBOM's own
shape, not a CycloneDX or SPDX document, because there is no "native" format
for a retire.js-style fingerprint result.
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
    engine_id="webrecon-fingerprint",
    families=("sbom",),
    source_kinds=("url",),
    produces=("components",),
    native_format="axebom-webrecon-json-1",
    ecosystems=("npm",),
    db_backed=False,
    default_weight=1,
)


class WebreconFingerprintAdapter(ToolAdapterBase):
    """Parses services/webrecon's discovery + JS-fingerprint document."""

    media_type = "application/json"

    def __init__(self, *, artifact_dir: Any = None, **_: Any) -> None:
        # `**_` absorbs `sandbox=...`, which runner.py passes to every adapter
        # uniformly — this one never touches it, there is no container here.
        super().__init__(CAPABILITIES)
        self._artifact_dir = artifact_dir

    def available(self) -> Availability:
        """Environmentally, this engine is always usable — services/webrecon
        already did the work, this adapter just reads it back. Whether THIS
        job's document was actually staged is a per-job question, answered in
        generate(), matching github_dependency_graph.py's identical split.
        """
        return Availability(available=True, mode=EngineMode.INTERNAL)

    def generate(self, target: ScanTarget) -> GenerateResult:
        """Read the staged document and wrap it as a raw artifact.

        Never raises: every failure mode here — no document staged, an
        unreadable file, invalid JSON, an unexpected shape — becomes a
        status plus a diagnostic, matching the contract every adapter in
        this codebase honors.
        """
        if target.native_sbom_path is None or not target.native_sbom_path.is_file():
            return GenerateResult(
                status=ResultStatus.UNAVAILABLE,
                diagnostics=[
                    {
                        "severity": "warn",
                        "code": "ENGINE_INPUT_MISSING",
                        "message": "no webrecon discovery document was staged for this scan",
                        "hint": (
                            "services/webrecon's job may not have completed yet, or failed "
                            "before it could stage a document — this is a stated coverage "
                            "gap, not a scan failure"
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

        hosts = payload.get("hosts")
        if not isinstance(hosts, list):
            return GenerateResult(
                status=ResultStatus.PARTIAL,
                artifacts=[artifact] if artifact else [],
                summary=summarize(self.capabilities, {"components": 0}),
                diagnostics=[
                    {
                        "severity": "warn",
                        "code": "ENGINE_FIELD_MISSING",
                        "message": "the staged document has no `hosts` array",
                    }
                ],
            )

        component_count = sum(
            len(h.get("libraries", []) or []) for h in hosts if isinstance(h, dict)
        )
        unreachable = sum(
            1 for h in hosts if isinstance(h, dict) and h.get("status") != "succeeded"
        )

        diagnostics: list[dict[str, Any]] = []
        if unreachable:
            diagnostics.append(
                {
                    "severity": "info",
                    "code": "WEBRECON_HOST_UNREACHABLE",
                    "message": f"{unreachable} of {len(hosts)} host(s) could not be "
                    "fetched or fingerprinted",
                    "hint": "a per-host gap, not a scan failure — see the raw artifact "
                    "for which hosts and why",
                }
            )

        if component_count == 0:
            return GenerateResult(
                status=ResultStatus.PARTIAL,
                artifacts=[artifact] if artifact else [],
                summary=summarize(self.capabilities, {"components": 0}),
                diagnostics=[
                    *diagnostics,
                    {
                        "severity": "warn",
                        "code": "ENGINE_ZERO_RESULTS",
                        "message": "webrecon-fingerprint found no known JS libraries",
                        "hint": (
                            "reported as partial rather than succeeded: zero is a claim, "
                            "and a silent zero is indistinguishable from a page with "
                            "nothing detectable"
                        ),
                    },
                ],
            )

        return GenerateResult(
            status=ResultStatus.SUCCEEDED,
            artifacts=[artifact] if artifact else [],
            summary=summarize(self.capabilities, {"components": component_count}),
            diagnostics=diagnostics,
        )

    def _write_artifact(self, raw: bytes) -> RawArtifact | None:
        if self._artifact_dir is None:
            return None
        try:
            return ArtifactWriter(output_dir=self._artifact_dir).write(
                "webrecon-fingerprint.json", raw, self.media_type
            )
        except OSError:
            # Not fatal: the components below are still reported. Without the
            # artifact this run cannot be re-normalized later without
            # re-running services/webrecon, a real but survivable loss — the
            # same tradeoff SandboxedAdapter.generate() makes for the same
            # reason.
            return None
