"""The SBOM worker: subscribe, dispatch to an adapter, publish.

⚠ THE FIRST ACTION IS THE IDEMPOTENCY CHECK, NOT THE SCAN.

A worker that dies between uploading its artifacts and acking WILL be
redelivered — ``ack_wait`` is 30 minutes and a container can be killed at any
point. Re-running would produce a second artifact set under the same prefix and
double-count everything downstream. So: HEAD the manifest, and if it is there,
re-emit the stored result and ack.

⚠ grype IS SCHEDULED AFTER syft, NEVER INDEPENDENTLY.

grype matches against OUR syft SBOM. Pointing it at the directory would make it
catalogue components itself, producing a second inventory to reconcile — exactly
the work the normalizer exists to avoid. If syft did not produce an SBOM, grype
is `skipped` with a diagnostic rather than silently falling back.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from encorebom_shared.adapters.base import GenerateResult, RawArtifact, ResultStatus, ScanTarget
from encorebom_shared.logging import get_logger
from encorebom_shared.sandbox import Sandbox
from encorebom_shared.worker_runtime import run_worker

from .adapters import (
    DependencyCheckAdapter,
    GrypeAdapter,
    OSVScannerAdapter,
    SyftAdapter,
    SyftSPDXAdapter,
    TrivyFSAdapter,
    TrivyImageAdapter,
)
from .adapters.common import ArtifactWriter, SandboxedAdapter

log = get_logger("sbom-worker")

#: Every engine this worker can run.
ADAPTERS: dict[str, type[SandboxedAdapter]] = {
    "syft": SyftAdapter,
    "syft-spdx": SyftSPDXAdapter,
    "grype": GrypeAdapter,
    "trivy-fs": TrivyFSAdapter,
    "trivy-image": TrivyImageAdapter,
    "osv-scanner": OSVScannerAdapter,
    "dependency-check": DependencyCheckAdapter,
}

#: Engines that consume another engine's output rather than the source tree.
#: The value is what they depend on.
DEPENDS_ON: dict[str, str] = {"grype": "syft"}


@dataclass
class JobContext:
    """One job, decoded from ScanJobV1."""

    job_id: str
    scan_id: str
    tenant_id: str
    engine: str
    workspace: Path
    output_dir: Path
    source_kind: str = "git"
    commit_sha: str | None = None
    image_digest: str | None = None
    engine_config: dict[str, Any] | None = None

    @classmethod
    def from_job(cls, job: dict[str, Any], workspace_root: Path, output_root: Path) -> JobContext:
        job_id = str(job.get("job_id", ""))
        scan_id = str(job.get("scan_id", ""))
        source = job.get("source_meta") or {}
        return cls(
            job_id=job_id,
            scan_id=scan_id,
            tenant_id=str(job.get("tenant_id", "")),
            engine=str(job.get("engine", "")),
            workspace=workspace_root / scan_id,
            output_dir=output_root / job_id,
            source_kind=str(source.get("kind", "git")),
            commit_sha=source.get("commit_sha") or None,
            image_digest=source.get("image_digest") or None,
            engine_config=job.get("engine_config") or {},
        )

    def manifest_path(self) -> Path:
        """Where the completed-work marker lives.

        Named ``manifest.json`` to match ``ScanJobV1.ManifestKey()`` — the Go
        side derives the same name, and idempotency depends on both sides
        agreeing.
        """
        return self.output_dir / "manifest.json"


class SBOMWorker:
    """Runs one engine per job."""

    def __init__(
        self,
        *,
        workspace_root: Path | None = None,
        output_root: Path | None = None,
        sandbox: Sandbox | None = None,
        adapters: dict[str, type] | None = None,
        depends_on: dict[str, str] | None = None,
    ) -> None:
        """
        `adapters` and `depends_on` default to the SBOM family's, so existing
        callers and every test are unaffected.

        They are parameters because the job path — idempotency check first,
        unknown-engine handling, envelope construction, artifact persistence,
        manifest written last — is identical for every family. Copying it per
        family is how one worker ends up acking before it has stored its
        evidence, with nothing to catch it because each worker passes its own
        tests. CBOM and AIBOM reuse this class with their own engine maps.
        """
        self._workspace_root = workspace_root or Path(
            os.environ.get("ENCOREBOM_WORKSPACE_ROOT", "/var/lib/encorebom/workspaces")
        )
        self._output_root = output_root or Path(
            os.environ.get("ENCOREBOM_OUTPUT_ROOT", "/var/lib/encorebom/artifacts")
        )
        self._sandbox = sandbox or Sandbox()
        self._adapters = adapters if adapters is not None else ADAPTERS
        self._depends_on = depends_on if depends_on is not None else DEPENDS_ON

    @property
    def sandbox(self) -> Sandbox:
        """The sandbox this worker runs engines through."""
        return self._sandbox

    # -- the job path -------------------------------------------------------

    def handle(self, job: dict[str, Any]) -> dict[str, Any]:
        """Process one ScanJobV1 and return a ScanResultV1.

        Never raises. Every failure becomes a STATUS, because an exception here
        would take down the worker and lose every other job it holds.
        """
        ctx = JobContext.from_job(job, self._workspace_root, self._output_root)

        # ⚠ IDEMPOTENCY FIRST.
        stored = self._read_manifest(ctx)
        if stored is not None:
            log.info(
                "job already complete; re-emitting the stored result",
                extra={"job_id": ctx.job_id, "engine": ctx.engine},
            )
            return stored

        adapter_cls = self._adapters.get(ctx.engine)
        if adapter_cls is None:
            # An engine this worker does not implement. `skipped`, not failed:
            # the orchestrator dispatched it, so the mismatch is a configuration
            # problem to surface, and failing the scan over it would punish the
            # user for our misconfiguration.
            return self._result(
                ctx,
                GenerateResult(
                    status=ResultStatus.SKIPPED,
                    diagnostics=[
                        {
                            "severity": "warn",
                            "code": "ENGINE_NOT_IMPLEMENTED",
                            "message": f"this worker does not implement {ctx.engine!r}",
                            "hint": f"implemented: {', '.join(sorted(ADAPTERS))}",
                        }
                    ],
                ),
            )

        target = self._build_target(ctx)

        # ⚠ grype NEEDS syft's SBOM. No fallback to scanning the directory.
        dependency = self._depends_on.get(ctx.engine)
        if dependency and target.sbom_path is None:
            return self._result(
                ctx,
                GenerateResult(
                    status=ResultStatus.SKIPPED,
                    diagnostics=[
                        {
                            "severity": "warn",
                            "code": "ENGINE_INPUT_MISSING",
                            "message": (
                                f"{ctx.engine} needs the {dependency} SBOM, which is not present"
                            ),
                            "hint": (
                                "scanning the directory instead would produce a second "
                                "component inventory to reconcile, which is the work the "
                                "normalizer exists to avoid"
                            ),
                        }
                    ],
                ),
            )

        # ⚠ artifact_dir MUST be passed, or raw output is never persisted.
        #
        # SandboxedAdapter treats artifact_dir=None as "the caller collects the
        # output from the result instead" — which is right for the fixture
        # generator and for tests, and silently wrong here. The worker omitted
        # it, so every live scan ran the engine, parsed its output, and then
        # discarded the bytes.
        #
        # That is not a cosmetic loss. Raw scanner output is the immutable
        # evidence a report rests on (ADR-0003, CLAUDE.md invariant 10):
        # normalization is a pure function of it, so fixing a parser bug means
        # re-normalizing stored artifacts rather than re-running the scanners.
        # With nothing stored there is nothing to re-normalize, nothing to
        # re-parse when a mapping is corrected, and nothing to show six months
        # later when someone asks what the report was derived from.
        #
        # The path embeds job_id, and ArtifactWriter refuses to overwrite, so a
        # redelivered job cannot mutate evidence already written.
        adapter = adapter_cls(sandbox=self._sandbox, artifact_dir=ctx.output_dir)
        started = time.time()
        try:
            generated = adapter.generate(target)
        except Exception as exc:
            log.exception("adapter raised", extra={"engine": ctx.engine, "job_id": ctx.job_id})
            generated = GenerateResult(
                status=ResultStatus.FAILED,
                diagnostics=[
                    {
                        "severity": "error",
                        "code": "ADAPTER_EXCEPTION",
                        "message": f"{ctx.engine} adapter raised: {type(exc).__name__}",
                        "hint": str(exc)[:300],
                    }
                ],
            )
        generated.duration_ms = generated.duration_ms or int((time.time() - started) * 1000)

        result = self._result(ctx, generated)

        # Written LAST, after the result is complete: the manifest is the
        # "this work is done" marker, and writing it early would make a crash
        # mid-run look like a completed job.
        self._write_manifest(ctx, result)
        return result

    # -- helpers ------------------------------------------------------------

    def _build_target(self, ctx: JobContext) -> ScanTarget:
        sbom_path = None
        candidate = ctx.workspace / "sbom.cdx.json"
        if candidate.exists():
            sbom_path = candidate

        return ScanTarget(
            scan_id=ctx.scan_id,
            job_id=ctx.job_id,
            kind=ctx.source_kind,
            workspace=ctx.workspace,
            commit_sha=ctx.commit_sha,
            image_digest=ctx.image_digest,
            sbom_path=sbom_path,
            engine_config=ctx.engine_config or {},
        )

    def _read_manifest(self, ctx: JobContext) -> dict[str, Any] | None:
        path = ctx.manifest_path()
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            # A corrupt manifest is worse than none: re-run rather than
            # re-emit something unreadable.
            log.warning("manifest is unreadable; re-running", extra={"job_id": ctx.job_id})
            return None

    def _write_manifest(self, ctx: JobContext, result: dict[str, Any]) -> None:
        ctx.output_dir.mkdir(parents=True, exist_ok=True)
        ctx.manifest_path().write_text(json.dumps(result), encoding="utf-8")

    def _result(self, ctx: JobContext, generated: GenerateResult) -> dict[str, Any]:
        """Build the ScanResultV1 envelope."""
        artifacts = []
        for artifact in generated.artifacts:
            artifacts.append(
                {
                    "role": artifact.role,
                    "uri": str(artifact.path),
                    "media_type": artifact.media_type,
                    "sha256": artifact.sha256,
                    "size_bytes": artifact.size_bytes,
                }
            )

        payload: dict[str, Any] = {
            "schema_version": "scan.result/v1",
            "job_id": ctx.job_id,
            "scan_id": ctx.scan_id,
            "tenant_id": ctx.tenant_id,
            "engine": ctx.engine,
            "engine_version": generated.engine_version or "unknown",
            "status": generated.status.value,
            "invocation": {
                # Redacted at build time by the adapter. argv is world-readable
                # in /proc and this copy is persisted in the provenance manifest.
                "argv_redacted": generated.argv_redacted,
                "exit_code": generated.exit_code if generated.exit_code is not None else 0,
                "duration_ms": generated.duration_ms,
            },
            "artifacts": artifacts,
            "ecosystems_covered": generated.ecosystems_covered,
            "summary": {
                "components": 0,
                "vulnerabilities": 0,
                "licenses": 0,
                "crypto_assets": 0,
            },
            "diagnostics": generated.diagnostics,
        }

        if generated.engine_db_version:
            payload["engine_db_version"] = generated.engine_db_version

        if generated.status in (ResultStatus.FAILED, ResultStatus.TIMEOUT):
            payload["error"] = {
                "code": _first_code(generated.diagnostics) or "ENGINE_FAILED",
                "message": _first_message(generated.diagnostics) or f"{ctx.engine} failed",
                # A timeout may succeed on a quieter host; a hard failure will
                # not. Getting this wrong burns four delivery attempts on
                # something that cannot work, or drops work that could.
                "retryable": generated.status == ResultStatus.TIMEOUT,
            }

        return payload

    def write_artifact(
        self, ctx: JobContext, name: str, content: bytes, media_type: str
    ) -> RawArtifact:
        """Store one raw artifact. Immutable once written (ADR-0003)."""
        return ArtifactWriter(output_dir=ctx.output_dir).write(name, content, media_type)


def _first_code(diagnostics: list[dict[str, Any]]) -> str:
    for d in diagnostics:
        if d.get("severity") == "error" and d.get("code"):
            return str(d["code"])
    return ""


def _first_message(diagnostics: list[dict[str, Any]]) -> str:
    for d in diagnostics:
        if d.get("severity") == "error" and d.get("message"):
            return str(d["message"])
    return ""


def main() -> int:
    """Entry point: preflight the sandbox, then consume scan.job.sbom.

    Preflight runs FIRST and refuses to attach a consumer if it fails. A
    WorkQueue delivers each job to exactly one consumer, so a worker that cannot
    reach Docker must not claim jobs — claiming one hides it from a replica that
    could have done the work, and the scan reports a failure that was really a
    deployment problem.
    """
    worker = SBOMWorker()

    return run_worker(
        "sbom",
        worker.handle,
        preflight=lambda: {**worker.sandbox.check(), "engines": len(ADAPTERS)},
        # One container at a time per replica. This is a concurrency limit, not
        # a throughput setting: scans are minutes of container, and handing a
        # replica more than it can run just means messages sitting unacked
        # against a thirty-minute ack_wait.
        max_ack_pending=2,
    )


if __name__ == "__main__":
    raise SystemExit(main())
