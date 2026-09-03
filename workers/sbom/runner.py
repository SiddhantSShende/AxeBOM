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
import shutil
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from axebom_shared import source
from axebom_shared.adapters.base import GenerateResult, RawArtifact, ResultStatus, ScanTarget
from axebom_shared.adapters.summary import EngineSummary
from axebom_shared.errors import EngineUnavailableError
from axebom_shared.logging import get_logger
from axebom_shared.sandbox import Sandbox
from axebom_shared.worker_runtime import run_worker

from .adapters import (
    CdxgenAdapter,
    DependencyCheckAdapter,
    GitHubDependencyGraphAdapter,
    GrypeAdapter,
    OSVScannerAdapter,
    SyftAdapter,
    SyftSPDXAdapter,
    TrivyFSAdapter,
    TrivyImageAdapter,
    WebreconFingerprintAdapter,
)
from .adapters.common import ArtifactWriter, SandboxedAdapter

log = get_logger("sbom-worker")

#: Every engine this worker can run.
#:
#: ⚠ THE TYPE HINT UNDERSTATES IT SLIGHTLY: GitHubDependencyGraphAdapter and
#: WebreconFingerprintAdapter are ToolAdapterBase, not SandboxedAdapter —
#: neither has a container to sandbox. Both still fit this dict
#: (structurally, all three accept the same constructor kwargs — see their
#: own __init__) and the same dispatch path below, which is the point:
#: adding an engine that needs no sandbox should not need a second worker
#: class.
ADAPTERS: dict[str, type[SandboxedAdapter]] = {
    "cdxgen": CdxgenAdapter,
    "syft": SyftAdapter,
    "syft-spdx": SyftSPDXAdapter,
    "grype": GrypeAdapter,
    "trivy-fs": TrivyFSAdapter,
    "trivy-image": TrivyImageAdapter,
    "osv-scanner": OSVScannerAdapter,
    "dependency-check": DependencyCheckAdapter,
    "github-dependency-graph-sbom": GitHubDependencyGraphAdapter,  # type: ignore[dict-item]
    "webrecon-fingerprint": WebreconFingerprintAdapter,  # type: ignore[dict-item]
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
            os.environ.get("AXEBOM_WORKSPACE_ROOT", "/var/lib/axebom/workspaces")
        )
        self._output_root = output_root or Path(
            os.environ.get("AXEBOM_OUTPUT_ROOT", "/var/lib/axebom/artifacts")
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

        # Cheap for the overwhelming majority of jobs: source.native_sbom_ref
        # returns "" without a subprocess call whenever the job carries none,
        # which is every job except github-dependency-graph-sbom's own.
        native_sbom_path = source.materialize_native_sbom(
            job, ctx.output_dir / "native-sbom-staged.json"
        )
        target = self._build_target(ctx, native_sbom_path)

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

        # ⚠ MATERIALIZE THE SOURCE BEFORE THE ENGINE STARTS.
        #
        # The fetcher uploads a content-addressed archive and the fan-out puts
        # its reference on every job, but until this call nothing downloaded it:
        # engines ran against an empty directory and reported honestly on
        # nothing. The dispatch chain was complete and the source never arrived.
        #
        # Failure is UNAVAILABLE, never a scan of whatever happens to be there.
        # An engine that runs against a missing tree reports a clean project,
        # and a false all-clear in a compliance artifact is the worst outcome
        # this codebase has.
        try:
            source.materialize(job, ctx.workspace)
        except EngineUnavailableError as exc:
            log.error(
                "source could not be materialized; refusing to scan",
                extra={"job_id": ctx.job_id, "engine": ctx.engine, "cause": str(exc)},
            )
            return self._result(
                ctx,
                GenerateResult(
                    status=ResultStatus.UNAVAILABLE,
                    diagnostics=[
                        {
                            "severity": "error",
                            "code": "SOURCE_UNAVAILABLE",
                            "message": str(exc),
                            "hint": "the engine was not run; this appears in Engine Coverage",
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
        started_at = _now()
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
        # ⚠ THE THREE FIELDS FALL BACK TOGETHER, NEVER SEPARATELY.
        #
        # The sandbox stamps all three when an engine actually ran, and its
        # interval is the narrower, truer one. When it did not run — a refused
        # database, an adapter that raised, an engine this worker does not
        # implement — the worker's own clock supplies all three. Mixing them
        # would publish a duration from one interval next to timestamps from
        # another, and `finished - started != duration_ms` makes a reader
        # rightly distrust every number in the block.
        if generated.started_at is None or generated.finished_at is None:
            generated.started_at = started_at
            generated.finished_at = _now()
            generated.duration_ms = int((time.time() - started) * 1000)

        # Before the manifest, so a job that is later re-emitted from its
        # manifest has already left its output where a consumer can find it.
        self._publish_to_workspace(adapter, ctx, generated)

        result = self._result(ctx, generated)

        # Written LAST, after the result is complete: the manifest is the
        # "this work is done" marker, and writing it early would make a crash
        # mid-run look like a completed job.
        self._write_manifest(ctx, result)
        return result

    # -- helpers ------------------------------------------------------------

    def _build_target(self, ctx: JobContext, native_sbom_path: Path | None = None) -> ScanTarget:
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
            native_sbom_path=native_sbom_path,
            engine_config=ctx.engine_config or {},
        )

    def _publish_to_workspace(
        self, adapter: Any, ctx: JobContext, generated: GenerateResult
    ) -> None:
        """Put an engine's output where the engine that consumes it will look.

        ⚠ THE WORKSPACE IS PER-SCAN; THE OUTPUT DIRECTORY IS PER-JOB.

        grype matches against OUR syft SBOM rather than re-cataloguing the tree,
        and it runs as a SEPARATE JOB with its own job id — so it cannot address
        syft's output directory. _build_target reads the shared per-scan
        workspace, so that is where a consumed artifact has to land. Until it
        did, grype reported ENGINE_INPUT_MISSING on every real scan while the
        SBOM sat one directory away.

        Written atomically and world-readable: engine containers run as uid
        65534 and mount the workspace read-only, so a 0600 file would be
        invisible to them — and an engine that cannot read its input reports a
        clean project rather than an error.
        """
        name = getattr(adapter, "workspace_artifact_name", None)
        if not name:
            return
        if generated.status not in (ResultStatus.SUCCEEDED, ResultStatus.PARTIAL):
            return

        source_path = next((a.path for a in generated.artifacts if a.role == "native_output"), None)
        if source_path is None or not Path(source_path).is_file():
            return

        target = ctx.workspace / name
        try:
            ctx.workspace.mkdir(parents=True, exist_ok=True)
            # Same directory, so the replace is atomic: a consumer never sees a
            # half-written document.
            tmp = ctx.workspace / f".{name}.{ctx.job_id}"
            shutil.copyfile(source_path, tmp)
            tmp.chmod(0o644)
            tmp.replace(target)
        except OSError as exc:
            # Not fatal to THIS engine — its own result is complete and stored.
            # The consumer reports ENGINE_INPUT_MISSING, which is the honest
            # outcome, and this line is what explains it.
            log.error(
                "could not publish output to the workspace; the consuming engine "
                "will report its input as missing",
                extra={
                    "job_id": ctx.job_id,
                    "engine": ctx.engine,
                    "artifact": name,
                    "cause": str(exc),
                },
            )
            return

        log.info(
            "published output for a consuming engine",
            extra={"job_id": ctx.job_id, "engine": ctx.engine, "artifact": str(target)},
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
        # ⚠ A RUN THAT WAS REFUSED REPORTS NO COUNTS.
        #
        # `unavailable`, `skipped`, `failed` and `timeout` all mean the output
        # was not accepted, and several adapters compute their counts before
        # they reach the check that refuses the run — osv-scanner counts every
        # finding, then declares itself unavailable because it cannot date
        # them. Publishing those numbers on a refused run would let a consumer
        # sum findings the engine itself declined to stand behind.
        #
        # Enforced here rather than in each adapter: this is the one place
        # every family's envelope is built, so a new adapter cannot forget it.
        summary = generated.summary
        if generated.status not in (ResultStatus.SUCCEEDED, ResultStatus.PARTIAL):
            summary = EngineSummary()

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
                # ⚠ WHEN, not just how long. Both were absent from every
                # envelope, so `scan.engine_runs.started_at` and `finished_at`
                # were NULL on every run ever recorded and a report could say
                # how long an engine took but never when it ran — which is the
                # half that makes a result datable.
                #
                # Omitted rather than zeroed when unknown: Go decodes a missing
                # time to the zero value and HandleResult already skips it, so
                # an absent stamp stays absent instead of becoming year 1.
                **_timestamps(generated),
                # ⚠ WHAT RAN, resolved by the daemon rather than copied from the
                # reference we asked for. Omitted when unknown: an empty string
                # in a provenance field reads as a value.
                **({"image_digest": generated.image_digest} if generated.image_digest else {}),
                "exit_code": generated.exit_code if generated.exit_code is not None else 0,
                "duration_ms": generated.duration_ms,
            },
            "artifacts": artifacts,
            "ecosystems_covered": generated.ecosystems_covered,
            # ⚠ null IS NOT 0 HERE. This was four hardcoded zeros on every
            # job, so syft inventoried 21 components in expressjs/express and
            # `scan.engine_runs.summary` recorded nothing — for every scan ever
            # run. Filling all four in unconditionally would have been the same
            # bug wearing a number: the adapter reports only the dimensions its
            # manifest entry claims, and null says "this engine does not
            # measure this" where 0 says "it measured, and found none".
            "summary": summary.as_dict(),
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


def _now() -> datetime:
    """UTC, always. No local time anywhere, ever (CLAUDE.md §Conventions)."""
    return datetime.now(UTC)


def _rfc3339z(ts: datetime) -> str:
    """RFC3339 with a LITERAL Z, which is what every consumer expects.

    Python renders UTC as `+00:00`; Go's time.RFC3339 parser accepts it, but the
    contract and every other timestamp this system emits use `Z`, and a stored
    provenance record that is formatted two ways is one a human has to reconcile
    by eye.
    """
    return ts.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _timestamps(generated: GenerateResult) -> dict[str, str]:
    if generated.started_at is None or generated.finished_at is None:
        return {}
    return {
        "started_at": _rfc3339z(generated.started_at),
        "finished_at": _rfc3339z(generated.finished_at),
    }


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
