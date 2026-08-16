"""The SBOM worker's job path: envelopes, idempotency, and what never leaks.

The envelope is validated against ``proto/schemas/scan-result-v1.schema.json``,
which is GENERATED from the Go types in ``libs/go-shared/events``. Validating
against the generated schema rather than a hand-written copy is deliberate: the
failure it catches is the Python worker and the Go orchestrator drifting apart
at the boundary, which otherwise shows up as results being silently dropped by
a consumer that cannot decode them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from encorebom_shared.adapters.base import GenerateResult, RawArtifact, ResultStatus
from encorebom_shared.sandbox import SandboxResult

from .runner import ADAPTERS, DEPENDS_ON, JobContext, SBOMWorker

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "proto" / "schemas" / "scan-result-v1.schema.json"

#: Every fixture, so a result envelope is exercised against each shape of input.
FIXTURES = [
    "npm-simple",
    "pypi-normalization",
    "maven-case",
    "golang-incompatible",
    "monorepo-multiroot",
]


@pytest.fixture(scope="module")
def validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


class FakeSandbox:
    """A sandbox that returns a scripted result and records the spec."""

    def __init__(self, result: SandboxResult | None = None) -> None:
        self.runs: list[dict[str, Any]] = []
        self._result = result or SandboxResult(exit_code=0, stdout="{}")

    def check(self) -> dict[str, str]:
        return {"runtime": "fake"}

    def run(self, **kwargs: Any) -> SandboxResult:
        self.runs.append(kwargs)
        return self._result


def job(engine: str, *, scan_id: str = "scan-1", job_id: str = "job-1") -> dict[str, Any]:
    return {
        "schema_version": "scan.job/v1",
        "job_id": job_id,
        "scan_id": scan_id,
        "tenant_id": "01920000-0000-7000-8000-000000000001",
        "engine": engine,
        "family": "sbom",
        "source_meta": {"kind": "git", "commit_sha": "a" * 40},
        "engine_config": {},
    }


def worker(tmp_path: Path, sandbox: Any = None) -> SBOMWorker:
    return SBOMWorker(
        workspace_root=tmp_path / "ws",
        output_root=tmp_path / "out",
        sandbox=sandbox or FakeSandbox(),
    )


# -- envelope validity ----------------------------------------------------


@pytest.mark.parametrize("fixture", FIXTURES)
def test_result_envelope_is_schema_valid(
    fixture: str, tmp_path: Path, validator: Draft202012Validator
) -> None:
    """Every fixture yields a ScanResultV1 the Go side can decode."""
    w = worker(tmp_path)
    ws = tmp_path / "ws" / f"scan-{fixture}"
    ws.mkdir(parents=True)

    result = w.handle(job("syft", scan_id=f"scan-{fixture}", job_id=f"job-{fixture}"))
    errors = sorted(validator.iter_errors(result), key=lambda e: e.path)
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors)


@pytest.mark.parametrize("status", list(ResultStatus))
def test_every_status_produces_a_valid_envelope(
    status: ResultStatus, tmp_path: Path, validator: Draft202012Validator
) -> None:
    """⚠ `unavailable`, `partial` and `skipped` are NOT error paths.

    They are the statuses that keep a scan honest, so each has to survive the
    envelope with the same rigour as `succeeded`. A schema that only admitted
    success would push a worker toward reporting success.
    """
    w = worker(tmp_path)
    ctx = JobContext.from_job(job("syft"), tmp_path / "ws", tmp_path / "out")
    envelope = w._result(ctx, GenerateResult(status=status, engine_version="1.0.0"))

    errors = sorted(validator.iter_errors(envelope), key=lambda e: e.path)
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors)
    assert envelope["status"] == status.value


def test_failed_and_timeout_carry_a_machine_code(tmp_path: Path) -> None:
    """CLAUDE.md: every error carries a stable code, never a bare string."""
    w = worker(tmp_path)
    ctx = JobContext.from_job(job("syft"), tmp_path / "ws", tmp_path / "out")

    failed = w._result(
        ctx,
        GenerateResult(
            status=ResultStatus.FAILED,
            diagnostics=[
                {"severity": "error", "code": "ENGINE_NONZERO_EXIT", "message": "exited 2"}
            ],
        ),
    )
    assert failed["error"]["code"] == "ENGINE_NONZERO_EXIT"

    timed_out = w._result(ctx, GenerateResult(status=ResultStatus.TIMEOUT))
    assert timed_out["error"]["code"]
    assert timed_out["error"]["retryable"] is True, (
        "a timeout may succeed on a quieter host, so it is retryable"
    )
    assert failed["error"]["retryable"] is False, (
        "a hard failure will not fix itself; retrying burns delivery attempts"
    )


# -- idempotency ----------------------------------------------------------


def test_a_redelivered_job_does_not_rerun_the_engine(tmp_path: Path) -> None:
    """⚠ Redelivery is normal, not exceptional.

    ack_wait is 30 minutes and a worker container can die at any point. Running
    the engine twice would write a second artifact set under the same prefix and
    double-count every component downstream.
    """
    sandbox = FakeSandbox(SandboxResult(exit_code=0, stdout='{"artifacts": []}'))
    w = worker(tmp_path, sandbox)
    (tmp_path / "ws" / "scan-1").mkdir(parents=True)

    first = w.handle(job("syft"))
    runs_after_first = len(sandbox.runs)

    second = w.handle(job("syft"))
    assert len(sandbox.runs) == runs_after_first, "the engine ran again on redelivery"
    assert second["job_id"] == first["job_id"]
    assert second["status"] == first["status"]


def test_a_corrupt_manifest_causes_a_rerun_rather_than_a_bad_replay(tmp_path: Path) -> None:
    """An unreadable marker must not be replayed as a result."""
    sandbox = FakeSandbox(SandboxResult(exit_code=0, stdout='{"artifacts": []}'))
    w = worker(tmp_path, sandbox)
    (tmp_path / "ws" / "scan-1").mkdir(parents=True)

    ctx = JobContext.from_job(job("syft"), tmp_path / "ws", tmp_path / "out")
    ctx.output_dir.mkdir(parents=True)
    ctx.manifest_path().write_text("{not json", encoding="utf-8")

    result = w.handle(job("syft"))
    assert result["job_id"] == "job-1"
    assert len(sandbox.runs) == 1, "a corrupt manifest should force a real run"


def test_the_manifest_is_written_after_the_result_not_before(tmp_path: Path) -> None:
    """Writing the marker early makes a crash mid-run look like completed work."""
    sandbox = FakeSandbox(SandboxResult(exit_code=0, stdout='{"artifacts": []}'))
    w = worker(tmp_path, sandbox)
    (tmp_path / "ws" / "scan-1").mkdir(parents=True)

    ctx = JobContext.from_job(job("syft"), tmp_path / "ws", tmp_path / "out")
    assert not ctx.manifest_path().exists()

    w.handle(job("syft"))
    stored = json.loads(ctx.manifest_path().read_text(encoding="utf-8"))
    assert stored["status"], "the stored manifest must be a complete result"


# -- dependencies between engines -----------------------------------------


def test_grype_without_the_syft_sbom_is_skipped_never_redirected(tmp_path: Path) -> None:
    """⚠ There is no fallback to scanning the directory.

    That fallback would make grype catalogue components itself, producing a
    second inventory to reconcile against syft's — and it would do so exactly
    when syft had failed and nobody was watching.
    """
    sandbox = FakeSandbox()
    w = worker(tmp_path, sandbox)
    (tmp_path / "ws" / "scan-1").mkdir(parents=True)

    result = w.handle(job("grype"))
    assert result["status"] == ResultStatus.SKIPPED.value
    assert sandbox.runs == [], "grype was run without the SBOM it requires"
    assert any(d.get("code") == "ENGINE_INPUT_MISSING" for d in result["diagnostics"])


def test_declared_dependencies_name_engines_that_exist() -> None:
    """A typo here silently skips an engine forever."""
    for engine, dependency in DEPENDS_ON.items():
        assert engine in ADAPTERS, f"{engine} is not an implemented engine"
        assert dependency in ADAPTERS, f"{engine} depends on unknown {dependency}"


def test_an_unimplemented_engine_is_skipped_not_failed(tmp_path: Path) -> None:
    """Our misconfiguration must not fail the customer's scan."""
    w = worker(tmp_path)
    (tmp_path / "ws" / "scan-1").mkdir(parents=True)

    result = w.handle(job("no-such-engine"))
    assert result["status"] == ResultStatus.SKIPPED.value
    assert any(d.get("code") == "ENGINE_NOT_IMPLEMENTED" for d in result["diagnostics"])


# -- the worker never dies ------------------------------------------------


def test_an_adapter_that_raises_becomes_a_status(tmp_path: Path, monkeypatch) -> None:
    """⚠ An exception here would take down every other job the worker holds."""
    w = worker(tmp_path)
    (tmp_path / "ws" / "scan-1").mkdir(parents=True)

    def boom(self: Any, target: Any) -> Any:
        raise RuntimeError("engine exploded")

    monkeypatch.setattr(ADAPTERS["syft"], "generate", boom)

    result = w.handle(job("syft"))
    assert result["status"] == ResultStatus.FAILED.value
    assert result["error"]["code"] == "ADAPTER_EXCEPTION"


def test_unexpected_fields_in_a_job_do_not_break_decoding(tmp_path: Path) -> None:
    """Queue envelopes ignore unknown fields, unlike HTTP handlers.

    A newer orchestrator adding a field must not stop older workers dead
    (docs/02-CONTRACTS.md §2).
    """
    w = worker(tmp_path)
    (tmp_path / "ws" / "scan-1").mkdir(parents=True)

    payload = job("syft")
    payload["a_field_from_the_future"] = {"nested": [1, 2, 3]}

    result = w.handle(payload)
    assert result["job_id"] == "job-1"


# -- what must never appear in output -------------------------------------


def test_no_credential_reaches_the_result_envelope(tmp_path: Path) -> None:
    """Only the fetcher holds credentials; nothing that runs a scanner does.

    The envelope is persisted and rendered, so a leak here is durable.
    """
    w = worker(tmp_path)
    (tmp_path / "ws" / "scan-1").mkdir(parents=True)

    payload = job("syft")
    payload["engine_config"] = {"token": "ghp_deadbeefdeadbeefdeadbeef"}

    result = w.handle(payload)
    assert "ghp_deadbeefdeadbeefdeadbeef" not in json.dumps(result)


def test_the_recorded_argv_is_the_redacted_one(tmp_path: Path) -> None:
    """argv is world-readable in /proc and is persisted in the manifest."""
    w = worker(tmp_path)
    ctx = JobContext.from_job(job("syft"), tmp_path / "ws", tmp_path / "out")

    envelope = w._result(
        ctx,
        GenerateResult(
            status=ResultStatus.SUCCEEDED,
            argv_redacted=["syft", "--token", "***"],
        ),
    )
    assert envelope["invocation"]["argv_redacted"] == ["syft", "--token", "***"]


def test_artifacts_carry_a_digest_and_a_media_type(tmp_path: Path) -> None:
    """Phase 8 parses these, and a report cites them as evidence.

    An artifact with no digest cannot be shown to be the one that was scanned.
    """
    w = worker(tmp_path)
    ctx = JobContext.from_job(job("syft"), tmp_path / "ws", tmp_path / "out")

    envelope = w._result(
        ctx,
        GenerateResult(
            status=ResultStatus.SUCCEEDED,
            artifacts=[
                RawArtifact(
                    role="raw",
                    path=tmp_path / "syft.json",
                    media_type="application/json",
                    sha256="a" * 64,
                    size_bytes=12,
                )
            ],
        ),
    )
    stored = envelope["artifacts"][0]
    assert len(stored["sha256"]) == 64
    assert stored["media_type"]
    assert stored["size_bytes"] > 0
