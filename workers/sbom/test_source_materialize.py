"""The engine must never scan a tree that was supposed to be there and is not.

The fetcher uploads a content-addressed archive and the fan-out puts its
reference on every job. Until that reference was acted on, engines ran against
an empty directory and reported honestly on nothing — syft `partial`,
osv-scanner `failed`. The dispatch chain was complete and the source never
arrived.

These tests pin the distinction that matters most here: a job with NO archive is
a legitimate shape (an upload or manual scan has nothing to fetch), while a job
that NAMES an archive which cannot be materialized is a real failure. Collapsing
the two would mean scanning an empty directory and reporting a clean project.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from axebom_shared.adapters.base import ResultStatus
from axebom_shared.errors import EngineUnavailableError

from . import runner as runner_mod
from .runner import SBOMWorker
from .test_runner import FakeSandbox, job


def worker(tmp_path: Path) -> SBOMWorker:
    return SBOMWorker(
        workspace_root=tmp_path / "ws",
        output_root=tmp_path / "out",
        sandbox=FakeSandbox(),
    )


def with_archive(
    j: dict[str, Any], uri: str = "scans/s/raw/fetcher/j/abc/source.tar.zst", sha: str = "d" * 64
) -> dict[str, Any]:
    j["workspace"] = {"artifact_uri": uri, "sha256": sha}
    return j


def test_a_job_carrying_an_archive_materializes_it_before_the_engine_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, Path]] = []

    def fake(j: dict[str, Any], dest: Path, **_: Any) -> bool:
        calls.append((j["workspace"]["artifact_uri"], dest))
        dest.mkdir(parents=True, exist_ok=True)
        return True

    monkeypatch.setattr(runner_mod.source, "materialize", fake)

    w = worker(tmp_path)
    w.handle(with_archive(job("syft", scan_id="scan-1", job_id="job-1")))

    assert len(calls) == 1, "the source was not materialized"
    uri, dest = calls[0]
    assert uri.endswith("source.tar.zst")
    assert dest == tmp_path / "ws" / "scan-1", (
        "materialized somewhere other than the scan workspace the engine reads"
    )


def test_a_failed_materialization_is_unavailable_and_the_engine_never_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠ THE ENGINE MUST NOT RUN. This is the whole point.

    An engine pointed at a missing tree does not fail — it finds nothing and
    reports a clean project. There is no way to tell that apart from a genuinely
    clean repository afterwards, so the run is refused up front, exactly as the
    no-database rule refuses a vulnerability engine with nothing to match
    against.
    """

    def boom(*_: Any, **__: Any) -> bool:
        raise EngineUnavailableError("syft", "object not found: scans/s/.../source.tar.zst")

    monkeypatch.setattr(runner_mod.source, "materialize", boom)

    sandbox = FakeSandbox()
    w = SBOMWorker(
        workspace_root=tmp_path / "ws",
        output_root=tmp_path / "out",
        sandbox=sandbox,
    )
    result = w.handle(with_archive(job("syft", scan_id="scan-2", job_id="job-2")))

    assert result["status"] == ResultStatus.UNAVAILABLE.value, result["status"]
    codes = [d.get("code") for d in result.get("diagnostics", [])]
    assert "SOURCE_UNAVAILABLE" in codes, codes

    messages = " ".join(str(d.get("message", "")) for d in result["diagnostics"])
    assert "object not found" in messages, (
        "the underlying cause was dropped; the report would say the engine found "
        "nothing rather than why"
    )

    assert getattr(sandbox, "runs", []) == [], (
        "the engine was executed against a workspace that was never materialized"
    )


def test_a_job_with_no_archive_still_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An upload or manual scan has nothing to fetch, and that is not an error.

    Treating a missing reference as a failure would break every source kind that
    does not come from a repository.
    """
    called = False

    def fake(j: dict[str, Any], dest: Path, **_: Any) -> bool:
        nonlocal called
        called = True
        return False  # no archive reference on the job

    monkeypatch.setattr(runner_mod.source, "materialize", fake)

    ws = tmp_path / "ws" / "scan-3"
    ws.mkdir(parents=True)

    w = worker(tmp_path)
    result = w.handle(job("syft", scan_id="scan-3", job_id="job-3"))

    assert called, "materialize was not consulted"
    assert result["status"] != ResultStatus.UNAVAILABLE.value, (
        "a job with no archive was refused; upload and manual scans would never run"
    )


def test_the_reference_is_read_from_the_job_envelope() -> None:
    """The field is `workspace`, written by the orchestrator's fan-out.

    Pinned separately because reading the wrong key yields empty strings and the
    worker then silently treats every job as having no source — which is exactly
    the failure this whole change exists to remove, reintroduced quietly.
    """
    from axebom_shared.source import workspace_ref

    uri, sha = workspace_ref({"workspace": {"artifact_uri": "k/source.tar.zst", "sha256": "abc"}})
    assert uri == "k/source.tar.zst"
    assert sha == "abc"

    assert workspace_ref({}) == ("", "")
    assert workspace_ref({"workspace": None}) == ("", "")
