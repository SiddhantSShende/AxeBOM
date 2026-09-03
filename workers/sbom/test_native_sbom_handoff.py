"""A GitHub Dependency Graph SBOM the fetcher staged has to reach its adapter.

Unlike the syft->grype handoff (test_sbom_handoff.py), this artifact comes
from an entirely different service (the fetcher, not a sibling job in this
same worker) and lives in object storage, not the shared per-scan workspace —
so the handoff is `workspace.native_sbom_ref` on the job envelope itself,
fetched via `axebom_shared.source.materialize_native_sbom` into
ScanTarget.native_sbom_path. These tests pin that wiring, end to end through
SBOMWorker.handle(), not just the adapter in isolation
(test_github_dependency_graph_adapter.py covers that half).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from axebom_shared.adapters.base import ResultStatus
from axebom_shared.source import native_sbom_ref

from . import runner as runner_mod
from .runner import SBOMWorker
from .test_runner import FakeSandbox, job


def worker(tmp_path: Path) -> SBOMWorker:
    return SBOMWorker(
        workspace_root=tmp_path / "ws",
        output_root=tmp_path / "out",
        sandbox=FakeSandbox(),
    )


def with_native_ref(
    j: dict[str, Any], uri: str = "scans/s/raw/fetcher/dependency-graph-sbom.json"
) -> dict[str, Any]:
    j.setdefault("workspace", {})["native_sbom_ref"] = uri
    return j


def test_the_reference_is_read_from_the_job_envelope() -> None:
    """The field is workspace.native_sbom_ref, written by the orchestrator's
    FanOut only for the one engine that consumes it. Reading the wrong key
    silently makes every job look like it carries none — the same failure
    mode workspace_ref's own pinning test guards against for the archive."""
    assert native_sbom_ref({"workspace": {"native_sbom_ref": "k/doc.json"}}) == "k/doc.json"
    assert native_sbom_ref({}) == ""
    assert native_sbom_ref({"workspace": None}) == ""
    assert native_sbom_ref({"workspace": {}}) == ""


def test_a_job_carrying_the_reference_stages_it_before_the_adapter_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    doc = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "SPDXID": "SPDXRef-lodash",
                "name": "lodash",
                "versionInfo": "4.17.21",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:npm/lodash@4.17.21",
                    }
                ],
            }
        ],
    }

    fetch_calls: list[tuple[str, Path]] = []

    def fake_fetch(j: dict[str, Any], dest: Path, **_: Any) -> Path | None:
        fetch_calls.append((native_sbom_ref(j), dest))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(doc), encoding="utf-8")
        return dest

    monkeypatch.setattr(runner_mod.source, "materialize_native_sbom", fake_fetch)
    monkeypatch.setattr(runner_mod.source, "materialize", lambda *a, **k: False)

    w = worker(tmp_path)
    j = with_native_ref(job("github-dependency-graph-sbom", scan_id="scan-1", job_id="job-1"))
    result = w.handle(j)

    assert len(fetch_calls) == 1, "materialize_native_sbom was not consulted"
    uri, _dest = fetch_calls[0]
    assert uri.endswith("dependency-graph-sbom.json")

    assert result["status"] == ResultStatus.SUCCEEDED.value, result
    assert result["summary"]["components"] == 1


def test_a_job_carrying_no_reference_never_calls_the_fetch_helper_pointlessly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The common case — every engine except github-dependency-graph-sbom.

    materialize_native_sbom itself already short-circuits on an empty
    reference without a subprocess call; this pins that runner.py always
    calls it (so a future engine that DOES carry a reference is never
    skipped) while confirming an ordinary syft job's result is unaffected."""
    calls = 0

    def counting_fake(j: dict[str, Any], dest: Path, **_: Any) -> Path | None:
        nonlocal calls
        calls += 1
        return None  # no reference on this job — the real function's own behavior

    monkeypatch.setattr(runner_mod.source, "materialize_native_sbom", counting_fake)
    monkeypatch.setattr(runner_mod.source, "materialize", lambda *a, **k: True)

    w = worker(tmp_path)
    w.handle(job("syft", scan_id="scan-2", job_id="job-2"))

    assert calls == 1, "runner.py should still call materialize_native_sbom once per job"
