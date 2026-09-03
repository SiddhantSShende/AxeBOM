"""The HBOM adapters, and the worker contract they must satisfy.

⚠ THE FIRST LIVE RUN CRASHED THREE FRAMES INSIDE THE WORKER.

`ECADAdapter.generate` returned a plain dict for `summary`; `SBOMWorker._result`
calls `summary.as_dict()` on whatever an adapter hands back, so the job died
with `AttributeError: 'dict' object has no attribute 'as_dict'` — after the
engine had done all its work and written its artifact.

Nothing caught it. The adapter's own tests exercised parsing and never went
through the worker, and the worker's tests used adapters that already got it
right. This module tests the SEAM: what an adapter returns has to be what the
worker can consume.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from axebom_shared.adapters.base import EngineMode, ResultStatus, ScanTarget
from axebom_shared.adapters.summary import EngineSummary

from .adapters import CdxgenHostHBOMAdapter, ECADAdapter
from .runner import ADAPTERS


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "hw").mkdir()
    (tmp_path / "hw" / "board.kicad_sch").write_text(
        '(kicad_sch (symbol (property "Reference" "R1") (property "Value" "10k") '
        '(property "MPN" "RC0402") (property "Manufacturer" "Yageo")) '
        '(symbol (property "Reference" "R4") (property "Value" "10k") '
        '(property "MPN" "RC0402")))'
    )
    return tmp_path


def target(workspace: Path) -> ScanTarget:
    return ScanTarget(scan_id="s", job_id="j", kind="upload", workspace=workspace)


# ---------------------------------------------------------------------------
# The worker seam
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("engine_id", sorted(ADAPTERS))
def test_every_adapter_returns_a_summary_the_worker_can_serialize(engine_id, workspace):
    """⚠ THE REGRESSION GUARD FOR THE BUG THAT ONLY A LIVE RUN FOUND.

    `SBOMWorker._result` calls `summary.as_dict()` unconditionally. An adapter
    returning a dict, a tuple or None fails there — after the engine has run,
    after the artifact is written, with a traceback that names the worker rather
    than the adapter that caused it.

    Parametrized over the registry so a THIRD engine cannot be added without
    satisfying the same contract.
    """
    adapter = ADAPTERS[engine_id](artifact_dir=workspace / "out")
    result = adapter.generate(target(workspace))

    assert isinstance(result.summary, EngineSummary) or result.summary is None, (
        f"{engine_id} returned {type(result.summary).__name__} for summary; "
        "SBOMWorker._result calls .as_dict() on it"
    )
    if result.summary is not None:
        # The call the worker actually makes.
        assert isinstance(result.summary.as_dict(), dict)


@pytest.mark.parametrize("engine_id", sorted(ADAPTERS))
def test_every_adapter_is_available_without_docker(engine_id):
    """⚠ NEITHER HBOM ENGINE STARTS A CONTAINER, and the worker's preflight
    deliberately does not probe the sandbox for that reason. An adapter that
    reported unavailable without Docker would strand work that never needed it.
    """
    availability = ADAPTERS[engine_id](artifact_dir=None).available()
    assert availability.available
    assert availability.mode is EngineMode.INTERNAL


# ---------------------------------------------------------------------------
# hbom-ecad
# ---------------------------------------------------------------------------


def test_ecad_reports_the_hardware_ecosystem_as_covered(workspace):
    """⚠ ONE MISSING LIST LITERAL WOULD PUT A FALSE GAP IN EVERY HBOM REPORT.

    `hbom-csv` is recorded as UNAVAILABLE for the `hardware` ecosystem at
    scan-create time (it declares no source kind, so Resolve puts it in
    SkippedForSource). `Store.CoverageGaps` only neutralises such a row when a
    matching available=true row exists — and that row comes from THIS field.
    Drop it and every HBOM report grows "ecosystem `hardware` had no available
    engine", which is invariant 12 inverted.
    """
    result = ECADAdapter(artifact_dir=workspace / "out").generate(target(workspace))
    assert result.status is ResultStatus.SUCCEEDED
    assert result.ecosystems_covered == ["hardware"]


def test_ecad_groups_placements_into_line_items(workspace):
    """R1 and R4 of the same 10k resistor are ONE line with quantity 2.

    Emitting two components would inflate the count in a compliance document
    and produce a BOM nobody can order from.
    """
    result = ECADAdapter(artifact_dir=workspace / "out").generate(target(workspace))
    document = json.loads((workspace / "out" / "hbom-ecad.json").read_text())

    board = document["roots"][0]
    assert len(board["children"]) == 1, "the two placements did not group"
    part = board["children"][0]
    assert part["quantity"] == 2
    assert part["designators"] == ["R1", "R4"]
    # ⚠ The manufacturer was recorded on R1 only. Reading fields off one
    # arbitrary member loses it — see _coalesce.
    assert part["manufacturer_name"] == "Yageo"
    assert result.summary is not None and result.summary.as_dict()["components"] == 2


def test_ecad_says_what_it_looked_for_when_it_finds_nothing():
    """ "Found nothing" leaves a customer unable to tell a wrong subpath from an
    unsupported format, and they will assume the latter."""
    with tempfile.TemporaryDirectory() as empty:
        result = ECADAdapter(artifact_dir=None).generate(target(Path(empty)))

    assert result.status is ResultStatus.UNAVAILABLE
    hint = " ".join(d.get("hint", "") for d in result.diagnostics)
    assert ".kicad_sch" in hint
    assert "subpath" in hint


def test_ecad_is_byte_reproducible(workspace, tmp_path):
    """Invariant 10: the same tree must serialize to the same artifact, or a
    re-normalization is a different document."""
    first = tmp_path / "a"
    second = tmp_path / "b"
    ECADAdapter(artifact_dir=first).generate(target(workspace))
    ECADAdapter(artifact_dir=second).generate(target(workspace))

    assert (first / "hbom-ecad.json").read_bytes() == (second / "hbom-ecad.json").read_bytes()


# ---------------------------------------------------------------------------
# hbom-cdxgen-host
# ---------------------------------------------------------------------------


def test_cdxgen_host_picks_the_hardware_document_by_content(tmp_path):
    """⚠ CONTENT DECIDES, NOT THE FILENAME. An upload documenting a device
    normally holds an SBOM and an HBOM side by side; picking by name would read
    the wrong one and report a software inventory as hardware.
    """
    (tmp_path / "a-sbom.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"type": "library", "name": "left-pad"}],
            }
        )
    )
    (tmp_path / "z-inventory.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "metadata": {"component": {"type": "device", "name": "ThinkPad"}},
                "components": [{"type": "device", "name": "Samsung SSD"}],
            }
        )
    )

    result = CdxgenHostHBOMAdapter(artifact_dir=tmp_path / "out").generate(target(tmp_path))

    assert result.status is ResultStatus.SUCCEEDED
    # ⚠ THE CUSTOMER'S BYTES, VERBATIM. A re-serialized copy is no longer the
    # evidence they supplied.
    assert (tmp_path / "out" / "hbom-cdxgen-host.json").read_bytes() == (
        tmp_path / "z-inventory.json"
    ).read_bytes()


def test_cdxgen_host_names_what_it_looked_for_when_absent(tmp_path):
    result = CdxgenHostHBOMAdapter(artifact_dir=None).generate(target(tmp_path))

    assert result.status is ResultStatus.UNAVAILABLE
    hint = " ".join(d.get("hint", "") for d in result.diagnostics)
    assert "cdxgen -t hbom" in hint
    # ⚠ AND IT SAYS AxeBOM CANNOT REACH THE DEVICE. Without that, a customer
    # reasonably assumes the feature is broken rather than that it is theirs to
    # run.
    assert "cannot reach it" in hint
