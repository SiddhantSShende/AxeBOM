"""syft's SBOM has to reach grype, and grype runs as a separate job.

grype matches against OUR syft SBOM rather than re-cataloguing the tree — a
second inventory would be a second thing to reconcile, which is exactly the work
the normalizer exists to avoid. But the two are separate jobs with separate job
ids, so grype cannot address syft's per-job output directory. The shared
per-scan workspace is the only place both can name.

Until that handoff existed, grype reported ENGINE_INPUT_MISSING on every real
scan while the SBOM sat one directory away.
"""

from __future__ import annotations

from pathlib import Path

from encorebom_shared.adapters.base import GenerateResult, RawArtifact, ResultStatus

from .adapters.syft import SyftAdapter, SyftSPDXAdapter
from .runner import SBOMWorker


def artifact(tmp_path: Path, body: str = '{"bomFormat":"CycloneDX"}') -> RawArtifact:
    p = tmp_path / "syft.json"
    p.write_text(body, encoding="utf-8")
    return RawArtifact(role="native_output", path=p, media_type="application/json")


def worker(tmp_path: Path) -> SBOMWorker:
    return SBOMWorker(workspace_root=tmp_path / "ws", output_root=tmp_path / "out")


class Ctx:
    """Minimal JobContext stand-in: the helper reads only these fields."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.job_id = "job-1"
        self.engine = "syft"


def test_syft_publishes_its_sbom_where_build_target_looks() -> None:
    assert SyftAdapter.workspace_artifact_name == "sbom.cdx.json", (
        "grype's _build_target reads sbom.cdx.json from the workspace; a "
        "different name here means grype is skipped on every scan"
    )


def test_the_spdx_pass_does_not_overwrite_the_cyclonedx_sbom() -> None:
    """⚠ SyftSPDXAdapter INHERITS FROM SyftAdapter.

    Left inherited, the second syft pass would write an SPDX document over
    sbom.cdx.json. grype would then either fail to parse it or, worse, parse it
    partially and report vulnerabilities against an inventory nobody produced.
    """
    assert SyftSPDXAdapter.workspace_artifact_name is None


def test_a_successful_run_lands_the_artifact_readable(tmp_path: Path) -> None:
    w = worker(tmp_path)
    ws = tmp_path / "ws" / "scan-1"
    ws.mkdir(parents=True)

    generated = GenerateResult(status=ResultStatus.SUCCEEDED, artifacts=[artifact(tmp_path)])
    w._publish_to_workspace(SyftAdapter(), Ctx(ws), generated)

    published = ws / "sbom.cdx.json"
    assert published.is_file(), "the SBOM never reached the workspace"
    assert published.read_text(encoding="utf-8").startswith('{"bomFormat"')

    # Engine containers run as uid 65534 and mount this read-only. A 0600 file
    # is invisible to them, and an engine that cannot read its input reports a
    # clean project rather than an error.
    assert published.stat().st_mode & 0o044, "the SBOM is not readable by the engine user"

    assert not list(ws.glob(".sbom.cdx.json.*")), "a staging file was left behind"


def test_a_failed_run_publishes_nothing(tmp_path: Path) -> None:
    """A failed engine's partial output must not become another's input.

    grype matching against a truncated SBOM would report vulnerabilities for a
    subset of the project while looking like a complete scan.
    """
    w = worker(tmp_path)
    ws = tmp_path / "ws" / "scan-2"
    ws.mkdir(parents=True)

    generated = GenerateResult(status=ResultStatus.FAILED, artifacts=[artifact(tmp_path)])
    w._publish_to_workspace(SyftAdapter(), Ctx(ws), generated)

    assert not (ws / "sbom.cdx.json").exists()


def test_an_engine_nothing_consumes_publishes_nothing(tmp_path: Path) -> None:
    from .adapters.trivy_fs import TrivyFSAdapter

    w = worker(tmp_path)
    ws = tmp_path / "ws" / "scan-3"
    ws.mkdir(parents=True)

    generated = GenerateResult(status=ResultStatus.SUCCEEDED, artifacts=[artifact(tmp_path)])
    w._publish_to_workspace(TrivyFSAdapter(), Ctx(ws), generated)

    assert list(ws.iterdir()) == [], "an engine with no consumer wrote to the workspace"
