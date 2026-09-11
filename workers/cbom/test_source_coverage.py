"""Engine Coverage for source languages: what each CBOM engine read, and what it
saw and could not (invariant 12).

⚠ A GO REPOSITORY SCANNED FOR CRYPTOGRAPHY BY ENGINES THAT READ JAVA AND
JAVASCRIPT IS NOT A REPOSITORY WITH NO CRYPTOGRAPHY. Before `ecosystems_uncovered`
its CBOM held the certificates theia found and nothing else, every engine
`succeeded`, and nothing said the Go code had never been read.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from workers.cbom.adapters._source import SOURCE_LANGUAGES, source_coverage
from workers.cbom.adapters.cbomkit_action import SOURCE_SUFFIXES as ACTION_SURFACES
from workers.cbom.adapters.cbomkit_action import CBOMkitActionAdapter
from workers.cbom.adapters.cbomkit_theia import CBOMkitTheiaAdapter
from workers.cbom.adapters.cdxgen_cbom import SOURCE_SUFFIXES as CDXGEN_SURFACES
from workers.cbom.adapters.cdxgen_cbom import CdxgenCBOMAdapter
from workers.sbom.adapters.common import EngineImage

from axebom_shared.adapters.base import GenerateResult, ResultStatus, ScanTarget
from axebom_shared.sandbox import SandboxResult

EMPTY: dict[str, Any] = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}


class StubResolver:
    def image_for(self, engine_id: str) -> EngineImage:
        return EngineImage(
            reference=f"example.invalid/{engine_id}:1.0.0", version="1.0.0", digest_pinned=True
        )


def tree(root: Path, *files: str) -> Path:
    ws = root / "src"
    ws.mkdir(exist_ok=True)
    for name in files:
        path = ws / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("// fixture\n", encoding="utf-8")
    return ws


def run(adapter: type, ws: Path) -> GenerateResult:
    target = ScanTarget(scan_id="s", job_id="j", kind="git", workspace=ws)
    return adapter(resolver=StubResolver()).interpret(
        target,
        EMPTY,
        SandboxResult(exit_code=0, stdout=json.dumps(EMPTY)),
        GenerateResult(status=ResultStatus.SUCCEEDED),
    )


@pytest.mark.parametrize("surfaces", [ACTION_SURFACES, CDXGEN_SURFACES])
def test_every_adapter_surface_is_a_known_source_language(
    surfaces: dict[str, tuple[str, ...]],
) -> None:
    """One name per language, or a covered row and a gap row never meet."""
    for surface, suffixes in surfaces.items():
        assert SOURCE_LANGUAGES[surface] == suffixes


def test_a_go_repository_is_a_gap_not_a_clean_result(tmp_path: Path) -> None:
    ws = tree(tmp_path, "cmd/main.go", "src/App.java")

    action = run(CBOMkitActionAdapter, ws)

    assert action.ecosystems_covered == ["java-source"]
    assert action.ecosystems_uncovered == ["go-source"]


def test_a_repository_with_only_go_is_still_a_gap(tmp_path: Path) -> None:
    """Nothing for the engine to read is `succeeded` — and the Go is still named."""
    ws = tree(tmp_path, "main.go", "crypto/sign.go")

    action = run(CBOMkitActionAdapter, ws)

    assert action.status is ResultStatus.SUCCEEDED
    assert action.ecosystems_covered == []
    assert action.ecosystems_uncovered == ["go-source"]


def test_between_them_the_source_engines_leave_no_false_gap(tmp_path: Path) -> None:
    """Each engine names what the other reads; CoverageGaps' rule (a gap only
    where NO engine covered it) then leaves exactly the language nobody reads."""
    ws = tree(tmp_path, "App.java", "web/app.ts", "native/aes.c")

    action = run(CBOMkitActionAdapter, ws)
    cdxgen = run(CdxgenCBOMAdapter, ws)
    theia = run(CBOMkitTheiaAdapter, ws)

    covered = {*action.ecosystems_covered, *cdxgen.ecosystems_covered, *theia.ecosystems_covered}
    reported = {
        *action.ecosystems_uncovered,
        *cdxgen.ecosystems_uncovered,
        *theia.ecosystems_uncovered,
    }
    assert covered == {"java-source", "js-source"}
    assert reported - covered == {"c-cpp-source"}


def test_theia_reads_no_source_and_says_so(tmp_path: Path) -> None:
    ws = tree(tmp_path, "App.java", "certs/server.pem")

    theia = run(CBOMkitTheiaAdapter, ws)

    assert theia.ecosystems_uncovered == ["java-source"]


def test_vendored_trees_are_not_the_project(tmp_path: Path) -> None:
    ws = tree(tmp_path, "node_modules/lib/index.js", ".venv/lib/site.py")

    assert source_coverage(ws, CDXGEN_SURFACES) == ([], [])


class NoRunSandbox:
    """A sandbox that fails the test if a container is started."""

    def check(self) -> dict[str, str]:
        return {"runtime": "fake"}

    def run(self, **_: Any) -> SandboxResult:
        raise AssertionError("cdxgen-cbom was started on a tree with no JS/TS")


def test_cdxgen_is_not_started_where_there_is_no_js(tmp_path: Path) -> None:
    """⚠ ON A MAVEN JAVA REPOSITORY cdxgen `cbom` HANGS until the wall clock kills
    it (atom's reachables slice; live on 1MansiS/JavaCrypto, 2026-09-11). It
    reads only JS/TS, so with none present it is not run at all."""
    ws = tree(tmp_path, "pom.xml", "src/main/java/App.java")
    target = ScanTarget(scan_id="s", job_id="j", kind="git", workspace=ws)

    result = CdxgenCBOMAdapter(resolver=StubResolver(), sandbox=NoRunSandbox()).generate(target)

    assert result.status is ResultStatus.SUCCEEDED
    assert result.ecosystems_uncovered == ["java-source"]
    assert [d["code"] for d in result.diagnostics] == ["ENGINE_NO_SOURCE_FOR_ENGINE"]


def test_cdxgen_s_hang_costs_minutes_not_a_quarter_hour() -> None:
    assert CdxgenCBOMAdapter(resolver=StubResolver()).limits().wall_clock_sec <= 300
