"""What each engine reports as its headline count, and what it must not.

⚠ THE BUG THIS PINS: `summary` WAS FOUR HARDCODED ZEROS.

Every job published ``{"components": 0, "vulnerabilities": 0, "licenses": 0,
"crypto_assets": 0}``. syft inventoried 21 components in expressjs/express and
the envelope said zero, so ``scan.engine_runs.summary`` held nothing for every
scan ever run.

⚠ AND THE BUG THE OBVIOUS FIX WOULD HAVE INTRODUCED.

Filling all four fields in would have replaced one false zero with three: syft
does not match vulnerabilities and grype does not catalogue licences, so
publishing `0` for those states a fact neither engine established. `None` means
"not measured"; `0` means "measured, none found". Most of these tests exist to
keep those two apart, because nothing downstream can tell them apart once they
have collapsed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from workers.aibom.adapters import AIBomAdapter
from workers.cbom.adapters import CBOMkitTheiaAdapter

from axebom_shared.adapters.base import ResultStatus, ScanTarget
from axebom_shared.adapters.summary import (
    EngineSummary,
    count_cyclonedx,
    count_distinct_vulnerabilities,
    count_spdx,
    dimensions_for,
    summarize,
)
from axebom_shared.sandbox import SandboxResult

from .adapters import (
    DependencyCheckAdapter,
    GrypeAdapter,
    OSVScannerAdapter,
    SyftAdapter,
    SyftSPDXAdapter,
    TrivyFSAdapter,
    TrivyImageAdapter,
)
from .adapters.common import MANIFEST_PATH, EngineImage
from .runner import SBOMWorker
from .test_runner import FakeSandbox, job

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "fixtures"


class StubResolver:
    def image_for(self, engine_id: str) -> EngineImage:
        return EngineImage(reference=f"example.invalid/{engine_id}:1.0.0", version="1.0.0")


IMAGE = StubResolver().image_for("stub")


def target(tmp_path: Path) -> ScanTarget:
    ws = tmp_path / "src"
    ws.mkdir(exist_ok=True)
    return ScanTarget(scan_id="s", job_id="j", kind="git", workspace=ws)


def raw(fixture: str, name: str) -> str:
    return (FIXTURES / fixture / "raw" / name).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The distinction the whole module exists for
# ---------------------------------------------------------------------------


def test_a_dimension_an_engine_does_not_measure_is_null_not_zero(tmp_path: Path) -> None:
    """⚠ THE CENTRAL CLAIM.

    syft catalogues components and licences. It never matches a vulnerability
    and never looks for a cryptographic asset. `0` in either field reads as a
    clean result for a question syft was never asked.
    """
    result = SyftAdapter(resolver=StubResolver()).classify(
        target(tmp_path),
        SandboxResult(exit_code=0, stdout=raw("npm-simple", "syft.json")),
        [],
        IMAGE,
    )
    got = result.summary.as_dict()

    assert got["components"] == 4
    assert got["vulnerabilities"] is None, (
        "syft reported a vulnerability count; it does not match vulnerabilities, "
        "and 0 here reads as 'syft found none'"
    )
    assert got["crypto_assets"] is None


def test_a_dimension_an_engine_measured_and_found_none_in_is_zero_not_null() -> None:
    """The other half. Zero is a MEASUREMENT and must survive as one.

    The npm fixture carries no licence data at all, so syft's licence count is
    a genuine zero — it looked, and there was nothing to find. Rendering that
    as null would hide a real gap in the scanned project behind "we did not
    check".
    """
    payload = json.loads(raw("npm-simple", "syft.json"))
    counts = count_cyclonedx(payload)
    assert counts["licenses"] == 0

    summary = summarize(SyftAdapter(resolver=StubResolver()).capabilities, counts)
    assert summary.licenses == 0
    assert summary.licenses is not None


def test_an_empty_summary_reports_every_field_as_null() -> None:
    """A run that measured nothing says so in every field, explicitly.

    Omitting the nulls would leave a consumer unable to tell "this engine does
    not measure it" from "this publisher predates the field".
    """
    assert EngineSummary().as_dict() == {
        "components": None,
        "vulnerabilities": None,
        "licenses": None,
        "crypto_assets": None,
    }
    assert EngineSummary().measured() == frozenset()


# ---------------------------------------------------------------------------
# What each engine is entitled to report
# ---------------------------------------------------------------------------

#: Every wired adapter, and the manifest id its capabilities are declared under.
#:
#: syft-spdx is the SECOND syft pass — the manifest carries it as syft's
#: `also_emits`, not as an engine of its own — so both share syft's entry.
ADAPTERS: dict[str, tuple[type, str]] = {
    "syft": (SyftAdapter, "syft"),
    "syft-spdx": (SyftSPDXAdapter, "syft"),
    "grype": (GrypeAdapter, "grype"),
    "trivy-fs": (TrivyFSAdapter, "trivy-fs"),
    "trivy-image": (TrivyImageAdapter, "trivy-image"),
    "osv-scanner": (OSVScannerAdapter, "osv-scanner"),
    "dependency-check": (DependencyCheckAdapter, "dependency-check"),
    "cbomkit-theia": (CBOMkitTheiaAdapter, "cbomkit-theia"),
    "ai-bom": (AIBomAdapter, "ai-bom"),
}


def manifest_produces() -> dict[str, tuple[str, ...]]:
    data = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8")) or {}
    return {
        entry["id"]: tuple(entry.get("produces", ()))
        for entry in data.get("tools", []) or []
        if entry.get("id")
    }


@pytest.mark.parametrize("name", sorted(ADAPTERS))
def test_an_adapters_produces_matches_the_manifest(name: str) -> None:
    """⚠ THE MANIFEST IS THE SSOT AND THIS COPY HAD ALREADY DRIFTED.

    docs/04-OSINT-INTEGRATION.md owns OSINT/tools.manifest.yaml, and each
    adapter restates `produces` in a module-level Capabilities. Nothing checked
    the two agreed, and dependency-check's copy said `(vulnerabilities,)` where
    the manifest says `[components, vulnerabilities]` — so its component count
    would have been silently dropped from every envelope, looking exactly like
    an engine that does not catalogue components.
    """
    cls, manifest_id = ADAPTERS[name]
    declared = manifest_produces()[manifest_id]
    assert cls(resolver=StubResolver()).capabilities.produces == declared, (
        f"{name} restates `produces` and it no longer matches the manifest entry "
        f"for {manifest_id!r}; the manifest is the source of truth"
    )


@pytest.mark.parametrize("name", sorted(ADAPTERS))
def test_every_produces_token_maps_to_a_summary_decision(name: str) -> None:
    """No manifest token may be unknown to the summary.

    An unrecognised token is dropped with a log line nobody reads, and the
    dimension it named then reports null forever — indistinguishable from an
    engine that does not measure it.
    """
    from axebom_shared.adapters.summary import _DIMENSION_OF

    cls, _ = ADAPTERS[name]
    unmapped = [
        t for t in cls(resolver=StubResolver()).capabilities.produces if t not in _DIMENSION_OF
    ]
    assert not unmapped, f"{name} declares {unmapped}, which summary.py does not map"


def test_a_token_that_is_not_an_inventory_count_is_deliberately_dropped() -> None:
    """trivy-fs declares `secrets`, and a secret is not a summary dimension.

    Folding it into `vulnerabilities` would put a number in a compliance report
    that no CVE backs.
    """
    caps = TrivyFSAdapter(resolver=StubResolver()).capabilities
    assert "secrets" in caps.produces
    assert dimensions_for(caps) == frozenset({"components", "vulnerabilities", "licenses"})


# ---------------------------------------------------------------------------
# The counts themselves, against the committed fixtures
# ---------------------------------------------------------------------------

#: (fixture, engine, adapter, artifact, expected non-null counts).
#:
#: Read off the fixtures, which are the same documents the golden corpus
#: normalizes — so a summary that disagrees with the canonical output here is a
#: counting bug, not a fixture change.
FIXTURE_COUNTS: list[tuple[str, str, str, dict[str, int]]] = [
    ("npm-simple", "syft", "syft.json", {"components": 4, "licenses": 0}),
    ("npm-simple", "syft-spdx", "syft-spdx.json", {"components": 4, "licenses": 0}),
    ("npm-simple", "grype", "grype.json", {"vulnerabilities": 5}),
    ("maven-case", "syft", "syft.json", {"components": 5, "licenses": 0}),
    ("maven-case", "grype", "grype.json", {"vulnerabilities": 7}),
    ("monorepo-multiroot", "syft", "syft.json", {"components": 11, "licenses": 0}),
    ("monorepo-multiroot", "grype", "grype.json", {"vulnerabilities": 13}),
    ("pypi-normalization", "syft", "syft.json", {"components": 6, "licenses": 0}),
    ("golang-incompatible", "syft", "syft.json", {"components": 5, "licenses": 0}),
]


@pytest.mark.parametrize(("fixture", "engine", "artifact", "expected"), FIXTURE_COUNTS)
def test_the_counts_match_the_fixture(
    tmp_path: Path, fixture: str, engine: str, artifact: str, expected: dict[str, int]
) -> None:
    cls, _ = ADAPTERS[engine]
    result = cls(resolver=StubResolver()).classify(
        target(tmp_path),
        SandboxResult(exit_code=0, stdout=raw(fixture, artifact)),
        [],
        IMAGE,
    )
    got = result.summary.as_dict()
    for dimension, count in expected.items():
        assert got[dimension] == count, f"{engine} on {fixture}: {dimension}"
    # Everything not named above must be null, not zero.
    for dimension, value in got.items():
        if dimension not in expected:
            assert value is None, f"{engine} reported {dimension}={value} without measuring it"


# ---------------------------------------------------------------------------
# Counting rules
# ---------------------------------------------------------------------------


def test_findings_are_deduplicated_into_vulnerabilities() -> None:
    """⚠ ONE CVE ACROSS THREE PACKAGES IS ONE VULNERABILITY, NOT THREE.

    grype emits one match per (vulnerability, package) pair; trivy emits one
    entry per vulnerability with an `affects` list. Counting rows would make
    the same project look three times worse under grype than under trivy, in a
    field both publish under the same name.
    """
    assert count_distinct_vulnerabilities(["CVE-1", "CVE-1", "CVE-2"]) == 2


def test_an_unidentified_finding_still_counts() -> None:
    """Dropping it would understate, which is the bug being fixed.

    Two findings with no id cannot be deduplicated against each other, so each
    counts once.
    """
    assert count_distinct_vulnerabilities([None, "", "CVE-1"]) == 3


def test_nested_components_are_counted() -> None:
    """CycloneDX nests, and trivy uses that for multi-root repositories.

    Counting only the top level would report a monorepo's four roots as four
    components — the same understatement one level down.
    """
    doc = {
        "components": [
            {
                "type": "application",
                "name": "root",
                "components": [
                    {"type": "library", "name": "a"},
                    {"type": "library", "name": "b"},
                ],
            },
        ]
    }
    assert count_cyclonedx(doc)["components"] == 3


def test_crypto_assets_are_counted_separately_from_components() -> None:
    """A cryptographic asset is a CycloneDX component with a distinct type.

    Counting it in both fields would double-report a CBOM: 40 assets would
    render as 40 components AND 40 crypto assets in the same envelope.
    """
    doc = {
        "components": [
            {"type": "library", "name": "openssl"},
            {"type": "cryptographic-asset", "name": "RSA-2048"},
            {"type": "cryptographic-asset", "name": "AES-256"},
        ]
    }
    counts = count_cyclonedx(doc)
    assert counts["components"] == 1
    assert counts["crypto_assets"] == 2


@pytest.mark.parametrize(
    ("licenses", "expected"),
    [
        ([{"license": {"id": "MIT"}}], 1),
        ([{"license": {"id": "MIT"}}, {"license": {"id": "MIT"}}], 1),
        ([{"license": {"id": "MIT"}}, {"license": {"id": "Apache-2.0"}}], 2),
        ([{"license": {"name": "Some Bespoke Licence"}}], 1),
        ([{"expression": "MIT OR Apache-2.0"}], 1),
        # ⚠ NOT ASSERTIONS. CLAUDE.md invariant 3: NOASSERTION, unknown and ""
        # all score present = 0, and counting them here would inflate a licence
        # inventory with rows that say nothing.
        ([{"license": {"id": "NOASSERTION"}}], 0),
        ([{"license": {"id": ""}}], 0),
        ([{"license": {"name": "unknown"}}], 0),
        # ⚠ `NONE` IS SUBSTANTIVE FOR COVERAGE AND STILL NAMES NO LICENCE.
        # Invariant 3 makes it count as PRESENT when scoring a component's
        # licence field — "we looked, there is none" is an answer. This is a
        # different question: how many distinct licences were identified. Zero.
        ([{"license": {"id": "NONE"}}], 0),
    ],
)
def test_only_real_licence_assertions_are_counted(
    licenses: list[dict[str, Any]], expected: int
) -> None:
    doc = {"components": [{"type": "library", "name": "x", "licenses": licenses}]}
    assert count_cyclonedx(doc)["licenses"] == expected


def test_spdx_counts_both_concluded_and_declared_licences() -> None:
    doc = {
        "packages": [
            {"name": "a", "licenseConcluded": "MIT", "licenseDeclared": "NOASSERTION"},
            {"name": "b", "licenseConcluded": "NOASSERTION", "licenseDeclared": "Apache-2.0"},
        ]
    }
    assert count_spdx(doc) == {"components": 2, "licenses": 2}


def test_a_shape_change_degrades_the_count_rather_than_raising() -> None:
    """An engine that changes its output must not fail a scan that succeeded."""
    for payload in (None, [], "nonsense", {"components": "not a list"}):
        assert isinstance(count_cyclonedx(payload), dict)
        assert isinstance(count_spdx(payload), dict)


# ---------------------------------------------------------------------------
# The envelope
# ---------------------------------------------------------------------------


def test_a_refused_run_publishes_no_counts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """⚠ `unavailable` MEANS THE OUTPUT WAS NOT ACCEPTED.

    Several adapters count before they reach the check that refuses the run —
    osv-scanner counts every finding, then declares itself unavailable because
    it cannot date them. Publishing those numbers would let a consumer sum
    findings the engine itself declined to stand behind.
    """
    from . import runner as runner_mod

    monkeypatch.setattr(runner_mod.source, "materialize", lambda *a, **k: False)

    worker = SBOMWorker(
        workspace_root=tmp_path / "ws", output_root=tmp_path / "out", sandbox=FakeSandbox()
    )
    result = worker.handle(job("no-such-engine", scan_id="s1", job_id="j1"))

    assert result["status"] == ResultStatus.SKIPPED.value
    assert result["summary"] == {
        "components": None,
        "vulnerabilities": None,
        "licenses": None,
        "crypto_assets": None,
    }


def test_the_envelope_carries_the_engines_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: what the adapter counted is what the orchestrator receives.

    This is the whole defect. syft inventoried 21 components on a live scan of
    expressjs/express and the envelope reported 0.
    """
    from . import runner as runner_mod

    monkeypatch.setattr(runner_mod.source, "materialize", lambda *a, **k: False)

    sandbox = FakeSandbox(SandboxResult(exit_code=0, stdout=raw("npm-simple", "syft.json")))

    worker = SBOMWorker(
        workspace_root=tmp_path / "ws", output_root=tmp_path / "out", sandbox=sandbox
    )
    result = worker.handle(job("syft", scan_id="s2", job_id="j2"))

    assert result["status"] == ResultStatus.SUCCEEDED.value, result
    assert result["summary"]["components"] == 4, result["summary"]
    assert result["summary"]["vulnerabilities"] is None
