"""Adapter-contract tests.

These assert the properties that keep a missing engine from becoming a silent
gap in a compliance report.
"""

from __future__ import annotations

import pytest

from axebom_shared.adapters import (
    Availability,
    Capabilities,
    EngineMode,
    RawArtifact,
    Registry,
    ResultStatus,
    ScanTarget,
    ToolAdapterBase,
)


@pytest.fixture(scope="module")
def registry() -> Registry:
    return Registry.from_manifest()


def test_registry_loads_every_engine(registry: Registry) -> None:
    ids = registry.ids()
    # The manifest is the source of truth for WHICH engines exist; asserting a
    # specific count here would be the hardcoded-count anti-pattern. Assert the
    # ones the pipeline structurally depends on instead.
    for required in ("syft", "grype", "trivy-fs", "trivy-image", "osv-scanner"):
        assert required in ids, f"{required} missing from the registry"


def test_trivy_fs_and_image_are_separate_engines(registry: Registry) -> None:
    """The unit is (tool, mode), not tool.

    They have different invocations, capabilities and parsers. Collapsing them
    would leave one adapter guessing which mode it is running in.
    """
    fs = registry.get("trivy-fs")
    img = registry.get("trivy-image")

    assert fs is not img
    assert "git" in fs.capabilities.source_kinds
    assert "image" in img.capabilities.source_kinds
    assert "image" not in fs.capabilities.source_kinds


def test_availability_never_raises(registry: Registry) -> None:
    """An engine that cannot run is `unavailable`, never an exception.

    Raising would fail the whole scan and cost every OTHER engine's output too.
    """
    for engine_id in registry.ids():
        a = registry.get(engine_id).available()
        assert isinstance(a, Availability)
        assert isinstance(a.mode, EngineMode)


def test_unavailable_engines_state_a_reason(registry: Registry) -> None:
    """The reason is what the report's Engine Coverage section shows a customer.

    "unavailable" with no explanation is indistinguishable from a bug.
    """
    for engine_id, a in registry.availability().items():
        if not a.available:
            assert a.detail.strip(), f"{engine_id} is unavailable with no stated reason"


def test_disabled_engine_carries_its_deferral_reason(registry: Registry) -> None:
    a = registry.get("sonar-cryptography").available()
    assert not a.available
    assert "SonarQube" in a.detail


def test_internal_engines_are_always_available(registry: Registry) -> None:
    """HBOM import has no artifact to fetch, so nothing can make it unavailable."""
    for engine_id in ("hbom-csv", "hbom-form"):
        a = registry.get(engine_id).available()
        assert a.available
        assert a.mode is EngineMode.INTERNAL


def test_for_family_filters(registry: Registry) -> None:
    sbom = {a.engine_id for a in registry.for_family("sbom")}
    assert {"syft", "grype", "osv-scanner"} <= sbom
    assert "hbom-csv" not in sbom

    hbom = {a.engine_id for a in registry.for_family("hbom")}
    assert "hbom-csv" in hbom


def test_unknown_engine_lists_known_ones(registry: Registry) -> None:
    with pytest.raises(KeyError, match="unknown engine"):
        registry.get("does-not-exist")


# ---------------------------------------------------------------------------
# The contract itself
# ---------------------------------------------------------------------------


def test_generate_and_parse_are_not_yet_implemented(registry: Registry) -> None:
    """Phase 2 implements availability only.

    They raise NotImplementedError naming the owning phase rather than
    returning empty results — an empty inventory that renders as a clean
    report is precisely the failure mode to avoid.
    """
    syft = registry.get("syft")
    target = ScanTarget(
        scan_id="s", job_id="j", kind="git", workspace=__import__("pathlib").Path(".")
    )
    with pytest.raises(NotImplementedError, match="Phase 7"):
        syft.generate(target)
    with pytest.raises(NotImplementedError, match="Phase 7"):
        syft.parse([])


def test_scan_target_carries_no_credentials() -> None:
    """Workers hold no credentials (ADR-0008).

    A structural assertion, not a style check: if a token field is added here,
    the sandbox's security property — that compromising a scanner yields only
    the code it was scanning — quietly stops holding.
    """
    target = ScanTarget(
        scan_id="s", job_id="j", kind="git", workspace=__import__("pathlib").Path(".")
    )
    forbidden = ("token", "password", "secret", "credential", "auth")
    for attr in vars(target):
        assert not any(f in attr.lower() for f in forbidden), (
            f"ScanTarget.{attr} looks credential-shaped; only the fetcher holds "
            f"credentials (docs/ADR/0008)"
        )


def test_partial_is_a_distinct_status() -> None:
    """`partial` must not collapse into success or failure.

    Into failure loses the output; into success loses the gap — and losing the
    gap turns an unknown into a false negative the customer trusts.
    """
    assert ResultStatus.PARTIAL not in (ResultStatus.SUCCEEDED, ResultStatus.FAILED)
    assert len({s.value for s in ResultStatus}) == len(list(ResultStatus))


def test_custom_adapter_satisfies_the_contract() -> None:
    """A new engine is an adapter, not a change to the orchestrator."""

    class FakeAdapter(ToolAdapterBase):
        def available(self) -> Availability:
            return Availability(True, EngineMode.INTERNAL, "1.0", "fake")

    caps = Capabilities(
        engine_id="fake", families=("sbom",), source_kinds=("git",), produces=("components",)
    )
    adapter = FakeAdapter(caps)

    assert adapter.engine_id == "fake"
    assert adapter.available().available
    with pytest.raises(NotImplementedError):
        adapter.parse(
            [
                RawArtifact(
                    role="native_output",
                    path=__import__("pathlib").Path("x"),
                    media_type="application/json",
                )
            ]
        )
