"""The golden corpus — normalization replayed over pinned raw artifacts.

⚠ THESE TESTS RUN NO SCANNERS AND TOUCH NO NETWORK.

They read `fixtures/*/raw/*.json`, which were produced once by real engines and
committed. That is what makes them deterministic, fast, offline, and stable when
an upstream tool changes its output — and it is the same property (ADR-0003)
that lets a normalizer bug be fixed by re-normalizing rather than re-scanning.

Each fixture proves something specific; its README says what. The assertions
here are the ones that would silently produce a wrong number, not a crash.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from .normalize_runner import normalize_fixture

FIXTURES = Path("fixtures")

#: Fixtures with committed raw artifacts.
#:
#: Discovered rather than listed, so a fixture added without its raw/ directory
#: is simply not tested instead of failing the suite for the wrong reason.
AVAILABLE = sorted(p.parent.name for p in FIXTURES.glob("*/raw") if any(p.glob("*.json")))


def canonical(name: str) -> dict:
    return normalize_fixture(FIXTURES / name)


@pytest.mark.golden
@pytest.mark.parametrize("name", AVAILABLE)
def test_normalization_is_deterministic(name: str) -> None:
    """⚠ THE PROPERTY EVERYTHING ELSE RESTS ON.

    Same artifacts in, byte-identical canonical model out. Without it a report
    cannot be defended six months later, `renormalize` cannot be trusted, and
    every golden diff flaps — and a flapping test gets ignored, which is worse
    than not having it.
    """
    first = json.dumps(canonical(name), sort_keys=True)
    second = json.dumps(canonical(name), sort_keys=True)
    assert first == second


@pytest.mark.golden
@pytest.mark.parametrize("name", AVAILABLE)
def test_both_coverage_numbers_are_published(name: str) -> None:
    """⚠ Publishing only `declaration_pct` and calling it coverage is how tools
    in this space produce a misleading 100%."""
    coverage = canonical(name)["coverage"]
    assert "completeness_pct" in coverage
    assert "declaration_pct" in coverage
    assert coverage["denominator"] > 0
    # The formula is rendered so the number is auditable rather than magic.
    assert coverage["formula"]
    assert coverage["declaration_pct"] >= coverage["completeness_pct"], (
        "declaration counts a superset of what completeness counts, so it can "
        "never be the lower number"
    )


@pytest.mark.golden
@pytest.mark.parametrize("name", AVAILABLE)
def test_every_report_states_what_it_could_not_see(name: str) -> None:
    """Invariant 12: Engine Coverage is mandatory, and includes the gaps."""
    result = canonical(name)
    rows = result["engine_coverage"]
    assert rows, "a report with no Engine Coverage section hides its own gaps"
    assert result["known_unknowns"], "known_unknowns is derived, never blank"

    statuses = {row["status"] for row in rows}
    assert statuses, "every requested engine has a terminal status"


@pytest.mark.golden
@pytest.mark.parametrize("name", AVAILABLE)
def test_provenance_is_complete_enough_to_replay(name: str) -> None:
    """ "Where did this line come from?" must have an answer without re-running."""
    provenance = canonical(name)["provenance"]
    assert provenance["ruleset_version"]
    assert provenance["spdx_license_list_version"]
    assert provenance["normalization_version"] >= 1
    assert provenance["engines"]


@pytest.mark.golden
@pytest.mark.parametrize("name", AVAILABLE)
def test_no_component_is_silently_dropped(name: str) -> None:
    """Every component is either scored or explicitly counted as unscored."""
    result = canonical(name)
    scored = result["coverage"]["scored_entities"]
    assert scored >= result["component_count"] - result["unidentified_count"]


# -- what each fixture specifically proves --------------------------------


@pytest.mark.golden
@pytest.mark.skipif("npm-simple" not in AVAILABLE, reason="fixture not generated")
def test_npm_simple_deduplicates_across_engines() -> None:
    """The baseline. Four engines see lodash; the BOM contains one lodash."""
    result = canonical("npm-simple")
    keys = [c["component_key"] for c in result["components"]]

    lodash = [k for k in keys if "lodash" in k]
    assert len(lodash) == 1, f"lodash was not deduplicated: {lodash}"

    component = next(c for c in result["components"] if "lodash" in c["component_key"])
    engines = {o["engine"] for o in component["observed_by"]}
    assert len(engines) > 1, "the merge should record every engine that saw it"


@pytest.mark.golden
@pytest.mark.skipif("npm-simple" not in AVAILABLE, reason="fixture not generated")
def test_npm_simple_reports_one_finding_per_vulnerability() -> None:
    """⚠ Deduping on the primary id inflates counts roughly threefold.

    grype reports GHSA, osv-scanner reports GHSA plus CVE aliases. One
    vulnerability on one component must be one finding, with both engines named.
    """
    result = canonical("npm-simple")

    seen: set[tuple[str, str]] = set()
    for finding in result["findings"]:
        key = (finding["vuln_cluster_id"], finding["component_key"])
        assert key not in seen, f"duplicate finding for {key}"
        seen.add(key)

    multi = [f for f in result["findings"] if len(f["detected_by"]) > 1]
    assert multi, "no finding was corroborated by two engines — dedup did nothing"


@pytest.mark.golden
@pytest.mark.skipif("npm-simple" not in AVAILABLE, reason="fixture not generated")
def test_findings_display_a_cve_when_one_is_known() -> None:
    """CVE is the id a remediation ticket quotes, and the alias closure is what
    recovers it when the scanner only reported a GHSA."""
    result = canonical("npm-simple")
    displayed = {f["display_id"] for f in result["findings"]}
    assert any(d.startswith("CVE-") for d in displayed), (
        f"no finding resolved to a CVE: {displayed}"
    )


@pytest.mark.golden
@pytest.mark.skipif("pypi-normalization" not in AVAILABLE, reason="fixture not generated")
def test_pypi_names_are_pep503_normalized() -> None:
    """⚠ The most common dedup bug in Python SBOM tooling.

    PyYAML and pyyaml are one project; zope.interface and zope-interface are one
    project. An implementation comparing raw strings reports each twice and
    inflates the count without ever looking wrong.
    """
    keys = [c["component_key"] for c in canonical("pypi-normalization")["components"]]
    joined = " ".join(keys)

    assert "pkg:pypi/pyyaml@" in joined, keys
    assert "PyYAML" not in joined
    assert "pkg:pypi/zope-interface@" in joined
    assert "zope.interface" not in joined
    assert "pkg:pypi/django-rest-framework@" in joined


@pytest.mark.golden
@pytest.mark.skipif("maven-case" not in AVAILABLE, reason="fixture not generated")
def test_maven_coordinates_keep_their_case() -> None:
    """⚠ Lowercasing Maven merges genuinely distinct artifacts.

    That under-reports — and a missing component is a missing vulnerability,
    with nothing in the report to say anything is absent.
    """
    keys = " ".join(c["component_key"] for c in canonical("maven-case")["components"])
    assert "MavenCase" in keys, "the mixed-case artifactId was lowercased"
    assert "com.fasterxml.jackson.core/jackson-databind" in keys


@pytest.mark.golden
@pytest.mark.skipif("golang-incompatible" not in AVAILABLE, reason="fixture not generated")
def test_go_identity_survives_all_three_traps() -> None:
    """Capitalisation, +incompatible, and the .vN path suffix."""
    keys = " ".join(c["component_key"] for c in canonical("golang-incompatible")["components"])

    assert "Masterminds" in keys, "proxy escaping was decoded to the wrong case"
    assert "+incompatible" in keys, "the suffix was stripped, naming a version that does not exist"
    assert "gopkg.in/yaml.v3" in keys, "the .v3 path suffix was treated as a version"


@pytest.mark.golden
@pytest.mark.skipif("golang-incompatible" not in AVAILABLE, reason="fixture not generated")
def test_the_same_go_module_is_not_counted_twice() -> None:
    """⚠ REGRESSION GUARD — this fixture found a real bug.

    One engine emits `v24.0.5+incompatible`, another `24.0.5+incompatible`. The
    `v` is part of Go's version grammar, not part of the number. Unnormalized,
    docker/docker appeared twice and every one of its vulnerabilities was
    counted twice.
    """
    keys = [c["component_key"] for c in canonical("golang-incompatible")["components"]]
    docker = [k for k in keys if "docker/docker" in k]
    assert len(docker) == 1, f"docker/docker was counted more than once: {docker}"


@pytest.mark.golden
@pytest.mark.skipif("monorepo-multiroot" not in AVAILABLE, reason="fixture not generated")
def test_a_monorepo_yields_multiple_ecosystems() -> None:
    """⚠ A scanner that stops at the first manifest reports a smaller,
    cleaner-looking component count for a repository it barely scanned."""
    result = canonical("monorepo-multiroot")
    ecosystems = {c["ecosystem"] for c in result["components"] if c.get("ecosystem")}
    assert len(ecosystems) >= 3, f"only found {ecosystems}"


# -- structural guarantees ------------------------------------------------


@pytest.mark.golden
@pytest.mark.parametrize("name", AVAILABLE)
def test_an_orphan_never_has_a_fabricated_depth(name: str) -> None:
    """⚠ Forcing an orphan to depth 1 inflates the direct-dependency count."""
    result = canonical(name)
    depth = result["graph"]["depth"]
    for orphan in result["graph"]["orphans"]:
        assert orphan not in depth, f"{orphan} is an orphan but carries a depth"


@pytest.mark.golden
@pytest.mark.parametrize("name", AVAILABLE)
def test_fix_versions_are_ordered_or_admitted_unknown(name: str) -> None:
    """Never a guessed ordering: `unknown` is the answer when no comparator
    exists, because a confident wrong version is unrecoverable."""
    for finding in canonical(name)["findings"]:
        assert finding["fix_version_ordering"] in ("comparator", "unknown", "none")
        if finding["fix_version_ordering"] == "unknown":
            assert finding["fixed_in_min"] == "", (
                "a minimum was reported despite having no ordering to compute it"
            )


@pytest.mark.golden
@pytest.mark.parametrize("name", AVAILABLE)
def test_every_cluster_can_explain_its_merges(name: str) -> None:
    """A compliance product must answer "why did these two become one?"."""
    for cluster in canonical(name)["vuln_clusters"]:
        assert cluster["display_id_at_render"], "the display id must be pinned at render"
        if len(cluster["members"]) > 1:
            assert cluster["merges"], (
                f"{cluster['cluster_id']} merged {len(cluster['members'])} ids with no "
                f"recorded evidence"
            )
            for merge in cluster["merges"]:
                assert merge["source"], "a merge with no source is unexplainable"


# -- the golden diff ------------------------------------------------------

GOLDEN = sorted(p.parent.parent.name for p in FIXTURES.glob("*/expected/canonical.json"))


@pytest.mark.golden
@pytest.mark.parametrize("name", GOLDEN)
def test_canonical_output_matches_the_committed_golden(name: str) -> None:
    """⚠ THE GUARDRAIL AGAINST SILENTLY WRONG OUTPUT.

    Normalizer changes are gated on this. A rule change that alters a component
    count, a coverage percentage or a dedup decision fails here — which is the
    only way those changes get noticed, because none of them crash anything.

    Updating a golden is a DELIBERATE act requiring a justification in the commit
    message (`--write-expected`). A golden updated to make a test pass is not a
    guardrail, it is a rubber stamp.
    """
    expected_path = FIXTURES / name / "expected" / "canonical.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    actual = canonical(name)

    # Compared field by field so a failure names WHAT changed rather than
    # dumping two 30 KB documents at the reader.
    for key in ("component_count", "finding_count", "unidentified_count"):
        assert actual[key] == expected[key], (
            f"{name}: {key} changed {expected[key]} -> {actual[key]}. If this is "
            f"intended, re-run with --write-expected and justify it in the commit"
        )

    assert actual["coverage"]["completeness_pct"] == expected["coverage"]["completeness_pct"], (
        f"{name}: completeness_pct changed"
    )
    assert actual["coverage"]["declaration_pct"] == expected["coverage"]["declaration_pct"], (
        f"{name}: declaration_pct changed"
    )

    actual_keys = [c["component_key"] for c in actual["components"]]
    expected_keys = [c["component_key"] for c in expected["components"]]
    assert actual_keys == expected_keys, (
        f"{name}: the component set changed\n"
        f"  added:   {sorted(set(actual_keys) - set(expected_keys))}\n"
        f"  removed: {sorted(set(expected_keys) - set(actual_keys))}"
    )

    actual_findings = sorted((f["display_id"], f["component_key"]) for f in actual["findings"])
    expected_findings = sorted((f["display_id"], f["component_key"]) for f in expected["findings"])
    assert actual_findings == expected_findings, f"{name}: the finding set changed"

    # Finally the whole document, so nothing outside the named fields drifts.
    assert json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True), (
        f"{name}: canonical output differs from the golden outside the checked fields"
    )


# -- re-normalization -----------------------------------------------------


@pytest.mark.golden
@pytest.mark.skipif("npm-simple" not in AVAILABLE, reason="fixture not generated")
def test_renormalize_produces_version_2_without_touching_version_1() -> None:
    """⚠ THE PAYOFF OF ADR-0003.

    Fixing a normalizer bug replays STORED artifacts into a new version. It does
    not re-run the scanners — which would not even be reproducible, because the
    vulnerability databases have moved and the tools have changed since.

    Version 1 must come back byte-identical afterwards, or a report issued
    against it no longer resolves to the data it was rendered from.
    """
    from encorebom_shared.normalize.renormalize import renormalize

    from .normalize_runner import load_artifacts, sbom_fields

    fixture = FIXTURES / "npm-simple"
    version_1 = canonical("npm-simple")
    v1_bytes = json.dumps(version_1, sort_keys=True)

    result, delta = renormalize(
        load_artifacts(fixture / "raw"),
        version_1,
        scan_id="fixture-npm-simple",
        fields=sbom_fields(),
        alias_snapshot_id="fixture-npm-simple-aliases",
    )
    version_2 = result.as_dict()

    assert version_2["provenance"]["normalization_version"] == 2
    assert version_1["provenance"]["normalization_version"] == 1

    # ⚠ Version 1 is untouched. Not "restored" — never modified.
    assert json.dumps(canonical("npm-simple"), sort_keys=True) == v1_bytes

    # Same artifacts and same ruleset, so the content must not have moved.
    assert not delta.changed, f"re-normalization changed the answer: {delta.summary()}"
    assert delta.from_version == 1
    assert delta.to_version == 2


@pytest.mark.golden
@pytest.mark.skipif("npm-simple" not in AVAILABLE, reason="fixture not generated")
def test_vex_joins_to_findings_without_changing_them() -> None:
    """A suppressed finding is still a finding, with its justification beside
    it. Removing it would make "assessed and not applicable" indistinguishable
    from "never seen"."""
    from encorebom_shared.normalize.pipeline import normalize
    from encorebom_shared.normalize.vex import VexStatement, apply

    from .normalize_runner import load_artifacts, sbom_fields

    result = normalize(
        load_artifacts(FIXTURES / "npm-simple" / "raw"),
        scan_id="fixture-npm-simple",
        fields=sbom_fields(),
    )
    assert result.findings, "the fixture should produce findings to join against"

    target = result.findings[0]
    before = target.as_dict()

    rows, diagnostics = apply(
        result.findings,
        [
            VexStatement(
                id="vex-1",
                cluster_id=target.vuln_cluster_id,
                component_key=target.component_key,
                status="not_affected",
                justification="vulnerable_code_not_in_execute_path",
                created_at="2026-08-17T00:00:00Z",
            )
        ],
    )

    assert len(rows) == 1
    assert rows[0]["suppresses_from_actionable"] is True
    assert target.as_dict() == before, "VEX mutated the finding it joined to"
    assert any(d["code"] == "VEX_SUPPRESSED_FINDINGS" for d in diagnostics)
