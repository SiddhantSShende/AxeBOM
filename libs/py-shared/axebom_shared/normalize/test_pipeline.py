"""pipeline.normalize() — the findings→components join, exercised directly.

⚠ WHY THIS FILE EXISTS AT ALL. `normalize()` had no unit test of its own; it
was covered only end-to-end through `workers/sbom/test_golden.py` against
fixture artifacts. That is why the patch_status join could be missing entirely
— every ingredient was unit-tested in isolation (`resolve_fix_version`,
`patch_status`, `merge`), and nothing asserted they were ever wired together.
These tests assert the WIRING, with synthetic artifacts rather than fixtures,
so a future refactor that drops the join fails here rather than silently
producing a column of `not-provided`.
"""

from __future__ import annotations

from typing import Any

from .coverage import Field
from .pipeline import Artifact, normalize


def f(field_id: str, path: str, weight: int = 3) -> Field:
    return Field(id=field_id, name=field_id, canonical_path=path, weight=weight)


FIELDS = [
    f("name", "component.name"),
    f("version", "component.version_raw"),
    f("patch_status", "component.patch_status"),
]


def grype_match(purl: str, vuln_id: str, fixed: list[str]) -> dict[str, Any]:
    """One grype match: a component contribution AND a finding, as grype emits."""
    return {
        "vulnerability": {
            "id": vuln_id,
            "severity": "High",
            "fix": {"versions": fixed, "state": "fixed" if fixed else "unknown"},
        },
        "artifact": {"purl": purl, "name": purl.split("/")[-1].split("@")[0]},
    }


def run(matches: list[dict[str, Any]]):
    return normalize(
        [Artifact(engine="grype", payload={"matches": matches}, engine_version="0.117.0")],
        scan_id="test-scan",
        fields=FIELDS,
    )


def component_by_purl(result, purl: str):
    for component in result.components:
        if component.purl == purl:
            return component
    raise AssertionError(
        f"no component with purl {purl!r} in {[c.purl for c in result.components]}"
    )


def test_a_component_with_an_available_fix_is_patch_available() -> None:
    """The installed version is below the minimum fix — a patch exists, unapplied."""
    result = run([grype_match("pkg:npm/lodash@4.17.20", "CVE-2021-23337", ["4.17.21"])])
    assert component_by_purl(result, "pkg:npm/lodash@4.17.20").patch_status == "patch-available"


def test_a_component_at_or_above_the_fix_is_up_to_date() -> None:
    result = run([grype_match("pkg:npm/lodash@4.17.21", "CVE-2021-23337", ["4.17.21"])])
    assert component_by_purl(result, "pkg:npm/lodash@4.17.21").patch_status == "up-to-date"


def test_a_finding_with_no_fix_version_is_no_fix_available() -> None:
    """⚠ NOT `unknown`. Zero fix versions reported is a finding, not a gap."""
    result = run([grype_match("pkg:npm/lodash@4.17.20", "CVE-2021-23337", [])])
    assert component_by_purl(result, "pkg:npm/lodash@4.17.20").patch_status == "no-fix-available"


def test_multiple_findings_aggregate_worst_case_first() -> None:
    """⚠ THE WHOLE POINT: one unfixable finding defines the component.

    Two findings against the same component — one with an available fix, one
    with none at all. Reporting the first would hide the second.
    """
    purl = "pkg:npm/lodash@4.17.20"
    result = run(
        [
            grype_match(purl, "CVE-2021-23337", ["4.17.21"]),
            grype_match(purl, "CVE-2020-8203", []),
        ]
    )
    assert component_by_purl(result, purl).patch_status == "no-fix-available"


def test_a_component_with_no_findings_is_left_unset_not_up_to_date() -> None:
    """⚠ "Nothing was reported" is not "we checked and it is clean".

    Defaulting to up-to-date would manufacture a substantive claim out of an
    absence — exactly what `not-provided` exists to prevent. The component must
    come out with an empty patch_status, which scores zero on BOTH coverage
    numbers rather than counting as covered.
    """
    clean = "pkg:npm/left-pad@1.3.0"
    vulnerable = "pkg:npm/lodash@4.17.20"
    result = normalize(
        [
            # syft contributes both components; grype reports a finding against
            # only one of them.
            Artifact(
                engine="syft",
                payload={
                    "components": [
                        {"purl": clean, "name": "left-pad", "version": "1.3.0"},
                        {"purl": vulnerable, "name": "lodash", "version": "4.17.20"},
                    ]
                },
                engine_version="1.51.0",
            ),
            Artifact(
                engine="grype",
                payload={"matches": [grype_match(vulnerable, "CVE-2021-23337", ["4.17.21"])]},
                engine_version="0.117.0",
            ),
        ],
        scan_id="test-scan",
        fields=FIELDS,
    )

    assert component_by_purl(result, clean).patch_status == ""
    assert component_by_purl(result, vulnerable).patch_status == "patch-available"


def test_patch_status_reaches_the_canonical_dict_and_the_coverage_score() -> None:
    """It must survive as_dict() (what the writer reads) AND be scored.

    Without `component.patch_status` in `_flatten`, the field scores 0/0 no
    matter how well it is derived — the derivation and the scoring are two
    separate wirings and both have to hold.
    """
    result = run([grype_match("pkg:npm/lodash@4.17.20", "CVE-2021-23337", ["4.17.21"])])

    payload = result.as_dict()
    assert payload["components"][0]["patch_status"] == "patch-available"

    scored = {entry["field_id"]: entry for entry in result.coverage.as_dict()["fields"]}
    assert scored["patch_status"]["present"] == 1
