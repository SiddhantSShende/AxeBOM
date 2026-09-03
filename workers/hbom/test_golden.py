"""The HBOM golden — `hbom-nested`, replayed and compared byte for byte.

⚠ THIS IS A DIFFERENT SHAPE OF GOLDEN FROM THE SBOM CORPUS, AND DELIBERATELY SO.

`workers/sbom/test_golden.py` replays `fixtures/*/raw/*.json` — scanner output
produced once by real engines and committed. There is no equivalent for
hardware, because no engine produces it: the input IS the customer's CSV. So the
committed artifact here is the parts list itself, and the golden is the
canonical model it normalizes into.

The property is the same one, and it is the property everything else rests on:
same input in, byte-identical canonical model out. Without it a report cannot be
defended six months later, and every golden diff flaps — a flapping test gets
ignored, which is worse than not having it.

Updating `expected.json` requires a justification in the commit message. A
golden that changes silently is a guardrail that has been removed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from .csv_import import parse
from .normalize import normalize_bom

FIXTURE = Path("fixtures") / "hbom-nested"
PARTS = FIXTURE / "parts.csv"
EXPECTED = FIXTURE / "expected.json"


def canonical() -> dict:
    """Normalize the fixture into the committed shape.

    ⚠ NO CLOCK, NO RANDOMNESS, NO ENVIRONMENT. Everything here is a pure
    function of the CSV bytes and the compliance profile. A timestamp anywhere
    in this output would make the golden unusable within a second of writing it.
    """
    result = normalize_bom(parse(PARTS.read_text(encoding="utf-8")).roots)
    coverage = result.coverage
    assert coverage is not None
    manufacturing = result.manufacturing
    assert manufacturing is not None

    return {
        "component_count": result.component_count(),
        "max_depth": result.max_depth(),
        "rows": result.rows,
        "coverage": {
            # ⚠ BOTH NUMBERS, ALWAYS (invariant 3). A golden that pinned only
            # `declaration_pct` would let completeness drift to zero unnoticed,
            # which is precisely the failure the two-number rule exists to stop.
            "completeness_pct": coverage.completeness_pct,
            "declaration_pct": coverage.declaration_pct,
            "denominator": coverage.denominator,
            "scored_entities": coverage.scored_entities,
        },
        # ⚠ PINNED SEPARATELY, UNDER A SEPARATE KEY, AND NEVER MERGED.
        #
        # This is AxeBOM's manufacturing-readiness number, not CERT-In's. It is
        # in the golden for the same reason the compliance pair is — so a
        # change to it has to be deliberate — but the two are kept apart here
        # exactly as they are kept apart everywhere else. The `denominator`
        # matters most: if a manufacturing field ever leaked into the CERT-In
        # field set, `coverage.denominator` above would move and this golden
        # would fail, which is the cheapest possible detector for that mistake.
        "manufacturing_coverage": {
            "completeness_pct": manufacturing.completeness_pct,
            "declaration_pct": manufacturing.declaration_pct,
            "denominator": manufacturing.denominator,
            "scored_entities": manufacturing.scored_entities,
        },
        "diagnostics": sorted(d["code"] for d in result.diagnostics),
    }


@pytest.mark.golden
def test_normalization_is_deterministic() -> None:
    first = json.dumps(canonical(), sort_keys=True)
    second = json.dumps(canonical(), sort_keys=True)
    assert first == second, "the same parts list produced two different canonical models"


@pytest.mark.golden
def test_matches_the_committed_golden() -> None:
    if not EXPECTED.exists():
        pytest.fail(
            f"{EXPECTED} is missing. Write it with "
            f"`python -m workers.hbom.write_golden`, and justify the change in "
            f"the commit message — a golden is a guardrail, not a cache."
        )

    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    actual = canonical()

    if actual != expected:
        # A whole-object diff is unreadable at this size. Name the first
        # divergence, which is almost always enough to see what moved.
        for key in sorted(set(expected) | set(actual)):
            if expected.get(key) != actual.get(key):
                pytest.fail(
                    f"golden diverged at {key!r}:\n"
                    f"  expected {json.dumps(expected.get(key))[:400]}\n"
                    f"  actual   {json.dumps(actual.get(key))[:400]}"
                )
    assert actual == expected


@pytest.mark.golden
def test_the_fixture_proves_what_its_readme_claims() -> None:
    """⚠ A FIXTURE THAT STOPS EXERCISING ITS OWN CASE IS WORSE THAN NO FIXTURE —
    it is a green test that has quietly become a no-op. Each assertion here maps
    to a row of the table in `fixtures/hbom-nested/README.md`.
    """
    result = parse(PARTS.read_text(encoding="utf-8"))
    root = result.roots[0]

    # Four levels of nesting.
    assert root.depth() == 3, "the fixture no longer nests four levels deep"

    # Both supplier relationships, populated distinctly.
    assert root.supplier_info, "the product supplier is empty"
    mcu = root.children[0].children[0]
    assert mcu.component_supplier_info, "the component supplier is empty"
    assert root.supplier_info != mcu.component_supplier_info

    # A level that returns to a shallower depth.
    flash = [c for c in root.children[0].children if c.model_number == "W25Q128JV"]
    assert flash, "the row that returns from level 3 to level 2 is gone"

    # Varied origins — a single-country fixture cannot demonstrate provenance.
    origins = {c.origin for _, c in root.walk() if c.origin}
    assert len(origins) >= 3, f"the fixture has only {len(origins)} distinct origins"

    # The judgement fields are deliberately absent.
    for _, node in root.walk():
        assert not node.warranty_amc, "a parts list should not carry warranty terms"
        assert not node.test_result, "a parts list should not carry test results"
