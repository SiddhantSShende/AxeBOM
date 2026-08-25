"""VEX joining and re-normalization.

Two properties dominate both modules, and both are about not destroying
evidence:

  * **VEX joins to a finding; it never mutates one.** The finding is what the
    scanners observed. The statement is what a human asserted. Writing one over
    the other makes them impossible to disagree — which is exactly what a
    reviewer needs to see.

  * **Re-normalization writes a NEW version.** Version N stays byte-identical,
    so a report issued against it still resolves to the data it was rendered
    from.
"""

from __future__ import annotations

from dataclasses import dataclass

from .renormalize import diff
from .vex import VexStatement, apply, effective_for, validate


@dataclass
class FakeFinding:
    vuln_cluster_id: str
    component_key: str


def statement(**kwargs) -> VexStatement:
    defaults = {
        "id": "vex-1",
        "cluster_id": "c1",
        "status": "not_affected",
        "created_at": "2026-08-01T00:00:00Z",
        "justification": "vulnerable_code_not_in_execute_path",
    }
    return VexStatement(**{**defaults, **kwargs})


# -- VEX never mutates ----------------------------------------------------


def test_vex_returns_a_join_table_and_leaves_findings_untouched() -> None:
    """⚠ A suppressed finding is still a finding.

    "We assessed this and it does not apply" is a defensible position. "This
    CVE does not appear in our scan" is a different claim, and the two must not
    look the same.
    """
    finding = FakeFinding(vuln_cluster_id="c1", component_key="purl:pkg:npm/x@1")
    before = (finding.vuln_cluster_id, finding.component_key)

    rows, _ = apply([finding], [statement(component_key="purl:pkg:npm/x@1")])

    assert (finding.vuln_cluster_id, finding.component_key) == before
    assert len(rows) == 1
    assert rows[0]["status"] == "not_affected"
    assert rows[0]["suppresses_from_actionable"] is True


def test_a_finding_with_no_statement_gets_no_row() -> None:
    rows, _ = apply([FakeFinding("c2", "purl:pkg:npm/x@1")], [statement()])
    assert rows == []


# -- specificity and recency ----------------------------------------------


def test_a_component_scoped_statement_beats_a_cluster_wide_one() -> None:
    """Most specific scope wins."""
    broad = statement(id="broad", component_key="", status="affected", justification="")
    narrow = statement(id="narrow", component_key="purl:pkg:npm/x@1")

    effective = effective_for([broad, narrow], cluster_id="c1", component_key="purl:pkg:npm/x@1")
    assert effective is not None
    assert effective.statement_id == "narrow"


def test_the_latest_statement_wins_a_specificity_tie() -> None:
    older = statement(
        id="older", created_at="2026-01-01T00:00:00Z", status="affected", justification=""
    )
    newer = statement(id="newer", created_at="2026-08-01T00:00:00Z")

    effective = effective_for([older, newer], cluster_id="c1", component_key="")
    assert effective is not None
    assert effective.statement_id == "newer"
    assert effective.status == "not_affected"


def test_superseded_statements_are_excluded_from_the_decision_but_kept() -> None:
    """⚠ APPEND-ONLY. A statement withdrawn in September must not erase what
    was asserted in March — CERT-In §6 is explicit that VEX is iterative."""
    old = statement(id="old", created_at="2026-01-01T00:00:00Z", superseded_by="new")
    new = statement(
        id="new", created_at="2026-08-01T00:00:00Z", status="affected", justification=""
    )

    effective = effective_for([old, new], cluster_id="c1", component_key="")
    assert effective is not None
    assert effective.statement_id == "new"
    assert effective.status == "affected"
    assert len(effective.history) == 2, "the superseded statement must stay visible"


def test_history_is_newest_first() -> None:
    a = statement(id="a", created_at="2026-01-01T00:00:00Z")
    b = statement(id="b", created_at="2026-08-01T00:00:00Z")
    effective = effective_for([a, b], cluster_id="c1", component_key="")
    assert effective is not None
    assert [h["id"] for h in effective.history] == ["b", "a"]


# -- validation -----------------------------------------------------------


def test_not_affected_requires_a_justification() -> None:
    """⚠ CSAF requires it, and for a good reason: an unjustified suppression is
    an assertion a reviewer cannot evaluate."""
    problems = validate(statement(justification=""))
    assert any(p["code"] == "VEX_JUSTIFICATION_REQUIRED" for p in problems)


def test_a_non_csaf_status_is_rejected() -> None:
    problems = validate(statement(status="probably_fine"))
    assert any(p["code"] == "VEX_STATUS_INVALID" for p in problems)


def test_an_unknown_justification_code_is_flagged_not_rejected() -> None:
    """A warning rather than an error: the statement is still usable, and
    refusing it outright would discard a real human assessment over a typo."""
    problems = validate(statement(justification="seems_fine_to_me"))
    codes = {p["code"] for p in problems}
    assert "VEX_JUSTIFICATION_UNKNOWN" in codes
    assert "VEX_STATUS_INVALID" not in codes


def test_a_valid_statement_produces_no_diagnostics() -> None:
    assert validate(statement()) == []


def test_affected_and_under_investigation_do_not_suppress() -> None:
    for status in ("affected", "under_investigation"):
        rows, _ = apply(
            [FakeFinding("c1", "k")],
            [statement(status=status, justification="")],
        )
        assert rows[0]["suppresses_from_actionable"] is False, status


# -- re-normalization -----------------------------------------------------


def test_the_diff_reports_no_change_when_nothing_changed() -> None:
    """A silent re-normalization that changed every count would be
    indistinguishable from one that changed nothing."""
    model = {
        "provenance": {"normalization_version": 1},
        "ruleset_version": "2026.08.1",
        "components": [{"component_key": "purl:pkg:npm/x@1"}],
        "findings": [{"display_id": "CVE-1", "component_key": "purl:pkg:npm/x@1"}],
        "coverage": {"completeness_pct": 50.0, "declaration_pct": 60.0},
    }
    result = diff(model, {**model, "provenance": {"normalization_version": 2}})
    assert not result.changed
    assert "identical" in result.summary()


def test_the_diff_names_what_changed() -> None:
    before = {
        "provenance": {"normalization_version": 1},
        "components": [
            {"component_key": "purl:pkg:golang/x@24.0.5+incompatible"},
            {"component_key": "purl:pkg:golang/x@v24.0.5+incompatible"},
        ],
        "findings": [
            {"display_id": "CVE-1", "component_key": "purl:pkg:golang/x@24.0.5+incompatible"},
            {"display_id": "CVE-1", "component_key": "purl:pkg:golang/x@v24.0.5+incompatible"},
        ],
        "coverage": {"completeness_pct": 40.0, "declaration_pct": 50.0},
    }
    after = {
        "provenance": {"normalization_version": 2},
        "components": [{"component_key": "purl:pkg:golang/x@v24.0.5+incompatible"}],
        "findings": [
            {"display_id": "CVE-1", "component_key": "purl:pkg:golang/x@v24.0.5+incompatible"}
        ],
        "coverage": {"completeness_pct": 55.0, "declaration_pct": 60.0},
    }

    result = diff(before, after)
    assert result.changed
    assert result.components_removed == ["purl:pkg:golang/x@24.0.5+incompatible"]
    assert result.components_added == []
    assert len(result.findings_removed) == 1
    assert result.completeness_delta == 15.0
    assert "-1" in result.summary()


def test_the_diff_keys_findings_on_display_id_not_cluster_id() -> None:
    """⚠ Cluster ids are durable SURROGATES and differ between a stored run and
    a fresh one. Diffing on them would report every finding as changed."""
    before = {
        "provenance": {"normalization_version": 1},
        "components": [],
        "findings": [{"display_id": "CVE-1", "component_key": "k", "vuln_cluster_id": "stored-99"}],
        "coverage": {},
    }
    after = {
        "provenance": {"normalization_version": 2},
        "components": [],
        "findings": [{"display_id": "CVE-1", "component_key": "k", "vuln_cluster_id": "fresh-01"}],
        "coverage": {},
    }
    assert not diff(before, after).changed
