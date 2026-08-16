"""Bulk insertion: caps that refuse rather than truncate, and NUL safety."""

from __future__ import annotations

from .bulk import MAX_COMPONENTS, _text, copy_statement, plan


def model(components=None, findings=None, edges=None) -> dict:
    return {
        "components": components or [],
        "findings": findings or [],
        "graph": {"edges": edges or []},
    }


def component(key: str, **kwargs) -> dict:
    return {
        "component_key": key,
        "identity_rule": "purl",
        "identity_confidence": "high",
        "name": key.rsplit("/", 1)[-1],
        "version_raw": "1.0.0",
        "scope": "required",
        "observed_by": [{"engine": "syft"}],
        **kwargs,
    }


def test_a_normal_scan_produces_batches_for_every_table() -> None:
    result = plan(
        model(
            components=[component("purl:pkg:npm/x@1", locations=[{"path": "a/b.js"}])],
            findings=[
                {
                    "vuln_cluster_id": "c1",
                    "component_key": "purl:pkg:npm/x@1",
                    "display_id": "CVE-1",
                }
            ],
            edges=[{"from": "a", "to": "b"}],
        ),
        tenant_id="t1",
        bom_document_id="b1",
    )
    assert not result.refused
    assert len(result.batch("normalize.components")) == 1
    assert len(result.batch("normalize.component_locations")) == 1
    assert len(result.batch("normalize.findings")) == 1
    assert len(result.batch("normalize.component_dependencies")) == 1


def test_exceeding_the_component_cap_refuses_rather_than_truncating() -> None:
    """⚠ A TRUNCATED BOM IS THE WORST POSSIBLE ARTIFACT.

    It looks complete, it is smaller than the truth, and every component past
    the cut-off is a false negative the customer trusts.
    """
    too_many = [component(f"purl:pkg:npm/x{i}@1") for i in range(MAX_COMPONENTS + 1)]
    result = plan(model(components=too_many), tenant_id="t1", bom_document_id="b1")

    assert result.refused
    assert result.total_rows() == 0, "a refused plan must write nothing at all"
    assert any(d["code"] == "NORMALIZE_COMPONENT_CAP_EXCEEDED" for d in result.diagnostics)


def test_nul_bytes_never_reach_a_text_column() -> None:
    """⚠ A NUL SILENTLY TRUNCATES a Postgres text value.

    The row inserts, nothing errors, and the stored string is a prefix of the
    real one — so it must be cleaned before the write, not after.
    """
    assert "\x00" not in _text("evil\x00name")


def test_over_long_values_are_truncated_visibly() -> None:
    """A silently shortened value looks like a real, shorter value."""
    result = _text("x" * 20000)
    assert len(result) <= 8192
    assert "truncated" in result


def test_locations_are_one_to_many_against_a_single_component() -> None:
    """Identity is the package; the same jar at two paths is ONE component."""
    result = plan(
        model(
            components=[
                component(
                    "purl:pkg:maven/g/a@1",
                    locations=[{"path": "app/lib.jar"}, {"path": "vendor/lib.jar"}],
                )
            ]
        ),
        tenant_id="t1",
        bom_document_id="b1",
    )
    assert len(result.batch("normalize.components")) == 1
    assert len(result.batch("normalize.component_locations")) == 2


def test_field_status_records_not_provided_explicitly() -> None:
    """Both coverage numbers derive from this, so it is stored rather than
    recomputed at render — a report must not disagree with itself."""
    import json

    result = plan(
        model(components=[component("purl:pkg:npm/x@1", license_effective="NOASSERTION")]),
        tenant_id="t1",
        bom_document_id="b1",
    )
    row = result.batch("normalize.components").rows[0]
    status = json.loads(row[-1])
    assert status["name"] == "provided"
    assert status["license_effective"] == "not-provided", (
        "NOASSERTION declines to say, so it is not coverage"
    )


def test_the_pinned_display_id_is_what_gets_stored() -> None:
    result = plan(
        model(
            findings=[
                {"vuln_cluster_id": "c1", "component_key": "k", "display_id": "CVE-2021-44228"}
            ]
        ),
        tenant_id="t1",
        bom_document_id="b1",
    )
    row = result.batch("normalize.findings").rows[0]
    assert "CVE-2021-44228" in row


def test_copy_statement_names_only_our_own_identifiers() -> None:
    batch = plan(
        model(components=[component("purl:pkg:npm/x@1")]), tenant_id="t", bom_document_id="b"
    ).batch("normalize.components")
    statement = copy_statement(batch)
    assert statement.startswith("COPY normalize.components (")
    assert "FROM STDIN" in statement
