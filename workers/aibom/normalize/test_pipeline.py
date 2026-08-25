"""End-to-end: discovery + enrichment -> canonical AIBOM, ready to write.

Reuses `workers.aibom.test_aibom`'s own fixtures (a LangChain app referencing
`meta-llama/Llama-3-8B`, and that model's real-shaped card) rather than
inventing parallel ones — this module proves the pieces those tests verify in
isolation (discovery, enrichment, merge, per-model normalization) actually
compose into one canonical document.
"""

from __future__ import annotations

from workers.aibom.adapters.ai_bom import extract_discovery
from workers.aibom.adapters.aibom_generator import parse_model_card
from workers.aibom.normalize.pipeline import build_canonical_aibom
from workers.aibom.test_aibom import HF_MODEL, LANGCHAIN, MODEL_CARD_DOC, cdx


def _discovery() -> dict:
    return extract_discovery(cdx([LANGCHAIN, HF_MODEL]))


def _cards() -> dict:
    card = parse_model_card("meta-llama/Llama-3-8B", "main", MODEL_CARD_DOC)
    return {"meta-llama/Llama-3-8B": card}


def test_a_full_scan_produces_one_scored_model_row() -> None:
    canonical = build_canonical_aibom(_discovery(), _cards())

    assert len(canonical["ai_models"]) == 1
    row = canonical["ai_models"][0]
    assert row["model_name"] == "Llama-3-8B"
    assert row["model_developer"] == "Meta"
    assert row["licensing"] == "llama3"

    coverage = canonical["coverage"]
    assert coverage["completeness_pct"] > 0
    assert coverage["declaration_pct"] >= coverage["completeness_pct"]


def test_the_enriched_model_s_dataset_is_carried_through_to_the_row() -> None:
    canonical = build_canonical_aibom(_discovery(), _cards())
    row = canonical["ai_models"][0]

    assert row["_datasets"] == [
        {"name": "the-pile", "type": "dataset", "license": "MIT", "source": ""}
    ]


def test_a_framework_dependency_the_sbom_already_catalogued_is_linked() -> None:
    canonical = build_canonical_aibom(
        _discovery(), _cards(), sbom_component_keys={"purl:pkg:pypi/langchain@0.3.7"}
    )
    row = canonical["ai_models"][0]

    assert row["_dependencies"] == ["purl:pkg:pypi/langchain@0.3.7"]
    assert not any(d["code"] == "AIBOM_DEPENDENCY_NOT_IN_SBOM" for d in canonical["diagnostics"])


def test_an_unresolved_dependency_is_reported_as_a_diagnostic() -> None:
    """No SBOM component keys supplied — same as the case where no SBOM scan
    exists for the project yet. The dependency is not silently dropped."""
    canonical = build_canonical_aibom(_discovery(), _cards())
    row = canonical["ai_models"][0]

    assert row["_dependencies"] == []
    diag = next(d for d in canonical["diagnostics"] if d["code"] == "AIBOM_DEPENDENCY_NOT_IN_SBOM")
    assert "langchain" in diag["message"]


def test_risk_score_and_owasp_top10_are_captured_but_never_scored() -> None:
    """HF_MODEL's properties carry both AxeBOM extensions
    (`aibom:risk_score`, `aibom:owasp_llm_top10`). They must reach the row so
    a report can display them, and must never appear in `field_status` — that
    would let a third party's heuristic move a customer's CERT-In coverage
    percentage (ai.py's own module docstring)."""
    canonical = build_canonical_aibom(_discovery(), _cards())
    row = canonical["ai_models"][0]

    assert row["risk_score"] == 7.5
    assert row["owasp_llm_top10"] == ["LLM01", "LLM06"]
    assert "risk_score" not in row["field_status"]
    assert "owasp_llm_top10" not in row["field_status"]


def test_a_user_supplied_value_is_reflected_in_the_row_and_its_coverage() -> None:
    identity = "meta-llama/Llama-3-8B"
    without = build_canonical_aibom(_discovery(), _cards())
    with_user_value = build_canonical_aibom(
        _discovery(),
        _cards(),
        user_values_by_identity={identity: {"intended_usage": "internal chat assistant"}},
    )

    assert without["ai_models"][0]["intended_usage"] == "not-provided"
    assert with_user_value["ai_models"][0]["intended_usage"] == "internal chat assistant"
    assert with_user_value["coverage"]["completeness_pct"] > without["coverage"]["completeness_pct"]


def test_two_calls_over_the_same_input_are_byte_identical_except_provenance() -> None:
    """CLAUDE.md invariant 10: normalization is a pure function of its input
    at a given ruleset version, `provenance.alias_snapshot_id` excepted (see
    `build_canonical_aibom`'s own docstring on why AIBOM has no real alias
    concept for that field to describe)."""
    first = build_canonical_aibom(_discovery(), _cards())
    second = build_canonical_aibom(_discovery(), _cards())

    first.pop("provenance")
    second.pop("provenance")
    assert first == second


def test_no_models_produces_an_empty_but_valid_document() -> None:
    canonical = build_canonical_aibom({}, {})

    assert canonical["ai_models"] == []
    assert canonical["coverage"]["completeness_pct"] == 0
