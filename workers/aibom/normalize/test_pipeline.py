"""End-to-end: discovery + enrichment -> canonical AIBOM, ready to write.

Reuses `workers.aibom.test_aibom`'s own fixtures (a LangChain app referencing
`meta-llama/Llama-3-8B`, and that model's real-shaped card) rather than
inventing parallel ones — this module proves the pieces those tests verify in
isolation (discovery, enrichment, merge, per-model normalization) actually
compose into one canonical document.
"""

from __future__ import annotations

from workers.aibom import merge
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

    # ⚠ THE PUBLISHER'S DECLARATION, NOT AIBOM-GENERATOR'S PROSE SCRAPE. The
    # `datasets:` front matter of the model card names real Hub dataset ids;
    # aibom-generator's re-parse of the rendered page returns English words
    # (`consisting`, `given`, `one`, `a` on three real models). See
    # `aibom_generator._resolved_datasets`.
    assert row["_datasets"] == [
        {
            "name": "the-pile",
            "type": "dataset",
            "license": "",
            "source": "https://huggingface.co/datasets/the-pile",
        }
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

    # ⚠ THIS USED TO ASSERT `_dependencies == []`. Reporting a dependency only in a
    # diagnostic and storing nothing meant the AI Model Dependencies sheet was empty
    # for every project without an SBOM scan — an absence rendered as a fact.
    assert row["_dependencies"], "an unresolved dependency must still be stored"
    # It keeps its real purl: the SBOM that catalogues langchain may simply be a
    # document not joined yet. What it must never do is vanish.
    assert "purl:pkg:pypi/langchain@0.3.7" in row["_dependencies"]

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
    # ⚠ DERIVED FROM THE LADDER, NEVER TYPED OUT. `user_values_by_identity` is keyed
    # on the model's merge key, so a test that hardcodes the key silently stops
    # exercising the lookup the moment the ladder changes a tier's format — which is
    # exactly what happened when `merge.identity` stopped returning a bare
    # `org/name` and started returning a prefixed `purl:pkg:huggingface/...` key.
    # ⚠ DERIVED FROM THE MODEL THE PIPELINE ACTUALLY SEES, not a synthetic stand-in.
    # A hand-built `{"model_ref": ...}` lacks the `provider` the real discovery
    # carries, and the ladder reads it — a Hugging Face purl is only minted where
    # something said Hugging Face. Keying this lookup off a different dict than the
    # pipeline uses is precisely the mismatch this test exists to catch.
    merged, _ = merge.merge(_discovery()["models"], _cards())
    identity = merged[0]["_model_key"]
    without = build_canonical_aibom(_discovery(), _cards())
    with_user_value = build_canonical_aibom(
        _discovery(),
        _cards(),
        user_values_by_identity={identity: {"intended_usage": "internal chat assistant"}},
    )

    assert without["ai_models"][0]["intended_usage"] == "not-provided"
    assert with_user_value["ai_models"][0]["intended_usage"] == "internal chat assistant"
    assert with_user_value["coverage"]["completeness_pct"] > without["coverage"]["completeness_pct"]


def test_two_calls_over_the_same_input_are_byte_identical() -> None:
    """CLAUDE.md invariant 10: normalization is a pure function of its input at
    a given ruleset version.

    ⚠ provenance IS NO LONGER POPPED BEFORE COMPARING. It used to be, because
    `alias_snapshot_id` was minted fresh per call to satisfy a `uuid NOT NULL`
    column AIBOM had nothing real to put in. Migration 0012 made it nullable
    with a real FK, so the field is None and the comparison covers the whole
    document — including the key that used to be the one exception.
    """
    first = build_canonical_aibom(_discovery(), _cards())
    second = build_canonical_aibom(_discovery(), _cards())

    assert first == second
    assert first["provenance"]["alias_snapshot_id"] is None


def test_no_models_produces_an_empty_but_valid_document() -> None:
    canonical = build_canonical_aibom({}, {})

    assert canonical["ai_models"] == []
    assert canonical["coverage"]["completeness_pct"] == 0
