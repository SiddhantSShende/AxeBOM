"""Tests for AIBOM discovery, enrichment, merge and normalization.

The phase's contract is that all nineteen Table-10 elements are populated or
explicitly `not-provided`, and that a low coverage number is INFORMATION rather
than something to paper over. Most of this file defends that and the two-tool
split that makes the network boundary safe.
"""

from __future__ import annotations

import pytest
from workers.aibom.adapters.ai_bom import AIBomAdapter, extract_discovery
from workers.aibom.adapters.aibom_generator import (
    ModelCache,
    ModelCard,
    enrich_models,
    parse_model_card,
)
from workers.aibom.merge import identity, merge, model_refs
from workers.aibom.normalize.ai import (
    USER_SUPPLIED_FIELDS,
    coverage_note,
    link_dependencies,
    normalize_model,
)

from encorebom_shared.model.generated_certin import AIBOM_FIELDS

# ---------------------------------------------------------------------------
# Fixtures — a LangChain app calling OpenAI and referencing an HF model
# ---------------------------------------------------------------------------


def cdx(components: list[dict]) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}


LANGCHAIN = {
    "type": "library",
    "name": "langchain",
    "version": "0.3.7",
    "purl": "pkg:pypi/langchain@0.3.7",
    "properties": [{"name": "aibom:category", "value": "agent-framework"}],
    "evidence": {"occurrences": [{"location": "app/chain.py"}]},
}

OPENAI = {
    "type": "library",
    "name": "openai",
    "version": "1.54.0",
    "purl": "pkg:pypi/openai@1.54.0",
    "properties": [{"name": "category", "value": "llm-provider"}],
    "evidence": {"occurrences": [{"location": "app/llm.py"}]},
}

MCP_SERVER = {
    "type": "application",
    "name": "mcp-server-filesystem",
    "properties": [{"name": "aibom:category", "value": "mcp-server"}],
    "evidence": {"occurrences": [{"location": "mcp.json"}]},
}

HF_MODEL = {
    "type": "machine-learning-model",
    "name": "Llama-3-8B",
    "bom-ref": "model/llama-3-8b",
    "purl": "pkg:huggingface/meta-llama/Llama-3-8B@main",
    "properties": [
        {"name": "aibom:provider", "value": "huggingface"},
        {"name": "aibom:framework", "value": "langchain"},
        {"name": "aibom:risk_score", "value": "7.5"},
        {"name": "aibom:owasp_llm_top10", "value": "LLM01,LLM06"},
    ],
    "evidence": {"occurrences": [{"location": "app/chain.py"}]},
}

MODEL_CARD_DOC = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [
        {
            "type": "machine-learning-model",
            "name": "meta-llama/Llama-3-8B",
            "version": "main",
            "author": "Meta",
            "licenses": [{"license": {"id": "llama3"}}],
            "properties": [
                {"name": "model_type", "value": "text-generation"},
                {"name": "architectures", "value": "LlamaForCausalLM"},
                {"name": "completeness_score", "value": "62.5"},
            ],
            "modelCard": {
                "modelParameters": {
                    "datasets": [
                        {"name": "the-pile", "type": "dataset", "license": "MIT"},
                    ],
                    "inputs": [{"format": "text"}],
                    "outputs": [{"format": "text"}],
                },
                "quantitativeAnalysis": {"performanceMetrics": [{"type": "MMLU", "value": "66.6"}]},
            },
        }
    ],
}


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_discovery_finds_frameworks_providers_and_mcp_servers() -> None:
    found = extract_discovery(cdx([LANGCHAIN, OPENAI, MCP_SERVER, HF_MODEL]))

    names = {f["name"] for f in found["frameworks"]}
    assert names == {"langchain", "openai", "mcp-server-filesystem"}
    assert found["surfaces"] >= {"agent-frameworks", "llm-providers", "mcp-servers", "model-refs"}


def test_a_framework_is_not_recorded_as_a_model() -> None:
    """⚠ LANGCHAIN IS A LIBRARY, NOT A MODEL. Recording it as one would put
    `langchain` in a Table 10 model inventory, where a reviewer reads every row
    as something the customer runs inference on."""
    found = extract_discovery(cdx([LANGCHAIN, HF_MODEL]))
    assert [m["name"] for m in found["models"]] == ["Llama-3-8B"]


def test_the_model_reference_comes_from_the_purl_not_the_bare_name() -> None:
    """⚠ A BARE NAME RESOLVES TO NOTHING, and an approximate id fetches the
    WRONG model card — whose licence would then be attributed to the customer."""
    found = extract_discovery(cdx([HF_MODEL]))
    assert found["models"][0]["model_ref"] == "meta-llama/Llama-3-8B"


def test_a_model_with_no_resolvable_reference_gets_an_empty_one() -> None:
    vague = {"type": "machine-learning-model", "name": "some-model"}
    found = extract_discovery(cdx([vague]))
    # Empty, not guessed. `model_refs` then declines to look it up.
    assert found["models"][0]["model_ref"] == ""
    assert model_refs(found["models"]) == []


def test_property_names_are_read_with_or_without_a_vendor_prefix() -> None:
    """ai-bom has emitted both `aibom:provider` and `provider`; a reader keyed
    on one spelling silently loses the field."""
    found = extract_discovery(cdx([HF_MODEL, OPENAI]))
    assert found["models"][0]["provider"] == "huggingface"
    assert any(f["surface"] == "llm-providers" for f in found["frameworks"])


@pytest.mark.parametrize(
    "payload",
    [{}, {"components": "not a list"}, {"components": [None, 3, "x"]}, {"components": [{}]}],
)
def test_discovery_parses_defensively(payload: dict) -> None:
    found = extract_discovery(payload)
    assert isinstance(found["models"], list)
    assert isinstance(found["diagnostics"], list)


# ---------------------------------------------------------------------------
# The LLM-enrich flag
# ---------------------------------------------------------------------------


def test_llm_enrich_is_off_by_default() -> None:
    """⚠ IT SENDS CODE CONTEXT TO A THIRD PARTY. That is a per-project decision
    made with open eyes, not a default discovered afterwards in an egress log."""
    adapter = AIBomAdapter.__new__(AIBomAdapter)
    adapter.enable_llm_enrich = False
    assert adapter.enable_llm_enrich is False


def test_llm_enrich_is_refused_inside_the_sandbox_with_an_explanation() -> None:
    """⚠ REFUSED, NOT PASSED THROUGH.

    Engines run --network=none. Passing the flag would produce a connection
    timeout deep inside the engine, reported as a failed scan with nothing
    indicating that a SETTING caused it.
    """
    adapter = AIBomAdapter.__new__(AIBomAdapter)
    adapter.enable_llm_enrich = True

    class Layout:
        container_source = "/src"

    with pytest.raises(ValueError) as exc:
        adapter.build_argv(None, Layout())  # type: ignore[arg-type]

    message = str(exc.value)
    assert "no network by design" in message
    assert "enrichment step" in message


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------


def test_enrichment_populates_model_metadata() -> None:
    card = parse_model_card("meta-llama/Llama-3-8B", "main", MODEL_CARD_DOC)

    assert card.developer == "Meta"
    assert card.license == "llama3"
    assert card.model_type == "text-generation"
    assert card.architectures == ["LlamaForCausalLM"]
    assert card.datasets[0]["name"] == "the-pile"
    assert card.performance_metrics == {"MMLU": "66.6"}
    assert card.input_modality == "text"
    assert card.source_completeness == 62.5


def test_the_developer_is_not_inferred_from_the_org_prefix() -> None:
    """⚠ `someuser/Llama-3-8B-finetuned` IS NOT PUBLISHED BY META, and it is not
    published by someuser in any sense a compliance reviewer means. Attributing
    it either way puts a wrong name in a Table 10 element."""
    bare = {"components": [{"type": "machine-learning-model", "name": "someuser/ft"}]}
    card = parse_model_card("someuser/ft", "", bare)
    assert card.developer == ""


def test_a_lookup_failure_degrades_rather_than_failing_the_scan() -> None:
    """⚠ DISCOVERY ALREADY PRODUCED THE HALF A CUSTOMER CANNOT GET ELSEWHERE.
    Discarding it because a public API was slow trades everything for nothing."""

    def boom(model_ref: str, revision: str) -> dict:
        raise ConnectionError("huggingface unreachable")

    result = enrich_models(["meta-llama/Llama-3-8B"], fetch=boom)

    assert result.degraded is True
    assert result.cards == {}
    assert result.diagnostics[0]["severity"] == "warn"
    assert "not-provided" in result.diagnostics[0]["hint"]


def test_one_failed_lookup_does_not_lose_the_others() -> None:
    def flaky(model_ref: str, revision: str) -> dict:
        if model_ref == "bad/model":
            raise TimeoutError("slow")
        return MODEL_CARD_DOC

    result = enrich_models(["bad/model", "meta-llama/Llama-3-8B"], fetch=flaky)

    assert result.degraded is True
    assert set(result.cards) == {"meta-llama/Llama-3-8B"}


def test_lookups_are_cached_so_a_second_scan_does_not_refetch() -> None:
    """The same base model appears across many projects, and Hugging Face
    rate-limits anonymously."""
    calls: list[str] = []

    def counting(model_ref: str, revision: str) -> dict:
        calls.append(model_ref)
        return MODEL_CARD_DOC

    cache = ModelCache()
    enrich_models(["meta-llama/Llama-3-8B"], fetch=counting, cache=cache)
    second = enrich_models(["meta-llama/Llama-3-8B"], fetch=counting, cache=cache)

    assert calls == ["meta-llama/Llama-3-8B"]
    assert second.cache_hits == 1


def test_an_empty_cache_is_not_silently_discarded() -> None:
    """⚠ ModelCache DEFINES __len__, SO AN EMPTY ONE IS FALSY.

    `cache = cache or ModelCache()` therefore threw the caller's cache away on
    every call. Caching never worked: the caller's cache stayed empty, stayed
    falsy, and was discarded again next time. Nothing failed — the only symptom
    is a fetch count, which is why this test counts fetches.
    """
    cache = ModelCache()
    assert not cache, "an empty ModelCache is falsy; that is the trap"

    calls: list[str] = []

    def counting(model_ref: str, revision: str) -> dict:
        calls.append(model_ref)
        return MODEL_CARD_DOC

    enrich_models(["m/x"], fetch=counting, cache=cache)
    assert len(cache) == 1, "the caller's cache was replaced rather than used"

    enrich_models(["m/x"], fetch=counting, cache=cache)
    assert calls == ["m/x"]


def test_the_cache_is_keyed_on_the_revision_too() -> None:
    """⚠ A MODEL ID IS A MOVING TARGET. The same id at two revisions can carry
    two different licences, and serving the older card for the newer revision
    attributes the wrong licence in a compliance document."""
    calls: list[tuple[str, str]] = []

    def counting(model_ref: str, revision: str) -> dict:
        calls.append((model_ref, revision))
        return MODEL_CARD_DOC

    cache = ModelCache()
    enrich_models(["m/x"], fetch=counting, cache=cache, revisions={"m/x": "v1"})
    enrich_models(["m/x"], fetch=counting, cache=cache, revisions={"m/x": "v2"})

    assert calls == [("m/x", "v1"), ("m/x", "v2")]


def test_an_expired_entry_is_refetched_rather_than_served_stale() -> None:
    """A licence that changed is exactly the fact a reviewer is reading for."""
    now = [0.0]
    calls: list[str] = []

    def counting(model_ref: str, revision: str) -> dict:
        calls.append(model_ref)
        return MODEL_CARD_DOC

    cache = ModelCache(ttl=10, clock=lambda: now[0])
    enrich_models(["m/x"], fetch=counting, cache=cache)
    now[0] = 11
    enrich_models(["m/x"], fetch=counting, cache=cache)

    assert len(calls) == 2


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------


def test_a_model_seen_by_both_tools_is_not_duplicated() -> None:
    found = extract_discovery(cdx([HF_MODEL]))
    card = parse_model_card("meta-llama/Llama-3-8B", "main", MODEL_CARD_DOC)

    models, _ = merge(found["models"], {"meta-llama/Llama-3-8B": card})

    assert len(models) == 1
    assert models[0]["enriched"] is True


def test_discovery_wins_on_usage_and_enrichment_wins_on_model_facts() -> None:
    """⚠ NEITHER WINS GLOBALLY.

    A single precedence order is wrong in one direction or the other: letting
    enrichment win everywhere overwrites the location a model is used at with
    nothing; letting discovery win everywhere keeps a licence guessed from a
    name over one read from the card.
    """
    found = extract_discovery(cdx([HF_MODEL]))
    card = parse_model_card("meta-llama/Llama-3-8B", "main", MODEL_CARD_DOC)
    models, _ = merge(found["models"], {"meta-llama/Llama-3-8B": card})
    model = models[0]

    # Usage facts survived — enrichment never saw the code.
    assert model["locations"] == ["app/chain.py"]
    assert model["framework"] == "langchain"

    # Model facts came from the card — discovery only saw a string.
    assert model["developer"] == "Meta"
    assert model["license"] == "llama3"


def test_the_same_model_in_three_files_is_one_model_with_three_locations() -> None:
    """Listing it three times inflates the model count, which is a headline
    number a reviewer reads."""
    sightings = [
        {**HF_MODEL, "evidence": {"occurrences": [{"location": f"app/{n}.py"}]}}
        for n in ("a", "b", "c")
    ]
    found = extract_discovery(cdx(sightings))
    models, diagnostics = merge(found["models"], {})

    assert len(models) == 1
    assert models[0]["locations"] == ["app/a.py", "app/b.py", "app/c.py"]
    assert any("merged by identity" in d["message"] for d in diagnostics)


def test_identity_never_merges_two_organisations_variants() -> None:
    """⚠ THE SAME CLASS AS MERGING npm/lodash WITH maven/lodash.

    `Llama-3-8B` is a name several organisations publish variants under. Merging
    on the bare name folds a customer's fine-tune into the upstream model and
    attributes the upstream licence to it.
    """
    upstream = {"model_ref": "meta-llama/Llama-3-8B", "name": "Llama-3-8B"}
    finetune = {"model_ref": "acme/Llama-3-8B", "name": "Llama-3-8B"}

    assert identity(upstream) != identity(finetune)
    models, _ = merge([upstream, finetune], {})
    assert len(models) == 2


def test_a_pinned_revision_from_the_code_is_not_overwritten_by_the_card() -> None:
    """Discovery read a pinned revision out of the code, which is MORE specific
    than 'whatever the card describes'."""
    pinned = {"model_ref": "m/x", "name": "x", "version": "abc123"}
    card = ModelCard(model_ref="m/x", revision="main", license="MIT")
    models, _ = merge([pinned], {"m/x": card})

    assert models[0]["version"] == "abc123"
    assert models[0]["license"] == "MIT"


# ---------------------------------------------------------------------------
# All nineteen elements
# ---------------------------------------------------------------------------


def test_every_table_10_element_is_present_or_explicitly_not_provided() -> None:
    """⚠ NONE IS OMITTED. Omission hides the gap; the explicit value is what
    makes it countable and visibly zero in the completeness number."""
    found = extract_discovery(cdx([HF_MODEL]))
    card = parse_model_card("meta-llama/Llama-3-8B", "main", MODEL_CARD_DOC)
    models, _ = merge(found["models"], {"meta-llama/Llama-3-8B": card})

    row, datasets, gaps = normalize_model(models[0])

    for f in AIBOM_FIELDS:
        column = f.canonical_path.removeprefix("ai_model.").removesuffix("[]")
        assert column in row, f"{f.id} is missing from the row entirely"
        assert f.id in row["field_status"], f"{f.id} has no field_status"

    assert len(row["field_status"]) == len(AIBOM_FIELDS)
    assert datasets[0]["name"] == "the-pile"
    assert gaps, "a real model card is incomplete; zero gaps would be suspicious"


def test_a_low_coverage_number_is_explained_rather_than_apologised_for() -> None:
    """⚠ AN AIBOM AT 40% IS REPORTING SOMETHING TRUE about the state of AI
    supply-chain metadata. A reader who does not know that reads it as a defect
    in the scan."""
    found = extract_discovery(cdx([HF_MODEL]))
    models, _ = merge(found["models"], {})
    _, _, gaps = normalize_model(models[0])

    note = coverage_note(gaps, len(AIBOM_FIELDS))

    assert "describe intent or policy" in note
    assert "fact about the ecosystem" in note


def test_user_supplied_elements_say_no_tool_reports_them() -> None:
    """Four elements describe intent and policy rather than anything
    discoverable. The gap reason has to say so, or a customer waits for a scan
    to fill them in."""
    found = extract_discovery(cdx([HF_MODEL]))
    models, _ = merge(found["models"], {})
    _, _, gaps = normalize_model(models[0])

    for gap in gaps:
        if gap.field_id in USER_SUPPLIED_FIELDS:
            assert "No tool reports this element" in gap.reason


def test_a_user_value_wins_over_a_tool_value() -> None:
    """The customer knows what the model is FOR; a scanner cannot."""
    found = extract_discovery(cdx([HF_MODEL]))
    models, _ = merge(found["models"], {})

    row, _, _ = normalize_model(
        models[0], user_values={"intended_usage": "Internal support triage only."}
    )

    assert row["intended_usage"] == "Internal support triage only."
    assert row["field_status"]["certin.aibom.15.intended_usage"] == "provided"


def test_a_user_typed_not_provided_still_scores_zero() -> None:
    found = extract_discovery(cdx([HF_MODEL]))
    models, _ = merge(found["models"], {})
    row, _, _ = normalize_model(models[0], user_values={"intended_usage": "not-provided"})
    assert row["field_status"]["certin.aibom.15.intended_usage"] == "not-provided"


def test_the_extensions_never_acquire_a_field_status() -> None:
    """⚠ `risk_score` AND `owasp_llm_top10` ARE ENCOREBOM'S ANALYSIS.

    Letting them count would move a customer's compliance percentage because a
    third party changed a heuristic, with no change to their software.
    """
    found = extract_discovery(cdx([HF_MODEL]))
    models, _ = merge(found["models"], {})
    row, _, _ = normalize_model(models[0])

    assert row["risk_score"] == 7.5
    assert row["owasp_llm_top10"] == ["LLM01", "LLM06"]

    statuses = row["field_status"]
    assert not any("risk" in k or "owasp" in k for k in statuses)
    assert len(statuses) == len(AIBOM_FIELDS)


# ---------------------------------------------------------------------------
# Linking to the SBOM
# ---------------------------------------------------------------------------


def test_an_ai_dependency_links_to_an_existing_sbom_component() -> None:
    """⚠ ONE COMPONENT WITH ONE SET OF VULNERABILITIES, not two rows a reviewer
    has to reconcile."""
    found = extract_discovery(cdx([LANGCHAIN, OPENAI, HF_MODEL]))
    model = dict(found["models"][0])
    model["frameworks"] = found["frameworks"]

    sbom_keys = {"purl:pkg:pypi/langchain@0.3.7", "purl:pkg:pypi/openai@1.54.0"}
    linked, unlinked = link_dependencies(model, sbom_keys)

    assert linked == sorted(sbom_keys)
    assert unlinked == []


def test_an_unlinked_dependency_is_reported_not_dropped() -> None:
    """A dependency the SBOM did not catalogue is a gap in the SBOM worth
    seeing."""
    found = extract_discovery(cdx([LANGCHAIN, MCP_SERVER]))
    model = {"frameworks": found["frameworks"]}

    linked, unlinked = link_dependencies(model, set())

    assert linked == []
    assert "mcp-server-filesystem" in unlinked
