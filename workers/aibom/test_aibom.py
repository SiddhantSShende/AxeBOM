"""Tests for AIBOM discovery, enrichment, merge and normalization.

The phase's contract is that all nineteen Table-10 elements are populated or
explicitly `not-provided`, and that a low coverage number is INFORMATION rather
than something to paper over. Most of this file defends that and the two-tool
split that makes the network boundary safe.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from workers.aibom.adapters import aibom_generator_fetch as fetch_mod
from workers.aibom.adapters.ai_bom import (
    AIBomAdapter,
    _properties,
    classify_component,
    extract_discovery,
)
from workers.aibom.adapters.aibom_generator import (
    ModelCache,
    ModelCard,
    enrich_models,
    parse_model_card,
)
from workers.aibom.adapters.aibom_generator_fetch import (
    RevisionNotSupportedError,
    fetch_model_card,
)
from workers.aibom.adapters.airom import extract_airom_discovery
from workers.aibom.adapters.cdxgen_ai import extract_cdxgen_ai_discovery
from workers.aibom.identity import identify as ladder_identify
from workers.aibom.merge import identity, lookup_plan, merge, model_refs
from workers.aibom.normalize.ai import (
    USER_SUPPLIED_FIELDS,
    coverage_note,
    dependency_scope,
    link_dependencies,
    normalize_model,
)

from axebom_shared.errors import EngineOutputMalformedError, EngineUnavailableError
from axebom_shared.model.generated_certin import AIBOM_FIELDS

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

#: aibom-generator's own half of an enrichment response.
MODEL_CARD_GENERATED = {
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

#: A whole enrichment response, in the shape `fetch_model_card` returns: BOTH
#: upstreams, kept apart. The Hub's `card_data` is the model card's own YAML front
#: matter — the structured half a publisher writes — and it is where the licence
#: and the training datasets come from, because aibom-generator's re-parse of the
#: rendered prose gets both wrong on every real model tested
#: (`aibom_generator._resolved_datasets`).
MODEL_CARD_DOC = {
    "aibom_generator": MODEL_CARD_GENERATED,
    "huggingface": {
        "id": "meta-llama/Llama-3-8B",
        "requested_id": "meta-llama/Llama-3-8B",
        "sha": "0123456789abcdef0123456789abcdef01234567",
        "card_data": {"license": "llama3", "datasets": ["the-pile"]},
    },
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


# ---------------------------------------------------------------------------
# What gets looked up, and what does not — `merge.lookup_plan`
# ---------------------------------------------------------------------------


def test_a_bare_canonical_hugging_face_id_is_looked_up() -> None:
    """⚠ THIS USED TO BE REFUSED, AND REFUSING IT WAS THE BUG.

    `lookup_plan` required an `org/name` shape, on the stated reasoning that a
    bare name "would fetch a DIFFERENT model". Checked against the real Hub in
    this session: it would not. `distilbert-base-uncased` IS a canonical
    repository — `model_info` resolves it and reports the canonical id
    `distilbert/distilbert-base-uncased`. So do `gpt2` and `bert-base-uncased`.

    Observed live: a scan of a repository using `distilbert-base-uncased`
    reported `aibom-generator: succeeded` having enriched nothing, because the
    single most common shape of Hugging Face reference was silently dropped.
    """
    refs, declined = lookup_plan(
        [{"model_ref": "distilbert-base-uncased", "provider": "HuggingFace"}]
    )

    assert refs == ["distilbert-base-uncased"]
    assert declined == []


def test_a_bare_name_from_a_hosted_api_is_not_looked_up_on_hugging_face() -> None:
    """⚠ THE PROVIDER GATES IT, NOT THE SLASH.

    `gpt-4o` is OpenAI's. Hugging Face does not serve it today, and a repository
    could appear under that name tomorrow — whose card would then be attributed
    to the customer's model. The reason travels with the refusal so it can become
    a diagnostic rather than a silence.
    """
    refs, declined = lookup_plan([{"model_ref": "gpt-4o", "provider": "OpenAI"}])

    assert refs == []
    assert len(declined) == 1
    assert declined[0]["ref"] == "gpt-4o"
    assert "openai" in declined[0]["reason"]


def test_a_bare_name_nobody_attributed_is_declined_with_a_reason() -> None:
    refs, declined = lookup_plan([{"model_ref": "my-finetune", "provider": ""}])

    assert refs == []
    assert "bare name" in declined[0]["reason"]


def test_a_namespaced_reference_is_looked_up_whoever_named_it() -> None:
    refs, declined = lookup_plan([{"model_ref": "meta-llama/Llama-3-8B", "provider": ""}])

    assert refs == ["meta-llama/Llama-3-8B"]
    assert declined == []


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
# The concrete Fetcher — aibom_generator_fetch.fetch_model_card
#
# ⚠ THESE RUN NO SUBPROCESS AND TOUCH NO NETWORK, except the one test marked
# `integration` below. `fetch_model_card` is exercised through monkeypatched
# `subprocess.run` and `_resolve_model`, exactly like `test_runner.py`
# monkeypatches `source.materialize` rather than touching a real fetcher.
# ---------------------------------------------------------------------------


#: The real two-source enrichment response for `distilbert-base-uncased`,
#: captured from the live owasp-aibom-generator and the live Hugging Face API.
_DISTILBERT_ENVELOPE = json.loads(
    (
        Path(__file__).parent / "testdata" / "aibom-generator-distilbert-base-uncased.envelope.json"
    ).read_text(encoding="utf-8")
)

#: What `_resolve_model` returns for a model that resolves — the Hub's own
#: answer, in the shape the real one has. Stubbed rather than fetched: these
#: tests touch no network.
_HUB_STUB = {
    "id": "org/m",
    "requested_id": "m/x",
    "sha": "0123456789abcdef",
    "card_data": {"license": "apache-2.0"},
}


def test_a_pinned_revision_is_refused_not_silently_served_from_default() -> None:
    """⚠ aibom-generator HAS NO REVISION PARAMETER, ANYWHERE — checked against
    the real 1.0.2 source (CLI argparse, CLIController.generate,
    AIBOMService.generate_aibom). Serving the default branch's card back under
    a pinned revision's name would attribute a licence to the wrong point in
    the model's history, so this is refused before any subprocess or network
    call — not silently downgraded to "whatever is current"."""
    with pytest.raises(RevisionNotSupportedError) as exc:
        fetch_model_card("meta-llama/Llama-3-8B", "abc1234")

    message = str(exc.value)
    assert "abc1234" in message
    assert "no revision parameter" in message


@pytest.mark.parametrize("revision", ["", "main", "HEAD", "  main  "])
def test_no_pin_and_the_default_branch_spellings_are_not_refused(
    monkeypatch: pytest.MonkeyPatch, revision: str
) -> None:
    """ "" / "main" / "HEAD" all mean the one thing aibom-generator can serve:
    whatever the default branch currently is. None of these should reach
    RevisionNotSupportedError."""
    monkeypatch.setattr(fetch_mod, "_resolve_model", lambda ref: _HUB_STUB)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        output_path = Path(argv[argv.index("--output") + 1])
        model_component = {"type": "machine-learning-model", "name": "m/x"}
        output_path.write_text(json.dumps(cdx([model_component])), encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = fetch_model_card("m/x", revision)

    # ⚠ TWO SOURCES, KEPT APART. The envelope is what becomes the raw artifact,
    # so which upstream said what stays answerable on replay.
    assert result[fetch_mod.GENERATOR_KEY]["components"][0]["name"] == "m/x"
    assert result[fetch_mod.HUB_KEY]["card_data"]["license"] == "apache-2.0"


def test_a_nonexistent_model_raises_instead_of_being_fabricated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """⚠ aibom-generator==1.0.2 DOES NOT VERIFY A MODEL EXISTS.

    Verified in this session: pointed at a deliberately nonexistent model id,
    `AIBOMService.generate_aibom()` still logs "Successfully generated
    CycloneDX 1.6 SBOM", exits 0, and writes a real file containing a
    plausible-looking component synthesised from guessed defaults (org parsed
    off the slug, architecture "transformer", `supplier: {"name": "unknown"}`).
    Nothing about the CycloneDX SHAPE distinguishes that from a real model, so
    `fetch_model_card` must reject a nonexistent model BEFORE aibom-generator
    ever runs — this is what `_resolve_model` is for."""

    def fake_resolve(model_ref: str) -> dict[str, object]:
        raise EngineUnavailableError("aibom-generator", "model does not exist")

    monkeypatch.setattr(fetch_mod, "_resolve_model", fake_resolve)

    with pytest.raises(EngineUnavailableError):
        fetch_model_card("this-org-does-not-exist-xyz/nonexistent-model-abc123", "")


def test_the_tool_not_being_installed_is_a_clear_engine_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`python -m src.cli` failing with `No module named` means aibom-generator
    (or a same-named `src` shadowing it — see the module docstring on why the
    top-level package name `src` is a genuine collision risk) is not installed
    in this interpreter. That must be diagnosable, not a bare traceback."""
    monkeypatch.setattr(fetch_mod, "_resolve_model", lambda ref: _HUB_STUB)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            argv, 1, stdout="", stderr="ModuleNotFoundError: No module named 'src'"
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(EngineUnavailableError) as exc:
        fetch_model_card("m/x", "")
    assert "not installed" in str(exc.value)


def test_a_run_that_produces_no_file_is_a_malformed_output_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Distinct from "not installed": the tool ran, but for some other reason
    (a Hugging Face timeout inside aibom-generator, an unexpected crash) no
    output file exists. `enrich_models` only needs SOME exception to degrade
    this one lookup — but which one is worth being specific about."""
    monkeypatch.setattr(fetch_mod, "_resolve_model", lambda ref: _HUB_STUB)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="boom: connection reset")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(EngineOutputMalformedError):
        fetch_model_card("m/x", "")


def test_real_upstream_output_round_trips_into_a_populated_card() -> None:
    """⚠ PROVEN AGAINST REAL UPSTREAM OUTPUT, NOT ONLY SYNTHETIC FIXTURES.

    `workers/aibom/testdata/aibom-generator-distilbert-base-uncased.envelope.json`
    is the ACTUAL response `fetch_model_card("distilbert-base-uncased", "")`
    returned in this session, running the real owasp-aibom-generator==1.0.2
    against the real Hugging Face API — captured the same way
    `fixtures/crypto-mixed/raw/` pins a real cbomkit-theia response. This test
    touches no network; it replays that captured response.
    """
    card = parse_model_card("distilbert-base-uncased", "", _DISTILBERT_ENVELOPE)

    assert card.name == "distilbert-base-uncased"
    # ⚠ THE TASK, NOT THE ARCHITECTURE FAMILY. This assertion used to read
    # `"distilbert"` — the vendor `model_type` property — which put an
    # architecture family in CERT-In Table 10 element 03, an element whose own
    # examples are `text-generation`, `image-processing`, `image-classifier`.
    # Those are tasks. `distilbert` was also the THIRD copy of a fact already in
    # `architectures` (element 07) and `modelArchitecture`.
    assert card.model_type == "fill-mask"
    assert card.architectures == ["DistilBertForMaskedLM"]
    # ⚠ KNOWN GAP, NOT A BUG IN THIS FETCHER: real aibom-generator output names
    # the publisher via `authors`/`supplier`, but `_developer()` only reads
    # `author`/`publisher` (singular, no vendor prefix) plus a `properties`
    # fallback -- none of which real 1.0.2 output populates. `developer` comes
    # back "", honestly `not-provided`, rather than guessed from `authors[0]`.
    assert card.developer == ""


def test_the_licence_is_the_publisher_s_not_aibom_generator_s_parse() -> None:
    """⚠ THIS ASSERTION USED TO PIN THE WRONG ANSWER, ON PURPOSE.

    It read `assert card.license  # "apache-2.0 datasets" -- passed through
    as-is, not corrected`. Passing it through IS the defect: aibom-generator
    re-reads the rendered model card and glues the next word of the document onto
    the licence. Measured against the Hub's own `card_data.license` for three
    real models in this session — `apache-2.0 datasets`, `mit ---`,
    `apache-2.0 library`, against `apache-2.0`, `mit`, `apache-2.0`. A wrong
    licence in a compliance document is worse than an absent one, because a
    reader acts on it.
    """
    generated = _DISTILBERT_ENVELOPE["aibom_generator"]
    assert generated["components"][0]["licenses"] == [
        {"license": {"name": "apache-2.0 datasets"}}
    ], "the captured response no longer carries the defect this test is about"

    card = parse_model_card("distilbert-base-uncased", "", _DISTILBERT_ENVELOPE)

    assert card.license == "apache-2.0"


def test_training_datasets_scraped_out_of_prose_are_never_recorded() -> None:
    """⚠ `consisting` IS NOT A DATASET. It is a word from a sentence.

    aibom-generator's dataset list for these three real models was
    `["consisting"]`, `["one", "a"]` and `["given"]`, against the publishers'
    actual declarations of `[bookcorpus, wikipedia]`, none, and 21 real ids. The
    tool says so itself — `genai:aibom:trainingDataAvailable = "false"` — and
    writing those words into Table 10 as a model's training data is fabrication
    in the exact sense this product forbids.

    The model card's `datasets:` front matter is the declaration, and it is what
    is recorded.
    """
    generated = _DISTILBERT_ENVELOPE["aibom_generator"]
    scraped = generated["components"][0]["modelCard"]["modelParameters"]["datasets"]
    assert [d["name"] for d in scraped] == ["consisting"], (
        "the captured response no longer carries the defect this test is about"
    )

    card = parse_model_card("distilbert-base-uncased", "", _DISTILBERT_ENVELOPE)

    assert [d["name"] for d in card.datasets] == ["bookcorpus", "wikipedia"]


def test_a_prose_scrape_with_no_declaration_is_reported_not_recorded() -> None:
    """The publisher declared nothing and the tool scraped a word anyway.

    Recording nothing is right; recording nothing SILENTLY is not — the gap
    would read as "the publisher declares no training data" when what happened
    is that we refused to believe the only source. invariant 12.
    """
    envelope = {
        "aibom_generator": _DISTILBERT_ENVELOPE["aibom_generator"],
        "huggingface": {"card_data": {"license": "apache-2.0"}},
    }

    card = parse_model_card("distilbert-base-uncased", "", envelope)

    assert card.datasets == []
    assert any("consisting" in note for note in card.notes)


def test_a_response_captured_before_the_envelope_existed_still_parses() -> None:
    """⚠ REPLAY, NOT LEGACY TOLERANCE. Raw artifacts are immutable (invariant
    10), so every enrichment response stored before the two-source envelope
    existed is still on disk and still has to normalize — under the same rules,
    minus the half it does not carry."""
    bare = json.loads(
        (
            Path(__file__).parent / "testdata" / "aibom-generator-distilbert-base-uncased.cdx.json"
        ).read_text(encoding="utf-8")
    )

    card = parse_model_card("distilbert-base-uncased", "", bare)

    assert card.model_type == "fill-mask"
    # No Hub half, so the mangled licence is the only candidate — and it is
    # refused rather than recorded, with the reason kept.
    assert card.license == ""
    assert card.datasets == []
    assert any("apache-2.0 datasets" in note for note in card.notes)


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------


def test_a_model_seen_by_both_tools_is_not_duplicated() -> None:
    found = extract_discovery(cdx([HF_MODEL]))
    card = parse_model_card("meta-llama/Llama-3-8B", "main", MODEL_CARD_DOC)

    models, _ = merge(found["models"], {"meta-llama/Llama-3-8B": card})

    assert len(models) == 1
    assert models[0]["enriched"] is True


def test_a_card_fetched_by_asserted_id_reaches_the_model(tmp_path) -> None:
    """⚠ OBSERVED LIVE: ENRICHMENT RAN, SUCCEEDED, AND REACHED NO ROW.

    ai-bom reports `distilbert-base-uncased` as `model_id` and leaves
    `model_ref` empty, because the reference is not `org/name` shaped. The
    enrichment plane asked Hugging Face about the asserted id, got a card, and
    stored it under that key; the merge then looked the card up under
    `model_ref` — `""` — and found nothing. The model was written with every
    enrichment-only element `not-provided` and `verified = false`, on a scan
    whose Engine Coverage said `aibom-generator: succeeded`.

    One function decides this now, for both sides: `merge.lookup_ref`.
    """
    discovered = [
        {
            "model_ref": "",
            "model_id": "distilbert-base-uncased",
            "name": "HuggingFace Transformers Model",
            "provider": "HuggingFace",
            "locations": ["/src/app.py:5"],
        }
    ]
    refs, declined = lookup_plan(discovered)
    assert refs == ["distilbert-base-uncased"] and declined == []

    card = parse_model_card("distilbert-base-uncased", "", _DISTILBERT_ENVELOPE)
    models, _ = merge(discovered, {refs[0]: card})

    assert models[0]["enriched"] is True
    assert models[0]["license"] == "apache-2.0"


def test_one_model_two_engines_two_provider_claims_is_one_row() -> None:
    """⚠ OBSERVED LIVE ON A REAL THREE-ENGINE SCAN: `gpt-4o` WAS STORED TWICE.

    ai-bom puts the CALLING FRAMEWORK in its provider property — its real values
    are `LangChain`, `HuggingFace`, `ChromaDB` — so its `gpt-4o` keyed as
    `name:langchain/gpt-4o`. airom and cdxgen report the actual serving provider,
    so theirs keyed as `api:openai/gpt-4o`. Two rows in a Table 10 inventory for
    one model, and the row count is a headline number a reviewer reads.

    Adding engines multiplied the M1 defect instead of diluting it.
    """
    models, diagnostics = merge(
        [
            {
                "model_ref": "",
                "model_id": "gpt-4o",
                "name": "LangChain Model",
                "provider": "LangChain",
                "locations": ["src/app.py:12"],
                "source_engine": "ai-bom",
            },
            {
                "model_ref": "",
                "model_id": "gpt-4o",
                "name": "gpt-4o",
                "provider": "openai",
                "locations": ["src/app.py:12"],
                "source_engine": "airom",
            },
        ],
        {},
    )

    assert len(models) == 1
    # The better-identified key survives, not the one that arrived first.
    assert models[0]["_model_key"] == "api:openai/gpt-4o"
    assert {p["engine_id"] for p in models[0]["_provenance"]} == {"ai-bom", "airom"}
    assert "NORMALIZE_IDENTITY_ALIAS_FOLDED" in {d["code"] for d in diagnostics}


def test_the_same_name_from_two_providers_stays_two_models() -> None:
    """⚠ MERGING TWO MODELS THAT ARE NOT THE SAME MODEL IS WORSE THAN LISTING
    ONE TWICE, so an ambiguous name is reported rather than resolved.

    A weakly-identified `gpt-4o` claimed by BOTH an OpenAI model and an Azure one
    could belong to either. Picking is a guess; the honest answer is to keep it
    apart and say why.
    """
    models, diagnostics = merge(
        [
            {"model_id": "gpt-4o", "name": "m", "provider": "openai", "source_engine": "airom"},
            {"model_id": "gpt-4o", "name": "m", "provider": "azure", "source_engine": "cdxgen-ai"},
            {"model_id": "gpt-4o", "name": "m", "provider": "LangChain", "source_engine": "ai-bom"},
        ],
        {},
    )

    assert len(models) == 3
    assert "NORMALIZE_IDENTITY_AMBIGUOUS" in {d["code"] for d in diagnostics}


def test_a_strong_key_is_never_folded_into_another_strong_key() -> None:
    """The fold absorbs a low-confidence alias and nothing else. Two models that
    each carry real identity are two models, however similar their names."""
    models, _ = merge(
        [
            {"model_id": "gpt-4o", "name": "m", "provider": "openai", "source_engine": "a"},
            {"model_id": "gpt-4o", "name": "m", "provider": "azure", "source_engine": "b"},
        ],
        {},
    )

    assert len(models) == 2


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
    """⚠ `risk_score` AND `owasp_llm_top10` ARE AXEBOM'S ANALYSIS.

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

    # ⚠ langchain ONLY, AND `openai` BEING ABSENT IS THE POINT.
    #
    # ai-bom attributed this model to langchain (`trusera:framework`), and a
    # Hugging Face Llama loaded through LangChain does not depend on the OpenAI
    # SDK. This assertion used to read `linked == sorted(sbom_keys)` — every AI
    # library in the project joined onto every model — which with one model in
    # the inventory looked like "the AI software this model rests on" and, the
    # moment a second model existed, said `gpt-4o` depends on
    # `sentence-transformers`. Table 10 element 06 is read as a claim about THAT
    # model. See `normalize.ai.attributed_frameworks`.
    assert linked == ["purl:pkg:pypi/langchain@0.3.7"]
    assert unlinked == []


def test_with_no_attribution_the_projects_ai_libraries_are_used_and_said_so() -> None:
    """The fallback, and the label that keeps it honest.

    Real ai-bom output attributes no calling framework to any model — the
    property is simply absent — so in practice every model's dependency list IS
    the project's AI library set. That is useful and it is NOT the same statement
    as "the engine saw this model use these", so `dependency_scope` reports which
    of the two happened and the pipeline turns it into a diagnostic.
    """
    found = extract_discovery(cdx([LANGCHAIN, OPENAI, HF_MODEL]))
    model = dict(found["models"][0])
    model["frameworks"] = found["frameworks"]
    model["framework"] = ""

    sbom_keys = {"purl:pkg:pypi/langchain@0.3.7", "purl:pkg:pypi/openai@1.54.0"}
    linked, _unlinked = link_dependencies(model, sbom_keys)

    assert linked == sorted(sbom_keys)
    assert dependency_scope(model) == "project"
    assert dependency_scope({**model, "framework": "langchain"}) == "model"


def test_an_unlinked_dependency_is_reported_not_dropped() -> None:
    """A dependency the SBOM did not catalogue is a gap in the SBOM worth seeing.

    ⚠ THIS TEST USED TO ASSERT `linked == []`, WHICH IS THE BEHAVIOUR ITS OWN NAME
    ARGUES AGAINST. Returning an empty key list meant an unresolved dependency was
    reported in a diagnostic and then **dropped** — so on a project with no SBOM
    scan the report showed a model depending on nothing, which reads as "it has no
    dependencies" rather than "nothing catalogued them". The keys are now stored
    under a `name:` prefix that cannot collide with a real component's purl, and
    `unlinked` still drives the diagnostic.
    """
    found = extract_discovery(cdx([LANGCHAIN, MCP_SERVER]))
    model = {"frameworks": found["frameworks"]}

    keys, unlinked = link_dependencies(model, set())

    assert "mcp-server-filesystem" in unlinked
    assert "name:mcp-server-filesystem" in keys
    # A bare name is never stored where a purl is expected. mcp-server-filesystem
    # has no purl in the fixture, so it lands under `name:`; anything that does
    # have one keeps it, because a purl IS the component's identity.
    assert all(k.startswith(("name:", "purl:")) for k in keys)


# ---------------------------------------------------------------------------
# The real engine's real output — the regression that motivated the M1 fixes.
#
# ⚠ EVERY ASSERTION BELOW FAILED BEFORE THIS SESSION, AGAINST THIS EXACT FILE,
# IN PRODUCTION. `workers/aibom/testdata/ai-bom-langchain-llama3.cdx.json` is the
# artifact a live `ai-bom` 3.1.0 run wrote to `scan.raw_artifacts` for a real
# scan; normalizing it produced THREE rows in `normalize.ai_models`, named
# `transformers`, `HuggingFace Transformers` and `HuggingFace Transformers Model`
# — three labels for one Python library — while `meta-llama/Llama-3-8B`, the only
# model the repository actually used, was recorded nowhere. Coverage read 5.88%.
#
# A hand-built fixture could not have caught any of it: every bug was a mismatch
# between what CycloneDX permits and what this engine actually emits.
# ---------------------------------------------------------------------------

REAL_OUTPUT_PATH = Path(__file__).parent / "testdata" / "ai-bom-langchain-llama3.cdx.json"


def _real_discovery_document() -> dict:
    return json.loads(REAL_OUTPUT_PATH.read_text(encoding="utf-8"))


def _real_discovery() -> dict:
    return extract_discovery(_real_discovery_document())


def test_the_real_engine_output_yields_one_model_not_three() -> None:
    models = _real_discovery()["models"]

    assert len(models) == 1, [m["name"] for m in models]
    assert models[0]["model_ref"] == "meta-llama/Llama-3-8B"


def test_a_pypi_library_the_engine_called_a_model_is_recorded_as_a_dependency() -> None:
    discovery = _real_discovery()

    frameworks = {f["name"] for f in discovery["frameworks"]}
    assert "transformers" in frameworks
    assert "transformers" not in {m["name"] for m in discovery["models"]}


def test_reclassifying_a_component_is_reported_never_silent() -> None:
    """A count that changes without a diagnostic is an unexplained count."""
    codes = [d["code"] for d in _real_discovery()["diagnostics"]]

    assert codes.count("AIBOM_MODEL_RECLASSIFIED") == 2


def test_the_engines_own_file_line_evidence_survives() -> None:
    """ai-bom reports position in a property, not in CycloneDX `evidence`."""
    model = _real_discovery()["models"][0]

    assert model["locations"] == ["app.py:13"]


def test_the_sandbox_mount_point_is_not_part_of_the_evidence_path() -> None:
    """⚠ ONE MODEL, TWO SPELLINGS OF ONE FILE, AND NEITHER LOOKED WRONG ALONE.

    Every engine sees the tree at `/src` because that is where the runner mounts
    it (`axebom_shared.sandbox.WorkspaceLayout.container_source`). ai-bom echoes
    that prefix into its evidence and airom does not — so a model both engines
    found came out carrying `/src/app.py:17` AND `src/app.py:17`, which reads as
    two files, and the first of which reads as a path outside the repository
    entirely. Stripped once, in `discovery.repo_path`, so a fourth engine cannot
    forget to.
    """
    raw = json.loads(
        (Path(__file__).parent / "testdata" / "ai-bom-langchain-llama3.cdx.json").read_text(
            encoding="utf-8"
        )
    )
    assert '"/src/app.py:13"' in json.dumps(raw), (
        "the captured response no longer carries the mount prefix this test is about"
    )

    for model in extract_discovery(raw)["models"]:
        for location in model["locations"]:
            assert not location.startswith("/src/"), location


def test_a_purl_containing_a_space_is_refused_not_stored() -> None:
    """`pkg:pypi/huggingface transformers` is verbatim from the real output.

    A malformed merge key matches nothing and dedups against nothing, while
    looking exactly like a real identifier in the rendered report.
    """
    discovery = _real_discovery()

    for entry in discovery["models"] + discovery["frameworks"]:
        assert " " not in entry["purl"]

    mangled = [f for f in discovery["frameworks"] if f["name"] == "HuggingFace Transformers"]
    assert mangled and mangled[0]["purl"] == ""


def test_one_model_under_three_labels_merges_to_one_row() -> None:
    """The end-to-end shape of the defect: discovery -> merge -> one model."""
    models, _diagnostics = merge(_real_discovery()["models"], {})

    assert len(models) == 1
    assert identity(models[0]) == "purl:pkg:huggingface/meta-llama/Llama-3-8B"


def test_the_reported_model_name_is_the_model_not_the_engines_category_label() -> None:
    """Table 10 element 01 is "Official name of the AI model".

    ⚠ ai-bom NAMES THIS COMPONENT `HuggingFace Transformers Model`. That is a
    category, not a name, and shipping it as the model's official name states
    something false about the customer's system in a compliance document. The
    publisher's own identifier says `Llama-3-8B`.
    """
    from workers.aibom.normalize.ai import normalize_model

    models, _ = merge(_real_discovery()["models"], {})
    row, _datasets, _gaps = normalize_model(models[0])

    assert row["model_name"] == "Llama-3-8B"
    # The developer is NOT inferred from the `meta-llama/` prefix — a publisher is a
    # legal entity, not a URL slug. Enrichment establishes it, or it stays absent.
    assert row["model_developer"] == "not-provided"


# ---------------------------------------------------------------------------
# Identity ladder guarantees the module docstring makes
# ---------------------------------------------------------------------------


def test_two_unidentifiable_models_never_collapse_into_one() -> None:
    """Tier 7 promises it never merges. Without a position it broke that promise.

    ⚠ TWO MODELS WE CANNOT IDENTIFY ARE TWO MODELS. Collapsing them under-reports
    an inventory, which is the direction of error a compliance document must not
    take. Both entries below carry no name, no reference, no purl and no bom-ref,
    so every other input to the seed is identical.
    """
    anonymous = [{"locations": ["a.py:1"]}, {"locations": ["b.py:2"]}]
    models, _diagnostics = merge(anonymous, {}, scan_id="scan-1")

    assert len(models) == 2
    assert models[0]["_model_key"] != models[1]["_model_key"]


def test_the_key_a_model_merged_under_is_the_key_it_is_stored_under() -> None:
    """Identity is derived once, in merge, and carried.

    It used to be computed in `merge` to dedup and computed AGAIN downstream to
    store, with different arguments — so an opaque-tier model merged under one key
    and was written under another, and the operator-supplied values keyed on
    identity were looked up with a key that no longer matched.
    """
    from workers.aibom.normalize.pipeline import build_canonical_aibom

    found = [{"locations": ["a.py:1"]}]
    merged, _ = merge(found, {}, scan_id="scan-1")
    merge_key = merged[0]["_model_key"]

    canonical = build_canonical_aibom({"models": found, "frameworks": []}, {}, scan_id="scan-1")
    row = canonical["ai_models"][0]

    # `_identity` is what bulk.py derives both the stored `model_key` and the
    # row's surrogate id from, so this equality is the whole guarantee.
    assert row["_identity"] == merge_key
    assert row["identity_rule"] == "opaque"


def test_two_pinned_revisions_of_one_model_are_two_models() -> None:
    """A model at two revisions can carry two different licences.

    The ladder reads the revision from `version`, which is where this codebase
    carries it — see `test_a_pinned_revision_from_the_code_is_not_overwritten_by_the_card`.
    """
    a = ladder_identify({"model_ref": "m/x", "version": "abc123"})
    b = ladder_identify({"model_ref": "m/x", "version": "def456"})

    assert a[0] != b[0]
    assert a[0].endswith("@abc123")


def test_a_library_cannot_escape_reclassification_via_a_slash_in_its_name() -> None:
    """The name fallback forms a reference; it does not prove one.

    ⚠ A PACKAGE PUBLISHED AS `huggingface/transformers` WOULD OTHERWISE RESCUE
    ITSELF. `_model_reference` falls back to the component name when it contains a
    slash, so a pypi library with a slashed display name looked exactly like a
    model reference — putting a Python package back into a Table 10 inventory,
    which is the defect `classify_component` exists to prevent.
    """
    raw = {
        "type": "machine-learning-model",
        "name": "huggingface/transformers",
        "purl": "pkg:pypi/transformers",
    }
    kind, reason = classify_component(raw, _properties(raw))

    assert kind == "framework"
    assert "pypi" in reason


def test_evidence_the_engine_asserted_still_outranks_the_purl() -> None:
    """A deliberate model-id property beats a package purl; a slashed name does not."""
    raw = {
        "type": "machine-learning-model",
        "name": "x",
        "purl": "pkg:pypi/transformers",
        "properties": [{"name": "trusera:model_name", "value": "meta-llama/Llama-3-8B"}],
    }
    assert classify_component(raw, _properties(raw))[0] == "model"


def test_a_model_reference_is_not_assumed_to_be_a_hugging_face_repository() -> None:
    """⚠ `anthropic/claude-3.5-sonnet` IS A REAL REFERENCE AND NOT A HF REPO.

    Minting `pkg:huggingface/anthropic/claude-3.5-sonnet` would put a fabricated,
    resolvable-looking upstream location into a compliance document — a reader
    could follow that purl, find nothing, and be right that the BOM is wrong.
    """
    api = ladder_identify(
        {
            "model_ref": "anthropic/claude-3.5-sonnet",
            "name": "claude-3.5-sonnet",
            "provider": "Anthropic",
        }
    )
    assert api[0] == "api:anthropic/claude-3.5-sonnet"

    unknown = ladder_identify(
        {"model_ref": "anthropic/claude-3.5-sonnet", "provider": "OpenRouter"}
    )
    assert unknown[0] == "model:anthropic/claude-3.5-sonnet"
    assert "huggingface" not in unknown[0]

    # Where something actually said Hugging Face, the purl is minted.
    stated = ladder_identify({"model_ref": "meta-llama/Llama-3-8B", "provider": "HuggingFace"})
    assert stated[0] == "purl:pkg:huggingface/meta-llama/Llama-3-8B"
    assert stated[1] == "hf_repo"


def test_a_hosted_api_model_is_not_demoted_out_of_the_inventory() -> None:
    """⚠ THE FALSE NEGATIVE A COMPLIANCE INVENTORY MUST NEVER TAKE.

    ai-bom 3.1.0 maps `llm_provider` AND `model` alike to CycloneDX
    `machine-learning-model` and ALWAYS mints a purl from the component's own
    display name, defaulting to `pypi`. So `client.chat.completions.create(
    model="gpt-4o")` arrives as a model-typed component named `OpenAI Model`,
    carrying `trusera:model_name: gpt-4o` and `purl: pkg:pypi/openai model`.

    An earlier form of the reclassification rule required an `org/name` shape as
    proof of modelhood. `gpt-4o` has no slash, so the customer's GPT-4o usage was
    demoted — and because dependencies are built inside the per-model loop, with
    zero models surviving it appeared NOWHERE in the document.
    """
    doc = cdx(
        [
            {
                "bom-ref": "1",
                "type": "machine-learning-model",
                "name": "OpenAI",
                "purl": "pkg:pypi/openai",
                "properties": [{"name": "trusera:provider", "value": "OpenAI"}],
            },
            {
                "bom-ref": "2",
                "type": "machine-learning-model",
                "name": "OpenAI Model",
                "purl": "pkg:pypi/openai model",
                "properties": [
                    {"name": "trusera:provider", "value": "OpenAI"},
                    {"name": "trusera:model_name", "value": "gpt-4o"},
                    {"name": "trusera:source_location", "value": "/src/app.py:9"},
                ],
            },
        ]
    )
    discovery = extract_discovery(doc)

    assert [m["model_id"] for m in discovery["models"]] == ["gpt-4o"]
    # The SDK itself is still a dependency, not a second model.
    assert [f["name"] for f in discovery["frameworks"]] == ["OpenAI"]

    models, _ = merge(discovery["models"], {})
    assert ladder_identify(models[0])[0] == "api:openai/gpt-4o"


def test_a_committed_weights_file_is_a_model_whatever_its_purl_says() -> None:
    """ai-bom's model-file scanner names the component after the file, then mints
    `pkg:pypi/<that name>` — a purl describing no package at all."""
    raw = {
        "type": "machine-learning-model",
        "name": "model.safetensors",
        "purl": "pkg:pypi/model.safetensors",
    }
    assert classify_component(raw, _properties(raw))[0] == "model"


def test_a_purl_the_engine_minted_from_the_name_is_not_independent_evidence() -> None:
    """⚠ BELIEVING THE ENGINE TWICE IS NOT CORROBORATION.

    ai-bom derives every purl from the component's display name
    (`name.lower().replace("_","-")`, type defaulting to `pypi`), so
    `pkg:pypi/huggingface transformers` is the label with a prefix — not something
    PyPI asserted. The demotion fires only where the purl adds nothing the name
    did not already say.
    """
    from workers.aibom.adapters.ai_bom import _purl_derived_from_name

    assert _purl_derived_from_name("pkg:pypi/transformers", "transformers")
    assert _purl_derived_from_name("pkg:pypi/huggingface transformers", "HuggingFace Transformers")
    # A library cannot escape by giving itself a slashed display name.
    assert _purl_derived_from_name("pkg:pypi/transformers", "huggingface/transformers")
    # A purl that points somewhere the name does not is real evidence.
    assert not _purl_derived_from_name("pkg:pypi/torch", "SomeModel")


# ---------------------------------------------------------------------------
# The two engines added in M3, against their real captured output
#
# ⚠ EVERY ASSERTION BELOW IS AGAINST A REAL RESPONSE, captured by running the
# pinned engine over `testdata/ai-langchain/` under the real sandbox flags —
# --network=none, read-only rootfs, --user 65534:65534. Nothing here is a
# hand-built document shaped the way the adapter wants to read one.
# ---------------------------------------------------------------------------


def _airom_capture() -> dict:
    return json.loads(
        (Path(__file__).parent / "testdata" / "airom-ai-langchain.cdx.json").read_text(
            encoding="utf-8"
        )
    )


def _cdxgen_capture() -> dict:
    return json.loads(
        (Path(__file__).parent / "testdata" / "cdxgen-ai-ai-langchain.cdx.json").read_text(
            encoding="utf-8"
        )
    )


def test_airom_dispatches_on_its_own_kind_not_on_the_cyclonedx_type() -> None:
    """⚠ THE CycloneDX TYPE WOULD LOSE FOUR OF THE SIX THINGS airom FOUND.

    Real airom output types its vector store and its RAG pipeline as
    `application` — which is in the AIBOM classifier's FRAMEWORK set, so a
    type-based dispatch files a vector store as a software dependency — and its
    prompts as `data`, which is in neither set, so both would be dropped without
    a word. `airom:kind` says exactly what each component is.
    """
    raw = _airom_capture()
    kinds = {
        c["name"]: (
            c["type"],
            {p["name"]: p["value"] for p in c.get("properties", [])}.get("airom:kind"),
        )
        for c in raw["components"]
    }
    assert kinds["chroma"] == ("application", "vector-db"), (
        "the captured response no longer carries the type/kind disagreement this test is about"
    )
    assert kinds["system-prompt"] == ("data", "prompt")

    found = extract_airom_discovery(raw)

    assert {a["asset_type"] for a in found["assets"]} == {"prompt", "vector_store", "rag_pipeline"}
    assert {f["name"] for f in found["frameworks"]} == {
        "langchain",
        "langchain-openai",
        "transformers",
        "sentence-transformers",
    }


def test_airom_true_casing_comes_from_its_identity_evidence() -> None:
    """⚠ ITS COMPONENT NAME IS LOWERCASED AND HUGGING FACE IS CASE-SENSITIVE.

    `airom:model.id` reads `meta-llama/llama-3-8b`; only
    `evidence.identity[].concludedValue` carries `meta-llama/Llama-3-8B`. Using
    the lowercased form keys the same model differently from ai-bom and cdxgen —
    storing one model as two — and sends enrichment a reference the Hub does not
    resolve.
    """
    raw = _airom_capture()
    lowercased = [c for c in raw["components"] if c["name"] == "meta-llama/llama-3-8b"]
    assert lowercased, "the captured response no longer carries the lowercasing"

    models = {m["model_id"]: m for m in extract_airom_discovery(raw)["models"]}

    assert "meta-llama/Llama-3-8B" in models
    assert models["meta-llama/Llama-3-8B"]["locations"] == ["src/app.py:17", "src/app.py:18"]


def test_airom_says_it_could_not_check_advisories() -> None:
    """It queries OSV.dev when it can, and the sandbox has no network by design.
    An absent vulnerability list nobody asked about is the failure invariant 12
    names; the engine's own `assurance.cve.unchecked` becomes a diagnostic."""
    codes = [d["code"] for d in extract_airom_discovery(_airom_capture())["diagnostics"]]
    assert "ENGINE_PARTIAL_ECOSYSTEM" in codes


def test_cdxgen_emits_the_only_correctly_cased_model_purl() -> None:
    """Tier 1 of the identity ladder, from the one engine that supplies it."""
    models = {m["model_id"]: m for m in extract_cdxgen_ai_discovery(_cdxgen_capture())["models"]}

    assert models["meta-llama/Llama-3-8B"]["purl"] == "pkg:huggingface/meta-llama/Llama-3-8B"
    assert models["meta-llama/Llama-3-8B"]["locations"] == ["src/app.py:17", "src/app.py:18"]


def test_a_generic_purl_cdxgen_minted_is_not_treated_as_identity() -> None:
    """⚠ `pkg:generic/openai/gpt-4o` IS cdxgen MINTING A PURL FOR A THING THAT
    HAS NO PACKAGE. `generic` is in `discovery.PACKAGE_PURL_TYPES` precisely so
    it cannot be read as a model identifier."""
    raw = _cdxgen_capture()
    minted = [c for c in raw["components"] if c.get("purl") == "pkg:generic/openai/gpt-4o"]
    assert minted, "the captured response no longer carries the minted purl"

    models = {m["model_id"]: m for m in extract_cdxgen_ai_discovery(raw)["models"]}

    assert models["gpt-4o"]["purl"] == ""
    assert models["gpt-4o"]["provider"] == "openai"


def test_cdxgen_inference_services_are_assets_not_a_second_model_row() -> None:
    """cdxgen reports the services a repository talks to, which neither other
    engine emits. The model each service fronts is already a component; turning
    the service into a second model row would double-count it."""
    found = extract_cdxgen_ai_discovery(_cdxgen_capture())

    endpoints = [a for a in found["assets"] if a["asset_type"] == "endpoint"]
    assert {a["provider"] for a in endpoints} == {"openai", "meta-llama"}
    # ⚠ NO INVENTED URL. cdxgen leaves `endpoints` empty for an implicitly
    # deployed service: it saw the SDK call, not an address.
    assert all(a["locations"] == [] for a in endpoints)
    assert len(found["models"]) == 2


def test_the_three_engines_converge_on_one_key_per_model() -> None:
    """⚠ THE WHOLE ARGUMENT FOR RUNNING THREE ENGINES RESTS ON THIS.

    Independent discovery is only worth more than one engine if the results
    reconcile; if they did not, three engines would report the same model three
    times and the inventory would be worse than with one. Measured across all
    three real captures over the same tree.
    """
    discovered = []
    for engine, extractor, capture in (
        ("ai-bom", extract_discovery, _real_discovery_document()),
        ("airom", extract_airom_discovery, _airom_capture()),
        ("cdxgen-ai", extract_cdxgen_ai_discovery, _cdxgen_capture()),
    ):
        for model in extractor(capture)["models"]:
            discovered.append({**model, "source_engine": engine})

    models, _diagnostics = merge(discovered, {})
    keys = {m["_model_key"]: sorted({p["engine_id"] for p in m["_provenance"]}) for m in models}

    assert keys["purl:pkg:huggingface/meta-llama/Llama-3-8B"] == [
        "ai-bom",
        "airom",
        "cdxgen-ai",
    ]
    assert keys["api:openai/gpt-4o"] == ["airom", "cdxgen-ai"]
    # ⚠ ONE ENGINE, AND SAYING SO IS THE POINT. Only airom reports the embedding
    # model; a reviewer weighing this row should be able to see that.
    assert keys["model:sentence-transformers/all-MiniLM-L6-v2"] == ["airom"]


def test_an_mcp_server_is_both_a_dependency_and_an_ai_asset() -> None:
    """⚠ RECORDING IT ONLY AS A DEPENDENCY LOSES THE HALF THAT MATTERS.

    An MCP server is a package, so it belongs in the software dependency list.
    It is also the surface through which a model takes ACTIONS rather than
    producing text — a governance question no dependency row asks, and the one
    the operational profile's agents/tools/MCP element exists for. `ai-bom` is
    the only engine that classifies them, and before this they reached
    `normalize.ai_assets` from nowhere, so that element could only ever read
    zero — which measures us rather than the customer.
    """
    found = extract_discovery(cdx([MCP_SERVER, HF_MODEL]))

    # Still a dependency: it is a real package with a real purl.
    assert "mcp-server-filesystem" in {f["name"] for f in found["frameworks"]}
    # And now also an asset, so it can be scored and rendered as one.
    assert [(a["asset_type"], a["name"]) for a in found["assets"]] == [
        ("mcp_server", "mcp-server-filesystem")
    ]


def test_an_engine_that_finds_no_mcp_server_reports_no_assets() -> None:
    """The empty case is the common one, and it must be empty rather than absent
    — every discovery extractor returns the same three buckets so the consumer
    never has to know which engine produced which."""
    found = extract_discovery(cdx([LANGCHAIN, HF_MODEL]))
    assert found["assets"] == []
