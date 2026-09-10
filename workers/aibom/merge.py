"""Merging discovery with enrichment.

⚠ THE TWO ENGINES ANSWER DIFFERENT QUESTIONS, AND THE MERGE RULE FOLLOWS FROM
THAT RATHER THAN FROM A PRECEDENCE ORDER.

    ai-bom (discovery)          what the repository USES
                                where, which framework, which provider

    aibom-generator (enrichment)  what the model IS
                                licence, developer, architecture, datasets

So neither "wins" globally. Discovery wins on USAGE facts because it read the
customer's code and enrichment never saw it; enrichment wins on MODEL facts
because it read the model card and discovery only saw a string.

A single precedence order would be wrong in one direction or the other: letting
enrichment win everywhere overwrites the location a model is used at with
nothing, and letting discovery win everywhere keeps a licence guessed from a
name over one read from the card.
"""

from __future__ import annotations

from typing import Any

from . import identity as ai_identity
from .adapters.aibom_generator import ModelCard
from .discovery import ASSET_PROMPT

#: Facts only the code can establish. Enrichment must never overwrite these.
USAGE_FIELDS = ("locations", "framework", "provider", "purl", "bom_ref")

#: Facts only the model card can establish. Discovery must never supply these.
MODEL_FIELDS = (
    "developer",
    "license",
    "model_type",
    "architectures",
    "datasets",
    "performance_metrics",
    "input_modality",
    "output_modality",
)


def merge(
    discovered: list[dict[str, Any]],
    cards: dict[str, ModelCard],
    *,
    scan_id: str = "",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Join discovery and enrichment into one model per identity.

    Returns `(models, diagnostics)`.

    ⚠ IDENTITY IS COMPUTED HERE, ONCE, AND CARRIED ON THE MODEL. It used to be
    computed here to merge and then computed AGAIN downstream to store, with
    different arguments — so an opaque-tier model was merged under one key and
    written under another, and `user_values_by_identity` was looked up with a key
    that no longer matched the one the merge had used. Two derivations of the same
    fact eventually disagree; this leaves only one.
    """
    merged: dict[str, dict[str, Any]] = {}
    diagnostics: list[dict[str, Any]] = []

    for ordinal, found in enumerate(discovered):
        key, rule, confidence = ai_identity.identify(found, scan_id=scan_id, ordinal=ordinal)
        found = {
            **found,
            "_model_key": key,
            "_identity_rule": rule,
            "_identity_confidence": confidence,
            # ⚠ ONE ENTRY PER SIGHTING, AND THE LIST IS THE ANSWER.
            #
            # Three engines discover independently and converge on the same key,
            # so "which engine found this model" has up to three answers and a
            # singular `source_engine` column can hold one. Each sighting keeps
            # what THAT engine called it and where THAT engine saw it, because
            # the engines disagree in ways worth being able to read afterwards:
            # for one model on one tree, ai-bom said `HuggingFace Transformers
            # Model`, airom said `meta-llama/llama-3-8b` and cdxgen said
            # `Llama-3-8B`. Written to `normalize.ai_model_provenance`.
            "_provenance": [_sighting(found)],
        }

        if key in merged:
            # ⚠ THE SAME MODEL SEEN TWICE IS ONE MODEL WITH TWO LOCATIONS.
            #
            # A model referenced from three files is one entry in a Table 10
            # inventory; listing it three times inflates the model count, which
            # is a headline number a reviewer reads.
            _absorb_usage(merged[key], found)
            continue

        merged[key] = dict(found)

    # ⚠ COUNTED BEFORE THE ALIAS FOLD, WHICH REPORTS ITSELF SEPARATELY. These are
    # two different facts — "one model referenced from three files" and "two
    # engines disagreed about a model's provider" — and one number covering both
    # would attribute the second to the first.
    duplicates = len(discovered) - len(merged)

    diagnostics.extend(_fold_low_confidence_aliases(merged))

    for key, model in merged.items():
        # ⚠ THE SAME VALUE `lookup_plan` ASKED UNDER, OR THE CARD NEVER LANDS.
        # `cards` is keyed by whatever was sent to Hugging Face. Looking it up
        # under `model_ref` alone missed every model whose reference is not
        # `org/name` shaped — observed live: `distilbert-base-uncased` was
        # fetched, parsed and stored, and then joined against `""`.
        card = cards.get(lookup_ref(model)) or cards.get(key)
        if card is None:
            # Not an error. Most models in most repositories are not on Hugging
            # Face, or the lookup failed; the Table 10 elements enrichment would
            # have filled stay `not-provided`, visibly.
            continue
        _apply_card(model, card)

    if duplicates > 0:
        diagnostics.append(
            {
                "severity": "info",
                "code": "NORMALIZE_IDENTITY_MERGED",
                "message": f"{duplicates} duplicate model reference(s) merged by identity",
                "hint": "a model referenced from several files is one model with several locations",
            }
        )

    return list(merged.values()), diagnostics


def identity(model: dict[str, Any], *, scan_id: str = "", ordinal: int | None = None) -> str:
    """The merge key for an AI model — the first tier of the ladder that fires.

    ⚠ THE MODEL REFERENCE FIRST, NOT THE NAME.

    `Llama-3-8B` is a name several organisations publish variants under;
    `meta-llama/Llama-3-8B` is one model. Merging on the bare name would fold a
    customer's fine-tune into the upstream model and attribute the upstream
    licence to it — the same class of error as merging `npm/lodash` with
    `maven/lodash`.

    ⚠ THE COMPONENT PURL IS NO LONGER A TIER, AND REMOVING IT WAS THE FIX.
    This used to fall back to the component's own purl, so one model reported
    under three labels with three purls became three rows in a Table 10
    inventory. A package purl describes the library that LOADS a model, never the
    model — `identity.py` explains the full ladder and why each tier is prefixed.
    """
    # A model that has already been through `merge` carries its key; recomputing
    # it would risk a different answer for the opaque tier, which depends on the
    # position this model held in the discovery list.
    carried = model.get("_model_key")
    if isinstance(carried, str) and carried:
        return carried
    key, _rule, _confidence = ai_identity.identify(model, scan_id=scan_id, ordinal=ordinal)
    return key


#: Ladder tiers strong enough to absorb a low-confidence alias. Each of these
#: rests on something an engine actually established — a namespaced reference, a
#: digest, or a provider from a known API vendor.
_STRONG_RULES = frozenset(
    {
        ai_identity.RULE_HF_REPO,
        ai_identity.RULE_MODEL_REF,
        ai_identity.RULE_WEIGHT_DIGEST,
        ai_identity.RULE_OCI_DIGEST,
        ai_identity.RULE_API_MODEL,
    }
)


def _fold_low_confidence_aliases(merged: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Fold a `name:`-tier model into a stronger one asserting the SAME model id.

    ⚠ OBSERVED LIVE, ON A REAL THREE-ENGINE SCAN: `gpt-4o` WAS STORED TWICE.

    ai-bom puts the CALLING FRAMEWORK in its provider property — its values are
    `LangChain`, `HuggingFace`, `ChromaDB` — so the model it found came out as
    `name:langchain/gpt-4o`. airom and cdxgen both report the real serving
    provider, so theirs came out as `api:openai/gpt-4o`. One model, two rows in a
    Table 10 inventory, and the row count is a headline number a reviewer reads.
    Adding engines multiplied a defect instead of diluting it, which is exactly
    what the identity ladder was introduced to stop.

    ⚠ THE FOLD IS DELIBERATELY NARROW, because merging two models that are not
    the same model is worse than listing one twice:

      * only a LOW-confidence `name:` key is ever absorbed; a strong key is
        never folded into anything,
      * the asserted model ids must match exactly, case-insensitively,
      * and exactly ONE strong candidate may claim it. Two candidates means the
        name is ambiguous — `gpt-4o` from two providers is two models — so
        nothing is folded and the ambiguity is reported instead.

    Returns diagnostics; mutates `merged` in place.
    """
    diagnostics: list[dict[str, Any]] = []

    strong_by_id: dict[str, list[str]] = {}
    for key, model in merged.items():
        if model.get("_identity_rule") in _STRONG_RULES:
            asserted = _asserted_id(model)
            if asserted:
                strong_by_id.setdefault(asserted, []).append(key)

    for key in list(merged):
        model = merged[key]
        if model.get("_identity_rule") != ai_identity.RULE_NAME:
            continue
        asserted = _asserted_id(model)
        if not asserted:
            continue
        candidates = strong_by_id.get(asserted) or []

        if len(candidates) == 1:
            _absorb_usage(merged[candidates[0]], model)
            del merged[key]
            diagnostics.append(
                {
                    "severity": "info",
                    "code": "NORMALIZE_IDENTITY_ALIAS_FOLDED",
                    "message": (
                        f"{key} named the same model as {candidates[0]} and was folded into it"
                    ),
                    "hint": (
                        "one engine reported the calling framework where another "
                        "reported the serving provider; the model is the same one"
                    ),
                }
            )
        elif len(candidates) > 1:
            diagnostics.append(
                {
                    "severity": "info",
                    "code": "NORMALIZE_IDENTITY_AMBIGUOUS",
                    "message": (
                        f"{key} names {asserted!r}, which {len(candidates)} better-"
                        f"identified models also claim ({', '.join(sorted(candidates))}); "
                        f"it is kept separate rather than merged into one of them"
                    ),
                    "hint": "the same model name from two providers is two models",
                }
            )

    return diagnostics


def _asserted_id(model: dict[str, Any]) -> str:
    """The identifier an engine actually asserted, lowercased for comparison.

    ⚠ THE DISPLAY NAME IS DELIBERATELY NOT A FALLBACK. ai-bom labels components
    `LangChain Model` and `HuggingFace Transformers Model`, and folding on those
    would merge every model one framework loads into a single row — the original
    defect, running in reverse.
    """
    return str(model.get("model_id") or "").strip().lower()


def _sighting(model: dict[str, Any]) -> dict[str, Any]:
    """One engine's record of having seen this model."""
    confidence = model.get("engine_confidence")
    return {
        "engine_id": str(model.get("source_engine") or ""),
        "observed_name": str(model.get("name") or ""),
        # airom publishes a number, cdxgen a low/medium/high label. Stored as
        # text either way: this is EVIDENCE, never scored — a third party
        # changing its heuristics must not move a compliance percentage.
        "confidence": (
            str(confidence)
            if confidence is not None
            else str(model.get("engine_confidence_label") or "")
        ),
        "evidence": list(model.get("locations") or []),
    }


def _absorb_usage(target: dict[str, Any], other: dict[str, Any]) -> None:
    """Fold a second sighting into the first."""
    locations = list(target.get("locations") or []) + list(other.get("locations") or [])
    target["locations"] = sorted(set(locations))

    # ⚠ APPENDED, NEVER REPLACED. A second engine finding the same model is the
    # fact this list exists to record; overwriting would leave a row claiming one
    # finder where three agreed.
    target["_provenance"] = [*(target.get("_provenance") or []), *(other.get("_provenance") or [])]

    # A framework or provider seen on one sighting and not the other is still
    # true of the model. Neither overwrites a value already present, because
    # the first sighting is not more authoritative than the second.
    for key in ("framework", "provider"):
        if not target.get(key) and other.get(key):
            target[key] = other[key]


def _apply_card(model: dict[str, Any], card: ModelCard) -> None:
    """Layer enrichment over discovery.

    ⚠ MODEL FIELDS ONLY. The loop is over MODEL_FIELDS rather than over the
    card's attributes, so a field added to ModelCard cannot silently start
    overwriting a usage fact.
    """
    values = {
        "developer": card.developer,
        "license": card.license,
        "model_type": card.model_type,
        "architectures": card.architectures,
        "datasets": card.datasets,
        "performance_metrics": card.performance_metrics,
        "input_modality": card.input_modality,
        "output_modality": card.output_modality,
    }

    for key in MODEL_FIELDS:
        value = values.get(key)
        if value not in (None, "", [], {}):
            model[key] = value

    # ⚠ THE CARD'S NAME IS KEPT SEPARATELY, NOT WRITTEN OVER `name`.
    #
    # `name` is a USAGE fact — what the code called the thing — and overwriting it
    # would lose the only record of how the model is referred to in the customer's
    # own source. `card_name` is the publisher's own name for the model, and it is
    # the top rung of `normalize/ai.py`'s model_name ladder for Table 10 element 01:
    # the publisher outranks both the reference and whatever the engine labelled it.
    # ⚠ ONLY WHEN IT IS ACTUALLY A NAME. `parse_model_card` falls back to
    # `name=component.name or model_ref`, so a card whose CycloneDX component
    # carries no name yields the reference itself. Storing that as `card_name`
    # would make the ladder's top rung return `meta-llama/Llama-3-8B` where the
    # rung below correctly returns `Llama-3-8B` — the publisher's own name is
    # only more authoritative than the reference when it IS one.
    if card.name and card.name != card.model_ref:
        model["card_name"] = card.name

    # The version is the awkward one: discovery may have read a pinned revision
    # out of the code, which is MORE specific than the card's. Only filled when
    # discovery had nothing.
    if not model.get("version") and card.revision:
        model["version"] = card.revision

    model["enriched"] = True
    if card.source_completeness is not None:
        # Kept as evidence, NOT mixed into our coverage number — it scores a
        # different thing against different rules.
        model["source_completeness"] = card.source_completeness


def lookup_plan(
    discovered: list[dict[str, Any]],
) -> tuple[list[str], list[dict[str, str]]]:
    """Split discovered models into "ask Hugging Face" and "do not, because …".

    Returns `(refs, declined)`. `refs` is deduplicated and stably ordered;
    each `declined` entry is `{"ref": …, "reason": …}` and is destined for a
    diagnostic, because a reference we quietly skipped is a Table 10 element
    that silently stays `not-provided` (invariant 12).

    ⚠ A BARE NAME IS LOOKED UP ONLY WHEN SOMETHING SAID HUGGING FACE, and that
    distinction is the whole rule.

    This used to require an `org/name` shape, on the reasoning that a bare name
    "would fetch a DIFFERENT model". Checked against the real Hub: it would not.
    `distilbert-base-uncased`, `gpt2` and `bert-base-uncased` are canonical
    repositories in their own right — `model_info("distilbert-base-uncased")`
    resolves and reports the canonical id `distilbert/distilbert-base-uncased`.
    Refusing them meant the single most common shape of Hugging Face reference
    enriched to nothing at all.

    The real risk the old rule was reaching for is a bare name from SOMEWHERE
    ELSE: `gpt-4o` is OpenAI's, and a Hub repository could exist under that
    name tomorrow. So the provider is what gates it, not the slash.
    """
    seen: dict[str, None] = {}
    declined: dict[str, str] = {}

    for model in discovered:
        ref = lookup_ref(model)
        if ref in seen or ref in declined:
            continue

        provider = ai_identity.provider_of(model)
        huggingface = ai_identity.is_huggingface(model)

        if not ref:
            declined[str(model.get("name") or "an unnamed model")] = (
                "no model identifier was asserted anywhere in the engine's output, "
                "so there is nothing to look up"
            )
            continue
        if provider in ai_identity.API_PROVIDERS and not huggingface:
            declined[ref] = (
                f"served over {provider}'s API, which publishes no Hugging Face model card"
            )
            continue
        if "/" in ref or huggingface:
            seen[ref] = None
            continue
        declined[ref] = (
            "a bare name with no organisation namespace, and nothing said Hugging "
            "Face, so looking it up could return an unrelated repository"
        )

    return list(seen), [{"ref": r, "reason": why} for r, why in declined.items()]


def merge_assets(discovered: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate the AI assets several engines found, and key them.

    ⚠ THE KEY DEPENDS ON THE KIND, BECAUSE THE IDENTITY OF A PROMPT AND THE
    IDENTITY OF A VECTOR STORE ARE DIFFERENT THINGS.

    A prompt IS a piece of text at a place: `src/app.py:9` is what makes one
    system prompt distinct from another in the same file, and airom names them
    all `system-prompt`. A vector store is a SERVICE the application talks to —
    Chroma is one Chroma however many files mention it, and airom evidences it
    from `requirements.txt:4` while another engine might evidence it from the
    import site. Keying both on location would split Chroma in two; keying both
    on name would collapse every system prompt in a repository into one.

    Every key is prefixed with its type, so a prompt named `chroma` and a vector
    store named `chroma` can never collide — the same reasoning the `model_key`
    ladder's tier prefixes carry.
    """
    merged: dict[str, dict[str, Any]] = {}

    for asset in discovered:
        asset_type = str(asset.get("asset_type") or "").strip()
        if not asset_type:
            continue
        key = f"{asset_type}:{_asset_discriminator(asset)}"

        existing = merged.get(key)
        if existing is None:
            merged[key] = {
                **asset,
                "asset_key": key,
                "evidence": sorted(set(asset.get("locations") or [])),
                "_provenance": [_asset_sighting(asset)],
            }
            continue

        existing["evidence"] = sorted(set(existing["evidence"]) | set(asset.get("locations") or []))
        existing["_provenance"] = [*existing["_provenance"], _asset_sighting(asset)]
        for field in ("provider", "serves_model", "deployment", "transport_security"):
            if not existing.get(field) and asset.get(field):
                existing[field] = asset[field]

    return [_asset_row(a) for a in merged.values()]


#: Asset kinds whose identity is WHERE they are, not what they are called.
_LOCATION_KEYED = frozenset({ASSET_PROMPT})


def _asset_discriminator(asset: dict[str, Any]) -> str:
    asset_type = str(asset.get("asset_type") or "")
    name = str(asset.get("name") or "").strip().lower()
    locations = [str(x) for x in (asset.get("locations") or []) if str(x).strip()]

    if asset_type in _LOCATION_KEYED and locations:
        return sorted(locations)[0]
    provider = str(asset.get("provider") or "").strip().lower()
    return provider or name or (sorted(locations)[0] if locations else "unnamed")


def _asset_sighting(asset: dict[str, Any]) -> dict[str, str]:
    return {
        "engine_id": str(asset.get("source_engine") or ""),
        "observed_name": str(asset.get("name") or ""),
    }


def _asset_row(asset: dict[str, Any]) -> dict[str, Any]:
    """The canonical shape `bulk._ai_assets_batch` writes.

    ⚠ `attributes` IS EVIDENCE, NEVER SCORED. It carries what one engine happened
    to say — a service's deployment mode, whether it observed transport security,
    which engines saw it — and none of that is a CERT-In element. Letting it into
    a coverage number would move a compliance percentage because a third party
    added a property.
    """
    attributes = {
        k: asset[k]
        for k in ("deployment", "transport_security", "engine_confidence", "airom_kind")
        if asset.get(k) not in (None, "")
    }
    attributes["found_by"] = sorted(
        {str(p.get("engine_id") or "") for p in asset.get("_provenance") or []} - {""}
    )
    return {
        "asset_type": asset["asset_type"],
        "asset_key": asset["asset_key"],
        "name": str(asset.get("name") or ""),
        "provider": str(asset.get("provider") or ""),
        "evidence": list(asset.get("evidence") or []),
        "serves_model_key": str(asset.get("serves_model_key") or ""),
        "attributes": attributes,
    }


def lookup_ref(model: dict[str, Any]) -> str:
    """The one string this model is asked about, and stored under.

    ⚠ THE ASSERTED ID COUNTS, NOT ONLY THE RESOLVED REFERENCE, and this being
    ONE function is the point.

    `_model_reference` returns "" for anything that is not `org/name` shaped, so
    `distilbert-base-uncased` and `gpt-4o` both arrive with `model_ref: ""` and
    the real identifier in `model_id`. When the enrichment plane and the merge
    each decided this for themselves they disagreed: `lookup_plan` asked Hugging
    Face about `distilbert-base-uncased`, the card came back and was stored under
    that key, and `_apply_card` then looked it up under `""`. Enrichment ran,
    succeeded, wrote its artifact — and reached no row.
    """
    return str(model.get("model_ref") or "").strip() or str(model.get("model_id") or "").strip()


def model_refs(discovered: list[dict[str, Any]]) -> list[str]:
    """The identities worth looking up — `lookup_plan`'s first half."""
    refs, _declined = lookup_plan(discovered)
    return refs
