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

from .adapters.aibom_generator import ModelCard

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
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Join discovery and enrichment into one model per identity.

    Returns `(models, diagnostics)`.
    """
    merged: dict[str, dict[str, Any]] = {}
    diagnostics: list[dict[str, Any]] = []

    for found in discovered:
        key = identity(found)

        if key in merged:
            # ⚠ THE SAME MODEL SEEN TWICE IS ONE MODEL WITH TWO LOCATIONS.
            #
            # A model referenced from three files is one entry in a Table 10
            # inventory; listing it three times inflates the model count, which
            # is a headline number a reviewer reads.
            _absorb_usage(merged[key], found)
            continue

        merged[key] = dict(found)

    for key, model in merged.items():
        card = cards.get(model.get("model_ref", "")) or cards.get(key)
        if card is None:
            # Not an error. Most models in most repositories are not on Hugging
            # Face, or the lookup failed; the Table 10 elements enrichment would
            # have filled stay `not-provided`, visibly.
            continue
        _apply_card(model, card)

    duplicates = len(discovered) - len(merged)
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


def identity(model: dict[str, Any]) -> str:
    """The merge key for an AI model.

    ⚠ THE MODEL REFERENCE FIRST, NOT THE NAME.

    `Llama-3-8B` is a name several organisations publish variants under;
    `meta-llama/Llama-3-8B` is one model. Merging on the bare name would fold a
    customer's fine-tune into the upstream model and attribute the upstream
    licence to it — the same class of error as merging `npm/lodash` with
    `maven/lodash`.

    Falls back to a name-scoped key only when no reference exists, and that key
    is deliberately prefixed so it can never collide with a real reference.
    """
    ref = str(model.get("model_ref") or "").strip()
    if ref:
        return ref

    purl = str(model.get("purl") or "").strip()
    if purl:
        return purl

    name = str(model.get("name") or "").strip()
    return f"name:{name.lower()}" if name else "name:<unnamed>"


def _absorb_usage(target: dict[str, Any], other: dict[str, Any]) -> None:
    """Fold a second sighting into the first."""
    locations = list(target.get("locations") or []) + list(other.get("locations") or [])
    target["locations"] = sorted(set(locations))

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


def model_refs(discovered: list[dict[str, Any]]) -> list[str]:
    """The identities worth looking up, deduplicated and in a stable order.

    ⚠ ONLY REAL REFERENCES. A model with no `org/name` reference cannot be
    looked up, and passing its bare name to Hugging Face would fetch a
    DIFFERENT model whose card would then be attributed to the customer's.
    """
    seen: dict[str, None] = {}
    for model in discovered:
        ref = str(model.get("model_ref") or "").strip()
        if ref and "/" in ref:
            seen.setdefault(ref, None)
    return list(seen)
