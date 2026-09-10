"""The merge key for an AI model, and the ladder that produces it.

⚠ `normalize.ai_models` HAD NO IDENTITY COLUMN AT ALL, AND THAT IS WHY ONE MODEL
BECAME THREE ROWS. `merge.identity()` fell back from the model reference to the
component's purl to a lowercased display name, so `transformers`,
`HuggingFace Transformers` and `HuggingFace Transformers Model` — three labels ai-bom
produced for one repository — hashed to three different surrogate ids and were stored
as three separate AI models in a CERT-In Table 10 inventory.

This module is the AI-model counterpart of `03-NORMALIZER-SPEC.md` §1.2's
`component_key` chain, which already reserves its lowest-confidence tier for "AIBOM
model lists". The rules mirror it deliberately: first rule that produces a value wins,
the rule that fired is always recorded, and the last tier never merges with anything.

⚠ EVERY TIER IS PREFIXED, AND THE PREFIX IS LOAD-BEARING. `hash:` and `name:` keys can
never collide even if their payloads are byte-identical, which is the property that
stops a weight digest from being mistaken for a name somebody typed.

⚠ TIER 4 NEVER MERGES ACROSS PROVIDERS. `openai/gpt-4o` and `azure/gpt-4o` are billed,
governed, versioned and deprecated separately. Folding them together would attribute
one provider's terms to the other, which is the same class of error as merging
`pkg:npm/lodash` with `pkg:maven/lodash`.
"""

from __future__ import annotations

import uuid
from typing import Any

#: Namespace for tier-7 keys. Stable forever — changing it re-identifies every
#: unidentifiable model in every stored document.
OPAQUE_NAMESPACE = uuid.UUID("6f2a1c94-8d3b-5e7a-9c41-2b8e5d0a7f36")

#: Providers that serve a model over an API rather than publishing a repository.
#: A model here has a real, resolvable identity even though nothing is downloadable.
API_PROVIDERS = frozenset(
    {
        "openai",
        "anthropic",
        "azure",
        "azure-openai",
        "bedrock",
        "aws-bedrock",
        "vertex",
        "vertexai",
        "google",
        "gemini",
        "cohere",
        "mistral",
        "groq",
        "together",
        "fireworks",
        "replicate",
        "deepseek",
        "xai",
        "perplexity",
    }
)

#: Rule ids, recorded on every row. Never renumber — they appear in provenance.
RULE_HF_REPO = "hf_repo"
RULE_MODEL_REF = "model_ref"
RULE_WEIGHT_DIGEST = "weight_digest"
RULE_OCI_DIGEST = "oci_digest"
RULE_API_MODEL = "api_model"
RULE_LOCAL_FILE = "local_file"
RULE_NAME = "name"
RULE_OPAQUE = "opaque"

#: Confidence per rule, mirroring the component ladder's vocabulary.
CONFIDENCE = {
    RULE_HF_REPO: "high",
    RULE_MODEL_REF: "medium",
    RULE_WEIGHT_DIGEST: "high",
    RULE_OCI_DIGEST: "high",
    RULE_API_MODEL: "medium",
    RULE_LOCAL_FILE: "low",
    RULE_NAME: "low",
    RULE_OPAQUE: "low",
}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _normalized_provider(model: dict[str, Any]) -> str:
    return _text(model.get("provider")).lower().replace(" ", "-")


#: Provider spellings that mean Hugging Face.
_HUGGINGFACE_PROVIDERS = frozenset({"huggingface", "hugging-face", "hf"})


def _is_huggingface(model: dict[str, Any], provider: str) -> bool:
    """Did something actually say Hugging Face, or are we assuming it?"""
    if provider in _HUGGINGFACE_PROVIDERS:
        return True
    if _text(model.get("model_ref_source")) == "huggingface":
        return True
    return _text(model.get("purl")).startswith("pkg:huggingface/")


def provider_of(model: dict[str, Any]) -> str:
    """The discovered provider, in the one spelling the ladder compares against.

    Public because the enrichment plane has to make the SAME judgement this module
    makes — see `merge.lookup_plan`. Two normalisations of one string eventually
    disagree, and the disagreement here would be "we asked Hugging Face about a
    model Hugging Face does not serve".
    """
    return _normalized_provider(model)


def is_huggingface(model: dict[str, Any]) -> bool:
    """Did something actually say Hugging Face about this model?

    Never a guess: a provider spelling, an explicit `model_ref_source`, or a
    `pkg:huggingface/` purl. The absence of all three means we do not know, which
    is what stops a bare name being looked up on a Hub that may serve an unrelated
    repository under it.
    """
    return _is_huggingface(model, _normalized_provider(model))


def identify(
    model: dict[str, Any], *, scan_id: str = "", ordinal: int | None = None
) -> tuple[str, str, str]:
    """Return `(model_key, identity_rule, confidence)` for one discovered model.

    `scan_id` and `ordinal` are read ONLY by the opaque tier, and only to keep two
    unidentifiable models distinct. Without `ordinal`, two models carrying no name, no
    reference, no purl and no bom-ref produce byte-identical seeds and therefore the
    same key — which would silently merge them and under-report the inventory, the
    exact thing tier 7 promises never to do. Callers that can supply a stable position
    must; `merge.merge` does.
    """
    provider = _normalized_provider(model)
    ref = _text(model.get("model_ref"))

    # ⚠ AN `org/name` REFERENCE IS NOT AUTOMATICALLY A HUGGING FACE REPOSITORY.
    #
    # `anthropic/claude-3.5-sonnet` is a real model reference and there is no such
    # Hugging Face repo. Minting `pkg:huggingface/anthropic/claude-3.5-sonnet` for
    # it would put a fabricated, resolvable-looking upstream location into a
    # compliance document — a reader could follow that purl, find nothing, and be
    # right to conclude the BOM is wrong.
    #
    # A Hugging Face purl is minted only where something actually said Hugging
    # Face: the provider, an `huggingface_id` property, or a `pkg:huggingface/`
    # purl the engine already emitted (recorded by the adapter as
    # `model_ref_source`). An API provider's model takes the api tier below.
    # Everything else keeps its reference under a neutral `model:` prefix — same
    # dedup power, no claim about where it lives.
    if ref and "/" in ref and provider not in API_PROVIDERS:
        # ⚠ THE REVISION IS CARRIED AS `version` IN THIS CODEBASE, not `revision`.
        # `merge._apply_card` writes an enrichment revision into `version` and
        # `test_a_pinned_revision_from_the_code_is_not_overwritten_by_the_card`
        # pins that. Reading a `revision` key nothing sets would make this rung
        # look revision-aware while collapsing two pinned revisions of one model
        # into a single row — and a model at two revisions can carry two
        # different licences (see `aibom_generator.ModelCache`).
        revision = _text(model.get("version")) or _text(model.get("revision"))
        suffix = f"@{revision}" if revision else ""
        if _is_huggingface(model, provider):
            return (
                f"purl:pkg:huggingface/{ref}{suffix}",
                RULE_HF_REPO,
                CONFIDENCE[RULE_HF_REPO],
            )
        return f"model:{ref}{suffix}", RULE_MODEL_REF, CONFIDENCE[RULE_MODEL_REF]

    # A digest of the weights themselves is the strongest thing anyone can hold: it
    # survives a rename, a re-upload and a deleted repository. `model_signing`
    # produces exactly this, which is what makes attestation and identity agree.
    digest = _text(model.get("weight_digest")) or _text(model.get("checkpoint_sha256"))
    if digest:
        return f"hash:{digest.lower()}", RULE_WEIGHT_DIGEST, CONFIDENCE[RULE_WEIGHT_DIGEST]

    oci = _text(model.get("oci_digest"))
    if oci:
        return f"oci:{oci.lower()}", RULE_OCI_DIGEST, CONFIDENCE[RULE_OCI_DIGEST]

    # ⚠ THE ASSERTED ID, NOT THE DISPLAY LABEL. ai-bom names this component
    # `OpenAI Model` and puts the actual model — `gpt-4o` — in a property. Keying
    # on the label would give every OpenAI model in the estate the same identity.
    name = _text(model.get("model_id")) or _text(model.get("name"))
    version = _text(model.get("version"))
    if provider in API_PROVIDERS and name:
        suffix = f"@{version}" if version else ""
        key = f"api:{provider}/{name.lower()}{suffix}"
        return key, RULE_API_MODEL, CONFIDENCE[RULE_API_MODEL]

    path = _text(model.get("file_path"))
    file_sha = _text(model.get("file_sha256"))
    if path and file_sha:
        return f"file:{path}@{file_sha.lower()}", RULE_LOCAL_FILE, CONFIDENCE[RULE_LOCAL_FILE]

    if name:
        scope = provider or "unscoped"
        suffix = f"@{version}" if version else ""
        return f"name:{scope}/{name.lower()}{suffix}", RULE_NAME, CONFIDENCE[RULE_NAME]

    # ⚠ NEVER MERGES WITH ANYTHING, INCLUDING ANOTHER OPAQUE MODEL. Two models we
    # cannot identify are two models, not one. Collapsing them would under-report an
    # inventory, which is the direction of error a compliance document must not take.
    position = "" if ordinal is None else str(ordinal)
    seed = f"{scan_id}|{position}|{model.get('bom_ref') or ''}|{model.get('purl') or ''}"
    return (
        f"opaque:{uuid.uuid5(OPAQUE_NAMESPACE, seed)}",
        RULE_OPAQUE,
        CONFIDENCE[RULE_OPAQUE],
    )
