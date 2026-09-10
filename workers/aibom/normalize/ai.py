"""Canonical AI models — CERT-In Table 10's nineteen elements.

⚠ EVERY ELEMENT IS POPULATED OR EXPLICITLY `not-provided`. NONE IS OMITTED.

Several elements — intended usage, out-of-scope usage, environmental impact,
security requirements — are rarely in any tool's output and will mostly be
`not-provided` or user-supplied.

**That is the correct outcome, and it is information.** A coverage number that
honestly reports 40% for an AIBOM is telling a customer something true about the
state of AI supply-chain metadata. Papering over it with a plausible default
would produce a higher number and a false one, and the guess would be read as a
fact about their model.

⚠ `risk_score` AND `owasp_llm_top10` ARE AXEBOM EXTENSIONS.

They carry `scored: false` in the profile and are excluded from both coverage
numbers. They come from Trusera's heuristics; letting them count would move a
customer's compliance percentage because a third party changed a rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from axebom_shared.model.generated_certin import AIBOM_FIELDS

NOT_PROVIDED = "not-provided"

#: Elements no tool populates today. The UI collects them, and until it does
#: they are honestly `not-provided`.
#:
#: ⚠ THIS LIST IS DOCUMENTATION, NOT BEHAVIOUR. Nothing branches on it — every
#: element goes through the same substantive-value check. It exists so the form
#: and the report can say WHY a field is empty rather than leaving a reader to
#: wonder whether the scan failed.
#: Elements NO TOOL CAN REPORT — intent and policy, not anything discoverable
#: from code or a model card.
#:
#: ⚠ DERIVED FROM THE PROFILE, NOT LISTED HERE. This used to be a literal set,
#: and so did its Go counterpart, and they disagreed by one element:
#: `environmental_impact` was in this set and absent from Go's, so it was
#: reachable by no form and populated by no tool. The profile declares
#: `user_supplied: true` and both languages generate from it.
USER_SUPPLIED_FIELDS = frozenset(f.id for f in AIBOM_FIELDS if f.user_supplied)

#: How a merged model's keys map onto the canonical columns.
_FROM_MODEL: dict[str, str] = {
    "model_name": "name",
    "model_version": "version",
    "model_type": "model_type",
    "model_developer": "developer",
    "licensing": "license",
    "ml_models_algorithms": "architectures",
    "performance_metrics": "performance_metrics",
    "hardware": "hardware",
    "input": "input_modality",
    "output": "output_modality",
    "security_requirements": "security_requirements",
    "intended_usage": "intended_usage",
    "out_of_scope_usage": "out_of_scope_usage",
    "environmental_impact": "environmental_impact",
    "attestation_signature": "attestation_signature",
}


@dataclass
class FieldGap:
    """One element with no substantive value, and why."""

    field_id: str
    name: str
    reason: str


def normalize_model(
    model: dict[str, Any],
    *,
    user_values: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[FieldGap]]:
    """Build one `normalize.ai_models` row plus its datasets and gaps.

    Returns `(row, datasets, gaps)`.
    """
    user_values = user_values or {}
    row: dict[str, Any] = {}
    field_status: dict[str, str] = {}
    gaps: list[FieldGap] = []

    for f in AIBOM_FIELDS:
        column = f.canonical_path.removeprefix("ai_model.").removesuffix("[]")

        value = _value_for(column, model, user_values)
        if _is_substantive(value):
            row[column] = value
            field_status[f.id] = "provided"
            continue

        # ⚠ STORED EXPLICITLY. Omission hides the gap; the explicit value is
        # what makes it countable, reportable and — crucially — visibly zero in
        # the completeness number (CLAUDE.md invariant 3).
        row[column] = _empty_for(f.type)
        field_status[f.id] = NOT_PROVIDED
        gaps.append(FieldGap(f.id, f.name, _reason_for(f.id, model)))

    row["field_status"] = field_status

    # ⚠ THE TWO EXTENSIONS ARE WRITTEN OUTSIDE THE PROFILE LOOP, so they can
    # never acquire a `field_status` entry and start counting toward coverage.
    if model.get("risk_score") is not None:
        row["risk_score"] = model["risk_score"]
    if model.get("owasp_llm_top10"):
        row["owasp_llm_top10"] = list(model["owasp_llm_top10"])

    return row, _datasets(model), gaps


def _value_for(column: str, model: dict[str, Any], user_values: dict[str, Any]) -> Any:
    """Find a column's value.

    ⚠ A USER-SUPPLIED VALUE WINS OVER A TOOL'S.

    The four elements no tool reports are exactly the ones a customer knows and
    a scanner cannot: what the model is FOR, what it must not be used for, what
    security requirements apply. If a tool ever starts guessing at those, the
    customer's answer is still the authoritative one.
    """
    if column in user_values and _is_substantive(user_values[column]):
        return user_values[column]

    if column == "model_name":
        # ⚠ THE REFERENCE OUTRANKS THE ENGINE'S LABEL, AND IT HAS TO.
        #
        # Table 10 element 01 is "Official name of the AI model". ai-bom emits
        # `HuggingFace Transformers Model` as the `name` of a component whose real
        # identity — `meta-llama/Llama-3-8B` — is in a property. That label is a
        # category, not a name: reporting it as the model's official name states
        # something false about the customer's system in a compliance document.
        #
        # Enrichment's card name wins when present (it is the publisher's own), then
        # the NAME SEGMENT of the reference, then whatever the engine called it.
        #
        # ⚠ THE SEGMENT, NOT THE WHOLE REFERENCE. `meta-llama/Llama-3-8B` is
        # `developer/name`; returning it whole would duplicate the developer into
        # element 04's neighbour and read as a path where a name belongs. The org
        # prefix is deliberately NOT used to fill `model_developer` either — see
        # `test_the_developer_is_not_inferred_from_the_org_prefix`; a publisher is a
        # legal entity, not a URL slug, and enrichment is what establishes it.
        enriched = _string_or_empty(model.get("card_name"))
        if enriched:
            return enriched
        ref = _string_or_empty(model.get("model_ref"))
        if "/" in ref:
            return ref.rsplit("/", 1)[-1]
        # An asserted identifier of any shape still beats the engine's label:
        # `gpt-4o` is the model; `OpenAI Model` is a category.
        asserted = _string_or_empty(model.get("model_id"))
        if asserted:
            return asserted
        return model.get("name")

    if column == "data_source":
        # Derived from the datasets rather than stored twice — two places
        # holding the same fact drift.
        names = [d.get("name", "") for d in _datasets(model)]
        return ", ".join(n for n in names if n)

    if column == "software_dependencies":
        return list(model.get("software_dependencies") or [])

    if column == "findings":
        return list(model.get("findings") or [])

    if column == "data_sets":
        return [d.get("name", "") for d in _datasets(model) if d.get("name")]

    source_key = _FROM_MODEL.get(column, column)
    return model.get(source_key)


def _reason_for(field_id: str, model: dict[str, Any]) -> str:
    """Why an element is empty — which is not the same question as whether."""
    if field_id in USER_SUPPLIED_FIELDS:
        return (
            "No tool reports this element. It describes intent and policy rather "
            "than anything discoverable from code or a model card, so it is "
            "recorded here by you."
        )
    if not model.get("enriched"):
        return (
            "This model was discovered in your code but not enriched — it has no "
            "resolvable model reference, or the lookup failed. Model facts such "
            "as licence and developer come from the model card."
        )
    return (
        "The model card does not carry this element. Most published cards are "
        "incomplete; that is a fact about the ecosystem, not a scan failure."
    )


def _datasets(model: dict[str, Any]) -> list[dict[str, str]]:
    datasets = model.get("datasets")
    return [d for d in datasets if isinstance(d, dict)] if isinstance(datasets, list) else []


def _empty_for(field_type: str) -> Any:
    """The explicit empty value for a type.

    A list field gets `[]` rather than the string `not-provided`, because a
    column typed `text[]` cannot hold it — and both score zero, so nothing is
    lost by using the type's own empty.
    """
    return [] if field_type in {"ref_list", "string_list"} else NOT_PROVIDED


def _is_substantive(value: Any) -> bool:
    """Mirror the normalizer's rule.

    `not-provided`, `unknown`, `""` and `[]` all score present = 0. A user who
    types "not-provided" has DECLARED the gap, which is a real act — and it
    still counts as zero.
    """
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip().lower() not in {"", NOT_PROVIDED, "noassertion", "unknown", "n/a"}
    if isinstance(value, (list, tuple, dict, set)):
        return len(value) > 0
    return True


def link_dependencies(
    model: dict[str, Any],
    sbom_component_keys: set[str],
) -> tuple[list[str], list[str]]:
    """Link an AI model's dependencies to SBOM components already catalogued.

    ⚠ AN AI DEPENDENCY IS USUALLY ALSO A PACKAGE. `langchain` appears in the
    SBOM as `pkg:pypi/langchain`, and linking rather than duplicating means one
    component with one set of vulnerabilities — not two rows a reviewer has to
    reconcile.

    Returns `(keys, unlinked)`.

    ⚠ BOTH LISTS ARE STORED. `keys` holds every dependency — the ones that
    resolved to an SBOM component under its own `component_key`, AND the ones that
    did not, under a `name:` key that deliberately cannot collide with a purl.
    `unlinked` is the same second group by name, for the diagnostic.

    This used to return only the resolved ones, and the rest were dropped. On real
    `ai-bom` output over a project with no SBOM scan that meant EVERY dependency
    vanished: the report showed a model with no dependencies, which reads as "this
    model depends on nothing" rather than "nothing catalogued them". Storing an
    unresolved dependency costs nothing — `ai_model_dependencies.component_key` is
    a plain text column with no foreign key precisely because the component it
    names usually lives in a different document (`01-DATA-MODEL.md`) — and it is
    the difference between an absence and a silence.
    """
    keys: list[str] = []
    unlinked: list[str] = []

    for dep in attributed_frameworks(model):
        purl = str(dep.get("purl") or "").strip()
        candidate = f"purl:{purl}" if purl else ""

        if candidate and candidate in sbom_component_keys:
            keys.append(candidate)
        elif purl and purl in sbom_component_keys:
            keys.append(purl)
        else:
            name = str(dep.get("name") or purl or "<unnamed>")
            unlinked.append(name)
            # A dependency WITH a purl keeps it: the purl is the component's real
            # identity, and `component_key` is resolved by string match at read
            # time across documents (`01-DATA-MODEL.md`), so the SBOM that
            # catalogues it may simply be a document we have not joined yet.
            #
            # ⚠ WITHOUT ONE, `name:` PREFIXED, MIRRORING `component_key` RULE 6.
            # A bare name must never be stored where a purl is expected — a reader
            # joining on `component_key` would treat `transformers` as an identity
            # the ecosystem minted, which nobody did.
            keys.append(f"purl:{purl}" if purl else f"name:{name.lower()}")

    return sorted(set(keys)), sorted(set(unlinked))


def attributed_frameworks(model: dict[str, Any]) -> list[dict[str, Any]]:
    """The frameworks THIS model's dependencies are drawn from.

    ⚠ THE PROJECT-WIDE LIST IS THE FALLBACK, NOT THE ANSWER, AND THE DIFFERENCE
    BECAME VISIBLE THE MOMENT A SECOND MODEL EXISTED.

    `frameworks` is a SCAN-WIDE list — every AI library the engines found
    anywhere in the tree — and the pipeline joins it onto each model. With one
    model in the inventory that reads as "the AI software this model rests on".
    With three, it says `gpt-4o` depends on `sentence-transformers`, which is
    false: an embedding library has nothing to do with a hosted chat model, and
    Table 10 element 06 is read as a claim about THAT model.

    Where an engine actually attributed a calling framework to a model, that
    attribution wins and only the matching framework is linked. Where none did,
    the project-wide set is used and `dependency_scope` reports which of the two
    happened, so the report can say so rather than implying per-model evidence
    it does not have.
    """
    frameworks = list(model.get("frameworks") or [])
    named = str(model.get("framework") or "").strip().lower()
    if not named:
        return frameworks

    matched = [f for f in frameworks if str(f.get("name") or "").strip().lower() == named]
    # An attribution naming a framework no engine catalogued is still an
    # attribution, and falling back to everything would silently widen it.
    return matched


def dependency_scope(model: dict[str, Any]) -> str:
    """`model` when an engine attributed a framework to this model, else `project`.

    Rendered beside element 06 so a reader knows whether "this model's
    dependencies" means "the engine said so" or "these are the AI libraries in
    the project". See `attributed_frameworks`.
    """
    return "model" if str(model.get("framework") or "").strip() else "project"


def coverage_note(gaps: list[FieldGap], total_fields: int) -> str:
    """The sentence a report puts under an AIBOM's coverage number.

    ⚠ IT EXPLAINS A LOW NUMBER RATHER THAN APOLOGISING FOR IT. An AIBOM at 40%
    is reporting something true about the state of AI supply-chain metadata, and
    a reader who does not know that will read it as a defect in the scan.
    """
    user_gaps = sum(1 for g in gaps if g.field_id in USER_SUPPLIED_FIELDS)
    tool_gaps = len(gaps) - user_gaps

    parts = [
        f"{total_fields - len(gaps)} of {total_fields} CERT-In elements carry a substantive value."
    ]
    if user_gaps:
        parts.append(
            f"{user_gaps} describe intent or policy and no tool reports them — "
            f"they are recorded by you, and are `not-provided` until then."
        )
    if tool_gaps:
        parts.append(
            f"{tool_gaps} were not present in the model card. Most published "
            f"cards are incomplete; that is a fact about the ecosystem rather "
            f"than a failure of this scan."
        )
    return " ".join(parts)


def _string_or_empty(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""
