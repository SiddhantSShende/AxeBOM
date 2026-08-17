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

⚠ `risk_score` AND `owasp_llm_top10` ARE ENCOREBOM EXTENSIONS.

They carry `scored: false` in the profile and are excluded from both coverage
numbers. They come from Trusera's heuristics; letting them count would move a
customer's compliance percentage because a third party changed a rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from encorebom_shared.model.generated_certin import AIBOM_FIELDS

NOT_PROVIDED = "not-provided"

#: Elements no tool populates today. The UI collects them, and until it does
#: they are honestly `not-provided`.
#:
#: ⚠ THIS LIST IS DOCUMENTATION, NOT BEHAVIOUR. Nothing branches on it — every
#: element goes through the same substantive-value check. It exists so the form
#: and the report can say WHY a field is empty rather than leaving a reader to
#: wonder whether the scan failed.
USER_SUPPLIED_FIELDS = frozenset(
    {
        "certin.aibom.12.security_requirements",
        "certin.aibom.15.intended_usage",
        "certin.aibom.16.out_of_scope_usage",
        "certin.aibom.17.environmental_impact",
        "certin.aibom.19.attestations",
    }
)

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

    Returns `(linked, unlinked)`. The unlinked list is reported, not dropped: a
    dependency the SBOM did not catalogue is a gap in the SBOM worth seeing.
    """
    linked: list[str] = []
    unlinked: list[str] = []

    for dep in model.get("frameworks") or []:
        purl = str(dep.get("purl") or "").strip()
        candidate = f"purl:{purl}" if purl else ""

        if candidate and candidate in sbom_component_keys:
            linked.append(candidate)
        elif purl and purl in sbom_component_keys:
            linked.append(purl)
        else:
            unlinked.append(str(dep.get("name") or purl or "<unnamed>"))

    return sorted(set(linked)), sorted(set(unlinked))


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
