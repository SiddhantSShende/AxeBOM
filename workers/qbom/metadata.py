"""QBOM device metadata — CERT-In Table 8's eleven elements.

⚠ CAPTURED, NOT DISCOVERED. There is no quantum-hardware scanner, so every
value here comes from a form or an import. The product says so at the point of
entry rather than letting a user wait for a scan that will never populate it.

⚠ THE SAME `not-provided` DISCIPLINE AS EVERYWHERE ELSE. An unrecorded element
is stored explicitly as `not-provided` — never silently omitted, because
omission hides the gap — and `not-provided` scores zero for completeness. Both
halves matter (CLAUDE.md invariant 3).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from encorebom_shared.model.generated_certin import QBOM_FIELDS

NOT_PROVIDED = "not-provided"

#: Two of Table 8's eleven elements are not free-form device metadata.
#:
#: `crypto_assets` REFERENCES the CBOM-derived assets — a QBOM does not
#: re-discover them — and `findings` references vulnerabilities matched against
#: them. Both are populated by derivation, so a form that asked a user to type
#: them would be asking them to duplicate the scan.
DERIVED_FIELDS = frozenset(
    {
        "certin.qbom.05.cryptographic_asset",
        "certin.qbom.10.vulnerabilities",
    }
)


@dataclass
class FieldGap:
    """One element that carries no substantive value, and why."""

    field_id: str
    name: str
    reason: str


def form_fields() -> list[dict[str, Any]]:
    """The elements a user is asked to supply.

    ⚠ GENERATED FROM THE PROFILE. No count is written anywhere — a CERT-In
    revision that adds an element adds a form field, without a code change
    (CLAUDE.md invariant 2).
    """
    return [
        {
            "field_id": f.id,
            "name": f.name,
            "canonical_path": f.canonical_path,
            "type": f.type,
            "source_page": f.source_page,
            "derived": f.id in DERIVED_FIELDS,
        }
        for f in QBOM_FIELDS
    ]


def normalize_device(
    values: dict[str, Any],
    *,
    crypto_asset_refs: list[str] | None = None,
    finding_refs: list[str] | None = None,
) -> tuple[dict[str, Any], list[FieldGap]]:
    """Build a quantum component row, recording every gap explicitly.

    Returns `(row, gaps)`. The gaps are what the report renders; they are not an
    error, and a device with ten of eleven elements unrecorded is a legitimate
    state that must be visible rather than hidden behind a percentage.
    """
    row: dict[str, Any] = {}
    field_status: dict[str, str] = {}
    gaps: list[FieldGap] = []

    for f in QBOM_FIELDS:
        column = f.canonical_path.removeprefix("quantum_component.").removesuffix("[]")

        if f.id in DERIVED_FIELDS:
            derived = crypto_asset_refs if "crypto" in f.id else finding_refs
            derived = derived or []
            row[column] = derived
            # ⚠ AN EMPTY DERIVED LIST IS `not-provided`, NOT `provided`. A QBOM
            # whose CBOM found nothing has no crypto assets to reference, and
            # recording that as present would score a field that carries no
            # information.
            field_status[f.id] = "provided" if derived else NOT_PROVIDED
            if not derived:
                gaps.append(
                    FieldGap(
                        f.id,
                        f.name,
                        "Derived from CBOM discovery, which found nothing to reference. "
                        "Run a CBOM scan for this project.",
                    )
                )
            continue

        value = values.get(column)
        if _is_substantive(value):
            row[column] = value
            field_status[f.id] = "provided"
        else:
            # ⚠ STORED EXPLICITLY, NEVER OMITTED. Omission hides the gap; the
            # explicit value is what makes it countable and reportable.
            row[column] = NOT_PROVIDED if f.type != "ref_list" else []
            field_status[f.id] = NOT_PROVIDED
            gaps.append(
                FieldGap(
                    f.id,
                    f.name,
                    "Not recorded. There is no quantum-hardware scanner; this "
                    "element is captured by form or import.",
                )
            )

    row["field_status"] = field_status
    return row, gaps


def _is_substantive(value: Any) -> bool:
    """Mirror the normalizer's rule, deliberately.

    `not-provided`, `unknown`, `""` and `[]` all score present = 0. A user who
    types "not-provided" into a form has DECLARED the gap, which is a real act —
    and it still counts as zero.
    """
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip().lower() not in {"", NOT_PROVIDED, "noassertion", "unknown", "n/a"}
    if isinstance(value, (list, tuple, dict)):
        return len(value) > 0
    return True


#: The sentence the UI shows above the form.
#:
#: ⚠ THIS IS A PRODUCT COMMITMENT, NOT COPY. Implying that a scan will fill
#: these in leaves a customer waiting for results that are never coming, and the
#: empty QBOM then reads as a broken product rather than an honest one.
FORM_DISCLOSURE = (
    "There is no open-source scanner for quantum hardware. The cryptographic "
    "assets in this QBOM are DERIVED from CBOM discovery with quantum-"
    "vulnerability rules applied; the device metadata below is captured here, "
    "by you. Anything you leave blank is recorded as `not-provided` and counts "
    "as a gap rather than being hidden."
)
