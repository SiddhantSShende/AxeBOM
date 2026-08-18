"""Structured manual entry.

⚠ THE FORM IS A FIRST-CLASS INPUT, NOT A FALLBACK FOR A FAILED IMPORT.

Four §10.4.1.4 and Table 11 elements — warranty, licence terms, test result and
criticality — appear in no parts list ever exported by a CAD or ERP system.
They are judgements the customer makes about their own hardware. If the only
way in is a CSV, those four are permanently `not-provided` and the coverage
number is permanently and unnecessarily low.

⚠ IT VALIDATES THE SAME WAY THE IMPORTER DOES, THROUGH THE SAME CODE.

A form that accepted a criticality of "urgent" while the importer dropped it
would give the same BOM two different shapes depending on how it was entered —
and the discrepancy would only surface in a report, months later.
"""

from __future__ import annotations

from typing import Any

from .model import CRITICALITY_VALUES, MAX_DEPTH, HardwareComponent, normalize


class FormError(Exception):
    """A submitted component that cannot be stored."""


#: Fields a form may set. Anything else in a payload is rejected rather than
#: ignored: a typo'd key that is silently dropped means the customer believes
#: they recorded something they did not.
EDITABLE_FIELDS = frozenset(
    {
        "product_name",
        "product_version",
        "product_details",
        "warranty_amc",
        "manufacturer_name",
        "manufacturer_location",
        "manufacturing_date",
        "supplier_info",
        "supplier_location",
        "model_number",
        "serial_number",
        "technical_specification",
        "component_supplier_info",
        "component_supplier_location",
        "technology_node",
        "compliance",
        "power_supply",
        "license_info",
        "test_result",
        "firmware_version",
        "origin",
        "criticality",
        "quantity",
        "children",
    }
)


def from_payload(payload: dict[str, Any], *, _depth: int = 0, _path: str = "") -> HardwareComponent:
    """Build a component tree from a submitted structure.

    Recursive, and depth-capped by the same constant the importer uses — a
    hand-crafted payload nesting a thousand levels deep is a denial of service
    against our own recursion limit, not a hardware assembly.
    """
    if _depth > MAX_DEPTH:
        where = _path or "the root component"
        raise FormError(
            f"{where}: sub-components nest deeper than {MAX_DEPTH} levels. "
            f"That is deeper than any real assembly; check for a component that "
            f"contains itself."
        )

    unknown = set(payload) - EDITABLE_FIELDS
    if unknown:
        raise FormError(
            f"{_path or 'the root component'}: unrecognised field(s) "
            f"{', '.join(sorted(unknown))}. A field that is silently ignored "
            f"means you believe you recorded something you did not."
        )

    name = str(payload.get("product_name", "") or "").strip()
    if not name:
        raise FormError(
            f"{_path or 'the root component'}: a product name is required. "
            f"Every other field may be left blank and reported as not-provided; "
            f"a component with no name cannot be referred to at all."
        )

    component = HardwareComponent(
        local_id=_path or "root",
        level=_depth,
        product_name=name,
    )

    for attribute in EDITABLE_FIELDS:
        if attribute in ("product_name", "children", "compliance", "quantity"):
            continue
        if attribute in payload:
            setattr(component, attribute, str(payload[attribute] or "").strip())

    compliance = payload.get("compliance") or []
    if isinstance(compliance, str):
        compliance = [c.strip() for c in compliance.replace(";", ",").split(",")]
    component.compliance = [str(c).strip() for c in compliance if str(c).strip()]

    quantity = payload.get("quantity", 1)
    try:
        component.quantity = max(1, int(quantity))
    except (TypeError, ValueError):
        raise FormError(
            f"{_path or 'the root component'}: quantity {quantity!r} is not a number."
        ) from None

    # ⚠ CHECKED, NOT COERCED. The importer drops an unrecognised rating; a form
    # can do better, because there is somebody there to tell. Mapping "urgent"
    # onto "critical" would be inventing a severity in a compliance document.
    criticality = component.criticality.strip().lower()
    if criticality and criticality not in CRITICALITY_VALUES:
        raise FormError(
            f"{_path or 'the root component'}: criticality {component.criticality!r} "
            f"is not one of {', '.join(CRITICALITY_VALUES)}."
        )
    component.criticality = criticality

    for index, child in enumerate(payload.get("children") or []):
        if not isinstance(child, dict):
            raise FormError(f"{_path or 'root'}: sub-component {index} is not an object.")
        built = from_payload(
            child,
            _depth=_depth + 1,
            _path=f"{_path or 'root'} > child {index}",
        )
        built.parent_local_id = component.local_id
        component.children.append(built)

    return normalize(component)


def blank_form() -> dict[str, Any]:
    """An empty payload with every editable field present.

    ⚠ EVERY FIELD, INCLUDING THE ONES NO IMPORT CAN FILL. Rendering the form
    from this means the four judgement fields are visible and askable rather
    than quietly absent — which is the whole reason the form exists.
    """
    out: dict[str, Any] = dict.fromkeys(sorted(EDITABLE_FIELDS), "")
    out["compliance"] = []
    out["children"] = []
    out["quantity"] = 1
    return out
