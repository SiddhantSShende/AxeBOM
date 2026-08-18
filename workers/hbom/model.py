"""The canonical hardware component — CERT-In Table 11 plus §10.4.1.4.

⚠ TWENTY-FOUR ELEMENTS, AND TABLE 11 ALONE IS NOT ENOUGH.

§10.4.1.4 (p.62) mandates `firmware_version`, `origin`, `criticality` and
`vulnerabilities` for hardware supplied to government and public-sector
entities. None of the four appears anywhere in Table 11. A tool that implements
Table 11 and stops is not compliant, and — worse — reports itself as complete.

⚠ TWO SUPPLIER RELATIONSHIPS, NOT ONE.

Table 11 lists "Supplier Information" and "Supplier Location" **twice**, with
different descriptions: the company that sold you the PRODUCT, and the company
that supplied a COMPONENT to that product's manufacturer. Collapsing them into
one pair loses the distinction that makes an HBOM useful for supply-chain
provenance — the whole point of §10.2.1.

The field count is never written here or anywhere else. It is rendered from the
profile (`len(HBOM_FIELDS)`), because hardcoding a count is exactly how a
product ships a false compliance claim when a guideline is revised.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from encorebom_shared.model.generated_certin import HBOM_FIELDS

NOT_PROVIDED = "not-provided"

#: How deep a subcomponent tree may go before the importer stops descending.
#:
#: ⚠ CAPPED, WITH A DIAGNOSTIC — NOT UNBOUNDED, AND NOT SILENT. A CSV whose
#: `level` column walks 1, 2, 3, … forever is a plausible export bug, and
#: unbounded recursion turns it into a crash. Ten levels is deeper than any real
#: assembly; past that, the customer is told rather than guessed at.
MAX_DEPTH = 10

#: Criticality is a closed set, matching the CHECK constraint on
#: `normalize.hardware_components`.
CRITICALITY_VALUES = ("critical", "high", "medium", "low")

#: Elements no import path can populate from a parts list, and which the form
#: collects instead.
#:
#: ⚠ DOCUMENTATION, NOT BEHAVIOUR. Nothing branches on this set — every field
#: goes through the same substantive-value check. It exists so a report can say
#: WHY a field is empty rather than leaving a reader to wonder whether the
#: import failed.
USER_SUPPLIED_FIELDS = frozenset(
    {
        "certin.hbom.04.warranty_amc",
        "certin.hbom.18.license_information",
        "certin.hbom.19.test_result",
        "certin.hbom.23.criticality",
    }
)


@dataclass
class HardwareComponent:
    """One node in a hardware bill of materials.

    Mirrors `normalize.hardware_components` exactly. Every Table 11 element and
    every §10.4.1.4 addition has a home; absent values become `not-provided` at
    normalization rather than being dropped, because an omitted field hides the
    gap and a `not-provided` one reports it.
    """

    # --- identity within the imported tree ---------------------------------
    #: Stable within one import, used to wire `parent_id` before ids exist.
    local_id: str = ""
    parent_local_id: str | None = None

    #: Depth in the tree. 0 is the product itself.
    level: int = 0

    #: Which row of the source file this came from, for legible errors.
    source_row: int | None = None

    #: How many of this component the parent contains. Not a CERT-In element —
    #: it is the one field every real parts list has and Table 11 does not.
    quantity: int = 1

    # --- Table 11 ----------------------------------------------------------
    product_name: str = ""
    product_version: str = ""
    product_details: str = ""
    warranty_amc: str = ""
    manufacturer_name: str = ""
    manufacturer_location: str = ""
    manufacturing_date: str = ""

    #: The PRODUCT's supplier — who sold this item.
    supplier_info: str = ""
    supplier_location: str = ""

    model_number: str = ""
    serial_number: str = ""
    technical_specification: str = ""

    #: The COMPONENT's supplier — who supplied this part to the manufacturer of
    #: the larger product. A DIFFERENT RELATIONSHIP from the pair above.
    component_supplier_info: str = ""
    component_supplier_location: str = ""

    technology_node: str = ""
    compliance: list[str] = field(default_factory=list)
    power_supply: str = ""
    license_info: str = ""
    test_result: str = ""

    #: Sub-components. The recursion IS element 20.
    children: list[HardwareComponent] = field(default_factory=list)

    # --- §10.4.1.4, absent from Table 11 -----------------------------------
    firmware_version: str = ""
    origin: str = ""
    criticality: str = ""
    #: Vulnerability cluster ids. Populated by matching, not by import.
    findings: list[str] = field(default_factory=list)

    # --- provenance --------------------------------------------------------
    #: Which fields an enrichment provider supplied, so a report can say where a
    #: value came from. A datasheet URL from Nexar is a different kind of fact
    #: from a serial number the customer typed.
    enriched_fields: dict[str, str] = field(default_factory=dict)

    def walk(self, _depth: int = 0) -> Iterator[tuple[int, HardwareComponent]]:
        """Yield (depth, component) for this node and every descendant.

        Depth-first, parents before children, so a renderer can indent as it
        goes. The depth is yielded rather than recomputed because a caller that
        recomputed it would walk the tree twice.
        """
        yield _depth, self
        if _depth >= MAX_DEPTH:
            return
        for child in self.children:
            yield from child.walk(_depth + 1)

    def count(self) -> int:
        """Total nodes in this subtree, including this one."""
        return sum(1 for _ in self.walk())

    def depth(self) -> int:
        """Deepest level below this node."""
        return max(d for d, _ in self.walk())


# ---------------------------------------------------------------------------
# Canonical-path mapping
# ---------------------------------------------------------------------------


#: Profile canonical path -> attribute on HardwareComponent.
#:
#: ⚠ DERIVED FROM THE PROFILE, NOT HAND-LISTED. `_ATTRIBUTE_FOR` is built by
#: stripping the `hardware_component.` prefix and the `[]` suffix, so a profile
#: revision that renames a path fails loudly in `validate_mapping()` instead of
#: silently dropping a field from every report.
def _attribute_for(canonical_path: str) -> str:
    return canonical_path.removeprefix("hardware_component.").removesuffix("[]")


_ATTRIBUTE_FOR: dict[str, str] = {f.id: _attribute_for(f.canonical_path) for f in HBOM_FIELDS}


def validate_mapping() -> list[str]:
    """Report profile elements this model cannot store.

    Called by a test rather than at import time: a mapping gap must fail a
    build, not a customer's request.
    """
    known = set(HardwareComponent.__dataclass_fields__)
    return [
        f"{f.id} -> hardware_component.{_ATTRIBUTE_FOR[f.id]}"
        for f in HBOM_FIELDS
        if _ATTRIBUTE_FOR[f.id] not in known
    ]


def to_profile_row(component: HardwareComponent) -> dict[str, Any]:
    """Render one component as {profile field id: value}.

    ⚠ EVERY ELEMENT APPEARS. An absent value becomes `not-provided` — reported,
    never omitted — because omission hides the gap while `not-provided` states
    it. Coverage scoring then treats `not-provided` as present = 0, which is
    what keeps `completeness_pct` honest.
    """
    row: dict[str, Any] = {}

    for f in HBOM_FIELDS:
        attribute = _ATTRIBUTE_FOR[f.id]
        value = getattr(component, attribute, None)

        if f.type == "recursive_ref":
            # Element 20 is the sub-component list. Its VALUE is the count of
            # direct children: a report needs to say "this assembly declares
            # four sub-components", and the children themselves are rendered as
            # their own rows.
            row[f.id] = len(component.children) if component.children else NOT_PROVIDED
            continue

        if isinstance(value, list):
            row[f.id] = value if value else NOT_PROVIDED
            continue

        row[f.id] = value if value not in ("", None) else NOT_PROVIDED

    return row


def normalize(component: HardwareComponent) -> HardwareComponent:
    """Return a component with its values cleaned, recursively.

    Deliberately narrow: it trims whitespace, lower-cases the criticality enum,
    and drops empty strings out of list fields. It does NOT guess — an absent
    manufacturer stays absent, because a plausible default would be read as a
    fact about somebody's hardware.
    """
    component.product_name = component.product_name.strip()
    component.criticality = component.criticality.strip().lower()
    if component.criticality and component.criticality not in CRITICALITY_VALUES:
        # An unrecognised rating is dropped rather than coerced. Mapping
        # "urgent" onto "critical" is a guess about severity, and severity in a
        # compliance document is not ours to invent.
        component.criticality = ""

    for attribute in (
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
        "power_supply",
        "license_info",
        "test_result",
        "firmware_version",
        "origin",
    ):
        setattr(component, attribute, str(getattr(component, attribute) or "").strip())

    component.compliance = [c.strip() for c in component.compliance if c and c.strip()]
    component.children = [normalize(child) for child in component.children]
    return component
