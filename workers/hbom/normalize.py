"""Canonical hardware components and their coverage.

⚠ EVERY NODE IN THE TREE IS SCORED, NOT JUST THE ROOT.

A four-level assembly whose root is fully populated and whose 200 leaf parts
have a part number and nothing else is not a well-documented BOM, and a coverage
number computed over the root alone would say it was. Flattening the tree first
means the number describes the hardware rather than its top row.

⚠ THE FIELD COUNT IS NEVER WRITTEN. It comes from `len(HBOM_FIELDS)`, so a
CERT-In revision is a data change and not a code change — and so this module
cannot ship a false claim about how many elements it covers (invariant 2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from encorebom_shared.model.generated_certin import HBOM_FIELDS
from encorebom_shared.normalize.coverage import CoverageResult, Field, score

from .model import USER_SUPPLIED_FIELDS, HardwareComponent, to_profile_row

#: The scored field set, derived from the profile.
#:
#: `Field.canonical_path` is what `score()` keys on, and `to_profile_row` emits
#: profile IDS — so the rows are re-keyed by path below rather than the two
#: representations being kept in step by hand.
_SCORED: list[Field] = [
    Field(
        id=f.id,
        name=f.name,
        canonical_path=f.canonical_path,
        weight=f.weight,
    )
    for f in HBOM_FIELDS
    if f.scored
]


@dataclass
class HBOMResult:
    """A normalized hardware bill of materials."""

    roots: list[HardwareComponent] = field(default_factory=list)
    coverage: CoverageResult | None = None

    #: Flat rows, one per node, keyed by canonical path. What gets written.
    rows: list[dict[str, Any]] = field(default_factory=list)

    diagnostics: list[dict[str, Any]] = field(default_factory=list)

    def component_count(self) -> int:
        return sum(root.count() for root in self.roots)

    def max_depth(self) -> int:
        return max((root.depth() for root in self.roots), default=0)


def flatten(roots: list[HardwareComponent]) -> list[dict[str, Any]]:
    """Every node in every tree, as a row keyed by canonical path."""
    by_id = {f.id: f.canonical_path for f in HBOM_FIELDS}
    rows: list[dict[str, Any]] = []

    for root in roots:
        for depth, node in root.walk():
            profile_row = to_profile_row(node)
            row = {by_id[field_id]: value for field_id, value in profile_row.items()}
            # Structural facts, outside the profile: they are how a report
            # renders the tree and how a writer wires parent_id.
            row["_local_id"] = node.local_id
            row["_parent_local_id"] = node.parent_local_id
            row["_depth"] = depth
            row["_quantity"] = node.quantity
            row["_enriched_fields"] = dict(node.enriched_fields)
            rows.append(row)

    return rows


def normalize_bom(roots: list[HardwareComponent]) -> HBOMResult:
    """Score a hardware BOM and produce the rows to store."""
    rows = flatten(roots)
    coverage = score(rows, _SCORED)

    result = HBOMResult(roots=roots, coverage=coverage, rows=rows)
    result.diagnostics.extend(_diagnose(roots, rows))
    return result


def _diagnose(roots: list[HardwareComponent], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Say what this BOM does not know, in the terms a reader needs.

    ⚠ THE ORIGIN AND SUPPLIER DIAGNOSTICS EXIST BECAUSE THOSE FIELDS ARE THE
    POINT. §10.2.1 makes an HBOM a supply-chain provenance document; one with no
    manufacturer location and no origin is a parts list. A coverage percentage
    alone does not communicate that — it averages the gap away across twenty
    other fields.
    """
    out: list[dict[str, Any]] = []
    total = len(rows)
    if not total:
        return out

    def missing(path: str) -> int:
        return sum(1 for r in rows if r.get(path) in ("", None, "not-provided", []))

    origin_gaps = missing("hardware_component.origin")
    if origin_gaps:
        out.append(
            {
                "severity": "warn",
                "code": "HBOM_ORIGIN_NOT_PROVIDED",
                "message": f"{origin_gaps} of {total} components declare no origin",
                "hint": (
                    "§10.4.1.4 requires origin for hardware supplied to government "
                    "and public-sector entities; §10.2.1 is why it matters — an HBOM "
                    "without it cannot answer where the parts came from"
                ),
            }
        )

    manufacturer_gaps = missing("hardware_component.manufacturer_location")
    if manufacturer_gaps:
        out.append(
            {
                "severity": "info",
                "code": "HBOM_MANUFACTURER_LOCATION_NOT_PROVIDED",
                "message": (
                    f"{manufacturer_gaps} of {total} components declare no manufacturer location"
                ),
                "hint": "the supply-chain provenance signal in §10.2.1",
            }
        )

    # ⚠ THE TWO SUPPLIER RELATIONSHIPS ARE REPORTED SEPARATELY. Collapsing them
    # into one "supplier coverage" number would hide exactly the distinction
    # Table 11 draws by listing them twice.
    product_supplier_gaps = missing("hardware_component.supplier_info")
    component_supplier_gaps = missing("hardware_component.component_supplier_info")
    if product_supplier_gaps or component_supplier_gaps:
        out.append(
            {
                "severity": "info",
                "code": "HBOM_SUPPLIER_NOT_PROVIDED",
                "message": (
                    f"product supplier missing on {product_supplier_gaps} of {total}; "
                    f"component supplier missing on {component_supplier_gaps} of {total}"
                ),
                "hint": (
                    "Table 11 lists these twice with different meanings — who sold "
                    "you the product, and who supplied a part to its manufacturer"
                ),
            }
        )

    user_supplied_gaps = sum(
        1
        for f in HBOM_FIELDS
        if f.id in USER_SUPPLIED_FIELDS and missing(f.canonical_path) == total
    )
    if user_supplied_gaps:
        out.append(
            {
                "severity": "info",
                "code": "HBOM_USER_SUPPLIED_NOT_ENTERED",
                "message": (
                    f"{user_supplied_gaps} element(s) no parts list can supply are "
                    f"empty across every component"
                ),
                "hint": (
                    "warranty, licence terms, test result and criticality are "
                    "judgements about your hardware; the manual entry form collects "
                    "them, and until it is used they are honestly not-provided"
                ),
            }
        )

    deepest = max((root.depth() for root in roots), default=0)
    if deepest == 0 and total > 1:
        out.append(
            {
                "severity": "info",
                "code": "HBOM_FLAT_TREE",
                "message": f"all {total} components are at the top level",
                "hint": (
                    "the `level` column builds the sub-component tree; a flat "
                    "import usually means it was not mapped"
                ),
            }
        )

    return out


def source_label() -> str:
    """How this BOM's provenance is described in a report.

    ⚠ "IMPORT", NEVER "SCAN". There is no open-source tool that discovers
    physical parts. A report that says a hardware BOM was scanned is claiming a
    capability the product does not have, on the document a customer hands to an
    auditor.
    """
    return "imported (structured entry — hardware is not discoverable by scan)"
