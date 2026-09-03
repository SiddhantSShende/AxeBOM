"""Canonical hardware components and their coverage.

⚠ EVERY NODE IN THE TREE IS SCORED, NOT JUST THE ROOT.

A four-level assembly whose root is fully populated and whose 200 leaf parts
have a part number and nothing else is not a well-documented BOM, and a coverage
number computed over the root alone would say it was. Flattening the tree first
means the number describes the hardware rather than its top row.

⚠ THE FIELD COUNT IS NEVER WRITTEN. It comes from `len(HBOM_FIELDS)`, so a
CERT-In revision is a data change and not a code change — and so this module
cannot ship a false claim about how many elements it covers (invariant 2).

⚠ TWO SCORES, AND ONLY ONE OF THEM IS COMPLIANCE.

`coverage` is CERT-In's: the 24 elements of Table 11 plus §10.4.1.4, and the
two numbers (`completeness_pct`, `declaration_pct`) a customer hands to a
regulator. `manufacturing` is AxeBOM's own — designators, quantities, supplier
SKUs, alternates, prices, lifecycle — read from
`docs/reference/hbom-manufacturing-v1.yaml` and reported under its own label.

Nothing in the manufacturing set may move the CERT-In numbers. That is not a
convention here; the two field lists come from two files, they share no field
id, and `libs/go-shared/compliance`'s lint refuses a profile that mixes them.
Both are computed from the SAME flat row, by the SAME `score()`, so the
`not-provided` rule has one implementation rather than two that could drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from axebom_shared.model.generated_certin import HBOM_FIELDS
from axebom_shared.normalize.coverage import CoverageResult, Field, score

from .model import NOT_PROVIDED, USER_SUPPLIED_FIELDS, Alternate, HardwareComponent, to_profile_row
from .profile import manufacturing_fields, manufacturing_meta

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

    #: CERT-In coverage. THE compliance signal — Table 11 + §10.4.1.4, nothing
    #: else. Never influenced by the manufacturing fields below.
    coverage: CoverageResult | None = None

    #: Manufacturing and procurement readiness. AxeBOM's own number, scored
    #: against a separate profile and reported under a separate label. Present
    #: alongside `coverage`, never summed into it or substituted for it.
    manufacturing: CoverageResult | None = None

    #: Flat rows, one per node, keyed by canonical path. What gets written.
    rows: list[dict[str, Any]] = field(default_factory=list)

    diagnostics: list[dict[str, Any]] = field(default_factory=list)

    def component_count(self) -> int:
        return sum(root.count() for root in self.roots)

    def max_depth(self) -> int:
        return max((root.depth() for root in self.roots), default=0)


def flatten(roots: list[HardwareComponent]) -> list[dict[str, Any]]:
    """Every node in every tree, as a row keyed by canonical path.

    ⚠ ONE ROW, SCORED TWICE. The CERT-In elements and the manufacturing set are
    both emitted here, keyed by canonical path, so `normalize_bom` can run
    `score()` over the same dict with two different field lists. Building two
    row shapes would mean two places that decide what `not-provided` means.

    Where both profiles name the SAME path — the manufacturing "Description"
    deliberately reuses CERT-In element 3's `product_details` column — the value
    is written once and scored under both field ids. That is correct: a second
    description column would split one fact in two and halve element 3.
    """
    certin_paths = {f.id: f.canonical_path for f in HBOM_FIELDS}
    mfg_fields = manufacturing_fields()
    mfg_paths = {f.id: f.canonical_path for f in mfg_fields}
    rows: list[dict[str, Any]] = []

    for root in roots:
        for depth, node in root.walk():
            row = {
                certin_paths[field_id]: value for field_id, value in to_profile_row(node).items()
            }
            for field_id, value in to_profile_row(node, mfg_fields).items():
                row.setdefault(mfg_paths[field_id], value)

            # ⚠ ALTERNATES ARE A LIST OF OBJECTS, NOT A SCALAR, so the scored
            # value is the list itself — `coverage.is_substantive` treats a
            # non-empty list as present and an empty one as absent, which is
            # exactly the question "does this part have a second source?".
            row["hardware_component.alternates"] = (
                [_alternate_row(a) for a in node.alternates] if node.alternates else NOT_PROVIDED
            )

            # Structural facts, outside both profiles: they are how a report
            # renders the tree and how a writer wires parent_id.
            row["_local_id"] = node.local_id
            row["_parent_local_id"] = node.parent_local_id
            row["_depth"] = depth
            row["_enriched_fields"] = dict(node.enriched_fields)
            row["_source_engine"] = node.source_engine
            rows.append(row)

    return rows


def _alternate_row(alternate: Alternate) -> dict[str, Any]:
    """One approved second source, as the writer stores it."""
    return {
        "ordinal": alternate.ordinal,
        "manufacturer_name": alternate.manufacturer_name,
        "model_number": alternate.model_number,
        "supplier_info": alternate.supplier_info,
        "supplier_sku": alternate.supplier_sku,
        "lifecycle_status": alternate.lifecycle_status,
        "equivalence": alternate.equivalence,
        "approval_note": alternate.approval_note,
    }


def normalize_bom(roots: list[HardwareComponent]) -> HBOMResult:
    """Score a hardware BOM and produce the rows to store."""
    rows = flatten(roots)

    # ⚠ TWO CALLS, TWO FIELD LISTS, ONE ROW SET AND ONE score(). The CERT-In
    # number and the manufacturing number are computed the same way from the
    # same data and stay completely independent of each other's field set.
    coverage = score(rows, _SCORED)
    manufacturing = score(rows, manufacturing_fields())

    result = HBOMResult(roots=roots, coverage=coverage, manufacturing=manufacturing, rows=rows)
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


# ---------------------------------------------------------------------------
# The canonical document
# ---------------------------------------------------------------------------

#: Bumped when a change to this module would produce different output from the
#: same stored artifacts. HBOM's own counter, same arrangement CBOM and AIBOM
#: use — the families do not normalize in step and a shared version would force
#: re-normalizations nothing changed for.
RULESET_VERSION = "2026.09.1"


def build_canonical_hbom(
    roots: list[HardwareComponent],
    *,
    project_id: str | None = None,
    ruleset_version: str = RULESET_VERSION,
) -> dict[str, Any]:
    """Turn parsed hardware trees into a document `writer.write_bom_document`
    can store.

    ⚠ NO MERGE, NO GRAPH, NO ALIAS CLOSURE — see `workers/hbom/ingest.py` for
    why four of the SBOM pipeline's seven stages are not merely unnecessary
    here but actively wrong.

    ⚠ AND NO FABRICATED alias_snapshot_id. CBOM and AIBOM used to mint a
    throwaway uuid to satisfy a NOT NULL column; migration 0012 made it
    nullable with a real foreign key, so this passes None and means it.

    ⚠ A PURE FUNCTION. No clock, no randomness, no network — the same input at
    the same ruleset version produces byte-identical output, which is what
    makes a normalizer bug a re-normalization pass rather than a re-scan
    (invariant 10).
    """
    result = normalize_bom(roots)
    coverage, manufacturing = result.coverage, result.manufacturing
    if coverage is None or manufacturing is None:  # pragma: no cover
        # normalize_bom always sets both; this narrows the Optionals without an
        # `assert`, which `python -O` strips and which would then turn a
        # would-be error into an AttributeError three frames away.
        raise RuntimeError("normalize_bom did not produce both coverage numbers")

    meta = manufacturing_meta()
    return {
        "hardware_components": result.rows,
        # THE compliance signal — CERT-In Table 11 + §10.4.1.4, nothing else.
        "coverage": coverage.as_dict(),
        # ⚠ A DIFFERENT NUMBER, UNDER A DIFFERENT KEY, CARRYING ITS OWN LABEL
        # AND AN is_compliance FLAG. Keyed by profile id so a second
        # operational profile needs no schema change, and flagged so no
        # consumer has to know which profile ids are standards.
        "supplementary_coverage": {
            meta["profile_id"]: {**meta, **manufacturing.as_dict()},
        },
        "ruleset_version": ruleset_version,
        # HBOM carries no SPDX licence concept — no hardware field is an SPDX
        # expression. Empty string, not None: the column is `text NOT NULL`,
        # the same convention build_canonical_cbom uses.
        "spdx_license_list_version": "",
        "unidentified_count": coverage.unidentified_count,
        # HBOM's second lineage key. An imported document and a scanned one
        # describe the same project's hardware; project_id is what
        # resolveHBOMDocument reads, because normalization_version counts
        # within a lineage and cannot rank across two.
        "project_id": project_id,
        "provenance": {"alias_snapshot_id": None},
        "diagnostics": result.diagnostics,
    }
