"""CSV import — a parts list becomes a recursive tree.

⚠ THE `level` COLUMN DRIVES THE TREE, AND ITS SEQUENCE IS VALIDATED.

A row at level 3 following a row at level 1 has no parent: the level-2 assembly
it belongs to does not exist. Accepting it means silently reparenting the part
onto the level-1 product, which produces a plausible-looking BOM that says
something false about how the hardware is built — and nothing downstream can
detect it, because the output is structurally valid.

So the jump is rejected, and the error names THE ROW AND BOTH LEVELS. A customer
staring at a 400-line export needs to know it was line 217 that broke, not that
"the file is invalid".

⚠ THE COLUMN MAPPING EXISTS SO NOBODY EDITS THEIR FILE.

Every parts list in the world has different headers. Requiring a customer to
rename columns before importing means they edit an export, make a mistake, and
import something that no longer matches their source of truth. The mapping step
takes their headers as they are.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from .model import (
    ASSEMBLY_TYPES,
    LIFECYCLE_VALUES,
    MAX_DEPTH,
    HardwareComponent,
    normalize,
)

#: Canonical column names the importer understands.
#:
#: The values are the attribute each maps to. A customer's own headers reach
#: these through `ColumnMapping`, so this list is the vocabulary rather than a
#: requirement on their file.
CANONICAL_COLUMNS: dict[str, str] = {
    "level": "level",
    "part_number": "model_number",
    "description": "product_details",
    "quantity": "quantity",
    "manufacturer": "manufacturer_name",
    "mpn": "model_number",
    "supplier": "component_supplier_info",
    # --- manufacturing and procurement -------------------------------------
    #
    # ⚠ NOT CERT-In ELEMENTS, AND THEY ARE STORED RATHER THAN IGNORED NOW.
    # `unit_cost` used to map to "" — accepted and thrown away — because there
    # was no column to put it in. Migration 0011 added the columns; these are
    # scored against docs/reference/hbom-manufacturing-v1.yaml, never against
    # CERT-In. See the manufacturing block on HardwareComponent.
    "unit_cost": "unit_price",
    "currency": "currency",
    "designator": "designators",
    "footprint": "package_footprint",
    "supplier_sku": "supplier_sku",
    "preferred_supplier": "preferred_supplier",
    "dni": "do_not_populate",
    "assembly_type": "assembly_type",
    "lifecycle": "lifecycle_status",
    "datasheet": "datasheet_url",
    "name": "product_name",
    "version": "product_version",
    "serial_number": "serial_number",
    "manufacturer_location": "manufacturer_location",
    "supplier_location": "component_supplier_location",
    "product_supplier": "supplier_info",
    "product_supplier_location": "supplier_location",
    "firmware_version": "firmware_version",
    "origin": "origin",
    "criticality": "criticality",
    "technology_node": "technology_node",
    "compliance": "compliance",
    "power_supply": "power_supply",
    "license": "license_info",
    "test_result": "test_result",
    "technical_specification": "technical_specification",
    "manufacturing_date": "manufacturing_date",
    "warranty": "warranty_amc",
}

#: Headers seen in the wild that mean one of the above.
#:
#: ⚠ A CONVENIENCE FOR THE MAPPING UI, NEVER AN AUTOMATIC REWRITE. The importer
#: suggests these; a human confirms. Silently deciding that a column called
#: "Supplier" is the component supplier rather than the product supplier would
#: put data in the wrong one of the two relationships Table 11 distinguishes,
#: which is precisely the mistake this product exists to avoid.
HEADER_SUGGESTIONS: dict[str, str] = {
    "lvl": "level",
    "bom level": "level",
    "indent": "level",
    "item": "part_number",
    "part": "part_number",
    "part no": "part_number",
    "part number": "part_number",
    "partnumber": "part_number",
    "desc": "description",
    "qty": "quantity",
    "quantity per": "quantity",
    "mfr": "manufacturer",
    "mfg": "manufacturer",
    "manufacturer part number": "mpn",
    "mfr part number": "mpn",
    "vendor": "supplier",
    "cost": "unit_cost",
    "unit price": "unit_cost",
    # --- manufacturing and procurement -------------------------------------
    "ref": "designator",
    "refs": "designator",
    "refdes": "designator",
    "reference": "designator",
    "references": "designator",
    "designator": "designator",
    "designators": "designator",
    "package": "footprint",
    "footprint": "footprint",
    "dnp": "dni",
    "dni": "dni",
    "do not populate": "dni",
    "do not install": "dni",
    "nofit": "dni",
    "mounting": "assembly_type",
    "mount type": "assembly_type",
    "mounting technology": "assembly_type",
    "lifecycle": "lifecycle",
    "lifecycle status": "lifecycle",
    "part status": "lifecycle",
    "product status": "lifecycle",
    "supplier part number": "supplier_sku",
    "supplier sku": "supplier_sku",
    "sku": "supplier_sku",
    "distributor part number": "supplier_sku",
    "preferred supplier": "preferred_supplier",
    "distributor": "preferred_supplier",
    "datasheet": "datasheet",
    "datasheet url": "datasheet",
    "currency": "currency",
}


class HBOMImportError(Exception):
    """A CSV that cannot be turned into a tree.

    Deliberately NOT named `ImportError`: that is a builtin meaning a module
    could not be loaded, and a reader of a traceback would take it for an
    interpreter failure rather than a problem with the customer's file.
    """


@dataclass
class ColumnMapping:
    """Maps a customer's headers onto canonical column names."""

    #: their header (as written) -> canonical column name
    columns: dict[str, str] = field(default_factory=dict)

    @classmethod
    def suggest(cls, headers: list[str]) -> ColumnMapping:
        """Propose a mapping from a file's headers.

        ⚠ A PROPOSAL. The caller shows it to a human and gets confirmation.
        """
        mapping: dict[str, str] = {}
        for header in headers:
            key = header.strip().lower().replace("_", " ")
            if key.replace(" ", "_") in CANONICAL_COLUMNS:
                mapping[header] = key.replace(" ", "_")
            elif key in HEADER_SUGGESTIONS:
                mapping[header] = HEADER_SUGGESTIONS[key]
        return cls(columns=mapping)

    def canonical(self, header: str) -> str | None:
        return self.columns.get(header)


@dataclass
class ImportResult:
    """What an import produced, and what it could not."""

    #: Root components. Usually one; a file may describe several products.
    roots: list[HardwareComponent] = field(default_factory=list)

    #: Rows that were read but carried nothing beyond a level.
    empty_rows: list[int] = field(default_factory=list)

    #: Headers present in the file that no canonical column claimed.
    #:
    #: ⚠ REPORTED, NOT SWALLOWED. A customer whose "Criticality" column was
    #: spelled "Crit." and therefore ignored would otherwise get a BOM missing a
    #: §10.4.1.4 element with nothing saying so.
    unmapped_headers: list[str] = field(default_factory=list)

    #: Diagnostics that did not stop the import.
    warnings: list[str] = field(default_factory=list)

    def total(self) -> int:
        return sum(root.count() for root in self.roots)


def parse(
    data: str | bytes,
    mapping: ColumnMapping | None = None,
    *,
    max_rows: int = 50_000,
) -> ImportResult:
    """Parse a CSV parts list into a component tree.

    `mapping` is optional; absent, the file's own headers are matched against
    the canonical vocabulary. That path exists for our own fixtures and for a
    file already in our shape — a customer's export goes through a confirmed
    mapping.
    """
    text = data.decode("utf-8-sig") if isinstance(data, bytes) else data.lstrip("﻿")

    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        raise HBOMImportError("the file has no header row")

    if mapping is None:
        mapping = ColumnMapping.suggest(list(reader.fieldnames))

    if "level" not in mapping.columns.values():
        raise HBOMImportError(
            "no column is mapped to `level`. The level column is what builds the "
            "sub-component tree; without it every part would be a sibling of the "
            "product rather than a part of it."
        )

    result = parse_rows(
        (_canonicalize(raw, mapping) for raw in reader),
        max_rows=max_rows,
    )
    result.unmapped_headers = [h for h in reader.fieldnames if h and mapping.canonical(h) is None]
    return result


def parse_rows(
    rows: Iterable[Mapping[str, str]],
    *,
    max_rows: int = 50_000,
) -> ImportResult:
    """Build the component tree from rows already in canonical column names.

    ⚠ EXTRACTED SO THE LEVEL-SEQUENCE RULE HAS EXACTLY ONE IMPLEMENTATION.

    That rule — a level-3 row after a level-1 row is REJECTED, naming the row
    and both levels — carries more safety comment than anything else in this
    file, because quietly reparenting a part produces a structurally valid BOM
    that says something false about how the hardware is assembled, and nothing
    downstream can detect it.

    `parse()` above is now this function plus a CSV reader and a column
    mapping. The ECAD adapters (KiCad schematics and netlists, Altium/OrCAD
    exports) build canonical rows their own way and then come here — because
    an adapter that built its own tree would be a second copy of that rule,
    and the second copy is the one that gets it wrong.

    Rows are consumed lazily, so a caller may pass a generator over a file it
    is still reading.
    """
    result = ImportResult()

    #: The current ancestor at each level. `stack[n]` is the open component at
    #: level n, so a row at level n+1 attaches to it.
    stack: list[HardwareComponent] = []
    result_roots: list[HardwareComponent] = []
    previous_level: int | None = None
    row_number = 1  # the header

    for values in rows:
        row_number += 1
        if row_number - 1 > max_rows:
            raise HBOMImportError(
                f"the file exceeds {max_rows:,} rows. A parts list that long is "
                f"almost certainly an export mistake; split it or raise the cap "
                f"deliberately."
            )

        level_text = str(values.get("level", "")).strip()

        if not level_text and not any(str(v).strip() for v in values.values()):
            result.empty_rows.append(row_number)
            continue

        level = _parse_level(level_text, row_number)

        # ⚠ THE SEQUENCE CHECK. See the module docstring: a level-3 row after a
        # level-1 row has no parent, and quietly reparenting it produces a
        # structurally valid BOM that is factually wrong.
        if previous_level is not None and level > previous_level + 1:
            raise HBOMImportError(
                f"row {row_number}: level {level} follows level {previous_level}. "
                f"A sub-component cannot skip a level — the level-{previous_level + 1} "
                f"assembly it belongs to is not in the file. Check for a missing row "
                f"or an off-by-one in the export."
            )

        if level > MAX_DEPTH:
            result.warnings.append(
                f"row {row_number}: level {level} exceeds the depth cap of "
                f"{MAX_DEPTH}; this component and anything below it were not "
                f"imported. The gap is recorded rather than the tree truncated "
                f"silently."
            )
            previous_level = level
            continue

        component = _build(values, level, row_number)

        if level == 0 or not stack:
            result_roots.append(component)
            stack = [component]
        else:
            parent = stack[level - 1]
            component.parent_local_id = parent.local_id
            parent.children.append(component)
            del stack[level:]
            stack.append(component)

        previous_level = level

    result.roots = [normalize(root) for root in result_roots]

    _warn_on_duplicate_parts(result)
    return result


def _canonicalize(
    raw: Mapping[str | None, str | list[str] | None], mapping: ColumnMapping
) -> dict[str, str]:
    """Rewrite one row's keys to canonical column names.

    ⚠ THE KEY AND THE VALUE ARE BOTH OPTIONAL, AND THAT IS csv.DictReader, NOT
    DEFENSIVENESS.

    A row with MORE fields than the header puts the surplus under a `None` key,
    as a list:  `{'a': '1', 'b': '2', None: ['3', '4']}`.
    A row with FEWER fields gets `None` values:  `{'a': '1', 'b': None}`.

    Both happen in real exports — a stray trailing comma produces the first, a
    truncated last line the second. The signature says so, because a
    `dict[str, str]` annotation here is simply false about what DictReader
    yields, and a false annotation is what makes a type checker call a live
    branch unreachable.

    ⚠ THE THREE None-HANDLING BRANCHES BELOW ARE BELT-AND-BRACES, NOT THE THING
    THAT PREVENTS A CRASH — and saying so is the point of this paragraph.
    Deleting any one of them today breaks nothing: a `None` key is filtered
    because `mapping.canonical(None)` finds no mapping, and a `None` value is
    flattened downstream by `_build`'s `str(value or "")`. Both of those are
    incidental. If a future change makes the mapping tolerant of unknown keys,
    or `_build` stops coalescing, the guards here are what stops a customer's
    truncated export becoming an AttributeError with a traceback that says
    nothing about their file.
    """
    out: dict[str, str] = {}
    for header, value in raw.items():
        if header is None:
            continue
        canonical = mapping.canonical(header)
        if canonical is None or canonical == "":
            continue
        # First mapped column wins: two headers mapped to `mpn` means the
        # customer confirmed a mapping we should not second-guess by
        # overwriting with whichever happens to come later in the file.
        if isinstance(value, list):
            # The surplus-fields bucket. Joined rather than dropped: it is
            # somebody's data, and losing it silently is worse than showing
            # it in the wrong column, which they can at least see.
            out.setdefault(canonical, ", ".join(v for v in value if v))
            continue
        out.setdefault(canonical, value if value is not None else "")
    return out


def _parse_level(text: str, row_number: int) -> int:
    """Read a level, accepting both `2` and the outline form `1.2.1`."""
    if not text:
        raise HBOMImportError(f"row {row_number}: no level. Every row needs one.")

    # An outline number's DEPTH is its level: `1.2.1` is level 2 (zero-based),
    # which is how most CAD and ERP exports write a nested BOM.
    if "." in text:
        parts = [p for p in text.split(".") if p.strip()]
        if not all(p.strip().isdigit() for p in parts):
            raise HBOMImportError(
                f"row {row_number}: level {text!r} is neither a number nor an "
                f"outline number such as 1.2.1."
            )
        return len(parts) - 1

    try:
        level = int(text)
    except ValueError:
        raise HBOMImportError(f"row {row_number}: level {text!r} is not a number.") from None

    if level < 0:
        raise HBOMImportError(f"row {row_number}: level {level} is negative.")
    return level


def _build(values: dict[str, str], level: int, row_number: int) -> HardwareComponent:
    """Turn one canonical row into a component."""
    component = HardwareComponent(
        local_id=f"row-{row_number}",
        level=level,
        source_row=row_number,
    )

    for canonical, attribute in CANONICAL_COLUMNS.items():
        if not attribute or attribute in ("level", "quantity"):
            continue
        value = str(values.get(canonical, "") or "").strip()
        if not value:
            continue
        if attribute == "compliance":
            # RoHS, CE and friends arrive as one cell.
            component.compliance = [
                part.strip() for part in value.replace(";", ",").split(",") if part.strip()
            ]
        elif attribute == "designators":
            # ⚠ ONE CELL, MANY PLACEMENTS. "R1, R4, R17" is one line item with
            # quantity 3, which is how every CAD and ERP export writes it.
            # Splitting on both separators because both are common and neither
            # is ambiguous here — a reference designator contains no comma.
            component.designators = [
                part.strip() for part in value.replace(";", ",").split(",") if part.strip()
            ]
        elif attribute == "do_not_populate":
            component.do_not_populate = _parse_dnp(value)
        elif attribute == "assembly_type":
            component.assembly_type = _parse_enum(value, ASSEMBLY_TYPES, _ASSEMBLY_ALIASES)
        elif attribute == "lifecycle_status":
            component.lifecycle_status = _parse_enum(value, LIFECYCLE_VALUES, _LIFECYCLE_ALIASES)
        elif attribute == "unit_price":
            component.unit_price = _parse_price(value)
        else:
            # setdefault semantics: `part_number` and `mpn` both map to
            # model_number, and whichever the file supplies first wins rather
            # than an empty second column clearing a populated first.
            if not getattr(component, attribute, ""):
                setattr(component, attribute, value)

    quantity_text = str(values.get("quantity", "") or "").strip()
    if quantity_text:
        try:
            component.quantity = max(1, int(float(quantity_text)))
        except ValueError:
            # A quantity that will not parse is left at 1 and reported, rather
            # than failing the import: it is the least load-bearing field here,
            # and a whole parts list should not be rejected over one cell.
            component.quantity = 1

    # ⚠ A COMPONENT NEEDS A NAME, AND THE PART NUMBER IS THE FALLBACK. A row
    # with a part number and no description is entirely normal in a real parts
    # list; rendering it as an unnamed component makes a report unreadable.
    if not component.product_name:
        component.product_name = (
            component.model_number
            or component.product_details
            or f"unnamed component (row {row_number})"
        )

    return component


def _warn_on_duplicate_parts(result: ImportResult) -> None:
    """Note repeated part numbers.

    ⚠ A WARNING, NOT AN ERROR. The same capacitor legitimately appears in four
    sub-assemblies, and rejecting that would reject most real hardware. But a
    part number repeated at the SAME level under the SAME parent is usually two
    rows that should have been one with a quantity, and that is worth saying.
    """
    for root in result.roots:
        _check_siblings(root, result)


def _check_siblings(component: HardwareComponent, result: ImportResult) -> None:
    seen: dict[str, int] = {}
    for child in component.children:
        key = child.model_number.strip().lower()
        if not key:
            continue
        if key in seen:
            result.warnings.append(
                f"part {child.model_number!r} appears twice under "
                f"{component.product_name!r} (rows {seen[key]} and {child.source_row}). "
                f"If these are the same part, one row with a quantity is more "
                f"accurate than two."
            )
        else:
            seen[key] = child.source_row or 0
        _check_siblings(child, result)


# ---------------------------------------------------------------------------
# Manufacturing value parsing
# ---------------------------------------------------------------------------
#
# ⚠ EVERY ONE OF THESE DROPS WHAT IT CANNOT RECOGNISE, AND NONE OF THEM
# GUESSES. That is the same rule `normalize()` applies to `criticality`, for
# the same reason: mapping an unrecognised value onto a plausible neighbour
# invents a fact about somebody's hardware, in a document they hand to an
# auditor or a contract manufacturer.

#: Spellings of "smt"/"tht" seen in real exports. Data, not inference — each
#: entry is a name the industry actually uses for that exact process.
_ASSEMBLY_ALIASES: dict[str, str] = {
    "smd": "smt",
    "surface mount": "smt",
    "surface-mount": "smt",
    "through hole": "tht",
    "through-hole": "tht",
    "thru-hole": "tht",
    "pth": "tht",
    "mech": "mechanical",
    "hardware": "mechanical",
}

#: Likewise for lifecycle. `nrnd` has the most spellings because it is the
#: status distributors word most freely.
_LIFECYCLE_ALIASES: dict[str, str] = {
    "not recommended for new designs": "nrnd",
    "not recommended": "nrnd",
    "nrfnd": "nrnd",
    "end of life": "eol",
    "end-of-life": "eol",
    "discontinued": "obsolete",
    "inactive": "obsolete",
    "in production": "active",
    "production": "active",
    "new": "preview",
    "pre-production": "preview",
}

#: Every spelling of "do not fit" seen in real exports.
#:
#: ⚠ THE COLUMN HAS NO THIRD STATE, SO AN UNRECOGNISED VALUE MEANS "fitted" —
#: AND THAT IS THE SAFE DIRECTION, WHICH IS WHY IT IS ACCEPTABLE.
#:
#: The two errors are not symmetric. Treating a marked DNP as fitted puts one
#: unwanted part on a board. Treating an unrecognised value as DNP OMITS a part
#: the design needs, which is a board that does not work and a respin. So this
#: is the affirmative spellings only, and anything else is fitted.
#:
#: (An earlier version carried an explicit falsy set as well, with a comment
#: claiming an unrecognised value must not silently become False. Both branches
#: returned False, so the comment described behaviour the code did not have —
#: and the Go port's linter is what noticed.)
_TRUTHY = frozenset({"1", "y", "yes", "true", "dnp", "dni", "x", "nofit", "do not populate"})


def _parse_dnp(value: str) -> bool:
    """Read a do-not-populate cell."""
    return value.strip().lower() in _TRUTHY


def _parse_enum(value: str, allowed: tuple[str, ...], aliases: dict[str, str]) -> str:
    """Map a cell onto a closed set, or drop it.

    Returns "" for anything unrecognised. A dropped value scores as absent,
    which is honest; a coerced one would score as knowledge we do not have.
    """
    text = value.strip().lower()
    text = aliases.get(text, text)
    return text if text in allowed else ""


def _parse_price(value: str) -> str:
    """Read a unit price, keeping it a string all the way to the writer.

    ⚠ NOT A float. Postgres casts the bound parameter into `numeric(18,6)`;
    routing it through a Python float first would lose cents on values like
    0.1, and an extended price over a 4000-line BOM accumulates that error into
    a figure somebody procures against.

    Currency symbols and thousands separators are stripped because exports
    carry them; a value that still will not parse is DROPPED rather than
    guessed at, since a wrong price is worse than an absent one.
    """
    text = value.strip().replace(",", "").lstrip("$£€₹").strip()
    if not text:
        return ""
    try:
        if float(text) < 0:
            return ""
    except ValueError:
        return ""
    return text
