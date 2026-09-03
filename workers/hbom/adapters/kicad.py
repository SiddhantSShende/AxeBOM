"""KiCad design files — schematics and netlists — read as parts lists.

⚠ THIS PARSES DESIGN FILES THE CUSTOMER WROTE. IT DOES NOT LOOK AT HARDWARE.

A `.kicad_sch` is a schematic; a KiCad netlist is what `kicad-cli sch export
netlist` produces from one. Both are documents describing an intended design,
in exactly the sense `package-lock.json` describes an intended dependency set.
Reading them is not discovery of a physical device, and nothing here claims it
is. See CLAUDE.md's honest-labels section.

⚠ WHY NOT KiBoM. `SchrodingersGat/KiBoM` is MIT and does most of this, but
upstream ARCHIVED it in March 2025 — pinning it would mean an artifact that can
never receive a fix, in a supply chain whose whole discipline is pinned,
verifiable, maintained releases (ADR-0002). Its grouping rule is about thirty
lines, reimplemented below, and its file formats are stable and documented.

⚠ AND WHY NOT `kicad-cli`. It would be authoritative, but it is GPL-3.0 (fine
in a subprocess, per invariant 9) inside a ~1.5 GB image, to read two text
formats we can read directly. The trade is not worth it.

GROUPING IS THE PART WORTH GETTING RIGHT
----------------------------------------
A schematic has one symbol per placement: R1, R4 and R17 are three symbols of
the same 10k resistor. A parts list has one LINE per part, with a quantity and
the designators that line covers — because that is what gets ordered and what
gets placed. Emitting three components would inflate the component count in a
compliance document and make the BOM useless for procurement.

Parts group on (MPN) when an MPN is present, and on (value, footprint) when it
is not. ⚠ NEVER on value alone: a 10k 0402 and a 10k 0805 are different parts
that cannot substitute for each other, and merging them would produce a line
item nobody can actually buy.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

#: How deep an S-expression may nest before the reader gives up.
#:
#: ⚠ A HARD CAP, NOT RECURSION. A hand-written recursive-descent reader over
#: untrusted input is a stack overflow waiting for a file with 100,000 open
#: parens. This reader is iterative and refuses past this depth, which a real
#: schematic never approaches — KiCad's own nesting is under twenty.
MAX_SEXP_DEPTH = 64

#: Ceiling on tokens read from one schematic, so a pathological file cannot
#: spend unbounded time even within the size cap discovery already applied.
MAX_SEXP_TOKENS = 5_000_000

#: KiCad property names that carry a manufacturer part number, lower-cased.
#: Data rather than inference: each is a name KiCad users and the KiCad
#: templates actually use for this field.
_MPN_KEYS = frozenset({"mpn", "manufacturer part number", "mfr. no", "mfr no", "part number", "pn"})
_MANUFACTURER_KEYS = frozenset({"manufacturer", "mfr", "mfg", "mfr."})
_SKU_KEYS = frozenset(
    {"sku", "supplier part number", "distributor part number", "digikey", "mouser"}
)
_SUPPLIER_KEYS = frozenset({"supplier", "distributor", "vendor"})
_DNP_KEYS = frozenset({"dnp", "dni", "do not populate", "do not install", "nofit"})


@dataclass
class Part:
    """One placement, before grouping."""

    reference: str = ""
    value: str = ""
    footprint: str = ""
    mpn: str = ""
    manufacturer: str = ""
    supplier: str = ""
    supplier_sku: str = ""
    datasheet: str = ""
    do_not_populate: bool = False
    #: Everything else the file carried, so nothing is silently dropped.
    extra: dict[str, str] = field(default_factory=dict)

    def group_key(self) -> tuple[str, str, str]:
        """What makes two placements the same LINE ITEM.

        MPN when there is one — it is the thing actually ordered. Otherwise
        value AND footprint together, never value alone.
        """
        if self.mpn:
            return ("mpn", self.mpn.strip().lower(), "")
        return ("value+footprint", self.value.strip().lower(), self.footprint.strip().lower())


# ---------------------------------------------------------------------------
# Netlist XML
# ---------------------------------------------------------------------------


def parse_netlist(data: bytes) -> tuple[list[Part], list[dict[str, Any]]]:
    """Read a KiCad netlist XML into placements.

    Never raises: a malformed document returns no parts and a diagnostic,
    matching the contract every parser in this codebase honours.
    """
    diagnostics: list[dict[str, Any]] = []

    # ⚠ THE ENTITY GUARD LIVES HERE, NOT ONLY IN THE CALLER.
    #
    # discovery._looks_like already refuses a DOCTYPE or ENTITY declaration, so
    # this is the second check — deliberately. A security property that holds
    # only because some other function was called first is the "remember to
    # sanitize" pattern, and this function is public: a future caller that
    # hands it bytes from somewhere else must not silently lose the guarantee.
    #
    # Refusing the SHAPE is a complete mitigation for this input class rather
    # than a partial one. Billion-laughs needs `<!ENTITY`; XXE needs a
    # `<!DOCTYPE` to declare an external entity in. Without either, the
    # documented ElementTree weaknesses have no vector — which is why this does
    # not pull in `defusedxml` for one call site. A KiCad netlist contains
    # neither construct, so nothing legitimate is refused.
    if _declares_entities(data):
        return [], [
            {
                "severity": "warn",
                "code": "HBOM_NETLIST_REFUSED",
                "message": "a netlist declaring XML entities was refused unparsed",
                "hint": "a KiCad netlist contains no DOCTYPE or ENTITY declaration; "
                "these are the constructs entity-expansion and external-entity "
                "attacks need, so the document is refused rather than parsed",
            }
        ]

    try:
        root = ET.fromstring(data)  # noqa: S314 — entity declarations refused directly above
    except ET.ParseError as exc:
        return [], [
            {
                "severity": "warn",
                "code": "HBOM_NETLIST_UNPARSEABLE",
                "message": f"a KiCad netlist could not be parsed: {exc}",
            }
        ]

    parts: list[Part] = []
    for comp in root.iterfind("./components/comp"):
        part = Part(reference=(comp.get("ref") or "").strip())
        part.value = _text(comp.find("value"))
        part.footprint = _shorten_footprint(_text(comp.find("footprint")))
        part.datasheet = _text(comp.find("datasheet"))

        for f in comp.iterfind("./fields/field"):
            name = (f.get("name") or "").strip().lower()
            value = (f.text or "").strip()
            if not name or not value:
                continue
            _assign_field(part, name, value)

        # KiCad 7+ marks unfitted symbols with a <property name="dnp"/>.
        for prop in comp.iterfind("./property"):
            if (prop.get("name") or "").strip().lower() in _DNP_KEYS:
                part.do_not_populate = True

        if part.reference or part.value or part.mpn:
            parts.append(part)

    if not parts:
        diagnostics.append(
            {
                "severity": "warn",
                "code": "HBOM_NETLIST_EMPTY",
                "message": "a KiCad netlist was read but declared no components",
            }
        )
    return parts, diagnostics


# ---------------------------------------------------------------------------
# Schematic S-expressions
# ---------------------------------------------------------------------------


def parse_schematic(data: bytes) -> tuple[list[Part], list[dict[str, Any]]]:
    """Read a `.kicad_sch` into placements.

    ⚠ ONE FILE, ONE SHEET. A hierarchical design spreads across several
    `.kicad_sch` files; the caller passes each and the results concatenate. A
    sub-sheet's symbols are real placements on the board, so that is correct —
    but it does mean this parser produces a FLAT list, and the assembly
    hierarchy a hierarchical schematic implies is not recovered. That gap is
    reported by the adapter rather than papered over with an invented tree.
    """
    diagnostics: list[dict[str, Any]] = []
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception as exc:  # pragma: no cover — decode with errors= cannot raise
        return [], [{"severity": "warn", "code": "HBOM_SCHEMATIC_UNPARSEABLE", "message": str(exc)}]

    try:
        tree = _read_sexp(text)
    except _SexpError as exc:
        return [], [
            {
                "severity": "warn",
                "code": "HBOM_SCHEMATIC_UNPARSEABLE",
                "message": f"a KiCad schematic could not be parsed: {exc}",
            }
        ]

    parts: list[Part] = []
    for symbol in _find_all(tree, "symbol"):
        properties: dict[str, str] = {}
        dnp = False
        for node in symbol:
            if not isinstance(node, list) or not node:
                continue
            head = node[0]
            if head == "property" and len(node) >= 3:
                name = str(node[1]).strip()
                if name:
                    properties[name.lower()] = str(node[2]).strip()
            elif head == "dnp" and len(node) >= 2:
                dnp = str(node[1]).strip().lower() in ("yes", "true")
            elif head == "in_bom" and len(node) >= 2:
                if str(node[1]).strip().lower() in ("no", "false"):
                    properties["__excluded__"] = "1"

        if properties.pop("__excluded__", ""):
            # ⚠ EXCLUDED FROM THE BOM BY THE DESIGNER, which is a decision, not
            # an omission — power flags and mounting-hole graphics carry it.
            continue

        reference = properties.get("reference", "")
        # KiCad writes unannotated symbols as "R?" — a placeholder, not a
        # designator. Keeping it would put "R?" in a procurement document.
        if reference.endswith("?"):
            reference = ""

        part = Part(
            reference=reference,
            value=properties.get("value", ""),
            footprint=_shorten_footprint(properties.get("footprint", "")),
            datasheet=properties.get("datasheet", ""),
            do_not_populate=dnp,
        )
        if part.datasheet == "~":  # KiCad's own "no datasheet" placeholder
            part.datasheet = ""
        for name, value in properties.items():
            if name in ("reference", "value", "footprint", "datasheet") or not value:
                continue
            _assign_field(part, name, value)

        if part.reference or part.value or part.mpn:
            parts.append(part)

    if not parts:
        diagnostics.append(
            {
                "severity": "warn",
                "code": "HBOM_SCHEMATIC_EMPTY",
                "message": "a KiCad schematic was read but declared no BOM symbols",
            }
        )
    return parts, diagnostics


class _SexpError(Exception):
    pass


def _read_sexp(text: str) -> list[Any]:
    """An iterative S-expression reader with an explicit depth and token cap.

    Returns nested lists of strings. Deliberately minimal: KiCad's format is
    atoms, quoted strings and parens, and a fuller reader would be more surface
    for no gain.
    """
    out: list[Any] = []
    stack: list[list[Any]] = [out]
    i, n, tokens = 0, len(text), 0

    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "(":
            if len(stack) > MAX_SEXP_DEPTH:
                raise _SexpError(f"nesting deeper than {MAX_SEXP_DEPTH} levels")
            node: list[Any] = []
            stack[-1].append(node)
            stack.append(node)
            i += 1
            continue
        if ch == ")":
            if len(stack) == 1:
                raise _SexpError("unbalanced closing parenthesis")
            stack.pop()
            i += 1
            continue

        tokens += 1
        if tokens > MAX_SEXP_TOKENS:
            raise _SexpError(f"more than {MAX_SEXP_TOKENS:,} tokens")

        if ch == '"':
            buf, i = [], i + 1
            while i < n:
                c = text[i]
                if c == "\\" and i + 1 < n:
                    buf.append(text[i + 1])
                    i += 2
                    continue
                if c == '"':
                    i += 1
                    break
                buf.append(c)
                i += 1
            stack[-1].append("".join(buf))
            continue

        start = i
        while i < n and not text[i].isspace() and text[i] not in "()":
            i += 1
        stack[-1].append(text[start:i])

    if len(stack) != 1:
        raise _SexpError("unbalanced opening parenthesis")
    return out


def _find_all(tree: Any, head: str) -> list[list[Any]]:
    """Every node whose first element is `head`, at any depth.

    ⚠ DOCUMENT ORDER, AND ITERATIVE.

    Iterative because a recursive walk over untrusted input is a stack overflow
    waiting for a deeply nested file — the same reason `_read_sexp` is
    iterative and depth-capped.

    Document order because the output is a parts list a human reads and a
    machine diffs. A LIFO stack reverses it, which is not merely untidy: the
    grouping step downstream reads fields off the members of each group, and a
    reversed order silently changes which placement is "first". That produced a
    real bug — a resistor whose manufacturer was recorded on R1 came out blank
    because R4 was visited first. The grouping now coalesces across members so
    order cannot lose data either way, but an artifact whose row order flips
    for no reason is still a bad diff.
    """
    found: list[list[Any]] = []
    stack: list[Any] = [tree]
    while stack:
        node = stack.pop()
        if not isinstance(node, list):
            continue
        if node and node[0] == head:
            found.append(node)
        # Reversed, so that popping restores document order.
        stack.extend(child for child in reversed(node) if isinstance(child, list))
    return found


# ---------------------------------------------------------------------------
# Shared
# ---------------------------------------------------------------------------


def _assign_field(part: Part, name: str, value: str) -> None:
    """Route a KiCad custom field onto a part attribute, or keep it as extra.

    ⚠ NOTHING IS DROPPED. A field this does not recognise lands in `extra`,
    which the adapter renders into the technical specification — a customer who
    put "Tolerance: 1%" in their schematic should see it in the BOM, not lose
    it because our vocabulary is smaller than theirs.
    """
    if name in _MPN_KEYS:
        part.mpn = part.mpn or value
    elif name in _MANUFACTURER_KEYS:
        part.manufacturer = part.manufacturer or value
    elif name in _SKU_KEYS:
        part.supplier_sku = part.supplier_sku or value
    elif name in _SUPPLIER_KEYS:
        part.supplier = part.supplier or value
    elif name in _DNP_KEYS:
        part.do_not_populate = value.strip().lower() in ("1", "y", "yes", "true", "dnp")
    else:
        part.extra.setdefault(name, value)


def _shorten_footprint(value: str) -> str:
    """KiCad writes `Resistor_SMD:R_0402_1005Metric`; the part after the colon
    is the land pattern, which is what a BOM column means by footprint."""
    return value.split(":", 1)[1] if ":" in value else value


def _text(node: ET.Element | None) -> str:
    return (node.text or "").strip() if node is not None else ""


def _declares_entities(data: bytes) -> bool:
    """Whether the document contains a DOCTYPE or ENTITY declaration.

    Case-insensitive over the whole document rather than only its head: a
    declaration is legal anywhere in the prolog, and an internal subset can be
    large enough to push it past any fixed prefix.
    """
    lowered = data.lower()
    return b"<!doctype" in lowered or b"<!entity" in lowered
