"""EAGLE schematic parsing.

⚠ NOTHING HERE EXAMINES HARDWARE. An `.sch` file is a design the customer
wrote and committed. It states what was *designed*, not what was built or what
is currently fitted on a board. See CLAUDE.md's honest-labels section.

# Why EAGLE, and why it was the gap worth closing first

`hbom-ecad` read KiCad schematics, KiCad netlists and BOM tables. EAGLE is the
other format open hardware is actually published in — Arduino, SparkFun and
Adafruit reference designs are EAGLE — so a customer with an EAGLE repository
got `HBOM_NO_DESIGN_FILES` and a list of extensions that did not include
theirs. The engine was working correctly and the roster was too narrow.

# Shape

An EAGLE schematic is XML::

    <eagle version="9.6.2">
      <drawing>
        <schematic>
          <parts>
            <part name="R1" library="rcl" deviceset="R-EU_" device="0207/10"
                  value="10k">
              <attribute name="MPN" value="RC0805FR-0710KL"/>
            </part>
          </parts>
        </schematic>
      </drawing>
    </eagle>

`<part>` is a PLACEMENT, which is the same unit `kicad.Part` models, so this
returns that type and the whole grouping/coalescing path downstream is shared
rather than reimplemented.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from .kicad import Part, _declares_entities

#: EAGLE library parts that are not components on the board.
#:
#: ⚠ FRAMES AND GROUND SYMBOLS ARE NOT PARTS, AND COUNTING THEM INFLATES A BOM.
#: Every EAGLE sheet carries a drawing frame (library `frames`) and supply
#: symbols (library `supply1`/`supply2`) as `<part>` elements exactly like a
#: resistor. A BOM that lists "FRAME_A_L" as a component is wrong in a way a
#: customer notices immediately and trusts less afterwards.
_NON_COMPONENT_LIBRARIES = frozenset({"frames", "supply1", "supply2", "supply"})

#: Attribute names that carry a manufacturer part number, lowercased.
#:
#: EAGLE has no standard for this — it is a free-form `<attribute>` — so the
#: field is whatever the designer's house style used. These are the spellings
#: seen in published reference designs.
_MPN_KEYS = ("mpn", "manufacturer_part_number", "mfr_part_no", "part_number", "pn")
_MANUFACTURER_KEYS = ("mf", "manufacturer", "mfr", "mfg")
_SUPPLIER_KEYS = ("supplier", "distributor", "vendor")
_SKU_KEYS = ("sku", "supplier_part_number", "distributor_part_number", "order_number", "spn")


def parse_schematic(data: bytes) -> tuple[list[Part], list[dict[str, Any]]]:
    """Read an EAGLE schematic into placements.

    Never raises: a malformed document returns no parts and a diagnostic,
    matching the contract every parser in this codebase honours.
    """
    diagnostics: list[dict[str, Any]] = []

    # ⚠ THE ENTITY GUARD IS REPEATED HERE ON PURPOSE, exactly as
    # kicad.parse_netlist explains: discovery._looks_like already refuses these
    # shapes, and a security property that holds only because another function
    # ran first is the "remember to sanitize" pattern. This function is public.
    if _declares_entities(data):
        return [], [
            {
                "severity": "warn",
                "code": "HBOM_SCHEMATIC_REFUSED",
                "message": "an EAGLE schematic declaring XML entities was refused unparsed",
                "hint": "an EAGLE schematic contains no DOCTYPE or ENTITY declaration; "
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
                "code": "HBOM_SCHEMATIC_UNPARSEABLE",
                "message": "an EAGLE schematic could not be parsed as XML",
                "hint": str(exc),
            }
        ]

    parts: list[Part] = []
    skipped_non_components = 0

    for element in root.iter("part"):
        library = (element.get("library") or "").strip().lower()
        if library in _NON_COMPONENT_LIBRARIES:
            skipped_non_components += 1
            continue

        reference = (element.get("name") or "").strip()
        if not reference:
            # A placement with no designator cannot be referred to, ordered or
            # matched against a board. Dropping it is right; inventing a
            # designator would put a part in a compliance document that no
            # schematic names.
            continue

        part = Part(
            reference=reference,
            value=(element.get("value") or "").strip(),
            footprint=_footprint(element),
        )

        # ⚠ POPULATE="no" IS EAGLE'S DNP, and it must survive into the BOM.
        # A do-not-populate part is designed in and deliberately not fitted;
        # listing it as a component to be ordered is how somebody buys a reel
        # of parts the board was never meant to carry.
        part.do_not_populate = (element.get("populate") or "").strip().lower() == "no"

        for attribute in element.findall("attribute"):
            name = (attribute.get("name") or "").strip()
            value = (attribute.get("value") or "").strip()
            if not name or not value:
                continue
            _assign_attribute(part, name.lower(), value)
            # Everything is kept, so nothing the file carried is silently lost
            # even when this parser has no field for it.
            part.extra.setdefault(name, value)

        parts.append(part)

    if not parts:
        diagnostics.append(
            {
                "severity": "warn",
                "code": "HBOM_SCHEMATIC_EMPTY",
                "message": "an EAGLE schematic contained no component placements",
                "hint": "the file parsed as XML but declared no <part> outside the "
                "frame and supply libraries — an empty or template sheet",
            }
        )
    elif skipped_non_components:
        diagnostics.append(
            {
                "severity": "info",
                "code": "HBOM_SCHEMATIC_SYMBOLS_SKIPPED",
                "message": (
                    f"{skipped_non_components} drawing-frame and supply symbol(s) "
                    "were not counted as components"
                ),
                "hint": "EAGLE stores sheet frames and ground/supply symbols as "
                "<part> elements; they are not parts of the product",
            }
        )

    return parts, diagnostics


def _footprint(element: ET.Element) -> str:
    """The package, from EAGLE's two-part device naming.

    EAGLE splits a component into a `deviceset` (R-EU_) and a `device`
    (0207/10), where the device IS the package variant. Joined rather than
    picking one: the deviceset alone loses the package, and the device alone is
    meaningless out of context — and the package is what makes two placements
    the same line item in `Part.group_key`.
    """
    deviceset = (element.get("deviceset") or "").strip()
    device = (element.get("device") or "").strip()
    if deviceset and device:
        return f"{deviceset}{device}"
    return deviceset or device


def _assign_attribute(part: Part, name: str, value: str) -> None:
    """Map one EAGLE attribute onto a Part field, if it is one we model."""
    if name in _MPN_KEYS and not part.mpn:
        part.mpn = value
    elif name in _MANUFACTURER_KEYS and not part.manufacturer:
        part.manufacturer = value
    elif name in _SUPPLIER_KEYS and not part.supplier:
        part.supplier = value
    elif name in _SKU_KEYS and not part.supplier_sku:
        part.supplier_sku = value
    elif name == "datasheet" and not part.datasheet:
        part.datasheet = value
