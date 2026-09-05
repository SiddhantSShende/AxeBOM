"""EAGLE schematic parsing.

⚠ EAGLE IS THE FORMAT OPEN HARDWARE IS ACTUALLY PUBLISHED IN — Arduino,
SparkFun and Adafruit reference designs are EAGLE — and `hbom-ecad` could not
read a byte of it. A customer with an EAGLE repository got
ENGINE_INPUT_MISSING and a list of extensions that did not include theirs.
"""

from __future__ import annotations

from pathlib import Path

from .adapters import discovery, eagle

MINIMAL = b"""<?xml version="1.0" encoding="utf-8"?>
<eagle version="9.6.2">
  <drawing>
    <schematic>
      <parts>
        <part name="R1" library="rcl" deviceset="R-EU_" device="0207/10" value="10k">
          <attribute name="MPN" value="RC0805FR-0710KL"/>
          <attribute name="MF" value="Yageo"/>
        </part>
        <part name="C1" library="rcl" deviceset="C-EU" device="C0805" value="100nF"/>
        <part name="FRAME1" library="frames" deviceset="A4L-LOC" device=""/>
        <part name="GND1" library="supply1" deviceset="GND" device=""/>
      </parts>
    </schematic>
  </drawing>
</eagle>
"""


def test_an_eagle_schematic_yields_its_placements() -> None:
    parts, diagnostics = eagle.parse_schematic(MINIMAL)

    references = sorted(p.reference for p in parts)
    assert references == ["C1", "R1"], (
        f"got {references}: the frame and ground symbols must not be components"
    )

    resistor = next(p for p in parts if p.reference == "R1")
    assert resistor.value == "10k"
    assert resistor.mpn == "RC0805FR-0710KL"
    assert resistor.manufacturer == "Yageo"
    # deviceset + device, joined: the deviceset alone loses the package and the
    # package is what makes two placements the same line item.
    assert resistor.footprint == "R-EU_0207/10"

    codes = {d["code"] for d in diagnostics}
    assert "HBOM_SCHEMATIC_SYMBOLS_SKIPPED" in codes, (
        "dropping the frame and supply symbols must be STATED, not silent — "
        "a component count that changed for an unexplained reason is worse "
        "than one that is wrong"
    )


def test_frames_and_supply_symbols_are_never_components() -> None:
    """⚠ EVERY EAGLE SHEET CARRIES A DRAWING FRAME AS A <part>.

    So does every ground symbol. They are stored exactly like a resistor, and a
    BOM listing "FRAME_A_L" as a component is wrong in a way a customer notices
    immediately and trusts less afterwards.
    """
    parts, _ = eagle.parse_schematic(MINIMAL)
    names = {p.reference for p in parts}
    assert "FRAME1" not in names
    assert "GND1" not in names


def test_do_not_populate_survives() -> None:
    """A DNP part is designed in and deliberately not fitted.

    Listing it as a component to order is how somebody buys a reel of parts the
    board was never meant to carry.
    """
    data = MINIMAL.replace(
        b'<part name="C1" library="rcl" deviceset="C-EU" device="C0805" value="100nF"/>',
        b'<part name="C1" library="rcl" deviceset="C-EU" device="C0805" value="100nF"'
        b' populate="no"/>',
    )
    parts, _ = eagle.parse_schematic(data)
    capacitor = next(p for p in parts if p.reference == "C1")
    assert capacitor.do_not_populate is True


def test_an_entity_declaration_is_refused_unparsed() -> None:
    """The billion-laughs shape is refused rather than parsed.

    ⚠ CHECKED HERE AND IN discovery, DELIBERATELY. A security property that
    holds only because another function ran first is the "remember to sanitize"
    pattern, and parse_schematic is public.
    """
    hostile = b"""<?xml version="1.0"?>
<!DOCTYPE eagle [<!ENTITY a "aaaaaaaaaa">]>
<eagle version="9.6.2"><drawing><schematic><parts>
<part name="R1" library="rcl" deviceset="R" device="0805" value="&a;"/>
</parts></schematic></drawing></eagle>
"""
    parts, diagnostics = eagle.parse_schematic(hostile)
    assert parts == []
    assert diagnostics[0]["code"] == "HBOM_SCHEMATIC_REFUSED"


def test_malformed_xml_returns_a_diagnostic_and_never_raises() -> None:
    parts, diagnostics = eagle.parse_schematic(b"<eagle><drawing>")
    assert parts == []
    assert diagnostics[0]["code"] == "HBOM_SCHEMATIC_UNPARSEABLE"


def test_an_empty_schematic_says_so() -> None:
    empty = b'<?xml version="1.0"?><eagle version="9.6.2"><drawing><schematic>'
    empty += b"<parts></parts></schematic></drawing></eagle>"
    parts, diagnostics = eagle.parse_schematic(empty)
    assert parts == []
    assert diagnostics[0]["code"] == "HBOM_SCHEMATIC_EMPTY"


def test_a_placement_with_no_designator_is_dropped() -> None:
    """Inventing a designator would put a part in a compliance document that
    no schematic names."""
    data = MINIMAL.replace(b'<part name="C1"', b'<part name=""')
    parts, _ = eagle.parse_schematic(data)
    assert sorted(p.reference for p in parts) == ["R1"]


def test_discovery_classifies_an_eagle_sch_and_not_a_geda_one(tmp_path: Path) -> None:
    """⚠ `.sch` IS AMBIGUOUS: EAGLE, gEDA and legacy KiCad all use it.

    Classifying on the extension alone would hand a gEDA file to an XML parser
    and produce a confusing failure about a file the customer never meant to
    include.
    """
    eagle_file = tmp_path / "board.sch"
    eagle_file.write_bytes(MINIMAL)
    geda_file = tmp_path / "legacy.sch"
    geda_file.write_bytes(b"v 20130925 2\nC 40000 40000 1 0 0 resistor-1.sym\n")

    found = discovery.walk(tmp_path)
    kinds = {f.relative: f.kind for f in found.files}

    assert kinds.get("board.sch") == "eagle-schematic"
    assert "legacy.sch" not in kinds, (
        "a gEDA schematic was handed to the EAGLE parser; only the content "
        "check separates them"
    )


def test_sch_is_in_the_searched_extensions_so_an_empty_result_names_it() -> None:
    """"Found nothing" leaves a customer unable to tell a wrong subpath from an
    unsupported format, and they will assume the latter."""
    assert ".sch" in discovery.SEARCHED_EXTENSIONS
