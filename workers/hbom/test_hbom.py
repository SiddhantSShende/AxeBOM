"""HBOM: import, model, enrichment, and the honest labels.

The phase file names several assertions explicitly. Each has a test below whose
name says which, so a future reader can find the requirement from the test and
the test from the requirement.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from axebom_shared.model.generated_certin import HBOM_FIELDS

from .csv_import import CANONICAL_COLUMNS, ColumnMapping, HBOMImportError, parse
from .form import FormError, blank_form, from_payload
from .model import (
    ASSEMBLY_TYPES,
    CRITICALITY_VALUES,
    LIFECYCLE_VALUES,
    MAX_DEPTH,
    NOT_PROVIDED,
    Alternate,
    HardwareComponent,
    to_profile_row,
    validate_mapping,
)
from .normalize import flatten, normalize_bom, source_label
from .providers import ManualProvider, resolve
from .providers.base import Enrichment, apply, mpns
from .providers.mouser import MouserProvider
from .providers.nexar import NexarProvider

FIXTURE = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "hbom-nested" / "parts.csv"


@pytest.fixture
def nested():
    return parse(FIXTURE.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# The honest label
# ---------------------------------------------------------------------------


#: Patterns that would claim AxeBOM discovers PHYSICAL hardware.
#:
#: ⚠ "hbom scan" WAS ON THIS LIST AND IS NOT ANY MORE. THAT REMOVAL IS THE ONE
#: THING HERE MOST WORTH READING BEFORE CHANGING ANYTHING.
#:
#: It belonged for as long as HBOM had no scanner at all: every hardware BOM
#: came from a CSV or a form, so an "HBOM scan" button was a lie the customer
#: discovered while assembling audit evidence.
#:
#: `hbom-ecad` made it true. It parses the customer's own KiCad, Altium and
#: OrCAD design files out of an upload or a connected repository — a real scan,
#: producing real jobs, over documents they wrote. That is the same act as
#: reading a committed lockfile for an SBOM, and calling it a scan is accurate.
#:
#: ⚠ WHAT HAS NOT CHANGED IS THE ACTUAL LIE THIS GUARDS: that AxeBOM looks at
#: PHYSICAL HARDWARE. Nothing inspects a device and enumerates its parts. A
#: parts list the customer drew, and an inventory their own machine reported,
#: are not us having examined their hardware.
#:
#: ⚠ REGEXES, NOT SUBSTRINGS, and the change is not cosmetic. The old list
#: missed "discover your hardware" while catching "discovers hardware" — a real
#: discovery claim walking straight through a guard that looked thorough. A
#: rule expressed as a verb next to a noun cannot be defeated by a possessive.
_DISCOVERY_CLAIMS = (
    re.compile(r"\b(hardware|device)\s+scan"),
    re.compile(r"\bscans?\s+(your\s+|the\s+|their\s+)?(hardware|device)\b"),
    re.compile(
        r"\b(discover|discovers|discovered|detect|detects|inspect|inspects|enumerate|enumerates)"
        r"\s+(your\s+|the\s+|their\s+|its\s+)?(hardware|device|parts)\b"
    ),
)

#: Words that turn one of the above into a warning AGAINST making the claim.
#:
#: ⚠ THE NEGATION CHECK IS THE WHOLE SUBTLETY. The package docstring says an
#: "HBOM scan" button is a lie; a naive substring search flags that sentence and
#: the rule becomes unenforceable, so somebody deletes the test. What must be
#: caught is the phrase asserted, not the phrase discussed.
_NEGATIONS = (
    "not ",
    "no ",
    "never",
    "cannot",
    "is a lie",
    "would be",
    "must not",
    "there is",
    "rather than",
    "instead of",
)


def test_nothing_in_this_package_claims_to_scan():
    """⚠ THERE IS NO OPEN-SOURCE HBOM SCANNER.

    No tool inspects a physical device and enumerates its parts. Labelling this
    as discovery is a claim the product cannot honour, on a document a customer
    hands to an auditor — and they find out at exactly the wrong moment.

    This walks the package's own source, because the rule is about what we SAY,
    and a docstring is as much of a claim as a UI string.
    """
    package = pathlib.Path(__file__).parent
    offenders: list[str] = []

    for path in sorted(package.rglob("*.py")):
        if path.name == pathlib.Path(__file__).name:
            # The test file names the forbidden phrases in order to forbid them.
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, 1):
            lowered = line.lower()
            for phrase in _DISCOVERY_CLAIMS:
                if not phrase.search(lowered):
                    continue
                context = (lines[number - 2].lower() if number >= 2 else "") + lowered
                if any(negation in context for negation in _NEGATIONS):
                    continue
                offenders.append(f"{path.name}:{number}: {line.strip()}")

    assert not offenders, (
        "HBOM is import plus a data model, and these read as discovery claims:\n  "
        + "\n  ".join(offenders)
    )


def test_a_design_file_scan_is_not_a_discovery_claim():
    """⚠ THE OTHER HALF OF THE RULE, ADDED WHEN "hbom scan" LEFT THE LIST.

    A guard that only ever forbids is a guard nobody can work with. Parsing a
    schematic the customer committed IS a scan and saying so is accurate; what
    must stay forbidden is the claim that AxeBOM looked at their hardware.

    Without this test the natural response to the narrower list would be to
    re-add "hbom scan" the next time somebody skims it, and the honest label
    would go back to forbidding a true sentence — which is how a rule ends up
    ignored.
    """
    permitted = [
        "an HBOM scan parses the design files in your repository",
        "run an HBOM scan to read your KiCad schematics",
        "this HBOM scan found 42 line items in your parts list",
    ]
    for text in permitted:
        lowered = text.lower()
        assert not any(claim.search(lowered) for claim in _DISCOVERY_CLAIMS), (
            f"a design-file scan is not a discovery claim, but this was flagged: {text}"
        )

    forbidden = [
        "AxeBOM scans your hardware for components",
        "we inspect the device and enumerate its parts",
        "this feature discovers hardware automatically",
        "AxeBOM detects your hardware",
        "run an HBOM scan to discover your hardware",
        "we enumerate the parts on your board by inspecting it",
    ]
    for text in forbidden:
        lowered = text.lower()
        assert any(claim.search(lowered) for claim in _DISCOVERY_CLAIMS), (
            f"this asserts discovery of physical hardware and was NOT caught: {text}"
        )


def test_the_scan_claim_check_would_actually_catch_one():
    """⚠ THE CHECK ABOVE PASSES TRIVIALLY IF ITS NEGATION FILTER IS TOO BROAD.

    A filter that excused every line would leave a green test proving nothing —
    the exact failure mode this codebase has hit before. So the filter is
    exercised directly: an asserted claim is caught, a warning against one is not.
    """
    claim = "    return 'Run an HBOM scan to discover your hardware'"
    warning = "    # There is no HBOM scan: hardware is not discoverable."

    def flagged(line: str) -> bool:
        lowered = line.lower()
        return any(p.search(lowered) for p in _DISCOVERY_CLAIMS) and not any(
            n in lowered for n in _NEGATIONS
        )

    assert flagged(claim), "an asserted discovery claim would not be caught"
    assert not flagged(warning), "a warning against the claim would be flagged"


def test_the_source_label_says_import_not_scan():
    label = source_label()
    assert "import" in label.lower()
    assert "scan" not in label.lower().replace("not discoverable by scan", "")


def test_no_gpl_package_is_imported_anywhere_in_this_worker():
    """⚠ `django-bom` IS GPL-3.0 (CLAUDE.md invariant 9).

    Importing it would make this worker a derivative work — and it is a Django
    *application* rather than a library, so it would not work either. It is a
    schema reference, read and closed.
    """
    package = pathlib.Path(__file__).parent
    for path in package.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")):
                assert "django" not in stripped.lower(), f"{path.name}: {stripped}"
                assert "bom_" not in stripped.lower() or "axebom" in stripped.lower()


# ---------------------------------------------------------------------------
# The profile
# ---------------------------------------------------------------------------


def test_every_profile_element_has_somewhere_to_live():
    """A profile revision that renames a path must fail here, loudly, rather
    than silently dropping a field out of every report."""
    assert validate_mapping() == []


def test_the_four_section_10_4_1_4_elements_are_present():
    """⚠ TABLE 11 ALONE IS NOT COMPLIANT.

    §10.4.1.4 (p.62) mandates firmware version, origin, criticality and
    vulnerabilities. None appears in Table 11. A tool that implements Table 11
    and stops reports itself as complete while missing four required elements.
    """
    ids = {f.id for f in HBOM_FIELDS}
    for required in (
        "certin.hbom.21.firmware_version",
        "certin.hbom.22.origin",
        "certin.hbom.23.criticality",
        "certin.hbom.24.vulnerabilities",
    ):
        assert required in ids, f"{required} is missing from the profile"


def test_the_two_supplier_relationships_are_separately_addressable():
    """⚠ TABLE 11 LISTS SUPPLIER INFORMATION AND LOCATION TWICE, with different
    descriptions: who sold you the PRODUCT, and who supplied a COMPONENT to that
    product's manufacturer. Four columns, not two."""
    paths = {f.canonical_path for f in HBOM_FIELDS}
    assert "hardware_component.supplier_info" in paths
    assert "hardware_component.supplier_location" in paths
    assert "hardware_component.component_supplier_info" in paths
    assert "hardware_component.component_supplier_location" in paths

    component = HardwareComponent(
        product_name="gateway",
        supplier_info="Bharat Integrators Ltd",
        supplier_location="New Delhi, India",
        component_supplier_info="Arrow Electronics",
        component_supplier_location="Bengaluru, India",
    )
    row = to_profile_row(component)
    assert row["certin.hbom.08.supplier_information"] == "Bharat Integrators Ltd"
    assert row["certin.hbom.13.component_supplier_information"] == "Arrow Electronics"
    assert (
        row["certin.hbom.09.supplier_location"] != row["certin.hbom.14.component_supplier_location"]
    )


def test_every_element_is_present_or_explicitly_not_provided():
    """⚠ REPORTED, NEVER OMITTED. Omission hides the gap; `not-provided` states
    it, and coverage then scores it zero."""
    row = to_profile_row(HardwareComponent(product_name="bare"))
    assert set(row) == {f.id for f in HBOM_FIELDS}
    empty = [k for k, v in row.items() if v == NOT_PROVIDED]
    assert len(empty) == len(HBOM_FIELDS) - 1  # product_name is set


def test_no_field_count_is_hardcoded_in_this_package():
    """⚠ INVARIANT 2. Writing `24` anywhere is how a product ships a false
    compliance claim when the guideline is revised."""
    package = pathlib.Path(__file__).parent
    count = str(len(HBOM_FIELDS))

    for path in package.rglob("*.py"):
        if path.name == "test_hbom.py":
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"'):
                continue
            assert f"= {count}" not in stripped, f"{path.name}:{number} hardcodes the field count"


# ---------------------------------------------------------------------------
# CSV import — the tree
# ---------------------------------------------------------------------------


def test_the_level_column_builds_the_tree(nested):
    assert len(nested.roots) == 1
    root = nested.roots[0]
    assert root.product_name == "ENC-GW-4400"

    # gateway -> mainboard -> DDR3L -> die
    assert root.depth() == 3

    names = [c.model_number for c in root.children]
    assert names == ["ENC-MB-01", "ENC-PSU-02", "ENC-ENC-01"]

    mainboard = root.children[0]
    assert [c.model_number for c in mainboard.children] == [
        "STM32H753ZI",
        "MT41K256M16",
        "W25Q128JV",
    ]

    sdram = mainboard.children[1]
    assert [c.model_number for c in sdram.children] == ["MT41K-DIE"]


def test_returning_to_a_shallower_level_reattaches_correctly(nested):
    """Row 6 is level 2 following a level-3 row. It belongs to the mainboard,
    not to the memory die — a stack that was not truncated would attach it to
    whatever was last seen at any depth."""
    mainboard = nested.roots[0].children[0]
    flash = [c for c in mainboard.children if c.model_number == "W25Q128JV"]
    assert len(flash) == 1, "the flash chip did not reattach to the mainboard"


def test_a_skipped_level_is_rejected_and_names_the_row():
    """⚠ THE ROW THAT BROKE, AND BOTH LEVELS.

    A level-3 row after a level-1 row has no parent. Accepting it silently
    reparents the part, producing a structurally valid BOM that says something
    false about how the hardware is built — and nothing downstream can detect it.
    """
    csv_text = "level,part_number,description\n0,A,product\n1,B,assembly\n3,C,orphan\n"
    with pytest.raises(HBOMImportError) as excinfo:
        parse(csv_text)

    message = str(excinfo.value)
    assert "row 4" in message, f"the error does not name the row: {message}"
    assert "level 3" in message and "level 1" in message, message
    assert "skip" in message.lower()


def test_an_outline_level_is_understood():
    """`1.2.1` is how most CAD and ERP exports write a nested BOM."""
    csv_text = "level,part_number,description\n1,A,product\n1.1,B,assembly\n1.1.1,C,part\n"
    result = parse(csv_text)
    assert result.roots[0].depth() == 2


def test_a_level_that_is_not_a_number_is_rejected_legibly():
    with pytest.raises(HBOMImportError) as excinfo:
        parse("level,part_number\n0,A\nsub,B\n")
    assert "row 3" in str(excinfo.value)


def test_depth_beyond_the_cap_is_reported_not_recursed():
    """⚠ CAPPED WITH A DIAGNOSTIC, NOT SILENTLY TRUNCATED. A `level` column that
    walks upward forever is a plausible export bug; unbounded recursion turns it
    into a crash, and silent truncation into a BOM missing parts nobody knows
    about."""
    rows = ["level,part_number,description"]
    for level in range(MAX_DEPTH + 3):
        rows.append(f"{level},PART-{level},component at level {level}")

    result = parse("\n".join(rows) + "\n")

    assert result.warnings, "exceeding the depth cap produced no diagnostic"
    assert any(str(MAX_DEPTH) in w for w in result.warnings)
    assert result.roots[0].depth() <= MAX_DEPTH


def test_an_unmapped_header_is_reported_not_swallowed():
    """A customer whose "Criticality" column was spelled "Crit." would otherwise
    get a BOM missing a §10.4.1.4 element, with nothing saying so."""
    result = parse("level,part_number,Crit.\n0,A,critical\n")
    assert "Crit." in result.unmapped_headers


def test_a_file_with_no_level_column_is_rejected_with_a_reason():
    with pytest.raises(HBOMImportError) as excinfo:
        parse("part_number,description\nA,thing\n")
    message = str(excinfo.value)
    assert "level" in message
    assert "sibling" in message or "sub-component" in message


def test_a_customers_own_headers_work_without_editing_their_file():
    """⚠ REQUIRING A CUSTOMER TO RENAME COLUMNS MEANS THEY EDIT AN EXPORT, make
    a mistake, and import something that no longer matches their source of
    truth."""
    csv_text = "BOM Level,Mfr Part Number,Desc,Qty,Mfr\n0,ENC-1,Gateway,1,Encore\n"
    mapping = ColumnMapping.suggest(["BOM Level", "Mfr Part Number", "Desc", "Qty", "Mfr"])
    result = parse(csv_text, mapping)

    root = result.roots[0]
    assert root.model_number == "ENC-1"
    assert root.manufacturer_name == "Encore"
    assert root.quantity == 1


def test_a_component_with_no_description_still_has_a_name():
    """A row with a part number and nothing else is entirely normal in a real
    parts list; an unnamed component makes a report unreadable."""
    result = parse("level,part_number\n0,ENC-1\n")
    assert result.roots[0].product_name == "ENC-1"


def test_repeated_sibling_parts_warn_rather_than_fail():
    """The same capacitor legitimately appears in four sub-assemblies; rejecting
    that would reject most real hardware. Twice under the SAME parent is usually
    two rows that should have been one with a quantity."""
    csv_text = (
        "level,part_number,description\n0,BOARD,board\n1,CAP-1,capacitor\n1,CAP-1,capacitor again\n"
    )
    result = parse(csv_text)
    assert result.warnings
    assert any("CAP-1" in w for w in result.warnings)
    assert result.total() == 3, "a duplicate must not be dropped, only reported"


def test_the_same_part_under_different_parents_is_not_a_warning(nested):
    """Arrow supplies parts under the mainboard; Mouser under two different
    assemblies. Neither is a duplicate."""
    assert not any("Arrow" in w for w in nested.warnings)


def test_a_bom_field_is_stripped_from_the_first_cell():
    """Excel writes a UTF-8 BOM. Left in place it becomes part of the first
    header name, so `level` is not recognised and the import fails with a
    confusing error about a missing column."""
    result = parse("﻿level,part_number\n0,ENC-1\n")
    assert result.roots[0].model_number == "ENC-1"


def test_compliance_splits_on_either_separator(nested):
    root = nested.roots[0]
    assert root.compliance == ["RoHS", "CE"]


# ---------------------------------------------------------------------------
# The form
# ---------------------------------------------------------------------------


def test_the_form_collects_what_no_parts_list_contains():
    """⚠ THE REASON THE FORM EXISTS. Warranty, licence terms, test result and
    criticality appear in no CAD or ERP export; without the form they are
    permanently `not-provided` and the coverage number is needlessly low."""
    component = from_payload(
        {
            "product_name": "Edge Gateway",
            "warranty_amc": "3 years on-site, AMC to 2029",
            "license_info": "Firmware under a proprietary OEM licence",
            "test_result": "Passed IEC 61000-4-2 ESD immunity",
            "criticality": "critical",
        }
    )
    row = to_profile_row(component)
    assert row["certin.hbom.04.warranty_amc"] != NOT_PROVIDED
    assert row["certin.hbom.18.license_information"] != NOT_PROVIDED
    assert row["certin.hbom.19.test_result"] != NOT_PROVIDED
    assert row["certin.hbom.23.criticality"] == "critical"


def test_an_invalid_criticality_is_refused_rather_than_coerced():
    """⚠ MAPPING "urgent" ONTO "critical" WOULD BE INVENTING A SEVERITY in a
    compliance document. The importer drops it; the form can do better, because
    there is somebody there to tell."""
    with pytest.raises(FormError) as excinfo:
        from_payload({"product_name": "x", "criticality": "urgent"})
    for value in CRITICALITY_VALUES:
        assert value in str(excinfo.value)


def test_an_unrecognised_field_is_rejected_not_ignored():
    """A silently dropped key means the customer believes they recorded
    something they did not."""
    with pytest.raises(FormError) as excinfo:
        from_payload({"product_name": "x", "manufacturor": "typo"})
    assert "manufacturor" in str(excinfo.value)


def test_a_component_needs_a_name():
    with pytest.raises(FormError):
        from_payload({"model_number": "ENC-1"})


def test_the_form_is_depth_capped():
    """A hand-crafted payload nesting a thousand deep is a denial of service
    against our own recursion limit, not a hardware assembly."""
    payload: dict = {"product_name": "leaf"}
    for _ in range(MAX_DEPTH + 3):
        payload = {"product_name": "node", "children": [payload]}

    with pytest.raises(FormError) as excinfo:
        from_payload(payload)
    assert str(MAX_DEPTH) in str(excinfo.value)


def test_the_blank_form_offers_every_editable_field():
    form = blank_form()
    for expected in ("warranty_amc", "license_info", "test_result", "criticality"):
        assert expected in form, f"{expected} is not askable, so it can never be answered"


def test_the_form_builds_a_nested_tree():
    component = from_payload(
        {
            "product_name": "Gateway",
            "children": [
                {"product_name": "Mainboard", "children": [{"product_name": "MCU"}]},
                {"product_name": "PSU"},
            ],
        }
    )
    assert component.depth() == 2
    assert component.count() == 4
    assert component.children[0].parent_local_id == component.local_id


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------


def test_the_default_provider_works_with_no_api_key():
    """⚠ THE DEFAULT PATH MUST BE THE TESTED PATH. Requiring a commercial parts
    database would make HBOM unusable for a customer recording hardware they
    already own."""
    provider = resolve([])
    assert provider.name == "manual"
    assert provider.configured()
    assert provider.lookup(["STM32H753ZI"]) == {}


def test_an_unconfigured_commercial_provider_is_skipped_cleanly():
    """⚠ NO ERROR AND NO EMPTY-CREDENTIAL CALL. A request with a blank API key
    produces a 401 in somebody's logs and a support ticket about a feature they
    never enabled."""
    for provider in (NexarProvider(token=""), MouserProvider(api_key="")):
        assert not provider.configured()
        assert provider.lookup(["STM32H753ZI"]) == {}

    chosen = resolve([NexarProvider(token=""), MouserProvider(api_key="")])
    assert chosen.name == "manual"


def test_a_configured_provider_is_preferred():
    chosen = resolve([NexarProvider(token="a-token"), ManualProvider()])
    assert chosen.name == "nexar"


def test_enrichment_never_overwrites_what_the_customer_supplied():
    """⚠ THE CUSTOMER'S VALUE IS THE ONE THAT GOES IN THE COMPLIANCE DOCUMENT.

    A parts database is a third party's opinion about an MPN; the customer's BOM
    is a statement about the hardware in front of them. Overwriting is how a
    supplier field verified against a purchase order gets replaced by a
    distributor's guess, with nothing in the output saying it happened.
    """
    component = HardwareComponent(
        product_name="MCU",
        model_number="STM32H753ZI",
        manufacturer_name="STMicroelectronics N.V.",
        origin="Switzerland",
    )
    apply(
        component,
        {
            "stm32h753zi": Enrichment(
                mpn="STM32H753ZI",
                manufacturer_name="ST Micro",
                manufacturer_location="Geneva, Switzerland",
                origin="Malaysia",
                source="nexar",
            )
        },
    )

    assert component.manufacturer_name == "STMicroelectronics N.V."
    assert component.origin == "Switzerland"
    # The empty field WAS filled, and its provenance recorded.
    assert component.manufacturer_location == "Geneva, Switzerland"
    assert component.enriched_fields["manufacturer_location"] == "nexar"


def test_enrichment_unions_compliance_rather_than_replacing_it():
    """A customer asserting RoHS and a provider asserting CE are both true."""
    component = HardwareComponent(product_name="x", model_number="ABC", compliance=["RoHS"])
    apply(component, {"abc": Enrichment(mpn="ABC", compliance=["CE", "RoHS"], source="mouser")})
    assert component.compliance == ["RoHS", "CE"]


def test_part_numbers_are_deduped_before_a_billable_lookup(nested):
    """⚠ THE SAME CAPACITOR APPEARS IN FOUR SUB-ASSEMBLIES of a real board.
    Looking it up four times burns a quota the customer pays for, to learn the
    same thing."""
    root = nested.roots[0]
    numbers = mpns(root)
    assert len(numbers) == len(set(numbers))
    assert "stm32h753zi" in numbers


def test_the_nexar_parser_reads_a_response_without_a_network():
    body = {
        "data": {
            "supMultiMatch": [
                {
                    "parts": [
                        {
                            "mpn": "STM32H753ZI",
                            "manufacturer": {"name": "STMicroelectronics"},
                            "specs": [
                                {
                                    "attribute": {"shortname": "rohsstatus"},
                                    "displayValue": "RoHS Compliant",
                                },
                                {
                                    "attribute": {"shortname": "lifecyclestatus"},
                                    "displayValue": "Active",
                                },
                            ],
                            "bestDatasheet": {"url": "https://example.com/ds.pdf"},
                        }
                    ]
                }
            ]
        }
    }
    parsed = NexarProvider.parse(body)
    assert parsed["stm32h753zi"].manufacturer_name == "STMicroelectronics"
    assert parsed["stm32h753zi"].compliance == ["RoHS"]
    assert parsed["stm32h753zi"].source == "nexar"


def test_the_mouser_parser_reads_a_response_without_a_network():
    body = {
        "SearchResults": {
            "Parts": [
                {
                    "ManufacturerPartNumber": "LM2596S-5.0",
                    "Manufacturer": "Texas Instruments",
                    "ROHSStatus": "RoHS Compliant",
                    "LifecycleStatus": "Active",
                    "DataSheetUrl": "https://example.com/lm2596.pdf",
                    "ProductAttributes": [],
                }
            ]
        }
    }
    parsed = MouserProvider.parse(body)
    assert parsed["lm2596s-5.0"].manufacturer_name == "Texas Instruments"
    assert parsed["lm2596s-5.0"].source == "mouser"


def test_a_provider_parser_tolerates_an_empty_response():
    assert NexarProvider.parse({}) == {}
    assert MouserProvider.parse({}) == {}


# ---------------------------------------------------------------------------
# Normalization and coverage
# ---------------------------------------------------------------------------


def test_every_node_is_scored_not_just_the_root(nested):
    """⚠ A ROOT-ONLY COVERAGE NUMBER WOULD DESCRIBE THE TOP ROW, not the
    hardware. A fully populated gateway over 200 bare leaf parts is not a
    well-documented BOM."""
    result = normalize_bom(nested.roots)
    assert result.coverage is not None
    assert result.coverage.scored_entities == result.component_count()
    assert result.component_count() == 9


def test_both_coverage_numbers_are_published(nested):
    """⚠ INVARIANT 3. Publishing only `declaration_pct` and calling it coverage
    is how a tool reports 100% for a BOM full of `not-provided`."""
    coverage = normalize_bom(nested.roots).coverage
    assert coverage is not None
    assert 0 < coverage.completeness_pct < 100
    assert coverage.declaration_pct >= coverage.completeness_pct


def test_not_provided_scores_zero_for_completeness():
    """A BOM of nothing but names must not report high completeness."""
    bare = [HardwareComponent(product_name=f"part-{i}") for i in range(5)]
    coverage = normalize_bom(bare).coverage
    assert coverage is not None
    assert coverage.completeness_pct < 15
    # Every field IS declared, explicitly, which is the second number's job.
    assert coverage.declaration_pct == 100.0


def test_the_flattened_rows_carry_the_tree_structure(nested):
    rows = flatten(nested.roots)
    root_row = rows[0]
    assert root_row["_depth"] == 0
    assert root_row["_parent_local_id"] is None

    child_rows = [r for r in rows if r["_depth"] == 1]
    assert len(child_rows) == 3
    assert all(r["_parent_local_id"] == root_row["_local_id"] for r in child_rows)


def test_a_missing_origin_is_diagnosed_by_name(nested):
    """⚠ §10.2.1 MAKES AN HBOM A PROVENANCE DOCUMENT. A coverage percentage
    averages that gap away across twenty other fields."""
    bare = [HardwareComponent(product_name="x")]
    result = normalize_bom(bare)
    codes = {d["code"] for d in result.diagnostics}
    assert "HBOM_ORIGIN_NOT_PROVIDED" in codes

    hint = next(d["hint"] for d in result.diagnostics if d["code"] == "HBOM_ORIGIN_NOT_PROVIDED")
    assert "10.4.1.4" in hint


def test_the_supplier_diagnostic_reports_both_relationships_separately():
    """Collapsing them into one "supplier coverage" number would hide exactly
    the distinction Table 11 draws by listing them twice."""
    result = normalize_bom([HardwareComponent(product_name="x")])
    message = next(
        d["message"] for d in result.diagnostics if d["code"] == "HBOM_SUPPLIER_NOT_PROVIDED"
    )
    assert "product supplier" in message
    assert "component supplier" in message


def test_a_flat_import_is_diagnosed():
    """A flat tree usually means the level column was not mapped."""
    result = normalize_bom([HardwareComponent(product_name=f"part-{i}") for i in range(3)])
    assert "HBOM_FLAT_TREE" in {d["code"] for d in result.diagnostics}


def test_the_sub_component_element_reports_direct_children(nested):
    root = nested.roots[0]
    row = to_profile_row(root)
    assert row["certin.hbom.20.sub_component"] == 3

    leaf = root.children[2]  # the enclosure, no children
    assert to_profile_row(leaf)["certin.hbom.20.sub_component"] == NOT_PROVIDED


def test_a_row_with_extra_fields_does_not_crash_the_import():
    """⚠ csv.DictReader PUTS SURPLUS FIELDS UNDER A `None` KEY, as a list:
    `{'a': '1', 'b': '2', None: ['3', '4']}`.

    A stray trailing comma in one row of a 400-line export produces this. The
    import must survive it rather than failing over a typo in a cell nobody
    cares about — this asserts the OUTCOME, not any particular guard, because
    which line does the filtering is an implementation detail that has already
    moved once.
    """
    csv_text = "level,part_number,description\n0,ENC-1,gateway,surplus,more\n"
    result = parse(csv_text)
    assert result.roots[0].model_number == "ENC-1"


def test_a_truncated_row_does_not_crash_the_import():
    """⚠ A SHORT ROW GIVES `None` VALUES: `{'a': '1', 'b': None}`.

    A file whose last line was cut off mid-write is the common case. The missing
    column must land as an empty string — reported as `not-provided` downstream
    — rather than as a None that raises on `.strip()` three frames later.
    """
    csv_text = "level,part_number,description,manufacturer\n0,ENC-1\n"
    result = parse(csv_text)
    assert result.roots[0].model_number == "ENC-1"
    assert result.roots[0].manufacturer_name == ""


# ---------------------------------------------------------------------------
# The manufacturing profile — scored, and structurally unable to move CERT-In
# ---------------------------------------------------------------------------


def test_a_fully_populated_manufacturing_block_does_not_move_completeness():
    """⚠ INVARIANTS 2 AND 3, AND THE POINT OF THE WHOLE SEPARATION.

    A customer who fills in every price, designator, SKU and alternate must see
    exactly the SAME compliance percentage as one who fills in none of them.
    Those fields are AxeBOM's, not CERT-In's — letting procurement diligence
    raise a number that goes to a regulator would change what that number MEANS
    while leaving its name intact.

    The denominator is asserted as well as the percentages: a leak that added
    manufacturing weight to BOTH numerator and denominator could leave a
    percentage coincidentally unchanged while the number underneath it had
    quietly become a different measurement.
    """
    certin_only = {
        "product_name": "gateway",
        "manufacturer_name": "Encore Systems",
        "manufacturer_location": "Pune, India",
        "model_number": "ENC-GW-4400",
        "origin": "India",
        "criticality": "critical",
    }
    bare = normalize_bom([HardwareComponent(**certin_only)])
    loaded = normalize_bom(
        [
            HardwareComponent(
                **certin_only,
                designators=["U1", "U2"],
                package_footprint="QFN-48",
                quantity=12,
                supplier_sku="497-11767-ND",
                preferred_supplier="Digi-Key",
                unit_price="1.2400",
                currency="USD",
                assembly_type="smt",
                lifecycle_status="active",
                alternates=[Alternate(model_number="STM32H753ZI", equivalence="drop-in")],
            )
        ]
    )

    assert bare.coverage is not None and loaded.coverage is not None
    assert loaded.coverage.completeness_pct == bare.coverage.completeness_pct
    assert loaded.coverage.declaration_pct == bare.coverage.declaration_pct
    assert loaded.coverage.denominator == bare.coverage.denominator

    # ...and the second number DOES move, or this test would pass by scoring
    # nothing at all.
    assert loaded.manufacturing is not None and bare.manufacturing is not None
    assert loaded.manufacturing.completeness_pct > bare.manufacturing.completeness_pct


def test_no_manufacturing_field_id_is_a_certin_field_id():
    """The two field sets must not overlap.

    An id collision would let a manufacturing field be mistaken for a CERT-In
    element by anything that keys on the id — and the only warning would be a
    duplicate-id lint failure, which fires only if both files are ever linted
    as one document. They are not.
    """
    from .profile import manufacturing_fields

    mfg = {f.id for f in manufacturing_fields()}
    assert mfg, "no manufacturing fields loaded; this test would pass vacuously"
    assert not mfg & {f.id for f in HBOM_FIELDS}
    assert all(i.startswith("axebom.hbom.mfg.") for i in mfg)


def test_the_manufacturing_count_is_never_written():
    """⚠ INVARIANT 2, APPLIED TO THE SECOND PROFILE TOO.

    The compliance profile's count is guarded by `axebom profile guardrails`.
    This one is not in that tool's scope, so the equivalent guarantee is
    asserted here: the number of manufacturing fields comes from the profile,
    and nothing may hardcode it.
    """
    from .profile import manufacturing_fields

    source = pathlib.Path(__file__).parent
    count = str(len(manufacturing_fields()))
    offenders = [
        f"{path.name}:{n}: {line.strip()}"
        for path in sorted(source.rglob("*.py"))
        if path.name != pathlib.Path(__file__).name
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if f"{count} manufacturing" in line or f"{count} procurement" in line
    ]
    assert not offenders, "a manufacturing field count is written down:\n  " + "\n  ".join(
        offenders
    )


def test_unknown_lifecycle_is_declared_but_scores_zero():
    """⚠ THE FIELD WHERE A PARTS DATABASE MOST OFTEN ANSWERS "unknown".

    `unknown` is in coverage.NON_SUBSTANTIVE, so it is stored and REPORTED
    without counting as knowledge — invariant 3's rule, on the one manufacturing
    field where the distinction matters most. A distributor saying it cannot
    determine a part's lifecycle is not the same as the part being active, and
    scoring it as covered would hide exactly the parts an engineer needs to see.
    """
    known = normalize_bom([HardwareComponent(product_name="p", lifecycle_status="nrnd")])
    unknown = normalize_bom([HardwareComponent(product_name="p", lifecycle_status="unknown")])

    assert known.manufacturing is not None and unknown.manufacturing is not None
    assert unknown.manufacturing.completeness_pct < known.manufacturing.completeness_pct
    # Declared either way: the value is present in the document, not omitted.
    assert unknown.manufacturing.declaration_pct == known.manufacturing.declaration_pct


def test_do_not_populate_false_is_an_answer():
    """`False` means "this part IS fitted" — a stated fact, not an absence.

    coverage.is_substantive treats a boolean as substantive for exactly this
    reason. If DNP scored zero when false, every ordinary part on every board
    would read as an unanswered question.
    """
    rows = flatten([HardwareComponent(product_name="p", do_not_populate=False)])
    assert rows[0]["hardware_component.do_not_populate"] is False


# ---------------------------------------------------------------------------
# The Go port must not drift
# ---------------------------------------------------------------------------


def test_the_go_port_understands_the_same_columns():
    """⚠ THE TWO IMPLEMENTATIONS DIVERGED ONCE, SILENTLY, AND THIS IS THE GUARD.

    `services/project/internal/hbom` is a hand-written Go port of this module,
    because there is no Go->Python bridge anywhere in this codebase and HBOM's
    REST path is Go like every other. Its own package doc says the two must be
    kept in step by hand.

    They were not. The manufacturing columns were added here for the scan path
    and not there, so the INTERACTIVE import silently dropped designators,
    prices, SKUs and lifecycle that a SCAN of the very same file kept — a
    difference no customer could see, explain, or work around.

    ⚠ THIS TEST READS THE GO SOURCE, WHICH IS UGLY AND IS THE POINT. There is
    no shared artifact between the two languages to compare instead, and the
    alternative is a comment asking the next person to remember. A comment is
    what failed.
    """
    go_source = pathlib.Path("services/project/internal/hbom/csvimport.go")
    if not go_source.is_file():
        pytest.skip("the Go port is not present in this checkout")

    text = go_source.read_text(encoding="utf-8")
    block = re.search(r"var canonicalColumns = map\[string\]string\{(.*?)\n\}", text, re.S)
    assert block, "canonicalColumns is not in the shape this test can read"

    go_columns = dict(re.findall(r'"([a-z_]+)":\s*"([a-z_]*)"', block.group(1)))
    assert go_columns, "no columns parsed out of the Go source"

    missing = sorted(set(CANONICAL_COLUMNS) - set(go_columns))
    extra = sorted(set(go_columns) - set(CANONICAL_COLUMNS))
    mismatched = {
        key: (CANONICAL_COLUMNS[key], go_columns[key])
        for key in set(CANONICAL_COLUMNS) & set(go_columns)
        if CANONICAL_COLUMNS[key] != go_columns[key]
    }

    assert not missing, f"the Go port does not understand these columns: {missing}"
    assert not extra, f"the Go port understands columns this module does not: {extra}"
    assert not mismatched, f"the two ports disagree about where these land: {mismatched}"


def test_the_go_ports_column_order_matches():
    """⚠ ORDER IS LOAD-BEARING, AND ONLY ON THE GO SIDE.

    `part_number` and `mpn` both target `model_number`, and "first column wins"
    depends on visiting `part_number` first. Python's dict preserves insertion
    order; a Go map does not, which is why the port carries an explicit
    `canonicalOrder` slice. A slice that has drifted from the map it orders
    would make the winner depend on which column a customer's file happens to
    contain.
    """
    go_source = pathlib.Path("services/project/internal/hbom/csvimport.go")
    if not go_source.is_file():
        pytest.skip("the Go port is not present in this checkout")

    text = go_source.read_text(encoding="utf-8")
    block = re.search(r"var canonicalOrder = \[\]string\{(.*?)\n\}", text, re.S)
    assert block, "canonicalOrder is not in the shape this test can read"

    go_order = re.findall(r'"([a-z_]+)"', block.group(1))
    assert sorted(go_order) == sorted(CANONICAL_COLUMNS), (
        "canonicalOrder does not cover exactly the columns canonicalColumns declares"
    )
    assert go_order.index("part_number") < go_order.index("mpn"), (
        "part_number must be visited before mpn, or the first-column-wins rule "
        "silently prefers whichever the customer's file happens to list"
    )


def _operational_profile() -> dict:
    """Load the operational profile from the repository.

    A TEST-ONLY read. `model.py`'s comment explains why the constants are not
    loaded this way at runtime: the operational profile generates Go only, and
    a worker container has no copy of `docs/`.
    """
    import pathlib

    import yaml

    path = pathlib.Path(__file__).resolve().parents[2] / "docs/reference/hbom-manufacturing-v1.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _operational_values(element_id: str) -> tuple[str, ...]:
    profile = _operational_profile()
    for element in profile["hbom_manufacturing"]["elements"]:
        if element["id"] == element_id:
            return tuple(element.get("values") or ())
    raise AssertionError(f"the operational profile declares no element {element_id}")


def test_criticality_comes_from_the_compliance_profile() -> None:
    """⚠ ONE CLOSED SET HAD FOUR HAND-WRITTEN COPIES AND TWO DISAGREED.

    Go's device-form list carried a fifth value (`unknown`) beneath a comment
    asserting it matched `normalize.hardware_components`, whose CHECK allows
    four — so a device recorded as `unknown` was storable here and
    unrepresentable in the parts table its tree flows into. They multiplied
    because `axebom profile gen` dropped the profile's values list.
    """
    from axebom_shared.model.generated_certin import HBOM_FIELDS

    declared = next(
        f.values for f in HBOM_FIELDS if f.id == "certin.hbom.23.criticality"
    )
    assert declared, "the profile declares no criticality values"
    assert CRITICALITY_VALUES == declared


def test_the_operational_enums_match_their_profile() -> None:
    """The operational profile generates Go only, so a TEST is what holds the
    Python constants to it — the same arrangement the engine-registry
    agreement tests use, and for the same reason: the authority lives
    somewhere this module may not import at runtime."""
    assert ASSEMBLY_TYPES == _operational_values("axebom.hbom.mfg.11.assembly_type")
    assert LIFECYCLE_VALUES == _operational_values("axebom.hbom.mfg.12.lifecycle_status")
