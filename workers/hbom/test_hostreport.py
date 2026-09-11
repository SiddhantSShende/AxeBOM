"""hbom-host-report: the five collector formats, and what each one cannot say."""

from __future__ import annotations

import json
from pathlib import Path

from axebom_shared.adapters.base import ResultStatus, ScanTarget

from .adapters import hostformats
from .adapters.hostreport import HostReportAdapter


def _target(tmp_path: Path) -> ScanTarget:
    return ScanTarget(
        scan_id="01900000-0000-7000-8000-0000000000s1",
        job_id="01900000-0000-7000-8000-0000000000j1",
        kind="upload",
        workspace=tmp_path,
        root_subpath="",
    )


# ---------------------------------------------------------------------------
# Format sniffing — content, never filename
# ---------------------------------------------------------------------------


def test_each_format_is_recognised_by_its_content() -> None:
    """⚠ THE FILENAME IS NEVER CONSULTED, AND THAT IS THE POINT.

    An upload holding an lshw dump beside a dmidecode one is exactly what
    somebody documenting a server produces, and `report.json` is as likely to be
    a test report as an inventory. Every file below is named `x` on purpose.
    """
    cases = {
        "lshw": json.dumps({"id": "host", "class": "system", "product": "X1"}),
        "fwupd": json.dumps({"Devices": [{"Name": "System Firmware", "Version": "1.0"}]}),
        "redfish": json.dumps({"@odata.type": "#ComputerSystem.v1_5_0", "Model": "R640"}),
        "wmi": json.dumps(
            [{"CimClass": {"CimClassName": "Win32_ComputerSystem"}, "Model": "L7420"}]
        ),
        "dmidecode": "Handle 0x0001, DMI type 1, 27 bytes\nSystem Information\n\tProduct Name: T14\n",
    }
    for want, raw in cases.items():
        report = hostformats.parse(raw.encode())
        assert report is not None, f"{want} was not recognised"
        assert report.tool == want


def test_a_file_no_parser_recognises_is_none_not_an_exception() -> None:
    """A JSON file that is simply something else must not be forced into a shape."""
    assert hostformats.parse(b'{"hello": "world"}') is None
    assert hostformats.parse(b"not json at all") is None
    assert hostformats.parse(b"") is None


# ---------------------------------------------------------------------------
# The placeholder problem
# ---------------------------------------------------------------------------


def test_smbios_placeholder_text_is_not_recorded_as_a_serial_number() -> None:
    """⚠ THE SINGLE MOST CONSEQUENTIAL ASSERTION IN THIS FILE.

    SMBIOS and WMI both use placeholder TEXT for "the manufacturer left this
    blank": `Default string`, `To Be Filled By O.E.M.`, `System Serial Number`.
    Carrying one through records a serial number that is not one — and, worse,
    every device shipped with `Default string` would then COLLIDE on the unique
    index that exists to catch one unit registered twice.
    """
    raw = json.dumps(
        {
            "id": "host",
            "class": "system",
            "product": "Board",
            "serial": "Default string",
            "vendor": "To Be Filled By O.E.M.",
        }
    )
    report = hostformats.parse(raw.encode())
    assert report is not None
    root = report.roots[0]
    assert root.serial_number == "", f"a placeholder was recorded: {root.serial_number!r}"
    assert root.manufacturer_name == ""


# ---------------------------------------------------------------------------
# Per-format shape
# ---------------------------------------------------------------------------


def test_dmidecode_promotes_the_system_block_and_does_not_also_nest_it() -> None:
    """⚠ ONE MACHINE, COUNTED ONCE.

    SMBIOS type 1 IS the machine. Emitting it as a child of itself as well as
    promoting it onto the root inflated the parts count and put the system's own
    serial on a component row inside itself.
    """
    raw = (
        "Handle 0x0001, DMI type 1, 27 bytes\n"
        "System Information\n"
        "\tManufacturer: LENOVO\n"
        "\tProduct Name: 20KH006JMH\n"
        "\tSerial Number: PF0BBB\n"
        "\n"
        "Handle 0x0002, DMI type 17, 40 bytes\n"
        "Memory Device\n"
        "\tManufacturer: Samsung\n"
        "\tPart Number: M471A2K43CB1\n"
    )
    report = hostformats.parse(raw.encode())
    assert report is not None
    root = report.roots[0]

    assert root.product_name == "20KH006JMH"
    assert root.serial_number == "PF0BBB"
    assert len(root.children) == 1, [c.product_name for c in root.children]
    assert root.children[0].model_number == "M471A2K43CB1"


def test_fwupd_versions_are_firmware_versions_not_product_revisions() -> None:
    """fwupd's whole subject is the firmware running on a component."""
    raw = json.dumps({"Devices": [{"Name": "UEFI dbx", "Vendor": "UEFI", "Version": "371"}]})
    report = hostformats.parse(raw.encode())
    assert report is not None
    child = report.roots[0].children[0]
    assert child.firmware_version == "371"
    assert child.product_version == ""


def test_an_unexpanded_redfish_collection_contributes_nothing_and_says_so() -> None:
    """⚠ A LINK IS NOT A LIST, AND AxeBOM DOES NOT FOLLOW IT.

    Redfish returns `{"@odata.id": "…/Processors"}` unless the caller asked for
    $expand. Following it would mean AxeBOM talking to a BMC, which it does not
    do — so the collection contributes nothing, and the report says why rather
    than leaving a reader to conclude the machine has no processors.
    """
    raw = json.dumps(
        {
            "@odata.type": "#ComputerSystem.v1_5_0.ComputerSystem",
            "Model": "PowerEdge R640",
            "Manufacturer": "Dell",
            "Processors": {"@odata.id": "/redfish/v1/Systems/1/Processors"},
        }
    )
    report = hostformats.parse(raw.encode())
    assert report is not None
    assert report.roots[0].children == []
    codes = [d["code"] for d in report.diagnostics]
    assert "HBOM_HOST_COLLECTION_NOT_EXPANDED" in codes


def test_an_expanded_redfish_collection_becomes_components() -> None:
    raw = json.dumps(
        {
            "@odata.id": "/redfish/v1/Systems/1",
            "Model": "PowerEdge R640",
            "Memory": {
                "Members": [
                    {"Name": "DIMM A1", "Manufacturer": "Hynix", "PartNumber": "HMA84GR7"},
                ]
            },
        }
    )
    report = hostformats.parse(raw.encode())
    assert report is not None
    assert [c.model_number for c in report.roots[0].children] == ["HMA84GR7"]


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------


def test_a_report_beyond_the_node_cap_is_truncated_with_a_diagnostic() -> None:
    """⚠ A TRUNCATED PARTS LIST THAT DOES NOT SAY SO IS THE FALSE NEGATIVE
    invariant 12 EXISTS TO PREVENT. The reader would take a partial inventory
    for a complete one.
    """
    devices = [{"Name": f"dev-{i}"} for i in range(hostformats.MAX_NODES + 50)]
    report = hostformats.parse(json.dumps({"Devices": devices}).encode())
    assert report is not None
    assert len(report.roots[0].children) <= hostformats.MAX_NODES
    assert "HBOM_HOST_REPORT_TRUNCATED" in [d["code"] for d in report.diagnostics]


def test_deep_nesting_is_refused_with_a_diagnostic_rather_than_recursing() -> None:
    node: dict = {"id": "leaf", "class": "bus", "product": "leaf"}
    for i in range(hostformats.MAX_NESTING + 5):
        node = {"id": f"n{i}", "class": "bus", "product": f"n{i}", "children": [node]}
    report = hostformats.parse(json.dumps(node).encode())
    assert report is not None
    assert "HBOM_HOST_REPORT_TOO_DEEP" in [d["code"] for d in report.diagnostics]


# ---------------------------------------------------------------------------
# The adapter
# ---------------------------------------------------------------------------


def test_an_upload_with_no_report_is_unavailable_and_names_what_was_wanted(tmp_path) -> None:
    """⚠ THE HINT HAS TO NAME THE TOOLS, because the customer cannot guess.

    An `unavailable` with no instruction reads as a broken feature. The whole
    point of this engine is that the customer runs something themselves.
    """
    (tmp_path / "readme.txt").write_text("nothing useful here")
    result = HostReportAdapter().generate(_target(tmp_path))

    assert result.status is ResultStatus.UNAVAILABLE
    hint = " ".join(str(d.get("hint", "")) for d in result.diagnostics)
    assert "lshw" in hint and "dmidecode" in hint
    assert "cannot reach" in hint


def test_a_parsed_report_succeeds_and_stamps_its_provenance(tmp_path) -> None:
    """Every row says which tool produced it, and the root says what that means."""
    (tmp_path / "inventory.json").write_text(
        json.dumps(
            {
                "id": "host",
                "class": "system",
                "product": "PowerEdge R640",
                "vendor": "Dell",
                "children": [
                    {"id": "cpu", "class": "processor", "product": "Xeon Gold 6130"},
                    {"id": "mem", "class": "memory", "product": "32GiB DIMM"},
                ],
            }
        )
    )
    result = HostReportAdapter().generate(_target(tmp_path))

    assert result.status is ResultStatus.SUCCEEDED
    assert result.ecosystems_covered == ["hardware"]
    codes = [d["code"] for d in result.diagnostics]
    assert "HBOM_HOST_REPORT_PARSED" in codes


def test_a_report_naming_only_the_machine_is_partial_not_succeeded(tmp_path) -> None:
    """⚠ ZERO IS A CLAIM. A silent zero cannot be told apart from a file whose
    shape was not understood, so it is reported as partial with a reason.
    """
    (tmp_path / "x.json").write_text(json.dumps({"id": "host", "class": "system", "product": "PC"}))
    result = HostReportAdapter().generate(_target(tmp_path))

    assert result.status is ResultStatus.PARTIAL
    assert "ENGINE_ZERO_RESULTS" in [d["code"] for d in result.diagnostics]


def test_a_symlink_is_skipped_rather_than_followed(tmp_path) -> None:
    """⚠ SKIPPED, NOT RESOLVED-AND-CHECKED. Resolving first and comparing paths
    afterwards is the classic TOCTOU shape; an inventory report that is a
    symlink has no legitimate meaning here.
    """
    secret = tmp_path / "outside.json"
    secret.write_text(json.dumps({"id": "host", "class": "system", "product": "Leaked"}))
    link = tmp_path / "sub" / "link.json"
    link.parent.mkdir()
    link.symlink_to(secret)

    result = HostReportAdapter().generate(_target(tmp_path / "sub"))
    assert result.status is ResultStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# `axebom collect hardware` — the one format where both ends are ours
# ---------------------------------------------------------------------------


def _collector_output(**overrides) -> str:
    doc = {
        "axebom_hbom": "axebom-hbom-json-1",
        "collector": {
            "name": "axebom collect hardware",
            "os": "linux",
            "privileged": False,
            "disclosure": "Produced on this machine by its operator.",
        },
        "root": {
            "product_name": "Standard PC",
            "manufacturer_name": "QEMU",
            "technical_specification": "system",
            "children": [
                {"product_name": "Xeon Platinum 8173M", "technical_specification": "processor"},
            ],
        },
        "unreadable": [
            {"path": "/sys/class/dmi/id/product_serial", "reason": "permission denied"},
        ],
    }
    doc.update(overrides)
    return json.dumps(doc)


def test_the_collectors_own_output_round_trips() -> None:
    report = hostformats.parse(_collector_output().encode())
    assert report is not None
    assert report.tool == "axebom-collect"
    root = report.roots[0]
    assert root.product_name == "Standard PC"
    assert [c.product_name for c in root.children] == ["Xeon Platinum 8173M"]
    assert "Produced on this machine by its operator." in root.product_details


def test_a_field_nobody_could_read_is_reported_not_left_blank() -> None:
    """⚠ THE DIFFERENCE THIS WHOLE COLLECTOR EXISTS TO PRESERVE.

    SMBIOS serial numbers are root-readable only. lshw and dmidecode simply omit
    them when unprivileged, so a reader sees a blank and concludes the machine
    has no serial. Our collector records the path and the reason, and this turns
    that into a diagnostic — because "nobody had permission to look" is fixed by
    re-running with sudo, and "there is no serial" is not.
    """
    report = hostformats.parse(_collector_output().encode())
    assert report is not None
    codes = [d["code"] for d in report.diagnostics]
    assert "HBOM_HOST_REPORT_FIELDS_UNREADABLE" in codes
    assert "HBOM_HOST_REPORT_UNPRIVILEGED" in codes

    joined = " ".join(str(d.get("message", "")) for d in report.diagnostics)
    assert "/sys/class/dmi/id/product_serial" in joined


def test_a_privileged_run_does_not_carry_the_unprivileged_caveat() -> None:
    """The caveat has to be absent when it does not apply, or it is noise people
    learn to skip — and then miss on the run where it mattered."""
    raw = _collector_output(
        collector={"name": "axebom collect hardware", "os": "linux", "privileged": True},
        unreadable=[],
    )
    report = hostformats.parse(raw.encode())
    assert report is not None
    assert report.diagnostics == []
