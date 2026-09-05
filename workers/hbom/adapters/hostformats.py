"""Parsers for what a hardware-inventory collector reported.

⚠ THE CUSTOMER RAN THE TOOL. AxeBOM DID NOT, AND CANNOT.

Every format here is the output of a command somebody ran on the machine they
want documented, saved to a file and uploaded. AxeBOM reaches no machine. The
same boundary `hbom-cdxgen-host` already draws, widened to the tools people
actually have: `lshw`, `dmidecode`, `fwupdmgr`, PowerShell's CIM cmdlets and a
Redfish service's own JSON.

⚠ AND WHAT THAT MEANS FOR THE RESULT, said here because the report has to say
it too: an operating system reports what it can see. A part with no driver, no
bus presence and no SMBIOS entry is absent from every one of these files, and
its absence is not evidence. A record produced this way describes a running
machine, not a product's build recipe — there is no assembly hierarchy in it
beyond what the tool chose to nest.

⚠ THE TOOLS ARE GPL, AND THAT IS NOT A PROBLEM HERE. Nothing in this module
invokes, links against, or ships any of them. It reads text the customer
produced, which carries no licence obligation whatsoever — the same reason a
CSV exported from Altium is not an Altium derivative work. See CLAUDE.md
invariant 9 for the case that WOULD matter.

Each parser is pure: bytes in, canonical nodes and diagnostics out. Selection is
by CONTENT, never by filename, because an upload legitimately holds several
files and picking by name reads the wrong one.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from ..model import HardwareComponent

#: How deep a nested report may go before nesting is refused.
#:
#: lshw nests buses under controllers and Redfish can expand collections; ten is
#: far deeper than any real machine and stops a hand-edited file from recursing
#: without bound.
MAX_NESTING = 10

#: The most nodes one report may contribute.
#:
#: A `dmidecode` dump of a large server is a few hundred blocks; lshw on a fat
#: host is similar. Five thousand is generous and bounded — an unbounded parse of
#: an uploaded file is a denial of service with extra steps.
MAX_NODES = 5_000


class Report:
    """One parsed collector report."""

    def __init__(self, tool: str, roots: list[HardwareComponent],
                 diagnostics: list[dict[str, Any]]) -> None:
        self.tool = tool
        self.roots = roots
        self.diagnostics = diagnostics


# ---------------------------------------------------------------------------
# Node construction
# ---------------------------------------------------------------------------


def _node(local_id: str, parent: str | None, level: int, **fields: Any) -> HardwareComponent:
    node = HardwareComponent(local_id=local_id, parent_local_id=parent, level=level)
    for key, value in fields.items():
        if value:
            setattr(node, key, str(value).strip())
    return node


def _text(value: Any) -> str:
    """Render a scalar, refusing the strings that MEAN absent.

    ⚠ SMBIOS AND WMI BOTH USE PLACEHOLDER TEXT FOR "the manufacturer left this
    blank": `dmidecode` prints "Not Specified" and "To Be Filled By O.E.M.",
    Windows reports "System Serial Number", and a motherboard with no serial
    ships with "Default string" burned into it. Carrying those through would
    record a serial number that is not one — and, worse, `Default string` would
    then collide across every device that has it, which is exactly what the
    unique index on serial exists to catch.
    """
    if value is None or isinstance(value, (dict, list)):
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if text.casefold() in _PLACEHOLDERS:
        return ""
    return text


_PLACEHOLDERS = frozenset(
    s.casefold()
    for s in (
        "not specified",
        "not available",
        "none",
        "n/a",
        "unknown",
        "default string",
        "to be filled by o.e.m.",
        "to be filled by oem",
        "system serial number",
        "system manufacturer",
        "system product name",
        "chassis serial number",
        "0x00000000",
        "00000000",
    )
)


# ---------------------------------------------------------------------------
# lshw --json
# ---------------------------------------------------------------------------


def looks_like_lshw(payload: Any) -> bool:
    """lshw emits one object (or, with -json on some builds, a list of them)."""
    root = payload[0] if isinstance(payload, list) and payload else payload
    if not isinstance(root, dict):
        return False
    # `class` (older) or `class` plus `id` is lshw's shape; `handle`/`capabilities`
    # confirm it against any other JSON that happens to carry an `id`.
    return "class" in root and "id" in root


def parse_lshw(payload: Any) -> Report:
    root_obj = payload[0] if isinstance(payload, list) and payload else payload
    diagnostics: list[dict[str, Any]] = []
    counter = _Counter()

    root = _lshw_node(root_obj, None, 0, counter, diagnostics)
    if root is None:
        return Report("lshw", [], diagnostics)
    return Report("lshw", [root], diagnostics)


def _lshw_node(
    obj: Any, parent: str | None, level: int, counter: _Counter,
    diagnostics: list[dict[str, Any]],
) -> HardwareComponent | None:
    if not isinstance(obj, dict) or not counter.take(diagnostics):
        return None

    local_id = f"lshw-{counter.n}"
    name = _text(obj.get("product")) or _text(obj.get("description")) or _text(obj.get("id"))
    if not name:
        return None

    node = _node(
        local_id, parent, level,
        product_name=name,
        product_version=_text(obj.get("version")),
        manufacturer_name=_text(obj.get("vendor")),
        serial_number=_text(obj.get("serial")),
        # `class` is lshw's own category — system, bus, processor, memory,
        # network. It is the most useful thing it says about what a node IS.
        technical_specification=_text(obj.get("class")),
    )

    if level < MAX_NESTING:
        for child in obj.get("children") or []:
            built = _lshw_node(child, local_id, level + 1, counter, diagnostics)
            if built is not None:
                node.children.append(built)
    elif obj.get("children"):
        diagnostics.append(_too_deep("lshw"))

    return node


# ---------------------------------------------------------------------------
# dmidecode
# ---------------------------------------------------------------------------

#: `Handle 0x0002, DMI type 2, 15 bytes`
_DMI_HANDLE = re.compile(r"^Handle\s+0x[0-9A-Fa-f]+,\s*DMI type\s+(\d+)", re.MULTILINE)

#: The SMBIOS structure types worth recording as components.
#:
#: ⚠ A DELIBERATE SUBSET. A full dump carries dozens of types, most of them
#: describing capabilities rather than parts — "BIOS Language Information",
#: "Physical Memory Array". Recording those as components would inflate a parts
#: count with rows nobody can order, price or replace.
_DMI_TYPES = {
    0: "Firmware",
    1: "System",
    2: "Baseboard",
    3: "Chassis",
    4: "Processor",
    17: "Memory module",
    39: "Power supply",
}


def looks_like_dmidecode(raw: str) -> bool:
    return bool(_DMI_HANDLE.search(raw))


def parse_dmidecode(raw: str) -> Report:
    diagnostics: list[dict[str, Any]] = []
    counter = _Counter()

    root = _node("dmi-host", None, 0, product_name="Reported host")
    blocks = _dmi_blocks(raw)

    for dmi_type, fields in blocks:
        label = _DMI_TYPES.get(dmi_type)
        if label is None:
            continue
        # ⚠ TYPE 1 IS THE MACHINE, AND IT IS THE ROOT — NOT ALSO A CHILD OF
        # ITSELF. It is promoted onto the root below; emitting it here as well
        # counted one host twice, which inflates a parts count and puts the
        # system's own serial on a component row inside itself.
        if dmi_type == 1:
            continue
        if not counter.take(diagnostics):
            break

        name = (
            _text(fields.get("Product Name"))
            or _text(fields.get("Version"))
            or _text(fields.get("Vendor"))
            or label
        )
        node = _node(
            f"dmi-{counter.n}", root.local_id, 1,
            product_name=name,
            product_version=_text(fields.get("Version")),
            manufacturer_name=_text(fields.get("Manufacturer")) or _text(fields.get("Vendor")),
            serial_number=_text(fields.get("Serial Number")),
            model_number=_text(fields.get("Part Number")) or _text(fields.get("Product Name")),
            technical_specification=label,
        )
        if dmi_type == 0:
            # SMBIOS type 0 IS the firmware record; its "Version" is the
            # firmware version, not a product revision.
            node.firmware_version = _text(fields.get("Version"))
        root.children.append(node)

    # Promote the System block's identity onto the root, so the tree is about a
    # machine rather than about an anonymous container of blocks.
    for dmi_type, fields in blocks:
        if dmi_type == 1:
            root.product_name = _text(fields.get("Product Name")) or root.product_name
            root.manufacturer_name = _text(fields.get("Manufacturer"))
            root.serial_number = _text(fields.get("Serial Number"))
            root.product_version = _text(fields.get("Version"))
            break

    return Report("dmidecode", [root], diagnostics)


def _dmi_blocks(raw: str) -> list[tuple[int, dict[str, str]]]:
    """Split a dmidecode dump into (type, fields) pairs.

    ⚠ ONLY TOP-LEVEL `Key: Value` LINES ARE TAKEN. dmidecode indents list
    members under a key — "Characteristics:" followed by several deeper lines —
    and folding those in would produce fields whose value is one arbitrary
    member of a list.
    """
    out: list[tuple[int, dict[str, str]]] = []
    current: dict[str, str] | None = None
    current_type = -1

    for line in raw.splitlines():
        handle = _DMI_HANDLE.match(line)
        if handle:
            if current is not None:
                out.append((current_type, current))
            current_type = int(handle.group(1))
            current = {}
            continue
        if current is None:
            continue
        if not line.strip():
            out.append((current_type, current))
            current = None
            continue
        # One tab or one level of indent, then `Key: Value`.
        if line.startswith(("\t", "    ")) and ":" in line:
            depth = len(line) - len(line.lstrip("\t "))
            if depth > 8:  # a list member under a key, not a field
                continue
            key, _, value = line.strip().partition(":")
            current[key.strip()] = value.strip()

    if current is not None:
        out.append((current_type, current))
    return out


# ---------------------------------------------------------------------------
# fwupdmgr get-devices --json
# ---------------------------------------------------------------------------


def looks_like_fwupd(payload: Any) -> bool:
    return isinstance(payload, dict) and isinstance(payload.get("Devices"), list)


def parse_fwupd(payload: dict[str, Any]) -> Report:
    diagnostics: list[dict[str, Any]] = []
    counter = _Counter()
    root = _node("fwupd-host", None, 0, product_name="Reported host")

    for entry in payload.get("Devices") or []:
        if not isinstance(entry, dict) or not counter.take(diagnostics):
            break
        name = _text(entry.get("Name"))
        if not name:
            continue
        node = _node(
            f"fwupd-{counter.n}", root.local_id, 1,
            product_name=name,
            manufacturer_name=_text(entry.get("Vendor")),
            serial_number=_text(entry.get("Serial")),
            product_details=_text(entry.get("Summary")),
            # ⚠ fwupd's WHOLE POINT IS THE FIRMWARE VERSION. `Version` here is
            # the firmware running on the component, not a hardware revision,
            # which is why it lands in firmware_version and not product_version.
            firmware_version=_text(entry.get("Version")),
        )
        root.children.append(node)

    return Report("fwupd", [root], diagnostics)


# ---------------------------------------------------------------------------
# Redfish
# ---------------------------------------------------------------------------


def looks_like_redfish(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    return any(k.startswith("@odata.") for k in payload)


def parse_redfish(payload: dict[str, Any]) -> Report:
    diagnostics: list[dict[str, Any]] = []
    counter = _Counter()

    # A Systems collection, or one system.
    members = payload.get("Members")
    systems = [m for m in members if isinstance(m, dict)] if isinstance(members, list) else [payload]

    roots: list[HardwareComponent] = []
    for system in systems:
        if not counter.take(diagnostics):
            break
        name = (
            _text(system.get("Model"))
            or _text(system.get("Name"))
            or _text(system.get("Id"))
        )
        if not name:
            continue
        root = _node(
            f"redfish-{counter.n}", None, 0,
            product_name=name,
            manufacturer_name=_text(system.get("Manufacturer")),
            serial_number=_text(system.get("SerialNumber")),
            model_number=_text(system.get("PartNumber")) or _text(system.get("SKU")),
            product_version=_text(system.get("Version")),
            technical_specification=_text(system.get("SystemType")),
        )
        _redfish_children(system, root, counter, diagnostics)
        roots.append(root)

    return Report("redfish", roots, diagnostics)


def _redfish_children(
    system: dict[str, Any], root: HardwareComponent, counter: _Counter,
    diagnostics: list[dict[str, Any]],
) -> None:
    """Take whichever collections the export happened to expand.

    ⚠ AN UNEXPANDED COLLECTION IS A LINK, NOT A LIST. Redfish returns
    `{"@odata.id": "/redfish/v1/Systems/1/Processors"}` unless the caller asked
    for `$expand`. Following it would mean AxeBOM talking to a BMC, which it
    does not do — so an unexpanded collection contributes nothing and says so.
    """
    for key in ("Processors", "Memory", "Storage", "NetworkInterfaces", "PowerSupplies"):
        block = system.get(key)
        entries = block.get("Members") if isinstance(block, dict) else block
        if not isinstance(entries, list):
            if isinstance(block, dict) and "@odata.id" in block:
                diagnostics.append(
                    {
                        "severity": "info",
                        "code": "HBOM_HOST_COLLECTION_NOT_EXPANDED",
                        "message": f"the {key} collection is a link, not a list, so it "
                        "contributed no components",
                        "hint": "re-export with Redfish's $expand so the members are "
                        "included; AxeBOM does not call your BMC to follow the link",
                    }
                )
            continue
        for entry in entries:
            if not isinstance(entry, dict) or not counter.take(diagnostics):
                break
            name = _text(entry.get("Model")) or _text(entry.get("Name"))
            if not name:
                continue
            root.children.append(
                _node(
                    f"redfish-{counter.n}", root.local_id, 1,
                    product_name=name,
                    manufacturer_name=_text(entry.get("Manufacturer")),
                    serial_number=_text(entry.get("SerialNumber")),
                    model_number=_text(entry.get("PartNumber")),
                    firmware_version=_text(entry.get("FirmwareVersion")),
                    technical_specification=key,
                )
            )


# ---------------------------------------------------------------------------
# Windows — Get-CimInstance / Get-ComputerInfo, piped through ConvertTo-Json
# ---------------------------------------------------------------------------

#: Keys PowerShell adds to every CIM object it serialises.
_CIM_MARKERS = ("CimClass", "CimInstanceProperties", "PSComputerName", "__CLASS")


def looks_like_wmi(payload: Any) -> bool:
    entries = payload if isinstance(payload, list) else [payload]
    for entry in entries:
        if isinstance(entry, dict) and any(m in entry for m in _CIM_MARKERS):
            return True
    return False


def parse_wmi(payload: Any) -> Report:
    diagnostics: list[dict[str, Any]] = []
    counter = _Counter()
    entries = payload if isinstance(payload, list) else [payload]

    root = _node("wmi-host", None, 0, product_name="Reported host")
    for entry in entries:
        if not isinstance(entry, dict) or not counter.take(diagnostics):
            break
        name = (
            _text(entry.get("Model"))
            or _text(entry.get("Name"))
            or _text(entry.get("Caption"))
            or _text(entry.get("Product"))
        )
        if not name:
            continue
        node = _node(
            f"wmi-{counter.n}", root.local_id, 1,
            product_name=name,
            manufacturer_name=_text(entry.get("Manufacturer")) or _text(entry.get("Vendor")),
            serial_number=_text(entry.get("SerialNumber")) or _text(entry.get("SerialNumber")),
            model_number=_text(entry.get("PartNumber")) or _text(entry.get("Model")),
            product_version=_text(entry.get("Version")),
            technical_specification=_text(_cim_class(entry)),
        )
        root.children.append(node)

    # Win32_ComputerSystem is the machine itself; promote it onto the root.
    for entry in entries:
        if isinstance(entry, dict) and "ComputerSystem" in str(_cim_class(entry)):
            root.product_name = _text(entry.get("Model")) or root.product_name
            root.manufacturer_name = _text(entry.get("Manufacturer"))
            break

    return Report("wmi", [root], diagnostics)


def _cim_class(entry: dict[str, Any]) -> str:
    raw = entry.get("CimClass") or entry.get("__CLASS") or ""
    if isinstance(raw, dict):
        return str(raw.get("CimClassName") or "")
    return str(raw)


# ---------------------------------------------------------------------------
# axebom collect hardware — our own collector
# ---------------------------------------------------------------------------


def looks_like_axebom_collect(payload: Any) -> bool:
    return isinstance(payload, dict) and "axebom_hbom" in payload and "root" in payload


def parse_axebom_collect(payload: dict[str, Any]) -> Report:
    """Read what `axebom collect hardware` wrote on the customer's machine.

    ⚠ THE ONE FORMAT WHERE BOTH ENDS ARE OURS, so the mapping is exact rather
    than a best guess at somebody else's shape — and the one that can tell us
    what it FAILED to read. lshw and dmidecode simply omit a root-only field;
    our collector records the path and the reason, and that difference is the
    whole point: a serial nobody could read and a serial that does not exist are
    different facts, and only one of them is fixed by re-running with sudo.
    """
    diagnostics: list[dict[str, Any]] = []
    counter = _Counter()

    collector = payload.get("collector") if isinstance(payload.get("collector"), dict) else {}
    root_obj = payload.get("root")
    if not isinstance(root_obj, dict):
        return Report("axebom-collect", [], diagnostics)

    root = _collect_node(root_obj, None, 0, counter, diagnostics)
    if root is None:
        return Report("axebom-collect", [], diagnostics)

    disclosure = str(collector.get("disclosure") or "")
    if disclosure:
        root.product_details = (root.product_details + " " + disclosure).strip()

    unreadable = payload.get("unreadable")
    if isinstance(unreadable, list) and unreadable:
        # ⚠ SURFACED, NOT DROPPED. Without this the report shows a blank serial
        # and a reader concludes the machine has none — when in fact nobody had
        # permission to look. Invariant 12, applied to a collector's own limits.
        paths = ", ".join(
            str(u.get("path")) for u in unreadable if isinstance(u, dict) and u.get("path")
        )
        diagnostics.append(
            {
                "severity": "info",
                "code": "HBOM_HOST_REPORT_FIELDS_UNREADABLE",
                "message": f"{len(unreadable)} file(s) could not be read by the collector, "
                f"so the fields they hold are absent: {paths}",
                "hint": "re-run `axebom collect hardware` with more privilege to include "
                "them; a field nobody could read is not the same as a field that is empty",
            }
        )

    if not collector.get("privileged"):
        diagnostics.append(
            {
                "severity": "info",
                "code": "HBOM_HOST_REPORT_UNPRIVILEGED",
                "message": "the collector ran unprivileged",
                "hint": "SMBIOS serial numbers are root-readable only, so they are absent "
                "from this inventory rather than empty on the machine",
            }
        )

    return Report("axebom-collect", [root], diagnostics)


_COLLECT_FIELDS = (
    "product_name",
    "product_version",
    "manufacturer_name",
    "serial_number",
    "model_number",
    "firmware_version",
    "technical_specification",
)


def _collect_node(
    obj: dict[str, Any], parent: str | None, level: int, counter: _Counter,
    diagnostics: list[dict[str, Any]],
) -> HardwareComponent | None:
    if not counter.take(diagnostics):
        return None
    name = _text(obj.get("product_name"))
    if not name:
        return None

    node = _node(
        f"collect-{counter.n}", parent, level,
        **{f: _text(obj.get(f)) for f in _COLLECT_FIELDS},
    )

    if level < MAX_NESTING:
        for child in obj.get("children") or []:
            if isinstance(child, dict):
                built = _collect_node(child, node.local_id, level + 1, counter, diagnostics)
                if built is not None:
                    node.children.append(built)
    elif obj.get("children"):
        diagnostics.append(_too_deep("axebom-collect"))

    return node


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


class _Counter:
    """Counts nodes and refuses past MAX_NODES, once, with a diagnostic.

    ⚠ THE CAP IS REPORTED, NEVER SILENT. A parts list truncated without saying
    so is the false-negative class invariant 12 exists to prevent — the reader
    would take a partial inventory for a complete one.
    """

    def __init__(self) -> None:
        self.n = 0
        self._warned = False

    def take(self, diagnostics: list[dict[str, Any]]) -> bool:
        if self.n >= MAX_NODES:
            if not self._warned:
                self._warned = True
                diagnostics.append(
                    {
                        "severity": "warn",
                        "code": "HBOM_HOST_REPORT_TRUNCATED",
                        "message": f"the report declared more than {MAX_NODES} entries; "
                        "the rest were not read",
                        "hint": "the count in this report is a floor, not a total",
                    }
                )
            return False
        self.n += 1
        return True


def _too_deep(tool: str) -> dict[str, Any]:
    return {
        "severity": "warn",
        "code": "HBOM_HOST_REPORT_TOO_DEEP",
        "message": f"the {tool} report nests deeper than {MAX_NESTING} levels; "
        "the deeper entries were not read",
    }


#: Every parser, in the order they are tried.
#:
#: ⚠ CONTENT DECIDES, NOT THE FILENAME. An upload legitimately holds several
#: files — an lshw dump beside a dmidecode one is exactly what somebody
#: documenting a server produces — and picking by name would read the wrong one.
_JSON_PARSERS: tuple[tuple[str, Callable[[Any], bool], Callable[[Any], Report]], ...] = (
    # ⚠ OURS FIRST. It carries an explicit `axebom_hbom` marker, so it can never
    # be mistaken for another format — and putting it first means a document
    # that IS ours is never read by a looser sniffer further down.
    ("axebom-collect", looks_like_axebom_collect, parse_axebom_collect),
    ("fwupd", looks_like_fwupd, parse_fwupd),
    ("wmi", looks_like_wmi, parse_wmi),
    ("redfish", looks_like_redfish, parse_redfish),
    ("lshw", looks_like_lshw, parse_lshw),
)


def parse(raw: bytes) -> Report | None:
    """Parse one uploaded file, or return None when no parser recognises it."""
    try:
        text = raw.decode("utf-8", errors="replace")
    except (UnicodeDecodeError, AttributeError):
        return None

    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return None
        for _, matches, parser in _JSON_PARSERS:
            if matches(payload):
                return parser(payload)
        return None

    if looks_like_dmidecode(text):
        return parse_dmidecode(text)
    return None


#: The tools this engine reads, published so an empty result can name them.
SUPPORTED_TOOLS = (
    "axebom collect hardware",
    "lshw --json",
    "dmidecode",
    "fwupdmgr get-devices --json",
    "Get-CimInstance | ConvertTo-Json",
    "Redfish JSON",
)
