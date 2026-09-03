"""hbom-cdxgen-host — a host inventory the CUSTOMER produced, imported.

⚠ AxeBOM NEVER TOUCHES THE DEVICE, AND NEVER CLAIMS TO HAVE.

`cdxgen -t hbom` inventories the machine it runs on — board, firmware, TPM,
storage controllers, network interfaces — and emits CycloneDX 1.7. That is a
real, useful hardware record, and it is one the customer generates themselves,
on the device they want documented, and uploads. Running cdxgen inside our own
sandbox would inventory AxeBOM's container host and present it as the
customer's hardware, which is why this is an upload path and never a container
engine (see the registry entry for this id).

`RequiresImport: true` states exactly that as data — the same claim
`github-dependency-graph-sbom` makes about a document GitHub published.

⚠ WHAT THIS CANNOT SEE, said plainly because the report has to say it too: a
host inventory describes the machine the customer ran the tool on. It is not
the bill of materials of a product they manufacture, it carries no assembly
hierarchy beyond what the tool reported, and it says nothing about parts that
are not visible to the operating system.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from axebom_shared.adapters.base import (
    Availability,
    Capabilities,
    EngineMode,
    GenerateResult,
    RawArtifact,
    ResultStatus,
    ScanTarget,
    ToolAdapterBase,
)
from axebom_shared.adapters.summary import summarize

# ⚠ ABSOLUTE, NOT `from ...sbom.adapters.common`. `workers` has no
# __init__.py — it is a namespace package — so a three-level relative import
# resolves at runtime (the image sets WORKDIR /app) and raises
# "attempted relative import beyond top-level package" under pytest's
# rootdir-based collection. An import that works in production and breaks in
# the test runner is the worst of both: the tests that would catch a bug here
# cannot even be collected.
from workers.sbom.adapters.common import ArtifactWriter
from ..model import HardwareComponent, normalize
from . import discovery

CAPABILITIES = Capabilities(
    engine_id="hbom-cdxgen-host",
    families=("hbom",),
    source_kinds=("upload",),
    produces=("hardware_components",),
    native_format="cyclonedx-json-1.7",
    ecosystems=("hardware",),
    db_backed=False,
    default_weight=2,
)

#: CycloneDX component types that describe hardware.
_HARDWARE_TYPES = frozenset({"device", "device-driver", "firmware", "platform"})

#: How deep a nested `components` array may go. cdxgen nests buses under
#: controllers; ten is far deeper than any real host and stops a hand-crafted
#: document from recursing without bound.
_MAX_NESTING = 10


class CdxgenHostHBOMAdapter(ToolAdapterBase):
    """Reads a customer-produced CycloneDX hardware inventory."""

    media_type = "application/json"

    def __init__(self, *, artifact_dir: Any = None, **_: Any) -> None:
        super().__init__(CAPABILITIES)
        self._artifact_dir = artifact_dir

    def available(self) -> Availability:
        return Availability(available=True, mode=EngineMode.INTERNAL)

    def generate(self, target: ScanTarget) -> GenerateResult:
        """Find and parse an uploaded CycloneDX hardware document.

        Never raises. A missing, unreadable, non-JSON or non-hardware document
        is a status plus a diagnostic naming what was looked for.
        """
        document, raw, path, diagnostics = _locate(Path(target.workspace), target.root_subpath)
        if document is None:
            return GenerateResult(
                status=ResultStatus.UNAVAILABLE,
                diagnostics=[
                    *diagnostics,
                    {
                        "severity": "warn",
                        "code": "ENGINE_INPUT_MISSING",
                        "message": "no CycloneDX hardware document was found in this upload",
                        "hint": "generate one on the device you want documented with "
                        "`cdxgen -t hbom -o hbom.json` and upload that file. AxeBOM does "
                        "not run cdxgen against your hardware — it cannot reach it.",
                    },
                ],
            )

        spec = str(document.get("specVersion") or "")
        if spec and spec not in ("1.6", "1.7"):
            # ⚠ RECORDED, NOT REFUSED. The hardware component types this reads
            # exist across 1.4+; an unexpected version is worth saying out loud
            # in case a field moved, but refusing a document a customer's own
            # tool produced would be worse than parsing it defensively.
            diagnostics.append(
                {
                    "severity": "info",
                    "code": "HBOM_CDX_SPEC_VERSION_UNEXPECTED",
                    "message": f"the document declares CycloneDX {spec}; "
                    "cdxgen writes 1.7 for `-t hbom`",
                    "hint": "parsed anyway — the hardware component types are stable "
                    "across versions; the version is recorded so a reader knows which "
                    "shape was read",
                }
            )

        roots = _to_tree(document, path, spec)
        # The raw artifact is the customer's document BYTE FOR BYTE. A
        # re-serialized copy is no longer the evidence they supplied, and
        # evidence is what a raw artifact is (ADR-0003).
        artifact = self._write_artifact(raw)
        count = sum(r.count() for r in roots)

        if count <= 1:
            return GenerateResult(
                status=ResultStatus.PARTIAL,
                artifacts=[artifact] if artifact else [],
                ecosystems_covered=["hardware"],
                summary=summarize(self.capabilities, {"components": 0}),
                diagnostics=[
                    *diagnostics,
                    {
                        "severity": "warn",
                        "code": "ENGINE_ZERO_RESULTS",
                        "message": "the document declared no hardware components",
                        "hint": "reported as partial rather than succeeded: zero is a "
                        "claim, and a silent zero is indistinguishable from a document "
                        "whose shape we did not understand",
                    },
                ],
            )

        return GenerateResult(
            status=ResultStatus.SUCCEEDED,
            artifacts=[artifact] if artifact else [],
            ecosystems_covered=["hardware"],
            summary=summarize(self.capabilities, {"components": count}),
            diagnostics=diagnostics,
        )

    def _write_artifact(self, raw: bytes) -> RawArtifact | None:
        if self._artifact_dir is None:
            return None
        try:
            return ArtifactWriter(output_dir=self._artifact_dir).write(
                "hbom-cdxgen-host.json", raw, self.media_type
            )
        except OSError:
            return None


def _locate(
    root: Path, subpath: str
) -> tuple[dict[str, Any] | None, bytes, str, list[dict[str, Any]]]:
    """Find the first CycloneDX document in the upload that describes hardware.

    ⚠ CONTENT DECIDES, NOT THE FILENAME. An upload may hold several JSON files
    — an SBOM and an HBOM side by side is the normal case for somebody
    documenting a device. Picking by name would read the wrong one and report a
    software inventory as hardware.
    """
    diagnostics: list[dict[str, Any]] = []
    base = (root / subpath) if subpath else root
    if not base.is_dir():
        return None, b"", "", diagnostics

    for path in sorted(base.rglob("*.json")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            if path.stat().st_size > discovery.MAX_FILE_BYTES:
                continue
            raw = path.read_bytes()
        except OSError:
            continue

        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        if str(payload.get("bomFormat") or "") != "CycloneDX":
            continue
        if not _describes_hardware(payload):
            diagnostics.append(
                {
                    "severity": "info",
                    "code": "HBOM_CDX_NOT_HARDWARE",
                    "message": f"{path.name} is a CycloneDX document but declares no "
                    "hardware components; skipped",
                }
            )
            continue
        return payload, raw, path.name, diagnostics

    return None, b"", "", diagnostics


def _describes_hardware(payload: dict[str, Any]) -> bool:
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        component = metadata.get("component")
        if isinstance(component, dict) and str(component.get("type") or "") in _HARDWARE_TYPES:
            return True
    return any(
        str(c.get("type") or "") in _HARDWARE_TYPES
        for c in payload.get("components") or []
        if isinstance(c, dict)
    )


def _to_tree(payload: dict[str, Any], filename: str, spec: str) -> list[HardwareComponent]:
    """Map a CycloneDX hardware document onto the canonical tree."""
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    meta_component = metadata.get("component") if isinstance(metadata, dict) else None

    root = HardwareComponent(local_id="host", level=0)
    if isinstance(meta_component, dict):
        _apply(root, meta_component)
    if not root.product_name:
        # ⚠ NOT INVENTED. The document did not name the host, so the row says
        # what it IS — a self-reported inventory — rather than a made-up
        # device name that would read as a fact.
        root.product_name = "Reported host"
    root.product_details = (
        root.product_details
        or f"Self-reported host inventory, imported from {filename}"
        + (f" (CycloneDX {spec})" if spec else "")
    ) + ". Generated by the customer on the device itself; AxeBOM did not inspect any hardware."

    index = 0
    for component in payload.get("components") or []:
        if not isinstance(component, dict):
            continue
        child = _build_node(component, root.local_id, 1, index)
        if child is not None:
            index += 1
            root.children.append(child)

    return [normalize(root)]


def _build_node(
    component: dict[str, Any], parent_local_id: str, level: int, index: int
) -> HardwareComponent | None:
    if str(component.get("type") or "") not in _HARDWARE_TYPES:
        return None
    node = HardwareComponent(
        local_id=f"{parent_local_id}-{index}",
        parent_local_id=parent_local_id,
        level=level,
    )
    _apply(node, component)
    if not node.product_name:
        return None

    if level < _MAX_NESTING:
        child_index = 0
        for nested in component.get("components") or []:
            if not isinstance(nested, dict):
                continue
            child = _build_node(nested, node.local_id, level + 1, child_index)
            if child is not None:
                child_index += 1
                node.children.append(child)
    return node


def _apply(node: HardwareComponent, component: dict[str, Any]) -> None:
    """Copy one CycloneDX component's fields onto a canonical node.

    ⚠ NOTHING IS INVENTED AND NOTHING IS INFERRED. A field the document does
    not state stays empty, and empty becomes an explicit `not-provided` at
    normalization — reported, never silently omitted (invariant 3).
    """
    node.product_name = _text(component.get("name"))
    node.product_version = _text(component.get("version"))
    node.product_details = _text(component.get("description"))
    node.manufacturer_name = _org(component.get("manufacturer")) or _text(
        component.get("publisher")
    )
    node.supplier_info = _org(component.get("supplier"))
    node.serial_number = _text(component.get("serialNumber"))

    # CycloneDX 1.6+ carries a `modelCard`-style `modelNumber` on hardware; a
    # `cpe` is also common on device components.
    node.model_number = _text(component.get("modelNumber")) or _text(component.get("mpn"))

    if str(component.get("type") or "") == "firmware":
        node.firmware_version = node.product_version

    specs: list[str] = []
    for prop in component.get("properties") or []:
        if not isinstance(prop, dict):
            continue
        name, value = _text(prop.get("name")), _text(prop.get("value"))
        if not name or not value:
            continue
        lowered = name.lower()
        if lowered.endswith("serialnumber") and not node.serial_number:
            node.serial_number = value
        elif lowered.endswith("firmwareversion") and not node.firmware_version:
            node.firmware_version = value
        elif lowered.endswith(("model", "modelnumber")) and not node.model_number:
            node.model_number = value
        elif lowered.endswith("vendor") and not node.manufacturer_name:
            node.manufacturer_name = value
        else:
            # ⚠ EVERYTHING ELSE IS KEPT. cdxgen reports storage wear, link
            # speeds, TPM versions and much more as properties; discarding
            # what our vocabulary does not name would lose most of what makes
            # a host inventory worth having.
            specs.append(f"{name}: {value}")
    if specs:
        node.technical_specification = "; ".join(sorted(specs))

    for ref in component.get("externalReferences") or []:
        if isinstance(ref, dict) and _text(ref.get("type")) == "documentation":
            node.datasheet_url = node.datasheet_url or _text(ref.get("url"))


def _org(value: Any) -> str:
    """CycloneDX writes an organizational entity as an object, or a bare
    string in older documents. Both are read; neither is guessed at."""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        return _text(value.get("name"))
    return ""


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""
