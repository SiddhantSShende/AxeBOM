"""hbom-host-report — a hardware inventory the CUSTOMER's machine reported.

⚠ AxeBOM NEVER REACHES THE MACHINE, AND NEVER CLAIMS TO HAVE.

`hbom-cdxgen-host` already reads one such format: a CycloneDX document from
`cdxgen -t hbom`. This engine reads the tools people actually have installed —
`lshw`, `dmidecode`, `fwupdmgr`, PowerShell's CIM cmdlets, and a Redfish
service's own JSON — because requiring one specific tool means most customers
have nothing to upload.

⚠ ONE ENGINE, FIVE PARSERS, AND THAT IS DELIBERATE.

`policy.Registry.Resolve` fans out one job per engine. Five engines over one
upload would put four `unavailable` rows in the Engine Coverage section of a
customer who ran one tool — reading as four broken things rather than one
working one. `hbom-ecad` already dispatches internally to its KiCad and
BOM-table parsers for the same reason. Which parser matched is recorded as a
diagnostic and on every component's `source_engine`.

⚠ WHAT A REPORT LIKE THIS CANNOT SEE, said plainly because the report says it
too: an operating system reports what it can see. A part with no driver, no bus
presence and no SMBIOS entry appears in none of these files, and its absence is
not evidence of anything. Nor is a running machine a product's build recipe —
there is no assembly structure here beyond what the tool chose to nest.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

# ⚠ ABSOLUTE, NOT RELATIVE — see cdxgen_host.py's import comment. `workers` is
# a namespace package, so a three-level relative import resolves in the image
# and breaks under pytest collection.
from workers.sbom.adapters.common import ArtifactWriter

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

from ..model import HardwareComponent, normalize
from . import discovery, hostformats

CAPABILITIES = Capabilities(
    engine_id="hbom-host-report",
    families=("hbom",),
    # ⚠ upload ONLY. There is no git source for this: a collector's output is
    # something a person ran and saved, not something a repository contains.
    source_kinds=("upload",),
    produces=("hardware_components",),
    native_format="axebom-hbom-json-1",
    ecosystems=("hardware",),
    db_backed=False,
    default_weight=2,
)

#: Files worth opening. Everything else in an upload is skipped unread.
_SUFFIXES = (".json", ".txt", ".log", ".out", ".dmi")


class HostReportAdapter(ToolAdapterBase):
    """Parses a hardware inventory the customer's own machine produced."""

    media_type = "application/json"

    def __init__(self, *, artifact_dir: Any = None, **_: Any) -> None:
        super().__init__(CAPABILITIES)
        self._artifact_dir = artifact_dir

    def available(self) -> Availability:
        """Always usable: the parsers are ours and need nothing installed.

        Whether THIS job's upload contained a report is a per-job question,
        answered in generate() — the same split every internal adapter makes.
        """
        return Availability(available=True, mode=EngineMode.INTERNAL)

    def generate(self, target: ScanTarget) -> GenerateResult:
        """Find and parse one collector report.

        Never raises. A missing, unreadable or unrecognised file is a status
        plus a diagnostic naming exactly what was looked for.
        """
        report, raw, filename, diagnostics = _locate(
            Path(target.workspace), target.root_subpath
        )

        if report is None:
            return GenerateResult(
                status=ResultStatus.UNAVAILABLE,
                diagnostics=[
                    *diagnostics,
                    {
                        "severity": "warn",
                        "code": "ENGINE_INPUT_MISSING",
                        "message": "no hardware inventory report was found in this upload",
                        "hint": "run one of these ON the machine you want documented and "
                        "upload the output: "
                        + "; ".join(hostformats.SUPPORTED_TOOLS)
                        + ". AxeBOM does not run them for you — it cannot reach your "
                        "machine.",
                    },
                ],
            )

        roots = [normalize(r) for r in report.roots]
        _stamp(roots, report.tool, filename)
        count = sum(r.count() for r in roots)

        diagnostics = [
            *diagnostics,
            *report.diagnostics,
            {
                "severity": "info",
                "code": "HBOM_HOST_REPORT_PARSED",
                "message": f"{filename} was read as {report.tool} output",
                "hint": "the customer ran this tool on the machine being documented; "
                "AxeBOM parsed the file they uploaded",
            },
        ]

        # ⚠ THE RAW ARTIFACT IS THEIR FILE, BYTE FOR BYTE. A re-serialized copy
        # is no longer the evidence they supplied, and evidence is what a raw
        # artifact is (ADR-0003).
        artifact = self._write_artifact(raw, filename)

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
                        "message": "the report named no components beyond the machine itself",
                        "hint": "reported as partial rather than succeeded: zero is a "
                        "claim, and a silent zero cannot be told apart from a file whose "
                        "shape was not understood",
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

    def _write_artifact(self, raw: bytes, filename: str) -> RawArtifact | None:
        if self._artifact_dir is None:
            return None
        try:
            return ArtifactWriter(output_dir=self._artifact_dir).write(
                f"hbom-host-report-{filename}", raw, self.media_type
            )
        except OSError:
            return None


def _stamp(roots: list[HardwareComponent], tool: str, filename: str) -> None:
    """Record which parser produced every row, and where the root came from.

    ⚠ THE PROVENANCE SENTENCE IS NOT DECORATION. A reader of this tree has to
    know it describes what an operating system could see on one machine at one
    moment, produced by a command somebody ran — not an inspection of anything.
    """
    for root in roots:
        if not root.product_details:
            root.product_details = f"Self-reported inventory, imported from {filename}"
        root.product_details += (
            f". Produced by {tool} on the machine itself and uploaded; AxeBOM did not "
            "examine any hardware, and a part the operating system cannot see is absent "
            "from this list rather than absent from the machine."
        )
        _stamp_node(root, tool)


def _stamp_node(node: HardwareComponent, tool: str) -> None:
    node.source_engine = CAPABILITIES.engine_id
    node.origin = node.origin or f"host report ({tool})"
    for child in node.children:
        _stamp_node(child, tool)


def _locate(
    root: Path, subpath: str
) -> tuple[hostformats.Report | None, bytes, str, list[dict[str, Any]]]:
    """Find the first file in the upload that a parser recognises.

    ⚠ CONTENT DECIDES, NOT THE FILENAME — the rule cdxgen_host.py already
    follows. An upload holding an lshw dump beside a dmidecode one is exactly
    what somebody documenting a server produces, and `report.json` is as likely
    to be a test report as an inventory.

    Bounds come from `discovery`, so this walk inherits the same limits every
    other HBOM parser has: a size cap per file, and symlinks skipped rather
    than resolved (skipping avoids the TOCTOU shape entirely).
    """
    diagnostics: list[dict[str, Any]] = []
    base = (root / subpath) if subpath else root
    if not base.is_dir():
        return None, b"", "", diagnostics

    visited = 0
    for path in sorted(base.rglob("*")):
        if visited >= discovery.MAX_FILES:
            diagnostics.append(
                {
                    "severity": "warn",
                    "code": "HBOM_HOST_REPORT_WALK_TRUNCATED",
                    "message": f"stopped after {discovery.MAX_FILES} files; "
                    "a report beyond that point was not looked for",
                }
            )
            break
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix.lower() not in _SUFFIXES:
            continue
        visited += 1
        try:
            if path.stat().st_size > discovery.MAX_FILE_BYTES:
                diagnostics.append(
                    {
                        "severity": "info",
                        "code": "HBOM_HOST_REPORT_FILE_TOO_LARGE",
                        "message": f"{path.name} is larger than the {discovery.MAX_FILE_BYTES}"
                        "-byte cap and was not read",
                    }
                )
                continue
            raw = path.read_bytes()
        except OSError:
            continue

        report = hostformats.parse(raw)
        if report is not None and report.roots:
            return report, raw, path.name, diagnostics

    return None, b"", "", diagnostics
