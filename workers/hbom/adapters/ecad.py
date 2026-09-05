"""hbom-ecad — the customer's own design files, read as a parts list.

⚠ THIS IS NOT DISCOVERY OF HARDWARE, AND NOTHING HERE SAYS IT IS.

No open-source tool inspects a physical device and enumerates its parts, and
this one does not either. What it does is read design documents the customer
wrote and committed — KiCad schematics, KiCad netlists, and BOM exports from
KiCad, Altium and OrCAD — exactly as an SBOM engine reads a lockfile the
customer committed. The distinction is the whole basis for HBOM being
scannable at all; see CLAUDE.md's honest-labels section and
`services/scan-orchestrator/internal/policy/registry.go`'s entry for this id.

⚠ NO CONTAINER, NO SANDBOX, NO NETWORK.

There is no third-party binary to run, so there is nothing to sandbox — the
same shape as `webrecon_fingerprint.py` and `github_dependency_graph.py`, and
consistent with invariant 7, which is about EXECUTING third-party binaries over
untrusted code. Parsing happens in-process against explicit bounds; see
`discovery.py` for the file/byte caps and the symlink and XML-entity rules.

⚠ ONE OUTPUT SHAPE FROM FIVE INPUT FORMATS.

The raw artifact is always `axebom-hbom-json-1`, whichever parser produced it —
the same choice `services/webrecon` made with `axebom-webrecon-json-1`. The
normalize path then has one document to read rather than five, and each source
file's path and sha256 ride along so a re-normalization six months later can
still say which schematic produced which row (invariant 10).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

# ⚠ ABSOLUTE, NOT `from ...sbom.adapters.common`. `workers` has no
# __init__.py — it is a namespace package — so a three-level relative import
# resolves at runtime (the image sets WORKDIR /app) and raises
# "attempted relative import beyond top-level package" under pytest's
# rootdir-based collection. An import that works in production and breaks in
# the test runner is the worst of both: the tests that would catch a bug here
# cannot even be collected.
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

from ..csv_import import ColumnMapping, HBOMImportError, parse, parse_rows
from ..model import HardwareComponent, normalize, to_dict
from . import discovery, eagle, kicad

SCHEMA_VERSION = "axebom-hbom-json-1"

CAPABILITIES = Capabilities(
    engine_id="hbom-ecad",
    families=("hbom",),
    source_kinds=("git", "upload"),
    produces=("hardware_components",),
    native_format=SCHEMA_VERSION,
    # ⚠ LOAD-BEARING, NOT DECORATIVE. hbom-csv is recorded as UNAVAILABLE for
    # the `hardware` ecosystem at scan-create time (it declares no source kind
    # and lands in Resolution.SkippedForSource). Store.CoverageGaps only
    # neutralises such a row when a matching available=true row exists for the
    # same ecosystem, and that row comes from this engine reporting `hardware`
    # covered. Drop it and every HBOM report grows a false "ecosystem
    # `hardware` had no available engine" line — invariant 12 inverted.
    ecosystems=("hardware",),
    db_backed=False,
    default_weight=3,
)

#: KiCad's own BOM export headers, as a fixed mapping.
#:
#: ⚠ THIS ONE IS DATA, NOT INFERENCE, AND THE DIFFERENCE MATTERS. A KiCad BOM
#: has known headers written by a known tool, so mapping them is a fact. A
#: customer's Altium export is not — that goes through ColumnMapping.suggest(),
#: which is a guess, and the adapter says so in a diagnostic (see below).
KICAD_BOM_HEADERS: dict[str, str] = {
    "reference": "designator",
    "references": "designator",
    "ref": "designator",
    "value": "description",
    "footprint": "footprint",
    "quantity": "quantity",
    "qty": "quantity",
    "datasheet": "datasheet",
    "manufacturer": "manufacturer",
    "mpn": "mpn",
    "dnp": "dni",
}


class ECADAdapter(ToolAdapterBase):
    """Parses hardware design files out of a materialized source tree."""

    media_type = "application/json"

    def __init__(self, *, artifact_dir: Any = None, **_: Any) -> None:
        # `**_` absorbs `sandbox=...`, which the runner passes to every adapter
        # uniformly. There is no container here and it is never touched.
        super().__init__(CAPABILITIES)
        self._artifact_dir = artifact_dir

    def available(self) -> Availability:
        """Always usable: the parsers are ours and have no external dependency.

        Whether THIS job's tree contained anything readable is a per-job
        question, answered in generate() — the same split every internal
        adapter in this codebase makes.
        """
        return Availability(available=True, mode=EngineMode.INTERNAL)

    def generate(self, target: ScanTarget) -> GenerateResult:
        """Find, parse and group design files into one hardware BOM document.

        Never raises. Every failure — no files, an unparseable schematic, a CSV
        with no level column — becomes a status plus a diagnostic.
        """
        found = discovery.walk(Path(target.workspace), target.root_subpath)
        diagnostics: list[dict[str, Any]] = list(found.diagnostics)

        if not found.files:
            return GenerateResult(
                status=ResultStatus.UNAVAILABLE,
                diagnostics=[
                    *diagnostics,
                    {
                        "severity": "warn",
                        "code": "ENGINE_INPUT_MISSING",
                        "message": "no hardware design files were found in this source",
                        # ⚠ NAME WHAT WAS LOOKED FOR. "Found nothing" leaves a
                        # customer unable to tell a wrong subpath from an
                        # unsupported format, and they will assume the latter.
                        "hint": "searched for "
                        + ", ".join(found.searched)
                        + " — a KiCad schematic or netlist, an EAGLE schematic, or a "
                        "BOM export in CSV/TSV. "
                        "If the design lives in a subdirectory, set the project's "
                        "source subpath.",
                    },
                ],
            )

        placements: list[kicad.Part] = []
        roots: list[HardwareComponent] = []
        sources: list[dict[str, Any]] = []

        for f in found.files:
            record: dict[str, Any] = {
                "path": f.relative,
                "sha256": hashlib.sha256(f.data).hexdigest(),
                "parser": f.kind,
            }
            if f.kind == "kicad-schematic":
                parts, diags = kicad.parse_schematic(f.data)
                placements.extend(parts)
                record["placements"] = len(parts)
            elif f.kind == "eagle-schematic":
                parts, diags = eagle.parse_schematic(f.data)
                placements.extend(parts)
                record["placements"] = len(parts)
            elif f.kind == "kicad-netlist":
                parts, diags = kicad.parse_netlist(f.data)
                placements.extend(parts)
                record["placements"] = len(parts)
            else:
                tree, diags, mapping_note = _parse_bom_table(f)
                roots.extend(tree)
                record["components"] = sum(r.count() for r in tree)
                if mapping_note:
                    record["column_mapping"] = mapping_note
            diagnostics.extend(_attribute(diags, f.relative))
            sources.append(record)

        # Placements from every schematic and netlist collapse into ONE board,
        # because they are placements on one board. A BOM table already carries
        # its own tree and is kept as its own root.
        if placements:
            roots.insert(0, _board_from_placements(placements, target))
            if any(f.kind in ("kicad-schematic", "eagle-schematic") for f in found.files):
                diagnostics.append(
                    {
                        "severity": "info",
                        "code": "HBOM_HIERARCHY_FLAT",
                        "message": "schematic symbols were read as a flat parts list under "
                        "one board assembly",
                        "hint": "a hierarchical schematic's sheet structure is a drawing "
                        "convenience, not an assembly hierarchy — inventing sub-assemblies "
                        "from it would assert a build structure the design does not state. "
                        "Import a levelled BOM export, or use the Hardware tab, to record "
                        "real sub-assemblies.",
                    }
                )

        artifact = self._write_artifact(roots, sources, diagnostics)
        component_count = sum(r.count() for r in roots)

        if component_count == 0:
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
                        "message": f"{len(found.files)} design file(s) were read and yielded "
                        "no components",
                        "hint": "reported as partial rather than succeeded: zero is a claim, "
                        "and a silent zero is indistinguishable from a file we could not "
                        "understand",
                    },
                ],
            )

        return GenerateResult(
            status=ResultStatus.SUCCEEDED,
            artifacts=[artifact] if artifact else [],
            ecosystems_covered=["hardware"],
            # ⚠ summarize(), NOT A PLAIN DICT. SBOMWorker._result calls
            # `summary.as_dict()` on whatever an adapter returns, so a dict
            # raises AttributeError three frames into the worker — which is
            # exactly what happened on the first live run, and what the
            # adapter's own unit tests could not see because they never go
            # through the worker.
            #
            # summarize also enforces the rule that matters: an engine may only
            # report dimensions its `produces` claims. `hardware_components`
            # maps to `components`; anything else here would be dropped rather
            # than published as a count nobody measured.
            summary=summarize(self.capabilities, {"components": component_count}),
            diagnostics=diagnostics,
        )

    def _write_artifact(
        self,
        roots: list[HardwareComponent],
        sources: list[dict[str, Any]],
        diagnostics: list[dict[str, Any]],
    ) -> RawArtifact | None:
        if self._artifact_dir is None:
            return None

        document = {
            "schema_version": SCHEMA_VERSION,
            "source_files": sources,
            "roots": [to_dict(r) for r in roots],
            "diagnostics": diagnostics,
        }
        # sort_keys: the artifact is compliance evidence and two runs over the
        # same tree must produce identical bytes (invariant 10). Dict insertion
        # order would make that depend on which file was read first.
        raw = json.dumps(document, sort_keys=True, ensure_ascii=False).encode("utf-8")
        try:
            return ArtifactWriter(output_dir=self._artifact_dir).write(
                "hbom-ecad.json", raw, self.media_type
            )
        except OSError:
            # Not fatal: the components are still reported. Without the
            # artifact this run cannot be re-normalized later without
            # re-parsing the source, a real but survivable loss — the same
            # tradeoff SandboxedAdapter.generate() makes for the same reason.
            return None


def _parse_bom_table(
    f: discovery.Found,
) -> tuple[list[HardwareComponent], list[dict[str, Any]], dict[str, str] | None]:
    """Read a BOM export (KiCad, Altium, OrCAD, generic) into a tree.

    ⚠ TWO PATHS, AND ONLY ONE OF THEM IS A GUESS.

    A KiCad BOM's headers are a fact about a known tool, so they map from
    KICAD_BOM_HEADERS. Anything else goes through ColumnMapping.suggest(),
    whose own docstring is explicit that it is "A CONVENIENCE FOR THE MAPPING
    UI, NEVER AN AUTOMATIC REWRITE" — a human confirms it, because silently
    deciding a column called "Supplier" is the component supplier rather than
    the product supplier puts data in the wrong one of the two relationships
    Table 11 distinguishes.

    A scan has no human in the loop. So the inferred path is USED — refusing it
    would make repo-sourced HBOM useless — and every choice it made is reported
    in a diagnostic and rides on the artifact, which is the honest version of
    "we guessed". A reader can see exactly which header became which column.
    """
    diagnostics: list[dict[str, Any]] = []
    try:
        text = f.data.decode("utf-8-sig", errors="replace")
    except Exception:  # pragma: no cover — errors="replace" cannot raise
        return [], [], None

    if f.path.suffix.lower() == ".tsv":
        text = _tsv_to_csv(text)

    header = text.splitlines()[0] if text.splitlines() else ""
    is_kicad = _looks_like_kicad_bom(header)

    try:
        if is_kicad:
            result = parse_rows(_kicad_bom_rows(text))
        else:
            result = parse(text)
    except HBOMImportError as exc:
        return (
            [],
            [
                {
                    "severity": "warn",
                    "code": "HBOM_TABLE_UNPARSEABLE",
                    "message": str(exc),
                }
            ],
            None,
        )

    mapping_note: dict[str, str] | None = None
    if not is_kicad:
        suggested = ColumnMapping.suggest(_headers(header))
        mapping_note = dict(suggested.columns)
        diagnostics.append(
            {
                "severity": "info",
                "code": "HBOM_COLUMN_MAPPING_INFERRED",
                "message": "column names were matched automatically, without confirmation",
                "hint": "a scan has nobody to confirm the mapping, so every choice is "
                "recorded instead: "
                + ", ".join(f"{k} -> {v}" for k, v in sorted(mapping_note.items()))
                + ". Re-import through the Hardware tab to correct any of them.",
            }
        )

    if result.unmapped_headers:
        diagnostics.append(
            {
                "severity": "info",
                "code": "HBOM_COLUMNS_UNMAPPED",
                "message": "columns no canonical field claimed: "
                + ", ".join(result.unmapped_headers),
                "hint": "shown rather than swallowed — a column we did not understand "
                "may be the one that matters most to the customer",
            }
        )
    for warning in result.warnings:
        diagnostics.append({"severity": "warn", "code": "HBOM_IMPORT_WARNING", "message": warning})

    return result.roots, diagnostics, mapping_note


def _board_from_placements(placements: list[kicad.Part], target: ScanTarget) -> HardwareComponent:
    """Group placements into line items under one board assembly.

    ⚠ ONE LINE PER PART, NOT ONE PER PLACEMENT. R1, R4 and R17 are three
    symbols of the same 10k resistor; a parts list has one row for it with
    quantity 3 and all three designators. Emitting three components would
    inflate the component count in a compliance document and produce a BOM
    nobody can order from.
    """
    board = HardwareComponent(
        local_id="board",
        level=0,
        # ⚠ NAMED FOR THE SCAN, NOT INVENTED. There is no product name in a
        # schematic; claiming one would be fabricating a fact about the
        # customer's product. The form and the Hardware tab are where a real
        # name comes from.
        product_name="Printed circuit assembly",
        product_details="Parsed from the project's own hardware design files. "
        "The product name, supplier and warranty are not stated in a schematic "
        "and remain not-provided until entered.",
    )

    groups: dict[tuple[str, str, str], list[kicad.Part]] = {}
    order: list[tuple[str, str, str]] = []
    for p in placements:
        key = p.group_key()
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(p)

    for index, key in enumerate(order, start=1):
        members = groups[key]
        # ⚠ COALESCED ACROSS EVERY MEMBER, NOT TAKEN FROM members[0].
        #
        # A designer commonly fills the manufacturer and MPN on the first
        # placement of a part and leaves the copies bare. Reading fields off
        # one arbitrary member throws that away — and which member is
        # "arbitrary" depends on walk order, so the loss is invisible and
        # inconsistent. This takes the first non-empty value for each field
        # across the whole group, which cannot lose a value any member stated.
        first = _coalesce(members)
        designators = sorted({m.reference for m in members if m.reference})
        child = HardwareComponent(
            local_id=f"part-{index}",
            parent_local_id=board.local_id,
            level=1,
            quantity=len(members),
            designators=designators,
            product_name=first.mpn or first.value or "unnamed part",
            product_details=first.value,
            model_number=first.mpn,
            manufacturer_name=first.manufacturer,
            component_supplier_info=first.supplier,
            supplier_sku=first.supplier_sku,
            package_footprint=first.footprint,
            datasheet_url=first.datasheet,
            # ⚠ ALL-OR-NOTHING, DELIBERATELY. A line is marked DNP only when
            # EVERY placement it covers is. Three fitted resistors and one
            # unfitted are not one unfitted line item, and flagging the whole
            # line would tell a factory to omit parts the design needs.
            do_not_populate=all(m.do_not_populate for m in members),
            # ⚠ SMT IS NOT INFERRED FROM THE FOOTPRINT. "0402" is an SMD
            # package and a human knows it; a footprint string is not a
            # reliable statement of assembly process, and guessing would put an
            # unverified value in a manufacturing document.
            technical_specification="; ".join(f"{k}: {v}" for k, v in sorted(first.extra.items())),
        )
        board.children.append(child)

    if target.commit_sha:
        board.product_version = target.commit_sha[:12]
    return normalize(board)


def _coalesce(members: list[kicad.Part]) -> kicad.Part:
    """One part carrying the first non-empty value each member stated.

    ⚠ FIRST NON-EMPTY, NEVER LAST, AND NEVER A MERGE OF CONFLICTS. If two
    placements disagree about the manufacturer they are arguably different
    parts and the grouping key was wrong; picking one silently would hide that.
    Taking the first stated value is the conservative reading and matches what
    `_build` already does for duplicate CSV columns ("whichever the file
    supplies first wins rather than an empty second column clearing a populated
    first").
    """
    merged = kicad.Part()
    for name in (
        "value",
        "footprint",
        "mpn",
        "manufacturer",
        "supplier",
        "supplier_sku",
        "datasheet",
    ):
        for m in members:
            current = getattr(m, name, "")
            if current:
                setattr(merged, name, current)
                break
    for m in members:
        for k, v in m.extra.items():
            merged.extra.setdefault(k, v)
    return merged


def _attribute(diagnostics: list[dict[str, Any]], path: str) -> list[dict[str, Any]]:
    """Tag each diagnostic with the file it came from.

    A parts list assembled from nine files with one unreadable schematic is
    useless feedback unless it names which of the nine.
    """
    for d in diagnostics:
        d.setdefault("file", path)
    return diagnostics


def _headers(header_line: str) -> list[str]:
    import csv as _csv
    import io as _io

    return next(_csv.reader(_io.StringIO(header_line)), [])


def _looks_like_kicad_bom(header_line: str) -> bool:
    """KiCad's exporter writes Reference and Value; almost nothing else does."""
    lowered = {h.strip().lower() for h in _headers(header_line)}
    return "reference" in lowered or "references" in lowered


def _kicad_bom_rows(text: str) -> list[dict[str, str]]:
    """Turn a KiCad BOM export into canonical rows, level column included.

    ⚠ KiCad BOMs HAVE NO LEVEL COLUMN, AND `parse()` REFUSES A FILE WITHOUT ONE
    — correctly, because the level is what builds the tree and inventing it for
    an arbitrary customer export would assert an assembly structure nobody
    stated.

    Here it is not invented. A KiCad BOM is known to be flat: one board, one
    row per part. So the level is a fact about the FORMAT, supplied by this
    function rather than read from the file, and a synthetic board row at level
    0 gives the parts something real to hang from. This is exactly what
    `parse_rows` was extracted for — the tree-building and level-sequence rules
    stay in one implementation.
    """
    import csv as _csv
    import io as _io

    reader = _csv.DictReader(_io.StringIO(text))
    rows: list[dict[str, str]] = [{"level": "0", "name": "Printed circuit assembly"}]
    for raw in reader:
        row: dict[str, str] = {"level": "1"}
        for header, value in raw.items():
            if header is None or value is None:
                continue
            canonical = KICAD_BOM_HEADERS.get(str(header).strip().lower())
            if canonical:
                row.setdefault(canonical, str(value))
        rows.append(row)
    return rows


def _tsv_to_csv(text: str) -> str:
    import csv as _csv
    import io as _io

    out = _io.StringIO()
    writer = _csv.writer(out)
    for row in _csv.reader(_io.StringIO(text), delimiter="\t"):
        writer.writerow(row)
    return out.getvalue()


__all__ = ["CAPABILITIES", "SCHEMA_VERSION", "ECADAdapter", "parse_rows"]
