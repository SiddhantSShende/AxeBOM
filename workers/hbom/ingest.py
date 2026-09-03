"""Raw HBOM artifacts back into canonical components.

⚠ THIS IS THE LAYER THAT MUST NEVER RAISE ON AN UNEXPECTED SHAPE, and it must
never invent. Same contract as `axebom_shared.normalize.ingest` for the SBOM
family, for the same reason: it reads stored evidence, some of it written by
an older version of this code and some of it produced by a customer's own
tool. A parser that throws on a shape it did not expect turns a re-normalization
pass into an outage; one that fills in a plausible value turns it into a lie.

⚠ WHY THIS IS SEPARATE FROM axebom_shared.normalize.ingest._PARSERS.

That table returns `Ingested`, whose every field is an SBOM concept —
`contributions` for merge.py, `edges` for graph.py, `ref_to_key` for CycloneDX
bom-refs. An HBOM parser would return one with all six empty plus a seventh
field bolted on, and every SBOM consumer of `Ingested` would have to learn to
ignore it.

Worse, four of `pipeline.normalize()`'s seven stages are actively WRONG for
hardware:

  merge          two identical 10k resistors on one board are two placements
                 of one line item, not one component to dedup. There is no
                 merge key; identity.resolve() would fall to `opaque` and put
                 every hardware row in `unidentified_count`, inflating the
                 coverage denominator by the entire parts list.
  graph          the structure is `parent_id`, an assembly tree, not a
                 dependency DAG with per-ecosystem trust replacement.
  alias closure  nothing to close: no purl, no cross-scanner vulnerability
                 identifiers to reconcile.
  findings       purl-keyed, and hardware matches are CPE-keyed and advisory.

`workers/cbom/normalize/pipeline.py` and `workers/aibom/normalize/pipeline.py`
each make this same argument in their own docstrings; HBOM has a stronger case
than either.
"""

from __future__ import annotations

from typing import Any

from .adapters.cdxgen_host import _to_tree as _cyclonedx_to_tree
from .model import HardwareComponent, from_dict

#: Which parser reads which engine's artifact. The single place a new HBOM
#: engine registers, mirroring `ingest._PARSERS` on the SBOM side.
_PARSERS = {
    "hbom-ecad": "_ingest_axebom_hbom",
    "hbom-cdxgen-host": "_ingest_cyclonedx_hardware",
}


def supported_engines() -> list[str]:
    return sorted(_PARSERS)


def ingest(engine: str, payload: Any) -> tuple[list[HardwareComponent], list[dict[str, Any]]]:
    """Turn one engine's raw artifact into canonical component trees.

    Returns (roots, diagnostics). An unknown engine or an unreadable payload
    yields no roots and a diagnostic — never an exception.
    """
    if engine not in _PARSERS:
        return [], [
            {
                "severity": "warn",
                "code": "NORMALIZE_NO_PARSER",
                "message": f"no HBOM parser is registered for engine {engine!r}",
                "hint": "known: " + ", ".join(supported_engines()),
            }
        ]

    if not isinstance(payload, dict):
        return [], [
            {
                "severity": "warn",
                "code": "NORMALIZE_ARTIFACT_UNPARSEABLE",
                "message": f"{engine}'s artifact is not a JSON object",
            }
        ]

    roots, diagnostics = (
        _ingest_axebom_hbom(payload)
        if engine == "hbom-ecad"
        else _ingest_cyclonedx_hardware(payload)
    )
    for root in roots:
        _tag(root, engine)
    return roots, diagnostics


def _tag(component: HardwareComponent, engine: str) -> None:
    """Record which engine produced this node, recursively.

    Set at INGEST rather than in each adapter: the adapters build trees, and
    the engine id is a fact about the artifact they were read from. Tagging
    here means one implementation instead of one per adapter, and it cannot be
    forgotten when a third engine is added.
    """
    component.source_engine = engine
    for child in component.children:
        _tag(child, engine)


def _ingest_axebom_hbom(
    payload: dict[str, Any],
) -> tuple[list[HardwareComponent], list[dict[str, Any]]]:
    """Read `axebom-hbom-json-1` — the shape hbom-ecad writes.

    The adapter already built the tree; this reconstitutes it. Deliberately
    NOT a re-parse of the design files: those may no longer exist at the same
    commit, and re-normalizing stored artifacts rather than re-scanning is what
    invariant 10 is for.
    """
    diagnostics: list[dict[str, Any]] = []
    schema = str(payload.get("schema_version") or "")
    if schema and schema != "axebom-hbom-json-1":
        diagnostics.append(
            {
                "severity": "info",
                "code": "NORMALIZE_ARTIFACT_SCHEMA_UNEXPECTED",
                "message": f"artifact declares schema {schema!r}",
                "hint": "read anyway — from_dict ignores unknown keys and defaults "
                "missing ones, so an artifact from an older build still normalizes",
            }
        )

    roots = [from_dict(r) for r in payload.get("roots") or [] if isinstance(r, dict)]
    # The engine's own diagnostics travel with the document, so a re-normalization
    # reports the same column-mapping guesses and skipped files the original run did.
    for d in payload.get("diagnostics") or []:
        if isinstance(d, dict):
            diagnostics.append(d)
    return roots, diagnostics


def _ingest_cyclonedx_hardware(
    payload: dict[str, Any],
) -> tuple[list[HardwareComponent], list[dict[str, Any]]]:
    """Read a CycloneDX hardware document — the customer's own host inventory.

    ⚠ THE SAME FUNCTION THE ADAPTER USED, NOT A SECOND IMPLEMENTATION. The
    artifact is the customer's bytes verbatim, so mapping it here means mapping
    it exactly as it was mapped at scan time — two implementations would
    eventually disagree, and the disagreement would look like data changing
    under a re-normalization that is supposed to be replayable.
    """
    spec = str(payload.get("specVersion") or "")
    return _cyclonedx_to_tree(payload, "the uploaded document", spec), []
