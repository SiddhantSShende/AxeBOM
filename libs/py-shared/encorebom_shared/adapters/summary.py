"""The headline counts one engine reports, and which of them it may report.

# The gap this closes

``ScanResultV1.summary`` was built as a literal ``{"components": 0,
"vulnerabilities": 0, "licenses": 0, "crypto_assets": 0}`` on every job. syft
inventoried 21 components in ``expressjs/express`` and the envelope said zero,
so ``scan.engine_runs.summary`` recorded nothing for any scan ever run and every
consumer of it understated the result.

# ⚠ None IS NOT ZERO, AND THIS IS THE WHOLE POINT OF THE MODULE

    None   this engine does not measure this dimension
    0      it measured, and there were none

Filling the four fields in unconditionally would have replaced one false zero
with three. syft catalogues components and never matches vulnerabilities; grype
matches vulnerabilities and never catalogues licences. "grype found 0 licences"
reads as a clean result and is really a question grype was never asked — the
same failure this codebase refuses everywhere else, where an unknown must never
present as a measured zero (CLAUDE.md invariant 3) and an unscanned ecosystem
must be declared rather than omitted (invariant 12).

# Where the entitlement comes from

Not from this module's opinion. ``OSINT/tools.manifest.yaml`` already declares
``produces:`` per engine, and docs/04-OSINT-INTEGRATION.md owns that file. An
engine reports exactly the dimensions its manifest entry claims, so adding an
engine or changing what one produces is a manifest edit, not a code edit.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from encorebom_shared.logging import get_logger

from .base import Capabilities

log = get_logger(__name__)

#: The four fields of ScanResultV1.summary. Mirrors events.Summary in
#: libs/go-shared/events/events.go; the envelope is validated against the
#: schema generated from it, so drift fails before publication.
DIMENSIONS: tuple[str, ...] = ("components", "vulnerabilities", "licenses", "crypto_assets")

#: Which summary dimension each manifest ``produces`` token measures.
#:
#: A token mapped to None is deliberately not a summary dimension. A token
#: absent from this table is a manifest entry nobody taught the summary about —
#: caught by test_summary.py rather than silently dropped.
_DIMENSION_OF: dict[str, str | None] = {
    "components": "components",
    "licenses": "licenses",
    "vulnerabilities": "vulnerabilities",
    "crypto_assets": "crypto_assets",
    # ai-bom's discoveries ARE CycloneDX components: a model, an agent
    # framework and an MCP server each arrive as one component. Counting them
    # as components rather than inventing a field keeps the envelope the four
    # fields docs/02-CONTRACTS.md §6 defines.
    "ai_models": "components",
    "ai_dependencies": "components",
    "hardware_components": "components",
    # ⚠ DELIBERATELY UNMAPPED. A leaked secret is a finding, not an inventory
    # count, and folding it into `vulnerabilities` would put a number in a
    # compliance report that no CVE backs.
    "secrets": None,
}

#: Values that assert nothing. CLAUDE.md invariant 3: `not-provided`,
#: NOASSERTION, unknown, "" and [] all score present = 0.
_NOT_AN_ASSERTION = frozenset({"", "noassertion", "unknown", "not-provided", "none"})


@dataclass
class EngineSummary:
    """Headline counts from one engine run. None means "not measured"."""

    components: int | None = None
    vulnerabilities: int | None = None
    licenses: int | None = None
    crypto_assets: int | None = None

    def as_dict(self) -> dict[str, int | None]:
        """Render for the ScanResultV1 envelope.

        Every dimension is present, as a number or an explicit null. Omitting
        the nulls would leave a consumer unable to tell "this engine does not
        measure it" from "this publisher is older than the field".
        """
        return {
            "components": self.components,
            "vulnerabilities": self.vulnerabilities,
            "licenses": self.licenses,
            "crypto_assets": self.crypto_assets,
        }

    def measured(self) -> frozenset[str]:
        """Which dimensions carry a number."""
        return frozenset(k for k, v in self.as_dict().items() if v is not None)


def dimensions_for(capabilities: Capabilities) -> frozenset[str]:
    """Which summary dimensions this engine is entitled to report."""
    out: set[str] = set()
    for token in capabilities.produces:
        if token not in _DIMENSION_OF:
            log.warning(
                "engine declares a `produces` token the summary does not map",
                extra={"engine": capabilities.engine_id, "token": token},
            )
            continue
        dimension = _DIMENSION_OF[token]
        if dimension is not None:
            out.add(dimension)
    return frozenset(out)


def summarize(capabilities: Capabilities, counts: Mapping[str, int]) -> EngineSummary:
    """Report the dimensions this engine's manifest entry claims, and no others.

    ⚠ A COUNT THE ENGINE DID NOT SET OUT TO MEASURE IS DROPPED, NOT REPORTED.

    A CycloneDX document from syft has no `vulnerabilities` array, so counting
    it yields 0 — and publishing that 0 would say syft looked and found none.
    It did not look. The manifest decides; the counter only counts.
    """
    allowed = dimensions_for(capabilities)
    return EngineSummary(
        **{d: int(counts[d]) for d in allowed if d in counts}  # type: ignore[arg-type]
    )


# -- format counters --------------------------------------------------------
#
# These return every count the document supports. Selecting from them is
# summarize()'s job, so a counter never has to know which engine called it.


def count_cyclonedx(payload: Any) -> dict[str, int]:
    """Count a CycloneDX document.

    Defensive throughout: an engine that changes its output shape must degrade
    the count, never raise. A raised exception here would fail a scan whose
    scanning part already succeeded.
    """
    if not isinstance(payload, dict):
        return {}

    components = 0
    crypto_assets = 0
    licenses: set[str] = set()

    # ⚠ RECURSIVE. CycloneDX nests components under a parent, and trivy uses
    # that for multi-root repositories. Counting only the top level reports a
    # monorepo's four roots as four components — the same understatement this
    # module exists to remove, one level down.
    def walk(items: Any, depth: int) -> None:
        nonlocal components, crypto_assets
        if depth > 32 or not isinstance(items, list):
            return
        for c in items:
            if not isinstance(c, dict):
                continue
            if c.get("type") == "cryptographic-asset":
                crypto_assets += 1
            else:
                components += 1
            licenses.update(_cyclonedx_licenses(c.get("licenses")))
            walk(c.get("components"), depth + 1)

    walk(payload.get("components"), 0)

    out = {
        "components": components,
        "crypto_assets": crypto_assets,
        "licenses": len(licenses),
    }
    vulnerabilities = payload.get("vulnerabilities")
    if isinstance(vulnerabilities, list):
        out["vulnerabilities"] = count_distinct_vulnerabilities(
            v.get("id") for v in vulnerabilities if isinstance(v, dict)
        )
    return out


def count_distinct_vulnerabilities(ids: Iterable[Any]) -> int:
    """Count DISTINCT vulnerability identifiers.

    ⚠ FINDINGS ARE NOT VULNERABILITIES, and the engines disagree about which
    they emit. grype emits one `match` per (vulnerability, package) pair, so
    one CVE across three packages is three matches; trivy emits one entry per
    vulnerability with an `affects` list. Counting rows would make the same
    project look three times worse under grype than under trivy, in a field
    named `vulnerabilities`.

    An entry with no identifier is still counted — dropping it would understate
    — but it cannot be deduplicated, so each one counts once.
    """
    seen: set[str] = set()
    unidentified = 0
    for raw in ids:
        if isinstance(raw, str) and raw.strip():
            seen.add(raw.strip())
        else:
            unidentified += 1
    return len(seen) + unidentified


def _cyclonedx_licenses(entries: Any) -> set[str]:
    """Distinct licence identifiers asserted on one component."""
    if not isinstance(entries, list):
        return set()

    out: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        # An SPDX expression is one assertion, however many licences it names.
        expression = entry.get("expression")
        if isinstance(expression, str):
            out.update(_licence_value(expression))
            continue
        lic = entry.get("license")
        if isinstance(lic, dict):
            out.update(_licence_value(lic.get("id") or lic.get("name")))
    return out


def _licence_value(raw: Any) -> set[str]:
    """Normalise one licence assertion, dropping the non-assertions.

    ⚠ `NONE` IS DROPPED HERE AND STILL COUNTS AS PRESENT ELSEWHERE.

    CLAUDE.md invariant 3 makes licence `NONE` a substantive value for COVERAGE
    scoring — "we looked, there is no licence" is an answer, where NOASSERTION
    is not. This is a different question: how many distinct licences did the
    engine identify. `NONE` names none, so adding one to that inventory would
    invent a licence that does not exist. The two rules disagree because they
    measure different things.
    """
    if not isinstance(raw, str):
        return set()
    value = raw.strip()
    if value.lower() in _NOT_AN_ASSERTION:
        return set()
    return {value}


def count_spdx(payload: Any) -> dict[str, int]:
    """Count an SPDX document."""
    if not isinstance(payload, dict):
        return {}

    packages = payload.get("packages")
    if not isinstance(packages, list):
        packages = []

    licenses: set[str] = set()
    components = 0
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        components += 1
        # Concluded is the stronger claim; declared is what the package said
        # about itself. Both are assertions and both belong in the inventory.
        licenses.update(_licence_value(pkg.get("licenseConcluded")))
        licenses.update(_licence_value(pkg.get("licenseDeclared")))

    return {"components": components, "licenses": len(licenses)}
