"""The canonical hardware component — CERT-In Table 11 plus §10.4.1.4.

⚠ TWENTY-FOUR ELEMENTS, AND TABLE 11 ALONE IS NOT ENOUGH.

§10.4.1.4 (p.62) mandates `firmware_version`, `origin`, `criticality` and
`vulnerabilities` for hardware supplied to government and public-sector
entities. None of the four appears anywhere in Table 11. A tool that implements
Table 11 and stops is not compliant, and — worse — reports itself as complete.

⚠ TWO SUPPLIER RELATIONSHIPS, NOT ONE.

Table 11 lists "Supplier Information" and "Supplier Location" **twice**, with
different descriptions: the company that sold you the PRODUCT, and the company
that supplied a COMPONENT to that product's manufacturer. Collapsing them into
one pair loses the distinction that makes an HBOM useful for supply-chain
provenance — the whole point of §10.2.1.

The field count is never written here or anywhere else. It is rendered from the
profile (`len(HBOM_FIELDS)`), because hardcoding a count is exactly how a
product ships a false compliance claim when a guideline is revised.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from axebom_shared.model.generated_certin import HBOM_FIELDS

from .vulnmatch import HardwareFinding

NOT_PROVIDED = "not-provided"

#: How deep a subcomponent tree may go before the importer stops descending.
#:
#: ⚠ CAPPED, WITH A DIAGNOSTIC — NOT UNBOUNDED, AND NOT SILENT. A CSV whose
#: `level` column walks 1, 2, 3, … forever is a plausible export bug, and
#: unbounded recursion turns it into a crash. Ten levels is deeper than any real
#: assembly; past that, the customer is told rather than guessed at.
MAX_DEPTH = 10

#: Criticality is a closed set, matching the CHECK constraint on
#: `normalize.hardware_components`.
CRITICALITY_VALUES = ("critical", "high", "medium", "low")

#: Assembly method. Closed, matching migration 0011's CHECK.
ASSEMBLY_TYPES = ("smt", "tht", "mechanical")

#: Part lifecycle. Closed, matching migration 0011's CHECK.
#:
#: ⚠ "nrnd" IS NOT A SYNONYM FOR EITHER NEIGHBOUR. Not Recommended for New
#: Designs means buyable today and refused at the next respin — the one status
#: that prompts a redesign before the part actually goes away. Collapsing it
#: into "active" or "obsolete" destroys exactly that signal.
#:
#: ⚠ "unknown" IS STORABLE AND SCORES ZERO. It is in
#: axebom_shared.normalize.coverage.NON_SUBSTANTIVE, so a distributor that
#: answered "unknown" is REPORTED without counting as knowledge — invariant 3
#: on the field where that answer is most common.
LIFECYCLE_VALUES = ("active", "nrnd", "obsolete", "eol", "preview", "unknown")

#: How confident we are that an alternate really substitutes.
#:
#: ⚠ "unverified" IS THE DEFAULT, NOT "drop-in". Asserting that a part is a
#: drop-in replacement is a substitution decision about somebody's hardware;
#: defaulting to the flattering value would make AxeBOM the author of a claim
#: it never checked.
EQUIVALENCE_VALUES = ("drop-in", "functional", "unverified")


@dataclass
class Alternate:
    """An approved second source for a part.

    Mirrors `normalize.hardware_component_alternates`. Not a CERT-In element —
    see the manufacturing block on HardwareComponent.
    """

    #: The customer's own preference order, preserved rather than re-sorted:
    #: which second source they would actually use is a procurement judgement.
    ordinal: int = 0

    manufacturer_name: str = ""
    model_number: str = ""
    supplier_info: str = ""
    supplier_sku: str = ""
    lifecycle_status: str = ""
    equivalence: str = "unverified"
    #: "Approved by EE 2026-03, pin-compatible." An alternate nobody signed off
    #: on is a suggestion, not an alternate.
    approval_note: str = ""

    def identifies_a_part(self) -> bool:
        """Whether this names anything at all.

        Mirrors the `hardware_alternate_identifiable` CHECK: an alternate that
        names no manufacturer, no MPN and no SKU is not an alternate.
        """
        return bool(self.manufacturer_name or self.model_number or self.supplier_sku)


#: Elements no import path can populate from a parts list, and which the form
#: collects instead.
#:
#: ⚠ DOCUMENTATION, NOT BEHAVIOUR. Nothing branches on this set — every field
#: goes through the same substantive-value check. It exists so a report can say
#: WHY a field is empty rather than leaving a reader to wonder whether the
#: import failed.
USER_SUPPLIED_FIELDS = frozenset(
    {
        "certin.hbom.04.warranty_amc",
        "certin.hbom.18.license_information",
        "certin.hbom.19.test_result",
        "certin.hbom.23.criticality",
    }
)


@dataclass
class HardwareComponent:
    """One node in a hardware bill of materials.

    Mirrors `normalize.hardware_components` exactly. Every Table 11 element and
    every §10.4.1.4 addition has a home; absent values become `not-provided` at
    normalization rather than being dropped, because an omitted field hides the
    gap and a `not-provided` one reports it.
    """

    # --- identity within the imported tree ---------------------------------
    #: Stable within one import, used to wire `parent_id` before ids exist.
    local_id: str = ""
    parent_local_id: str | None = None

    #: Depth in the tree. 0 is the product itself.
    level: int = 0

    #: Which row of the source file this came from, for legible errors.
    source_row: int | None = None

    #: How many of this component the parent contains. Not a CERT-In element —
    #: it is the one field every real parts list has and Table 11 does not.
    quantity: int = 1

    # --- Table 11 ----------------------------------------------------------
    product_name: str = ""
    product_version: str = ""
    product_details: str = ""
    warranty_amc: str = ""
    manufacturer_name: str = ""
    manufacturer_location: str = ""
    manufacturing_date: str = ""

    #: The PRODUCT's supplier — who sold this item.
    supplier_info: str = ""
    supplier_location: str = ""

    model_number: str = ""
    serial_number: str = ""
    technical_specification: str = ""

    #: The COMPONENT's supplier — who supplied this part to the manufacturer of
    #: the larger product. A DIFFERENT RELATIONSHIP from the pair above.
    component_supplier_info: str = ""
    component_supplier_location: str = ""

    technology_node: str = ""
    compliance: list[str] = field(default_factory=list)
    power_supply: str = ""
    license_info: str = ""
    test_result: str = ""

    #: Sub-components. The recursion IS element 20.
    children: list[HardwareComponent] = field(default_factory=list)

    # --- §10.4.1.4, absent from Table 11 -----------------------------------
    firmware_version: str = ""
    origin: str = ""
    criticality: str = ""
    #: CERT-In element 24. The CVE ids matched against this component —
    #: DERIVED from `vuln_findings`, never set independently, so the scored
    #: element and the rendered detail can never disagree.
    findings: list[str] = field(default_factory=list)

    #: How element 24 was arrived at: matched | no-match | no-cpe |
    #: not-attempted.
    #:
    #: ⚠ WITHOUT THIS, AN EMPTY `findings` IS AMBIGUOUS AND DANGEROUSLY SO.
    #: "we searched and found nothing" and "we never searched" are the same
    #: empty list, and only one of them is reassuring. Defaults to
    #: `not-attempted`, which is the truthful state for a component nobody has
    #: run a matcher over.
    vuln_match_status: str = "not-attempted"

    #: The CPEs the matcher searched, or would have searched. Kept even when
    #: the lookup did not run, so a report can show what enabling a key buys.
    cpe23_candidates: list[str] = field(default_factory=list)

    #: The full advisory matches. See `workers/hbom/vulnmatch.py` for why every
    #: one of these carries its basis and confidence rather than a bare CVE.
    vuln_findings: list[HardwareFinding] = field(default_factory=list)

    # --- manufacturing and procurement -------------------------------------
    #
    # ⚠ NOT CERT-In ELEMENTS, AND THEY MUST NEVER MOVE completeness_pct.
    #
    # Table 11 describes a component's identity and provenance. It says nothing
    # about how many are fitted, where they sit, what they cost, or whether the
    # part can still be bought — all of which the customer's own parts list
    # already carries. These are scored separately, against
    # docs/reference/hbom-manufacturing-v1.yaml, into their own number. See
    # `workers/hbom/profile.py` and migration 0011.

    #: Reference designators. A LIST, because one line item covers many
    #: placements: "R1, R4, R17" is one part with quantity 3.
    designators: list[str] = field(default_factory=list)
    package_footprint: str = ""

    supplier_sku: str = ""
    preferred_supplier: str = ""
    #: Held as a string all the way to the writer, which casts it. A float here
    #: would lose cents the moment a price like 0.1 round-trips.
    unit_price: str = ""
    #: ISO 4217. Never defaulted — a guessed currency turns an unusable number
    #: into a wrong one.
    currency: str = ""

    #: Deliberately not fitted for this variant. Distinct from absent: the part
    #: IS on the schematic.
    do_not_populate: bool = False
    assembly_type: str = ""
    lifecycle_status: str = ""

    datasheet_url: str = ""

    #: Which engine produced this node — `hbom-ecad`, `hbom-cdxgen-host`, or
    #: empty for a row entered through the REST import or the form.
    #:
    #: ⚠ PROVENANCE, NOT DECORATION. A parts list assembled from a schematic
    #: and a host inventory in the same scan holds two different KINDS of
    #: claim, and a reader who cannot tell them apart will read one as the
    #: other.
    source_engine: str = ""

    #: Approved second sources. The field that decides whether an obsolete part
    #: delays a build or stops it.
    alternates: list[Alternate] = field(default_factory=list)

    # --- provenance --------------------------------------------------------
    #: Which fields an enrichment provider supplied, so a report can say where a
    #: value came from. A datasheet URL from Nexar is a different kind of fact
    #: from a serial number the customer typed.
    enriched_fields: dict[str, str] = field(default_factory=dict)

    def walk(self, _depth: int = 0) -> Iterator[tuple[int, HardwareComponent]]:
        """Yield (depth, component) for this node and every descendant.

        Depth-first, parents before children, so a renderer can indent as it
        goes. The depth is yielded rather than recomputed because a caller that
        recomputed it would walk the tree twice.
        """
        yield _depth, self
        if _depth >= MAX_DEPTH:
            return
        for child in self.children:
            yield from child.walk(_depth + 1)

    def count(self) -> int:
        """Total nodes in this subtree, including this one."""
        return sum(1 for _ in self.walk())

    def depth(self) -> int:
        """Deepest level below this node."""
        return max(d for d, _ in self.walk())


# ---------------------------------------------------------------------------
# Canonical-path mapping
# ---------------------------------------------------------------------------


#: Profile canonical path -> attribute on HardwareComponent.
#:
#: ⚠ DERIVED FROM THE PROFILE, NOT HAND-LISTED. `_ATTRIBUTE_FOR` is built by
#: stripping the `hardware_component.` prefix and the `[]` suffix, so a profile
#: revision that renames a path fails loudly in `validate_mapping()` instead of
#: silently dropping a field from every report.
def _attribute_for(canonical_path: str) -> str:
    return canonical_path.removeprefix("hardware_component.").removesuffix("[]")


_ATTRIBUTE_FOR: dict[str, str] = {f.id: _attribute_for(f.canonical_path) for f in HBOM_FIELDS}


def validate_mapping() -> list[str]:
    """Report profile elements this model cannot store.

    Called by a test rather than at import time: a mapping gap must fail a
    build, not a customer's request.
    """
    known = set(HardwareComponent.__dataclass_fields__)
    return [
        f"{f.id} -> hardware_component.{_ATTRIBUTE_FOR[f.id]}"
        for f in HBOM_FIELDS
        if _ATTRIBUTE_FOR[f.id] not in known
    ]


def to_profile_row(
    component: HardwareComponent, fields: Sequence[Any] | None = None
) -> dict[str, Any]:
    """Render one component as {profile field id: value}.

    ⚠ EVERY ELEMENT APPEARS. An absent value becomes `not-provided` — reported,
    never omitted — because omission hides the gap while `not-provided` states
    it. Coverage scoring then treats `not-provided` as present = 0, which is
    what keeps `completeness_pct` honest.

    ⚠ `fields` MAKES THIS REUSABLE ACROSS PROFILES, AND THAT IS THE WHOLE POINT.
    The same component is scored twice — once against the CERT-In elements and
    once against the manufacturing set — and both scores must apply the
    identical `not-provided` rule. One implementation, two field lists. A second
    copy of this loop is how the two would eventually disagree about what counts
    as absent, which would show up as two percentages that cannot both be right.

    Defaults to the CERT-In elements so every existing caller is unchanged.
    """
    row: dict[str, Any] = {}

    for f in fields if fields is not None else HBOM_FIELDS:
        attribute = _attribute_for(f.canonical_path)
        value = getattr(component, attribute, None)

        # ⚠ getattr, BECAUSE TWO FIELD SHAPES REACH THIS LOOP. The generated
        # `ProfileField` carries `type`; `coverage.Field` — what
        # `fields_from_profile` builds for the manufacturing profile — carries
        # only what scoring needs and has no `type` at all. Only CERT-In
        # element 20 is ever `recursive_ref`, so an absent type is simply not
        # that case rather than an error.
        if getattr(f, "type", "") == "recursive_ref":
            # Element 20 is the sub-component list. Its VALUE is the count of
            # direct children: a report needs to say "this assembly declares
            # four sub-components", and the children themselves are rendered as
            # their own rows.
            row[f.id] = len(component.children) if component.children else NOT_PROVIDED
            continue

        if isinstance(value, list):
            row[f.id] = value if value else NOT_PROVIDED
            continue

        # ⚠ A BOOLEAN IS ALWAYS AN ANSWER, INCLUDING False. "This part IS
        # populated" is a stated fact, not an absence, and
        # coverage.is_substantive agrees (`False` is substantive). Falling
        # through to the `value not in ("", None)` check below would work by
        # accident today; saying it explicitly keeps it working if that check
        # ever changes.
        if isinstance(value, bool):
            row[f.id] = value
            continue

        row[f.id] = value if value not in ("", None) else NOT_PROVIDED

    return row


def normalize(component: HardwareComponent) -> HardwareComponent:
    """Return a component with its values cleaned, recursively.

    Deliberately narrow: it trims whitespace, canonicalises the closed enums,
    and drops empty strings out of list fields. It does NOT guess — an absent
    manufacturer stays absent, because a plausible default would be read as a
    fact about somebody's hardware.

    ⚠ EVERY CLOSED SET IS DROPPED-IF-UNRECOGNISED, NEVER COERCED, and every one
    of them is normalised HERE as well as in the importer. The importer is not
    the only way in: the form writes these fields too, and a value that reached
    the database bypassing this function would either violate a CHECK
    constraint (a lower-case currency against `^[A-Z]{3}$`) or store an enum
    nothing can render.
    """
    component.product_name = component.product_name.strip()
    component.criticality = component.criticality.strip().lower()
    if component.criticality and component.criticality not in CRITICALITY_VALUES:
        # An unrecognised rating is dropped rather than coerced. Mapping
        # "urgent" onto "critical" is a guess about severity, and severity in a
        # compliance document is not ours to invent.
        component.criticality = ""

    for attribute in (
        "product_version",
        "product_details",
        "warranty_amc",
        "manufacturer_name",
        "manufacturer_location",
        "manufacturing_date",
        "supplier_info",
        "supplier_location",
        "model_number",
        "serial_number",
        "technical_specification",
        "component_supplier_info",
        "component_supplier_location",
        "technology_node",
        "power_supply",
        "license_info",
        "test_result",
        "firmware_version",
        "origin",
    ):
        setattr(component, attribute, str(getattr(component, attribute) or "").strip())

    # --- manufacturing enums, same drop-rather-than-coerce rule -------------
    component.assembly_type = component.assembly_type.strip().lower()
    if component.assembly_type and component.assembly_type not in ASSEMBLY_TYPES:
        component.assembly_type = ""

    component.lifecycle_status = component.lifecycle_status.strip().lower()
    if component.lifecycle_status and component.lifecycle_status not in LIFECYCLE_VALUES:
        component.lifecycle_status = ""

    # ⚠ UPPER-CASED, BECAUSE THE COLUMN IS CHECKed ON `^[A-Z]{3}$`. A file that
    # writes "usd" is not wrong about the currency, only about the case, and
    # rejecting the row over that would lose a real price. A string that is not
    # three letters IS dropped — "US Dollars" is not an ISO 4217 code, and
    # storing it would make the column unusable for anything that reads it.
    component.currency = component.currency.strip().upper()
    if len(component.currency) != 3 or not component.currency.isalpha():
        component.currency = ""

    for attribute in (
        "package_footprint",
        "supplier_sku",
        "preferred_supplier",
        "unit_price",
        "datasheet_url",
    ):
        setattr(component, attribute, str(getattr(component, attribute) or "").strip())

    component.designators = [d.strip() for d in component.designators if d and d.strip()]
    component.alternates = [a for a in component.alternates if a.identifies_a_part()]

    component.compliance = [c.strip() for c in component.compliance if c and c.strip()]
    component.children = [normalize(child) for child in component.children]
    return component


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------
#
# ⚠ THIS IS WHAT MAKES AN HBOM SCAN REPLAYABLE (CLAUDE.md invariant 10).
#
# An engine writes its parsed tree as a raw artifact, once, and never mutates
# it. Normalization then runs from that stored artifact — so fixing a
# normalizer bug is a re-normalization pass, not a re-parse of files that may
# no longer exist at the same commit. Round-tripping through these two
# functions is what the artifact's `roots` array is.


def to_dict(component: HardwareComponent) -> dict[str, Any]:
    """One component and its subtree as plain JSON-safe data.

    Every field is emitted, including empty ones: an absent key and an empty
    value are different facts on the way back in, and a reader that had to
    guess which it was looking at would be guessing about the customer's data.
    """
    out: dict[str, Any] = {}
    for name in HardwareComponent.__dataclass_fields__:
        if name in ("children", "alternates", "vuln_findings"):
            continue
        out[name] = getattr(component, name)
    out["alternates"] = [
        {n: getattr(a, n) for n in Alternate.__dataclass_fields__} for a in component.alternates
    ]
    out["vuln_findings"] = [f.to_dict() for f in component.vuln_findings]
    out["children"] = [to_dict(child) for child in component.children]
    return out


def from_dict(payload: Mapping[str, Any]) -> HardwareComponent:
    """Rebuild a component and its subtree.

    ⚠ UNKNOWN KEYS ARE IGNORED AND MISSING ONES TAKE THEIR DEFAULT. A stored
    artifact may predate a field this model has since gained, and re-reading it
    must not raise — that is the whole point of storing artifacts immutably.
    The failure mode to avoid is a normalizer that cannot read its own history.
    """
    known = HardwareComponent.__dataclass_fields__
    component = HardwareComponent(
        **{
            k: v
            for k, v in payload.items()
            if k in known and k not in ("children", "alternates", "vuln_findings")
        }
    )
    finding_fields = HardwareFinding.__dataclass_fields__
    component.vuln_findings = [
        HardwareFinding(**{k: v for k, v in f.items() if k in finding_fields})
        for f in payload.get("vuln_findings") or []
        if isinstance(f, Mapping)
    ]
    alt_fields = Alternate.__dataclass_fields__
    component.alternates = [
        Alternate(**{k: v for k, v in a.items() if k in alt_fields})
        for a in payload.get("alternates") or []
        if isinstance(a, Mapping)
    ]
    component.children = [
        from_dict(c) for c in payload.get("children") or [] if isinstance(c, Mapping)
    ]
    return component
