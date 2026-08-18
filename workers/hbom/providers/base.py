"""The part-data provider interface.

⚠ ENRICHMENT IS ADDITIVE AND NEVER OVERWRITES WHAT THE CUSTOMER SUPPLIED.

A parts database is a third party's opinion about a manufacturer part number.
The customer's own BOM is a statement about the hardware in front of them. When
the two disagree — and they will, because MPNs get reused, revised and
mis-transcribed — the customer's value is the one that goes in the compliance
document, and the provider's is recorded as provenance.

Overwriting is how a supplier field that somebody verified against a purchase
order gets replaced by a distributor's guess, and nothing in the output would
say it had happened.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ..model import HardwareComponent


@dataclass
class Enrichment:
    """What a provider knows about one manufacturer part number."""

    mpn: str
    manufacturer_name: str = ""
    manufacturer_location: str = ""
    origin: str = ""
    technology_node: str = ""
    #: RoHS, CE, REACH…
    compliance: list[str] = field(default_factory=list)
    #: Active, NRND, obsolete. Not a CERT-In element, but the single most useful
    #: fact a parts database holds for a BOM that has to stay accurate.
    lifecycle: str = ""
    datasheet_url: str = ""
    #: Which provider said so. Carried into the component's provenance.
    source: str = ""


class PartDataProvider(Protocol):
    """Looks up manufacturer part numbers."""

    name: str

    def configured(self) -> bool:
        """Whether this provider can be called.

        ⚠ CHECKED BEFORE EVERY BATCH. An unconfigured provider must be skipped
        silently rather than called with an empty credential — a request with a
        blank API key produces a 401 in somebody's logs and a support ticket
        about a feature they never enabled.
        """
        ...

    def lookup(self, mpns: list[str]) -> dict[str, Enrichment]:
        """Resolve part numbers. Missing keys mean "not found", not an error."""
        ...


def resolve(providers: list[PartDataProvider]) -> PartDataProvider:
    """Pick the provider to use.

    The first configured one wins; if none is, the caller gets `manual`, which
    is the default and the tested path.
    """
    from .manual import ManualProvider

    for provider in providers:
        if provider.configured():
            return provider
    return ManualProvider()


def apply(
    component: HardwareComponent,
    enrichments: dict[str, Enrichment],
) -> HardwareComponent:
    """Fill EMPTY fields on a component and its descendants from a lookup.

    ⚠ EMPTY FIELDS ONLY. See the module docstring — the customer's value wins,
    always, and every value this function does write is recorded in
    `enriched_fields` so a report can say where it came from.
    """
    for _, node in component.walk():
        key = node.model_number.strip().lower()
        if not key or key not in enrichments:
            continue
        found = enrichments[key]

        for attribute, value in (
            ("manufacturer_name", found.manufacturer_name),
            ("manufacturer_location", found.manufacturer_location),
            ("origin", found.origin),
            ("technology_node", found.technology_node),
        ):
            if value and not getattr(node, attribute, ""):
                setattr(node, attribute, value)
                node.enriched_fields[attribute] = found.source

        # Compliance is a union rather than a replacement: a customer asserting
        # RoHS and a provider asserting CE are both true, and dropping either
        # would understate the component.
        if found.compliance:
            existing = {c.lower() for c in node.compliance}
            added = [c for c in found.compliance if c.lower() not in existing]
            if added:
                node.compliance.extend(added)
                node.enriched_fields["compliance"] = found.source

    return component


def mpns(component: HardwareComponent) -> list[str]:
    """Every distinct part number in a tree, lower-cased.

    ⚠ DEDUPED BEFORE THE CALL. The same capacitor appears in four sub-assemblies
    of a real board; looking it up four times burns a commercial quota the
    customer pays for, to learn the same thing.
    """
    seen: dict[str, None] = {}
    for _, node in component.walk():
        key = node.model_number.strip().lower()
        if key:
            seen.setdefault(key, None)
    return list(seen)
