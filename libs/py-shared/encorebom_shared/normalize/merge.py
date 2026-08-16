"""Component merge — group by `component_key`, union the evidence.

⚠ IDENTITY IS THE PACKAGE. LOCATIONS ARE 1:N.

The same jar vendored at two paths is ONE component with two locations, not two
components. Putting the path in the key inflates every count in the report, and
the inflation looks like thoroughness.

⚠ A LOW-CONFIDENCE CPE NEVER MERGES INTO A PURL COMPONENT.

Dependency-Check emits CPEs with a confidence field, and a LOW match is a guess.
Merging it inherits Dependency-Check's false positives into otherwise-clean data
and the customer cannot tell which findings came from a guess. It attaches as a
CANDIDATE identity instead — visible, reviewable, and not load-bearing.

See `docs/03-NORMALIZER-SPEC.md` §1.3.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .identity import Identity, normalize_path
from .licenses import LicenseSet

#: `required` beats `optional` beats `excluded`.
#:
#: Precedence rather than "last writer wins": if any engine says a component is
#: required, it is required. Downgrading it to optional would let it drop out of
#: a filtered report.
_SCOPE_ORDER = {"required": 3, "optional": 2, "excluded": 1, "": 0}

#: Dependency-Check confidence values that must NOT merge.
LOW_CONFIDENCE = frozenset({"low", "LOW"})


@dataclass
class Observation:
    """One engine's sighting of a component."""

    engine: str
    engine_version: str = ""
    native_id: str = ""
    confidence: str = "medium"

    def as_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "engine_version": self.engine_version,
            "native_id": self.native_id,
            "confidence": self.confidence,
        }


@dataclass
class Location:
    """Where a component was found. Many per component."""

    path: str
    layer: str = ""
    sha256: str = ""

    def key(self) -> tuple[str, str, str]:
        return (self.path, self.layer, self.sha256)

    def as_dict(self) -> dict[str, Any]:
        return {"path": self.path, "layer": self.layer, "sha256": self.sha256}


@dataclass
class CandidateIdentity:
    """An identity claim recorded WITHOUT merging.

    This is where a low-confidence CPE goes. It is real information — a reviewer
    may well confirm it — but it does not get to change the component's identity
    or pull in findings.
    """

    kind: str
    value: str
    source_engine: str
    confidence: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "source_engine": self.source_engine,
            "confidence": self.confidence,
        }


@dataclass
class MergedComponent:
    """One canonical component, merged across engines."""

    component_key: str
    identity_rule: str
    identity_confidence: str
    name: str
    version_raw: str
    ecosystem: str = ""
    purl: str = ""
    scope: str = "required"
    locations: list[Location] = field(default_factory=list)
    hashes: list[dict[str, str]] = field(default_factory=list)
    licenses: LicenseSet = field(default_factory=LicenseSet)
    observed_by: list[Observation] = field(default_factory=list)
    candidate_identities: list[CandidateIdentity] = field(default_factory=list)
    #: OR'd across TRUSTED GRAPH SOURCES ONLY — never across all engines.
    is_direct: bool = False
    diagnostics: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        value, rule = self.licenses.effective()
        return {
            "component_key": self.component_key,
            "identity_rule": self.identity_rule,
            "identity_confidence": self.identity_confidence,
            "purl": self.purl,
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version_raw": self.version_raw,
            "scope": self.scope,
            "is_direct": self.is_direct,
            "license_effective": value,
            "license_rule": rule,
            "license_ambiguous": self.licenses.ambiguous,
            "locations": [loc.as_dict() for loc in sorted(self.locations, key=Location.key)],
            "hashes": sorted(self.hashes, key=lambda h: (h.get("alg", ""), h.get("value", ""))),
            "observed_by": [o.as_dict() for o in sorted(self.observed_by, key=lambda o: o.engine)],
            "candidate_identities": [
                c.as_dict() for c in sorted(self.candidate_identities, key=lambda c: c.value)
            ],
        }


@dataclass
class Contribution:
    """One engine's view of one component, ready to merge."""

    identity: Identity
    observation: Observation
    locations: list[Location] = field(default_factory=list)
    hashes: list[dict[str, str]] = field(default_factory=list)
    licenses: LicenseSet = field(default_factory=LicenseSet)
    scope: str = "required"
    #: Set only by engines trusted for this ecosystem's graph (§4).
    is_direct_from_trusted_graph: bool = False
    cpes: list[tuple[str, str]] = field(default_factory=list)


def merge(contributions: Iterable[Contribution]) -> list[MergedComponent]:
    """Group contributions by `component_key` and union their evidence."""
    grouped: dict[str, list[Contribution]] = {}
    for contribution in contributions:
        grouped.setdefault(contribution.identity.key, []).append(contribution)

    out: list[MergedComponent] = []
    for key in sorted(grouped):
        items = grouped[key]
        first = items[0].identity

        merged = MergedComponent(
            component_key=key,
            identity_rule=first.rule,
            identity_confidence=first.confidence,
            name=first.name,
            version_raw=first.version_raw,
            ecosystem=first.ecosystem,
            purl=first.purl,
        )

        locations: dict[tuple[str, str, str], Location] = {}
        hashes: dict[tuple[str, str], dict[str, str]] = {}
        candidates: dict[tuple[str, str], CandidateIdentity] = {}
        scope_rank = 0

        for item in items:
            merged.observed_by.append(item.observation)

            for location in item.locations:
                cleaned = Location(
                    path=normalize_path(location.path),
                    layer=location.layer,
                    sha256=location.sha256.lower(),
                )
                locations[cleaned.key()] = cleaned

            for entry in item.hashes:
                alg = str(entry.get("alg", "")).lower()
                value = str(entry.get("value", "")).lower()
                if alg and value:
                    hashes[(alg, value)] = {"alg": alg, "value": value}

            rank = _SCOPE_ORDER.get(item.scope, 0)
            if rank > scope_rank:
                scope_rank = rank
                merged.scope = item.scope

            # ⚠ OR'd across TRUSTED graph sources only. A flat-inventory engine
            # marking everything "direct" would otherwise make every transitive
            # dependency direct, and the direct count is a headline number.
            if item.is_direct_from_trusted_graph:
                merged.is_direct = True

            _merge_licenses(merged.licenses, item.licenses)

            # ⚠ CPEs attach as CANDIDATES, never as identity, whenever this
            # component is already identified by something stronger.
            for cpe, confidence in item.cpes:
                if not cpe:
                    continue
                if first.rule == "purl" or confidence.lower() in LOW_CONFIDENCE:
                    candidates[(cpe, item.observation.engine)] = CandidateIdentity(
                        kind="cpe",
                        value=cpe,
                        source_engine=item.observation.engine,
                        confidence=confidence,
                    )

        merged.locations = list(locations.values())
        merged.hashes = list(hashes.values())
        merged.candidate_identities = list(candidates.values())

        if merged.candidate_identities:
            merged.diagnostics.append(
                {
                    "severity": "info",
                    "code": "NORMALIZE_CANDIDATE_IDENTITY",
                    "message": (
                        f"{len(merged.candidate_identities)} identity claim(s) attached "
                        f"without merging"
                    ),
                    "hint": (
                        "a low-confidence CPE does not change identity; merging it would "
                        "inherit its false positives into otherwise-clean data"
                    ),
                    "component_key": key,
                }
            )

        out.append(merged)

    return out


def _merge_licenses(target: LicenseSet, source: LicenseSet) -> None:
    """Union the three license kinds.

    ⚠ `concluded` NEVER OVERWRITES `declared`. SPDX requires the distinction and
    "the manifest says MIT but the LICENSE file says Apache-2.0" is a finding a
    reviewer needs to see, not a conflict to resolve silently.
    """
    if target.declared is None and source.declared is not None:
        target.declared = source.declared
    if target.concluded is None and source.concluded is not None:
        target.concluded = source.concluded
    if target.observed is None and source.observed is not None:
        target.observed = source.observed


def never_merge_check(a: Identity, b: Identity) -> str:
    """Explain why two identities must not merge, or "" if they may.

    Exists so the rule is testable in isolation and so a future caller cannot
    re-derive it slightly differently.
    """
    if not a.mergeable or not b.mergeable:
        return "opaque identities never merge — we could not tell what they are"

    if a.key == b.key:
        return ""

    # ⚠ The single most common dedup bug in SBOM tooling.
    if (
        a.rule == "name"
        and b.rule == "name"
        and a.name == b.name
        and a.version_raw == b.version_raw
        and a.ecosystem != b.ecosystem
    ):
        return (
            f"name+version match across ecosystems ({a.ecosystem} vs {b.ecosystem}); "
            "these are unrelated components that happen to share a name"
        )

    if a.version_raw != b.version_raw:
        return (
            "version_raw differs; normalized equality is for display and ordering only "
            "(e.g. v24.0.5+incompatible is not v24.0.5)"
        )

    return "different component keys"
