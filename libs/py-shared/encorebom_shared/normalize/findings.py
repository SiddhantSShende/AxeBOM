"""Finding dedup, severity precedence, and fix-version ordering.

A finding is `(vuln_cluster_id, component_key)`. That pairing is what makes the
counts right:

    two engines, same CVE, same jar   ->  ONE finding, detected_by: [grype, trivy]
    same CVE, two components          ->  TWO findings
    same CVE, same component, 2 paths ->  ONE finding, two locations

⚠ SEVERITY IS NEVER AVERAGED, AND NEVER MAX'D ACROSS CVSS VERSIONS.

CVSS v2, v3.1 and v4.0 use different formulas and different ranges. A v2 score of
10.0 is not "worse" than a v3.1 of 9.8 — they are different scales, and taking a
max across them produces a number that exists in no scoring system. Precedence,
not arithmetic.

⚠ WHEN ENGINES DISAGREE, SAY SO.

`severity_conflict` is set and surfaced. Hiding it is the wrong instinct: a
reviewer will ask why Trivy said High and Grype said Critical, and the answer has
to be visible rather than buried under a number we picked.

See `docs/03-NORMALIZER-SPEC.md` §2.4 and §2.5.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .aliases import normalize_id
from .versions import NoComparatorError, has_comparator, minimum

#: Severity ladder, low to high. Used for the last-resort "max of tool strings"
#: step ONLY — never to combine numeric scores from different CVSS versions.
SEVERITY_ORDER = ["none", "negligible", "unknown", "low", "medium", "high", "critical"]

_SEVERITY_ALIASES = {
    "moderate": "medium",
    "important": "high",
    "info": "none",
    "informational": "none",
    "": "unknown",
}

#: Precedence for `severity_effective`. Lower index wins.
#:
#: ⚠ The ORDER is the design. Each step is a different authority, and mixing
#: them arithmetically would be meaningless.
SEVERITY_PRECEDENCE = [
    "tenant-policy",
    "cvss-v4",
    "nvd-cvss-v3.1",
    "advisory-cvss-v3.1",
    "vendor-string",
    "tool-string-max",
]


@dataclass
class CvssVector:
    """One CVSS assertion, kept verbatim.

    EVERY source is stored. The report shows which one drove the effective
    severity and what the others said, because a reviewer asking "why Critical?"
    needs the whole picture, not the winner.
    """

    version: str
    vector: str
    score: float | None
    severity: str
    source: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "vector": self.vector,
            "score": self.score,
            "severity": self.severity,
            "source": self.source,
        }


@dataclass
class RawFinding:
    """One engine's report of one vulnerability against one component.

    Ingested verbatim into `normalize.raw_findings` and NEVER deduped at ingest:
    deduping there would destroy the audit trail and make the merge
    unexplainable (spec §2.1).
    """

    vuln_id: str
    component_key: str
    engine: str
    engine_version: str = ""
    severity: str = ""
    cvss: list[CvssVector] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    ecosystem: str = ""
    native_id: str = ""
    description: str = ""


@dataclass
class Finding:
    """A deduped finding."""

    vuln_cluster_id: str
    component_key: str
    display_id: str
    severity_effective: str
    severity_rule: str
    severity_conflict: bool
    detected_by: list[str]
    cvss_vectors: list[CvssVector]
    fixed_versions: list[str]
    fixed_in_min: str
    #: `unknown` when the ecosystem has no comparator — never a guess.
    fix_version_ordering: str
    ecosystem: str = ""
    diagnostics: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "vuln_cluster_id": self.vuln_cluster_id,
            "component_key": self.component_key,
            "display_id": self.display_id,
            "severity_effective": self.severity_effective,
            "severity_rule": self.severity_rule,
            "severity_conflict": self.severity_conflict,
            "detected_by": sorted(self.detected_by),
            "cvss_vectors": [v.as_dict() for v in self.cvss_vectors],
            "fixed_versions": self.fixed_versions,
            "fixed_in_min": self.fixed_in_min,
            "fix_version_ordering": self.fix_version_ordering,
            "ecosystem": self.ecosystem,
        }


def normalize_severity(value: str) -> str:
    """Fold vendor severity spellings onto the common ladder."""
    text = (value or "").strip().lower()
    text = _SEVERITY_ALIASES.get(text, text)
    return text if text in SEVERITY_ORDER else "unknown"


def dedup(
    raw: Iterable[RawFinding],
    *,
    cluster_of: dict[str, str],
    display_of: dict[str, str],
    policy_override: dict[str, str] | None = None,
) -> list[Finding]:
    """Collapse raw findings onto `(cluster, component)`.

    `cluster_of` maps a normalized vuln id -> durable cluster id.
    `display_of` maps cluster id -> the display id pinned for this render.
    """
    overrides = policy_override or {}

    # ⚠ The MAP KEYS are normalized too, not just the lookup.
    #
    # A caller holding `{"ghsa-a-b-c": "c1"}` would otherwise miss, and a miss is
    # silent: the finding keeps its raw id as its cluster, so the same
    # vulnerability reported by two engines under two spellings becomes two
    # findings. `display_of` is NOT normalized — it is keyed by opaque cluster
    # surrogates, which are not vulnerability ids.
    cluster_of = {normalize_id(k): v for k, v in cluster_of.items()}

    grouped: dict[tuple[str, str], list[RawFinding]] = {}

    for item in raw:
        # ⚠ Normalized before the lookup. Engines emit `GHSA-r5fr-...` and
        # `ghsa-r5fr-...` for the same advisory; an unnormalized miss would give
        # the finding a raw id where every other finding carries a durable
        # cluster id, and the two would never dedup against each other.
        vuln_id = normalize_id(item.vuln_id)
        cluster = cluster_of.get(vuln_id, vuln_id)
        grouped.setdefault((cluster, item.component_key), []).append(item)

    out: list[Finding] = []
    for (cluster, component_key), items in sorted(grouped.items()):
        severity, rule, conflict = resolve_severity(items, override=overrides.get(cluster))

        vectors: list[CvssVector] = []
        seen_vectors: set[tuple[str, str, str]] = set()
        for item in items:
            for vector in item.cvss:
                key = (vector.version, vector.vector, vector.source)
                if key not in seen_vectors:
                    seen_vectors.add(key)
                    vectors.append(vector)

        ecosystem = next((i.ecosystem for i in items if i.ecosystem), "")
        fixed = sorted({v for i in items for v in i.fixed_versions if v})

        fixed_min, ordering, diagnostics = resolve_fix_version(ecosystem, fixed)

        out.append(
            Finding(
                vuln_cluster_id=cluster,
                component_key=component_key,
                display_id=display_of.get(cluster, cluster),
                severity_effective=severity,
                severity_rule=rule,
                severity_conflict=conflict,
                detected_by=sorted({i.engine for i in items}),
                cvss_vectors=sorted(vectors, key=lambda v: (v.version, v.source, v.vector)),
                fixed_versions=fixed,
                fixed_in_min=fixed_min,
                fix_version_ordering=ordering,
                ecosystem=ecosystem,
                diagnostics=diagnostics,
            )
        )

    return out


def resolve_severity(
    items: list[RawFinding], *, override: str | None = None
) -> tuple[str, str, bool]:
    """Apply the precedence ladder. Returns (severity, rule, conflict).

    ⚠ NO AVERAGING AND NO CROSS-VERSION MAX. Each step consults exactly one
    authority; if it has an answer, that answer wins outright.
    """
    conflict = _has_conflict(items)

    if override:
        return normalize_severity(override), "tenant-policy", conflict

    # CVSS v4, then NVD v3.1, then advisory v3.1. Within a version the sources
    # agree by construction, so the first match is the answer.
    for version, source_filter, rule in (
        ("4.0", None, "cvss-v4"),
        ("3.1", "nvd", "nvd-cvss-v3.1"),
        ("3.1", None, "advisory-cvss-v3.1"),
    ):
        for item in items:
            for vector in item.cvss:
                if not vector.version.startswith(version.split(".")[0] + "."):
                    continue
                if version == "4.0" and not vector.version.startswith("4"):
                    continue
                if source_filter and source_filter not in vector.source.lower():
                    continue
                if vector.severity:
                    return normalize_severity(vector.severity), rule, conflict

    # Vendor severity string.
    for item in items:
        if item.severity:
            return normalize_severity(item.severity), "vendor-string", conflict

    # Last resort: the highest of the remaining tool strings. This IS a max, but
    # over an ordinal ladder of severity words — not over incomparable numeric
    # scores from different CVSS versions.
    best = "unknown"
    for item in items:
        candidate = normalize_severity(item.severity)
        if SEVERITY_ORDER.index(candidate) > SEVERITY_ORDER.index(best):
            best = candidate
    return best, "tool-string-max", conflict


def _has_conflict(items: list[RawFinding]) -> bool:
    """Whether the engines disagreed about severity.

    Computed over the words, not the scores: "Trivy said High, Grype said
    Critical" is the disagreement a reviewer notices and asks about.
    """
    seen = {normalize_severity(i.severity) for i in items if i.severity}
    seen.discard("unknown")
    return len(seen) > 1


def resolve_fix_version(
    ecosystem: str, versions: list[str]
) -> tuple[str, str, list[dict[str, Any]]]:
    """Compute `fixed_in_min` with an ecosystem-correct comparator.

    ⚠ WHERE NO COMPARATOR EXISTS, THE ANSWER IS `unknown` — NOT A GUESS.

    A lexical sort would report the lowest fix for a CVE as 1.10.0 when it is
    really 1.9.0, telling a customer to install a version that does not contain
    the fix. An admitted gap is recoverable; a confident wrong version is not.
    """
    if not versions:
        return "", "none", []

    if not has_comparator(ecosystem):
        return (
            "",
            "unknown",
            [
                {
                    "severity": "warn",
                    "code": "NORMALIZE_NO_VERSION_COMPARATOR",
                    "message": f"no version ordering is defined for ecosystem {ecosystem or '<unknown>'!r}",
                    "hint": (
                        "fixed_in_min is left empty and patch_status derives to unknown; "
                        "a lexical sort would report the wrong minimum fix"
                    ),
                }
            ],
        )

    try:
        return minimum(ecosystem, versions), "comparator", []
    except NoComparatorError:
        return (
            "",
            "unknown",
            [
                {
                    "severity": "warn",
                    "code": "NORMALIZE_NO_VERSION_COMPARATOR",
                    "message": f"no version ordering for {ecosystem!r}",
                    "hint": "patch_status derives to unknown",
                }
            ],
        )


def patch_status(installed: str, fixed_in_min: str, ecosystem: str, ordering: str) -> str:
    """Derive `patch_status` for a component.

    Returns `unknown` whenever the ordering is unknown, rather than guessing —
    the whole point of tracking `fix_version_ordering` separately.
    """
    if ordering == "unknown" or not fixed_in_min or not installed:
        return "unknown"
    if not has_comparator(ecosystem):
        return "unknown"

    try:
        from .versions import compare

        result = compare(ecosystem, installed, fixed_in_min)
    except NoComparatorError:
        return "unknown"

    return "patched" if result >= 0 else "vulnerable"
