"""Re-normalize stored artifacts into `normalization_version + 1`.

⚠ THIS IS THE PAYOFF OF ADR-0003, AND THE REASON RAW ARTIFACTS ARE IMMUTABLE.

Fixing a normalizer bug does NOT mean re-running the scanners. It means
replaying what is already in object storage through the new rules. That buys
three things, each of which would otherwise be very expensive:

  1. **Reports stay defensible.** Version 1 is untouched, so a report issued
     against it still resolves to exactly the data it was rendered from.
  2. **Fixes are retroactive.** A dedup bug fixed in month 9 applies to every
     scan ever run, without touching a customer's repository — and without
     needing their credentials, their network, or their permission.
  3. **A CERT-In revision is a data change.** New profile, re-normalize, done.

Re-running the scanners instead would not even be reproducible: vulnerability
databases have moved, the tools have changed, and the repository HEAD may
differ. You would get a different answer and be unable to tell which part of the
difference was your fix.

⚠ VERSION N IS NEVER OVERWRITTEN. A new version is written alongside it. If a
re-normalization produces something worse, the previous answer is still there.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from . import RULESET_VERSION
from .coverage import Field
from .pipeline import Artifact, NormalizationResult, normalize


@dataclass
class VersionDiff:
    """What changed between two normalization versions.

    ⚠ EVERY RE-NORMALIZATION PRODUCES ONE, and it is the artifact a human reads
    before trusting the new version. A silent re-normalization that changed
    every count would be indistinguishable from one that changed nothing.
    """

    from_version: int
    to_version: int
    from_ruleset: str
    to_ruleset: str

    components_added: list[str] = field(default_factory=list)
    components_removed: list[str] = field(default_factory=list)
    findings_added: list[str] = field(default_factory=list)
    findings_removed: list[str] = field(default_factory=list)

    completeness_delta: float = 0.0
    declaration_delta: float = 0.0

    @property
    def changed(self) -> bool:
        return bool(
            self.components_added
            or self.components_removed
            or self.findings_added
            or self.findings_removed
            or abs(self.completeness_delta) > 0.001
            or abs(self.declaration_delta) > 0.001
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "from_version": self.from_version,
            "to_version": self.to_version,
            "from_ruleset": self.from_ruleset,
            "to_ruleset": self.to_ruleset,
            "changed": self.changed,
            "components_added": self.components_added,
            "components_removed": self.components_removed,
            "findings_added": self.findings_added,
            "findings_removed": self.findings_removed,
            "completeness_delta": round(self.completeness_delta, 2),
            "declaration_delta": round(self.declaration_delta, 2),
        }

    def summary(self) -> str:
        if not self.changed:
            return (
                f"v{self.to_version} is identical to v{self.from_version}; "
                f"the ruleset change had no effect on this scan"
            )
        parts = []
        if self.components_added or self.components_removed:
            parts.append(
                f"components +{len(self.components_added)} -{len(self.components_removed)}"
            )
        if self.findings_added or self.findings_removed:
            parts.append(f"findings +{len(self.findings_added)} -{len(self.findings_removed)}")
        if abs(self.completeness_delta) > 0.001:
            parts.append(f"completeness {self.completeness_delta:+.2f}pp")
        return f"v{self.from_version} -> v{self.to_version}: " + ", ".join(parts)


def renormalize(
    artifacts: Iterable[Artifact],
    previous: dict[str, Any],
    *,
    scan_id: str,
    fields: list[Field],
    **kwargs: Any,
) -> tuple[NormalizationResult, VersionDiff]:
    """Replay stored artifacts into the next version, and diff against the old.

    `previous` is the stored canonical model for version N — passed in rather
    than loaded here, so this stays a pure function and can be tested without
    storage.
    """
    from_version = int(previous.get("provenance", {}).get("normalization_version", 1))
    to_version = from_version + 1

    result = normalize(
        artifacts,
        scan_id=scan_id,
        fields=fields,
        normalization_version=to_version,
        **kwargs,
    )

    return result, diff(previous, result.as_dict())


def diff(previous: dict[str, Any], current: dict[str, Any]) -> VersionDiff:
    """Compare two canonical models."""
    old_components = {c["component_key"] for c in previous.get("components", [])}
    new_components = {c["component_key"] for c in current.get("components", [])}

    def finding_key(f: dict[str, Any]) -> str:
        # Keyed on the DISPLAY id rather than the cluster id: cluster ids are
        # durable surrogates that differ between a stored run and a fresh one,
        # and diffing on them would report every finding as changed.
        return f"{f.get('display_id', '')}@{f.get('component_key', '')}"

    old_findings = {finding_key(f) for f in previous.get("findings", [])}
    new_findings = {finding_key(f) for f in current.get("findings", [])}

    old_coverage = previous.get("coverage", {})
    new_coverage = current.get("coverage", {})

    return VersionDiff(
        from_version=int(previous.get("provenance", {}).get("normalization_version", 1)),
        to_version=int(current.get("provenance", {}).get("normalization_version", 2)),
        from_ruleset=str(previous.get("ruleset_version", "")),
        to_ruleset=str(current.get("ruleset_version", RULESET_VERSION)),
        components_added=sorted(new_components - old_components),
        components_removed=sorted(old_components - new_components),
        findings_added=sorted(new_findings - old_findings),
        findings_removed=sorted(old_findings - new_findings),
        completeness_delta=(
            float(new_coverage.get("completeness_pct", 0))
            - float(old_coverage.get("completeness_pct", 0))
        ),
        declaration_delta=(
            float(new_coverage.get("declaration_pct", 0))
            - float(old_coverage.get("declaration_pct", 0))
        ),
    )
