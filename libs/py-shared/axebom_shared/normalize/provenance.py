"""Provenance — how a line in a report is traced back to its evidence.

⚠ THE QUESTION THIS ANSWERS: "where did this line in this report come from?"

In an audit, six months after issue, that question has to have an answer that
does not depend on re-running anything. Every normalized entity carries the
engine, its version, its database vintage, the raw artifact and its digest, and
the rule that produced the value.

⚠ NO WALL-CLOCK READS ANYWHERE IN THIS MODULE.

`observed_at` and `generated_at` are passed in from the scan record. A
`datetime.now()` here would make normalization non-deterministic and break
replay — the same stored artifacts must produce byte-identical output on every
run, or the golden tests flap and their failures get ignored (ADR-0003).

See `docs/03-NORMALIZER-SPEC.md` §7.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from . import RULESET_VERSION


@dataclass(frozen=True)
class EntityProvenance:
    """Provenance for one normalized entity."""

    engine_id: str
    engine_version: str
    job_id: str
    #: RFC3339 with a literal Z, from the scan record — never `now()`.
    observed_at: str
    engine_db_version: str = ""
    raw_finding_id: str = ""
    artifact_uri: str = ""
    artifact_sha256: str = ""
    rule_id: str = ""
    rule_version: str = RULESET_VERSION
    confidence: str = "medium"

    def as_dict(self) -> dict[str, Any]:
        return {
            "engine_id": self.engine_id,
            "engine_version": self.engine_version,
            "engine_db_version": self.engine_db_version,
            "job_id": self.job_id,
            "raw_finding_id": self.raw_finding_id,
            "artifact_uri": self.artifact_uri,
            "artifact_sha256": self.artifact_sha256,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "confidence": self.confidence,
            "observed_at": self.observed_at,
        }


@dataclass
class EngineRecord:
    """What one engine contributed to a scan, including when it did not."""

    engine_id: str
    version: str
    status: str
    image_digest: str = ""
    engine_db_version: str = ""
    ecosystems_covered: list[str] = field(default_factory=list)
    artifact_sha256: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "engine_id": self.engine_id,
            "version": self.version,
            "status": self.status,
            "image_digest": self.image_digest,
            "engine_db_version": self.engine_db_version,
            "ecosystems_covered": sorted(self.ecosystems_covered),
            "artifact_sha256": self.artifact_sha256,
        }


@dataclass
class ProvenanceManifest:
    """The scan-level record: everything needed to reproduce this output."""

    scan_id: str
    ruleset_version: str
    spdx_license_list_version: str
    alias_snapshot_id: str
    source_commit_sha: str = ""
    workspace_archive_sha256: str = ""
    normalization_version: int = 1
    engines: list[EngineRecord] = field(default_factory=list)
    #: ⚠ Ecosystems detected with NO available engine. The honest denominator.
    ecosystems_without_engine: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "ruleset_version": self.ruleset_version,
            "spdx_license_list_version": self.spdx_license_list_version,
            "alias_snapshot_id": self.alias_snapshot_id,
            "source_commit_sha": self.source_commit_sha,
            "workspace_archive_sha256": self.workspace_archive_sha256,
            "normalization_version": self.normalization_version,
            "engines": [e.as_dict() for e in sorted(self.engines, key=lambda e: e.engine_id)],
            "ecosystems_without_engine": sorted(self.ecosystems_without_engine),
        }

    def engine_coverage(self) -> list[dict[str, Any]]:
        """The mandatory Engine Coverage section (invariant 12).

        ⚠ INCLUDES THE ROWS WITH NO ENGINE. An SBOM that silently omits an
        ecosystem is worse than no SBOM: it converts an unknown into a false
        negative the customer trusts. The gap rows are the honest denominator
        that most tools hide.
        """
        rows = [e.as_dict() for e in sorted(self.engines, key=lambda e: e.engine_id)]
        for ecosystem in sorted(self.ecosystems_without_engine):
            rows.append(
                {
                    "engine_id": "",
                    "version": "",
                    "status": "no-engine-available",
                    "ecosystems_covered": [ecosystem],
                    "note": (
                        f"{ecosystem} was detected in the source but no configured engine "
                        f"can scan it; its components and vulnerabilities are NOT in this report"
                    ),
                }
            )
        return rows


def known_unknowns(manifest: ProvenanceManifest) -> str:
    """Text for `project.practices.known_unknowns`, derived not typed.

    CERT-In Table 5's Practices and Processes includes a Known Unknowns
    declaration. Deriving it from what actually happened — rather than asking a
    human to keep a paragraph up to date — is what keeps it true after the
    fourth scan.
    """
    parts: list[str] = []

    if manifest.ecosystems_without_engine:
        parts.append(
            "Ecosystems detected with no available engine: "
            + ", ".join(sorted(manifest.ecosystems_without_engine))
            + ". Components and vulnerabilities in these ecosystems are not represented."
        )

    degraded = [
        e for e in manifest.engines if e.status in ("unavailable", "failed", "timeout", "partial")
    ]
    if degraded:
        parts.append(
            "Engines that did not complete: "
            + ", ".join(
                f"{e.engine_id} ({e.status})" for e in sorted(degraded, key=lambda x: x.engine_id)
            )
            + "."
        )

    if not parts:
        return "All configured engines completed and every detected ecosystem had an engine."

    return " ".join(parts)


def merge_diagnostics(*groups: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Combine diagnostic lists deterministically.

    Sorted and deduplicated, because these end up in a report and in golden
    files: an unstable order would make every golden test flap on unrelated
    changes (spec §8).
    """
    seen: dict[str, dict[str, Any]] = {}
    for group in groups:
        for diagnostic in group:
            key = "|".join(
                str(diagnostic.get(k, ""))
                for k in ("code", "message", "component_key", "ecosystem")
            )
            seen.setdefault(key, diagnostic)
    return [seen[k] for k in sorted(seen)]
