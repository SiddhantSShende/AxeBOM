"""The normalization pipeline — raw artifacts in, canonical model out.

⚠ A DETERMINISTIC PURE FUNCTION of *(raw artifacts + ruleset version + alias
snapshot)*.

No wall-clock reads, no randomness, no network. `generated_at` is passed in from
the scan record. Every collection is sorted before it is returned. Run it twice
over the same inputs and the bytes are identical — that is what makes a report
defensible six months later, and what stops the golden tests flapping.

Order matters and is not arbitrary:

    1. ingest      every engine's artifact, verbatim, nothing deduped yet
    2. merge       components onto component_key
    3. graph       replace per ecosystem, then BFS for depth/directness
    4. aliases     union-find, then durable cluster ids
    5. findings    dedup on (cluster, component), severity precedence
    6. coverage    both numbers, over the merged set
    7. provenance  what ran, what did not, what had no engine at all

Findings come AFTER components because a finding's key references a component
key, and coverage comes last because it scores the merged result rather than any
single engine's view.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from . import RULESET_VERSION
from .aliases import (
    AliasEdge,
    assign_cluster_ids,
    close,
    edges_from_grype,
    edges_from_osv,
    normalize_id,
)
from .coverage import CoverageResult, Field, score
from .findings import Finding, dedup
from .graph import GraphResult, merge_edges
from .graph import build as build_graph
from .ingest import Ingested, ingest
from .licenses import SPDX_LICENSE_LIST_VERSION
from .merge import MergedComponent, merge
from .provenance import EngineRecord, ProvenanceManifest, known_unknowns, merge_diagnostics


@dataclass
class Artifact:
    """One engine's stored raw output."""

    engine: str
    payload: Any
    engine_version: str = ""
    engine_db_version: str = ""
    status: str = "succeeded"
    sha256: str = ""
    uri: str = ""


@dataclass
class NormalizationResult:
    """The canonical model for one scan."""

    components: list[MergedComponent]
    findings: list[Finding]
    graph: GraphResult
    coverage: CoverageResult
    manifest: ProvenanceManifest
    clusters: list[dict[str, Any]] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    unidentified_count: int = 0

    def as_dict(self) -> dict[str, Any]:
        """Serialize deterministically.

        ⚠ EVERY collection is sorted. An unstable order makes the golden diff
        flap on unrelated changes, and a test that flaps is a test that gets
        ignored — which is worse than not having it (spec §8).
        """
        return {
            "ruleset_version": RULESET_VERSION,
            "spdx_license_list_version": SPDX_LICENSE_LIST_VERSION,
            "components": [c.as_dict() for c in self.components],
            "component_count": len(self.components),
            "unidentified_count": self.unidentified_count,
            "findings": [f.as_dict() for f in self.findings],
            "finding_count": len(self.findings),
            "vuln_clusters": self.clusters,
            "graph": {
                "roots": self.graph.roots,
                "orphans": self.graph.orphans,
                "owning_engine": dict(sorted(self.graph.owning_engine.items())),
                "depth": dict(sorted(self.graph.depth.items())),
                "direct": sorted(self.graph.direct),
                "edges": [e.as_dict() for e in self.graph.edges],
            },
            "coverage": self.coverage.as_dict(),
            "provenance": self.manifest.as_dict(),
            "engine_coverage": self.manifest.engine_coverage(),
            "known_unknowns": known_unknowns(self.manifest),
            "diagnostics": self.diagnostics,
        }


def normalize(
    artifacts: Iterable[Artifact],
    *,
    scan_id: str,
    fields: list[Field],
    graph_trust: dict[str, dict[str, int]] | None = None,
    existing_clusters: dict[str, str] | None = None,
    cluster_ids: Iterator[str] | None = None,
    alias_snapshot_id: str = "",
    source_commit_sha: str = "",
    workspace_archive_sha256: str = "",
    normalization_version: int = 1,
    ecosystems_without_engine: Iterable[str] = (),
) -> NormalizationResult:
    """Run the full pipeline."""
    trust = graph_trust or _DEFAULT_GRAPH_TRUST
    artifacts = list(artifacts)

    # ── 1. INGEST ────────────────────────────────────────────────────────
    ingested: dict[str, Ingested] = {}
    engine_records: list[EngineRecord] = []
    diagnostic_groups: list[list[dict[str, Any]]] = []

    for artifact in artifacts:
        trusted = frozenset(
            eco for eco, rank in (trust.get(artifact.engine) or {}).items() if rank <= 2
        )
        result = ingest(
            artifact.engine,
            artifact.payload,
            scan_id=scan_id,
            engine_version=artifact.engine_version,
            trusted_graph_ecosystems=trusted,
        )
        ingested[artifact.engine] = result
        diagnostic_groups.append(result.diagnostics)

        engine_records.append(
            EngineRecord(
                engine_id=artifact.engine,
                version=artifact.engine_version,
                status=artifact.status,
                engine_db_version=artifact.engine_db_version,
                ecosystems_covered=sorted(
                    {c.identity.ecosystem for c in result.contributions if c.identity.ecosystem}
                ),
                artifact_sha256=artifact.sha256,
            )
        )

    # ── 2. MERGE COMPONENTS ──────────────────────────────────────────────
    components = merge(itertools.chain.from_iterable(r.contributions for r in ingested.values()))
    unidentified = sum(1 for c in components if c.identity_rule == "opaque")
    diagnostic_groups.extend(c.diagnostics for c in components if c.diagnostics)

    # ── 3. GRAPH ─────────────────────────────────────────────────────────
    contributions = {engine: r.edges for engine, r in ingested.items() if r.edges}
    edges, owning, graph_diagnostics = merge_edges(contributions, trust)

    roots = sorted({root for r in ingested.values() for root in r.roots})
    if not roots:
        # ⚠ No declared root. Falling back to "everything nothing depends on"
        # is a heuristic, and it is labelled as one — a monorepo legitimately
        # has N roots and this is how they are recovered when the SBOM does not
        # name them.
        targets = {e.to_key for e in edges}
        roots = sorted({c.component_key for c in components} - targets) if edges else []

    graph = build_graph(
        component_keys=[c.component_key for c in components],
        edges=edges,
        roots=roots,
        owning_engine=owning,
        extra_diagnostics=graph_diagnostics,
    )

    for component in components:
        if component.component_key in graph.direct:
            component.is_direct = True

    # ── 4. ALIAS CLOSURE ─────────────────────────────────────────────────
    alias_edges: list[AliasEdge] = []
    for artifact in artifacts:
        if artifact.engine == "osv-scanner" and isinstance(artifact.payload, dict):
            alias_edges.extend(edges_from_osv(artifact.payload))
        elif artifact.engine == "grype" and isinstance(artifact.payload, dict):
            alias_edges.extend(edges_from_grype(artifact.payload))

    raw_findings = list(itertools.chain.from_iterable(r.findings for r in ingested.values()))
    seed_ids = sorted({f.vuln_id for f in raw_findings if f.vuln_id})

    closure = close(alias_edges, seed_ids=seed_ids)
    clusters = assign_cluster_ids(
        closure,
        existing=existing_clusters or {},
        mint=cluster_ids or _default_ids(scan_id),
    )

    cluster_of: dict[str, str] = {}
    display_of: dict[str, str] = {}
    cluster_rows: list[dict[str, Any]] = []
    for cluster in clusters:
        for member in cluster.members:
            cluster_of[member] = cluster.cluster_id
        display_of[cluster.cluster_id] = cluster.display_id
        cluster_rows.append(
            {
                "cluster_id": cluster.cluster_id,
                # ⚠ PINNED AT RENDER. A report issued in March must still say
                # CVE-2021-44228 in September, even after the cluster absorbs
                # more aliases (ADR-0005).
                "display_id_at_render": cluster.display_id,
                "members": list(cluster.members),
                "flagged_for_review": cluster.flagged_for_review,
                "merges": [m.as_dict() for m in cluster.merges],
            }
        )

    if closure.refused:
        diagnostic_groups.append(
            [
                {
                    "severity": "info",
                    "code": "NORMALIZE_ALIAS_EDGE_REFUSED",
                    "message": f"{len(closure.refused)} alias edge(s) were refused",
                    "hint": "; ".join(sorted({r.reason for r in closure.refused}))[:400],
                }
            ]
        )
    if closure.flagged:
        diagnostic_groups.append(
            [
                {
                    "severity": "warn",
                    "code": "NORMALIZE_CLUSTER_FLAGGED",
                    "message": f"{len(closure.flagged)} vulnerability cluster(s) exceeded the size ceiling",
                    "hint": "flagged for review rather than merged further; likely an over-merge",
                }
            ]
        )

    # ── 5. FINDINGS ──────────────────────────────────────────────────────
    # A vulnerability that appears in no alias edge is its own cluster of one.
    # It still needs an entry in both maps, or the finding would carry a raw id
    # where every other finding carries a durable one.
    for finding_id in seed_ids:
        normalized = normalize_id(finding_id)
        if normalized not in cluster_of:
            cluster_of[normalized] = normalized
            display_of[normalized] = normalized

    findings = dedup(raw_findings, cluster_of=cluster_of, display_of=display_of)
    for finding in findings:
        if finding.diagnostics:
            diagnostic_groups.append(finding.diagnostics)

    # ── 6. COVERAGE ──────────────────────────────────────────────────────
    # ⚠ `excluded` AND `opaque` COMPONENTS STAY IN THE DENOMINATOR (spec §5.4).
    #
    # They are not scored — there is nothing to score them against — but their
    # weight still counts. Removing them is how a scan that understood three
    # components out of three hundred reports a coverage figure computed over
    # the three.
    scored = [c for c in components if c.identity_rule != "opaque" and c.scope != "excluded"]
    not_scored = len(components) - len(scored)

    coverage = score(
        [_flatten(c) for c in scored],
        fields,
        unidentified=not_scored,
    )
    diagnostic_groups.append(coverage.diagnostics)

    # ── 7. PROVENANCE ────────────────────────────────────────────────────
    manifest = ProvenanceManifest(
        scan_id=scan_id,
        ruleset_version=RULESET_VERSION,
        spdx_license_list_version=SPDX_LICENSE_LIST_VERSION,
        alias_snapshot_id=alias_snapshot_id,
        source_commit_sha=source_commit_sha,
        workspace_archive_sha256=workspace_archive_sha256,
        normalization_version=normalization_version,
        engines=engine_records,
        ecosystems_without_engine=list(ecosystems_without_engine),
    )

    return NormalizationResult(
        components=components,
        findings=findings,
        graph=graph,
        coverage=coverage,
        manifest=manifest,
        clusters=cluster_rows,
        diagnostics=merge_diagnostics(*diagnostic_groups),
        unidentified_count=unidentified,
    )


def _flatten(component: MergedComponent) -> dict[str, Any]:
    """Flatten a component onto the profile's canonical paths.

    The profile keys everything by `canonical_path`, so scoring needs that shape
    rather than the object. Fields the model does not carry yet are ABSENT
    rather than defaulted — an absent field scores zero on both numbers, which
    is the honest answer for something we never collected.
    """
    value, _rule = component.licenses.effective()
    return {
        "component.name": component.name,
        "component.version_raw": component.version_raw,
        "component.purl": component.purl,
        "component.ecosystem": component.ecosystem,
        "component.license_declared": (
            component.licenses.declared.value if component.licenses.declared else None
        ),
        "component.license_concluded": (
            component.licenses.concluded.value if component.licenses.concluded else None
        ),
        "component.license_effective": value,
        "component.hashes": component.hashes,
        "component.scope": component.scope,
        "component.author_of_sbom_data": ", ".join(
            sorted({o.engine for o in component.observed_by})
        ),
    }


def _default_ids(scan_id: str) -> Iterator[str]:
    """Deterministic cluster ids for a run with no database behind it.

    ⚠ Used by tests and the fixture generator ONLY. In production the ids come
    from `normalize.vuln_clusters` rows, which is what makes them durable across
    scans; these are stable within one run but carry no cross-scan meaning.
    """
    return (f"{scan_id}-cluster-{i:04d}" for i in itertools.count())


#: Per-ecosystem graph trust, lower rank winning.
#:
#: syft ranks LAST everywhere because it produces a near-flat inventory with weak
#: edges — useful as an inventory, misleading as a graph. See spec §4.2.
_DEFAULT_GRAPH_TRUST: dict[str, dict[str, int]] = {
    "trivy-fs": {"npm": 2, "pypi": 2, "maven": 1, "golang": 2},
    "osv-scanner": {"npm": 1, "pypi": 1, "maven": 2, "golang": 1},
    "syft": {"npm": 5, "pypi": 5, "maven": 5, "golang": 5},
}
