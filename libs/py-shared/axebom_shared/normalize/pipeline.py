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
from collections import defaultdict
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
from .findings import Finding, aggregate_patch_status, dedup, patch_status
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
    generated_at: str = "",
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

    # ── 5a. PATCH STATUS ─────────────────────────────────────────────────
    # CERT-In field 9, and the ONLY place it can be derived: merge() has the
    # installed version but no findings, dedup() has the fix versions but no
    # component. The join belongs here, between them.
    #
    # ⚠ A COMPONENT WITH NO FINDINGS IS LEFT UNSET, NOT MARKED up-to-date.
    # "No engine reported a vulnerability against this" is ambiguous between
    # "verified clean" and "no engine covered this ecosystem at all" — and at
    # this point nothing on the component can tell those apart (that lives in
    # the provenance manifest's ecosystems_without_engine). Defaulting to
    # up-to-date would manufacture a substantive claim out of an absence,
    # which is the same false-negative `not-provided` exists to prevent.
    findings_by_component: dict[str, list[Finding]] = {}
    for finding in findings:
        findings_by_component.setdefault(finding.component_key, []).append(finding)

    for component in components:
        component_findings = findings_by_component.get(component.component_key)
        if not component_findings:
            continue
        component.patch_status = aggregate_patch_status(
            # ⚠ component.ecosystem, NOT finding.ecosystem. The component is the
            # authority on its own ecosystem; a RawFinding's copy is set at each
            # of ingest.py's several construction sites and need not be present.
            patch_status(
                component.version_raw,
                f.fixed_in_min,
                component.ecosystem,
                f.fix_version_ordering,
            )
            for f in component_findings
        )

    # ── 6. COVERAGE ──────────────────────────────────────────────────────
    # ⚠ `excluded` AND `opaque` COMPONENTS STAY IN THE DENOMINATOR (spec §5.4).
    #
    # They are not scored — there is nothing to score them against — but their
    # weight still counts. Removing them is how a scan that understood three
    # components out of three hundred reports a coverage figure computed over
    # the three.
    scored = [c for c in components if c.identity_rule != "opaque" and c.scope != "excluded"]
    not_scored = len(components) - len(scored)

    # ⚠ GROUPED ONCE, KEYED BY THE SAME `component_key` FINDINGS AND THE GRAPH
    # ALREADY USE. Without this, certin.sbom.07/08 (Dependencies, Vulnerabilities)
    # score zero forever even when `normalize.component_dependencies` and
    # `normalize.findings` hold real rows — the data landed, it just never
    # reached the flattened entity `score()` reads.
    edges_by_from: dict[str, list[Any]] = defaultdict(list)
    for edge in graph.edges:
        edges_by_from[edge.from_key].append(edge)

    coverage = score(
        [
            _flatten(
                c,
                edges=edges_by_from.get(c.component_key, []),
                findings=findings_by_component.get(c.component_key, []),
                generated_at=generated_at,
            )
            for c in scored
        ],
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


def _flatten(
    component: MergedComponent,
    *,
    edges: Iterable[Any] = (),
    findings: Iterable[Finding] = (),
    generated_at: str = "",
) -> dict[str, Any]:
    """Flatten a component onto the profile's canonical paths.

    The profile keys everything by `canonical_path`, so scoring needs that shape
    rather than the object. Fields the model does not carry yet are ABSENT
    rather than defaulted — an absent field scores zero on both numbers, which
    is the honest answer for something we never collected.

    `edges` and `findings` are THIS component's own outgoing dependency edges
    and matched vulnerabilities — the caller looks them up by `component_key`,
    the same key the graph and findings dedup already use. A component with
    none is left with an empty list, which scores present=0: that is the
    correct, conservative reading (this pipeline does not yet distinguish
    "verified zero dependencies" from "no trusted graph engine for this
    ecosystem" — see `_DEFAULT_GRAPH_TRUST` — so it asserts nothing either way
    rather than guessing).
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
        # ⚠ WITHOUT THIS LINE THE FIELD SCORES ZERO FOREVER, even once it is
        # populated — see this function's own docstring on absent fields. It is
        # a weight-3 scored field, so filling it legitimately moves
        # completeness_pct. "" and "unknown" both score present=0 already
        # (coverage.NON_SUBSTANTIVE), so no special-casing is needed here.
        "component.patch_status": component.patch_status,
        "component.author_of_sbom_data": ", ".join(
            sorted({o.engine for o in component.observed_by})
        ),
        "component.dependencies": [e.as_dict() for e in edges],
        "component.findings": [f.as_dict() for f in findings],
        # ⚠ DOCUMENT-LEVEL, NOT PER-COMPONENT — certin.sbom.17 (Timestamp) is
        # one fact about the whole BOM, not about any single entity. `score()`
        # only knows how to weigh per-entity fields, so the same value is
        # asserted on every row; that is redundant, not dishonest — the BOM
        # genuinely was assembled at this instant, for every component in it.
        "bom_document.generated_at": generated_at,
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
