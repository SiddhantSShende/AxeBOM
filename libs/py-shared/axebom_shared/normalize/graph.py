"""Dependency-graph merge — replace per ecosystem, never union.

⚠ THE CRITICAL RULE: DO NOT UNION GRAPHS FROM DIFFERENT ENGINES.

Tools disagree *structurally*, not just in detail. syft produces a near-flat
inventory with weak edges; a manifest/lockfile-native resolver produces true
edges. Unioning them invents phantom transitive edges and corrupts the
direct-vs-transitive split — which is precisely the number a **Top-Level report**
is built on.

So: where a higher-trust engine supplies a graph for an ecosystem, that
ecosystem's subgraph is REPLACED entirely, and `owning_engine` records who
supplied it so provenance can explain the shape.

Three more things this module refuses to assume:

  * **Cycles are real.** Go module graphs and npm workspaces contain them.
    Every traversal carries a visited set; none assumes a DAG.
  * **A monorepo has N roots**, one per detected package/module. One root per
    repository makes every workspace package look like a direct dependency of
    an imaginary parent.
  * **Orphans get `depth = NULL`.** Never forced to depth 1 — that silently
    inflates the direct-dependency count, and "direct dependencies" is a
    headline number.

See `docs/03-NORMALIZER-SPEC.md` §4.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

#: Relationships aligned to CycloneDX/SPDX.
RELATIONSHIPS = frozenset({"depends_on", "contains", "describes", "generated_from", "variant_of"})


@dataclass(frozen=True)
class Edge:
    """One dependency edge, with the engine that asserted it."""

    from_key: str
    to_key: str
    relationship: str = "depends_on"
    scope: str = "required"
    owning_engine: str = ""
    confidence: str = "medium"
    #: Which ecosystem's subgraph this edge belongs to. Drives replacement.
    ecosystem: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_key,
            "to": self.to_key,
            "relationship": self.relationship,
            "scope": self.scope,
            "owning_engine": self.owning_engine,
            "confidence": self.confidence,
            "ecosystem": self.ecosystem,
        }


@dataclass
class GraphResult:
    """The merged graph plus the derived per-component facts."""

    edges: list[Edge]
    #: component_key -> depth from the root set. Absent means orphan.
    depth: dict[str, int]
    #: Explicitly from the root set, never inferred from depth.
    direct: set[str]
    roots: list[str]
    orphans: list[str]
    #: ecosystem -> engine whose subgraph was kept.
    owning_engine: dict[str, str]
    diagnostics: list[dict[str, Any]] = field(default_factory=list)

    def depth_of(self, key: str) -> int | None:
        """⚠ Returns None for an orphan, and None is the stored value.

        Not 0, not 1. An orphan is unreachable from any root, and any number
        here asserts a position in the tree that was never established.
        """
        return self.depth.get(key)

    def is_orphan(self, key: str) -> bool:
        return key not in self.depth


def merge_edges(
    contributions: Mapping[str, list[Edge]],
    trust: Mapping[str, Mapping[str, int]],
) -> tuple[list[Edge], dict[str, str], list[dict[str, Any]]]:
    """Pick one engine's subgraph per ecosystem.

    `contributions` maps engine_id -> its edges.
    `trust` maps engine_id -> {ecosystem: rank}, lower rank winning, from the
    engine registry's `graph_trust` (docs/02-CONTRACTS.md §7).

    ⚠ REPLACEMENT, NOT UNION. Two engines that both understand npm produce
    overlapping-but-different npm graphs; keeping both would create edges that
    exist in neither, and a transitive dependency that no tool actually
    reported.
    """
    by_ecosystem: dict[str, dict[str, list[Edge]]] = {}
    for engine, edges in contributions.items():
        for edge in edges:
            ecosystem = edge.ecosystem or "unknown"
            by_ecosystem.setdefault(ecosystem, {}).setdefault(engine, []).append(edge)

    merged: list[Edge] = []
    owning: dict[str, str] = {}
    diagnostics: list[dict[str, Any]] = []

    for ecosystem in sorted(by_ecosystem):
        candidates = by_ecosystem[ecosystem]

        def rank(engine: str, _eco: str = ecosystem) -> tuple[int, str]:
            engine_trust = trust.get(engine) or {}
            # Absent from the trust table means "no declared competence here".
            # Ranked last rather than excluded: a graph from an untrusted engine
            # still beats no graph at all.
            return (engine_trust.get(_eco, 99), engine)

        winner = sorted(candidates, key=rank)[0]
        owning[ecosystem] = winner
        merged.extend(candidates[winner])

        losers = sorted(set(candidates) - {winner})
        if losers:
            diagnostics.append(
                {
                    "severity": "info",
                    "code": "NORMALIZE_GRAPH_REPLACED",
                    "message": (
                        f"{ecosystem} graph taken from {winner}; discarded {', '.join(losers)}"
                    ),
                    "hint": (
                        "subgraphs are replaced per ecosystem, not unioned: unioning "
                        "invents transitive edges that no engine reported and corrupts "
                        "the direct-vs-transitive split"
                    ),
                    "ecosystem": ecosystem,
                }
            )

    return merged, owning, diagnostics


def build(
    *,
    component_keys: Iterable[str],
    edges: list[Edge],
    roots: Iterable[str],
    owning_engine: Mapping[str, str] | None = None,
    extra_diagnostics: Iterable[dict[str, Any]] = (),
) -> GraphResult:
    """Compute depth, directness and orphans from the merged graph.

    `roots` is the detected package/module set — N of them for a monorepo.
    """
    keys = set(component_keys)
    root_list = sorted({r for r in roots if r in keys})

    adjacency: dict[str, list[str]] = {}
    for edge in edges:
        if edge.from_key in keys and edge.to_key in keys:
            adjacency.setdefault(edge.from_key, []).append(edge.to_key)
    for targets in adjacency.values():
        targets.sort()

    diagnostics: list[dict[str, Any]] = list(extra_diagnostics)

    # ⚠ `is_direct` is taken from the ROOT SET, explicitly.
    #
    # Never `depth == 1`: depth is a derived traversal fact, and a component can
    # be reachable at depth 1 through a path that does not make it a declared
    # direct dependency. Storing it explicitly keeps the headline number tied to
    # what the manifest actually said.
    direct: set[str] = set()
    for root in root_list:
        for target in adjacency.get(root, []):
            direct.add(target)

    # BFS with a visited set. Cycles are real here — a Go module graph or an
    # npm workspace will loop, and a naive recursive walk hangs or overflows.
    depth: dict[str, int] = {}
    queue: deque[tuple[str, int]] = deque()
    for root in root_list:
        depth[root] = 0
        queue.append((root, 0))

    while queue:
        node, d = queue.popleft()
        for target in adjacency.get(node, []):
            if target in depth:
                # Already reached, at an equal or shallower depth. BFS
                # guarantees first-visit is minimal, so nothing to update — and
                # this is also the cycle break.
                continue
            depth[target] = d + 1
            queue.append((target, d + 1))

    orphans = sorted(keys - set(depth))

    if orphans:
        diagnostics.append(
            {
                "severity": "info",
                "code": "NORMALIZE_GRAPH_ORPHANS",
                "message": f"{len(orphans)} components are unreachable from any root",
                "hint": (
                    "stored with depth = NULL and is_orphan = true. Forcing them to "
                    "depth 1 would inflate the direct-dependency count"
                ),
            }
        )

    if not root_list and keys:
        # No roots means no depth for anything. Reported loudly: every component
        # becomes an orphan, and a reader seeing an all-orphan graph should know
        # it is a root-detection failure rather than a strange repository.
        diagnostics.append(
            {
                "severity": "warn",
                "code": "NORMALIZE_GRAPH_NO_ROOTS",
                "message": "no dependency roots were detected",
                "hint": (
                    "every component is reported as an orphan with depth = NULL; "
                    "direct-vs-transitive cannot be derived"
                ),
            }
        )

    return GraphResult(
        edges=sorted(edges, key=lambda e: (e.ecosystem, e.from_key, e.to_key, e.relationship)),
        depth=depth,
        direct=direct,
        roots=root_list,
        orphans=orphans,
        owning_engine=dict(owning_engine or {}),
        diagnostics=diagnostics,
    )


def level_membership(result: GraphResult, key: str, level: str) -> bool:
    """Whether a component belongs in a report at the requested level.

    `Top-Level` is `depth <= 1`; `Complete` is everything, orphans included and
    flagged. An orphan has no depth, so it can never satisfy Top-Level — which
    is the honest answer: we do not know where it sits.
    """
    if level == "complete":
        return True
    depth = result.depth_of(key)
    if depth is None:
        return False
    if level == "top-level":
        return depth <= 1
    return True


def has_cycle(edges: Iterable[Edge]) -> bool:
    """Whether the graph contains a cycle.

    Not an error — cycles are legitimate. Exposed so a report can say so rather
    than a reader wondering why a depth looks odd.
    """
    adjacency: dict[str, list[str]] = {}
    for edge in edges:
        adjacency.setdefault(edge.from_key, []).append(edge.to_key)

    white, grey, black = 0, 1, 2
    colour: dict[str, int] = {}

    # Iterative, not recursive: a deep dependency tree would blow the Python
    # stack, and this runs over user-supplied graphs.
    for start in list(adjacency):
        if colour.get(start, white) != white:
            continue
        stack: list[tuple[str, int]] = [(start, 0)]
        colour[start] = grey
        while stack:
            node, index = stack.pop()
            targets = adjacency.get(node, [])
            if index < len(targets):
                stack.append((node, index + 1))
                target = targets[index]
                state = colour.get(target, white)
                if state == grey:
                    return True
                if state == white:
                    colour[target] = grey
                    stack.append((target, 0))
            else:
                colour[node] = black
    return False
