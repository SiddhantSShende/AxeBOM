"""Durable persistence for the vulnerability alias-cluster graph (ADR-0005).

⚠ `normalize.vuln_clusters.id` MUST BE A DURABLE SURROGATE, NEVER DERIVED
FROM ITS MEMBERS — see `aliases.py`'s module docstring and
`docs/ADR/0005-durable-vuln-cluster-ids.md`. Before this module existed,
nothing ever called `pipeline.normalize()` with real `existing_clusters`/
`cluster_ids` values, so `bulk.py` fell back to deriving `cluster_id` as
`uuid5(bom_document_id + ...)` — exactly the trap the ADR warns against: it
mutates every re-normalization and isn't even durable within one scan, let
alone across scans of the same project.

`aliases.py`'s union-find (`close()`, `assign_cluster_ids()`) is correct and
untouched by this module — what was missing was persistence AROUND it. This
module is that persistence: resolve which of a scan's vulnerability ids
already belong to a durable cluster, apply ADR-0005's cross-scan size guard
(which the in-memory closure alone cannot enforce, because it only ever sees
one scan's local group), and write the result.

⚠ RUN AS ITS OWN, SHORT TRANSACTION — separate from `writer.write_bom_document
()`'s. The cluster graph is GLOBAL (no tenant_id, no RLS — same reasoning
`normalize.vuln_clusters` already established in migration 0002): if this
scan's bulk write is later refused for exceeding a cap, the alias-graph
knowledge this module just persisted (e.g. "OSV asserts CVE-X aliases
GHSA-Y") is still globally true and worth keeping regardless.

⚠ CONCURRENCY: a Postgres advisory lock (`pg_advisory_xact_lock`), NOT a row
lock — the graph has no single row to lock before it exists, and an advisory
lock needs no table privilege at all (unlike `SELECT ... FOR UPDATE`, which
requires UPDATE), which matters because `axebom_normalize_writer` is
INSERT/SELECT-only everywhere except one narrow column-scoped UPDATE
carve-out on `vuln_clusters` (migrations/normalize/0006_alias_snapshot.sql).
The lock key is centrally registered in
`libs/go-shared/platform/leader/leader.go`'s `NormalizeClusterGraph` — see
that file for why a Python caller still registers a Go-side constant.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Protocol

from . import aliases, ingest

#: Mirrors libs/go-shared/platform/leader/leader.go's NormalizeClusterGraph
#: (= 4). Postgres advisory locks are ONE GLOBAL INTEGER NAMESPACE per
#: database — there is no per-caller or per-language partition — so this
#: value must stay in sync with the Go constant by hand. Change it there
#: first; a mismatch here silently stops serializing against the Go side's
#: reservation, not a compile error.
NORMALIZE_CLUSTER_GRAPH_LOCK_KEY = 4

#: osv-scanner and grype are the only engines aliases.py has an edge
#: extractor for (`edges_from_osv`/`edges_from_grype`) — matches
#: pipeline.py's own engine check in its alias-closure step exactly.
_ALIAS_EDGE_ENGINES = frozenset({"osv-scanner", "grype"})


class Cursor(Protocol):
    def execute(self, query: str, params: Any = None) -> Any: ...
    def fetchone(self) -> Any: ...
    def fetchall(self) -> Any: ...


class Connection(Protocol):
    """Same Protocol shape as writer.py's — a caller's test double does not
    have to be a real psycopg connection, only shaped like one."""

    def cursor(self) -> Cursor: ...
    def transaction(self) -> Any: ...


@dataclass
class Artifact:
    """Mirrors pipeline.Artifact's shape (engine, payload) — this module
    only reads those two fields, so it accepts anything with them rather
    than importing pipeline.Artifact and creating a dependency the other
    direction would not need."""

    engine: str
    payload: Any


def uuid7() -> str:
    """A time-ordered uuid, matching `app.uuid_v7()`'s bit layout
    (migrations/bootstrap/0001_schemas_role_helpers.sql) — same reasoning
    that function documents: index locality, and ids that sort
    chronologically. No such generator existed in py-shared before this;
    `bulk.py`'s ids are all uuid5, deliberately content-derived, which is the
    opposite property this module needs (ADR-0005: NEVER content-derived).
    """
    unix_ms = int(time.time() * 1000)
    random_bytes = bytearray(os.urandom(16))
    random_bytes[0] = (unix_ms >> 40) & 0xFF
    random_bytes[1] = (unix_ms >> 32) & 0xFF
    random_bytes[2] = (unix_ms >> 24) & 0xFF
    random_bytes[3] = (unix_ms >> 16) & 0xFF
    random_bytes[4] = (unix_ms >> 8) & 0xFF
    random_bytes[5] = unix_ms & 0xFF
    random_bytes[6] = (random_bytes[6] & 0x0F) | 0x70  # version 7
    random_bytes[8] = (random_bytes[8] & 0x3F) | 0x80  # RFC 4122 variant
    return str(uuid.UUID(bytes=bytes(random_bytes)))


def _uuid7_iter():
    while True:
        yield uuid7()


def seed_ids_and_edges(artifacts: list[Artifact]) -> tuple[list[str], list[aliases.AliasEdge]]:
    """Re-derive this scan's vulnerability seed ids and alias edges from its
    raw artifacts — the same two values `pipeline.normalize()` computes
    internally for its own alias-closure step (pipeline.py's ── 4. ALIAS
    CLOSURE ── block), exposed here so cluster persistence can run BEFORE
    `pipeline.normalize()` is called with real `existing_clusters`/
    `cluster_ids` values.

    ⚠ RE-INGESTS EVERY ARTIFACT — a deliberate, acknowledged duplicate of
    work `pipeline.normalize()` will also do a moment later inside
    `normalize_consumer.py`'s single call site for this scan. `_PARSERS`
    (ingest.py) now attaches `vulnerabilities[]` parsing to the SAME pass
    that reads `components[]` (Gap A), so there is no cheaper "findings-only"
    subset of the ingest to run instead without either re-implementing
    parsing here or exposing a second entry point from ingest.py that risks
    drifting from the real one. Correctness first; if profiling ever shows
    this duplication matters, splitting ingest() into a components pass and
    a findings pass is the fix — not duplicating the parsing logic here.
    """
    seed_ids: list[str] = []
    edges: list[aliases.AliasEdge] = []

    for artifact in artifacts:
        result = ingest.ingest(
            artifact.engine, artifact.payload, scan_id="", trusted_graph_ecosystems=frozenset()
        )
        for finding in result.findings:
            if finding.vuln_id:
                seed_ids.append(finding.vuln_id)

        if artifact.engine not in _ALIAS_EDGE_ENGINES or not isinstance(artifact.payload, dict):
            continue
        if artifact.engine == "osv-scanner":
            edges.extend(aliases.edges_from_osv(artifact.payload))
        elif artifact.engine == "grype":
            edges.extend(aliases.edges_from_grype(artifact.payload))

    return sorted(set(seed_ids)), edges


def _load_existing_clusters(cur: Cursor, normalized_ids: set[str]) -> dict[str, str]:
    """Batched read: every (namespace, value) this scan touches, mapped to
    its current durable cluster id — the `existing` argument
    `aliases.assign_cluster_ids()` needs."""
    if not normalized_ids:
        return {}

    pairs = [
        (aliases.namespace_of(nid), nid.split("-", 1)[1] if "-" in nid else nid)
        for nid in normalized_ids
    ]
    namespaces = [p[0] for p in pairs]
    values = [p[1] for p in pairs]

    cur.execute(
        "SELECT namespace, value, cluster_id FROM normalize.vuln_ids "
        "WHERE (namespace, value) = ANY(SELECT unnest(%s::text[]), unnest(%s::text[]))",
        (namespaces, values),
    )
    out: dict[str, str] = {}
    for namespace, value, cluster_id in cur.fetchall():
        out[f"{namespace}-{value}"] = str(cluster_id)
    return out


def _true_member_count(cur: Cursor, cluster_id: str) -> int:
    """The REAL, cross-scan persisted membership of a cluster — resolved
    forward through any prior merges via `normalize.resolve_cluster()`, so a
    multi-hop merge chain is counted correctly (a naive
    `WHERE cluster_id = %s` would undercount once any prior merge has
    happened, since old `vuln_ids` rows are never rewritten to point at the
    surviving id).

    ⚠ THIS IS THE CHECK `aliases.close()`'s in-memory size guard CANNOT DO —
    it only ever sees this run's own local group, with no knowledge of what
    prior scans already attached to an existing cluster.
    """
    cur.execute(
        "SELECT count(*) FROM normalize.vuln_ids "
        "WHERE normalize.resolve_cluster(cluster_id) = normalize.resolve_cluster(%s::uuid)",
        (cluster_id,),
    )
    row = cur.fetchone()
    return int(row[0]) if row else 0


def _resolve_cluster(cur: Cursor, cluster_id: str) -> str:
    """The current, non-superseded cluster id a (possibly forwarded) one
    resolves to — a thin wrapper over `normalize.resolve_cluster()`, used to
    dedupe pre-existing cluster ids by their true current root before
    counting or merging them."""
    cur.execute("SELECT normalize.resolve_cluster(%s::uuid)", (cluster_id,))
    row = cur.fetchone()
    return str(row[0])


def _resolved_members(cur: Cursor, cluster_id: str) -> list[str]:
    """Every namespaced id belonging to a cluster's FULL resolved
    membership — used to recompute `display_id`/`member_count` from ground
    truth rather than this run's partial (this-scan-only) view, which would
    silently regress a stored aggregate downward."""
    cur.execute(
        "SELECT namespace, value FROM normalize.vuln_ids "
        "WHERE normalize.resolve_cluster(cluster_id) = normalize.resolve_cluster(%s::uuid)",
        (cluster_id,),
    )
    return [f"{namespace}-{value}" for namespace, value in cur.fetchall()]


def persist_clusters(conn: Connection, artifacts: list[Artifact]) -> dict[str, str]:
    """Resolve and persist durable cluster ids for one scan's vulnerability
    findings, applying all three ADR-0005 guards, and return the
    `existing_clusters` map `pipeline.normalize()` should be called with.

    Returns `{}` immediately, touching nothing, when the scan produced no
    vulnerability ids at all — a components-only scan (no vuln-capable
    engine ran, or none of them found anything) has no alias graph to
    persist, and taking the advisory lock for nothing would only add
    latency.
    """
    seed_ids, edges = seed_ids_and_edges(artifacts)
    if not seed_ids and not edges:
        return {}

    with conn.transaction():
        cur = conn.cursor()
        # ⚠ FIRST STATEMENT, before any read — the lock must cover the whole
        # read-compute-write cycle, or two concurrent scans touching
        # overlapping CVEs can both read, both compute independently, and
        # the second writer's INSERT/UPDATE silently loses the first's
        # update (lost update), not just race on row insert order.
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (NORMALIZE_CLUSTER_GRAPH_LOCK_KEY,))

        touched: set[str] = {aliases.normalize_id(x) for x in seed_ids if aliases.normalize_id(x)}
        for e in edges:
            n = e.normalized()
            touched.add(n.id_a)
            touched.add(n.id_b)

        # ⚠ EDGES ARE WRITTEN — AND TAGGED WITH THEIR REAL ROW ID — BEFORE
        # close() RUNS, not after. ADR-0005: "a compliance product must be
        # able to answer why did these two findings become one" — that
        # answer is normalize.vuln_cluster_merges.evidence_edge_id, a real
        # FK into vuln_alias_edges. edges_from_osv/edges_from_grype never
        # set AliasEdge.edge_id (they have no DB round-trip to get one from),
        # so without this, every merge this run discovers would record no
        # evidence at all. Persisting first and re-tagging is what makes a
        # real id available to attach.
        edges = _write_alias_edges(cur, edges)

        existing = _load_existing_clusters(cur, touched)
        closure = aliases.close(edges, seed_ids=seed_ids)
        clusters = aliases.assign_cluster_ids(closure, existing=existing, mint=_uuid7_iter())

        result_map: dict[str, str] = {}
        review_flagged: set[str] = set()

        for cluster in clusters:
            new_members = [m for m in cluster.members if m not in existing]
            # Every DISTINCT pre-existing cluster this union-find group
            # touches. ⚠ CAN BE MORE THAN ONE even with new_members == [] —
            # a new EDGE this scan found can bridge two previously-known,
            # previously-SEPARATE clusters with zero new member ids
            # involved (both endpoints already had their own cluster
            # before). Treating "no new members" as "nothing to do" would
            # silently miss exactly that merge.
            prior_ids = {existing[m] for m in cluster.members if m in existing}

            if not prior_ids:
                # Brand new cluster — nothing pre-existing to merge against,
                # so this run's local view IS the complete true state; no
                # cross-scan size check needed, aliases.close() already
                # enforced the cap within this run's own union-find.
                _insert_cluster(
                    cur,
                    cluster.cluster_id,
                    display_id=cluster.display_id,
                    member_count=len(cluster.members),
                    flagged_for_review=cluster.flagged_for_review,
                )
                _attach_members(cur, cluster.cluster_id, new_members)
                for m in cluster.members:
                    result_map[m] = cluster.cluster_id
                continue

            # Resolved through any earlier merge chain and deduped by root,
            # so an already-merged pair is never double-counted below.
            resolved_roots = {_resolve_cluster(cur, cid) for cid in prior_ids}

            if len(resolved_roots) == 1 and not new_members:
                # Truly nothing new: same single existing cluster, no new
                # members, no new merge — an edge reasserting something
                # already known. Just propagate.
                (only_root,) = resolved_roots
                for m in cluster.members:
                    result_map[m] = only_root
                continue

            true_count = sum(_true_member_count(cur, root) for root in resolved_roots)

            if true_count + len(new_members) > aliases.MAX_CLUSTER_SIZE:
                # ⚠ REFUSE THE MERGE — every pre-existing cluster this group
                # touched stays exactly as it was; new members (if any) get
                # their OWN fresh cluster, disconnected from all of them;
                # every touched pre-existing cluster is flagged for review
                # rather than silently grown past the ceiling. Under-merge
                # (separate clusters instead of one) is the intentionally
                # safer failure direction — ADR-0005's own reasoning:
                # over-merge UNDER-reports, which is worse.
                if new_members:
                    fresh_id = next(_uuid7_iter())
                    _insert_cluster(
                        cur,
                        fresh_id,
                        display_id=aliases.display_id(new_members),
                        member_count=len(new_members),
                        flagged_for_review=True,
                    )
                    _attach_members(cur, fresh_id, new_members)
                    for m in new_members:
                        result_map[m] = fresh_id
                review_flagged.update(resolved_roots)
                for m in cluster.members:
                    if m in existing:
                        result_map[m] = existing[m]
                continue

            # Accepted. The lowest resolved root is the deterministic merge
            # target — NOT cluster.cluster_id verbatim, which aliases.py
            # picked with no knowledge of prior-run forwarding chains and
            # could (rarely) name an id that has since been superseded.
            winner = min(resolved_roots)

            # Forwarding rows for every OTHER root FIRST — before attaching
            # members or recomputing the aggregate, both of which resolve
            # through normalize.resolve_cluster() and would otherwise miss
            # members still sitting under a not-yet-forwarded id within this
            # same transaction.
            #
            # Evidence: cluster.merges' edge_id values are now REAL
            # vuln_alias_edges row ids (edges were persisted and re-tagged
            # before close() ran, above) — any of them is real, queryable
            # evidence for why this cluster formed, satisfying ADR-0005's
            # "must be able to answer why did these two findings become one."
            evidence_id = next((m.edge_id for m in cluster.merges if m.edge_id), None)
            for root in resolved_roots:
                if root != winner:
                    _write_forwarding_row(
                        cur, from_id=root, into_id=winner, evidence_edge_id=evidence_id
                    )

            _attach_members(cur, winner, new_members)
            full_members = _resolved_members(cur, winner)
            _update_cluster_aggregate(
                cur,
                winner,
                display_id=aliases.display_id(full_members),
                member_count=len(full_members),
                flagged_for_review=cluster.flagged_for_review,
            )
            for m in cluster.members:
                result_map[m] = winner

        for cluster_id in review_flagged:
            _flag_for_review(cur, cluster_id)

    return result_map


def _insert_cluster(
    cur: Cursor, cluster_id: str, *, display_id: str, member_count: int, flagged_for_review: bool
) -> None:
    cur.execute(
        "INSERT INTO normalize.vuln_clusters (id, display_id, member_count, flagged_for_review) "
        "VALUES (%s, %s, %s, %s) ON CONFLICT (id) DO NOTHING",
        (cluster_id, display_id, member_count, flagged_for_review),
    )


def _update_cluster_aggregate(
    cur: Cursor, cluster_id: str, *, display_id: str, member_count: int, flagged_for_review: bool
) -> None:
    # The one narrow, column-scoped UPDATE grant axebom_normalize_writer has
    # (migrations/normalize/0006_alias_snapshot.sql) — see this module's
    # docstring for why append-only INSERT could not represent this.
    cur.execute(
        "UPDATE normalize.vuln_clusters "
        "SET display_id = %s, member_count = %s, flagged_for_review = %s "
        "WHERE id = %s",
        (display_id, member_count, flagged_for_review, cluster_id),
    )


def _flag_for_review(cur: Cursor, cluster_id: str) -> None:
    cur.execute(
        "UPDATE normalize.vuln_clusters SET flagged_for_review = true WHERE id = %s",
        (cluster_id,),
    )


def _attach_members(cur: Cursor, cluster_id: str, normalized_ids: list[str]) -> None:
    for nid in normalized_ids:
        namespace = aliases.namespace_of(nid)
        value = nid.split("-", 1)[1] if "-" in nid else nid
        cur.execute(
            "INSERT INTO normalize.vuln_ids (cluster_id, namespace, value) "
            "VALUES (%s, %s, %s) ON CONFLICT (namespace, value) DO NOTHING",
            (cluster_id, namespace, value),
        )


def _write_alias_edges(cur: Cursor, edges: list[aliases.AliasEdge]) -> list[aliases.AliasEdge]:
    """Persist every edge and return them RE-TAGGED with their real
    `vuln_alias_edges.id` row id — so `aliases.close()`, run afterward on
    these tagged edges, produces `MergeRecord.edge_id` values that are real,
    queryable evidence rather than always empty (the extractors that build
    `edges` — `edges_from_osv`/`edges_from_grype` — have no DB round trip of
    their own and never set `edge_id`).

    ⚠ `ON CONFLICT ... DO NOTHING`, NOT `DO UPDATE` — `axebom_normalize_writer`
    has no UPDATE grant on this table at all (only the one narrow
    column-scoped carve-out on `vuln_clusters`), and `INSERT ... ON CONFLICT
    DO UPDATE` requires UPDATE privilege even when nothing about the
    conflicting row actually needs to change. Confirmed the hard way: this
    failed with `permission denied for table vuln_alias_edges` under the
    real role the first time this module's own tests ran against it, not
    under `axebom_app` (which has UPDATE everywhere and would never have
    caught it). The cost is real but small: an already-seen edge's
    `last_seen` no longer refreshes on rediscovery — a monitoring nicety,
    not a correctness requirement (`alias_cluster_size`'s rising-tail signal
    per ADR-0005 depends on cluster membership, not this timestamp) — and
    `DO NOTHING` never returns a row for a conflict, so a second SELECT
    recovers the id when that happens.
    """
    out: list[aliases.AliasEdge] = []
    seen: dict[tuple[str, str, str], str] = {}
    for e in edges:
        n = e.normalized()
        if not n.id_a or not n.id_b or n.id_a == n.id_b:
            continue
        a, b = (n.id_a, n.id_b) if n.id_a <= n.id_b else (n.id_b, n.id_a)
        key = (a, b, n.source)

        edge_id = seen.get(key)
        if edge_id is None:
            cur.execute(
                "INSERT INTO normalize.vuln_alias_edges (id_a, id_b, source, authoritative) "
                "VALUES (%s, %s, %s, %s) "
                "ON CONFLICT (id_a, id_b, source) DO NOTHING "
                "RETURNING id",
                (a, b, n.source, n.authoritative),
            )
            row = cur.fetchone()
            if row is None:
                cur.execute(
                    "SELECT id FROM normalize.vuln_alias_edges WHERE id_a = %s AND id_b = %s AND source = %s",
                    (a, b, n.source),
                )
                row = cur.fetchone()
            edge_id = str(row[0])
            seen[key] = edge_id

        out.append(
            aliases.AliasEdge(
                id_a=n.id_a,
                id_b=n.id_b,
                source=n.source,
                authoritative=n.authoritative,
                edge_id=edge_id,
            )
        )
    return out


def _write_forwarding_row(
    cur: Cursor, *, from_id: str, into_id: str, evidence_edge_id: str | None
) -> None:
    """One row for `normalize.vuln_cluster_merges` — written whenever this
    run's closure discovered that two previously-separate clusters are the
    same vulnerability. `normalize.resolve_cluster()` reads this forward, so
    a report issued against the superseded id still resolves (ADR-0005)."""
    cur.execute(
        "INSERT INTO normalize.vuln_cluster_merges (from_cluster_id, into_cluster_id, evidence_edge_id) "
        "VALUES (%s, %s, %s)",
        (from_id, into_id, evidence_edge_id),
    )


def ensure_clusters_for_ids(conn: Connection, display_ids: list[str]) -> dict[str, str]:
    """Resolve or mint a durable cluster id for each plain vulnerability id.

    ⚠ THE LIGHT PATH, FOR SOURCES THAT CARRY NO ALIASES. `persist_clusters`
    exists because SBOM scanners report the same vulnerability under several
    ids (CVE, GHSA, OSV) and the alias graph has to be closed, merged and
    guarded. NVD's hardware answer is CVE ids and nothing else — there is no
    second id to alias to, so there is no graph, no merge, and none of
    ADR-0005's three guards have anything to fire on.

    ⚠ THE SAME GLOBAL CLUSTER NAMESPACE, THOUGH, AND THAT IS DELIBERATE.
    CVE-2021-1472 affecting a router and CVE-2021-1472 affecting a library are
    ONE vulnerability. Minting a hardware-private cluster for it would make the
    two look unrelated in every future query, which is precisely the mistake
    ADR-0005 was written to prevent.

    ⚠ EXISTING CLUSTER AGGREGATES ARE READ, NEVER REWRITTEN. A hardware match
    contributes no new member id to a cluster the SBOM path already built, so
    recomputing `member_count` from this partial view could only regress a
    stored aggregate downward — the exact failure `_resolved_members` exists to
    avoid on the other path.
    """
    wanted = [d for d in dict.fromkeys(display_ids) if d]
    if not wanted:
        return {}

    out: dict[str, str] = {}
    with conn.transaction():
        cur = conn.cursor()
        existing = _load_existing_clusters(cur, set(wanted))
        for display_id in wanted:
            found = existing.get(display_id)
            if found:
                # Forward through any prior merge, so a hardware finding never
                # points at a superseded cluster.
                out[display_id] = _resolve_cluster(cur, found)
                continue
            cluster_id = uuid7()
            _insert_cluster(
                cur,
                cluster_id,
                display_id=display_id,
                member_count=1,
                flagged_for_review=False,
            )
            _attach_members(cur, cluster_id, [display_id])
            out[display_id] = cluster_id
    return out
