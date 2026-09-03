"""Vulnerability identity — union-find over the global alias edge graph.

⚠ THIS IS WHERE NAIVE IMPLEMENTATIONS QUIETLY FAIL.

Four engines report the same vulnerability under four different namespaces:
grype emits GHSA, osv-scanner emits OSV-native (GO-, PYSEC-, RUSTSEC-),
dependency-check emits CVE, trivy emits both. Deduping on the primary id
inflates counts roughly threefold. A report claiming 240 vulnerabilities where
there are 80 is not cosmetic — it drives remediation budgets.

The identity is the CONNECTED COMPONENT of the alias graph, not any single id.
That is what lets

    CVE-2021-44228 ↔ GHSA-jfh8-c2jp-5v3q ↔ SNYK-JAVA-…

collapse into one cluster even though no single tool asserts the whole triangle.

Two traps dominate this module, and both are load-bearing:

  A. **Cluster ids must be durable.** Never derived from the members. An id
     computed from its contents mutates the moment a new alias is discovered,
     breaking every foreign key and invalidating every issued report.

  B. **Over-merge is real.** OSV aliases are not always equivalence-safe: some
     GHSAs alias several genuinely distinct CVEs, and MAL- ids alias broadly.
     Unguarded union-find eventually merges unrelated vulnerabilities and
     UNDER-reports, which is the more dangerous direction.

See `docs/03-NORMALIZER-SPEC.md` §2 and `docs/ADR/0005-durable-vuln-cluster-ids.md`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

#: Above this many members a cluster is far more likely to be an over-merge than
#: a real advisory family, so it is FLAGGED and auto-merging stops.
#:
#: Chosen from the spec rather than tuned: the point is not the exact number but
#: that some ceiling exists. Without one, a single bad MAL- edge can absorb an
#: entire ecosystem's advisories into one "vulnerability".
MAX_CLUSTER_SIZE = 12

#: Namespace rank for choosing a display id. Lower wins.
#:
#: CVE first because it is the identifier a reader recognises and the one that
#: appears in a remediation ticket.
_NAMESPACE_RANK = {
    "CVE": 0,
    "GHSA": 1,
    "OSV": 2,
    "GO": 3,
    "PYSEC": 3,
    "RUSTSEC": 3,
    "GSD": 4,
    "MAL": 5,
    "SNYK": 6,
    "RHSA": 7,
    "DSA": 7,
    "USN": 7,
    "ALAS": 7,
    "ELSA": 7,
    "DLA": 7,
    "NPM": 8,
    # Confirmed live, not assumed: a real osv-scanner run against a real
    # registered Go project reported a "BIT-GOLANG-<year>-<n>" id as a
    # vulnerability's primary identifier (OSV.dev aggregates Bitnami's own
    # per-image advisory database, whose ids carry this prefix). Missing from
    # migrations/normalize/0008_vuln_ids_namespace_widen.sql's widened list —
    # the same gap that migration fixed for GO/PYSEC/RUSTSEC/GSD/MAL, one
    # namespace it hadn't been hit by yet. See
    # migrations/normalize/0010_vuln_ids_namespace_add_bit.sql.
    "BIT": 7,
}

_ID_SHAPE = re.compile(r"^([A-Za-z]+)[-:]?(.*)$")


def normalize_id(raw: str) -> str:
    """Normalize a vulnerability id to `<NS>-<value>`.

    Case and separator normalization only. The value is otherwise preserved:
    `CVE-2021-44228` must not become `CVE-2021-4422` through any cleverness.
    """
    if not isinstance(raw, str):
        return ""
    text = raw.strip().upper().replace("_", "-")
    if not text:
        return ""

    match = _ID_SHAPE.match(text)
    if not match:
        return text
    namespace, rest = match.group(1), match.group(2)
    rest = rest.lstrip("-")
    if not rest:
        return namespace
    return f"{namespace}-{rest}"


def namespace_of(vuln_id: str) -> str:
    """The namespace portion, e.g. `CVE` for `CVE-2021-44228`."""
    normalized = normalize_id(vuln_id)
    return normalized.split("-", 1)[0] if "-" in normalized else normalized


@dataclass(frozen=True)
class AliasEdge:
    """One undirected assertion that two ids are the same vulnerability."""

    id_a: str
    id_b: str
    source: str
    #: ⚠ Only OSV.dev `aliases`/`upstream` and GHSA advisory `identifiers` are
    #: authoritative. A scanner asserting an alias in passing is not, and the
    #: CVE↔CVE guard depends on this distinction being honest.
    authoritative: bool = False
    #: Stable id of the stored edge row, recorded as merge evidence.
    edge_id: str = ""

    def normalized(self) -> AliasEdge:
        return AliasEdge(
            id_a=normalize_id(self.id_a),
            id_b=normalize_id(self.id_b),
            source=self.source,
            authoritative=self.authoritative,
            edge_id=self.edge_id,
        )

    def key(self) -> tuple[str, str]:
        """Order-independent key, so A↔B and B↔A are one edge."""
        a, b = normalize_id(self.id_a), normalize_id(self.id_b)
        return (a, b) if a <= b else (b, a)


@dataclass
class MergeRecord:
    """Why two ids ended up in one cluster.

    ⚠ A compliance product must be able to answer "why did these two findings
    become one?". If it cannot, the merge should not have happened. This record
    is that answer, and it is written for every merge without exception.
    """

    id_a: str
    id_b: str
    source: str
    authoritative: bool
    edge_id: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "id_a": self.id_a,
            "id_b": self.id_b,
            "source": self.source,
            "authoritative": self.authoritative,
            "evidence_edge_id": self.edge_id,
        }


@dataclass
class RefusedEdge:
    """An edge the guards rejected, and the reason.

    Kept rather than dropped: a refusal means two findings stay separate, which
    is a reportable decision. Silently discarding it would leave a reader unable
    to explain why the same CVE appears twice.
    """

    id_a: str
    id_b: str
    source: str
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "id_a": self.id_a,
            "id_b": self.id_b,
            "source": self.source,
            "reason": self.reason,
        }


@dataclass
class Cluster:
    """One vulnerability identity: the connected component."""

    #: ⚠ DURABLE SURROGATE, supplied by the caller from a database row. NEVER
    #: derived from `members` — see `assign_cluster_ids` for why.
    cluster_id: str
    members: tuple[str, ...]
    display_id: str
    flagged_for_review: bool = False
    merges: list[MergeRecord] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.members)


class _UnionFind:
    """Union-find with union-by-size and path compression."""

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}
        self._size: dict[str, int] = {}

    def add(self, item: str) -> None:
        if item not in self._parent:
            self._parent[item] = item
            self._size[item] = 1

    def find(self, item: str) -> str:
        self.add(item)
        root = item
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[item] != root:
            self._parent[item], item = root, self._parent[item]
        return root

    def size_of(self, item: str) -> int:
        return self._size[self.find(item)]

    def union(self, a: str, b: str) -> bool:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        if self._size[ra] < self._size[rb]:
            ra, rb = rb, ra
        self._parent[rb] = ra
        self._size[ra] += self._size[rb]
        return True

    def groups(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for item in self._parent:
            out.setdefault(self.find(item), []).append(item)
        return out


@dataclass
class ClosureResult:
    """The outcome of running the closure over an edge set."""

    #: Root -> sorted members.
    groups: dict[str, tuple[str, ...]]
    merges: list[MergeRecord]
    refused: list[RefusedEdge]
    flagged: set[str]

    def group_of(self, vuln_id: str) -> tuple[str, ...]:
        normalized = normalize_id(vuln_id)
        for members in self.groups.values():
            if normalized in members:
                return members
        return (normalized,)


def close(edges: Iterable[AliasEdge], *, seed_ids: Iterable[str] = ()) -> ClosureResult:
    """Compute the transitive closure with all three over-merge guards.

    Deterministic: edges are sorted before processing, so the same input always
    produces the same clusters and the same merge log. Without the sort, which
    edges get refused by the size cap would depend on iteration order — and the
    golden tests would flap, which is worse than not having them (spec §8).
    """
    uf = _UnionFind()
    for seed in seed_ids:
        normalized = normalize_id(seed)
        if normalized:
            uf.add(normalized)

    # Deduplicate and order. Authoritative edges are applied FIRST so that when
    # the size cap bites, the edges that survive are the trustworthy ones rather
    # than whichever happened to be processed early.
    unique: dict[tuple[str, str], AliasEdge] = {}
    for edge in edges:
        normalized = edge.normalized()
        if not normalized.id_a or not normalized.id_b:
            continue
        if normalized.id_a == normalized.id_b:
            continue
        key = normalized.key()
        existing = unique.get(key)
        if existing is None or (normalized.authoritative and not existing.authoritative):
            unique[key] = normalized

    ordered = sorted(
        unique.values(),
        key=lambda e: (not e.authoritative, e.key()),
    )

    merges: list[MergeRecord] = []
    refused: list[RefusedEdge] = []
    flagged: set[str] = set()

    for edge in ordered:
        a, b = edge.id_a, edge.id_b
        uf.add(a)
        uf.add(b)

        # ── GUARD 1: no CVE↔CVE merge without an authoritative source ──
        #
        # Two CVE ids are two entries in the same registry. A scanner claiming
        # they are the same is usually a batched-advisory artefact, and merging
        # them removes a real, separately-tracked vulnerability from the report.
        if namespace_of(a) == "CVE" and namespace_of(b) == "CVE" and not edge.authoritative:
            refused.append(
                RefusedEdge(
                    a,
                    b,
                    edge.source,
                    "CVE↔CVE edges require an authoritative source; a scanner "
                    "assertion is not sufficient",
                )
            )
            continue

        if uf.find(a) == uf.find(b):
            continue

        # ── GUARD 2: cap the cluster size ──
        #
        # Checked BEFORE the union, not after: undoing a union in a
        # path-compressed structure is not possible, so the only place to stop
        # is here.
        combined = uf.size_of(a) + uf.size_of(b)
        if combined > MAX_CLUSTER_SIZE:
            flagged.add(uf.find(a))
            flagged.add(uf.find(b))
            refused.append(
                RefusedEdge(
                    a,
                    b,
                    edge.source,
                    f"merging would produce a {combined}-member cluster, above the "
                    f"{MAX_CLUSTER_SIZE} ceiling; flagged for review instead of merged",
                )
            )
            continue

        if uf.union(a, b):
            # ── GUARD 3: log every merge with its evidence ──
            merges.append(
                MergeRecord(
                    id_a=a,
                    id_b=b,
                    source=edge.source,
                    authoritative=edge.authoritative,
                    edge_id=edge.edge_id,
                )
            )

    groups = {root: tuple(sorted(members)) for root, members in uf.groups().items()}
    flagged_roots = {uf.find(root) for root in flagged if root in groups or True}

    return ClosureResult(
        groups=groups,
        merges=merges,
        refused=refused,
        flagged=flagged_roots,
    )


def display_id(members: Iterable[str]) -> str:
    """Pick the id a human should see: lowest namespace rank, then lowest value.

    ⚠ Reports pin `display_id_at_render`. This function may return a different
    answer next month as the cluster absorbs aliases, and a report issued in
    March must still read `CVE-2021-44228` in September. The pinning is the
    caller's job; this only computes today's answer.
    """
    best = ""
    best_key: tuple[int, str] = (99, "")
    for member in members:
        normalized = normalize_id(member)
        if not normalized:
            continue
        rank = _NAMESPACE_RANK.get(namespace_of(normalized), 50)
        key = (rank, normalized)
        if not best or key < best_key:
            best, best_key = normalized, key
    return best


def assign_cluster_ids(
    result: ClosureResult,
    *,
    existing: dict[str, str],
    mint: Iterator[str],
) -> list[Cluster]:
    """Attach durable ids to the computed groups.

    ⚠ THE ID IS NEVER DERIVED FROM THE MEMBERS.

    Not `uuid5(sorted(members))`, not a hash, not anything content-addressed.
    Such an id changes the instant a new alias is discovered — and then every
    foreign key pointing at it dangles, and every report that cited it refers to
    a cluster that no longer exists.

    So: an existing id is REUSED whenever any member already belongs to one, and
    a new id is minted only for genuinely new clusters. When two previously
    separate clusters merge, the surviving id is the lowest existing one and the
    caller writes a forwarding row for the other — which is what keeps old
    references resolvable.

    `existing` maps member id -> cluster id, from storage.
    `mint` yields fresh surrogate ids (a database sequence, or a test stub).
    """
    # ⚠ The lookup keys are NORMALIZED here rather than trusted from the caller.
    #
    # A caller passing `GHSA-xxxx-yyyy-zzzz` where the closure produced
    # `GHSA-XXXX-YYYY-ZZZZ` would MISS — and a miss does not fail loudly, it
    # mints a brand-new cluster id and orphans the stored one. That is precisely
    # the durability failure this function exists to prevent, arriving through
    # the back door.
    existing = {normalize_id(k): v for k, v in existing.items()}

    clusters: list[Cluster] = []

    for root in sorted(result.groups):
        members = result.groups[root]

        # Every id this cluster's members already belong to. More than one means
        # this run merged previously separate clusters.
        prior = sorted({existing[m] for m in members if m in existing})

        if prior:
            cluster_id = prior[0]
        else:
            cluster_id = next(mint)

        clusters.append(
            Cluster(
                cluster_id=cluster_id,
                members=members,
                display_id=display_id(members),
                flagged_for_review=root in result.flagged,
                merges=[m for m in result.merges if m.id_a in members or m.id_b in members],
            )
        )

    return clusters


def forwarding_rows(
    clusters: Iterable[Cluster], *, existing: dict[str, str]
) -> list[dict[str, str]]:
    """Rows for `normalize.vuln_cluster_merges`.

    Written whenever this run collapsed two previously distinct clusters. A view
    resolves old ids forward, so a report issued against the superseded id still
    resolves — which is the entire point of not deriving ids from content.
    """
    # Normalized for the same reason as in `assign_cluster_ids`: a missed lookup
    # here means a superseded cluster id never gets a forwarding row, so every
    # report that cited it stops resolving.
    existing = {normalize_id(k): v for k, v in existing.items()}

    rows: list[dict[str, str]] = []
    for cluster in clusters:
        superseded = sorted(
            {
                existing[m]
                for m in cluster.members
                if m in existing and existing[m] != cluster.cluster_id
            }
        )
        for old in superseded:
            evidence = cluster.merges[0].edge_id if cluster.merges else ""
            rows.append(
                {
                    "from_id": old,
                    "into_id": cluster.cluster_id,
                    "evidence_edge_id": evidence,
                }
            )
    return rows


def edges_from_osv(payload: dict) -> list[AliasEdge]:
    """Extract authoritative alias edges from osv-scanner output.

    osv-scanner is the authoritative source of these edges (spec §2.3), which is
    why its adapter captures `aliases` verbatim. Losing them is expensive to
    notice: nothing fails, the counts are simply wrong and look plausible.
    """
    out: list[AliasEdge] = []
    results = payload.get("results")
    if not isinstance(results, list):
        return out

    for entry in results:
        if not isinstance(entry, dict):
            continue
        for pkg in entry.get("packages", []) or []:
            if not isinstance(pkg, dict):
                continue
            for vuln in pkg.get("vulnerabilities", []) or []:
                if not isinstance(vuln, dict):
                    continue
                primary = normalize_id(str(vuln.get("id", "")))
                if not primary:
                    continue
                for alias in vuln.get("aliases", []) or []:
                    if not isinstance(alias, str):
                        continue
                    other = normalize_id(alias)
                    if other and other != primary:
                        out.append(
                            AliasEdge(
                                id_a=primary,
                                id_b=other,
                                source="osv.dev/aliases",
                                authoritative=True,
                            )
                        )
                # `upstream` is also authoritative and carries the edges that
                # link a distro advisory back to its origin.
                for up in vuln.get("upstream", []) or []:
                    if not isinstance(up, str):
                        continue
                    other = normalize_id(up)
                    if other and other != primary:
                        out.append(
                            AliasEdge(
                                id_a=primary,
                                id_b=other,
                                source="osv.dev/upstream",
                                authoritative=True,
                            )
                        )
    return out


def edges_from_grype(payload: dict) -> list[AliasEdge]:
    """Extract alias edges from grype output.

    ⚠ NOT AUTHORITATIVE. grype's `relatedVulnerabilities` are useful and often
    right, but they are a scanner's assertion, so they cannot on their own merge
    two CVEs (guard 1).
    """
    out: list[AliasEdge] = []
    matches = payload.get("matches")
    if not isinstance(matches, list):
        return out

    for match in matches:
        if not isinstance(match, dict):
            continue
        vuln = match.get("vulnerability")
        if not isinstance(vuln, dict):
            continue
        primary = normalize_id(str(vuln.get("id", "")))
        if not primary:
            continue
        for related in match.get("relatedVulnerabilities", []) or []:
            if not isinstance(related, dict):
                continue
            other = normalize_id(str(related.get("id", "")))
            if other and other != primary:
                out.append(
                    AliasEdge(
                        id_a=primary,
                        id_b=other,
                        source="grype/relatedVulnerabilities",
                        authoritative=False,
                    )
                )
    return out
