"""cluster_store.py against a REAL Postgres connection.

⚠ INTEGRATION TESTS, SKIPPED WHEN THE STACK IS DOWN — same convention
test_writer.py already uses: try to connect, `pytest.skip` with a message
naming the fix, never fail a clean checkout that has not run `task dev` yet.

⚠ CONNECTS AS `axebom_normalize_writer`, NOT `axebom_app`. The whole point of
this role (migrations/normalize/0006_alias_snapshot.sql) is that it is
narrower than axebom_app — SELECT/INSERT only, plus one column-scoped UPDATE
on vuln_clusters. Testing under axebom_app would prove the SQL is well-formed
but say nothing about whether it actually runs under the real, restricted
grants the deployed normalize consumer holds.

⚠ THIS IS THE ONE THING NEITHER golden fixture CAN COVER — log4shell-java and
alias-overmerge (docs/09-GOLDEN-CORPUS.md) each run `aliases.close()` as a
single, offline, in-memory pass with no database behind it (normalize_runner
.normalize_fixture never wires one). The cross-scan guard this module adds —
"does the TRUE persisted membership, across separate scans, exceed the cap"
— only exists at this module's layer and can only be proven against a real
database that remembers what a PRIOR call wrote.
"""

from __future__ import annotations

import os

import pytest

from .aliases import MAX_CLUSTER_SIZE
from .cluster_store import Artifact, persist_clusters

psycopg = pytest.importorskip("psycopg")


@pytest.fixture
def pg_conn():
    try:
        conn = psycopg.connect(
            host=os.environ.get("POSTGRES_HOST", "localhost"),
            port=int(os.environ.get("POSTGRES_PORT", "55432")),
            dbname=os.environ.get("POSTGRES_DB", "axebom"),
            user=os.environ.get("POSTGRES_NORMALIZE_WRITER_ROLE", "axebom_normalize_writer"),
            password=os.environ.get(
                "POSTGRES_NORMALIZE_WRITER_PASSWORD", "axebom_normalize_writer"
            ),
            connect_timeout=5,
            # ⚠ AUTOCOMMIT — see writer.py's write_bom_document docstring for
            # the exact trap this avoids (a bare statement outside a real
            # `with conn.transaction():` silently downgrades a later
            # transaction to a SAVEPOINT). persist_clusters' own
            # `with conn.transaction():` is always the real kind this way.
            autocommit=True,
        )
    except psycopg.OperationalError as exc:
        pytest.skip(f"database unavailable as axebom_normalize_writer ({exc}) — run `task dev`")
    yield conn
    conn.close()


@pytest.fixture
def cleanup(pg_conn):
    """Tracks cluster ids this test minted and deletes every row under them
    on teardown — vuln_clusters is GLOBAL (no tenant_id), so nothing else
    cleans this up automatically the way RLS + tenant teardown does
    elsewhere.

    ⚠ CLEANS UP THROUGH A SEPARATE `axebom_app` CONNECTION, NOT `pg_conn`.
    `axebom_normalize_writer` has no DELETE grant anywhere (deliberately —
    this module's whole design rests on that), so it cannot tear down its
    own test data; only a role with DELETE (axebom_app, via bootstrap's
    default privileges) can. Using the connection under test to also do
    admin cleanup would defeat the point of testing under the restricted
    role at all.
    """
    created: list[str] = []
    yield created
    admin = psycopg.connect(
        host=os.environ.get("POSTGRES_HOST", "localhost"),
        port=int(os.environ.get("POSTGRES_PORT", "55432")),
        dbname=os.environ.get("POSTGRES_DB", "axebom"),
        user=os.environ.get("POSTGRES_APP_ROLE", "axebom_app"),
        password=os.environ.get("POSTGRES_APP_PASSWORD", "axebom_app"),
        connect_timeout=5,
        autocommit=True,
    )
    try:
        cur = admin.cursor()
        for cluster_id in created:
            cur.execute(
                "DELETE FROM normalize.vuln_cluster_merges WHERE from_cluster_id = %s OR into_cluster_id = %s",
                (cluster_id, cluster_id),
            )
            cur.execute("DELETE FROM normalize.vuln_ids WHERE cluster_id = %s", (cluster_id,))
            cur.execute("DELETE FROM normalize.vuln_clusters WHERE id = %s", (cluster_id,))
    finally:
        admin.close()


def grype_artifact(
    vuln_id: str, *, related: tuple[str, ...] = (), component: str = "x"
) -> Artifact:
    return Artifact(
        engine="grype",
        payload={
            "matches": [
                {
                    "vulnerability": {"id": vuln_id, "severity": "High"},
                    "relatedVulnerabilities": [{"id": r} for r in related],
                    "artifact": {
                        "id": f"pkg:npm/{component}@1",
                        "name": component,
                        "version": "1",
                        "type": "npm",
                        "purl": f"pkg:npm/{component}@1",
                    },
                }
            ]
        },
    )


def osv_artifact(vuln_id: str, *, aliases: tuple[str, ...] = (), component: str = "x") -> Artifact:
    return Artifact(
        engine="osv-scanner",
        payload={
            "results": [
                {
                    "source": {"path": "/x", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {"name": component, "version": "1", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {
                                    "id": vuln_id,
                                    "aliases": list(aliases),
                                    "affected": [
                                        {
                                            "package": {
                                                "ecosystem": "npm",
                                                "name": component,
                                                "purl": f"pkg:npm/{component}",
                                            },
                                            "ranges": [],
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        },
    )


def cluster_row(cur, cluster_id: str) -> tuple[str, int, bool]:
    cur.execute(
        "SELECT display_id, member_count, flagged_for_review FROM normalize.vuln_clusters WHERE id = %s",
        (cluster_id,),
    )
    return cur.fetchone()


def vuln_ids_for(cur, cluster_id: str) -> set[str]:
    cur.execute(
        "SELECT namespace, value FROM normalize.vuln_ids "
        "WHERE normalize.resolve_cluster(cluster_id) = normalize.resolve_cluster(%s::uuid)",
        (cluster_id,),
    )
    return {f"{ns}-{val}" for ns, val in cur.fetchall()}


# --------------------------------------------------------------------------
# Basics
# --------------------------------------------------------------------------


def test_a_scan_with_no_vulnerabilities_touches_nothing(pg_conn) -> None:
    result = persist_clusters(pg_conn, [Artifact(engine="syft", payload={"components": []})])
    assert result == {}


def test_a_brand_new_cluster_is_persisted(pg_conn, cleanup) -> None:
    result = persist_clusters(
        pg_conn, [osv_artifact("CVE-2024-0001", aliases=("GHSA-aaaa-bbbb-cccc",))]
    )

    assert result["CVE-2024-0001"] == result["GHSA-AAAA-BBBB-CCCC"]
    cluster_id = result["CVE-2024-0001"]
    cleanup.append(cluster_id)

    cur = pg_conn.cursor()
    display_id, member_count, flagged = cluster_row(cur, cluster_id)
    assert display_id == "CVE-2024-0001"  # CVE outranks GHSA (aliases.py's _NAMESPACE_RANK)
    assert member_count == 2
    assert flagged is False
    assert vuln_ids_for(cur, cluster_id) == {"CVE-2024-0001", "GHSA-AAAA-BBBB-CCCC"}


def test_replaying_the_same_scan_is_idempotent(pg_conn, cleanup) -> None:
    artifacts = [osv_artifact("CVE-2024-0002")]
    first = persist_clusters(pg_conn, artifacts)
    cleanup.append(first["CVE-2024-0002"])
    second = persist_clusters(pg_conn, artifacts)

    assert first == second
    cur = pg_conn.cursor()
    _, member_count, _ = cluster_row(cur, first["CVE-2024-0002"])
    assert member_count == 1, "replaying the same edge set must not double-count members"


# --------------------------------------------------------------------------
# Cross-scan growth and merge
# --------------------------------------------------------------------------


def test_a_second_scan_adds_a_new_alias_to_an_existing_cluster(pg_conn, cleanup) -> None:
    first = persist_clusters(pg_conn, [osv_artifact("CVE-2024-0003")])
    cluster_id = first["CVE-2024-0003"]
    cleanup.append(cluster_id)

    # A LATER, separate scan discovers the GHSA alias for the same CVE.
    second = persist_clusters(
        pg_conn, [osv_artifact("CVE-2024-0003", aliases=("GHSA-dddd-eeee-ffff",))]
    )

    assert second["CVE-2024-0003"] == cluster_id, (
        "the SAME durable id must survive across scans (ADR-0005)"
    )
    assert second["GHSA-DDDD-EEEE-FFFF"] == cluster_id

    cur = pg_conn.cursor()
    _, member_count, _ = cluster_row(cur, cluster_id)
    assert member_count == 2
    assert vuln_ids_for(cur, cluster_id) == {"CVE-2024-0003", "GHSA-DDDD-EEEE-FFFF"}


def test_a_new_edge_merges_two_previously_separate_clusters(pg_conn, cleanup) -> None:
    """Two scans, each discovering one half of a triangle in isolation, then
    a third scan discovers the connecting edge — the durable ids from the
    first two scans must both still resolve, to the SAME surviving cluster.
    """
    scan_a = persist_clusters(pg_conn, [osv_artifact("CVE-2024-0010", component="a")])
    cluster_a = scan_a["CVE-2024-0010"]
    cleanup.append(cluster_a)

    scan_b = persist_clusters(pg_conn, [osv_artifact("GHSA-1111-2222-3333", component="b")])
    cluster_b = scan_b["GHSA-1111-2222-3333"]
    cleanup.append(cluster_b)
    assert cluster_b != cluster_a

    # A third scan's osv-scanner run discovers the alias linking them.
    bridging = persist_clusters(
        pg_conn, [osv_artifact("CVE-2024-0010", aliases=("GHSA-1111-2222-3333",), component="a")]
    )

    winner = min(cluster_a, cluster_b)
    loser = max(cluster_a, cluster_b)
    assert bridging["CVE-2024-0010"] == winner
    assert bridging["GHSA-1111-2222-3333"] == winner

    cur = pg_conn.cursor()
    # The superseded id's OWN members still resolve to the winner.
    assert vuln_ids_for(cur, loser) == {"CVE-2024-0010", "GHSA-1111-2222-3333"}
    _, member_count, _ = cluster_row(cur, winner)
    assert member_count == 2

    cur.execute(
        "SELECT evidence_edge_id FROM normalize.vuln_cluster_merges WHERE from_cluster_id = %s",
        (loser,),
    )
    row = cur.fetchone()
    assert row is not None, "the merge must be logged"
    assert row[0] is not None, "a merge must cite real evidence (ADR-0005)"


# --------------------------------------------------------------------------
# The cross-scan size guard — the part no golden fixture can cover
# --------------------------------------------------------------------------


def test_the_cross_scan_cap_is_enforced_across_separate_scans(pg_conn, cleanup) -> None:
    """Push a cluster to exactly the ceiling across several separate scans
    (fine), then one more scan that would push it over (refused, flagged,
    the new alias gets its own cluster instead) — the guard aliases.close()
    alone cannot apply, because each of these calls only ever sees ONE new
    member at a time; only cluster_store.py, reading the true persisted
    count, can see the running total.
    """
    primary = "CVE-2024-9000"
    first = persist_clusters(pg_conn, [osv_artifact(primary)])
    cluster_id = first[primary]
    cleanup.append(cluster_id)

    # Grow it one alias at a time, up to the ceiling.
    aliases_added = []
    for i in range(MAX_CLUSTER_SIZE - 1):
        alias = f"GHSA-{i:04d}-aaaa-bbbb"
        aliases_added.append(alias.upper())
        result = persist_clusters(pg_conn, [osv_artifact(primary, aliases=(alias,))])
        assert result[primary] == cluster_id

    cur = pg_conn.cursor()
    _, member_count, flagged = cluster_row(cur, cluster_id)
    assert member_count == MAX_CLUSTER_SIZE
    assert flagged is False, "sitting exactly at the ceiling is not itself a reason to flag"

    # One more — this MUST be refused: the new alias gets its own cluster,
    # and the original is flagged for review rather than grown past 12.
    over_cap_alias = "GHSA-over-cap-000"
    result = persist_clusters(pg_conn, [osv_artifact(primary, aliases=(over_cap_alias,))])

    assert result[primary] == cluster_id, "the primary id's mapping is unchanged by a refused merge"
    fresh_cluster = result[over_cap_alias.upper()]
    assert fresh_cluster != cluster_id, "the over-cap alias must NOT join the existing cluster"
    cleanup.append(fresh_cluster)

    _, member_count, flagged = cluster_row(cur, cluster_id)
    assert member_count == MAX_CLUSTER_SIZE, "the original cluster must not have grown past the cap"
    assert flagged is True, "the original cluster must be flagged for review"

    _, fresh_count, fresh_flagged = cluster_row(cur, fresh_cluster)
    assert fresh_count == 1
    assert fresh_flagged is True, (
        "the refused alias's new cluster is flagged too — it is a known-uncertain split"
    )
