"""Vulnerability alias closure — the union-find and its three guards.

⚠ THE FAILURE THIS PREVENTS IS A COUNT THAT LOOKS PLAUSIBLE.

Four engines report the same vulnerability under four namespaces. Dedup on the
primary id and a report claims 240 vulnerabilities where there are 80 — a number
that drives remediation budgets and that nothing in the report contradicts.

Over-merging fails the other way and is worse: unrelated vulnerabilities collapse
into one, and a real one disappears.
"""

from __future__ import annotations

import itertools

from .aliases import (
    MAX_CLUSTER_SIZE,
    AliasEdge,
    assign_cluster_ids,
    close,
    display_id,
    edges_from_grype,
    edges_from_osv,
    forwarding_rows,
    namespace_of,
    normalize_id,
)


def ids(n: int = 0):
    """A deterministic id minter, standing in for a database sequence."""
    return (f"cluster-{i}" for i in itertools.count(n))


# -- the closure itself ---------------------------------------------------


def test_the_log4shell_triangle_collapses_from_partial_edges() -> None:
    """⚠ THE CASE THE WHOLE MODULE EXISTS FOR.

    No single tool asserts the full triangle. grype knows GHSA↔CVE, osv knows
    CVE↔SNYK. The transitive closure is what makes them one vulnerability
    instead of three.
    """
    result = close(
        [
            AliasEdge("GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228", "osv.dev/aliases", True),
            AliasEdge(
                "CVE-2021-44228", "SNYK-JAVA-ORGAPACHELOGGINGLOG4J-2314720", "osv.dev/aliases", True
            ),
        ]
    )
    group = result.group_of("GHSA-jfh8-c2jp-5v3q")
    assert len(group) == 3
    assert "CVE-2021-44228" in group
    assert "SNYK-JAVA-ORGAPACHELOGGINGLOG4J-2314720" in group


def test_unrelated_vulnerabilities_stay_separate() -> None:
    result = close(
        [
            AliasEdge("CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q", "osv.dev/aliases", True),
            AliasEdge("CVE-2022-22965", "GHSA-36p3-wjmg-h94x", "osv.dev/aliases", True),
        ]
    )
    assert len(result.groups) == 2


def test_display_id_prefers_cve() -> None:
    """CVE is what a remediation ticket quotes."""
    assert display_id(["GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228", "SNYK-JAVA-X"]) == (
        "CVE-2021-44228"
    )
    # With no CVE, GHSA wins over an OSV-native id.
    assert display_id(["GO-2021-0113", "GHSA-abcd-efgh-ijkl"]) == "GHSA-ABCD-EFGH-IJKL"


def test_id_normalization_is_case_and_separator_insensitive() -> None:
    assert normalize_id("cve-2021-44228") == "CVE-2021-44228"
    assert normalize_id("CVE_2021_44228") == "CVE-2021-44228"
    assert namespace_of("GHSA-jfh8-c2jp-5v3q") == "GHSA"


def test_a_self_edge_is_ignored() -> None:
    result = close([AliasEdge("CVE-2021-1", "CVE-2021-1", "x", True)])
    assert len(result.merges) == 0


# -- GUARD 1: CVE↔CVE requires an authoritative source --------------------


def test_a_scanner_asserted_cve_to_cve_edge_is_refused() -> None:
    """⚠ Two CVE ids are two entries in the same registry.

    A scanner claiming they are the same is usually a batched-advisory
    artefact, and merging removes a separately-tracked vulnerability from the
    report.
    """
    result = close([AliasEdge("CVE-2021-1", "CVE-2021-2", "grype/relatedVulnerabilities", False)])
    assert len(result.groups) == 2, "the two CVEs must stay separate"
    assert result.refused
    assert "authoritative" in result.refused[0].reason


def test_an_authoritative_cve_to_cve_edge_is_allowed() -> None:
    """The guard is about the SOURCE, not the namespaces."""
    result = close([AliasEdge("CVE-2021-1", "CVE-2021-2", "osv.dev/aliases", True)])
    assert len(result.groups) == 1


def test_a_scanner_asserted_ghsa_to_cve_edge_is_allowed() -> None:
    """The guard applies only to CVE↔CVE. Cross-namespace edges are the normal
    case and are how the closure does its job at all."""
    result = close([AliasEdge("GHSA-aaaa-bbbb-cccc", "CVE-2021-1", "grype", False)])
    assert len(result.groups) == 1


# -- GUARD 2: the size cap ------------------------------------------------


def test_an_oversized_cluster_is_flagged_not_merged() -> None:
    """⚠ A cluster that large is far more likely to be an over-merge than a
    real advisory family. One bad MAL- edge could otherwise absorb an entire
    ecosystem's advisories into a single "vulnerability"."""
    edges = [
        AliasEdge("GHSA-hub-0000-0000", f"OSV-{i:04d}", "osv.dev/aliases", True)
        for i in range(MAX_CLUSTER_SIZE + 5)
    ]
    result = close(edges)

    biggest = max(len(m) for m in result.groups.values())
    assert biggest <= MAX_CLUSTER_SIZE, "the cap was not enforced"
    assert result.flagged, "an oversized cluster must be flagged for review"
    assert result.refused


def test_the_cap_does_not_fire_below_the_ceiling() -> None:
    edges = [
        AliasEdge("GHSA-hub-0000-0000", f"OSV-{i:04d}", "osv.dev/aliases", True)
        for i in range(MAX_CLUSTER_SIZE - 2)
    ]
    result = close(edges)
    assert not result.flagged
    assert not result.refused


def test_authoritative_edges_are_applied_before_scanner_edges() -> None:
    """When the cap bites, the surviving edges must be the trustworthy ones —
    not whichever happened to be processed first."""
    edges = [AliasEdge("HUB-1", f"OSV-{i:04d}", "grype", False) for i in range(MAX_CLUSTER_SIZE)]
    edges.append(AliasEdge("HUB-1", "CVE-2021-44228", "osv.dev/aliases", True))

    result = close(edges)
    group = result.group_of("HUB-1")
    assert "CVE-2021-44228" in group, "the authoritative edge should have survived the cap"


# -- GUARD 3: every merge is explained ------------------------------------


def test_every_merge_records_its_evidence() -> None:
    """⚠ A compliance product must answer "why did these two become one?".

    If it cannot, the merge should not have happened.
    """
    result = close(
        [AliasEdge("CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q", "osv.dev/aliases", True, "edge-7")]
    )
    assert len(result.merges) == 1
    record = result.merges[0].as_dict()
    assert record["source"] == "osv.dev/aliases"
    assert record["authoritative"] is True
    assert record["evidence_edge_id"] == "edge-7"


def test_refusals_are_recorded_too() -> None:
    """A refusal means two findings stay separate — a reportable decision.

    Dropping it silently leaves a reader unable to explain why the same CVE
    appears twice.
    """
    result = close([AliasEdge("CVE-1", "CVE-2", "grype", False)])
    assert result.refused
    assert result.refused[0].as_dict()["reason"]


# -- TRAP A: durable cluster ids ------------------------------------------


def test_a_cluster_id_survives_absorbing_a_new_alias() -> None:
    """⚠ THE ADR-0005 TRAP, AND THE MOST EXPENSIVE ONE HERE.

    An id derived from its members — uuid5(sorted(members)), a hash, anything
    content-addressed — MUTATES the moment a new alias is discovered. Every
    foreign key dangles and every previously issued report cites a cluster id
    that no longer exists.
    """
    first = close([AliasEdge("CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q", "osv.dev/aliases", True)])
    clusters = assign_cluster_ids(first, existing={}, mint=ids())
    original_id = clusters[0].cluster_id

    existing = dict.fromkeys(clusters[0].members, original_id)

    # A month later, a third alias appears.
    second = close(
        [
            AliasEdge("CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q", "osv.dev/aliases", True),
            AliasEdge("CVE-2021-44228", "SNYK-JAVA-X", "osv.dev/aliases", True),
        ]
    )
    updated = assign_cluster_ids(second, existing=existing, mint=ids(99))

    assert updated[0].cluster_id == original_id, (
        "the cluster id changed when a new alias arrived — every foreign key "
        "referencing it is now dangling"
    )
    assert len(updated[0].members) == 3


def test_merging_two_known_clusters_keeps_one_id_and_forwards_the_other() -> None:
    """Old references must stay resolvable, which is the entire reason ids are
    not derived from content."""
    existing = {"CVE-2021-1": "cluster-A", "GHSA-xxxx-yyyy-zzzz": "cluster-B"}

    result = close(
        [AliasEdge("CVE-2021-1", "GHSA-xxxx-yyyy-zzzz", "osv.dev/aliases", True, "edge-1")]
    )
    clusters = assign_cluster_ids(result, existing=existing, mint=ids())

    assert len(clusters) == 1
    survivor = clusters[0].cluster_id
    assert survivor in ("cluster-A", "cluster-B")

    rows = forwarding_rows(clusters, existing=existing)
    assert len(rows) == 1
    assert rows[0]["into_id"] == survivor
    assert rows[0]["from_id"] != survivor
    assert rows[0]["evidence_edge_id"] == "edge-1"


def test_a_new_cluster_mints_a_fresh_id() -> None:
    result = close([AliasEdge("CVE-2099-1", "GHSA-new-new-new", "osv.dev/aliases", True)])
    clusters = assign_cluster_ids(result, existing={}, mint=ids())
    assert clusters[0].cluster_id == "cluster-0"


def test_cluster_ids_are_not_content_derived() -> None:
    """A direct assertion of the rule, not just its consequence.

    Two runs over the same members but different mint sequences must produce
    different ids — proving the id comes from the minter, not the content.
    """
    result = close([AliasEdge("CVE-2021-1", "GHSA-a-b-c", "osv.dev/aliases", True)])
    a = assign_cluster_ids(result, existing={}, mint=ids(0))[0].cluster_id
    b = assign_cluster_ids(result, existing={}, mint=ids(500))[0].cluster_id
    assert a != b


# -- determinism ----------------------------------------------------------


def test_the_closure_is_deterministic_regardless_of_input_order() -> None:
    """⚠ Non-determinism here makes every golden test flap, and flapping tests
    get ignored — worse than not having them (spec §8)."""
    edges = [
        AliasEdge("CVE-1", "GHSA-a-a-a", "osv.dev/aliases", True),
        AliasEdge("GHSA-a-a-a", "OSV-1", "osv.dev/aliases", True),
        AliasEdge("OSV-1", "SNYK-1", "osv.dev/aliases", True),
    ]
    forward = close(edges)
    backward = close(list(reversed(edges)))

    assert sorted(forward.groups.values()) == sorted(backward.groups.values())
    assert [m.as_dict() for m in forward.merges] == [m.as_dict() for m in backward.merges]


# -- extraction from engine output ----------------------------------------


def test_osv_aliases_are_extracted_as_authoritative() -> None:
    payload = {
        "results": [
            {
                "packages": [
                    {
                        "vulnerabilities": [
                            {"id": "GHSA-r5fr-rjxr-66jc", "aliases": ["CVE-2021-23337"]}
                        ]
                    }
                ]
            }
        ]
    }
    edges = edges_from_osv(payload)
    assert len(edges) == 1
    assert edges[0].authoritative is True


def test_grype_related_vulnerabilities_are_not_authoritative() -> None:
    """They are useful and often right, but a scanner's assertion cannot on its
    own merge two CVEs."""
    payload = {
        "matches": [
            {
                "vulnerability": {"id": "GHSA-a-b-c"},
                "relatedVulnerabilities": [{"id": "CVE-2021-1"}],
            }
        ]
    }
    edges = edges_from_grype(payload)
    assert len(edges) == 1
    assert edges[0].authoritative is False


def test_malformed_engine_output_yields_no_edges_rather_than_raising() -> None:
    """A shape change upstream must degrade coverage, not crash a run."""
    assert edges_from_osv({}) == []
    assert edges_from_osv({"results": "not a list"}) == []
    assert edges_from_grype({"matches": [None, {"vulnerability": None}]}) == []


def test_an_unnormalized_existing_id_still_matches() -> None:
    """⚠ REGRESSION GUARD FOR A SILENT ORPHANING.

    Storage may hold `ghsa-xxxx-yyyy-zzzz` while the closure produces
    `GHSA-XXXX-YYYY-ZZZZ`. A missed lookup does not fail loudly — it mints a
    brand-new cluster id and orphans the stored one, which is the exact
    durability failure ADR-0005 is about, arriving through the back door.
    """
    result = close([AliasEdge("CVE-2021-1", "GHSA-aaaa-bbbb-cccc", "osv.dev/aliases", True)])
    clusters = assign_cluster_ids(
        result,
        existing={"ghsa-aaaa-bbbb-cccc": "cluster-stored"},
        mint=ids(),
    )
    assert clusters[0].cluster_id == "cluster-stored", (
        "a case-different stored id was not matched, so a new cluster was minted"
    )
