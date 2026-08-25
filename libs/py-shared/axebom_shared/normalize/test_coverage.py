"""Coverage scoring, license resolution, graph merge and finding dedup.

⚠ THESE PRODUCE THE NUMBERS A CUSTOMER QUOTES.

None of the failures here crash anything. They report 94% where it is 61%, or
one finding where there are three, and everything downstream looks fine.
"""

from __future__ import annotations

from .coverage import (
    Field,
    fields_from_profile,
    is_declared,
    is_substantive,
    score,
    score_crypto,
)
from .findings import (
    CvssVector,
    RawFinding,
    dedup,
    patch_status,
    resolve_fix_version,
    resolve_severity,
)
from .graph import Edge, build, has_cycle, level_membership, merge_edges
from .licenses import (
    NOASSERTION,
    NONE,
    LicenseSet,
)
from .licenses import (
    resolve as resolve_license,
)

# =========================================================================
# COVERAGE — two numbers, always both
# =========================================================================


def f(field_id: str, path: str, weight: int = 3) -> Field:
    return Field(id=field_id, name=field_id, canonical_path=path, weight=weight)


FIELDS = [
    f("name", "component.name"),
    f("version", "component.version_raw"),
    f("supplier", "component.supplier", weight=1),
]


def test_not_provided_is_declared_but_not_complete() -> None:
    """⚠ THE CRUX OF THE WHOLE COVERAGE MODEL.

    A field explicitly marked `not-provided` is REPORTED — which is why it is
    stored rather than omitted — but it is NOT covered. Publishing only
    `declaration_pct` and labelling it "coverage" gives a 100% score to a BOM
    that knows almost nothing.
    """
    result = score(
        [
            {
                "component.name": "lodash",
                "component.version_raw": "4.17.21",
                "component.supplier": "not-provided",
            }
        ],
        FIELDS,
    )
    assert result.declaration_pct == 100.0
    assert result.completeness_pct < 100.0
    assert result.completeness_pct == 100.0 * 6 / 7


def test_the_non_substantive_set() -> None:
    for value in ("not-provided", "NOASSERTION", "unknown", "", "   ", []):
        assert not is_substantive(value), f"{value!r} must not count as covered"
    for value in ("Apache-2.0", "1.0.0", 0, False, ["x"]):
        assert is_substantive(value), f"{value!r} should count as covered"


def test_false_is_an_answer_not_an_absence() -> None:
    """`executable_property: false` is a real assertion. Treating it as absent
    would mark every non-executable component unscored."""
    assert is_substantive(False)
    assert is_declared(False)


def test_a_list_of_not_provided_is_not_coverage() -> None:
    assert not is_substantive(["not-provided"])
    assert is_declared(["not-provided"])


def test_license_none_counts_as_present_but_noassertion_does_not() -> None:
    """⚠ THE ONE DELIBERATE EXCEPTION, documented so it can be argued about.

    `NONE` is a substantive assertion — "we looked, there is no licence".
    `NOASSERTION` declines to say.
    """
    assert is_substantive("NONE", is_license=True)
    assert not is_substantive("NOASSERTION", is_license=True)
    # Outside a licence field, NONE is not special.
    assert not is_substantive("none-provided", is_license=False)


def test_unidentified_components_stay_in_the_denominator() -> None:
    """⚠ Dropping them lets a scan that understood almost nothing report a high
    percentage."""
    identified = [
        {"component.name": "x", "component.version_raw": "1", "component.supplier": "acme"}
    ]

    honest = score(identified, FIELDS, unidentified=9)
    flattering = score(identified, FIELDS, unidentified=0)

    assert flattering.completeness_pct == 100.0
    assert honest.completeness_pct == 10.0
    assert honest.unidentified_count == 9
    assert any(d["code"] == "NORMALIZE_UNIDENTIFIED_IN_DENOMINATOR" for d in honest.diagnostics)


def test_zero_entities_is_zero_coverage_not_perfect_coverage() -> None:
    """A scan that found nothing must not report perfect coverage of nothing."""
    result = score([], FIELDS)
    assert result.completeness_pct == 0.0
    assert result.declaration_pct == 0.0


def test_weights_come_from_the_profile_and_are_published() -> None:
    """The formula is rendered into every report so the number is auditable."""
    result = score([{"component.name": "x"}], FIELDS)
    assert result.denominator == 3 + 3 + 1
    assert result.completeness_numerator == 3
    assert "Σ" in result.as_dict()["formula"]


def test_the_field_count_is_derived_never_written() -> None:
    """⚠ Invariant 2: no field count is a literal anywhere.

    `fields_from_profile` is the only way the count enters the system, so a
    guideline revision is a data change.
    """
    entries = [
        {"id": "a", "name": "A", "canonical_path": "component.a", "weight": 3},
        {"id": "b", "name": "B", "canonical_path": "component.b[]", "weight": 1},
        {"id": "", "name": "skip", "canonical_path": "component.c"},
    ]
    fields = fields_from_profile(entries)
    assert len(fields) == 2, "entries without an id are skipped"
    assert fields[1].canonical_path == "component.b", "the [] notation is stripped"


# -- type-aware crypto scoring --------------------------------------------

ALGORITHM_FIELDS = [
    f("algo.name", "crypto_asset.name"),
    f("algo.primitive", "crypto_asset.primitive"),
    f("algo.mode", "crypto_asset.mode"),
]
CERTIFICATE_FIELDS = [
    f("cert.name", "crypto_asset.name"),
    f("cert.subject", "crypto_asset.cert_subject"),
    f("cert.issuer", "crypto_asset.cert_issuer"),
]
FIELD_SETS = {"algorithm": ALGORITHM_FIELDS, "certificate": CERTIFICATE_FIELDS}


def test_a_certificate_is_scored_against_certificate_fields_only() -> None:
    """⚠ A CORRECTNESS REQUIREMENT, NOT AN OPTIMIZATION.

    Scoring a certificate against a Keys field like `key_size` reports every
    CBOM at roughly 30% — falsely, in a compliance document.
    """
    certificate = {
        "crypto_asset.asset_type": "certificate",
        "crypto_asset.name": "example.com",
        "crypto_asset.cert_subject": "CN=example.com",
        "crypto_asset.cert_issuer": "CN=Example CA",
    }
    result = score_crypto([certificate], FIELD_SETS)
    assert result.completeness_pct == 100.0, (
        "a fully-populated certificate must score 100%, not be marked down for "
        "fields belonging to another asset type"
    )


def test_each_asset_type_uses_its_own_field_set() -> None:
    assets = [
        {
            "crypto_asset.asset_type": "algorithm",
            "crypto_asset.name": "AES-128-GCM",
            "crypto_asset.primitive": "block-cipher",
            "crypto_asset.mode": "gcm",
        },
        {
            "crypto_asset.asset_type": "certificate",
            "crypto_asset.name": "example.com",
            "crypto_asset.cert_subject": "CN=example.com",
            "crypto_asset.cert_issuer": "CN=CA",
        },
    ]
    result = score_crypto(assets, FIELD_SETS)
    assert result.completeness_pct == 100.0
    assert result.scored_entities == 2


def test_an_unknown_asset_type_is_unidentified_not_scored_against_a_guess() -> None:
    result = score_crypto(
        [{"crypto_asset.asset_type": "quantum-widget", "crypto_asset.name": "x"}],
        FIELD_SETS,
    )
    assert result.unidentified_count == 1
    assert any(d["code"] == "NORMALIZE_CRYPTO_ASSET_TYPE_UNKNOWN" for d in result.diagnostics)


# =========================================================================
# LICENSES
# =========================================================================


def test_none_and_noassertion_are_distinct_and_neither_is_an_error() -> None:
    assert resolve_license("NONE").value == NONE
    assert resolve_license("NOASSERTION").value == NOASSERTION
    assert resolve_license("NONE").is_substantive
    assert not resolve_license("NOASSERTION").is_substantive


def test_gpl_2_0_is_flagged_ambiguous_never_resolved() -> None:
    """⚠ CHOOSING WRONG IS A LEGAL ERROR, NOT A DATA-QUALITY ERROR.

    `GPL-2.0` could be `-only` or `-or-later`, with materially different
    obligations, and the guideline gives no way to choose.
    """
    result = resolve_license("GPL-2.0")
    assert result.ambiguous
    assert set(result.candidates) == {"GPL-2.0-only", "GPL-2.0-or-later"}
    assert any(d["code"] == "NORMALIZE_LICENSE_AMBIGUOUS" for d in result.diagnostics)


def test_ambiguity_survives_the_alias_table() -> None:
    """ "GPLv2" folds to GPL-2.0, which is still ambiguous."""
    result = resolve_license("GPLv2")
    assert result.ambiguous


def test_an_unambiguous_deprecated_id_is_rewritten() -> None:
    """`GPL-2.0+` can only mean one thing, so rewriting is safe."""
    result = resolve_license("GPL-2.0+")
    assert result.value == "GPL-2.0-or-later"
    assert not result.ambiguous


def test_the_alias_table_maps_real_world_spellings() -> None:
    for spelling in ("Apache 2.0", "ASL 2.0", "Apache License, Version 2.0", "apache-2.0"):
        assert resolve_license(spelling).value == "Apache-2.0", spelling


def test_an_unmapped_license_becomes_a_licenseref_with_the_raw_text_kept() -> None:
    """Not an error and not dropped: a human maps it later WITHOUT re-scanning."""
    result = resolve_license("Weird Corporate License v3")
    assert result.value.startswith("LicenseRef-AxeBOM-")
    assert result.raw == "Weird Corporate License v3"


def test_or_expressions_are_not_flattened() -> None:
    """⚠ Which disjunct applies is a POLICY decision for a later layer."""
    result = resolve_license("MIT OR Apache-2.0")
    assert "OR" in result.value
    assert "MIT" in result.value and "Apache-2.0" in result.value


def test_expression_operands_are_each_resolved() -> None:
    result = resolve_license("Apache 2.0 AND MIT")
    assert result.value == "Apache-2.0 AND MIT"


def test_an_unbalanced_expression_is_kept_verbatim_not_rewritten() -> None:
    result = resolve_license("(MIT OR Apache-2.0")
    assert result.rule == "expression-invalid"
    assert any(d["code"] == "NORMALIZE_LICENSE_EXPRESSION_INVALID" for d in result.diagnostics)


def test_concluded_never_overwrites_declared() -> None:
    """SPDX requires the distinction; "the manifest says MIT but the LICENSE
    file is Apache-2.0" is a finding, not a conflict to resolve silently."""
    licenses = LicenseSet(declared=resolve_license("MIT"), concluded=resolve_license("Apache-2.0"))
    value, rule = licenses.effective()
    assert value == "Apache-2.0", "concluded outranks declared for the EFFECTIVE value"
    assert rule.startswith("concluded")
    assert licenses.declared is not None and licenses.declared.value == "MIT", (
        "the declared value must still be there"
    )


# =========================================================================
# GRAPH — replace, do not union
# =========================================================================


def test_a_higher_trust_engine_replaces_an_ecosystem_subgraph() -> None:
    """⚠ Unioning invents transitive edges that no engine reported, and
    corrupts the direct-vs-transitive split a Top-Level report is built on."""
    contributions = {
        "syft": [
            Edge("root", "a", ecosystem="npm", owning_engine="syft"),
            Edge("root", "b", ecosystem="npm", owning_engine="syft"),
        ],
        "trivy-fs": [
            Edge("root", "a", ecosystem="npm", owning_engine="trivy-fs"),
            Edge("a", "b", ecosystem="npm", owning_engine="trivy-fs"),
        ],
    }
    trust = {"trivy-fs": {"npm": 1}, "syft": {"npm": 5}}

    edges, owning, diagnostics = merge_edges(contributions, trust)

    assert owning["npm"] == "trivy-fs"
    assert len(edges) == 2
    assert ("root", "b") not in {(e.from_key, e.to_key) for e in edges}, (
        "syft's edge survived — the graphs were unioned rather than replaced"
    )
    assert any(d["code"] == "NORMALIZE_GRAPH_REPLACED" for d in diagnostics)


def test_different_ecosystems_keep_their_own_owning_engine() -> None:
    contributions = {
        "syft": [Edge("r", "go1", ecosystem="golang", owning_engine="syft")],
        "trivy-fs": [Edge("r", "npm1", ecosystem="npm", owning_engine="trivy-fs")],
    }
    trust = {"trivy-fs": {"npm": 1}, "syft": {"golang": 1}}
    _, owning, _ = merge_edges(contributions, trust)
    assert owning == {"golang": "syft", "npm": "trivy-fs"}


def test_a_cycle_does_not_hang_the_traversal() -> None:
    """Go module graphs and npm workspaces contain cycles. Never assume a DAG."""
    edges = [Edge("root", "a"), Edge("a", "b"), Edge("b", "a")]
    result = build(component_keys=["root", "a", "b"], edges=edges, roots=["root"])
    assert result.depth_of("a") == 1
    assert result.depth_of("b") == 2
    assert has_cycle(edges)


def test_an_orphan_gets_depth_none_never_depth_one() -> None:
    """⚠ Forcing an orphan to depth 1 silently inflates the direct-dependency
    count, and that is a headline number."""
    result = build(
        component_keys=["root", "a", "stray"],
        edges=[Edge("root", "a")],
        roots=["root"],
    )
    assert result.depth_of("stray") is None
    assert result.is_orphan("stray")
    assert "stray" not in result.direct
    assert any(d["code"] == "NORMALIZE_GRAPH_ORPHANS" for d in result.diagnostics)


def test_a_monorepo_has_n_roots() -> None:
    """One root per repository makes every workspace package look like a direct
    dependency of an imaginary parent."""
    result = build(
        component_keys=["api", "worker", "express", "requests"],
        edges=[
            Edge("api", "express", ecosystem="npm"),
            Edge("worker", "requests", ecosystem="pypi"),
        ],
        roots=["api", "worker"],
    )
    assert result.roots == ["api", "worker"]
    assert result.direct == {"express", "requests"}
    assert result.depth_of("express") == 1


def test_is_direct_comes_from_the_root_set_not_from_depth() -> None:
    """Depth is a derived traversal fact; directness is what the manifest said."""
    result = build(
        component_keys=["root", "a", "b"],
        edges=[Edge("root", "a"), Edge("a", "b")],
        roots=["root"],
    )
    assert result.direct == {"a"}
    assert result.depth_of("b") == 2


def test_no_roots_is_reported_loudly() -> None:
    result = build(component_keys=["a", "b"], edges=[], roots=[])
    assert any(d["code"] == "NORMALIZE_GRAPH_NO_ROOTS" for d in result.diagnostics)


def test_top_level_excludes_orphans_because_their_depth_is_unknown() -> None:
    result = build(component_keys=["root", "a", "stray"], edges=[Edge("root", "a")], roots=["root"])
    assert level_membership(result, "a", "top-level")
    assert not level_membership(result, "stray", "top-level")
    assert level_membership(result, "stray", "complete")


# =========================================================================
# FINDINGS — dedup and severity
# =========================================================================


def test_the_same_cve_from_two_engines_is_one_finding() -> None:
    raw = [
        RawFinding("CVE-2021-1", "purl:pkg:npm/x@1", "grype", severity="high"),
        RawFinding("CVE-2021-1", "purl:pkg:npm/x@1", "trivy-fs", severity="high"),
    ]
    out = dedup(raw, cluster_of={"CVE-2021-1": "c1"}, display_of={"c1": "CVE-2021-1"})
    assert len(out) == 1
    assert out[0].detected_by == ["grype", "trivy-fs"]


def test_the_same_cve_on_two_components_is_two_findings() -> None:
    raw = [
        RawFinding("CVE-2021-1", "purl:pkg:npm/x@1", "grype"),
        RawFinding("CVE-2021-1", "purl:pkg:npm/y@1", "grype"),
    ]
    out = dedup(raw, cluster_of={"CVE-2021-1": "c1"}, display_of={"c1": "CVE-2021-1"})
    assert len(out) == 2


def test_aliased_ids_from_different_engines_collapse_to_one_finding() -> None:
    """The whole point of the alias closure, seen from the findings side."""
    raw = [
        RawFinding("GHSA-a-b-c", "purl:pkg:npm/x@1", "grype"),
        RawFinding("CVE-2021-1", "purl:pkg:npm/x@1", "dependency-check"),
    ]
    out = dedup(
        raw,
        cluster_of={"GHSA-a-b-c": "c1", "CVE-2021-1": "c1"},
        display_of={"c1": "CVE-2021-1"},
    )
    assert len(out) == 1
    assert out[0].display_id == "CVE-2021-1"
    assert out[0].detected_by == ["dependency-check", "grype"]


def test_severity_is_never_averaged() -> None:
    """⚠ Precedence, not arithmetic."""
    items = [
        RawFinding("CVE-1", "c", "grype", severity="critical"),
        RawFinding("CVE-1", "c", "trivy-fs", severity="low"),
    ]
    severity, _, conflict = resolve_severity(items)
    assert severity in ("critical", "low"), "an average would produce 'medium'"
    assert conflict, "engines disagreed and that must be surfaced"


def test_a_conflict_is_flagged_not_hidden() -> None:
    """A reviewer will ask why Trivy said High and Grype said Critical, and the
    answer must be visible rather than buried under a number we picked."""
    items = [
        RawFinding("CVE-1", "c", "grype", severity="critical"),
        RawFinding("CVE-1", "c", "trivy-fs", severity="high"),
    ]
    _, _, conflict = resolve_severity(items)
    assert conflict


def test_agreeing_engines_are_not_a_conflict() -> None:
    items = [
        RawFinding("CVE-1", "c", "grype", severity="high"),
        RawFinding("CVE-1", "c", "trivy-fs", severity="high"),
    ]
    _, _, conflict = resolve_severity(items)
    assert not conflict


def test_cvss_v4_outranks_v31() -> None:
    items = [
        RawFinding(
            "CVE-1",
            "c",
            "grype",
            severity="low",
            cvss=[
                CvssVector("3.1", "AV:N", 5.0, "medium", "nvd"),
                CvssVector("4.0", "AV:N", 9.1, "critical", "advisory"),
            ],
        )
    ]
    severity, rule, _ = resolve_severity(items)
    assert severity == "critical"
    assert rule == "cvss-v4"


def test_a_tenant_policy_override_wins_outright() -> None:
    items = [RawFinding("CVE-1", "c", "grype", severity="critical")]
    severity, rule, _ = resolve_severity(items, override="low")
    assert severity == "low"
    assert rule == "tenant-policy"


def test_every_cvss_source_is_kept() -> None:
    """The report shows which one drove the answer and what the others said."""
    raw = [
        RawFinding("CVE-1", "c", "grype", cvss=[CvssVector("3.1", "AV:N", 9.8, "critical", "nvd")]),
        RawFinding(
            "CVE-1", "c", "trivy-fs", cvss=[CvssVector("3.1", "AV:L", 6.2, "medium", "redhat")]
        ),
    ]
    out = dedup(raw, cluster_of={"CVE-1": "c1"}, display_of={"c1": "CVE-1"})
    assert len(out[0].cvss_vectors) == 2


# -- fix versions ---------------------------------------------------------


def test_fixed_in_min_uses_the_ecosystem_comparator() -> None:
    """A lexical sort would answer 1.10.0 — a version that does not fix it."""
    value, ordering, diagnostics = resolve_fix_version("npm", ["1.10.0", "1.9.0", "2.0.0"])
    assert value == "1.9.0"
    assert ordering == "comparator"
    assert not diagnostics


def test_an_ecosystem_without_a_comparator_reports_unknown_not_a_guess() -> None:
    """⚠ An admitted gap is recoverable; a confident wrong version is not."""
    value, ordering, diagnostics = resolve_fix_version("conan", ["1.10.0", "1.9.0"])
    assert value == ""
    assert ordering == "unknown"
    assert any(d["code"] == "NORMALIZE_NO_VERSION_COMPARATOR" for d in diagnostics)


def test_patch_status_is_unknown_when_the_ordering_is_unknown() -> None:
    assert patch_status("1.0.0", "", "conan", "unknown") == "unknown"
    assert patch_status("1.0.0", "1.9.0", "conan", "unknown") == "unknown"


def test_patch_status_derives_correctly_when_the_ordering_is_known() -> None:
    assert patch_status("1.9.0", "1.9.0", "npm", "comparator") == "patched"
    assert patch_status("2.0.0", "1.9.0", "npm", "comparator") == "patched"
    assert patch_status("1.8.0", "1.9.0", "npm", "comparator") == "vulnerable"


def test_dedup_output_is_deterministic() -> None:
    """Golden files depend on this."""
    raw = [
        RawFinding("CVE-2", "purl:b", "trivy-fs"),
        RawFinding("CVE-1", "purl:a", "grype"),
    ]
    cluster_of = {"CVE-1": "c1", "CVE-2": "c2"}
    display_of = {"c1": "CVE-1", "c2": "CVE-2"}
    first = [f.as_dict() for f in dedup(raw, cluster_of=cluster_of, display_of=display_of)]
    second = [
        f.as_dict()
        for f in dedup(list(reversed(raw)), cluster_of=cluster_of, display_of=display_of)
    ]
    assert first == second


def test_multi_word_operands_survive_expression_splitting() -> None:
    """⚠ Whitespace tokenization turns `Apache License 2.0` into three operands,
    each of which falls through to a LicenseRef — so a perfectly recognisable
    licence becomes unmapped."""
    result = resolve_license("Apache License 2.0 OR MIT")
    assert result.value == "Apache-2.0 OR MIT"


def test_with_exceptions_are_preserved() -> None:
    result = resolve_license("GPL-2.0-only WITH Classpath-exception-2.0")
    assert "WITH" in result.value
