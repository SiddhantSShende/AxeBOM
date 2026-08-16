"""PURL canonicalization and the identity fallback chain.

Every test here corresponds to a rule in `docs/03-NORMALIZER-SPEC.md` §1, and
most of them encode a way that a single `.lower()` would be wrong.

Two directions of failure, and they are not equally bad:

  * **Splitting** one component into two inflates the count. Visible, countable,
    fixable.
  * **Merging** two components into one removes a real component AND its
    vulnerabilities from the report, with nothing to indicate anything is gone.

Where a rule is uncertain the code chooses the splitting direction, and these
tests pin that choice.
"""

from __future__ import annotations

import pytest

from .identity import CONFIDENCE, Identity, normalize_path, resolve
from .merge import never_merge_check
from .purl import PurlError, canonicalize, parse

# -- per-ecosystem name rules ---------------------------------------------


def test_pypi_follows_pep503() -> None:
    """PEP 503: lowercase and collapse runs of - _ . into a single -.

    `zope.interface` is the sharp case — the dot is a SEPARATOR, not part of
    the name, so zope.interface and zope-interface are one project.
    """
    assert canonicalize("pkg:pypi/PyYAML@6.0.1") == "pkg:pypi/pyyaml@6.0.1"
    assert canonicalize("pkg:pypi/zope.interface@6.0") == "pkg:pypi/zope-interface@6.0"
    assert canonicalize("pkg:pypi/zope_interface@6.0") == "pkg:pypi/zope-interface@6.0"
    assert (
        canonicalize("pkg:pypi/Django_REST_framework@3.14.0")
        == "pkg:pypi/django-rest-framework@3.14.0"
    )
    assert canonicalize("pkg:pypi/python-dateutil@2.8.2") == "pkg:pypi/python-dateutil@2.8.2"


def test_pypi_variants_all_collapse_to_one_key() -> None:
    """The dedup this rule exists for: only CASE differs here."""
    spellings = [
        "pkg:pypi/PyYAML@6.0.1",
        "pkg:pypi/pyyaml@6.0.1",
        "pkg:pypi/PYYAML@6.0.1",
    ]
    assert len({canonicalize(s) for s in spellings}) == 1


def test_pep503_collapses_separator_runs_but_does_not_delete_them() -> None:
    """⚠ THE OVER-MERGE THIS RULE MUST NOT CAUSE.

    PEP 503 collapses a RUN of `-`, `_` or `.` into a single `-`. It does not
    remove separators. So `PyYAML` normalizes to `pyyaml` while `py-yaml`
    normalizes to `py-yaml`, and PyPI treats those as two different projects.

    Deleting separators instead of collapsing them would merge them — the
    under-reporting direction, where a real component and its vulnerabilities
    vanish from the report.
    """
    assert canonicalize("pkg:pypi/PyYAML@6.0.1") != canonicalize("pkg:pypi/py-yaml@6.0.1")
    # …but a RUN of separators does collapse.
    assert canonicalize("pkg:pypi/py--yaml@6.0.1") == canonicalize("pkg:pypi/py_.yaml@6.0.1")


def test_npm_scope_percent_encoding_is_decoded_before_comparison() -> None:
    """`%40types/node` and `@types/node` are the same package."""
    assert canonicalize("pkg:npm/%40types/node@20.0.0") == canonicalize(
        "pkg:npm/@types/node@20.0.0"
    )


def test_npm_is_lowercased() -> None:
    assert canonicalize("pkg:npm/Lodash@4.17.21") == "pkg:npm/lodash@4.17.21"


def test_maven_is_case_sensitive() -> None:
    """⚠ Lowercasing Maven merges genuinely distinct artifacts.

    That under-reports, and a missing component is a missing vulnerability.
    """
    a = canonicalize("pkg:maven/org.apache.commons/commons-lang3@3.12.0")
    b = canonicalize("pkg:maven/org.Apache.Commons/Commons-Lang3@3.12.0")
    assert a != b
    assert "commons-lang3" in a
    assert "Commons-Lang3" in b


def test_golang_is_case_preserving_and_decodes_proxy_escaping() -> None:
    """⚠ `!m` is how the module proxy encodes an uppercase M.

    Decoding it wrong yields `masterminds`, a module that does not exist.
    """
    assert (
        canonicalize("pkg:golang/github.com/!masterminds/semver@v3.2.1")
        == "pkg:golang/github.com/Masterminds/semver@v3.2.1"
    )
    assert (
        canonicalize("pkg:golang/github.com/Masterminds/semver@v3.2.1")
        == "pkg:golang/github.com/Masterminds/semver@v3.2.1"
    )


def test_golang_major_version_suffix_is_part_of_the_path() -> None:
    """`/v3` names a different module, not a version of the same one."""
    assert canonicalize("pkg:golang/github.com/x/semver/v3@v3.2.1") != canonicalize(
        "pkg:golang/github.com/x/semver@v3.2.1"
    )


def test_golang_incompatible_suffix_survives_canonicalization() -> None:
    """⚠ `+incompatible` is part of the version, not metadata to strip."""
    assert "+incompatible" in canonicalize(
        "pkg:golang/github.com/docker/docker@v24.0.5+incompatible"
    )


def test_go_and_golang_are_one_ecosystem() -> None:
    """syft emits one spelling, osv-scanner the other. Two rows in the Engine
    Coverage table would imply a gap that does not exist."""
    assert parse("pkg:golang/x/y@v1").ecosystem == "golang"
    assert parse("pkg:go/x/y@v1").ecosystem == "golang"


# -- qualifiers -----------------------------------------------------------


def test_identity_qualifiers_are_kept() -> None:
    """arch and epoch genuinely distinguish packages."""
    x86 = canonicalize("pkg:rpm/redhat/openssl@1.1.1?arch=x86_64")
    arm = canonicalize("pkg:rpm/redhat/openssl@1.1.1?arch=aarch64")
    assert x86 != arm
    assert "arch=x86_64" in x86


def test_provenance_qualifiers_are_dropped_from_the_key() -> None:
    """⚠ The same package from two mirrors is ONE component.

    Keeping `repository_url` in the key makes it two.
    """
    a = parse("pkg:npm/lodash@4.17.21?repository_url=https://registry.npmjs.org")
    b = parse("pkg:npm/lodash@4.17.21?repository_url=https://internal.mirror")
    assert a.canonical() == b.canonical()
    # …but the information is not lost.
    assert a.metadata["source_repo"] == "https://registry.npmjs.org"


def test_qualifiers_are_sorted_so_order_does_not_affect_the_key() -> None:
    """Without the sort, dedup depends on dict iteration order."""
    a = canonicalize("pkg:rpm/x/y@1?arch=x86_64&distro=rhel-9")
    b = canonicalize("pkg:rpm/x/y@1?distro=rhel-9&arch=x86_64")
    assert a == b


def test_empty_qualifier_values_are_dropped() -> None:
    assert canonicalize("pkg:npm/lodash@4.17.21?arch=") == "pkg:npm/lodash@4.17.21"


def test_unknown_qualifiers_do_not_split_a_component() -> None:
    """An engine adding a new annotation must not fork every component."""
    a = canonicalize("pkg:npm/lodash@4.17.21?some_new_field=x")
    assert a == "pkg:npm/lodash@4.17.21"


# -- parsing edge cases ---------------------------------------------------


def test_a_bare_name_is_not_a_purl() -> None:
    """Accepting it would put an unqualified name in the merge key, where it
    can collide across ecosystems."""
    with pytest.raises(PurlError):
        parse("lodash@4.17.21")


def test_version_splits_on_the_last_at_not_the_first() -> None:
    """An npm scope has no @ after the leading one, but Maven classifiers and
    Go pseudo-versions do."""
    assert parse("pkg:npm/@scope/name@1.0.0").version == "1.0.0"
    assert parse("pkg:npm/@scope/name@1.0.0").name == "name"


def test_subpath_traversal_is_refused() -> None:
    """`..` in a subpath is either meaningless or an escape attempt."""
    assert parse("pkg:golang/x/y@v1#../../etc").subpath == "etc"


# -- the fallback chain ---------------------------------------------------


def target(**kwargs) -> dict:
    return kwargs


def test_rule_1_purl_is_high_confidence() -> None:
    identity = resolve(target(purl="pkg:npm/lodash@4.17.21"), scan_id="s", engine="syft")
    assert identity.rule == "purl"
    assert identity.confidence == CONFIDENCE["purl"] == "high"
    assert identity.key == "purl:pkg:npm/lodash@4.17.21"


def test_rule_2_cpe_when_there_is_no_purl() -> None:
    identity = resolve(
        target(cpe="cpe:2.3:a:apache:tomcat:9.0.71:*:*:*:*:*:*:*", name="tomcat"),
        scan_id="s",
        engine="dependency-check",
    )
    assert identity.rule == "cpe"
    assert identity.confidence == "medium"


def test_rule_3_swid() -> None:
    identity = resolve(target(swid={"tagId": "example.com-widget-1.0"}), scan_id="s", engine="hbom")
    assert identity.rule == "swid"


def test_rule_4_hash_requires_sha256_not_md5() -> None:
    """⚠ md5 and sha1 have practical collisions.

    A collision here silently merges two unrelated components — removing one,
    and its vulnerabilities, from the report.
    """
    weak = resolve(
        target(hashes=[{"alg": "MD5", "value": "d41d8cd98f00b204e9800998ecf8427e"}]),
        scan_id="s",
        engine="syft",
    )
    assert weak.rule != "hash"

    strong = resolve(
        target(hashes=[{"alg": "SHA-256", "value": "a" * 64}]), scan_id="s", engine="syft"
    )
    assert strong.rule == "hash"


def test_rule_5_file_requires_a_digest_not_just_a_path() -> None:
    """A path alone is not identity: the same path can hold different content."""
    path_only = resolve(target(locations=[{"path": "vendor/lib.jar"}]), scan_id="s", engine="syft")
    assert path_only.rule != "file"

    with_digest = resolve(
        target(locations=[{"path": "vendor/lib.jar", "sha256": "b" * 64}]),
        scan_id="s",
        engine="syft",
    )
    assert with_digest.rule == "file"


def test_rule_5_is_reachable_at_all() -> None:
    """⚠ REGRESSION GUARD.

    Rule 5 originally read the digest from the same place as rule 4, so rule 4
    always fired first and rule 5 could never run — a documented branch of the
    fallback chain that was dead code. The location digest is what separates
    them.
    """
    identity = resolve(
        target(locations=[{"path": "vendor/lib.jar", "sha256": "c" * 64}]),
        scan_id="s",
        engine="syft",
    )
    assert identity.rule == "file"
    assert identity.key.startswith("file:vendor/lib.jar@")


def test_a_component_level_hash_still_takes_rule_4() -> None:
    """Ordering is preserved: hash outranks file when both could apply."""
    identity = resolve(
        target(sha256="d" * 64, locations=[{"path": "x.jar", "sha256": "e" * 64}]),
        scan_id="s",
        engine="syft",
    )
    assert identity.rule == "hash"


def test_rule_6_name_always_carries_the_ecosystem() -> None:
    """⚠ THE SINGLE MOST COMMON DEDUP BUG IN SBOM TOOLING."""
    npm = resolve(
        target(name="lodash", version="4.17.21", ecosystem="npm"), scan_id="s", engine="x"
    )
    maven = resolve(
        target(name="lodash", version="4.17.21", ecosystem="maven"), scan_id="s", engine="x"
    )
    assert npm.rule == "name"
    assert npm.key != maven.key
    assert "npm/" in npm.key
    assert "maven/" in maven.key


def test_rule_7_opaque_is_deterministic_and_never_merges() -> None:
    """uuid5, not uuid4: normalization must replay identically (ADR-0003)."""
    raw = target(some="unrecognisable")
    a = resolve(raw, scan_id="scan-1", engine="mystery")
    b = resolve(raw, scan_id="scan-1", engine="mystery")
    assert a.rule == "opaque"
    assert a.key == b.key, "opaque ids must be stable across runs"
    assert not a.mergeable

    other_scan = resolve(raw, scan_id="scan-2", engine="mystery")
    assert a.key != other_scan.key


def test_a_malformed_purl_falls_through_rather_than_failing() -> None:
    """Losing the component entirely is worse than a weaker identity."""
    identity = resolve(
        target(purl="::not a purl::", name="thing", version="1.0", ecosystem="npm"),
        scan_id="s",
        engine="x",
    )
    assert identity.rule == "name"


# -- never-merge assertions -----------------------------------------------


def test_name_version_across_ecosystems_never_merges() -> None:
    npm = Identity(
        key="name:npm/lodash@4",
        rule="name",
        confidence="low",
        ecosystem="npm",
        name="lodash",
        version_raw="4",
    )
    maven = Identity(
        key="name:maven/lodash@4",
        rule="name",
        confidence="low",
        ecosystem="maven",
        name="lodash",
        version_raw="4",
    )
    reason = never_merge_check(npm, maven)
    assert reason, "these must not merge"
    assert "ecosystem" in reason


def test_differing_version_raw_never_merges() -> None:
    """`v24.0.5+incompatible` is not `v24.0.5`; one of them was never published."""
    a = Identity(
        key="purl:pkg:golang/x@v24.0.5+incompatible",
        rule="purl",
        confidence="high",
        version_raw="v24.0.5+incompatible",
    )
    b = Identity(
        key="purl:pkg:golang/x@v24.0.5", rule="purl", confidence="high", version_raw="v24.0.5"
    )
    assert never_merge_check(a, b)


def test_opaque_never_merges_even_with_itself() -> None:
    a = Identity(key="opaque:1", rule="opaque", confidence="low")
    assert never_merge_check(a, a)


# -- hostile input --------------------------------------------------------


def test_nul_bytes_are_stripped_before_storage() -> None:
    """⚠ A NUL SILENTLY TRUNCATES a Postgres text value.

    The row inserts, nothing errors, and the stored path is a prefix of the
    real one. Sanitizing must happen BEFORE insert.
    """
    assert "\x00" not in normalize_path("src/\x00etc/passwd")


def test_control_characters_and_newlines_are_stripped() -> None:
    assert "\n" not in normalize_path("src/evil\nname.js")
    assert "\r" not in normalize_path("src/evil\rname.js")


def test_long_paths_are_truncated_visibly() -> None:
    """A silently shortened path looks like a real path to a different file."""
    result = normalize_path("a/" * 2000 + "file.js")
    assert len(result) <= 1024
    assert "truncated" in result


def test_backslashes_are_normalized_so_windows_paths_compare() -> None:
    assert normalize_path("src\\lib\\index.js") == "src/lib/index.js"


def test_go_version_v_prefix_is_normalized_so_engines_agree() -> None:
    """⚠ FOUND BY THE golang-incompatible FIXTURE, NOT BY READING THE SPEC.

    syft emits `v24.0.5+incompatible`; another engine emits
    `24.0.5+incompatible`. Same published module version — the `v` is part of
    Go's version grammar, not part of the number — but unnormalized they produce
    two components, and every vulnerability on that module is counted twice.
    """
    assert canonicalize("pkg:golang/github.com/docker/docker@24.0.5+incompatible") == (
        canonicalize("pkg:golang/github.com/docker/docker@v24.0.5+incompatible")
    )


def test_the_v_prefix_rule_does_not_touch_other_ecosystems() -> None:
    """npm versions have no `v` prefix; adding one would invent a version."""
    assert parse("pkg:npm/lodash@4.17.21").version == "4.17.21"
    assert parse("pkg:pypi/flask@2.3.2").version == "2.3.2"


def test_a_non_numeric_go_version_is_left_alone() -> None:
    """A commit sha or a branch name must not acquire a prefix it never had."""
    assert parse("pkg:golang/x/y@deadbeef").version == "deadbeef"
