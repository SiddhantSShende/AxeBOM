"""Version comparators, one ecosystem per section.

⚠ EVERY CASE HERE IS ONE A LEXICAL SORT GETS WRONG.

`fixed_in_min` is the version a remediation ticket quotes. Order it wrongly and
the product tells a customer to upgrade to something that does not contain the
fix, or reports them as patched when they are not.
"""

from __future__ import annotations

import pytest

from .versions import NoComparatorError, compare, has_comparator, minimum, sort_versions
from .versions.deb import compare_deb
from .versions.golang import compare_golang, strip_major_suffix
from .versions.maven import compare_maven
from .versions.pep440 import compare_pep440
from .versions.rpm import compare_rpm_evr, rpmvercmp
from .versions.semver import compare_semver


def lt(fn, a, b):
    assert fn(a, b) == -1, f"expected {a} < {b}, got {fn(a, b)}"
    assert fn(b, a) == 1, f"expected {b} > {a}, got {fn(b, a)}"


def eq(fn, a, b):
    assert fn(a, b) == 0, f"expected {a} == {b}, got {fn(a, b)}"
    assert fn(b, a) == 0


# -- semver ---------------------------------------------------------------


def test_semver_numeric_ordering_is_not_lexical() -> None:
    """The canonical trap: "1.10.0" sorts before "1.9.0" as a string."""
    lt(compare_semver, "1.9.0", "1.10.0")
    lt(compare_semver, "1.0.9", "1.0.10")
    lt(compare_semver, "2.0.0", "10.0.0")


def test_semver_prerelease_is_lower_than_its_release() -> None:
    """⚠ Backwards here means every rc looks like a valid fix for the final."""
    lt(compare_semver, "1.0.0-rc.1", "1.0.0")
    lt(compare_semver, "1.0.0-alpha", "1.0.0-beta")
    lt(compare_semver, "1.0.0-alpha", "1.0.0-alpha.1")


def test_semver_numeric_prerelease_ranks_below_alphanumeric() -> None:
    """semver §11.4 — reads oddly, but it is the specification."""
    lt(compare_semver, "1.0.0-1", "1.0.0-alpha")


def test_semver_build_metadata_is_ignored() -> None:
    """Two builds of one version are the same version; neither is newer."""
    eq(compare_semver, "1.0.0+build1", "1.0.0+build2")
    eq(compare_semver, "1.0.0", "1.0.0+anything")


def test_semver_missing_components_are_zero() -> None:
    eq(compare_semver, "1.2", "1.2.0")
    eq(compare_semver, "v1.2.0", "1.2.0")


# -- PEP 440 --------------------------------------------------------------


def test_pep440_epoch_dominates() -> None:
    """An epoch exists because a project changed scheme; ignoring it inverts
    the ordering it was introduced to fix."""
    lt(compare_pep440, "2.0", "1!1.0")


def test_pep440_post_is_higher_and_dev_is_lower() -> None:
    lt(compare_pep440, "1.0", "1.0.post1")
    lt(compare_pep440, "1.0.dev1", "1.0")


def test_pep440_prerelease_spellings_are_equivalent() -> None:
    """`rc`, `c`, `pre` and `preview` are one phase. Comparing the spellings as
    text puts `alpha` after `rc`."""
    eq(compare_pep440, "1.0rc1", "1.0c1")
    eq(compare_pep440, "1.0a1", "1.0alpha1")
    lt(compare_pep440, "1.0a1", "1.0b1")
    lt(compare_pep440, "1.0b1", "1.0rc1")
    lt(compare_pep440, "1.0rc1", "1.0")


def test_pep440_trailing_zeros_do_not_count() -> None:
    eq(compare_pep440, "1.0", "1.0.0")


def test_pep440_numeric_not_lexical() -> None:
    lt(compare_pep440, "1.9", "1.10")


# -- Maven ----------------------------------------------------------------


def test_maven_known_qualifiers_rank_below_the_release() -> None:
    lt(compare_maven, "1.0-alpha", "1.0-beta")
    lt(compare_maven, "1.0-beta", "1.0-milestone")
    lt(compare_maven, "1.0-milestone", "1.0-rc")
    lt(compare_maven, "1.0-rc", "1.0-snapshot")
    lt(compare_maven, "1.0-snapshot", "1.0")


def test_maven_service_pack_is_higher_than_the_release() -> None:
    """`sp` is the one qualifier that outranks the plain release."""
    lt(compare_maven, "1.0", "1.0-sp")


def test_maven_unknown_qualifier_outranks_every_known_one() -> None:
    lt(compare_maven, "1.0-sp", "1.0-zulu")


def test_maven_null_padding_makes_trailing_zeros_equal() -> None:
    eq(compare_maven, "1.0", "1")
    eq(compare_maven, "1.0.0", "1.0")


def test_maven_numeric_not_lexical() -> None:
    lt(compare_maven, "1.9", "1.10")
    lt(compare_maven, "1.0.9", "1.0.10")


# -- Go -------------------------------------------------------------------


def test_golang_incompatible_is_not_metadata() -> None:
    """⚠ +incompatible is part of the version.

    Stripping it makes `v24.0.5+incompatible` equal to `v24.0.5`, a version that
    was never published for that module.
    """
    assert compare_golang("v24.0.5+incompatible", "v24.0.5") != 0


def test_golang_pseudo_versions_order_by_timestamp() -> None:
    lt(
        compare_golang,
        "v0.0.0-20191109021931-daa7c04131f5",
        "v0.0.0-20200109021931-daa7c04131f5",
    )


def test_golang_pseudo_version_is_below_a_real_release() -> None:
    lt(compare_golang, "v0.0.0-20191109021931-daa7c04131f5", "v1.0.0")


def test_golang_major_suffix_is_not_stripped_for_identity() -> None:
    """`/v3` is part of the module path — a different module, not a version."""
    assert strip_major_suffix("github.com/Masterminds/semver/v3") == (
        "github.com/Masterminds/semver"
    )
    # And the helper leaves a non-suffix path alone.
    assert strip_major_suffix("gopkg.in/yaml.v3") == "gopkg.in/yaml.v3"


# -- rpm ------------------------------------------------------------------


def test_rpm_tilde_sorts_before_everything() -> None:
    """⚠ Reversed, every release candidate outranks its release."""
    lt(rpmvercmp, "1.0~rc1", "1.0")
    lt(compare_rpm_evr, "1.0~rc1-1", "1.0-1")


def test_rpm_caret_sorts_after() -> None:
    lt(rpmvercmp, "1.0", "1.0^git1")


def test_rpm_epoch_dominates() -> None:
    lt(compare_rpm_evr, "2.0-1", "1:1.0-1")


def test_rpm_digits_outrank_letters() -> None:
    lt(rpmvercmp, "1.0a", "1.0.1")


def test_rpm_leading_zeros_are_insignificant() -> None:
    eq(rpmvercmp, "1.007", "1.7")


def test_rpm_release_breaks_a_version_tie() -> None:
    lt(compare_rpm_evr, "1.0-1", "1.0-2")


# -- deb ------------------------------------------------------------------


def test_deb_tilde_sorts_before_the_release() -> None:
    lt(compare_deb, "1.0~beta1", "1.0")


def test_deb_epoch_dominates() -> None:
    lt(compare_deb, "2.0", "1:1.0")


def test_deb_revision_breaks_a_tie() -> None:
    lt(compare_deb, "1.0-1", "1.0-2")


def test_deb_numeric_not_lexical() -> None:
    lt(compare_deb, "1.9", "1.10")


# -- the dispatcher -------------------------------------------------------


def test_minimum_picks_the_earliest_fix_not_the_first_string() -> None:
    """`fixed_in_min` is what a remediation ticket quotes."""
    assert minimum("npm", ["1.10.0", "1.9.0", "2.0.0"]) == "1.9.0"
    assert minimum("pypi", ["1.10", "1.9", "2.0"]) == "1.9"
    assert minimum("maven", ["1.10.0", "1.9.0"]) == "1.9.0"


def test_sort_is_ascending_by_ecosystem_rules() -> None:
    assert sort_versions("npm", ["2.0.0", "1.0.0-rc.1", "1.0.0"]) == [
        "1.0.0-rc.1",
        "1.0.0",
        "2.0.0",
    ]


def test_an_ecosystem_with_no_comparator_raises_rather_than_guessing() -> None:
    """⚠ THE POINT OF THE WHOLE MODULE.

    A guessed ordering is worse than an admitted gap, because the customer
    cannot tell it was guessed. The caller sets `fix_version_ordering` to
    `unknown` and emits NORMALIZE_NO_VERSION_COMPARATOR.
    """
    assert not has_comparator("conan")
    with pytest.raises(NoComparatorError):
        compare("conan", "1.0", "2.0")
    with pytest.raises(NoComparatorError):
        minimum("conan", ["1.0", "2.0"])


def test_every_ecosystem_the_spec_names_has_a_comparator() -> None:
    for ecosystem in ("npm", "cargo", "pypi", "maven", "golang", "rpm", "deb"):
        assert has_comparator(ecosystem), f"{ecosystem} has no comparator"


def test_comparators_are_total_orders() -> None:
    """Antisymmetry and reflexivity.

    A comparator that is not a total order makes `sorted()` output depend on
    input order, which makes normalization non-deterministic and flaps every
    golden test built on it.
    """
    samples = {
        "npm": ["1.0.0", "1.0.0-rc.1", "2.0.0", "1.10.0", "1.9.0"],
        "pypi": ["1.0", "1.0.post1", "1.0.dev1", "1!1.0", "1.0rc1"],
        "maven": ["1.0", "1.0-sp", "1.0-alpha", "1.0-zulu", "1"],
        "golang": ["v1.0.0", "v24.0.5+incompatible", "v0.0.0-20191109021931-daa7c04131f5"],
        "rpm": ["1.0-1", "1.0~rc1-1", "1:1.0-1", "1.0^git1-1"],
        "deb": ["1.0", "1.0~beta1", "1:1.0", "1.0-2"],
    }
    for ecosystem, versions in samples.items():
        for a in versions:
            assert compare(ecosystem, a, a) == 0, f"{ecosystem}: {a} != itself"
            for b in versions:
                forward, backward = compare(ecosystem, a, b), compare(ecosystem, b, a)
                assert forward == -backward, f"{ecosystem}: {a} vs {b} is not antisymmetric"
