"""Ecosystem-correct version comparators.

⚠ NAIVE STRING SORT IS WRONG FOR EVERY ECOSYSTEM HERE.

`"1.10.0" < "1.9.0"` lexically, so a string sort reports the *lowest* fix for
CVE-X as 1.10.0 when it is really 1.9.0 — telling a customer to upgrade to a
version that does not fix their problem, or that they are already patched when
they are not.

Each ecosystem has a published ordering and they genuinely differ:

    npm, cargo   semver, with prerelease ordering
    pypi         PEP 440, with epochs and post/dev releases
    maven        Maven's own tokenizer, where "1.0" == "1.0.0"
    rpm          EVR, with rpmvercmp's tilde and caret rules
    deb          Debian order, where "~" sorts BEFORE everything
    golang       semver plus +incompatible

⚠ WHERE NO COMPARATOR EXISTS, THE ANSWER IS `unknown` — NEVER A GUESS.

`compare()` raises `NoComparatorError`, the caller sets
`fix_version_ordering = 'unknown'` and emits `NORMALIZE_NO_VERSION_COMPARATOR`,
and `patch_status` derives to `unknown`. A fabricated ordering is worse than an
admitted gap: the customer cannot tell it is fabricated.

See `docs/03-NORMALIZER-SPEC.md` §2.5.
"""

from __future__ import annotations

from collections.abc import Iterable

from .deb import compare_deb
from .golang import compare_golang
from .maven import compare_maven
from .pep440 import compare_pep440
from .rpm import compare_rpm_evr
from .semver import compare_semver


class NoComparatorError(LookupError):
    """No ordering is defined for this ecosystem.

    An exception rather than a fallback, because every fallback available here
    is wrong: lexical order is wrong for all six ecosystems above, and "assume
    they are equal" silently merges distinct versions.
    """


#: The comparator table. Ecosystem names match `purl.Purl.ecosystem`.
COMPARATORS = {
    "npm": compare_semver,
    "cargo": compare_semver,
    "hex": compare_semver,
    "pypi": compare_pep440,
    "maven": compare_maven,
    "golang": compare_golang,
    "rpm": compare_rpm_evr,
    "deb": compare_deb,
}


def compare(ecosystem: str, a: str, b: str) -> int:
    """Return -1, 0 or 1 for a<b, a==b, a>b within `ecosystem`."""
    comparator = COMPARATORS.get((ecosystem or "").lower())
    if comparator is None:
        raise NoComparatorError(ecosystem or "<unknown>")
    return comparator(a, b)


def has_comparator(ecosystem: str) -> bool:
    return (ecosystem or "").lower() in COMPARATORS


def minimum(ecosystem: str, versions: Iterable[str]) -> str:
    """The lowest version — i.e. the earliest release that carries the fix.

    This is `fixed_in_min`, and it is the number a remediation ticket quotes, so
    "lowest" has to mean lowest by the ecosystem's own ordering.
    """
    candidates = [v for v in versions if isinstance(v, str) and v.strip()]
    if not candidates:
        return ""
    comparator = COMPARATORS.get((ecosystem or "").lower())
    if comparator is None:
        raise NoComparatorError(ecosystem or "<unknown>")

    best = candidates[0]
    for candidate in candidates[1:]:
        if comparator(candidate, best) < 0:
            best = candidate
    return best


def sort_versions(ecosystem: str, versions: Iterable[str]) -> list[str]:
    """Ascending, by the ecosystem's ordering."""
    import functools

    comparator = COMPARATORS.get((ecosystem or "").lower())
    if comparator is None:
        raise NoComparatorError(ecosystem or "<unknown>")
    return sorted(versions, key=functools.cmp_to_key(comparator))


__all__ = [
    "COMPARATORS",
    "NoComparatorError",
    "compare",
    "compare_deb",
    "compare_golang",
    "compare_maven",
    "compare_pep440",
    "compare_rpm_evr",
    "compare_semver",
    "has_comparator",
    "minimum",
    "sort_versions",
]
