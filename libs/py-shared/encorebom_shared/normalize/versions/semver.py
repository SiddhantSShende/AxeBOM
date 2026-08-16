"""Semantic Versioning 2.0.0 ordering — npm, cargo, hex.

The two rules that a hand-rolled comparison usually gets wrong:

  * **A prerelease sorts BEFORE its release.** `1.0.0-rc.1 < 1.0.0`. Get this
    backwards and every release candidate looks like a valid fix for a
    vulnerability fixed in the final.
  * **Build metadata is ignored entirely.** `1.0.0+build1` and `1.0.0+build2`
    are the same version, so neither is "newer".
"""

from __future__ import annotations

import re

_NUMERIC = re.compile(r"^\d+$")
_LEADING = re.compile(r"^[vV=\s]+")


def _split(version: str) -> tuple[list[int], list[str]]:
    """Split into (release numbers, prerelease identifiers)."""
    text = _LEADING.sub("", (version or "").strip())

    # Build metadata carries no ordering, so it is discarded before anything
    # else — comparing it would invent a difference between equal versions.
    text = text.split("+", 1)[0]

    prerelease: list[str] = []
    if "-" in text:
        text, _, pre = text.partition("-")
        prerelease = [p for p in pre.split(".") if p]

    numbers: list[int] = []
    for part in text.split("."):
        if _NUMERIC.match(part):
            numbers.append(int(part))
        else:
            # A non-numeric core segment (`1.0.x`, `2.0.Final`) is not strict
            # semver. Take the leading digits and treat the rest as prerelease
            # rather than raising: real lockfiles contain these, and refusing
            # would lose an otherwise-usable comparison.
            leading = re.match(r"^(\d+)(.*)$", part)
            if leading:
                numbers.append(int(leading.group(1)))
                if leading.group(2):
                    prerelease.insert(0, leading.group(2).lstrip(".-"))
            else:
                prerelease.insert(0, part)
            break

    while len(numbers) < 3:
        numbers.append(0)

    return numbers, prerelease


def compare_semver(a: str, b: str) -> int:
    """Compare two semver strings. Returns -1, 0 or 1."""
    a_nums, a_pre = _split(a)
    b_nums, b_pre = _split(b)

    for x, y in zip(a_nums, b_nums, strict=False):
        if x != y:
            return -1 if x < y else 1
    if len(a_nums) != len(b_nums):
        # Missing components are zero, so `1.2` == `1.2.0`.
        longer, shorter = (a_nums, b_nums) if len(a_nums) > len(b_nums) else (b_nums, a_nums)
        for extra in longer[len(shorter) :]:
            if extra != 0:
                return -1 if longer is b_nums else 1

    # ⚠ A version WITH a prerelease is LOWER than the same version without one.
    if a_pre and not b_pre:
        return -1
    if b_pre and not a_pre:
        return 1
    if not a_pre and not b_pre:
        return 0

    return _compare_prerelease(a_pre, b_pre)


def _compare_prerelease(a: list[str], b: list[str]) -> int:
    """Compare prerelease identifier lists, per semver §11.4.

    Numeric identifiers compare numerically and always rank LOWER than
    alphanumeric ones — so `1.0.0-1 < 1.0.0-alpha`, which reads oddly but is the
    specified behaviour.
    """
    for x, y in zip(a, b, strict=False):
        x_num, y_num = _NUMERIC.match(x), _NUMERIC.match(y)
        if x_num and y_num:
            xi, yi = int(x), int(y)
            if xi != yi:
                return -1 if xi < yi else 1
        elif x_num:
            return -1
        elif y_num:
            return 1
        elif x != y:
            return -1 if x < y else 1

    # A longer identifier list is higher, all else equal: `1.0.0-alpha` <
    # `1.0.0-alpha.1`.
    if len(a) != len(b):
        return -1 if len(a) < len(b) else 1
    return 0
