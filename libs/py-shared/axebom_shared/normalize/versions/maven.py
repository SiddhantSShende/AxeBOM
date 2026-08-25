"""Maven version ordering — `ComparableVersion` semantics.

Maven's ordering is its own thing and two rules surprise people:

  * **Known qualifiers rank BELOW the release.** `1.0-alpha < 1.0-beta <
    1.0-milestone < 1.0-rc < 1.0-snapshot < 1.0 < 1.0-sp`. Note `sp` (service
    pack) is *higher* than the plain release.
  * **An unknown qualifier ranks ABOVE every known one**, and compares
    lexically. `1.0-zulu > 1.0-sp`.

And the null-padding rule: `1.0` == `1` == `1.0.0`, because trailing zero or
empty components are removed before comparison.
"""

from __future__ import annotations

import re

#: Rank of the known qualifiers. "" is the release itself.
#:
#: `snapshot` sits below the release: a snapshot is pre-release by definition,
#: so a fix "in 1.0" is not delivered by 1.0-SNAPSHOT.
_QUALIFIERS = {
    "alpha": -6,
    "a": -6,
    "beta": -5,
    "b": -5,
    "milestone": -4,
    "m": -4,
    "rc": -3,
    "cr": -3,
    "snapshot": -2,
    "": -1,
    "ga": -1,
    "final": -1,
    "release": -1,
    "sp": 0,
}

_NUMERIC = re.compile(r"^\d+$")


def _tokenize(version: str) -> list[tuple[int, object]]:
    """Split into comparable tokens.

    Each token is `(kind, value)` where kind 0 is numeric and kind 1 is a
    qualifier, so numeric and qualifier tokens never compare as raw strings.
    """
    text = (version or "").strip().lower()
    # Both separators are transitions; `1.0-1` and `1.0.1` tokenize alike, which
    # is what Maven does.
    parts = re.split(r"[-_.]+", text)

    tokens: list[tuple[int, object]] = []
    for part in parts:
        if not part:
            continue
        for chunk in re.findall(r"\d+|[a-z]+", part):
            if _NUMERIC.match(chunk):
                tokens.append((0, int(chunk)))
            else:
                tokens.append((1, chunk))

    # Trailing "null" values — numeric zeros and release-equivalent qualifiers —
    # carry no meaning, so 1.0.0 == 1.0 == 1.
    while tokens:
        kind, value = tokens[-1]
        if kind == 0 and value == 0:
            tokens.pop()
        elif kind == 1 and _QUALIFIERS.get(str(value)) == -1:
            tokens.pop()
        else:
            break

    return tokens


def _rank(token: tuple[int, object]) -> tuple[int, int, str]:
    """Map a token to a totally-ordered key."""
    kind, value = token
    if kind == 0:
        # Numeric tokens outrank every qualifier.
        return (1, int(value), "")
    text = str(value)
    known = _QUALIFIERS.get(text)
    if known is not None:
        return (0, known, "")
    # ⚠ An UNKNOWN qualifier ranks above all known ones and compares lexically.
    return (0, 1, text)


def compare_maven(a: str, b: str) -> int:
    ta, tb = _tokenize(a), _tokenize(b)

    for x, y in zip(ta, tb, strict=False):
        rx, ry = _rank(x), _rank(y)
        if rx != ry:
            return -1 if rx < ry else 1

    if len(ta) == len(tb):
        return 0

    # The shorter version is padded with the release-level "null", so the extra
    # tokens are compared against nothing: extra qualifier tokens make a version
    # LOWER while extra numeric tokens make it higher.
    #
    #     1.0-alpha  <  1.0  <  1.0.1
    #
    # ⚠ A numeric 0 and a release-equivalent qualifier are EQUAL to null, not
    # greater than it, and the loop must keep going past them. That is what
    # makes `1.0-snapshot` (tokens [1, 0, snapshot]) compare below `1.0`
    # (tokens [1]): the extra 0 is a tie, and `snapshot` breaks it downward.
    shorter_is_a = len(ta) < len(tb)
    longer = tb if shorter_is_a else ta
    for token in longer[min(len(ta), len(tb)) :]:
        against_null = _compare_to_null(token)
        if against_null == 0:
            continue
        return -against_null if shorter_is_a else against_null
    return 0


def _compare_to_null(token: tuple[int, object]) -> int:
    """Compare one token against an absent token. Returns -1, 0 or 1."""
    kind, value = token
    if kind == 0:
        # Numeric: 0 is the null value, anything else outranks it.
        return 0 if int(value) == 0 else 1
    known = _QUALIFIERS.get(str(value))
    if known is None:
        # An unknown qualifier outranks every known one, including the release.
        return 1
    if known == -1:
        # `ga`, `final`, `release` and "" ARE the release — equal to null.
        return 0
    return -1 if known < -1 else 1
