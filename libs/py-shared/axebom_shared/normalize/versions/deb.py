"""Debian version ordering — `dpkg --compare-versions` semantics.

Format: `[epoch:]upstream[-revision]`.

The rule that has no analogue elsewhere:

  * **`~` sorts before everything, including the end of string.** So
    `1.0~beta1 < 1.0`. This is how Debian expresses a prerelease, and reversing
    it makes every beta outrank its release.

And the letter-ordering rule that catches ports of this algorithm:

  * **All letters sort before all non-letters.** `1.0a < 1.0+` — because in
    dpkg's ordering a letter's value is its ordinal, while a non-letter's is its
    ordinal plus 256.
"""

from __future__ import annotations


def compare_deb(a: str, b: str) -> int:
    """Compare two Debian version strings."""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)

    if ea != eb:
        return -1 if ea < eb else 1

    result = _compare_part(ua, ub)
    if result != 0:
        return result

    return _compare_part(ra, rb)


def _split(version: str) -> tuple[int, str, str]:
    text = (version or "").strip()

    epoch = 0
    if ":" in text:
        head, _, text = text.partition(":")
        try:
            epoch = int(head)
        except ValueError:
            epoch = 0

    revision = ""
    if "-" in text:
        text, _, revision = text.rpartition("-")

    return epoch, text, revision


def _order(char: str) -> int:
    """dpkg's character ordering.

    ⚠ `~` is NEGATIVE so that it sorts before the empty string, which is the
    whole point of the character.
    """
    if char == "~":
        return -1
    if char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _compare_part(a: str, b: str) -> int:
    """Compare one upstream-or-revision part."""
    a = a or ""
    b = b or ""
    i = j = 0

    while i < len(a) or j < len(b):
        # Non-digit run, compared by dpkg's character order.
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                first_diff = -1 if ac < bc else 1
                return first_diff
            i += 1
            j += 1
        if first_diff:
            return first_diff

        # Digit run, compared numerically. Leading zeros are insignificant.
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1

        digits = 0
        while i < len(a) and j < len(b) and a[i].isdigit() and b[j].isdigit():
            if digits == 0:
                if a[i] != b[j]:
                    digits = -1 if a[i] < b[j] else 1
            i += 1
            j += 1

        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if digits:
            return digits

    return 0
