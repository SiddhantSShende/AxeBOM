"""RPM EVR ordering — `rpmvercmp` semantics.

EVR is epoch:version-release, and each part compares by the same algorithm.

  * **A missing epoch is 0**, and epoch dominates everything. `1:1.0` > `2.0`.
  * **`~` sorts BEFORE everything, including the empty string.** It exists for
    prereleases: `1.0~rc1 < 1.0`. Get this wrong and every release candidate
    outranks its release.
  * **`^` sorts AFTER the empty string** — the inverse, for post-release
    snapshots: `1.0 < 1.0^git1`.
  * Digits outrank letters, and comparison runs segment by segment, where a
    segment is a run of digits or a run of letters.
"""

from __future__ import annotations

import re

_ALNUM = re.compile(r"[a-zA-Z]+|[0-9]+")


def compare_rpm_evr(a: str, b: str) -> int:
    """Compare two full EVR strings."""
    ea, va, ra = _split_evr(a)
    eb, vb, rb = _split_evr(b)

    if ea != eb:
        return -1 if ea < eb else 1

    result = rpmvercmp(va, vb)
    if result != 0:
        return result

    return rpmvercmp(ra, rb)


def _split_evr(evr: str) -> tuple[int, str, str]:
    text = (evr or "").strip()

    epoch = 0
    if ":" in text:
        head, _, text = text.partition(":")
        try:
            epoch = int(head)
        except ValueError:
            # A non-numeric epoch is malformed. Treated as 0 rather than
            # raising: the version and release still order correctly, and
            # losing the whole comparison over a malformed epoch would send the
            # finding to `unknown` for no benefit.
            epoch = 0

    release = ""
    if "-" in text:
        text, _, release = text.rpartition("-")

    return epoch, text, release


def rpmvercmp(a: str, b: str) -> int:
    """The rpm version comparison algorithm.

    Ported deliberately rather than approximated — the tilde and caret rules
    have no equivalent in any other scheme, and an approximation gets
    prereleases backwards.
    """
    a = a or ""
    b = b or ""
    if a == b:
        return 0

    i = j = 0
    while i < len(a) or j < len(b):
        # ── tilde: sorts before everything ──
        a_tilde = i < len(a) and a[i] == "~"
        b_tilde = j < len(b) and b[j] == "~"
        if a_tilde or b_tilde:
            if not a_tilde:
                return 1
            if not b_tilde:
                return -1
            i += 1
            j += 1
            continue

        # ── caret: sorts after the empty string, before a longer version ──
        a_caret = i < len(a) and a[i] == "^"
        b_caret = j < len(b) and b[j] == "^"
        if a_caret or b_caret:
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if not a_caret:
                return 1
            if not b_caret:
                return -1
            i += 1
            j += 1
            continue

        while i < len(a) and not a[i].isalnum():
            i += 1
        while j < len(b) and not b[j].isalnum():
            j += 1

        if i >= len(a) or j >= len(b):
            break

        a_match = _ALNUM.match(a, i)
        b_match = _ALNUM.match(b, j)
        if a_match is None or b_match is None:
            break

        a_seg, b_seg = a_match.group(0), b_match.group(0)
        a_numeric, b_numeric = a_seg[0].isdigit(), b_seg[0].isdigit()

        # ⚠ A numeric segment always outranks an alphabetic one.
        if a_numeric != b_numeric:
            return 1 if a_numeric else -1

        if a_numeric:
            a_val, b_val = a_seg.lstrip("0") or "0", b_seg.lstrip("0") or "0"
            if len(a_val) != len(b_val):
                return -1 if len(a_val) < len(b_val) else 1
            if a_val != b_val:
                return -1 if a_val < b_val else 1
        elif a_seg != b_seg:
            return -1 if a_seg < b_seg else 1

        i = a_match.end()
        j = b_match.end()

    a_left = i < len(a)
    b_left = j < len(b)
    if a_left == b_left:
        return 0
    return 1 if a_left else -1
