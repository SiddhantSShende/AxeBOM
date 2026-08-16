"""PEP 440 ordering — PyPI.

PEP 440 is not semver and the differences bite:

  * **Epochs.** `1!1.0` beats `2.0`. An epoch exists precisely because a project
    changed its scheme, so ignoring it inverts the ordering it was added to fix.
  * **Post-releases are higher, dev-releases lower.** `1.0.post1 > 1.0 > 1.0.dev1`.
  * **`rc`, `c`, `pre`, `preview` all mean the same thing**, as do `a`/`alpha`
    and `b`/`beta`. Comparing the spellings as text orders `alpha` after `rc`.
  * **Trailing zeros do not count.** `1.0` == `1.0.0`.
"""

from __future__ import annotations

import re

_VERSION = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>\d+)!)?
    (?P<release>\d+(?:\.\d+)*)
    (?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>\d+)?)?
    (?:-(?P<post_n1>\d+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?)?
    (?:[-_.]?dev[-_.]?(?P<dev_n>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""",
    re.VERBOSE | re.IGNORECASE,
)

#: Spellings that mean the same phase. Without this, `1.0rc1` and `1.0c1` — the
#: same release — compare as different versions.
_PRE_ALIASES = {
    "alpha": "a",
    "a": "a",
    "beta": "b",
    "b": "b",
    "c": "rc",
    "pre": "rc",
    "preview": "rc",
    "rc": "rc",
}

_PHASE_RANK = {"dev": 0, "a": 1, "b": 2, "rc": 3, "final": 4, "post": 5}


def _parse(version: str) -> tuple:
    """Return a sortable key, or a fallback key for unparseable input."""
    match = _VERSION.match(version or "")
    if not match:
        # Unparseable versions sort below everything parseable and among
        # themselves by string. They are rare and usually a manifest typo;
        # ordering them arbitrarily beats crashing a whole normalization run,
        # and the alternative — treating them as equal — would merge them.
        return (-1, (), 0, 0, 0, version or "")

    epoch = int(match.group("epoch") or 0)

    release = tuple(int(p) for p in match.group("release").split("."))
    # Trailing zeros carry no meaning: 1.0 == 1.0.0.
    trimmed = list(release)
    while len(trimmed) > 1 and trimmed[-1] == 0:
        trimmed.pop()
    release = tuple(trimmed)

    pre_l = match.group("pre_l")
    post_l = match.group("post_l")
    post_n1 = match.group("post_n1")
    has_dev = ("dev" in (version or "").lower() and match.group("dev_n") is not None) or (
        re.search(r"[-_.]?dev", version or "", re.IGNORECASE) is not None
    )

    if has_dev and not pre_l and not post_l and post_n1 is None:
        phase = _PHASE_RANK["dev"]
        number = int(match.group("dev_n") or 0)
    elif pre_l:
        phase = _PHASE_RANK[_PRE_ALIASES.get(pre_l.lower(), "rc")]
        number = int(match.group("pre_n") or 0)
    elif post_l or post_n1 is not None:
        phase = _PHASE_RANK["post"]
        number = int(post_n1 or match.group("post_n2") or 0)
    else:
        phase = _PHASE_RANK["final"]
        number = 0

    # A dev suffix on a prerelease lowers it further: 1.0a1.dev1 < 1.0a1.
    dev_marker = 0 if (has_dev and (pre_l or post_l)) else 1

    # ⚠ The local version (+local) is NOT part of the public ordering. Two
    # wheels differing only in local segment are the same release.
    return (epoch, release, phase, number, dev_marker, "")


def compare_pep440(a: str, b: str) -> int:
    ka, kb = _parse(a), _parse(b)
    if ka == kb:
        return 0
    return -1 if ka < kb else 1
