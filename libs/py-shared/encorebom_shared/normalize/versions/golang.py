"""Go module version ordering — semver plus the Go-specific suffixes.

Two things semver alone gets wrong for Go:

  * **`+incompatible` is part of the version, not metadata to strip.** It marks
    a v2+ module without a `/vN` path suffix. Plain semver discards everything
    after `+`, which would make `v24.0.5+incompatible` and `v24.0.5` the same
    version — and `v24.0.5` alone was never published.
  * **Pseudo-versions** (`v0.0.0-20191109021931-daa7c04131f5`) encode a
    timestamp in the prerelease, so they order by that timestamp. Semver's
    prerelease rules already handle this correctly *provided* the string is not
    mangled first.
"""

from __future__ import annotations

from .semver import compare_semver

INCOMPATIBLE = "+incompatible"


def compare_golang(a: str, b: str) -> int:
    """Compare two Go module versions."""
    a_text, a_incompatible = _split_incompatible(a)
    b_text, b_incompatible = _split_incompatible(b)

    result = compare_semver(a_text, b_text)
    if result != 0:
        return result

    # ⚠ Same numeric version, one +incompatible: they are NOT equal.
    #
    # They are different published artifacts, and reporting them equal would
    # merge two components (or accept the wrong one as a fix). The plain form
    # sorts lower — arbitrary, but the ordering only has to be total and
    # deterministic; what matters is that it is not zero.
    if a_incompatible != b_incompatible:
        return 1 if a_incompatible else -1
    return 0


def _split_incompatible(version: str) -> tuple[str, bool]:
    text = (version or "").strip()
    if text.lower().endswith(INCOMPATIBLE):
        return text[: -len(INCOMPATIBLE)], True
    return text, False


def strip_major_suffix(module_path: str) -> str:
    """Remove a trailing `/v2`, `/v3`… from a module path.

    ⚠ USE WITH CARE — NOT FOR IDENTITY.

    `github.com/Masterminds/semver/v3` and `github.com/Masterminds/semver` are
    DIFFERENT MODULES that can both appear in one build. This helper exists for
    display grouping only; the merge key always uses the full path.
    """
    parts = module_path.rsplit("/", 1)
    if len(parts) == 2 and len(parts[1]) > 1 and parts[1][0] == "v" and parts[1][1:].isdigit():
        return parts[0]
    return module_path
