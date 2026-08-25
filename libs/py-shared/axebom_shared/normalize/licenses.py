"""License resolution — SPDX ids, expressions, and the things not to decide.

⚠ THE CENTRAL RULE: SOME AMBIGUITY IS NOT OURS TO RESOLVE.

`GPL-2.0` was deprecated because it does not say whether the "or later" clause
applies. `GPL-2.0-only` and `GPL-2.0-or-later` have materially different
obligations, and the guideline gives no way to choose between them. So the
normalizer FLAGS it and moves on.

Choosing wrong here is a legal error, not a data-quality error. A wrong license
in a compliance artifact is the kind of mistake that ends up in front of
counsel, and "the tool picked one" is not a defence.

Three more distinctions this module refuses to collapse:

  * **`NONE` and `NOASSERTION` are different, both valid, neither is an error.**
    `NONE` means "we looked, there is no license" — a substantive assertion that
    COUNTS AS PRESENT for coverage. `NOASSERTION` means "we are not saying" and
    counts as absent. Coercing either to null loses the distinction the whole
    coverage number rests on.

  * **`declared`, `concluded` and `observed` stay separate.** SPDX requires it
    and reviewers ask for it. `concluded` never overwrites `declared`.

  * **`A OR B` is not flattened.** Which disjunct applies is a policy decision
    for a later, configurable layer. Store the expression.

See `docs/03-NORMALIZER-SPEC.md` §3.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: The SPDX license list this normalizer validates against.
#:
#: ⚠ RECORDED IN EVERY REPORT (`bom_documents.spdx_license_list_version`). Ids
#: are added and deprecated over time, so "is this a valid SPDX id?" has no
#: answer without saying which list was used.
SPDX_LICENSE_LIST_VERSION = "3.25"

#: SPDX's two special values. Neither is an error and neither is null.
NONE = "NONE"
NOASSERTION = "NOASSERTION"

#: ⚠ Deprecated ids whose meaning is genuinely ambiguous.
#:
#: Each maps to the pair of ids it could mean. The normalizer records the raw
#: value, sets `license_ambiguous`, and surfaces both candidates. It does NOT
#: pick one.
AMBIGUOUS_DEPRECATED = {
    "GPL-1.0": ("GPL-1.0-only", "GPL-1.0-or-later"),
    "GPL-2.0": ("GPL-2.0-only", "GPL-2.0-or-later"),
    "GPL-3.0": ("GPL-3.0-only", "GPL-3.0-or-later"),
    "LGPL-2.0": ("LGPL-2.0-only", "LGPL-2.0-or-later"),
    "LGPL-2.1": ("LGPL-2.1-only", "LGPL-2.1-or-later"),
    "LGPL-3.0": ("LGPL-3.0-only", "LGPL-3.0-or-later"),
    "AGPL-1.0": ("AGPL-1.0-only", "AGPL-1.0-or-later"),
    "AGPL-3.0": ("AGPL-3.0-only", "AGPL-3.0-or-later"),
    "GFDL-1.1": ("GFDL-1.1-only", "GFDL-1.1-or-later"),
    "GFDL-1.2": ("GFDL-1.2-only", "GFDL-1.2-or-later"),
    "GFDL-1.3": ("GFDL-1.3-only", "GFDL-1.3-or-later"),
}

#: Deprecated ids with an UNAMBIGUOUS replacement. Safe to rewrite, because
#: there is exactly one thing they can mean.
DEPRECATED_UNAMBIGUOUS = {
    "GPL-2.0+": "GPL-2.0-or-later",
    "GPL-3.0+": "GPL-3.0-or-later",
    "LGPL-2.1+": "LGPL-2.1-or-later",
    "LGPL-3.0+": "LGPL-3.0-or-later",
    "AGPL-3.0+": "AGPL-3.0-or-later",
    "GPL-2.0-with-classpath-exception": "GPL-2.0-only WITH Classpath-exception-2.0",
    "GPL-2.0-with-autoconf-exception": "GPL-2.0-only WITH Autoconf-exception-2.0",
    "GPL-2.0-with-bison-exception": "GPL-2.0-only WITH Bison-exception-2.2",
    "GPL-2.0-with-font-exception": "GPL-2.0-only WITH Font-exception-2.0",
    "GPL-2.0-with-GCC-exception": "GPL-2.0-only WITH GCC-exception-2.0",
    "wxWindows": "wxWindows-exception-3.1",
    "Nunit": "NUnit",
    "eCos-2.0": "eCos-2.0",
    "StandardML-NJ": "SMLNJ",
    "BSD-2-Clause-FreeBSD": "BSD-2-Clause-Views",
    "BSD-2-Clause-NetBSD": "BSD-2-Clause",
    "bzip2-1.0.5": "bzip2-1.0.6",
    "Net-SNMP": "Net-SNMP",
}

#: The curated alias table: how licenses are actually spelled in the wild.
#:
#: Keys are pre-normalized by `_fold` (lowercase, punctuation and whitespace
#: stripped), so one entry covers "Apache 2.0", "Apache-2.0", "APACHE 2" and
#: "apache_2.0".
_ALIASES_RAW = {
    # Apache
    "apache2": "Apache-2.0",
    "apache20": "Apache-2.0",
    "apachelicense20": "Apache-2.0",
    "apachelicenseversion20": "Apache-2.0",
    "asl20": "Apache-2.0",
    "asl2": "Apache-2.0",
    "theapachesoftwarelicenseversion20": "Apache-2.0",
    "apachesoftwarelicense": "Apache-2.0",
    # MIT
    "mit": "MIT",
    "mitlicense": "MIT",
    "theexpatlicense": "MIT",
    "expat": "MIT",
    # BSD
    "bsd": "BSD-3-Clause",
    "bsd3": "BSD-3-Clause",
    "bsd3clause": "BSD-3-Clause",
    "newbsd": "BSD-3-Clause",
    "modifiedbsd": "BSD-3-Clause",
    "bsd2": "BSD-2-Clause",
    "bsd2clause": "BSD-2-Clause",
    "simplifiedbsd": "BSD-2-Clause",
    "freebsd": "BSD-2-Clause-Views",
    # GPL family — these fold to the AMBIGUOUS ids on purpose, so the
    # ambiguity check downstream still fires.
    "gpl2": "GPL-2.0",
    "gplv2": "GPL-2.0",
    "gnugeneralpubliclicenseversion2": "GPL-2.0",
    "gpl3": "GPL-3.0",
    "gplv3": "GPL-3.0",
    "gnugeneralpubliclicenseversion3": "GPL-3.0",
    "lgpl21": "LGPL-2.1",
    "lgplv21": "LGPL-2.1",
    "lgpl3": "LGPL-3.0",
    "lgplv3": "LGPL-3.0",
    "agpl3": "AGPL-3.0",
    "agplv3": "AGPL-3.0",
    # Mozilla / Eclipse / others
    "mpl20": "MPL-2.0",
    "mpl2": "MPL-2.0",
    "mozillapubliclicense20": "MPL-2.0",
    "epl10": "EPL-1.0",
    "epl20": "EPL-2.0",
    "eclipsepubliclicense20": "EPL-2.0",
    "isc": "ISC",
    "unlicense": "Unlicense",
    "publicdomain": "Unlicense",
    "wtfpl": "WTFPL",
    "zlib": "Zlib",
    "artistic20": "Artistic-2.0",
    "cddl10": "CDDL-1.0",
    "cddl11": "CDDL-1.1",
    "cc0": "CC0-1.0",
    "cc010": "CC0-1.0",
    "ccby40": "CC-BY-4.0",
    "ccbysa40": "CC-BY-SA-4.0",
    "python20": "Python-2.0",
    "psf": "Python-2.0",
    "psfl": "Python-2.0",
    "ruby": "Ruby",
    "openssl": "OpenSSL",
    "boostsoftwarelicense10": "BSL-1.0",
    "bsl10": "BSL-1.0",
}

#: SPDX ids we accept verbatim. Not the full list — that is reference data —
#: but enough that the common cases never fall through to LicenseRef.
_KNOWN_IDS = {
    "Apache-2.0",
    "MIT",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSD-2-Clause-Views",
    "ISC",
    "MPL-2.0",
    "EPL-1.0",
    "EPL-2.0",
    "Unlicense",
    "WTFPL",
    "Zlib",
    "Artistic-2.0",
    "CDDL-1.0",
    "CDDL-1.1",
    "CC0-1.0",
    "CC-BY-4.0",
    "CC-BY-SA-4.0",
    "Python-2.0",
    "Ruby",
    "OpenSSL",
    "BSL-1.0",
    "NUnit",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "LGPL-2.0-only",
    "LGPL-2.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "GPL-1.0-only",
    "GPL-1.0-or-later",
    "AGPL-1.0-only",
    "AGPL-1.0-or-later",
    "SMLNJ",
    "bzip2-1.0.6",
    "Net-SNMP",
    "eCos-2.0",
}

_FOLD = re.compile(r"[^a-z0-9]+")
_SLUG = re.compile(r"[^A-Za-z0-9.\-]+")
_OPERATORS = {"AND", "OR", "WITH"}
_TOKEN = re.compile(r"\(|\)|[^\s()]+")


@dataclass
class Resolution:
    """The outcome of resolving one license string."""

    #: The SPDX expression, or NONE / NOASSERTION / a LicenseRef.
    value: str
    #: Which pipeline stage produced it — recorded as `license_rule`.
    rule: str
    #: ⚠ True when the id is deprecated in a way we refuse to resolve.
    ambiguous: bool = False
    #: The candidates, when ambiguous. Surfaced, never chosen between.
    candidates: tuple[str, ...] = ()
    #: Raw text preserved for `normalize.license_refs`, so a human can map it
    #: later without re-running the scan.
    raw: str = ""
    diagnostics: list[dict[str, object]] = field(default_factory=list)

    @property
    def is_substantive(self) -> bool:
        """Whether this counts as PRESENT for `completeness_pct`.

        ⚠ THE ONE DELIBERATE EXCEPTION IN THE COVERAGE RULES: `NONE` counts as
        present. It is a substantive assertion — "we looked, there is no
        licence" — whereas `NOASSERTION` declines to say. Documented here
        because it will be argued about and there needs to be a written answer.
        """
        if not self.value:
            return False
        if self.value == NOASSERTION:
            return False
        return True


def resolve(raw: str) -> Resolution:
    """Run the resolution pipeline over one license string."""
    if raw is None or not isinstance(raw, str) or not raw.strip():
        return Resolution(value="", rule="empty", raw=raw or "")

    text = raw.strip()
    upper = text.upper()

    # SPDX's two special values, checked before anything else so they are never
    # folded into an alias or a LicenseRef.
    if upper == NONE:
        return Resolution(value=NONE, rule="spdx-none", raw=text)
    if upper in (NOASSERTION, "NO_ASSERTION", "NOASSERTION."):
        return Resolution(value=NOASSERTION, rule="spdx-noassertion", raw=text)

    if _looks_like_expression(text):
        return _resolve_expression(text)

    return _resolve_single(text)


def _resolve_single(text: str) -> Resolution:
    """Resolve one license id (no operators)."""
    # Stage 1: exact SPDX id.
    if text in _KNOWN_IDS:
        return Resolution(value=text, rule="spdx-exact", raw=text)

    # Stage 2: deprecated-but-unambiguous rewrite.
    if text in DEPRECATED_UNAMBIGUOUS:
        return Resolution(
            value=DEPRECATED_UNAMBIGUOUS[text],
            rule="spdx-deprecated-unambiguous",
            raw=text,
        )

    # ⚠ Stage 2a: deprecated AND ambiguous. Flagged, never resolved.
    ambiguous = _ambiguous_for(text)
    if ambiguous is not None:
        canonical, candidates = ambiguous
        return Resolution(
            value=canonical,
            rule="spdx-deprecated-ambiguous",
            ambiguous=True,
            candidates=candidates,
            raw=text,
            diagnostics=[ambiguity_diagnostic(text, candidates)],
        )

    # Stage 3: case-insensitive exact match.
    for known in _KNOWN_IDS:
        if known.lower() == text.lower():
            return Resolution(value=known, rule="spdx-caseless", raw=text)

    # Stage 4: the curated alias table.
    folded = _fold_key(text)
    alias = _ALIASES_RAW.get(folded)
    if alias:
        # An alias can land on an ambiguous deprecated id ("GPLv2" → GPL-2.0),
        # and the ambiguity must survive the alias lookup.
        ambiguous = _ambiguous_for(alias)
        if ambiguous is not None:
            canonical, candidates = ambiguous
            return Resolution(
                value=canonical,
                rule="alias-ambiguous",
                ambiguous=True,
                candidates=candidates,
                raw=text,
                diagnostics=[ambiguity_diagnostic(text, candidates)],
            )
        return Resolution(value=alias, rule="alias", raw=text)

    # Stage 5: LicenseRef fallback.
    #
    # ⚠ NOT an error and NOT dropped. The raw text is preserved in
    # `normalize.license_refs` so a human can map it later WITHOUT re-scanning —
    # which is the same replayability property as ADR-0003.
    return Resolution(
        value=license_ref(text),
        rule="license-ref",
        raw=text,
        diagnostics=[
            {
                "severity": "info",
                "code": "NORMALIZE_LICENSE_UNMAPPED",
                "message": f"license {text[:120]!r} is not a known SPDX id",
                "hint": "stored as a LicenseRef with the raw text for later mapping",
            }
        ],
    )


def _ambiguous_for(text: str) -> tuple[str, tuple[str, str]] | None:
    """Return (canonical, candidates) if `text` is an ambiguous deprecated id."""
    for deprecated, candidates in AMBIGUOUS_DEPRECATED.items():
        if text.lower() == deprecated.lower():
            return deprecated, candidates
    return None


def _looks_like_expression(text: str) -> bool:
    """Whether the string contains SPDX expression syntax."""
    if "(" in text or ")" in text:
        return True
    return any(f" {op} " in f" {text} " for op in _OPERATORS)


def _resolve_expression(text: str) -> Resolution:
    """Parse and re-render an SPDX expression, resolving each operand.

    ⚠ `A OR B` IS NOT FLATTENED. Which disjunct applies is a policy decision
    that belongs to a later, configurable layer — a project may be able to
    accept MIT but not GPL, and that judgement is the customer's.
    """
    tokens = _split_expression(text)
    if not tokens:
        return Resolution(value=NOASSERTION, rule="expression-empty", raw=text)

    rendered: list[str] = []
    ambiguous = False
    candidates: list[str] = []
    diagnostics: list[dict[str, object]] = []
    depth = 0

    for item in tokens:
        if item == "(":
            depth += 1
            rendered.append(item)
            continue
        if item == ")":
            depth -= 1
            rendered.append(item)
            continue
        if item.upper() in _OPERATORS:
            rendered.append(item.upper())
            continue

        part = _resolve_single(item)
        rendered.append(part.value)
        if part.ambiguous:
            ambiguous = True
            candidates.extend(part.candidates)
        diagnostics.extend(part.diagnostics)

    if depth != 0:
        # Unbalanced parentheses: keep the raw text rather than emitting a
        # rewritten expression that may mean something different.
        return Resolution(
            value=license_ref(text),
            rule="expression-invalid",
            raw=text,
            diagnostics=[
                {
                    "severity": "warn",
                    "code": "NORMALIZE_LICENSE_EXPRESSION_INVALID",
                    "message": f"unbalanced parentheses in {text[:120]!r}",
                    "hint": "stored verbatim as a LicenseRef rather than rewritten",
                }
            ],
        )

    return Resolution(
        value=" ".join(rendered).replace("( ", "(").replace(" )", ")"),
        rule="expression",
        ambiguous=ambiguous,
        candidates=tuple(dict.fromkeys(candidates)),
        raw=text,
        diagnostics=diagnostics,
    )


def _split_expression(text: str) -> list[str]:
    """Split an expression into parens, operators and whole operands.

    ⚠ SPLITTING ON WHITESPACE IS WRONG HERE.

    A strict SPDX id contains no spaces, but real manifests write
    `Apache License 2.0 OR MIT`. Whitespace tokenization turns that into three
    operands — `Apache`, `License`, `2.0` — and each falls through to a
    LicenseRef, so a perfectly recognisable licence becomes unmapped.

    Operands are therefore whole runs of text BETWEEN operators and parens.
    """
    tokens: list[str] = []
    buffer: list[str] = []

    def flush() -> None:
        if buffer:
            operand = " ".join(buffer).strip()
            if operand:
                tokens.append(operand)
            buffer.clear()

    for word in _TOKEN.findall(text):
        if word in ("(", ")"):
            flush()
            tokens.append(word)
        elif word.upper() in _OPERATORS:
            flush()
            tokens.append(word.upper())
        else:
            buffer.append(word)

    flush()
    return tokens


def license_ref(text: str) -> str:
    """Build a `LicenseRef-AxeBOM-<slug>` for an unmapped license."""
    slug = _SLUG.sub("-", text.strip()).strip("-")[:60]
    return f"LicenseRef-AxeBOM-{slug or 'unknown'}"


def ambiguity_diagnostic(text: str, candidates: tuple[str, ...]) -> dict[str, object]:
    """The diagnostic for a deprecated, ambiguous id.

    Severity `warn`, not `info`: a reviewer has to make this call, and it must
    be visible enough that they know it is waiting for them.
    """
    return {
        "severity": "warn",
        "code": "NORMALIZE_LICENSE_AMBIGUOUS",
        "message": f"{text} is deprecated and could mean {' or '.join(candidates)}",
        "hint": (
            "flagged rather than resolved: the two differ in their obligations and "
            "the guideline gives no way to choose. Choosing wrong is a legal error, "
            "not a data-quality one"
        ),
    }


def _fold_key(text: str) -> str:
    """Fold a license string for alias lookup: lowercase, alphanumerics only."""
    lowered = text.lower()
    for noise in (" license", " licence", " version", " the "):
        lowered = lowered.replace(noise, " ")
    return _FOLD.sub("", lowered)


@dataclass
class LicenseSet:
    """The three kinds, kept separate, plus the effective value.

    ⚠ `concluded` NEVER OVERWRITES `declared`. SPDX requires the distinction and
    compliance reviewers ask for it: "the manifest says MIT but the LICENSE file
    is Apache-2.0" is a finding, not a conflict to silently resolve.
    """

    declared: Resolution | None = None
    concluded: Resolution | None = None
    observed: Resolution | None = None

    def effective(self) -> tuple[str, str]:
        """Return (value, rule) for `license_effective` / `license_rule`.

        Precedence: concluded > declared > observed. A concluded license comes
        from reading the actual LICENSE file or from a human, both of which
        outrank a manifest field that is frequently copy-pasted and stale.
        """
        for kind, resolution in (
            ("concluded", self.concluded),
            ("declared", self.declared),
            ("observed", self.observed),
        ):
            if resolution is not None and resolution.value:
                return resolution.value, f"{kind}:{resolution.rule}"
        return "", "none"

    @property
    def ambiguous(self) -> bool:
        return any(
            r is not None and r.ambiguous for r in (self.declared, self.concluded, self.observed)
        )

    def diagnostics(self) -> list[dict[str, object]]:
        out: list[dict[str, object]] = []
        for resolution in (self.declared, self.concluded, self.observed):
            if resolution is not None:
                out.extend(resolution.diagnostics)
        return out
