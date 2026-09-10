"""What the AI BOM may say it did, and what it may not.

⚠ AN AIBOM IS DISCOVERY PLUS A PUBLIC LOOKUP, AND NEITHER IS AN EVALUATION.

Three engines parse the customer's source for model references, prompts, vector
stores and inference calls; one asks a public API about a model IDENTIFIER. That
is the whole of it. AxeBOM does not run a model, measure it, test it for bias,
audit it, or confirm that a licence permits a customer's use — and a compliance
document that implies otherwise is found out at exactly the wrong moment.

This is the twin of `workers/hbom/test_hbom.py`'s discovery-claim guard, and it
exists for the same reason: the rule is about what we SAY, and a docstring is as
much of a claim as a UI string, so the check walks the package's own source.
"""

from __future__ import annotations

import pathlib
import re

#: Claims this product cannot honour.
#:
#: ⚠ REGEXES, NOT SUBSTRINGS, for the reason the HBOM guard records: a rule
#: expressed as a verb next to a noun cannot be defeated by a possessive.
#: "evaluated the model" and "evaluates your model" are the same claim.
_OVERCLAIMS = (
    # We never execute or measure a model.
    re.compile(
        r"\b(evaluate|evaluates|evaluated|benchmark|benchmarks|benchmarked|test|tests|tested)"
        r"\s+(your\s+|the\s+|their\s+|its\s+|each\s+)?model\b"
    ),
    re.compile(r"\bscans?\s+(your\s+|the\s+|their\s+)?model\b"),
    re.compile(r"\baudits?\s+(your\s+|the\s+|their\s+|its\s+)?model\b"),
    re.compile(r"\baudited\s+(your\s+|the\s+|their\s+|its\s+)?model\b"),
    # Bias and fairness are measurements nothing here performs.
    re.compile(r"\b(test|tests|tested|check|checks|checked)\s+for\s+bias\b"),
    re.compile(r"\bbias\s+(test|testing|audit|evaluation)\b"),
    # A licence read off a model card is what the publisher SAID, never a legal
    # conclusion about a customer's use.
    re.compile(r"\bverif(y|ies|ied)\s+(your\s+|the\s+|its\s+)?licen[cs]e\b"),
    # Engines run --network=none inside a sealed container. Nothing streams from
    # inside a running scanner; events are emitted as each engine reports.
    re.compile(r"\bwatch(ing|es)?\s+(your\s+)?code\s+live\b"),
    re.compile(r"\breal[- ]time\s+(code\s+)?monitoring\b"),
)

#: Words that turn one of the above into a warning AGAINST making the claim.
#: The negation check is the whole subtlety — see the HBOM guard's own note.
_NEGATIONS = (
    "not ",
    "no ",
    "never",
    "cannot",
    "is a lie",
    "would be",
    "must not",
    "there is",
    "rather than",
    "instead of",
    "forbidden",
    "refuses",
)

_PACKAGES = ("aibom", "aienrich")


def _sources() -> list[pathlib.Path]:
    workers = pathlib.Path(__file__).resolve().parents[1]
    out: list[pathlib.Path] = []
    for package in _PACKAGES:
        out.extend(sorted((workers / package).rglob("*.py")))
    return out


def _flagged(line: str, previous: str = "") -> bool:
    lowered = line.lower()
    if not any(claim.search(lowered) for claim in _OVERCLAIMS):
        return False
    return not any(negation in (previous.lower() + lowered) for negation in _NEGATIONS)


def test_nothing_in_the_ai_packages_claims_to_evaluate_a_model() -> None:
    offenders: list[str] = []

    for path in _sources():
        if path.name == pathlib.Path(__file__).name:
            # This file names the forbidden phrases in order to forbid them.
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, 1):
            previous = lines[number - 2] if number >= 2 else ""
            if _flagged(line, previous):
                offenders.append(f"{path.parent.name}/{path.name}:{number}: {line.strip()}")

    assert not offenders, (
        "an AIBOM is discovery plus a public lookup; these read as claims to have "
        "evaluated, tested or audited a model:\n  " + "\n  ".join(offenders)
    )


def test_what_is_true_is_not_flagged() -> None:
    """⚠ A GUARD THAT ONLY EVER FORBIDS IS A GUARD NOBODY CAN WORK WITH.

    Everything below is an accurate description of what the product does, and
    flagging any of it would push somebody to soften a true sentence — which is
    how a rule ends up deleted.
    """
    permitted = [
        "discovered in source at src/app.py:17",
        "parsed the model card the publisher wrote",
        "the licence the model's own card declares",
        "reported by the model's own card, not verified by AxeBOM",
        "three engines scan the repository for model references",
        "real-time discovery counts as each engine reports",
        "the model resolves on the Hugging Face Hub",
    ]
    for text in permitted:
        assert not _flagged(text), f"a true statement was flagged: {text}"


def test_the_guard_would_actually_catch_one() -> None:
    """⚠ THE CHECK ABOVE PASSES TRIVIALLY IF ITS NEGATION FILTER IS TOO BROAD.

    A filter that excused every line would leave a green test proving nothing —
    a failure mode this codebase has hit before. So the filter is exercised
    directly: an asserted claim is caught, a warning against one is not.
    """
    forbidden = [
        "AxeBOM evaluates the model against your policy",
        "we tested the model for bias",
        "this scans your model for weaknesses",
        "AxeBOM verifies the licence permits your use",
        "watch your code live as the scan runs",
        "we audited the model end to end",
    ]
    for text in forbidden:
        assert _flagged(text), f"this overclaims and was NOT caught: {text}"

    warning = "# AxeBOM never evaluates the model, and no UI string may say it does."
    assert not _flagged(warning), "a warning against the claim was flagged as the claim"
