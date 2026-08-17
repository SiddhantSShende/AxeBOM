"""Name normalization for the crypto rules.

⚠ THE WORD-BOUNDARY PROBLEM, SOLVED ONCE INSTEAD OF PER-RULE.

Cryptographic algorithm names arrive concatenated in both directions, and `\\b`
fails on both:

    rsaEncryption            `\\brsa\\b` misses it — `E` is a word character
    sha1WithRSAEncryption    `\\brsa\\b` misses it — no boundary before `R`
    modp2048                 `\\bmodp\\b` misses it — `2` is a word character
    Kyber1024                `\\bkyber\\b` misses it

Nine rules were written with plain `\\b` first. Every one silently reported a
broken or quantum-vulnerable primitive as unassessed, which is the worst
possible direction for a rule whose output is a migration list.

Rather than patching each pattern — which is how the ninth one gets missed —
every name is split into tokens first, so the boundaries the rules assume
actually exist. `sha1WithRSAEncryption` becomes `sha1 With RSA Encryption`, and
a rule written the obvious way is correct.
"""

from __future__ import annotations

import re

#: Split at a lowercase-or-digit followed by an uppercase: `sha1With` -> `sha1 With`.
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

#: Split an uppercase run before a capitalised word: `RSAEncryption` -> `RSA Encryption`.
#: Without this, splitting only on the first rule leaves `RSAEncryption` intact.
_ACRONYM = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")

#: Split a letter run from a trailing digit run: `modp2048` -> `modp 2048`.
#:
#: ⚠ NOT APPLIED TO EVERY DIGIT BOUNDARY. `sha256` and `AES256` must stay whole,
#: because the rules match them as single tokens — splitting them would break
#: `\\bsha-?(224|256|384|512)\\b` and turn a correct rule into a miss. Only the
#: named prefixes below are split.
_SIZED_PREFIX = re.compile(r"\b(modp|kyber|dilithium|sphincs|falcon)(\d+)", re.I)


def tokenize(*parts: str) -> str:
    """Join and split names so word boundaries exist where rules expect them.

    Idempotent: tokenizing an already-spaced name changes nothing.
    """
    text = " ".join(p for p in parts if p).strip()
    if not text:
        return ""

    text = _SIZED_PREFIX.sub(r"\1 \2", text)
    text = _ACRONYM.sub(" ", text)
    text = _CAMEL.sub(" ", text)
    return re.sub(r"\s+", " ", text).strip()


def search_text(*parts: str) -> str:
    """The string the rules are matched against: the raw name AND its tokens.

    ⚠ BOTH FORMS, NOT THE TOKENIZED ONE ALONE — AND THAT WAS LEARNED THE HARD
    WAY.

    Replacing the raw name with its tokenization fixed `sha1WithRSAEncryption`
    and immediately broke four rules that were already correct:

        3DES       -> `3 DES`      `3des` stopped matching, and the asset
                                   was reported `broken` instead of `weak`
        ChaCha20   -> `Cha Cha20`  no longer recognised at all
        modp1024   -> `modp 1024`  the key-size reader stopped finding the size

    That is the general hazard of normalizing the input to a set of
    hand-written patterns: the transform helps the rules that were wrong and
    breaks the ones that were right, and the breakage is silent.

    Concatenating both is additive. A rule can only match MORE than it did, and
    for a rule whose output is a migration list, more is the safe direction.
    """
    raw = " ".join(p for p in parts if p).strip()
    if not raw:
        return ""
    tokens = tokenize(raw)
    return raw if tokens == raw else f"{raw} {tokens}"
