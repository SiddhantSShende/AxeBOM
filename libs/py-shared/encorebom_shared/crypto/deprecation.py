"""Deprecation status for cryptographic primitives.

⚠ FOUR STATES, AND THE DIFFERENCE BETWEEN THE MIDDLE TWO IS THE POINT.

    current      no known weakness for its intended use
    deprecated   withdrawn or discouraged by a standards body; no practical
                 break, but do not use it in new work
    weak         a practical attack exists but is expensive or situational
    broken       a practical attack is cheap and demonstrated

Collapsing `weak` and `broken` into one "bad" bucket is the tempting
simplification and it is wrong in a compliance document: SHA-1 collisions are
demonstrated and cheap, while a 1024-bit RSA key is within reach of a
well-funded adversary and nobody else. Those need different remediation
timelines, and a customer given one bucket triages neither.

⚠ THE USE MATTERS AS MUCH AS THE PRIMITIVE. SHA-1 in a signature is broken;
SHA-1 inside HMAC has no practical attack, because HMAC does not rely on
collision resistance. A rule that condemns every appearance of SHA-1 produces a
migration list full of HMAC-SHA1 entries that are fine, and the entries that are
not fine get lost in it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ._text import search_text

Status = str  # one of: current, deprecated, weak, broken


@dataclass(frozen=True)
class DeprecationVerdict:
    """What is wrong with a primitive, and how urgently."""

    status: Status
    #: Why, in one sentence a reader can act on.
    rationale: str
    #: The standard or advisory that says so, where one exists.
    reference: str = ""


#: ⚠ THE WORD-BOUNDARY BUG, A THIRD TIME. `\bsha-?1\b` does NOT match
#: `sha1WithRSAEncryption` — the boundary needs a non-word character after the
#: `1`, and `W` is a word character. That is the name a certificate signature
#: algorithm ACTUALLY carries, so the rule missed the exact case it exists for
#: and reported a SHA-1 certificate as `current`.
#:
#: A negative lookahead for a digit instead: it still refuses `sha-256`, and it
#: matches every concatenated form.
_SHA1 = re.compile(r"\bsha-?1(?![0-9])", re.I)
_MD5 = re.compile(r"\bmd5(?![0-9])", re.I)

_CURRENT = DeprecationVerdict("current", "No known weakness for its intended use.")


def assess_deprecation(
    *,
    name: str,
    primitive: str = "",
    key_size: int | None = None,
    crypto_functions: list[str] | None = None,
    asset_type: str = "algorithm",
) -> DeprecationVerdict:
    """Assess one crypto asset."""
    # Raw name AND its tokens, so a rule matches either form — see
    # _text.search_text for why replacing one with the other is wrong.
    haystack = search_text(name, primitive)
    if not haystack:
        return DeprecationVerdict(
            "current",
            "Not assessed: this asset reports no name or primitive.",
        )

    functions = {f.lower() for f in (crypto_functions or [])}
    lowered = haystack.lower()

    # ⚠ HMAC IS CHECKED FIRST, BEFORE THE HASH RULES BELOW. `HMAC-SHA1` contains
    # `SHA1`, and the hash rule would otherwise mark it broken — which is the
    # false positive that fills a migration list with work nobody needs to do.
    if "hmac" in lowered:
        if re.search(_MD5, lowered):
            return DeprecationVerdict(
                "deprecated",
                "HMAC-MD5 has no practical break — HMAC does not rely on "
                "collision resistance — but MD5 is withdrawn and it should not "
                "appear in new work.",
                "RFC 6151",
            )
        if re.search(_SHA1, lowered):
            return DeprecationVerdict(
                "deprecated",
                "HMAC-SHA1 has no practical break: HMAC's security does not rest "
                "on collision resistance, which is what is broken in SHA-1. "
                "Still, prefer HMAC-SHA-256 in new work.",
                "NIST SP 800-131A Rev. 2",
            )
        return _CURRENT

    # --- Hashes ------------------------------------------------------------
    if re.search(_MD5, lowered):
        return DeprecationVerdict(
            "broken",
            "MD5 collisions are trivial to produce and have been used in real "
            "attacks. Unusable for signatures, certificates or integrity.",
            "RFC 6151",
        )
    if re.search(r"\bmd4\b|\bmd2\b", lowered):
        return DeprecationVerdict("broken", "Comprehensively broken.", "RFC 6150")
    if re.search(_SHA1, lowered):
        return DeprecationVerdict(
            "broken",
            "SHA-1 collisions are demonstrated and affordable (SHAttered, 2017). "
            "Unusable for signatures and certificates.",
            "NIST SP 800-131A Rev. 2",
        )

    # --- Symmetric ciphers -------------------------------------------------
    if re.search(r"\brc4\b|\barcfour\b", lowered):
        return DeprecationVerdict(
            "broken",
            "RC4's keystream biases are practically exploitable; it is prohibited in TLS.",
            "RFC 7465",
        )
    if re.search(r"\b3des\b|\btriple[- ]?des\b|\bdes-ede\b", lowered):
        return DeprecationVerdict(
            "weak",
            "3DES has a 64-bit block, which makes Sweet32 birthday attacks "
            "practical on long-lived connections. Disallowed by NIST after 2023.",
            "NIST SP 800-131A Rev. 2",
        )
    if re.search(r"\bdes\b", lowered):
        return DeprecationVerdict(
            "broken",
            "Single DES has a 56-bit key and is brute-forceable in hours.",
            "NIST SP 800-131A Rev. 2",
        )
    if re.search(r"\brc2\b|\bblowfish\b", lowered):
        return DeprecationVerdict(
            "weak",
            "A 64-bit block cipher; vulnerable to Sweet32 birthday attacks on "
            "long-lived connections.",
        )

    # --- Modes -------------------------------------------------------------
    # ⚠ ECB IS A MODE, NOT AN ALGORITHM, and it is the one case where the mode
    # alone condemns an otherwise-current cipher. AES-128-ECB is AES; it is also
    # unusable, because identical plaintext blocks produce identical ciphertext.
    if re.search(r"\becb\b", lowered):
        return DeprecationVerdict(
            "broken",
            "ECB mode leaks plaintext structure: identical blocks encrypt to "
            "identical ciphertext. The underlying cipher is irrelevant.",
            "NIST SP 800-38A",
        )

    # --- Asymmetric key sizes ----------------------------------------------
    if re.search(r"\brsa", lowered):
        return _rsa_verdict(key_size or _bits_from_name(lowered))
    if re.search(r"\bdiffie[- ]?hellman\b|\bdhe?\b(?!\w)|\bmodp", lowered):
        return _dh_verdict(key_size or _bits_from_name(lowered))
    if re.search(r"\bdsa\b(?!\w)", lowered):
        return DeprecationVerdict(
            "deprecated",
            "DSA is withdrawn for new signatures; NIST allows verification only.",
            "FIPS 186-5",
        )

    # --- Curves ------------------------------------------------------------
    if re.search(r"\bsecp(160|192)|\bprime192|\bp-192\b", lowered):
        return DeprecationVerdict(
            "weak",
            "Curves below 224 bits fall short of the 112-bit classical security floor.",
            "NIST SP 800-131A Rev. 2",
        )

    if _is_certificate_signature(asset_type, functions) and re.search(_SHA1, lowered):
        return DeprecationVerdict(
            "broken",
            "A SHA-1 certificate signature. Rejected by every major browser.",
        )

    return _CURRENT


def _rsa_verdict(bits: int | None) -> DeprecationVerdict:
    if bits is None:
        # ⚠ NOT ASSESSED, NOT ASSUMED FINE. An RSA key with no reported size is
        # the one most likely to be a legacy 1024-bit key, and reporting it as
        # `current` would hide exactly the asset a reviewer is looking for.
        return DeprecationVerdict(
            "current",
            "RSA key size was not reported, so its strength could not be "
            "assessed. Anything below 2048 bits is disallowed.",
            "NIST SP 800-131A Rev. 2",
        )
    if bits < 1024:
        return DeprecationVerdict(
            "broken",
            f"{bits}-bit RSA is factorable with modest resources.",
            "NIST SP 800-131A Rev. 2",
        )
    if bits < 2048:
        return DeprecationVerdict(
            "weak",
            f"{bits}-bit RSA is below the 112-bit security floor and disallowed "
            f"by NIST. Within reach of a well-funded adversary.",
            "NIST SP 800-131A Rev. 2",
        )
    return _CURRENT


def _dh_verdict(bits: int | None) -> DeprecationVerdict:
    if bits is None:
        return DeprecationVerdict(
            "current",
            "Diffie-Hellman group size was not reported, so its strength could "
            "not be assessed. Anything below 2048 bits is disallowed.",
            "NIST SP 800-131A Rev. 2",
        )
    if bits < 1024:
        return DeprecationVerdict(
            "broken",
            f"A {bits}-bit Diffie-Hellman group is breakable; export-grade groups "
            f"are the Logjam attack.",
            "RFC 7919",
        )
    if bits < 2048:
        return DeprecationVerdict(
            "weak",
            f"A {bits}-bit Diffie-Hellman group is below the 112-bit floor. "
            f"Precomputation against a common group amortises across every "
            f"connection using it.",
            "RFC 7919",
        )
    return _CURRENT


def _is_certificate_signature(asset_type: str, functions: set[str]) -> bool:
    return asset_type == "certificate" or bool(functions & {"sign", "signature", "verify"})


# ⚠ NO TRAILING  ON THE FAMILY TOKENS ABOVE, AND THAT IS NOT AN OVERSIGHT.
#
# `rsa` does NOT match `rsaEncryption`: the boundary needs a non-word
# character after `rsa`, and `E` is a word character. The same failure hides
# `modp2048` and `Kyber1024` — which is to say most of the names these actually
# appear under in tool output. Six rules were written that way first, and every
# one silently reported a broken primitive as unassessed.
_BITS = re.compile(r"(?:rsa|dh|dsa|modp)[-_]?(\d{3,5})", re.I)


def _bits_from_name(name: str) -> int | None:
    """Recover a key size from a name like `RSA-2048` or `modp2048`.

    Narrow on purpose: a general "find a number" rule reads the 1 in `PKCS#1`
    as a key size, and this value decides whether an asset is reported broken.
    """
    match = _BITS.search(name)
    return int(match.group(1)) if match else None
