"""Deprecation status for cryptographic primitives.

⚠ FIVE STATES. THE DIFFERENCE BETWEEN THE MIDDLE TWO IS THE POINT, AND THE LAST
ONE IS WHAT KEEPS THE FIRST HONEST.

    current      no known weakness for its intended use
    deprecated   withdrawn or discouraged by a standards body; no practical
                 break, but do not use it in new work
    weak         a practical attack exists but is expensive or situational
    broken       a practical attack is cheap and demonstrated
    unassessed   no verdict could be reached: no name, no rule recognises the
                 algorithm, or a size the verdict depends on was not reported

Collapsing `weak` and `broken` into one "bad" bucket is the tempting
simplification and it is wrong in a compliance document: SHA-1 collisions are
demonstrated and cheap, while a 1024-bit RSA key is within reach of a
well-funded adversary and nobody else. Those need different remediation
timelines, and a customer given one bucket triages neither.

⚠ `unassessed` IS NOT `current`, AND FOR A WHILE IT WAS. Every path that could not
reach a verdict returned `current` with an apologetic rationale — an unsized RSA
key, an unnamed asset, and any algorithm no rule recognised. A reviewer filtering
on status saw all of them as fine, and the unsized RSA key is the one most likely
to be a legacy 1024-bit key. A name now has to be RECOGNISED to be called current.

⚠ THE USE MATTERS AS MUCH AS THE PRIMITIVE. SHA-1 in a signature is broken;
SHA-1 inside HMAC has no practical attack, because HMAC does not rely on
collision resistance. PKCS#1 v1.5 padding is disallowed for RSA key transport and
still permitted for RSA signatures. A rule that condemns every appearance of a
primitive produces a migration list full of entries that are fine, and the
entries that are not fine get lost in it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ._text import search_text
from .quantum_rules import is_bare_ec, pqc_family

Status = str  # one of STATUSES

#: Every status this module can return. `migrations/normalize/0019` mirrors it
#: in the column's CHECK constraint and the compliance profile lists it as the
#: extension's closed value set; `test_crypto.py` holds all three together.
STATUSES: tuple[str, ...] = ("current", "deprecated", "weak", "broken", "unassessed")


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

#: ⚠ JAVA SAYS `DESede`, OPENSSL SAYS `DES-EDE3`, NIST SAYS `TDEA`. The tokenizer
#: turns `DESede` into `DE Sede`, which matched nothing, so the most common 3DES
#: name in Java code was reported as unrecognised.
_3DES = re.compile(r"\b3des\b|\btriple[- ]?des\b|\bdes-?ede3?\b|\bdesede\b|\btdea\b", re.I)

#: The only primitives ECB mode can condemn. ⚠ NOT RSA: Java's
#: `RSA/ECB/PKCS1Padding` names ECB because the transformation syntax demands a
#: mode, and RSA encrypts a single block — blaming ECB there sends a reviewer
#: after the wrong fix. The real problem in that string is the padding.
_BLOCK_CIPHER = re.compile(r"\baes|\bcamellia\b|\baria\b|\bseed\b|\bsm4\b|\bidea\b", re.I)

#: ⚠ EdDSA AND THE X-CURVES ARE NOT DSA. `EdDSA` tokenizes to `Ed DSA`, and the
#: legacy DSA rule fired on the second token and reported Ed25519 deprecated.
_EDWARDS = re.compile(
    r"\beddsa\b|\bed25519\b|\bed448\b|\bx25519\b|\bx448\b|\bcurve25519\b|\bcurve448\b", re.I
)

_ECC = re.compile(
    r"\becdsa\b|\becdh\b|\becies\b|\bsecp\d|\bprime\d{3}v\d|\bbrainpool|\bnistp\d"
    r"|\bp-?(?:192|224|256|384|521)\b|\becc\b",
    re.I,
)
_WEAK_CURVE = re.compile(r"\bsecp(?:112|128|160|192)|\bprime192|\bp-?192\b", re.I)
#: A curve actually named — without one, an ECDSA or ECDH verdict has nothing to
#: rest on.
_NAMED_CURVE = re.compile(
    r"\bsecp\d|\bprime\d{3}v\d|\bbrainpool|\bnistp\d|\bp-?(?:224|256|384|521)\b"
    r"|\bsect\d|\bfrp256",
    re.I,
)

#: `RSA/ECB/PKCS1Padding` (a Java Cipher transformation — encryption by
#: definition) and the CycloneDX `padding: pkcs1v15` value.
_PKCS1_V15 = re.compile(r"pkcs1padding|pkcs1v15|\bpkcs#?1[ _-]?v?1\.5\b", re.I)
_RSA_CIPHER_TRANSFORMATION = re.compile(r"\brsa/[^/\s]*/pkcs1padding", re.I)

#: Families with no known weakness for their intended use, reached only when no
#: rule above matched. ⚠ A NAME HAS TO APPEAR HERE (OR IN A RULE) TO BE CURRENT.
_KNOWN_CURRENT = re.compile(
    r"\baes|\bchacha20?\b|\bxchacha|\bpoly1305\b|\bcamellia\b"
    r"|\bsha-?(?:224|256|384|512)\b|\bsha2\b|\bsha512/(?:224|256)\b"
    r"|\bsha-?3|\bshake(?:128|256)?\b|\bblake2|\bblake3\b"
    r"|\bpbkdf2\b|\bbcrypt\b|\bscrypt\b|\bargon2|\bhkdf\b|\bkmac",
    re.I,
)

_CURRENT = DeprecationVerdict("current", "No known weakness for its intended use.")

_UNRECOGNISED = DeprecationVerdict(
    "unassessed",
    "No deprecation rule recognises this algorithm, so it was not assessed rather "
    "than assumed current.",
)

#: What each post-quantum family's standing actually is. ⚠ "SELECTED" IS NOT
#: "STANDARDISED": FN-DSA and HQC are NIST selections with no final FIPS in this
#: ruleset, and saying otherwise would be a claim a customer cites at an audit.
_PQC_STANDING: dict[str, tuple[str, str]] = {
    "ml-kem": ("FIPS 203", "ML-KEM is a final NIST post-quantum standard (FIPS 203)."),
    "ml-dsa": ("FIPS 204", "ML-DSA is a final NIST post-quantum standard (FIPS 204)."),
    "slh-dsa": ("FIPS 205", "SLH-DSA is a final NIST post-quantum standard (FIPS 205)."),
    "lms": (
        "NIST SP 800-208",
        "Stateful hash-based signatures standardised in NIST SP 800-208; secure only "
        "with correct state management.",
    ),
    "falcon": (
        "",
        "FN-DSA (Falcon) is selected by NIST for standardisation; this ruleset does not "
        "treat it as a final standard until FIPS 206 is published.",
    ),
    "hqc": (
        "",
        "HQC was selected by NIST in March 2025 as a backup key-encapsulation "
        "mechanism; no final standard has been published.",
    ),
    "mceliece": (
        "",
        "A post-quantum scheme NIST has not standardised; no known practical weakness.",
    ),
}


def assess_deprecation(
    *,
    name: str,
    primitive: str = "",
    key_size: int | None = None,
    crypto_functions: list[str] | None = None,
    asset_type: str = "algorithm",
    mode: str = "",
    padding: str = "",
    protocol_version: str = "",
) -> DeprecationVerdict:
    """Assess one crypto asset.

    `mode`, `padding` and `protocol_version` come from the asset's own fields.
    They decide verdicts a name cannot: an asset named only `AES` with
    `mode: ecb`, PKCS#1 v1.5 key transport at any key size, and `TLS` whose
    version is the whole question.
    """
    # Raw name AND its tokens, so a rule matches either form — see
    # _text.search_text for why replacing one with the other is wrong.
    haystack = search_text(name, primitive)
    if not haystack:
        return DeprecationVerdict(
            "unassessed",
            "Not assessed: this asset reports no name or primitive.",
        )

    functions = {f.lower() for f in (crypto_functions or [])}
    lowered = haystack.lower()

    if asset_type == "protocol":
        return _protocol_verdict(lowered, protocol_version)

    # ⚠ POST-QUANTUM FIRST, BEFORE ANY LEGACY RULE. `\bdsa\b` matches the "-DSA"
    # in ML-DSA, SLH-DSA and FN-DSA, and the DSA rule used to run first — so the
    # algorithms a customer migrated TO were reported deprecated.
    family = pqc_family(name, primitive)
    if family is not None:
        reference, rationale = _PQC_STANDING[family]
        return DeprecationVerdict("current", rationale, reference)

    # ⚠ HMAC IS CHECKED BEFORE THE HASH RULES BELOW. `HMAC-SHA1` contains
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
    if _3DES.search(lowered):
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
    # alone condemns an otherwise-current block cipher. AES-128-ECB is AES; it is
    # also unusable, because identical plaintext blocks encrypt identically. The
    # `mode` FIELD counts as much as the name: an asset named `AES` whose engine
    # reported `mode: ecb` was reported current.
    if _BLOCK_CIPHER.search(lowered) and (
        mode.strip().lower() == "ecb" or re.search(r"\becb\b", lowered)
    ):
        return DeprecationVerdict(
            "broken",
            "ECB mode leaks plaintext structure: identical blocks encrypt to "
            "identical ciphertext. The underlying cipher is irrelevant.",
            "NIST SP 800-38A",
        )

    # --- Asymmetric --------------------------------------------------------
    if re.search(r"\brsa", lowered):
        if _is_pkcs1_v15_key_transport(lowered, primitive, functions, padding):
            return DeprecationVerdict(
                "weak",
                "RSA key transport with PKCS#1 v1.5 padding is disallowed by NIST "
                "after 2023 and is exposed to Bleichenbacher-style padding-oracle "
                "attacks. Use RSA-OAEP, or migrate key establishment to ML-KEM. "
                "PKCS#1 v1.5 signatures are unaffected.",
                "NIST SP 800-131A Rev. 2",
            )
        return _rsa_verdict(key_size or _bits_from_name(lowered))
    if re.search(r"\bdiffie[- ]?hellman\b|\bdhe?\b(?!\w)|\bmodp|\bffdhe", lowered):
        return _dh_verdict(key_size or _bits_from_name(lowered))
    if _EDWARDS.search(lowered):
        return DeprecationVerdict(
            "current",
            "An Edwards or Montgomery curve at roughly 128-bit classical security or "
            "better; no known classical weakness. Quantum exposure is reported "
            "separately.",
            "RFC 8032 / RFC 7748",
        )
    if _ECC.search(lowered):
        if _WEAK_CURVE.search(lowered) or (key_size is not None and key_size < 224):
            return DeprecationVerdict(
                "weak",
                "Curves below 224 bits fall short of the 112-bit classical security floor.",
                "NIST SP 800-131A Rev. 2",
            )
        if _NAMED_CURVE.search(lowered) or key_size is not None:
            return DeprecationVerdict(
                "current",
                "An elliptic-curve primitive with no known classical weakness on curves of "
                "224 bits or more. Quantum exposure is reported separately.",
            )
        # ⚠ `ECDSA` ALONE STATES NO CURVE, AND ITS STRENGTH IS THE CURVE'S. It was
        # `current` while RSA and DH with no size were `unassessed` — the same
        # missing fact judged two ways.
        return DeprecationVerdict(
            "unassessed",
            "An elliptic-curve primitive whose curve was not reported, so its strength "
            "could not be assessed. Curves below 224 bits are disallowed.",
            "NIST SP 800-131A Rev. 2",
        )
    if is_bare_ec(name, primitive):
        # JCA's `EC` with no curve reported: its strength IS the curve's.
        return DeprecationVerdict(
            "unassessed",
            "An elliptic-curve key or algorithm whose curve was not reported, so its "
            "strength could not be assessed. Curves below 224 bits are disallowed.",
            "NIST SP 800-131A Rev. 2",
        )
    if re.search(r"\bdsa\b(?!\w)", lowered):
        return DeprecationVerdict(
            "deprecated",
            "DSA is withdrawn for new signatures; NIST allows verification only.",
            "FIPS 186-5",
        )

    if _KNOWN_CURRENT.search(lowered):
        return _CURRENT
    return _UNRECOGNISED


def _is_pkcs1_v15_key_transport(
    lowered: str, primitive: str, functions: set[str], padding: str
) -> bool:
    """PKCS#1 v1.5 padding used to ENCRYPT, never to sign.

    ⚠ ONLY WHEN THE USE IS KNOWN. theia reports its RSA `pke` asset with
    `encapsulate, decapsulate, sign` together; calling that key transport would
    be a guess, and this verdict is one a reviewer acts on.
    """
    normalized = padding.strip().lower().replace("-", "").replace("_", "").replace(" ", "")
    v15 = normalized in {"pkcs1v15", "pkcs1v1.5", "pkcs1padding"} or bool(
        _PKCS1_V15.search(lowered)
    )
    if not v15:
        return False
    if _RSA_CIPHER_TRANSFORMATION.search(lowered):
        return True
    signing = bool(functions & {"sign", "verify", "signature"})
    encrypting = bool(functions & {"encrypt", "decrypt", "encapsulate", "decapsulate"})
    return not signing and (encrypting or primitive.strip().lower() in {"pke", "kem"})


def _rsa_verdict(bits: int | None) -> DeprecationVerdict:
    if bits is None:
        # ⚠ NOT ASSESSED, NOT ASSUMED FINE. An RSA key with no reported size is
        # the one most likely to be a legacy 1024-bit key; reporting it as
        # `current` hid exactly the asset a reviewer is looking for.
        return DeprecationVerdict(
            "unassessed",
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
            "unassessed",
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


# ---------------------------------------------------------------------------
# Protocols
# ---------------------------------------------------------------------------

_VERSION = re.compile(r"(\d+)(?:\.(\d+))?")


def _version(
    protocol_version: str, lowered_name: str, marker: str
) -> tuple[int, int | None] | None:
    """`1.2`, `TLSv1.2`, `v3`, or failing those a version in the name itself."""
    text = protocol_version.strip().lower()
    if not text:
        found = re.search(rf"{marker}\s*v?(\d+(?:\.\d+)?)", lowered_name)
        text = found.group(1) if found else ""
    match = _VERSION.search(text)
    if not match:
        return None
    return int(match.group(1)), (int(match.group(2)) if match.group(2) is not None else None)


def _protocol_verdict(lowered: str, protocol_version: str) -> DeprecationVerdict:
    """A protocol's verdict is its VERSION's verdict.

    ⚠ A NAME ALONE IS NOT ENOUGH. `TLS` is current at 1.3 and deprecated at 1.0,
    so a protocol asset with no version is unassessed — never current by default.
    """
    if re.search(r"\bdtls", lowered):
        version = _version(protocol_version, lowered, "dtls")
        if version is None:
            return _unversioned("DTLS", "DTLS 1.0 is deprecated (RFC 8996).")
        if version[0] == 1 and version[1] in (None, 0):
            return DeprecationVerdict("deprecated", "DTLS 1.0 is deprecated.", "RFC 8996")
        return _CURRENT
    if re.search(r"\btls", lowered):
        version = _version(protocol_version, lowered, "tls")
        if version is None:
            return _unversioned("TLS", "TLS 1.0 and 1.1 are deprecated (RFC 8996).")
        if version[0] == 1 and version[1] in (0, 1):
            return DeprecationVerdict(
                "deprecated",
                f"TLS 1.{version[1]} is deprecated; use TLS 1.2 or 1.3.",
                "RFC 8996",
            )
        if version[0] == 1 and version[1] in (2, 3):
            return _CURRENT
        return _unversioned("TLS", "TLS 1.0 and 1.1 are deprecated (RFC 8996).")
    if re.search(r"\bssl", lowered):
        # Every SSL version is prohibited, so no version is needed to say so.
        return DeprecationVerdict(
            "broken",
            "SSL 2.0 and 3.0 are prohibited: both have practical attacks (POODLE against SSL 3.0).",
            "RFC 6176 / RFC 7568",
        )
    if re.search(r"\bssh", lowered):
        version = _version(protocol_version, lowered, "ssh")
        if version is None:
            return _unversioned("SSH", "SSH protocol version 1 is obsolete.")
        if version[0] == 1:
            return DeprecationVerdict(
                "weak",
                "SSH protocol version 1 is obsolete and has known practical "
                "weaknesses; SSH-2 replaced it.",
                "RFC 4253",
            )
        return _CURRENT
    if re.search(r"\bike|\bipsec", lowered):
        if re.search(r"\bikev1\b", lowered):
            return _ikev1()
        version = _version(protocol_version, lowered, "ike")
        if version is None:
            return _unversioned("IKE", "IKEv1 is deprecated (RFC 9395).")
        return _ikev1() if version[0] == 1 else _CURRENT
    if re.search(r"\bquic\b", lowered):
        return _CURRENT
    return DeprecationVerdict(
        "unassessed",
        "No rule recognises this protocol, so it was not assessed rather than assumed current.",
    )


def _unversioned(protocol: str, context: str) -> DeprecationVerdict:
    return DeprecationVerdict(
        "unassessed",
        f"The {protocol} version was not reported, so it could not be assessed. {context}",
    )


def _ikev1() -> DeprecationVerdict:
    return DeprecationVerdict("deprecated", "IKEv1 is deprecated; use IKEv2.", "RFC 9395")


# ⚠ NO TRAILING \b ON THE FAMILY TOKENS BELOW, AND THAT IS NOT AN OVERSIGHT.
#
# `rsa` does NOT match `rsaEncryption`: the boundary needs a non-word
# character after `rsa`, and `E` is a word character. The same failure hides
# `modp2048` and `Kyber1024` — which is to say most of the names these actually
# appear under in tool output. Six rules were written that way first, and every
# one silently reported a broken primitive as unassessed.
_BITS = re.compile(r"(?:rsa|dh|dsa|modp|ffdhe)[-_]?(\d{3,5})", re.I)


def _bits_from_name(name: str) -> int | None:
    """Recover a key size from a name like `RSA-2048`, `modp2048` or `ffdhe2048`.

    Narrow on purpose: a general "find a number" rule reads the 1 in `PKCS#1`
    as a key size, and this value decides whether an asset is reported broken.
    """
    match = _BITS.search(name)
    return int(match.group(1)) if match else None
