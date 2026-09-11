"""Quantum-vulnerability rules.

⚠ SHOR BREAKS; GROVER RESIZES. THE PRODUCT MUST NOT CONFLATE THEM.

Shor's algorithm solves integer factorisation and discrete logarithms in
polynomial time. Every asymmetric primitive whose security rests on either —
RSA, DSA, Diffie-Hellman, and the whole elliptic-curve family — is *broken* by a
sufficiently large quantum computer. Those get `quantum_vulnerable = true`.

Grover's algorithm gives a quadratic speed-up on unstructured search, which
halves the *effective* strength of a symmetric key: AES-128 drops to about 64
bits of quantum security, AES-256 to about 128. That is a **sizing concern, not
a break**, and AES-256 at 128 bits of quantum security is comfortably beyond
reach.

⚠ FLAGGING AES-256 AS QUANTUM-VULNERABLE WOULD SIMPLY BE WRONG, and it is the
easy mistake: "quantum affects it" is true of both families, so a single boolean
over "is it affected" produces a migration list containing every cipher a
customer uses. A security team handed that list learns to ignore it, which
costs them the RSA entries that genuinely matter.

So symmetric primitives get a NOTE on effective strength and no flag.

Sources are cited in the rules themselves. Nothing here is invented guidance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ._text import search_text


@dataclass(frozen=True)
class QuantumVerdict:
    """What quantum computing does to one cryptographic asset."""

    #: True only for Shor-breakable primitives. Never for symmetric ones.
    quantum_vulnerable: bool
    #: The primitive family this was matched as, e.g. `rsa`, `ecc`, `aes`.
    family: str
    #: Why. Rendered in the report next to the flag.
    rationale: str
    #: Effective post-quantum security in bits, where it is calculable.
    #: None when the classical strength is unknown — a guess here would be a
    #: number a customer sizes a migration against.
    effective_quantum_bits: int | None = None
    #: Present for symmetric primitives: the Grover note.
    grover_note: str = ""
    diagnostics: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Family detection
# ---------------------------------------------------------------------------

#: Asymmetric families Shor breaks outright.
#:
#: ⚠ NO TRAILING \b ON THE ALGORITHM TOKENS, AND THAT IS NOT AN OVERSIGHT.
#:
#: `rsa` does NOT match `rsaEncryption` — the boundary requires a non-word
#: character after `rsa`, and `E` is a word character. The same failure hides
#: `modp2048`, `Kyber1024` and `Dilithium3`, which is to say most of the names
#: these actually appear under in tool output. Six rules were written this way
#: first and every one of them silently reported a broken primitive as
#: unassessed.
#:
#: Matched on the primitive name AND the algorithm name, because tools disagree
#: about which field carries it — cbomkit-theia puts `signature` in `primitive`
#: and `RSA-2048` in `name`, so keying on either alone misses half the assets.
#:
#: ⚠ ECC IS CHECKED BEFORE DSA. `EdDSA` tokenizes to `Ed DSA`, and with `dsa`
#: first Ed25519's family was reported as `dsa`.
_SHOR_FAMILIES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "rsa",
        re.compile(r"\brsa|\bpkcs#?1\b", re.I),
        "RSA rests on integer factorisation, which Shor's algorithm solves in polynomial time.",
    ),
    (
        "ecc",
        re.compile(
            r"\becdsa\b|\becdh\b|\becies\b|\beddsa\b|\bed25519\b|\bed448\b|\bx25519\b|\bx448\b"
            r"|\bsecp\d|\bprime\d{3}v\d|\bbrainpool|\bnistp\d|\bcurve25519\b|\bcurve448\b"
            r"|\bp-?(?:192|224|256|384|521)\b|\becc\b",
            re.I,
        ),
        "Elliptic-curve cryptography rests on the discrete logarithm problem, "
        "which Shor's algorithm solves in polynomial time.",
    ),
    (
        "dh",
        re.compile(r"\bdiffie[- ]?hellman\b|\bdhe?\b(?!\w)|\bmodp|\bffdhe", re.I),
        "Diffie-Hellman rests on the discrete logarithm problem, which Shor's "
        "algorithm solves in polynomial time.",
    ),
    (
        "dsa",
        re.compile(r"\bdsa\b(?!\w)", re.I),
        "DSA rests on the discrete logarithm problem, which Shor's algorithm "
        "solves in polynomial time.",
    ),
)

_ECC_RATIONALE = next(r for f, _, r in _SHOR_FAMILIES if f == "ecc")

#: Symmetric and hash primitives Grover speeds up without breaking.
#:
#: ⚠ `3des` BEFORE `des`, and `3des` knows Java's `DESede` and NIST's `TDEA` —
#: the tokenizer splits `DESede` into `DE Sede`, which matched nothing.
_GROVER_FAMILIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aes", re.compile(r"\baes\b", re.I)),
    ("chacha", re.compile(r"\bchacha20?\b|\bsalsa20\b", re.I)),
    ("3des", re.compile(r"\b3des\b|\btriple[- ]?des\b|\bdes-?ede3?\b|\bdesede\b|\btdea\b", re.I)),
    ("des", re.compile(r"\bdes\b(?!-ede)", re.I)),
    ("camellia", re.compile(r"\bcamellia\b", re.I)),
    ("rc4", re.compile(r"\brc4\b|\barcfour\b", re.I)),
    ("rc2", re.compile(r"\brc2\b", re.I)),
    ("blowfish", re.compile(r"\bblowfish\b", re.I)),
    ("sha2", re.compile(r"\bsha-?(224|256|384|512)\b|\bsha2\b", re.I)),
    ("sha3", re.compile(r"\bsha-?3\b|\bshake\d*\b", re.I)),
    ("sha1", re.compile(r"\bsha-?1\b", re.I)),
    ("md5", re.compile(r"\bmd5\b", re.I)),
    ("hmac", re.compile(r"\bhmac\b", re.I)),
)

#: Post-quantum families. Already quantum-resistant; flagging them would tell a
#: customer to migrate away from the thing they migrated to.
#:
#: ⚠ HQC IS ITS OWN FAMILY. It was folded into `mceliece`, which misnamed the
#: one code-based KEM NIST actually selected (March 2025) as a scheme it did not.
_PQC_FAMILIES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("ml-kem", re.compile(r"\bml-?kem|\bkyber", re.I), "ML-KEM (FIPS 203, final)"),
    ("ml-dsa", re.compile(r"\bml-?dsa|\bdilithium", re.I), "ML-DSA (FIPS 204, final)"),
    ("slh-dsa", re.compile(r"\bslh-?dsa|\bsphincs", re.I), "SLH-DSA (FIPS 205, final)"),
    (
        "falcon",
        re.compile(r"\bfalcon\b|\bfn-?dsa", re.I),
        "FN-DSA / Falcon (NIST-selected; not a final standard in this ruleset)",
    ),
    ("lms", re.compile(r"\blms\b|\bxmss|\bhss\b", re.I), "LMS / XMSS (NIST SP 800-208)"),
    (
        "hqc",
        re.compile(r"\bhqc\b", re.I),
        "HQC (NIST-selected March 2025; no final standard yet)",
    ),
    (
        "mceliece",
        re.compile(r"\bmceliece\b|\bbike\b", re.I),
        "a code-based scheme NIST has not standardised",
    ),
)

#: The family names from _PQC_FAMILIES, public. workers/qbom/derive.py used to
#: hand-copy these strings into its own PQC_FAMILIES constant — derived here
#: instead, so the two can no longer drift apart.
PQC_FAMILIES: frozenset[str] = frozenset(family for family, _, _ in _PQC_FAMILIES)


def is_bare_ec(*parts: str) -> bool:
    """True when a name or primitive IS `EC` — JCA's and OpenSSL's name for an
    elliptic-curve key (`KeyPairGenerator.getInstance("EC")`), curve unstated.

    ⚠ A WHOLE FIELD, NEVER A WORD IN THE HAYSTACK. `ec` is two hex digits: as a
    word it matched nothing real and risked an unresolved bom-ref UUID. Unmatched
    at all, an elliptic-curve key was reported NOT quantum-vulnerable
    (fixtures/crypto-quantum, 2026-09-11).
    """
    return any(isinstance(p, str) and p.strip().lower() == "ec" for p in parts)


def pqc_family(*parts: str) -> str | None:
    """The post-quantum family these names belong to, or None.

    Public so the deprecation rules can check post-quantum BEFORE their legacy
    DSA rule — the ordering bug that reported ML-DSA as deprecated DSA.
    """
    haystack = search_text(*parts)
    for family, pattern, _ in _PQC_FAMILIES:
        if pattern.search(haystack):
            return family
    return None


def assess_quantum(
    *,
    name: str,
    primitive: str = "",
    key_size: int | None = None,
    classical_security_level: int | None = None,
    asset_type: str = "algorithm",
) -> QuantumVerdict:
    """Assess one crypto asset.

    All the identifying strings are searched together, because tools put the
    algorithm in different fields and a rule keyed on one of them misses assets
    that are plainly RSA.
    """
    # Raw name AND its tokens, so a rule matches either form — see
    # _text.search_text for why replacing one with the other is wrong.
    haystack = search_text(name, primitive)

    if not haystack:
        # ⚠ AN UNNAMED ASSET IS NOT ASSESSED, AND IS NOT FLAGGED SAFE EITHER.
        # Defaulting to `quantum_vulnerable = false` would hide it from the
        # migration list; defaulting to true would fill that list with noise.
        # The diagnostic is what makes the gap visible.
        return QuantumVerdict(
            quantum_vulnerable=False,
            family="unknown",
            rationale="",
            diagnostics=["crypto asset has no name or primitive; not assessed"],
        )

    for family, pattern, standing in _PQC_FAMILIES:
        if pattern.search(haystack):
            return QuantumVerdict(
                quantum_vulnerable=False,
                family=family,
                rationale=(
                    f"A post-quantum algorithm — {standing}. Designed to resist both "
                    f"Shor and Grover; no migration needed."
                ),
            )

    for family, pattern, rationale in _SHOR_FAMILIES:
        if pattern.search(haystack):
            return QuantumVerdict(
                quantum_vulnerable=True,
                family=family,
                rationale=rationale,
                # ⚠ ZERO, NOT "SMALL". Shor does not weaken these; it solves
                # them. Reporting a reduced bit-strength would suggest a larger
                # key is a mitigation, which for RSA and ECC it is not.
                effective_quantum_bits=0,
            )
    if is_bare_ec(name, primitive):
        return QuantumVerdict(
            quantum_vulnerable=True,
            family="ecc",
            rationale=_ECC_RATIONALE,
            effective_quantum_bits=0,
        )

    for family, pattern in _GROVER_FAMILIES:
        if pattern.search(haystack):
            return _grover_verdict(family, haystack, key_size, classical_security_level)

    return QuantumVerdict(
        quantum_vulnerable=False,
        family="unknown",
        rationale="",
        diagnostics=[
            f"no quantum rule matches {asset_type} {haystack!r}; "
            "not assessed rather than assumed safe"
        ],
    )


#: Hashes: Grover bounds PREIMAGE resistance by half the digest length. The
#: advice is about the digest, never about "a key".
_HASH_FAMILIES = frozenset({"sha2", "sha3"})

#: Families whose classical verdict already says "migrate". A resizing hint on
#: them would be advice nobody should follow.
_LEGACY_FAMILIES: dict[str, str] = {
    "3des": "3DES",
    "des": "DES",
    "rc4": "RC4",
    "rc2": "RC2",
    "blowfish": "Blowfish",
    "sha1": "SHA-1",
    "md5": "MD5",
}


def _grover_verdict(
    family: str,
    haystack: str,
    key_size: int | None,
    classical_level: int | None,
) -> QuantumVerdict:
    """Build the note for a symmetric or hash primitive.

    ⚠ NO FLAG IS SET HERE, EVER. That is the whole point of the split.
    """
    bits = key_size or classical_level or _bits_from_name(haystack)
    rationale = (
        "A symmetric primitive. Grover's algorithm halves effective key "
        "strength — a sizing concern, not a break, so this is NOT reported "
        "as quantum-vulnerable."
    )

    if family in _LEGACY_FAMILIES:
        # ⚠ THE OLD NOTE TOLD A 3DES USER TO "CONSIDER A 224-BIT KEY" — a size
        # 3DES does not have, on a cipher NIST already disallows. The classical
        # verdict is the one that matters, and the note says so.
        label = _LEGACY_FAMILIES[family]
        return QuantumVerdict(
            quantum_vulnerable=False,
            family=family,
            rationale=rationale,
            effective_quantum_bits=bits // 2 if bits else None,
            grover_note=(
                f"{label} is already deprecated or broken classically (see its "
                f"deprecation status); Grover's algorithm is not the concern. "
                f"Migrate rather than resize."
            ),
        )

    if bits is None:
        return QuantumVerdict(
            quantum_vulnerable=False,
            family=family,
            rationale=(
                "A symmetric primitive. Grover's algorithm halves effective key "
                "strength, which is a sizing concern rather than a break."
            ),
            grover_note=(
                "Effective post-quantum strength could not be calculated because "
                "no key size was reported."
            ),
            diagnostics=[f"{family}: no key size, so effective strength is not calculable"],
        )

    effective = bits // 2
    unit = "digest" if family in _HASH_FAMILIES else "key"
    resistance = "preimage resistance" if family in _HASH_FAMILIES else "security"

    # ⚠ THE THRESHOLD IS 128 BITS OF *QUANTUM* SECURITY, which is 256 classical.
    # AES-128 lands at 64 and is worth resizing; AES-256 lands at 128 and is
    # not. Getting this backwards is how AES-256 ends up on a migration list.
    if effective >= 128:
        note = (
            f"{bits}-bit {unit} gives roughly {effective} bits of {resistance} against "
            f"Grover's algorithm, which is comfortably beyond reach. No action."
        )
    else:
        # ⚠ THE ADVICE NAMES A SIZE THE PRIMITIVE HAS. "Consider a 384-bit key"
        # for AES-192 was double the size, on a cipher whose largest key is 256.
        if family in _HASH_FAMILIES:
            advice = "Consider SHA-384 or SHA-512 where the protocol allows it."
        elif family in {"aes", "camellia"}:
            advice = "Consider a 256-bit key (AES-256) where the protocol allows it."
        else:
            advice = "Consider a 256-bit key where the protocol allows it."
        note = (
            f"{bits}-bit {unit} gives roughly {effective} bits of {resistance} against "
            f"Grover's algorithm. {advice} This is a sizing decision, not a break."
        )

    return QuantumVerdict(
        quantum_vulnerable=False,
        family=family,
        rationale=rationale,
        effective_quantum_bits=effective,
        grover_note=note,
    )


#: Trailing digits in a name are the key size for most symmetric primitives:
#: AES-256, ChaCha20 (which is not a key size), SHA-512.
_BITS_IN_NAME = re.compile(r"(?:aes|camellia|sha-?3?|shake)[-_]?(\d{3,4})", re.I)


def _bits_from_name(name: str) -> int | None:
    """Recover a key size from a name like `AES-256`.

    ⚠ DELIBERATELY NARROW. `ChaCha20` ends in 20 and has a 256-bit key; `3DES`
    starts with a 3. A general "find the number" rule produces confident wrong
    answers, and this value is what a customer sizes a migration against.
    """
    match = _BITS_IN_NAME.search(name)
    if not match:
        # ChaCha20 and Salsa20 are always 256-bit in practice, but the name says
        # 20. Named explicitly rather than pattern-matched.
        if re.search(r"\bchacha20\b|\bsalsa20\b", name, re.I):
            return 256
        if re.search(r"\b3des\b|\btriple[- ]?des\b|\bdesede\b|\btdea\b|\bdes-?ede3?\b", name, re.I):
            # 3DES has a 168-bit key with roughly 112 bits of effective
            # classical security (meet-in-the-middle). The lower figure is the
            # honest one to halve.
            return 112
        if re.search(r"\bdes\b", name, re.I):
            return 56
        return None
    return int(match.group(1))


def readiness_group(
    *, quantum_vulnerable: bool, grover_note: str, quantum_family: str
) -> str | None:
    """Classify one asset into QuantumReadiness's four buckets.

    ⚠ THE SINGLE SOURCE FOR THIS CLASSIFICATION. Both
    workers/cbom/normalize/crypto.py's analyse() (which stores the result on
    normalize.crypto_assets.quantum_readiness_group, migrations/normalize/0005)
    and workers/qbom/derive.py's derive_readiness() (which groups a document's
    worth of already-classified assets for the report) call this rather than
    each keeping their own copy of the branch — one rule change, one place,
    so the CBOM and the QBOM can never disagree about which bucket an asset
    is in.

    Returns None when nothing matches — an asset this deliberately leaves
    unbucketed, exactly as derive_readiness's original elif chain did.
    """
    if quantum_vulnerable:
        return "vulnerable"
    if grover_note:
        return "grover_note"
    if quantum_family in PQC_FAMILIES:
        return "post_quantum"
    if quantum_family == "unknown":
        return "unassessed"
    return None
