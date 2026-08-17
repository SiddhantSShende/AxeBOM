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
#: ⚠ NO TRAILING  ON THE ALGORITHM TOKENS, AND THAT IS NOT AN OVERSIGHT.
#:
#: `rsa` does NOT match `rsaEncryption` — the boundary requires a non-word
#: character after `rsa`, and `E` is a word character. The same failure hides
#: `modp2048`, `Kyber1024` and `Dilithium3`, which is to say most of the names
#: these actually appear under in tool output. Six rules were written this way
#: first and every one of them silently reported a broken primitive as
#: unassessed.
#:
#: Matched on the primitive name AND the algorithm name, because tools disagree
#: about which field carries it — cbomkit-theia puts `signature` in `primitive`
#: and `RSA-2048` in `name`, so keying on either alone misses half the assets.
_SHOR_FAMILIES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "rsa",
        re.compile(r"\brsa|\bpkcs#?1\b", re.I),
        "RSA rests on integer factorisation, which Shor's algorithm solves in polynomial time.",
    ),
    (
        "ecc",
        re.compile(
            r"\becdsa\b|\becdh\b|\becies\b|\bed25519\b|\bed448\b|\bx25519\b|\bx448\b"
            r"|\bsecp\d|\bprime\d{3}v\d|\bbrainpool|\bnistp\d|\bcurve25519\b|\becc\b",
            re.I,
        ),
        "Elliptic-curve cryptography rests on the discrete logarithm problem, "
        "which Shor's algorithm solves in polynomial time.",
    ),
    (
        "dh",
        re.compile(r"\bdiffie[- ]?hellman\b|\bdhe?\b(?!\w)|\bmodp", re.I),
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

#: Symmetric and hash primitives Grover speeds up without breaking.
_GROVER_FAMILIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aes", re.compile(r"\baes\b", re.I)),
    ("chacha", re.compile(r"\bchacha20?\b|\bsalsa20\b", re.I)),
    ("3des", re.compile(r"\b3des\b|\btriple[- ]?des\b|\bdes-ede\b", re.I)),
    ("des", re.compile(r"\bdes\b(?!-ede)", re.I)),
    ("camellia", re.compile(r"\bcamellia\b", re.I)),
    ("sha2", re.compile(r"\bsha-?(224|256|384|512)\b|\bsha2\b", re.I)),
    ("sha3", re.compile(r"\bsha-?3\b|\bshake\d*\b", re.I)),
    ("sha1", re.compile(r"\bsha-?1\b", re.I)),
    ("md5", re.compile(r"\bmd5\b", re.I)),
    ("hmac", re.compile(r"\bhmac\b", re.I)),
)

#: Post-quantum families. Already quantum-resistant; flagging them would tell a
#: customer to migrate away from the thing they migrated to.
_PQC_FAMILIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ml-kem", re.compile(r"\bml-?kem|\bkyber", re.I)),
    ("ml-dsa", re.compile(r"\bml-?dsa|\bdilithium", re.I)),
    ("slh-dsa", re.compile(r"\bslh-?dsa|\bsphincs", re.I)),
    ("falcon", re.compile(r"\bfalcon\b|\bfn-?dsa", re.I)),
    ("lms", re.compile(r"\blms\b|\bxmss\b|\bhss\b", re.I)),
    ("mceliece", re.compile(r"\bmceliece\b|\bbike\b|\bhqc\b", re.I)),
)


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

    for family, pattern in _PQC_FAMILIES:
        if pattern.search(haystack):
            return QuantumVerdict(
                quantum_vulnerable=False,
                family=family,
                rationale=(
                    "A NIST post-quantum algorithm. Designed to resist both "
                    "Shor and Grover; no migration needed."
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

    # ⚠ THE THRESHOLD IS 128 BITS OF *QUANTUM* SECURITY, which is 256 classical.
    # AES-128 lands at 64 and is worth resizing; AES-256 lands at 128 and is
    # not. Getting this backwards is how AES-256 ends up on a migration list.
    if effective >= 128:
        note = (
            f"{bits}-bit key gives roughly {effective} bits of security against "
            f"Grover's algorithm, which is comfortably beyond reach. No action."
        )
    else:
        note = (
            f"{bits}-bit key gives roughly {effective} bits of security against "
            f"Grover's algorithm. Consider a {bits * 2}-bit key where the "
            f"protocol allows it. This is a sizing decision, not a break."
        )

    return QuantumVerdict(
        quantum_vulnerable=False,
        family=family,
        rationale=(
            "A symmetric primitive. Grover's algorithm halves effective key "
            "strength — a sizing concern, not a break, so this is NOT reported "
            "as quantum-vulnerable."
        ),
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
        if re.search(r"\b3des\b|\btriple[- ]?des\b", name, re.I):
            # 3DES has a 168-bit key with roughly 112 bits of effective
            # classical security (meet-in-the-middle). The lower figure is the
            # honest one to halve.
            return 112
        if re.search(r"\bdes\b", name, re.I):
            return 56
        return None
    return int(match.group(1))
