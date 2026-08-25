"""Post-quantum migration guidance.

⚠ EVERY RECOMMENDATION CITES A PUBLISHED NIST STANDARD. NOTHING IS INVENTED.

A customer reads this and plans a migration against it. Guidance we made up
would be worse than no guidance: they would spend a quarter implementing it, and
the error would surface at an audit rather than in review.

So the rules only map a broken primitive onto the NIST algorithm that replaces
it, with the standard's number attached. Where NIST has not standardised a
replacement — and there are such cases — this says so instead of suggesting
something plausible.

Standards referenced:

    FIPS 203  ML-KEM (Kyber)      key establishment
    FIPS 204  ML-DSA (Dilithium)  digital signatures
    FIPS 205  SLH-DSA (SPHINCS+)  digital signatures, hash-based
    SP 800-208                    LMS / XMSS stateful hash-based signatures

FN-DSA (Falcon) is announced but not yet published as a FIPS; it is named as
such rather than recommended outright.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PQCRecommendation:
    """What to migrate a broken primitive to."""

    #: The replacement family, e.g. `ML-KEM`. Empty when none is standardised.
    algorithm: str
    #: The standard that defines it, e.g. `FIPS 203`.
    standard: str
    #: The mathematical family: lattice, hash-based, code-based, multivariate.
    category: str
    #: One sentence a reader can act on.
    guidance: str
    #: True when NIST has published a final standard for this use.
    standardised: bool = True

    def summary(self) -> str:
        """A single line for the `pqc_recommendation` column."""
        if not self.algorithm:
            return self.guidance
        return f"{self.algorithm} ({self.standard}, {self.category}): {self.guidance}"


#: Key establishment — what RSA key transport and (EC)DH are replaced by.
_KEY_ESTABLISHMENT = PQCRecommendation(
    algorithm="ML-KEM",
    standard="FIPS 203",
    category="lattice",
    guidance=(
        "Replace key establishment with ML-KEM. NIST recommends a HYBRID "
        "deployment during transition — ML-KEM alongside the existing "
        "primitive — so a flaw in either does not break the handshake."
    ),
)

#: Signatures — what RSA, ECDSA and DSA signing are replaced by.
_SIGNATURE = PQCRecommendation(
    algorithm="ML-DSA",
    standard="FIPS 204",
    category="lattice",
    guidance=(
        "Replace signatures with ML-DSA. SLH-DSA (FIPS 205, hash-based) is the "
        "conservative alternative where a lattice assumption is unacceptable, "
        "at the cost of much larger signatures."
    ),
)

#: Firmware and long-lived code signing.
_STATEFUL_HASH = PQCRecommendation(
    algorithm="LMS / XMSS",
    standard="SP 800-208",
    category="hash-based",
    guidance=(
        "For firmware and long-lived code signing, stateful hash-based "
        "signatures are already standardised. They require careful state "
        "management — reusing a one-time key destroys security."
    ),
)


def recommend_pqc(
    *,
    family: str,
    quantum_vulnerable: bool,
    crypto_functions: list[str] | None = None,
    name: str = "",
) -> PQCRecommendation | None:
    """Recommend a replacement, or return None when there is nothing to say.

    ⚠ None IS A REAL ANSWER AND THE COMMON ONE. A recommendation attached to
    AES-256 would put it on a migration list it does not belong on, which is the
    same error as flagging it quantum-vulnerable — just wearing a suit.
    """
    if not quantum_vulnerable:
        return None

    functions = {f.lower() for f in (crypto_functions or [])}
    lowered = f"{family} {name}".lower()

    # ⚠ THE USE DECIDES THE REPLACEMENT, NOT THE PRIMITIVE. RSA does key
    # transport AND signing, and they migrate to different algorithms. A
    # recommendation keyed only on "RSA" sends half of them to the wrong one.
    signing = bool(functions & {"sign", "verify", "signature", "digital-signature"})
    establishment = bool(
        functions
        & {
            "keygen",
            "encapsulate",
            "decapsulate",
            "key-agree",
            "keyagreement",
            "encrypt",
            "decrypt",
        }
    )

    if signing and not establishment:
        if "firmware" in lowered or "code" in lowered:
            return _STATEFUL_HASH
        return _SIGNATURE
    if establishment and not signing:
        return _KEY_ESTABLISHMENT

    # No crypto_functions reported, or both. Fall back to what the family is
    # overwhelmingly used for, and SAY that it is a fallback.
    if family in {"dh"}:
        return _KEY_ESTABLISHMENT
    if family in {"dsa"}:
        return _SIGNATURE
    if family in {"rsa", "ecc"}:
        return PQCRecommendation(
            algorithm="ML-KEM or ML-DSA",
            standard="FIPS 203 / FIPS 204",
            category="lattice",
            guidance=(
                "This asset reports no crypto functions, so its use could not be "
                "determined. Key establishment migrates to ML-KEM (FIPS 203); "
                "signatures migrate to ML-DSA (FIPS 204). Check which this is."
            ),
        )

    # ⚠ A VULNERABLE FAMILY WITH NO STANDARDISED REPLACEMENT SAYS SO.
    # Suggesting something plausible here would be exactly the invented guidance
    # this module exists to avoid.
    return PQCRecommendation(
        algorithm="",
        standard="",
        category="",
        standardised=False,
        guidance=(
            f"This primitive is broken by Shor's algorithm, and NIST has not "
            f"published a standardised replacement for the {family} family. "
            f"Treat it as requiring migration and choose a replacement with "
            f"cryptographic advice."
        ),
    )
