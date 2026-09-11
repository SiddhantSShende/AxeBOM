"""Tests for the crypto analysis rules.

The phase's headline requirement is one line: RSA/ECC/DH/DSA are flagged,
AES-256 is not, and AES-256 carries a Grover note instead. That distinction is
what most of this file defends.
"""

from __future__ import annotations

import pytest

from axebom_shared.crypto import assess_deprecation, assess_quantum, recommend_pqc
from axebom_shared.crypto._text import search_text, tokenize

# ---------------------------------------------------------------------------
# Shor: what is actually broken
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "RSA-2048",
        "RSASSA-PSS",
        "rsaEncryption",
        "ECDSA",
        "ecdsa-with-SHA256",
        "ECDH",
        "X25519",
        "Ed25519",
        "secp256r1",
        "brainpoolP256r1",
        "Diffie-Hellman",
        "DHE-RSA",
        "modp2048",
        "DSA",
    ],
)
def test_shor_breakable_primitives_are_flagged(name: str) -> None:
    verdict = assess_quantum(name=name)
    assert verdict.quantum_vulnerable, f"{name} should be flagged"
    # ⚠ ZERO, NOT "REDUCED". Shor does not weaken these, it solves them —
    # reporting a smaller bit-strength would suggest a longer key is a
    # mitigation, which for RSA and ECC it is not.
    assert verdict.effective_quantum_bits == 0
    assert verdict.rationale, "a flag with no rationale is an unactionable alarm"


@pytest.mark.parametrize(
    ("name", "expected_family"),
    [
        ("RSA-4096", "rsa"),
        ("ECDSA-P256", "ecc"),
        ("Diffie-Hellman group 14", "dh"),
        ("DSA-1024", "dsa"),
    ],
)
def test_the_family_is_reported(name: str, expected_family: str) -> None:
    assert assess_quantum(name=name).family == expected_family


# ---------------------------------------------------------------------------
# Grover: what is NOT broken
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["AES-256", "AES-128", "ChaCha20", "Camellia-256", "SHA-256", "SHA3-512", "HMAC-SHA256"],
)
def test_symmetric_primitives_are_never_flagged_quantum_vulnerable(name: str) -> None:
    """⚠ THE PHASE'S HEADLINE REQUIREMENT.

    Grover halves EFFECTIVE key strength. That is a sizing concern, not a break,
    and flagging AES-256 as quantum-vulnerable would be wrong — it would also
    fill a migration list with every cipher a customer uses, at which point the
    RSA entries that genuinely matter get lost in it.
    """
    verdict = assess_quantum(name=name)
    assert not verdict.quantum_vulnerable, f"{name} must not be flagged"


def test_aes_256_carries_a_grover_note_saying_no_action() -> None:
    verdict = assess_quantum(name="AES-256")
    assert not verdict.quantum_vulnerable
    # 256-bit key -> ~128 bits against Grover, comfortably beyond reach.
    assert verdict.effective_quantum_bits == 128
    assert "no action" in verdict.grover_note.lower()


def test_aes_128_is_advised_to_resize_without_being_flagged() -> None:
    verdict = assess_quantum(name="AES-128")
    assert not verdict.quantum_vulnerable
    assert verdict.effective_quantum_bits == 64
    # The advice is a SIZING decision, and the note has to say so or a reader
    # treats it as a break.
    assert "256-bit" in verdict.grover_note
    assert "not a break" in verdict.grover_note.lower()


def test_the_grover_threshold_is_quantum_bits_not_classical() -> None:
    """⚠ GETTING THIS BACKWARDS PUTS AES-256 ON THE MIGRATION LIST.

    The threshold is 128 bits of QUANTUM security, which is 256 classical.
    A rule comparing the classical size against 128 would clear AES-128 and
    condemn nothing — or, reversed, condemn AES-256.
    """
    assert assess_quantum(name="AES-128").effective_quantum_bits == 64
    assert assess_quantum(name="AES-256").effective_quantum_bits == 128
    assert "no action" in assess_quantum(name="AES-256").grover_note.lower()
    assert "no action" not in assess_quantum(name="AES-128").grover_note.lower()


def test_chacha20_is_read_as_256_bit_not_20_bit() -> None:
    """The name ends in 20 and the key is 256 bits.

    A general "find the trailing number" rule would report 10 bits of effective
    strength and put ChaCha20 at the top of a migration list.
    """
    assert assess_quantum(name="ChaCha20").effective_quantum_bits == 128


# ---------------------------------------------------------------------------
# Post-quantum algorithms
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["ML-KEM-768", "Kyber1024", "ML-DSA-65", "Dilithium3", "SPHINCS+"])
def test_pqc_algorithms_are_not_flagged(name: str) -> None:
    """Flagging these would tell a customer to migrate away from what they
    migrated to."""
    verdict = assess_quantum(name=name)
    assert not verdict.quantum_vulnerable
    assert "post-quantum" in verdict.rationale.lower()


# ---------------------------------------------------------------------------
# Unknowns
# ---------------------------------------------------------------------------


def test_an_unrecognised_primitive_is_not_assessed_rather_than_assumed_safe() -> None:
    """⚠ THE DEFAULT MATTERS IN BOTH DIRECTIONS.

    Defaulting to `quantum_vulnerable = false` hides an asset from the migration
    list; defaulting to true fills the list with noise. Neither is honest, so
    the flag stays false AND a diagnostic records that nothing was assessed.
    """
    verdict = assess_quantum(name="ACME-CIPHER-9000")
    assert not verdict.quantum_vulnerable
    assert verdict.family == "unknown"
    assert verdict.diagnostics, "an unassessed asset must be visible as unassessed"


def test_an_unnamed_asset_is_diagnosed() -> None:
    verdict = assess_quantum(name="", primitive="")
    assert verdict.diagnostics
    assert not verdict.quantum_vulnerable


def test_the_primitive_field_is_searched_as_well_as_the_name() -> None:
    """Tools disagree about which field carries the algorithm.

    cbomkit-theia puts `signature` in `primitive` and `RSA-2048` in `name`; a
    rule keyed on one field alone misses half the assets.
    """
    assert assess_quantum(name="signature", primitive="RSA").quantum_vulnerable
    assert assess_quantum(name="RSA-2048", primitive="signature").quantum_vulnerable


# ---------------------------------------------------------------------------
# PQC recommendations
# ---------------------------------------------------------------------------


def test_nothing_is_recommended_for_an_unflagged_asset() -> None:
    """A recommendation on AES-256 puts it on a migration list it does not
    belong on — the same error as flagging it, wearing a suit."""
    assert recommend_pqc(family="aes", quantum_vulnerable=False) is None


def test_signing_and_key_establishment_get_different_replacements() -> None:
    """⚠ RSA DOES BOTH, AND THEY MIGRATE TO DIFFERENT ALGORITHMS.

    A recommendation keyed only on "RSA" sends half of them to the wrong one.
    """
    signing = recommend_pqc(family="rsa", quantum_vulnerable=True, crypto_functions=["sign"])
    establishment = recommend_pqc(
        family="rsa", quantum_vulnerable=True, crypto_functions=["encapsulate"]
    )

    assert signing is not None and establishment is not None
    assert signing.algorithm == "ML-DSA"
    assert signing.standard == "FIPS 204"
    assert establishment.algorithm == "ML-KEM"
    assert establishment.standard == "FIPS 203"


def test_every_recommendation_cites_a_standard() -> None:
    """A customer plans a migration against this. Invented guidance would
    surface at an audit rather than in review."""
    for family, functions in [("rsa", ["sign"]), ("ecc", ["encapsulate"]), ("dh", []), ("dsa", [])]:
        rec = recommend_pqc(family=family, quantum_vulnerable=True, crypto_functions=functions)
        assert rec is not None
        assert rec.standard, f"{family} recommendation cites no standard"
        assert "FIPS" in rec.standard or "SP 800" in rec.standard


def test_an_unknown_use_says_so_rather_than_guessing() -> None:
    rec = recommend_pqc(family="rsa", quantum_vulnerable=True, crypto_functions=[])
    assert rec is not None
    assert "could not be determined" in rec.guidance
    # It names both, so a reader can pick — rather than silently choosing one.
    assert "ML-KEM" in rec.algorithm and "ML-DSA" in rec.algorithm


def test_a_family_with_no_standardised_replacement_says_so() -> None:
    rec = recommend_pqc(family="exotic", quantum_vulnerable=True)
    assert rec is not None
    assert not rec.standardised
    assert rec.algorithm == ""
    assert "has not published" in rec.guidance


@pytest.mark.parametrize(
    ("family", "name", "primitive", "functions", "want"),
    [
        # cbomkit-action reports every key-pair generator's function as `keygen`.
        ("ecc", "Ed25519", "signature", ["keygen"], "ML-DSA"),
        ("dsa", "DSA-2048", "signature", ["keygen"], "ML-DSA"),
        ("ecc", "x25519", "key-agree", ["keygen"], "ML-KEM"),
        ("rsa", "RSA-1024", "pke", ["keygen"], "ML-KEM"),
        # No functions and no primitive: a single-purpose name still states its use.
        ("ecc", "Ed25519", "", [], "ML-DSA"),
        ("ecc", "X25519", "", [], "ML-KEM"),
    ],
)
def test_generating_a_key_is_not_a_use(
    family: str, name: str, primitive: str, functions: list[str], want: str
) -> None:
    """⚠ `keygen` WAS COUNTED AS KEY ESTABLISHMENT. Every asymmetric algorithm
    generates keys, so Ed25519 and DSA — signature schemes — were told to migrate
    to ML-KEM (found on fixtures/crypto-quantum, 2026-09-11)."""
    rec = recommend_pqc(
        family=family,
        quantum_vulnerable=True,
        crypto_functions=functions,
        name=name,
        primitive=primitive,
    )
    assert rec is not None
    assert rec.algorithm == want


def test_signing_alongside_keygen_is_still_signing() -> None:
    rec = recommend_pqc(family="rsa", quantum_vulnerable=True, crypto_functions=["keygen", "sign"])
    assert rec is not None
    assert rec.algorithm == "ML-DSA"


def test_a_bare_ec_is_elliptic_curve_and_its_strength_stays_open() -> None:
    """⚠ JCA's `KeyPairGenerator.getInstance("EC")` reaches the rules named just
    `EC`. No rule matched it, and an elliptic-curve key was reported NOT
    quantum-vulnerable. The curve decides its classical strength, so that verdict
    stays unassessed until a curve is reported."""
    quantum = assess_quantum(name="EC", primitive="pke")
    assert quantum.quantum_vulnerable is True
    assert quantum.family == "ecc"
    assert assess_deprecation(name="EC", primitive="pke").status == "unassessed"
    # A key whose algorithm is EC: the key's name says nothing, the algorithm does.
    assert assess_quantum(name="key", primitive="EC", asset_type="key").family == "ecc"
    # With a curve it is judged on the curve.
    assert assess_deprecation(name="EC-secp256r1", primitive="pke").status == "current"


@pytest.mark.parametrize(
    ("name", "primitive", "key_size", "expected"),
    [
        # ⚠ The same missing fact RSA and DH are judged on: no curve, no verdict.
        ("ECDSA", "signature", None, "unassessed"),
        ("ECDH", "key-agree", None, "unassessed"),
        # A curve, or a size that fixes one, decides it.
        ("ECDSA", "signature secp384r1", None, "current"),
        ("ECDSA-P256", "signature", None, "current"),
        ("ECDSA", "signature", 256, "current"),
        ("ECDSA", "signature", 192, "weak"),
        ("ECDSA", "signature secp192r1", None, "weak"),
    ],
)
def test_an_elliptic_curve_verdict_needs_its_curve(
    name: str, primitive: str, key_size: int | None, expected: str
) -> None:
    assert assess_deprecation(name=name, primitive=primitive, key_size=key_size).status == expected


@pytest.mark.parametrize(
    ("name", "primitive"),
    [
        # `ECB` is a mode, not a curve.
        ("AES-128-ECB-PKCS5", "block-cipher"),
        # `ec` is two hex digits: an unresolved bom-ref must never read as a curve.
        ("leaf", "A3 EC-5F21"),
        ("leaf", "b21f7408-6344-4ea2-a3ec-541fa2579d3e"),
    ],
)
def test_ec_is_matched_only_as_a_whole_name(name: str, primitive: str) -> None:
    assert assess_quantum(name=name, primitive=primitive).family != "ecc"


# ---------------------------------------------------------------------------
# Deprecation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("MD5", "broken"),
        ("SHA-1", "broken"),
        ("RC4", "broken"),
        ("DES", "broken"),
        ("3DES", "weak"),
        ("Blowfish", "weak"),
        ("AES-256-GCM", "current"),
        ("SHA-256", "current"),
        ("ChaCha20-Poly1305", "current"),
    ],
)
def test_deprecated_algorithms_are_marked(name: str, expected: str) -> None:
    assert assess_deprecation(name=name).status == expected


def test_weak_and_broken_are_kept_apart() -> None:
    """⚠ COLLAPSING THEM INTO ONE "BAD" BUCKET IS WRONG IN A COMPLIANCE
    DOCUMENT.

    SHA-1 collisions are demonstrated and cheap; a 1024-bit RSA key is within
    reach of a well-funded adversary and nobody else. Those need different
    remediation timelines, and a customer given one bucket triages neither.
    """
    assert assess_deprecation(name="SHA-1").status == "broken"
    assert assess_deprecation(name="RSA", key_size=1024).status == "weak"
    assert assess_deprecation(name="3DES").status == "weak"


def test_hmac_sha1_is_not_reported_broken() -> None:
    """⚠ THE USE MATTERS AS MUCH AS THE PRIMITIVE.

    HMAC's security does not rest on collision resistance, which is what is
    broken in SHA-1. A rule condemning every appearance of SHA-1 fills a
    migration list with HMAC entries that are fine — and the entries that are
    not fine get lost in it.
    """
    verdict = assess_deprecation(name="HMAC-SHA1")
    assert verdict.status == "deprecated"
    assert verdict.status != "broken"
    assert "does not rest on collision resistance" in verdict.rationale


def test_ecb_condemns_an_otherwise_current_cipher() -> None:
    """A mode, not an algorithm — and the one case where the mode alone decides.

    AES-128-ECB is AES; it is also unusable, because identical plaintext blocks
    encrypt to identical ciphertext.
    """
    assert assess_deprecation(name="AES-128-ECB").status == "broken"
    assert assess_deprecation(name="AES-128-GCM").status == "current"


@pytest.mark.parametrize(
    ("bits", "expected"),
    [
        (512, "broken"),
        (768, "broken"),
        (1024, "weak"),
        (1536, "weak"),
        (2048, "current"),
        (4096, "current"),
    ],
)
def test_rsa_key_sizes(bits: int, expected: str) -> None:
    assert assess_deprecation(name="RSA", key_size=bits).status == expected


def test_an_unsized_rsa_key_says_it_was_not_assessed() -> None:
    """The one most likely to be a legacy 1024-bit key.

    Reporting it as plainly `current` would hide exactly the asset a reviewer is
    looking for, so the rationale says the size was missing.
    """
    verdict = assess_deprecation(name="rsaEncryption")
    assert "not reported" in verdict.rationale


def test_a_reference_is_cited_wherever_one_exists() -> None:
    for name in ["MD5", "SHA-1", "RC4", "3DES", "DES"]:
        assert assess_deprecation(name=name).reference, f"{name} cites no reference"


def test_key_size_from_the_name_when_no_field_is_supplied() -> None:
    assert assess_deprecation(name="RSA-1024").status == "weak"
    assert assess_deprecation(name="modp1024").status == "weak"
    # ⚠ NARROW ON PURPOSE: a general number-finder reads the 1 in PKCS#1 as a
    # key size, and this value decides whether an asset is reported broken.
    assert assess_deprecation(name="RSA PKCS#1 v1.5", key_size=4096).status == "current"


# ---------------------------------------------------------------------------
# Name matching
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "rsaEncryption",
        "sha1WithRSAEncryption",
        "sha256WithRSAEncryption",
        "md5WithRSAEncryption",
        "modp2048",
        "Kyber1024",
        "Dilithium3",
    ],
)
def test_concatenated_names_are_matched(name: str) -> None:
    """⚠ NINE RULES WERE WRITTEN WITH A PLAIN  FIRST, AND EVERY ONE MISSED.

    `rsa` does not match `rsaEncryption` — `E` is a word character — and it
    does not match `sha1WithRSAEncryption` either, because there is no boundary
    before `R`. Those are the names these ACTUALLY carry in certificate
    signature algorithms and TLS parameter lists.

    A missed rule reports a broken primitive as unassessed, which is the worst
    direction for a rule whose output is a migration list.
    """
    verdict = assess_quantum(name=name)
    assert verdict.family != "unknown", f"{name} was not recognised"


def test_a_sha1_certificate_signature_is_broken() -> None:
    """The exact case the boundary bug hid: a SHA-1 certificate reported
    `current` because `sha-?1` cannot match `sha1WithRSAEncryption`."""
    verdict = assess_deprecation(name="sha1WithRSAEncryption", asset_type="certificate")
    assert verdict.status == "broken"


def test_tokenizing_alone_would_break_rules_that_were_already_right() -> None:
    """⚠ THE REASON search_text KEEPS BOTH FORMS.

    Replacing the raw name with its tokenization fixed the camelCase cases and
    silently broke four that worked: `3DES` became `3 DES` and was reported
    `broken` instead of `weak`; `ChaCha20` became `Cha Cha20` and stopped being
    recognised at all.

    This pins the property that makes the fix safe: the raw form survives.
    """
    assert tokenize("3DES") == "3 DES"
    assert tokenize("ChaCha20") == "Cha Cha20"

    # ...and search_text keeps the original alongside it, so the rules still see it.
    assert "3DES" in search_text("3DES")
    assert "ChaCha20" in search_text("ChaCha20")

    assert assess_deprecation(name="3DES").status == "weak"
    assert assess_quantum(name="ChaCha20").family == "chacha"


def test_search_text_is_a_no_op_on_an_already_spaced_name() -> None:
    assert search_text("AES-256") == "AES-256"
    assert search_text("") == ""


# ---------------------------------------------------------------------------
# Verdicts that were wrong until 2026-09-11 — pinned so they stay fixed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "ML-DSA-65",
        "SLH-DSA-SHA2-128s",
        "FN-DSA-512",
        "Falcon-512",
        "ML-KEM-768",
        "Kyber1024",
        "HQC-128",
    ],
)
def test_post_quantum_algorithms_are_never_deprecated(name: str) -> None:
    """⚠ `\\bdsa\\b` MATCHED THE "-DSA" IN ML-DSA, SLH-DSA AND FN-DSA, and the
    legacy DSA rule ran before any post-quantum check — so the algorithms a
    customer migrated TO were reported deprecated."""
    assert assess_deprecation(name=name).status == "current"


def test_selected_is_not_reported_as_standardised() -> None:
    """FN-DSA and HQC are NIST selections with no final FIPS in this ruleset; a
    customer cites this at an audit."""
    assert assess_deprecation(name="ML-KEM-768").reference == "FIPS 203"
    for name in ("FN-DSA-512", "HQC-128"):
        verdict = assess_deprecation(name=name)
        assert verdict.reference == "", name
        assert "selected" in verdict.rationale.lower(), name


@pytest.mark.parametrize("name", ["EdDSA", "Ed25519", "Ed448", "X25519"])
def test_edwards_and_montgomery_curves_are_not_dsa(name: str) -> None:
    """`EdDSA` tokenizes to `Ed DSA`, and the DSA rule fired on the second token."""
    assert assess_deprecation(name=name).status == "current"
    verdict = assess_quantum(name=name)
    assert verdict.family == "ecc"
    assert verdict.quantum_vulnerable


def test_the_mode_field_condemns_ecb_even_when_the_name_does_not_say_it() -> None:
    assert assess_deprecation(name="AES", mode="ecb").status == "broken"
    assert assess_deprecation(name="AES", mode="gcm").status == "current"


def test_ecb_in_an_rsa_transformation_is_not_blamed_pkcs1_v15_is() -> None:
    """Java's `RSA/ECB/PKCS1Padding` names ECB only because the syntax demands a
    mode. Blaming ECB would send a reviewer after the wrong fix."""
    verdict = assess_deprecation(name="RSA/ECB/PKCS1Padding", key_size=2048)
    assert verdict.status == "weak"
    assert "ECB" not in verdict.rationale
    assert "PKCS#1 v1.5" in verdict.rationale


def test_pkcs1_v15_key_transport_is_weak_but_a_v15_signature_is_not() -> None:
    transport = assess_deprecation(
        name="RSA",
        primitive="pke",
        key_size=2048,
        padding="pkcs1v15",
        crypto_functions=["encrypt", "decrypt"],
    )
    signature = assess_deprecation(
        name="SHA256-RSA",
        primitive="signature",
        key_size=2048,
        padding="pkcs1v15",
        crypto_functions=["sign"],
    )
    assert transport.status == "weak"
    assert signature.status == "current"


def test_a_mixed_use_rsa_asset_is_not_guessed_to_be_key_transport() -> None:
    """theia's RSA `pke` asset lists encapsulate, decapsulate AND sign together."""
    verdict = assess_deprecation(
        name="RSA",
        primitive="pke",
        key_size=2048,
        padding="pkcs1v15",
        crypto_functions=["encapsulate", "decapsulate", "sign"],
    )
    assert verdict.status == "current"


@pytest.mark.parametrize("name", ["RSA", "rsaEncryption", "Diffie-Hellman"])
def test_an_unsized_modulus_is_unassessed_not_current(name: str) -> None:
    """⚠ It returned `current` with an apologetic rationale, so a status filter
    showed the likeliest legacy 1024-bit key as fine."""
    verdict = assess_deprecation(name=name)
    assert verdict.status == "unassessed"
    assert "not reported" in verdict.rationale


def test_an_unrecognised_or_unnamed_asset_is_unassessed_not_current() -> None:
    assert assess_deprecation(name="ACME-CIPHER-9000").status == "unassessed"
    assert assess_deprecation(name="").status == "unassessed"


@pytest.mark.parametrize("name", ["DESede", "TDEA", "DES-EDE3-CBC"])
def test_java_openssl_and_nist_names_for_3des(name: str) -> None:
    """Java's `DESede` tokenized to `DE Sede` and matched nothing."""
    assert assess_deprecation(name=name).status == "weak"
    assert assess_quantum(name=name).family == "3des"


@pytest.mark.parametrize(
    ("name", "family"),
    [
        ("P-256", "ecc"),
        ("P-384", "ecc"),
        ("prime256v1", "ecc"),
        ("ffdhe2048", "dh"),
        ("RC4", "rc4"),
        ("Blowfish", "blowfish"),
        ("HQC-128", "hqc"),
    ],
)
def test_names_that_used_to_go_unrecognised(name: str, family: str) -> None:
    assert assess_quantum(name=name).family == family


def test_an_ffdhe_group_is_sized_from_its_name() -> None:
    assert assess_deprecation(name="ffdhe2048").status == "current"
    assert assess_deprecation(name="ffdhe").status == "unassessed"


@pytest.mark.parametrize(
    ("name", "version", "expected"),
    [
        ("TLS", "1.0", "deprecated"),
        ("TLS", "1.1", "deprecated"),
        ("TLS", "1.2", "current"),
        ("TLS", "1.3", "current"),
        ("TLS", "", "unassessed"),
        ("SSL", "3.0", "broken"),
        ("DTLS", "1.0", "deprecated"),
        ("DTLS", "1.2", "current"),
        ("SSH", "2.0", "current"),
        ("SSH", "1.5", "weak"),
        ("IKE", "1", "deprecated"),
        ("IKE", "2", "current"),
        ("QUIC", "", "current"),
        ("CustomProto", "1", "unassessed"),
    ],
)
def test_a_protocol_is_judged_by_its_version(name: str, version: str, expected: str) -> None:
    """⚠ `TLS` WAS `current` WHATEVER ITS VERSION. TLS 1.0 and 1.1 are deprecated
    (RFC 8996); a protocol with no version is unassessed, never current."""
    verdict = assess_deprecation(name=name, asset_type="protocol", protocol_version=version)
    assert verdict.status == expected


def test_a_tls_version_in_the_name_is_read_when_the_field_is_empty() -> None:
    assert assess_deprecation(name="TLSv1.1", asset_type="protocol").status == "deprecated"
    assert assess_deprecation(name="TLSv1.3", asset_type="protocol").status == "current"


def test_grover_advice_names_a_size_the_primitive_has() -> None:
    """ "Consider a 384-bit key" for AES-192; "a 224-bit key" for 3DES."""
    aes192 = assess_quantum(name="AES-192").grover_note
    assert "384" not in aes192
    assert "AES-256" in aes192

    des3 = assess_quantum(name="3DES").grover_note
    assert "224-bit" not in des3
    assert "migrate" in des3.lower()


def test_a_hash_note_talks_about_the_digest_not_a_key() -> None:
    note = assess_quantum(name="SHA-256").grover_note
    assert "digest" in note
    assert "key" not in note


def test_the_status_set_is_the_database_s_and_the_profile_s() -> None:
    """The rules, the column's CHECK and the profile's closed value set agree."""
    import re
    from pathlib import Path

    from axebom_shared.crypto.deprecation import STATUSES

    repo = Path(__file__).resolve().parents[4]

    up = (
        (repo / "migrations/normalize/0019_crypto_unassessed_and_derivations.sql")
        .read_text()
        .split("-- +goose Down")[0]
    )
    checked = re.findall(r"deprecation_status IN \(([^)]*)\)", up)
    assert checked, "0019 no longer carries the deprecation_status CHECK"
    assert set(re.findall(r"'([a-z]+)'", checked[-1])) == set(STATUSES)

    yaml = pytest.importorskip("yaml")
    profile = yaml.safe_load((repo / "docs/reference/certin-v2.0.yaml").read_text())

    def find(node: object) -> list[str] | None:
        if isinstance(node, dict):
            if node.get("id") == "axebom.crypto.deprecation_status":
                return list(node.get("values") or [])
            nodes: list[object] = list(node.values())
        elif isinstance(node, list):
            nodes = list(node)
        else:
            return None
        for child in nodes:
            found = find(child)
            if found is not None:
                return found
        return None

    assert set(find(profile) or []) == set(STATUSES)


@pytest.mark.parametrize(
    "name",
    ["RSA", "AES-256-GCM", "MD5", "ML-DSA-65", "EdDSA", "ACME-9000", "", "DESede", "P-256"],
)
def test_every_verdict_is_a_known_status(name: str) -> None:
    from axebom_shared.crypto.deprecation import STATUSES

    assert assess_deprecation(name=name).status in STATUSES
