"""The algorithm canonicalizer, against the name forms engines actually emit.

Every row is a spelling seen in real tool output or real code: JCA transformation
strings, X.509 algorithm names, cbomkit-theia's own names, OpenSSL names.
"""

from __future__ import annotations

from typing import Any

import pytest

from axebom_shared.crypto.identity import Canonical, canonicalize


def expect(**fields: Any) -> dict[str, Any]:
    return fields


@pytest.mark.parametrize(
    ("args", "kwargs", "expected"),
    [
        # --- AES: key bits and mode from the name, the fields, or both -----
        (("AES-256-GCM",), {}, expect(family="aes", bits=256, mode="gcm")),
        (("AES256-GCM",), {}, expect(family="aes", bits=256, mode="gcm")),
        (("AES_128_CBC",), {}, expect(family="aes", bits=128, mode="cbc")),
        (
            ("AES/CBC/PKCS5Padding",),
            {},
            expect(family="aes", bits=None, mode="cbc", padding="pkcs5"),
        ),
        (
            ("AES",),
            {"parameter_set": "128", "mode": "ecb"},
            expect(family="aes", bits=128, mode="ecb"),
        ),
        (("AES",), {"key_size": 192}, expect(family="aes", bits=192, mode="")),
        # --- hashes ---------------------------------------------------------
        (("SHA-256",), {}, expect(family="sha2", digest=256)),
        (("SHA256",), {}, expect(family="sha2", digest=256)),
        (("SHA3-512",), {}, expect(family="sha3", digest=512)),
        (("SHA-512/256",), {}, expect(family="sha2", digest=256, scheme="sha512/256")),
        (("SHA-1",), {}, expect(family="sha1", digest=160)),
        (("MD5",), {}, expect(family="md5", digest=128)),
        (("SHAKE128",), {}, expect(family="shake", digest=128)),
        # --- hash-and-sign: the digest never becomes a modulus -------------
        (("SHA256withRSA",), {}, expect(family="rsa", digest=256, digest_family="sha2", bits=None)),
        (("sha256WithRSAEncryption",), {}, expect(family="rsa", digest=256, bits=None)),
        (
            ("SHA256-RSA",),
            {"primitive": "signature", "parameter_set": "256"},
            expect(family="rsa", digest=256, bits=None),
        ),
        (("ecdsa-with-SHA384",), {}, expect(family="ecdsa", digest=384)),
        (("SHA256withECDSA",), {}, expect(family="ecdsa", digest=256)),
        # --- RSA ------------------------------------------------------------
        (("RSA-2048",), {}, expect(family="rsa", bits=2048)),
        (("RSA",), {"parameter_set": "2048"}, expect(family="rsa", bits=2048)),
        (("RSA",), {"key_size": 3072}, expect(family="rsa", bits=3072)),
        (("RSASSA-PSS",), {}, expect(family="rsa", scheme="pss")),
        (("RSA/ECB/OAEPWithSHA-256AndMGF1Padding",), {}, expect(family="rsa", scheme="oaep")),
        (("RSA/ECB/PKCS1Padding",), {}, expect(family="rsa", scheme="pkcs1v15")),
        # --- elliptic curves ------------------------------------------------
        (("ECDSA",), {"curve": "secp256r1"}, expect(family="ecdsa", curve="p-256")),
        (("ECDSA-P384",), {}, expect(family="ecdsa", curve="p-384")),
        (("ECDH_P256",), {}, expect(family="ecdh", curve="p-256")),
        (("Ed25519",), {}, expect(family="eddsa", curve="ed25519")),
        (("EdDSA",), {}, expect(family="eddsa", curve="")),
        (("X25519",), {}, expect(family="xdh", curve="x25519")),
        (("P-384",), {}, expect(family="ec", curve="p-384")),
        (("prime256v1",), {}, expect(family="ec", curve="p-256")),
        # --- post-quantum ---------------------------------------------------
        (("ML-KEM-768",), {}, expect(family="ml-kem", parameter="768")),
        (("Kyber1024",), {}, expect(family="ml-kem", parameter="1024")),
        (("ML-DSA-65",), {}, expect(family="ml-dsa", parameter="65")),
        (("Dilithium3",), {}, expect(family="ml-dsa", parameter="65")),
        (("SLH-DSA-SHA2-128s",), {}, expect(family="slh-dsa", parameter="sha2-128s")),
        (("Falcon-512",), {}, expect(family="falcon", parameter="512")),
        # --- MACs and KDFs ----------------------------------------------------
        (("HmacSHA256",), {}, expect(family="hmac", digest=256, digest_family="sha2")),
        (("HMAC-SHA1",), {}, expect(family="hmac", digest=160, digest_family="sha1")),
        (("PBKDF2WithHmacSHA256",), {}, expect(family="pbkdf2", digest=256)),
        (("Argon2id",), {}, expect(family="argon2", scheme="argon2id")),
        # --- legacy symmetric ---------------------------------------------------
        (("DESede",), {}, expect(family="3des", bits=None)),
        (("DES-EDE3-CBC",), {}, expect(family="3des", bits=168, mode="cbc")),
        (("DES",), {}, expect(family="des", bits=56)),
        (("ChaCha20-Poly1305",), {}, expect(family="chacha20", bits=256, scheme="poly1305")),
        (("RC4",), {}, expect(family="rc4")),
        # --- finite-field DH ------------------------------------------------------
        (("ffdhe2048",), {}, expect(family="dh", bits=2048, scheme="ffdhe2048")),
        (("DH",), {"key_size": 3072}, expect(family="dh", bits=3072)),
        (("Diffie-Hellman",), {}, expect(family="dh", bits=None)),
        # --- DSA is only DSA ----------------------------------------------------
        (("DSA",), {"parameter_set": "2048"}, expect(family="dsa", bits=2048)),
    ],
)
def test_real_names_canonicalize(args: tuple, kwargs: dict, expected: dict) -> None:
    got = canonicalize(*args, **kwargs)
    for field_name, value in expected.items():
        assert getattr(got, field_name) == value, (args, kwargs, field_name, got)


@pytest.mark.parametrize("name", ["", "ACME-CIPHER-9000", "signature"])
def test_an_unrecognised_name_stays_unrecognised(name: str) -> None:
    """⚠ Unknown stays unknown — no plausible default."""
    got = canonicalize(name)
    assert not got.recognised
    assert got.bits is None


def test_a_digest_parameter_set_is_never_a_modulus() -> None:
    """⚠ theia reports `SHA256-RSA` with parameterSetIdentifier `256` — the digest.
    Read as a modulus it would report a 256-bit RSA key: "broken"."""
    got = canonicalize("SHA256-RSA", "signature", parameter_set="256")
    assert got.bits is None
    assert got.digest == 256


def test_the_primitive_is_carried_lower_cased() -> None:
    assert canonicalize("AES-128-GCM", "AE").primitive == "ae"


def test_the_default_is_the_empty_identity() -> None:
    assert Canonical() == canonicalize("")
