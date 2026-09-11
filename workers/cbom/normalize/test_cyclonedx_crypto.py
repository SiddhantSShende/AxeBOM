"""The shared CycloneDX crypto reader: 1.6 and 1.7, evidence, and no key material."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from workers.cbom.normalize.cyclonedx_crypto import extract_crypto_assets


def crypto(name: str, props: dict, **extra: object) -> dict:
    return {"type": "cryptographic-asset", "name": name, "cryptoProperties": props, **extra}


def test_cyclonedx_1_7_spellings_are_read() -> None:
    ecdsa = crypto(
        "ECDSA",
        {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "signature",
                "ellipticCurve": "secp384r1",
                "algorithmFamily": "ECDSA",
                "nistQuantumSecurityLevel": 0,
            },
        },
        **{"bom-ref": "e1"},
    )
    cert = crypto(
        "leaf",
        {
            "assetType": "certificate",
            "certificateProperties": {
                "subjectName": "CN=leaf",
                "issuerName": "CN=CA",
                "serialNumber": "0A1B",
                "fingerprint": {"alg": "SHA-256", "content": "ABCD"},
                "certificateFileExtension": "crt",
                "relatedCryptographicAssets": [
                    {"type": "signatureAlgorithm", "ref": "e1"},
                    {"type": "publicKey", "ref": "k1"},
                ],
            },
        },
    )

    (algorithm, certificate), diagnostics = extract_crypto_assets({"components": [ecdsa, cert]})

    assert not diagnostics
    assert algorithm["curve"] == "secp384r1"
    assert algorithm["algorithm_family"] == "ECDSA"
    assert algorithm["nist_quantum_security_level"] == 0
    assert certificate["cert_serial"] == "0A1B"
    assert certificate["cert_fingerprint"] == "sha-256:abcd"
    assert certificate["cert_extension"] == "crt"
    assert certificate["signature_algo_ref"] == "e1"
    assert certificate["subject_public_key_ref"] == "k1"


def test_a_nist_quantum_level_outside_the_schema_s_range_is_not_kept() -> None:
    """The schema bounds it to 0..6; a 9 is not a category."""
    (asset,), _ = extract_crypto_assets(
        {
            "components": [
                crypto(
                    "X",
                    {
                        "assetType": "algorithm",
                        "algorithmProperties": {"nistQuantumSecurityLevel": 9},
                    },
                )
            ]
        }
    )
    assert asset["nist_quantum_security_level"] is None


def test_a_public_key_is_fingerprinted_and_its_value_is_never_kept() -> None:
    value = base64.b64encode(b"\x30\x82\x01\x22fake-spki-bytes").decode()
    public = crypto(
        "RSA-2048",
        {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {"type": "public-key", "size": 2048, "value": value},
        },
    )

    (asset,), _ = extract_crypto_assets({"components": [public]})

    assert asset["public_key_fingerprint"] == (
        "sha256:" + hashlib.sha256(base64.b64decode(value)).hexdigest()
    )
    assert value not in json.dumps(asset)


@pytest.mark.parametrize("material", ["private-key", "secret-key", "symmetric-key"])
def test_secret_key_material_is_never_read(material: str) -> None:
    secret = crypto(
        "k",
        {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {"type": material, "value": "TOP-SECRET-BYTES"},
        },
    )

    (asset,), _ = extract_crypto_assets({"components": [secret]})

    assert "TOP-SECRET-BYTES" not in json.dumps(asset)
    assert "public_key_fingerprint" not in asset


def test_evidence_is_structured_and_repository_relative() -> None:
    asset_component = crypto(
        "AES-256-GCM",
        {"assetType": "algorithm", "algorithmProperties": {"primitive": "ae"}},
        evidence={"occurrences": [{"location": "/src/Main.java", "line": 42}]},
    )

    (asset,), _ = extract_crypto_assets({"components": [asset_component]})

    assert asset["evidence"] == [{"path": "Main.java", "line": 42}]


def test_diagnostics_name_the_engine_they_came_from() -> None:
    _, diagnostics = extract_crypto_assets({"components": "not a list"}, label="cdxgen-cbom")
    assert "cdxgen-cbom" in diagnostics[0]["message"]
