"""The CBOM analysis step: an asset's own fields reach the rules.

The rules themselves are tested in libs/py-shared/axebom_shared/crypto/test_crypto.py.
These prove `normalize_crypto_asset` hands them what the engine actually reported —
mode, padding, curve and protocol version were read by the extractor or stored as
columns and then never passed on, so the rules judged every asset by its name alone.
"""

from __future__ import annotations

from workers.cbom.adapters.cbomkit_theia import extract_crypto_assets
from workers.cbom.normalize.crypto import normalize_crypto_asset


def test_an_ecb_mode_field_reaches_the_deprecation_rules() -> None:
    """An asset named `AES` whose engine reported `mode: ecb` was reported current."""
    asset = normalize_crypto_asset(
        {"asset_type": "algorithm", "name": "AES", "primitive": "block-cipher", "mode": "ecb"}
    )
    assert asset["deprecation_status"] == "broken"


def test_a_key_size_only_in_the_parameter_set_reaches_the_grover_rule() -> None:
    """cbomkit-action names pyca's `Cipher(algorithms.AES(key), modes.ECB())`
    `AES-ECB` with `parameterSetIdentifier: 128`. The asset key and the derived
    security level used the 128; the Grover note said no key size was reported."""
    asset = normalize_crypto_asset(
        {
            "asset_type": "algorithm",
            "name": "AES-ECB",
            "primitive": "block-cipher",
            "mode": "ecb",
            "parameter_set": "128",
        }
    )
    assert asset["effective_quantum_bits"] == 64
    assert not any("no key size" in d for d in asset.get("analysis_diagnostics", []))


def test_a_digest_parameter_set_is_never_a_modulus_for_the_rules() -> None:
    """theia's `SHA256-RSA` carries `256`, the digest. Read as a modulus it would be
    a 256-bit RSA key and `weak`; with no modulus stated it stays unassessed."""
    asset = normalize_crypto_asset(
        {
            "asset_type": "algorithm",
            "name": "SHA256-RSA",
            "primitive": "signature",
            "parameter_set": "256",
        }
    )
    assert asset["deprecation_status"] == "unassessed"


def test_a_protocol_version_reaches_the_rules() -> None:
    old = normalize_crypto_asset(
        {"asset_type": "protocol", "name": "TLS", "protocol_version": "1.0"}
    )
    new = normalize_crypto_asset(
        {"asset_type": "protocol", "name": "TLS", "protocol_version": "1.3"}
    )

    assert old["deprecation_status"] == "deprecated"
    assert new["deprecation_status"] == "current"


def test_pkcs1_v15_padding_reaches_the_rules_and_is_not_a_column() -> None:
    asset = normalize_crypto_asset(
        {
            "asset_type": "algorithm",
            "name": "RSA-2048",
            "primitive": "pke",
            "crypto_functions": ["encrypt", "decrypt"],
            "padding": "pkcs1v15",
        }
    )
    assert asset["deprecation_status"] == "weak"
    # Analysis input only: padding is not a CERT-In Table 9 field.
    assert "padding" not in asset


def test_a_curve_reported_only_in_its_own_field_is_judged() -> None:
    asset = normalize_crypto_asset(
        {"asset_type": "algorithm", "name": "ECDSA", "primitive": "signature", "curve": "secp192r1"}
    )
    assert asset["deprecation_status"] == "weak"


def test_an_ml_kem_parameter_set_is_not_a_key_size() -> None:
    """⚠ `ML-KEM-768` names a parameter set; its encapsulation key is 1184 bytes."""
    pqc = normalize_crypto_asset(
        {"asset_type": "key", "name": "ML-KEM-768", "parameter_set": "768"}
    )
    rsa = normalize_crypto_asset({"asset_type": "key", "name": "RSA", "parameter_set": "RSA-2048"})

    assert "key_size" not in pqc
    assert rsa["key_size"] == 2048


def test_the_extractor_keeps_padding_and_both_curve_spellings() -> None:
    """CycloneDX 1.7 renamed `curve` to `ellipticCurve`; both must be read."""

    def algorithm(name: str, properties: dict) -> dict:
        return {
            "type": "cryptographic-asset",
            "name": name,
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": properties},
        }

    assets, _ = extract_crypto_assets(
        {
            "components": [
                algorithm("SHA256-RSA", {"primitive": "signature", "padding": "pkcs1v15"}),
                algorithm("ECDSA", {"primitive": "signature", "ellipticCurve": "secp384r1"}),
                algorithm("ECDH", {"primitive": "key-agree", "curve": "x25519"}),
            ]
        }
    )

    assert assets[0]["padding"] == "pkcs1v15"
    assert assets[1]["curve"] == "secp384r1"
    assert assets[2]["curve"] == "x25519"
