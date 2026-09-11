"""The crypto-asset identity ladder (docs/03-NORMALIZER-SPEC.md §1.6)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from workers.cbom.normalize.identity import IDENTITY_RULES, asset_identity

REPO = Path(__file__).resolve().parents[3]


def algorithm(name: str, primitive: str = "", **extra: object) -> dict:
    return {"asset_type": "algorithm", "name": name, "primitive": primitive, **extra}


def test_two_uses_of_rsa_are_two_assets() -> None:
    """⚠ theia reports "RSA" twice from one certificate — signature and pke."""
    signature = asset_identity(algorithm("RSA", "signature"))
    pke = asset_identity(algorithm("RSA", "pke"))
    assert signature.key != pke.key
    assert signature.rule == pke.rule == "algorithm"


def test_the_same_algorithm_from_two_engines_is_one_asset() -> None:
    theia = asset_identity(
        algorithm("SHA256-RSA", "signature", parameter_set="256"), "cbomkit-theia"
    )
    action = asset_identity(algorithm("SHA256withRSA", "signature"), "cbomkit-action")
    assert theia.key == action.key


def test_an_unrecognised_algorithm_falls_to_the_name_tier() -> None:
    got = asset_identity(algorithm("ACME-9000", "block-cipher"))
    assert got.key.startswith("name:algorithm/acme-9000")
    assert (got.rule, got.confidence) == ("algorithm-name", "low")


def test_a_public_key_is_identified_by_fingerprint() -> None:
    got = asset_identity(
        {"asset_type": "key", "name": "RSA-2048", "public_key_fingerprint": "sha256:ab12"}
    )
    assert got.key == "key:fp:sha256:ab12"
    assert (got.rule, got.confidence) == ("key-fingerprint", "high")


def test_a_private_key_is_identified_by_where_it_was_committed() -> None:
    first = asset_identity(
        {
            "asset_type": "key",
            "name": "RSA-2048",
            "material_type": "private-key",
            "key_size": 2048,
            "evidence": [{"path": "key.pem", "line": None}],
        }
    )
    second = asset_identity(
        {
            "asset_type": "key",
            "name": "RSA-2048",
            "material_type": "private-key",
            "key_size": 2048,
            "evidence": [{"path": "other/key.pem", "line": None}],
        }
    )
    assert first.rule == "key-location"
    assert first.key != second.key
    assert "path=key.pem" in first.key


@pytest.mark.parametrize(
    ("cert", "rule"),
    [
        ({"cert_fingerprint": "sha-256:AA"}, "certificate-fingerprint"),
        ({"cert_issuer": "CN=CA", "cert_serial": "01"}, "certificate-issuer-serial"),
        (
            {
                "cert_subject": "CN=x",
                "cert_issuer": "CN=CA",
                "not_valid_after": "2027-01-01T00:00:00Z",
            },
            "certificate-subject-issuer-validity",
        ),
    ],
)
def test_certificate_tiers(cert: dict, rule: str) -> None:
    assert asset_identity({"asset_type": "certificate", "name": "x", **cert}).rule == rule


def test_a_protocol_is_its_name_and_version() -> None:
    assert asset_identity(
        {"asset_type": "protocol", "name": "TLS", "protocol_version": "1.2"}
    ).key == ("protocol:tls;version=1.2")


@pytest.mark.parametrize(
    ("name", "version", "key"),
    [
        # cbomkit-action names the protocol with its version and fills the field.
        ("TLSv1.2", "1.2", "protocol:tls;version=1.2"),
        # The version only in the name.
        ("TLSv1.3", "", "protocol:tls;version=1.3"),
        ("TLS 1.3", "", "protocol:tls;version=1.3"),
        ("SSLv3", "", "protocol:ssl;version=3"),
        ("DTLSv1.2", "", "protocol:dtls;version=1.2"),
        ("IKEv2", "", "protocol:ike;version=2"),
        ("SSH", "", "protocol:ssh"),
        # An unrecognised name is kept whole, and a digit in it is not a version.
        ("Noise_XX_25519", "", "protocol:noise_xx_25519"),
    ],
)
def test_a_protocol_named_with_its_version_shares_a_key(name: str, version: str, key: str) -> None:
    """⚠ `TLSv1.2` from one engine and `TLS` + `1.2` from another are one protocol."""
    raw = {"asset_type": "protocol", "name": name, "protocol_version": version}
    assert asset_identity(raw).key == key


def test_nothing_better_is_opaque_and_replay_stable() -> None:
    raw = {"asset_type": "certificate", "name": "", "native_ref": "b21f7408"}
    first = asset_identity(raw, "cbomkit-theia")
    assert first.key == "opaque:cbomkit-theia:b21f7408"
    assert first == asset_identity(raw, "cbomkit-theia")


def test_every_rule_is_one_the_database_accepts() -> None:
    """IDENTITY_RULES and migration 0020's CHECK are one set."""
    sql = (REPO / "migrations/normalize/0020_crypto_identity_and_provenance.sql").read_text()
    up = sql.split("-- +goose Down")[0]
    block = re.search(r"identity_rule IN \((.*?)\)\)", up, re.S)
    assert block, "0020 no longer carries the identity_rule CHECK"
    assert set(re.findall(r"'([a-z-]+)'", block.group(1))) == IDENTITY_RULES
