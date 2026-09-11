"""The cross-engine merge: one asset per identity, evidence and provenance per engine."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from workers.cbom.normalize.cyclonedx_crypto import extract_crypto_assets
from workers.cbom.normalize.pipeline import build_canonical_cbom

REPO = Path(__file__).resolve().parents[3]
THEIA_FIXTURE = REPO / "fixtures" / "crypto-mixed" / "raw" / "cbomkit-theia.json"


def extract(engine: str, *components: dict[str, Any]) -> list[dict[str, Any]]:
    assets, _ = extract_crypto_assets(
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": list(components)},
        label=engine,
    )
    for asset in assets:
        asset["engine_id"] = engine
        asset["engine_version"] = "1.0"
        asset["artifact_sha256"] = "a" * 64
    return assets


def theia_fixture() -> list[dict[str, Any]]:
    assets, _ = extract_crypto_assets(json.loads(THEIA_FIXTURE.read_text()), label="cbomkit-theia")
    for asset in assets:
        asset["engine_id"] = "cbomkit-theia"
    return assets


def algorithm(name: str, primitive: str, *, ref: str, path: str, line: int, **props: Any) -> dict:
    return {
        "type": "cryptographic-asset",
        "name": name,
        "bom-ref": ref,
        "evidence": {"occurrences": [{"location": path, "line": line}]},
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {"primitive": primitive, **props},
        },
    }


def material(material_type: str, *, ref: str, path: str, line: int, name: str = "RSA-2048") -> dict:
    return {
        "type": "cryptographic-asset",
        "name": name,
        "bom-ref": ref,
        "evidence": {"occurrences": [{"location": path, "line": line}]},
        "cryptoProperties": {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {
                "type": material_type,
                "size": 2048,
                "value": "KEY-BYTES-MUST-NEVER-BE-STORED",
            },
        },
    }


def test_one_algorithm_from_two_engines_is_one_asset_with_two_provenance_rows() -> None:
    """theia's `SHA256-RSA` (padding pkcs1v15) and JCA's `SHA256withRSA` are one
    algorithm; the merge used to be impossible and would have listed it twice."""
    theia = extract(
        "cbomkit-theia",
        algorithm(
            "SHA256-RSA",
            "signature",
            ref="t1",
            path="certs/server.pem",
            line=0,
            parameterSetIdentifier="256",
            padding="pkcs1v15",
        ),
    )
    action = extract(
        "cbomkit-action",
        algorithm("SHA256withRSA", "signature", ref="a1", path="src/Sign.java", line=12),
    )

    result = build_canonical_cbom(theia + action)

    (asset,) = result["crypto_assets"]
    assert [p["engine_id"] for p in asset["_provenance"]] == ["cbomkit-action", "cbomkit-theia"]
    assert {(e["path"], e["line"], e["engine"]) for e in asset["evidence"]} == {
        ("certs/server.pem", None, "cbomkit-theia"),
        ("src/Sign.java", 12, "cbomkit-action"),
    }
    assert asset["identity_rule"] == "algorithm"
    assert asset["oid"] == "1.2.840.113549.1.1.11"


def test_the_theia_fixture_keeps_both_uses_of_rsa() -> None:
    result = build_canonical_cbom(theia_fixture())

    names = [a["name"] for a in result["crypto_assets"]]
    assert names.count("RSA") == 2
    assert len(result["crypto_assets"]) == 6
    assert len({a["asset_key"] for a in result["crypto_assets"]}) == 6


def test_input_order_does_not_change_one_byte_of_output() -> None:
    """Invariant 10: replay is reproducible whatever order artifacts arrive in."""
    assets = theia_fixture()
    first = json.dumps(build_canonical_cbom(assets), sort_keys=True)

    # Reversed, and rotated by one: two orders that differ from the original at
    # every position — a deterministic permutation rather than a random one.
    for reordered in (list(reversed(assets)), assets[1:] + assets[:1]):
        assert json.dumps(build_canonical_cbom(reordered), sort_keys=True) == first


def test_the_certificate_resolves_its_references_by_asset_key() -> None:
    result = build_canonical_cbom(theia_fixture())

    (cert,) = [a for a in result["crypto_assets"] if a["asset_type"] == "certificate"]
    assert cert["signature_algo_ref"] == "SHA256-RSA"
    assert cert["attributes"]["signature_algorithm_key"].startswith("algorithm:rsa")
    assert cert["attributes"]["subject_public_key_key"].startswith("key:")
    assert cert["quantum_vulnerable"] is True


def test_a_private_key_file_theia_found_is_flagged_and_its_bytes_are_never_stored() -> None:
    result = build_canonical_cbom(
        extract("cbomkit-theia", material("private-key", ref="p1", path="deploy/key.pem", line=0))
    )

    (asset,) = result["crypto_assets"]
    assert asset["attributes"]["private_key_in_source"] is True
    assert any(
        d["code"] == "CBOM_PRIVATE_KEY_IN_SOURCE" and "deploy/key.pem" in d["message"]
        for d in result["diagnostics"]
    )
    assert "KEY-BYTES-MUST-NEVER-BE-STORED" not in json.dumps(result)


def test_a_key_the_code_generates_is_never_called_a_key_in_the_source() -> None:
    """⚠ cbomkit-action reports `KeyPairGenerator.getInstance("RSA")` as
    `secret-key` material — a runtime key, not one committed to the repository."""
    result = build_canonical_cbom(
        extract(
            "cbomkit-action",
            material("secret-key", ref="k1", path="src/Keys.java", line=15, name="secret-key@df59"),
        )
    )

    (asset,) = result["crypto_assets"]
    assert "secret_key_in_source" not in asset["attributes"]
    assert "private_key_in_source" not in asset["attributes"]
    assert not any(d["code"] == "CBOM_PRIVATE_KEY_IN_SOURCE" for d in result["diagnostics"])
    assert "KEY-BYTES-MUST-NEVER-BE-STORED" not in json.dumps(result)


def test_a_disagreement_is_reported_and_the_trusted_engine_wins() -> None:
    """For an algorithm, the engine that read the code outranks the one that read a file."""
    theia = extract(
        "cbomkit-theia",
        algorithm("AES-256-GCM", "ae", ref="t", path="a.conf", line=1, classicalSecurityLevel=128),
    )
    action = extract(
        "cbomkit-action",
        algorithm("AES-256-GCM", "ae", ref="a", path="A.java", line=2, classicalSecurityLevel=256),
    )

    result = build_canonical_cbom(theia + action)

    (asset,) = result["crypto_assets"]
    assert asset["classical_security_level"] == 256
    assert any(d["code"] == "NORMALIZE_CRYPTO_FIELD_CONFLICT" for d in result["diagnostics"])


def test_a_key_named_for_nothing_is_judged_as_the_algorithm_it_depends_on() -> None:
    """⚠ cbomkit-action names a generated RSA key `key` and states its algorithm
    only as a CycloneDX dependency. Judged on the word `key`, an RSA key was
    reported not quantum-vulnerable."""
    rsa = algorithm("RSA-2048", "pke", ref="alg", path="src/Keys.java", line=15)
    key = material("secret-key", ref="k", path="src/Keys.java", line=15, name="key")
    assets, _ = extract_crypto_assets(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [rsa, key],
            "dependencies": [{"ref": "k", "dependsOn": ["alg"]}],
        },
        label="cbomkit-action",
    )
    for asset in assets:
        asset["engine_id"] = "cbomkit-action"

    result = build_canonical_cbom(assets)

    (row,) = [a for a in result["crypto_assets"] if a["asset_type"] == "key"]
    assert row["quantum_vulnerable"] is True
    assert row["quantum_family"] == "rsa"
    assert ";alg=rsa;" in row["asset_key"]
    assert row["attributes"]["algorithm_key"].startswith("algorithm:rsa;bits=2048")
    # The display name is still what the engine said; nothing is invented.
    assert row["name"] == "key"


def test_an_ambiguous_dependency_links_the_key_to_nothing() -> None:
    """A key depending on two algorithms says nothing about which it belongs to."""
    rsa = algorithm("RSA-2048", "pke", ref="a1", path="K.java", line=1)
    aes = algorithm("AES-256", "block-cipher", ref="a2", path="K.java", line=2)
    key = material("secret-key", ref="k", path="K.java", line=3, name="key")
    assets, _ = extract_crypto_assets(
        {
            "components": [rsa, aes, key],
            "dependencies": [{"ref": "k", "dependsOn": ["a1", "a2"]}],
        }
    )
    (linked,) = [a for a in assets if a["asset_type"] == "key"]
    assert not linked.get("key_algorithm_ref")


def test_two_keygens_in_one_file_stay_two_keys() -> None:
    result = build_canonical_cbom(
        extract(
            "cbomkit-action",
            material("secret-key", ref="k1", path="src/Keys.java", line=15, name="secret-key@a"),
            material("secret-key", ref="k2", path="src/Keys.java", line=30, name="secret-key@b"),
        )
    )
    assert len(result["crypto_assets"]) == 2
