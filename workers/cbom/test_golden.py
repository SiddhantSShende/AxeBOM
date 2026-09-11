"""The CBOM golden corpus — normalization replayed over committed engine output.

⚠ NO SCANNER RUNS AND NO NETWORK IS TOUCHED. Each fixture's `raw/<engine>.json`
was produced once by the real, digest-pinned engine and committed; its README
records the invocation. Replaying them is deterministic, fast and offline — the
property (ADR-0003) that lets a normalizer bug be fixed by re-normalizing.

There was no CBOM harness at all until 2026-09-11: `crypto-mixed/expected/` sat
un-checked for weeks, pinning a coverage figure that turned out to be wrong in
two ways. Changing a golden now requires a justification in the commit message.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from workers.cbom.normalize_runner import EXPECTED_FILES, expected_view, normalize_fixture

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"

#: A fixture is a CBOM golden exactly when it pins `expected/crypto_assets.json`.
AVAILABLE = sorted(p.parent.parent.name for p in FIXTURES.glob("*/expected/crypto_assets.json"))


def canonical(name: str) -> dict[str, Any]:
    return normalize_fixture(FIXTURES / name)


def test_there_is_at_least_one_cbom_golden() -> None:
    assert AVAILABLE, "no CBOM golden fixture found; the harness would pass vacuously"


@pytest.mark.golden
@pytest.mark.parametrize("name", AVAILABLE)
def test_the_output_matches_the_golden(name: str) -> None:
    view = json.loads(json.dumps(expected_view(canonical(name)), sort_keys=True))
    for filename in EXPECTED_FILES:
        pinned = json.loads((FIXTURES / name / "expected" / filename).read_text(encoding="utf-8"))
        assert view[filename] == pinned, (
            f"{name}/expected/{filename} differs. If the change is intended, regenerate with "
            f"`python -m workers.cbom.normalize_runner fixtures/{name} --write-expected` and "
            f"justify it in the commit message."
        )


@pytest.mark.golden
@pytest.mark.parametrize("name", AVAILABLE)
def test_normalization_is_deterministic(name: str) -> None:
    assert json.dumps(canonical(name), sort_keys=True) == json.dumps(
        canonical(name), sort_keys=True
    )


@pytest.mark.golden
@pytest.mark.parametrize("name", AVAILABLE)
def test_both_coverage_numbers_are_published_and_honest(name: str) -> None:
    """Invariant 3: two numbers, and `declaration_pct` counts a superset."""
    coverage = canonical(name)["coverage"]
    assert coverage["denominator"] > 0
    assert coverage["formula"]
    assert coverage["declaration_pct"] >= coverage["completeness_pct"]


@pytest.mark.golden
@pytest.mark.parametrize("name", AVAILABLE)
def test_every_asset_has_an_identity_and_evidence(name: str) -> None:
    for asset in canonical(name)["crypto_assets"]:
        assert asset["asset_key"] and asset["identity_rule"], asset["name"]
        assert asset["evidence"], f"{asset['asset_key']} has no evidence"
        assert asset["_provenance"], f"{asset['asset_key']} has no provenance"


@pytest.mark.golden
@pytest.mark.parametrize("name", AVAILABLE)
def test_no_key_material_reaches_the_canonical_output(name: str) -> None:
    """A key's `value` in the raw artifact never appears in what is stored."""
    output = json.dumps(canonical(name))
    for raw in (FIXTURES / name / "raw").glob("*.json"):
        for component in json.loads(raw.read_text(encoding="utf-8")).get("components") or []:
            material = (component.get("cryptoProperties") or {}).get(
                "relatedCryptoMaterialProperties"
            ) or {}
            value = material.get("value")
            if isinstance(value, str) and len(value) > 16:
                assert value not in output, f"{raw.name}: key material reached the output"


# -- what crypto-mixed specifically proves ---------------------------------


def _crypto_mixed() -> dict[str, Any]:
    return canonical("crypto-mixed")


def _locations(asset: dict[str, Any]) -> set[tuple[str, int | None, str]]:
    return {(e["path"], e["line"], e["engine"]) for e in asset["evidence"]}


def test_the_source_engine_finds_what_no_file_scanner_could() -> None:
    """⚠ THE GAP THIS WORK EXISTS TO CLOSE. `CryptoConfig.java` uses JCA five
    times; cbomkit-theia, which reads files, found none of them."""
    java = "src/main/java/com/example/CryptoConfig.java"
    lines = {
        line
        for asset in _crypto_mixed()["crypto_assets"]
        for path, line, engine in _locations(asset)
        if path == java and engine == "cbomkit-action"
    }
    # TLSv1.2 (11), RSA-2048 keygen (15), AES-256 keygen (21), AES/CBC (23), SHA-256 (27).
    assert {11, 15, 21, 23, 27} <= lines


def test_one_hash_seen_by_two_engines_is_one_asset() -> None:
    """theia's `SHA256` (from the certificate) and cbomkit-action's `SHA-256`
    (from `MessageDigest.getInstance`) are one algorithm with two locations."""
    hashes = [
        a for a in _crypto_mixed()["crypto_assets"] if a["asset_key"].startswith("algorithm:sha2;")
    ]
    assert len(hashes) == 1
    engines = {engine for _path, _line, engine in _locations(hashes[0])}
    assert engines == {"cbomkit-theia", "cbomkit-action"}


def test_cdxgen_s_pem_certificate_is_left_to_theia() -> None:
    codes = {d["code"] for d in _crypto_mixed()["diagnostics"]}
    assert "NORMALIZE_CRYPTO_FILE_FINDING_DEFERRED" in codes
    certificates = [a for a in _crypto_mixed()["crypto_assets"] if a["asset_type"] == "certificate"]
    assert len(certificates) == 1
    assert {p["engine_id"] for p in certificates[0]["_provenance"]} == {"cbomkit-theia"}


def test_a_generated_key_is_not_reported_as_a_key_in_the_source() -> None:
    """cbomkit-action's RSA/AES keygen entries are runtime keys, not committed ones."""
    codes = {d["code"] for d in _crypto_mixed()["diagnostics"]}
    assert "CBOM_PRIVATE_KEY_IN_SOURCE" not in codes


def test_the_generated_rsa_key_is_quantum_vulnerable() -> None:
    """`KeyPairGenerator.getInstance("RSA")` on line 15 — cbomkit-action names the
    key `key` and links it to RSA-2048 only through `dependencies`."""
    (key,) = [
        a
        for a in _crypto_mixed()["crypto_assets"]
        if a["asset_type"] == "key" and a["attributes"].get("material_type") == "secret-key"
        if ("src/main/java/com/example/CryptoConfig.java", 15, "cbomkit-action") in _locations(a)
    ]
    assert key["quantum_vulnerable"] is True
    assert key["attributes"]["algorithm_key"].startswith("algorithm:rsa;bits=2048")


# -- what crypto-quantum specifically proves -------------------------------


def _crypto_quantum() -> list[dict[str, Any]]:
    return canonical("crypto-quantum")["crypto_assets"]


def _one(prefix: str) -> dict[str, Any]:
    (asset,) = [a for a in _crypto_quantum() if a["asset_key"].startswith(prefix)]
    return asset


@pytest.mark.parametrize(
    ("prefix", "status", "reference"),
    [
        ("algorithm:aes;bits=128;mode=ecb;padding=pkcs5;", "broken", "NIST SP 800-38A"),
        ("algorithm:md5;", "broken", "RFC 6151"),
        ("algorithm:sha1;", "broken", "NIST SP 800-131A Rev. 2"),
        ("algorithm:3des;mode=cbc;padding=pkcs5;", "weak", "NIST SP 800-131A Rev. 2"),
        ("algorithm:rsa;bits=1024;", "weak", "NIST SP 800-131A Rev. 2"),
        ("algorithm:dsa;bits=2048;", "deprecated", "FIPS 186-5"),
        ("algorithm:eddsa;", "current", "RFC 8032 / RFC 7748"),
        ("algorithm:ml-kem;", "current", "FIPS 203"),
        ("algorithm:ml-dsa;", "current", "FIPS 204"),
    ],
)
def test_each_classical_verdict_is_the_cited_one(prefix: str, status: str, reference: str) -> None:
    asset = _one(prefix)
    assert (asset["deprecation_status"], asset["deprecation_reference"]) == (status, reference)


def test_shor_breaks_the_asymmetric_families_and_not_the_post_quantum_ones() -> None:
    for prefix in (
        "algorithm:rsa;bits=1024;",
        "algorithm:dsa;",
        "algorithm:eddsa;",
        "algorithm:xdh;",
        "algorithm:ec;curve=p-256;",
    ):
        assert _one(prefix)["quantum_vulnerable"] is True, prefix
    for prefix in ("algorithm:ml-kem;", "algorithm:ml-dsa;"):
        asset = _one(prefix)
        assert asset["quantum_vulnerable"] is False
        assert asset["quantum_readiness_group"] == "post_quantum"
        assert "pqc_recommendation" not in asset


def test_a_signature_scheme_is_told_to_migrate_to_ml_dsa_not_ml_kem() -> None:
    """⚠ Every key-pair generator comes back with function `keygen`, which was
    read as key establishment: Ed25519 and DSA were told to adopt ML-KEM."""
    for prefix in ("algorithm:eddsa;", "algorithm:dsa;"):
        assert _one(prefix)["pqc_recommendation"].startswith("ML-DSA"), prefix
    assert _one("algorithm:xdh;")["pqc_recommendation"].startswith("ML-KEM")


def test_a_bare_jca_ec_is_quantum_vulnerable_and_unassessed() -> None:
    """⚠ `KeyPairGenerator.getInstance("EC")` reached the rules as `EC`, matched
    nothing, and both it and its key were reported not quantum-vulnerable."""
    algorithm = _one("name:algorithm/ec;")
    key = _one("key:secret-key;path=src/main/java/com/example/LegacyAndPqc.java:23")
    for asset in (algorithm, key):
        assert asset["quantum_vulnerable"] is True
        assert asset["deprecation_status"] == "unassessed"


def test_symmetric_and_hash_assets_get_a_grover_note_and_no_migration() -> None:
    for asset in _crypto_quantum():
        if asset["quantum_family"] in {"aes", "3des", "md5", "sha1", "sha2"}:
            assert asset["quantum_vulnerable"] is False, asset["asset_key"]
            assert asset.get("grover_note"), asset["asset_key"]
            assert "pqc_recommendation" not in asset, asset["asset_key"]


def test_a_key_size_reported_only_as_a_parameter_set_reaches_the_grover_note() -> None:
    """pyca's `AES-ECB` carries its 128 only in `parameterSetIdentifier`."""
    asset = _one("algorithm:aes;bits=128;mode=ecb;primitive=block-cipher")
    assert asset["effective_quantum_bits"] == 64


def test_an_unsized_rsa_stays_unassessed_never_current() -> None:
    """cdxgen reports `generateKeyPairSync('rsa', {modulusLength: 1024})` as a bare
    `rsa`. It is not `weak` here because nothing says 1024; it is never `current`."""
    (asset,) = [a for a in _crypto_quantum() if a["asset_key"] == "algorithm:rsa"]
    assert asset["deprecation_status"] == "unassessed"
    assert asset["quantum_vulnerable"] is True


def test_one_hash_from_three_files_and_two_engines_is_one_asset() -> None:
    md5 = _one("algorithm:md5;")
    assert {(e["path"], e["line"], e["engine"]) for e in md5["evidence"]} == {
        ("app/legacy_and_pqc.py", 10, "cbomkit-action"),
        ("src/main/java/com/example/LegacyAndPqc.java", 12, "cbomkit-action"),
        ("web/legacy.js", 4, "cdxgen-cbom"),
    }


def test_cdxgen_s_sha1_oid_is_diagnosed_and_the_source_engine_s_kept() -> None:
    assert _one("algorithm:sha1;")["oid"] == "1.3.14.3.2.26"
    codes = {d["code"] for d in canonical("crypto-quantum")["diagnostics"]}
    assert "NORMALIZE_CRYPTO_FIELD_CONFLICT" in codes


def test_keys_the_code_generates_are_never_keys_in_the_source() -> None:
    """cbomkit-action reports pyca's `generate_private_key` as `private-key` material."""
    document = canonical("crypto-quantum")
    assert not any(a["attributes"].get("private_key_in_source") for a in document["crypto_assets"])
    assert "CBOM_PRIVATE_KEY_IN_SOURCE" not in {d["code"] for d in document["diagnostics"]}
