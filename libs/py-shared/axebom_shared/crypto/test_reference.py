"""The cited reference table: fills only what it can state exactly, never overwrites.

User decision (2026-09-11): derive + count, labelled.
"""

from __future__ import annotations

from typing import Any

import pytest

from axebom_shared.crypto import reference
from axebom_shared.crypto.reference import (
    CSOR_AES,
    CSOR_HASH,
    CSOR_PQC,
    DERIVABLE_COLUMNS,
    REFERENCES,
    SP800_57_TABLE2,
    derivation_sources,
    derive_reference_values,
)


def derive(name: str, **raw: Any) -> dict[str, Any]:
    asset: dict[str, Any] = {"asset_type": raw.pop("asset_type", "algorithm"), "name": name}
    for column in ("mode", "classical_security_level", "oid"):
        if column in raw:
            asset[column] = raw.pop(column)
    derive_reference_values(asset, {"name": name, **raw})
    return asset


def test_a_fully_identified_aes_gets_its_level_and_its_oid() -> None:
    asset = derive("AES-256-GCM", primitive="ae")

    assert asset["classical_security_level"] == 256
    assert asset["oid"] == "2.16.840.1.101.3.4.1.46"
    assert asset["derivations"] == {"classical_security_level": SP800_57_TABLE2, "oid": CSOR_AES}


def test_aes_without_a_mode_gets_a_level_but_no_oid() -> None:
    """The OID encodes the mode; the level does not."""
    asset = derive("AES-128")

    assert asset["classical_security_level"] == 128
    assert "oid" not in asset


@pytest.mark.parametrize("name", ["AES/CBC/PKCS5Padding", "RSA", "SHA256-RSA", "ACME-9000"])
def test_nothing_is_filled_without_the_facts_that_decide_it(name: str) -> None:
    """⚠ Bare RSA: the modulus decides the level. AES/CBC with no size: no level,
    no OID. theia's SHA256-RSA: the digest is known, the modulus is not."""
    asset = derive(name, primitive="signature" if "RSA" in name else "")
    assert "classical_security_level" not in asset


def test_a_modulus_table_2_does_not_state_gets_nothing() -> None:
    """RSA-4096 is not a row of SP 800-57 Table 2 — no interpolation."""
    assert "classical_security_level" not in derive("RSA-4096")
    assert derive("RSA-2048")["classical_security_level"] == 112
    assert derive("RSA-3072")["classical_security_level"] == 128


def test_hash_and_sign_names_resolve_to_their_signature_oid() -> None:
    for name in ("SHA256-RSA", "SHA256withRSA", "sha256WithRSAEncryption"):
        assert derive(name, primitive="signature")["oid"] == "1.2.840.113549.1.1.11", name
    assert derive("ecdsa-with-SHA384")["oid"] == "1.2.840.10045.4.3.3"


def test_a_hash_gets_its_oid_but_no_level() -> None:
    """A hash's strength depends on its use (collision vs preimage); no single
    Table 2 value states it, so none is derived."""
    asset = derive("SHA-256", primitive="hash")

    assert asset["oid"] == "2.16.840.1.101.3.4.2.1"
    assert asset["derivations"] == {"oid": CSOR_HASH}
    assert "classical_security_level" not in asset


def test_post_quantum_oids_come_from_the_register() -> None:
    assert derive("ML-KEM-768")["oid"] == "2.16.840.1.101.3.4.4.2"
    assert derive("ML-DSA-65")["oid"] == "2.16.840.1.101.3.4.3.18"
    assert derive("SLH-DSA-SHA2-128s")["oid"] == "2.16.840.1.101.3.4.3.20"
    assert derive("ML-KEM-768")["derivations"]["oid"] == CSOR_PQC
    # A post-quantum parameter set is not a classical security level.
    assert "classical_security_level" not in derive("ML-KEM-768")


def test_an_ecdsa_curve_decides_the_level() -> None:
    assert derive("ECDSA", curve="secp256r1")["classical_security_level"] == 128
    assert derive("ECDSA", curve="secp384r1")["classical_security_level"] == 192
    assert "classical_security_level" not in derive("ECDSA")


def test_edwards_levels_come_from_rfc_8032_and_x25519_gets_none() -> None:
    """RFC 8032 §8.5 states Ed25519/Ed448 outright. RFC 7748 puts X25519 at
    "~128" and "slightly under" — approximate, so no level is derived for it."""
    ed = derive("Ed25519")
    assert ed["classical_security_level"] == 128
    assert ed["derivations"]["classical_security_level"] == reference.RFC8032
    assert derive("Ed448")["classical_security_level"] == 224

    x = derive("X25519")
    assert "classical_security_level" not in x
    assert x["oid"] == "1.3.101.110"


def test_an_engine_value_is_never_overwritten_and_a_conflict_is_diagnosed() -> None:
    asset = derive("AES-256-GCM", classical_security_level=128)

    assert asset["classical_security_level"] == 128
    assert "classical_security_level" not in asset.get("derivations", {})
    assert any("NORMALIZE_CRYPTO_REFERENCE_CONFLICT" in d for d in asset["analysis_diagnostics"])


def test_an_engine_value_that_agrees_is_neither_derived_nor_a_conflict() -> None:
    asset = derive("SHA-256", oid="2.16.840.1.101.3.4.2.1")

    assert "derivations" not in asset
    assert not asset.get("analysis_diagnostics")


@pytest.mark.parametrize("asset_type", ["key", "protocol", "certificate"])
def test_only_algorithms_are_touched(asset_type: str) -> None:
    asset = derive("AES-256-GCM", asset_type=asset_type)
    assert "derivations" not in asset
    assert "oid" not in asset


def test_only_derivable_columns_are_ever_filled() -> None:
    asset = derive("AES-256-GCM", primitive="ae")
    assert set(asset["derivations"]) <= set(DERIVABLE_COLUMNS)


def test_every_reference_used_is_cited_and_every_citation_is_used() -> None:
    from pathlib import Path

    text = Path(reference.__file__).read_text(encoding="utf-8")
    for reference_id in REFERENCES:
        # Each constant naming a reference appears at least once outside the dict.
        assert text.count(reference_id) >= 1, reference_id
    assert all(REFERENCES.values())


def test_derivation_sources_names_exactly_the_references_used() -> None:
    assets = [derive("AES-256-GCM"), derive("SHA-256"), derive("RSA")]
    assert derivation_sources(assets) == {
        CSOR_AES: REFERENCES[CSOR_AES],
        CSOR_HASH: REFERENCES[CSOR_HASH],
        SP800_57_TABLE2: REFERENCES[SP800_57_TABLE2],
    }


def test_the_digest_is_stable_across_calls() -> None:
    assert reference.table_digest() == reference.table_digest()
