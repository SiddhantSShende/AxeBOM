"""Tests for CBOM normalization and QBOM derivation.

The phase's correctness requirement is type-aware coverage: a certificate must
not be scored against `key_size`, and each type's denominator must be its own.
Most of this file defends that and the honest-label rules around it.
"""

from __future__ import annotations

import pytest
from workers.cbom.adapters.cbomkit_theia import extract_crypto_assets, map_asset_type
from workers.cbom.normalize.crypto import TYPE_COLUMNS, normalize_all
from workers.cbom.normalize.pipeline import FIELD_SETS
from workers.qbom.derive import crypto_asset_refs, derive_readiness
from workers.qbom.metadata import DERIVED_FIELDS, form_fields, normalize_device

from axebom_shared.model.generated_certin import CRYPTO_FIELDS_BY_ASSET_TYPE
from axebom_shared.normalize.coverage import score_crypto

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def cyclonedx(components: list[dict]) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}


ALGORITHM = {
    "type": "cryptographic-asset",
    "name": "RSA-2048",
    "bom-ref": "crypto/algorithm/rsa-2048",
    "cryptoProperties": {
        "assetType": "algorithm",
        "oid": "1.2.840.113549.1.1.1",
        "algorithmProperties": {
            "primitive": "pke",
            "cryptoFunctions": ["encapsulate", "decapsulate"],
            "classicalSecurityLevel": 112,
            "parameterSetIdentifier": "2048",
        },
    },
}

KEY = {
    "type": "cryptographic-asset",
    "name": "tls-server-key",
    "bom-ref": "crypto/key/tls-server",
    "cryptoProperties": {
        "assetType": "related-crypto-material",
        "relatedCryptoMaterialProperties": {
            "type": "private-key",
            "id": "kid-7",
            "state": "active",
            "size": 2048,
            "creationDate": "2024-01-02",
        },
    },
}

PROTOCOL = {
    "type": "cryptographic-asset",
    "name": "TLS",
    "bom-ref": "crypto/protocol/tls12",
    "cryptoProperties": {
        "assetType": "protocol",
        "oid": "1.3.6.1.5.5.7",
        "protocolProperties": {
            "version": "1.2",
            "cipherSuites": [{"name": "TLS_RSA_WITH_AES_128_CBC_SHA"}, "TLS_AES_256_GCM_SHA384"],
        },
    },
}

CERTIFICATE = {
    "type": "cryptographic-asset",
    "name": "server.pem",
    "bom-ref": "crypto/cert/server",
    "cryptoProperties": {
        "assetType": "certificate",
        "certificateProperties": {
            "subjectName": "CN=example.com",
            "issuerName": "CN=Example CA",
            "notValidBefore": "2024-01-01T00:00:00Z",
            "notValidAfter": "2025-01-01T00:00:00Z",
            "signatureAlgorithmRef": "crypto/algorithm/sha256-rsa",
            "certificateFormat": "X.509",
        },
    },
    "evidence": {"occurrences": [{"location": "deploy/tls/server.pem"}]},
}


# `profile_fields`/`FIELD_SETS` used to be redefined here as a test-only
# helper. They are real pipeline code now (workers/cbom/normalize/pipeline.py)
# — `build_canonical_cbom` needs the exact same field sets to compute the
# coverage numbers it writes, so this file imports rather than duplicates them.

# ---------------------------------------------------------------------------
# All four types from one scan
# ---------------------------------------------------------------------------


def test_all_four_asset_types_normalize_from_one_document() -> None:
    raw, diagnostics = extract_crypto_assets(cyclonedx([ALGORITHM, KEY, PROTOCOL, CERTIFICATE]))
    assert len(raw) == 4
    assert not [d for d in diagnostics if d["severity"] == "error"]

    assets, errs = normalize_all(raw)
    assert not errs
    assert {a["asset_type"] for a in assets} == {"algorithm", "key", "protocol", "certificate"}


def test_each_type_populates_only_its_own_columns() -> None:
    """⚠ THE CORRECTNESS REQUIREMENT OF THE PHASE.

    Writing every value into every asset looks harmless and is then scored
    against the union of four field sets, reporting every CBOM at roughly 30%.
    """
    raw, _ = extract_crypto_assets(cyclonedx([ALGORITHM, KEY, PROTOCOL, CERTIFICATE]))
    assets, _ = normalize_all(raw)
    by_type = {a["asset_type"]: a for a in assets}

    # A certificate carries no key size and no primitive.
    cert = by_type["certificate"]
    assert "key_size" not in cert
    assert "primitive" not in cert
    assert cert["cert_subject"] == "CN=example.com"

    # A key carries no issuer and no cipher suites.
    key = by_type["key"]
    assert "cert_issuer" not in key
    assert "cipher_suites" not in key
    assert key["key_size"] == 2048

    # A protocol carries no key state.
    protocol = by_type["protocol"]
    assert "key_state" not in protocol
    assert protocol["protocol_version"] == "1.2"

    # An algorithm carries no certificate fields.
    algorithm = by_type["algorithm"]
    assert "cert_format" not in algorithm
    assert algorithm["primitive"] == "pke"


def test_the_column_map_agrees_with_the_compliance_profile() -> None:
    """⚠ THE PROFILE IS THE SOURCE OF TRUTH, NOT TYPE_COLUMNS.

    A CERT-In revision that adds a field to one asset type must fail a test
    rather than silently leaving that column unpopulated forever.
    """
    for asset_type, fields in CRYPTO_FIELDS_BY_ASSET_TYPE.items():
        expected = {
            f.canonical_path.removeprefix("crypto_asset.").removesuffix("[]") for f in fields
        }
        # `asset_type` is scored for every type and lives outside the per-type
        # list, so it is excluded from the comparison rather than duplicated.
        expected.discard("asset_type")
        mapped = set(TYPE_COLUMNS[asset_type])
        assert expected == mapped, (
            f"{asset_type}: the profile and TYPE_COLUMNS disagree.\n"
            f"  only in profile: {sorted(expected - mapped)}\n"
            f"  only in code:    {sorted(mapped - expected)}"
        )


# ---------------------------------------------------------------------------
# Type-aware coverage
# ---------------------------------------------------------------------------


def test_a_certificate_is_not_scored_against_key_size() -> None:
    """⚠ THE FALSE-30% BUG THIS PHASE EXISTS TO PREVENT."""
    raw, _ = extract_crypto_assets(cyclonedx([CERTIFICATE]))
    assets, _ = normalize_all(raw)
    scored = [{f"crypto_asset.{k}": v for k, v in a.items()} for a in assets]

    result = score_crypto(scored, FIELD_SETS)
    scored_ids = {f.field_id for f in result.fields}

    assert "certin.crypto.key.size" not in scored_ids
    assert "certin.crypto.cert.subject_name" in scored_ids


@pytest.mark.parametrize(
    ("asset_type", "expected_fields"),
    [("algorithm", 8), ("key", 7), ("protocol", 5), ("certificate", 10)],
)
def test_each_type_has_its_own_denominator(asset_type: str, expected_fields: int) -> None:
    """The four field sets are 8 / 7 / 5 / 10.

    The numbers are asserted against the PROFILE, not written here — this test
    checks that the profile still says what CERT-In Table 9 says, and it is the
    one place a count is legitimate because it is validating the source.
    """
    assert len(CRYPTO_FIELDS_BY_ASSET_TYPE[asset_type]) == expected_fields


def test_coverage_of_a_mixed_document_uses_each_type_s_fields() -> None:
    raw, _ = extract_crypto_assets(cyclonedx([ALGORITHM, KEY, PROTOCOL, CERTIFICATE]))
    assets, _ = normalize_all(raw)
    scored = [{f"crypto_asset.{k}": v for k, v in a.items()} for a in assets]

    result = score_crypto(scored, FIELD_SETS)

    # Every asset was scored; none fell through to unidentified.
    assert result.scored_entities == 4
    assert result.unidentified_count == 0
    # And the numbers are not the artefact of one wide denominator.
    assert 0 < result.completeness_pct <= 100


# ---------------------------------------------------------------------------
# The analysis
# ---------------------------------------------------------------------------


def test_rsa_is_flagged_and_aes_is_not() -> None:
    """⚠ THE HEADLINE REQUIREMENT, THROUGH THE FULL PIPELINE."""
    aes = {
        "type": "cryptographic-asset",
        "name": "AES-256-GCM",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {"primitive": "ae", "mode": "gcm"},
        },
    }
    raw, _ = extract_crypto_assets(cyclonedx([ALGORITHM, aes]))
    assets, _ = normalize_all(raw)
    by_name = {a["name"]: a for a in assets}

    assert by_name["RSA-2048"]["quantum_vulnerable"] is True
    assert by_name["RSA-2048"]["pqc_recommendation"]

    assert by_name["AES-256-GCM"]["quantum_vulnerable"] is False
    assert "pqc_recommendation" not in by_name["AES-256-GCM"]
    assert "grover_note" in by_name["AES-256-GCM"]


def test_every_flag_carries_a_rationale() -> None:
    """A boolean with no reason is an alarm a security team learns to silence."""
    raw, _ = extract_crypto_assets(cyclonedx([ALGORITHM]))
    assets, _ = normalize_all(raw)
    assert assets[0]["quantum_rationale"]
    assert assets[0]["deprecation_rationale"]


def test_quantum_readiness_group_is_computed_once_and_stored() -> None:
    """migrations/normalize/0005: the QBOM bucket is decided at CBOM-write

    time, not re-derived by a report renderer. RSA lands in `vulnerable`
    (Shor-broken); AES carries a Grover note and lands in `grover_note`, never
    `vulnerable` — the two buckets this whole phase exists to keep separate.
    """
    ml_kem = {
        "type": "cryptographic-asset",
        "name": "ML-KEM-768",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {"primitive": "kem"},
        },
    }
    raw, _ = extract_crypto_assets(cyclonedx([ALGORITHM, ml_kem]))
    assets, _ = normalize_all(raw)
    by_name = {a["name"]: a for a in assets}

    assert by_name["RSA-2048"]["quantum_readiness_group"] == "vulnerable"
    assert by_name["ML-KEM-768"]["quantum_readiness_group"] == "post_quantum"

    aes_raw, _ = extract_crypto_assets(
        cyclonedx(
            [
                {
                    "type": "cryptographic-asset",
                    "name": "AES-256-GCM",
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {"primitive": "ae", "mode": "gcm"},
                    },
                }
            ]
        )
    )
    aes_assets, _ = normalize_all(aes_raw)
    assert aes_assets[0]["quantum_readiness_group"] == "grover_note"


def test_a_certificate_is_assessed_on_the_algorithm_that_signed_it() -> None:
    """Dropping a column from the COVERAGE model is not the same as forgetting
    it exists — the signature algorithm still decides the verdict."""
    sha1_cert = {
        "type": "cryptographic-asset",
        "name": "legacy.pem",
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": {
                "subjectName": "CN=legacy",
                "signatureAlgorithmRef": "sha1WithRSAEncryption",
            },
        },
    }
    raw, _ = extract_crypto_assets(cyclonedx([sha1_cert]))
    assets, _ = normalize_all(raw)

    assert assets[0]["deprecation_status"] == "broken"
    assert assets[0]["quantum_vulnerable"] is True


# ---------------------------------------------------------------------------
# Defensive parsing
# ---------------------------------------------------------------------------


def test_an_asset_with_no_type_is_not_defaulted_to_algorithm() -> None:
    """⚠ DEFAULTING WOULD SCORE IT AGAINST THE WRONG FIELD SET, which is a
    confident false percentage in a compliance document."""
    typeless = {
        "type": "cryptographic-asset",
        "name": "mystery",
        "cryptoProperties": {"oid": "1.2.3"},
    }
    assets, diagnostics = extract_crypto_assets(cyclonedx([typeless]))

    assert assets == []
    assert any("assetType" in d["message"] for d in diagnostics)


def test_related_crypto_material_becomes_a_key_only_when_it_is_one() -> None:
    """CycloneDX's `related-crypto-material` covers nonces and salts too."""
    assert (
        map_asset_type(
            {
                "assetType": "related-crypto-material",
                "relatedCryptoMaterialProperties": {"type": "private-key"},
            }
        )
        == "key"
    )
    assert (
        map_asset_type(
            {
                "assetType": "related-crypto-material",
                "relatedCryptoMaterialProperties": {"type": "nonce"},
            }
        )
        is None
    )


@pytest.mark.parametrize(
    "mutation",
    [
        {"components": "not a list"},
        {"components": [None, 42, "string"]},
        {"components": [{"type": "cryptographic-asset", "cryptoProperties": "not an object"}]},
        {"components": [{"type": "cryptographic-asset", "cryptoProperties": {"assetType": 7}}]},
        {},
    ],
)
def test_defensive_parsing_survives_a_mutated_document(mutation: dict) -> None:
    """⚠ theia's SCHEMA IS EARLY AND MOVING.

    A crash loses a whole scan; a diagnosed gap loses one field and says so.
    Nothing here may raise.
    """
    assets, diagnostics = extract_crypto_assets(mutation)
    assert isinstance(assets, list)
    assert isinstance(diagnostics, list)


def test_an_unknown_key_state_becomes_unknown_not_active() -> None:
    """Defaulting to active would report a revoked key as live."""
    compromised = {
        "type": "cryptographic-asset",
        "name": "k",
        "cryptoProperties": {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {"type": "private-key", "state": "compromised"},
        },
    }
    raw, _ = extract_crypto_assets(cyclonedx([compromised]))
    assert raw[0]["key_state"] == "unknown"


def test_a_size_that_is_not_a_number_is_refused() -> None:
    """`"2048 bits"` from a schema that promised a number is not a key size."""
    odd = {
        "type": "cryptographic-asset",
        "name": "k",
        "cryptoProperties": {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {"type": "private-key", "size": "2048 bits"},
        },
    }
    raw, _ = extract_crypto_assets(cyclonedx([odd]))
    assert raw[0]["key_size"] is None


# ---------------------------------------------------------------------------
# QBOM
# ---------------------------------------------------------------------------


def test_the_qbom_references_crypto_assets_rather_than_duplicating_them() -> None:
    """⚠ A QBOM THAT EMBEDDED THEM WOULD DRIFT FROM THE CBOM the moment either
    is re-normalized, and a reviewer comparing the two would get two answers."""
    raw, _ = extract_crypto_assets(cyclonedx([ALGORITHM, CERTIFICATE]))
    assets, _ = normalize_all(raw)

    refs = crypto_asset_refs(assets)
    assert refs == ["crypto/algorithm/rsa-2048", "crypto/cert/server"]
    # References, not records.
    assert all(isinstance(r, str) for r in refs)


def test_readiness_separates_migration_from_sizing() -> None:
    """The Grover notes are deliberately NOT on the migration list."""
    docs = [
        ALGORITHM,
        {
            "type": "cryptographic-asset",
            "name": "AES-256",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {"primitive": "ae"},
            },
        },
        {
            "type": "cryptographic-asset",
            "name": "ML-KEM-768",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {"primitive": "kem"},
            },
        },
    ]
    raw, _ = extract_crypto_assets(cyclonedx(docs))
    assets, _ = normalize_all(raw)

    readiness = derive_readiness(assets)

    assert [a["name"] for a in readiness.vulnerable] == ["RSA-2048"]
    assert [a["name"] for a in readiness.grover_notes] == ["AES-256"]
    assert [a["name"] for a in readiness.post_quantum] == ["ML-KEM-768"]

    note = readiness.readiness_note()
    assert "require migration" in note
    assert "NOT vulnerabilities" in note


def test_readiness_never_produces_a_score() -> None:
    """⚠ "QUANTUM READINESS: 72%" WOULD BE A NUMBER WE INVENTED, weighted by
    judgements we did not publish, about a threat with no agreed timeline."""
    readiness = derive_readiness([])
    note = readiness.readiness_note()
    assert "%" not in note
    assert "not the same as" in note


def test_an_empty_readiness_does_not_read_as_clean() -> None:
    note = derive_readiness([]).readiness_note()
    assert "Engine Coverage" in note


# ---------------------------------------------------------------------------
# QBOM device metadata
# ---------------------------------------------------------------------------


def test_the_form_is_generated_from_the_profile() -> None:
    """No count is written anywhere; a CERT-In revision adds a field without a
    code change."""
    fields = form_fields()
    from axebom_shared.model.generated_certin import QBOM_FIELDS

    assert len(fields) == len(QBOM_FIELDS)
    assert {f["field_id"] for f in fields} == {f.id for f in QBOM_FIELDS}


def test_derived_elements_are_marked_so_the_form_does_not_ask_for_them() -> None:
    """Asking a user to type the crypto assets would be asking them to
    duplicate the scan."""
    derived = {f["field_id"] for f in form_fields() if f["derived"]}
    assert derived == DERIVED_FIELDS


def test_unrecorded_elements_are_stored_explicitly_as_not_provided() -> None:
    """⚠ OMISSION HIDES THE GAP. The explicit value is what makes it countable
    and reportable (CLAUDE.md invariant 3)."""
    row, gaps = normalize_device({"model_name": "IBM Quantum System Two"})

    assert row["model_name"] == "IBM Quantum System Two"
    assert row["version"] == "not-provided"
    assert row["field_status"]["certin.qbom.01.model_name"] == "provided"
    assert row["field_status"]["certin.qbom.02.version"] == "not-provided"

    gap_ids = {g.field_id for g in gaps}
    assert "certin.qbom.02.version" in gap_ids
    # And each gap says WHY, including that no scanner will fill it in.
    assert all(g.reason for g in gaps)
    assert any("no quantum-hardware scanner" in g.reason for g in gaps)


def test_a_user_typed_not_provided_still_scores_zero() -> None:
    """Declaring the gap is a real act, and it still counts as zero."""
    row, gaps = normalize_device({"model_name": "not-provided"})
    assert row["field_status"]["certin.qbom.01.model_name"] == "not-provided"
    assert any(g.field_id == "certin.qbom.01.model_name" for g in gaps)


def test_an_empty_derived_list_is_a_gap_not_a_provided_value() -> None:
    """A QBOM whose CBOM found nothing has nothing to reference, and recording
    that as present would score a field carrying no information."""
    row, gaps = normalize_device({"model_name": "x"}, crypto_asset_refs=[])

    assert row["crypto_assets"] == []
    assert row["field_status"]["certin.qbom.05.cryptographic_asset"] == "not-provided"
    assert any("Run a CBOM scan" in g.reason for g in gaps)


def test_derived_references_are_recorded_when_present() -> None:
    row, _ = normalize_device({"model_name": "x"}, crypto_asset_refs=["crypto/algorithm/rsa-2048"])
    assert row["crypto_assets"] == ["crypto/algorithm/rsa-2048"]
    assert row["field_status"]["certin.qbom.05.cryptographic_asset"] == "provided"
