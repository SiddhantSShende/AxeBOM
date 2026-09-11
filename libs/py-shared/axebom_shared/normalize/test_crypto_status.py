"""The one shared definition of a crypto asset's per-field status.

Both halves of the CBOM coverage bug found on 2026-09-11 are pinned here:

1. A list-valued field (crypto functions, algorithm list, cipher suites) must
   score as present when the asset holds a value. It scored zero on every CBOM
   because the profile's `[]` notation was used as a lookup key.
2. A field the stored `field_status` calls `not-provided` must count as
   DECLARED. It never did, so every CBOM published declaration_pct equal to
   completeness_pct.

And the `derived` status (user decision 2026-09-11: derive + count, labelled):
a value AxeBOM filled from a cited reference table is present, and is labelled.
"""

from __future__ import annotations

from typing import Any

import pytest

from axebom_shared.model.generated_certin import CRYPTO_FIELDS_BY_ASSET_TYPE
from axebom_shared.normalize.bulk import _crypto_field_status
from axebom_shared.normalize.coverage import Field, is_declared, is_substantive, score_crypto
from axebom_shared.normalize.crypto_status import (
    DERIVED,
    NOT_PROVIDED,
    PROVIDED,
    column_of,
    derived_counts,
    field_status,
    scored_entity,
    scored_path,
    type_columns,
)

FIELD_SETS: dict[str, list[Field]] = {
    asset_type: [
        Field(id=f.id, name=f.name, canonical_path=scored_path(f.canonical_path), weight=f.weight)
        for f in fields
    ]
    for asset_type, fields in CRYPTO_FIELDS_BY_ASSET_TYPE.items()
}

#: One partially known asset per type — every sample leaves at least one field
#: of its own type unknown, so declared and present must differ.
SAMPLES: dict[str, dict[str, Any]] = {
    "algorithm": {
        "asset_type": "algorithm",
        "name": "SHA256-RSA",
        "primitive": "signature",
        "crypto_functions": ["sign"],
    },
    "key": {"asset_type": "key", "name": "RSA-2048", "key_size": 2048, "key_state": "unknown"},
    "protocol": {
        "asset_type": "protocol",
        "name": "TLS",
        "protocol_version": "1.2",
        "cipher_suites": ["TLS_AES_256_GCM_SHA384"],
    },
    "certificate": {"asset_type": "certificate", "name": "example.com", "cert_subject": "CN=x"},
}

#: An algorithm whose security level AxeBOM filled from a reference table.
DERIVED_AES = {
    "asset_type": "algorithm",
    "name": "AES-256-GCM",
    "primitive": "ae",
    "mode": "gcm",
    "classical_security_level": 256,
    "derivations": {"classical_security_level": "nist-sp800-57p1r5-table2"},
}


def field_id_for(asset_type: str, column: str) -> str:
    """The profile id of one column — looked up, never written as a literal."""
    for f in CRYPTO_FIELDS_BY_ASSET_TYPE[asset_type]:
        if column_of(f.canonical_path) == column:
            return f.id
    raise AssertionError(f"the profile has no {column!r} field for {asset_type}")


def test_every_type_in_the_profile_has_a_sample() -> None:
    """A type added to the profile must be exercised here, not skipped."""
    assert set(SAMPLES) == set(CRYPTO_FIELDS_BY_ASSET_TYPE)


def test_no_scored_path_carries_the_list_notation() -> None:
    for asset_type, fields in FIELD_SETS.items():
        for f in fields:
            assert not f.canonical_path.endswith("[]"), (asset_type, f.id)
            assert column_of(f.canonical_path) in type_columns(asset_type)


@pytest.mark.parametrize(
    ("asset_type", "column"),
    [("algorithm", "crypto_functions"), ("protocol", "cipher_suites")],
)
def test_a_list_field_scores_present_when_it_holds_a_value(asset_type: str, column: str) -> None:
    """⚠ THE ZERO THAT WAS ON EVERY CBOM: `crypto_functions: ["sign"]` scored 0/1."""
    result = score_crypto([scored_entity(SAMPLES[asset_type])], FIELD_SETS)
    by_id = {f.field_id: f for f in result.fields}

    scored = by_id[field_id_for(asset_type, column)]
    assert scored.present == 1
    assert scored.declared == 1


@pytest.mark.parametrize("asset_type", sorted(SAMPLES))
def test_every_field_of_the_asset_s_type_is_declared(asset_type: str) -> None:
    entity = scored_entity(SAMPLES[asset_type])
    for f in FIELD_SETS[asset_type]:
        assert is_declared(entity[f.canonical_path]), f.id


@pytest.mark.parametrize("asset_type", sorted(SAMPLES))
def test_declaration_exceeds_completeness_when_a_field_is_unknown(asset_type: str) -> None:
    """⚠ THE TWO NUMBERS MUST DIFFER WHEN SOMETHING IS UNKNOWN (invariant 3).

    Every field is declared — a value or an explicit `not-provided` — so an
    identified asset declares everything, and completeness counts only values.
    """
    result = score_crypto([scored_entity(SAMPLES[asset_type])], FIELD_SETS)

    assert result.declaration_pct == 100.0
    assert result.completeness_pct < result.declaration_pct


@pytest.mark.parametrize("asset", [*SAMPLES.values(), DERIVED_AES])
def test_the_stored_status_and_the_scored_value_agree_field_by_field(asset: dict) -> None:
    """Provided or derived exactly when the scorer counts the value as present."""
    status = field_status(asset)
    entity = scored_entity(asset)

    for f in FIELD_SETS[asset["asset_type"]]:
        column = column_of(f.canonical_path)
        substantive = is_substantive(entity[f.canonical_path])
        assert (status[column] in {PROVIDED, DERIVED}) == substantive, f.id


def test_an_unknown_key_state_is_declared_but_not_present() -> None:
    """The one crypto column where "has a value" and "is known" differ."""
    key = SAMPLES["key"]

    assert field_status(key)["key_state"] == NOT_PROVIDED
    assert scored_entity(key)["crypto_asset.key_state"] == "unknown"


def test_a_missing_field_is_scored_as_explicit_not_provided() -> None:
    entity = scored_entity(SAMPLES["certificate"])
    assert entity["crypto_asset.cert_issuer"] == NOT_PROVIDED


def test_only_the_asset_s_own_type_is_described() -> None:
    """A certificate is never asked for a key size (invariant 5)."""
    cert = SAMPLES["certificate"]

    assert "key_size" not in field_status(cert)
    assert "crypto_asset.key_size" not in scored_entity(cert)


def test_an_asset_with_no_field_set_is_unidentified_not_guessed() -> None:
    result = score_crypto([scored_entity({"asset_type": "nonce"})], FIELD_SETS)

    assert result.unidentified_count == 1
    assert result.scored_entities == 1


@pytest.mark.parametrize("asset", [*SAMPLES.values(), DERIVED_AES])
def test_the_writer_stores_exactly_this_status(asset: dict) -> None:
    """The column the writer persists and the scorer's input cannot drift."""
    assert _crypto_field_status(asset) == field_status(asset)


# ---------------------------------------------------------------------------
# Derived values: present, and labelled
# ---------------------------------------------------------------------------


def test_a_derived_value_is_stored_as_derived_and_scores_present() -> None:
    status = field_status(DERIVED_AES)
    assert status["classical_security_level"] == DERIVED
    assert status["mode"] == PROVIDED

    result = score_crypto([scored_entity(DERIVED_AES)], FIELD_SETS)
    level = {f.field_id: f for f in result.fields}[
        field_id_for("algorithm", "classical_security_level")
    ]
    assert level.present == 1


def test_a_derivation_record_without_a_value_claims_nothing() -> None:
    """A stale `derivations` entry must never turn an absent value into a claim."""
    asset = {
        "asset_type": "algorithm",
        "name": "AES",
        "derivations": {"classical_security_level": "nist-sp800-57p1r5-table2"},
    }
    assert field_status(asset)["classical_security_level"] == NOT_PROVIDED
    assert derived_counts([asset]) == {}


def test_derived_counts_tally_per_field_across_assets() -> None:
    second = {**DERIVED_AES, "name": "AES-128-GCM", "classical_security_level": 128}
    counts = derived_counts([DERIVED_AES, second, SAMPLES["algorithm"]])

    assert counts == {field_id_for("algorithm", "classical_security_level"): 2}
