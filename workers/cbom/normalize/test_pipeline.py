"""build_canonical_cbom: pure-function assembly, no database needed.

Uses the same hand-built CycloneDX fixtures `test_crypto_normalize.py` already
exercises the extractor and `normalize_all` against — this module tests the
one additional step on top of those: assembling the document `bulk.plan()`
and `write_bom_document` expect. Live-Postgres write coverage lives in
`libs/py-shared/axebom_shared/normalize/test_bulk.py` and `test_writer.py`.
"""

from __future__ import annotations

import uuid

from workers.cbom.adapters.cbomkit_theia import extract_crypto_assets
from workers.cbom.normalize.crypto import normalize_all
from workers.cbom.normalize.pipeline import FIELD_SETS, build_canonical_cbom
from workers.cbom.test_crypto_normalize import ALGORITHM, CERTIFICATE, KEY, PROTOCOL, cyclonedx

from axebom_shared.normalize.coverage import score_crypto


def test_the_document_has_every_key_write_bom_document_reads() -> None:
    """`write_bom_document` reads `ruleset_version`, `spdx_license_list_version`,
    `coverage`, `unidentified_count` and `provenance.alias_snapshot_id` off the
    top level (see its own source) — every one of them has to be present, or
    the write fails three network round trips later with a much less legible
    error than a test catching it here."""
    raw, _ = extract_crypto_assets(cyclonedx([ALGORITHM, KEY, PROTOCOL, CERTIFICATE]))
    doc = build_canonical_cbom(raw)

    assert isinstance(doc["crypto_assets"], list) and doc["crypto_assets"]
    assert isinstance(doc["coverage"], dict)
    assert doc["ruleset_version"]
    assert doc["spdx_license_list_version"] == ""
    assert isinstance(doc["unidentified_count"], int)
    assert isinstance(doc["diagnostics"], list)

    # ⚠ MUST PARSE AS A REAL UUID — writer.py's _require_uuid rejects anything
    # else, including a human-readable fixture placeholder, with a message
    # naming the field rather than an opaque Postgres type-cast error.
    alias_snapshot_id = doc["provenance"]["alias_snapshot_id"]
    assert str(uuid.UUID(alias_snapshot_id)) == alias_snapshot_id


def test_the_assets_are_exactly_what_normalize_all_produces() -> None:
    """No merge, no graph, no alias closure (see the module docstring) — the
    assembly step must not silently transform what crypto.py already decided."""
    raw, _ = extract_crypto_assets(cyclonedx([ALGORITHM, KEY, PROTOCOL, CERTIFICATE]))
    expected, _ = normalize_all(raw)

    doc = build_canonical_cbom(raw)

    assert doc["crypto_assets"] == expected


def test_a_certificate_inherits_its_signers_quantum_verdict() -> None:
    """⚠ THE BUG REAL cbomkit-theia OUTPUT SURFACES, A HAND-BUILT FIXTURE
    NEVER DID.

    `CERTIFICATE`'s own `signatureAlgorithmRef` ("crypto/algorithm/sha256-rsa")
    never matches `ALGORITHM`'s bom-ref ("crypto/algorithm/rsa-2048") — every
    other test in this file exercises the DANGLING-reference path, never
    actual resolution, because none of the shared fixtures' refs happen to
    line up. Real cbomkit-theia output points a certificate at a SIBLING
    asset's own internal id, so this test builds that alignment on purpose:
    a certificate whose signature_algo_ref is a bom-ref matching a real RSA
    algorithm asset in the same document, the way a live scan actually shapes
    it, and asserts the certificate ends up `quantum_vulnerable=True` —
    inherited from what signed it, not left `False` because a UUID matched no
    regex.
    """
    rsa_signer = {
        "type": "cryptographic-asset",
        "name": "SHA256-RSA",
        "bom-ref": "signer-bom-ref-1234",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {"primitive": "signature"},
        },
    }
    signed_cert = {
        "type": "cryptographic-asset",
        "name": "leaf.example.com",
        "bom-ref": "cert-bom-ref-5678",
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": {
                "subjectName": "leaf.example.com",
                "issuerName": "leaf.example.com",
                "signatureAlgorithmRef": "signer-bom-ref-1234",
                "certificateFormat": "X.509",
            },
        },
    }
    raw, _ = extract_crypto_assets(cyclonedx([rsa_signer, signed_cert]))
    doc = build_canonical_cbom(raw)

    by_name = {a["name"]: a for a in doc["crypto_assets"]}
    cert = by_name["leaf.example.com"]

    assert cert["quantum_vulnerable"] is True
    assert cert["quantum_family"] == "rsa"
    assert cert["quantum_readiness_group"] == "vulnerable"
    # Display-name rewrite: no bom-ref UUID left in the rendered field.
    assert cert["signature_algo_ref"] == "SHA256-RSA"
    # The certificate's OWN failed-match diagnostic must not survive next to
    # a verdict that came from successful inheritance.
    assert "analysis_diagnostics" not in cert


def test_a_dangling_signature_ref_is_left_unassessed_with_a_diagnostic() -> None:
    """No sibling asset carries the referenced bom-ref — the honest outcome is
    an unassessed certificate and a diagnostic naming the gap, never a guess."""
    orphan_cert = {
        "type": "cryptographic-asset",
        "name": "orphan.example.com",
        "bom-ref": "cert-bom-ref-orphan",
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": {
                "subjectName": "orphan.example.com",
                "issuerName": "orphan.example.com",
                "signatureAlgorithmRef": "no-such-bom-ref",
                "certificateFormat": "X.509",
            },
        },
    }
    raw, _ = extract_crypto_assets(cyclonedx([orphan_cert]))
    doc = build_canonical_cbom(raw)

    cert = doc["crypto_assets"][0]
    assert cert["quantum_readiness_group"] == "unassessed"
    # Left as the raw bom-ref, not blanked — still evidence, even unresolved.
    assert cert["signature_algo_ref"] == "no-such-bom-ref"
    assert any(d["code"] == "NORMALIZE_CRYPTO_ASSET_REF_UNRESOLVED" for d in doc["diagnostics"])


def test_coverage_matches_calling_score_crypto_directly() -> None:
    """⚠ NOT A SECOND IMPLEMENTATION OF SCORING.

    `build_canonical_cbom` must call the same `score_crypto` + `FIELD_SETS`
    every other caller uses, not recompute the numbers its own way — two
    implementations of the same formula are exactly how a report and its own
    coverage badge disagree the first time either one changes.
    """
    raw, _ = extract_crypto_assets(cyclonedx([ALGORITHM, KEY, PROTOCOL, CERTIFICATE]))
    assets, _ = normalize_all(raw)
    expected = score_crypto(
        [{f"crypto_asset.{k}": v for k, v in a.items()} for a in assets], FIELD_SETS
    )

    doc = build_canonical_cbom(raw)

    assert doc["coverage"] == expected.as_dict()


def test_a_certificate_only_document_is_not_scored_against_key_size() -> None:
    """⚠ THE FALSE-30% BUG, THROUGH THE FULL ASSEMBLY STEP — not just
    `score_crypto` in isolation, which `test_crypto_normalize.py` already
    covers, but the function a real caller would actually use."""
    raw, _ = extract_crypto_assets(cyclonedx([CERTIFICATE]))
    doc = build_canonical_cbom(raw)

    scored_ids = {f["field_id"] for f in doc["coverage"]["fields"]}
    assert "certin.crypto.key.size" not in scored_ids
    assert "certin.crypto.cert.subject_name" in scored_ids


def test_an_empty_scan_produces_a_valid_zero_document() -> None:
    """A project with no cryptographic assets at all must still assemble a
    well-shaped document — zero assets is a real, first-class outcome
    (cbomkit_theia's own adapter reports it as `partial`, never a crash)."""
    doc = build_canonical_cbom([])

    assert doc["crypto_assets"] == []
    assert doc["coverage"]["scored_entities"] == 0
    # Zero entities is zero coverage, not 100% — coverage.py's own _pct
    # docstring: "a scan that found nothing must not report perfect coverage
    # of nothing."
    assert doc["coverage"]["completeness_pct"] == 0.0


def test_two_calls_over_the_same_input_mint_different_alias_snapshot_ids() -> None:
    """⚠ THE ONE DELIBERATE NON-DETERMINISM, DOCUMENTED RATHER THAN ACCIDENTAL.

    Every other field is byte-identical across repeated calls (CLAUDE.md
    invariant 10) — `alias_snapshot_id` is not, because CBOM has no real
    snapshot concept for it to replay FROM in the first place (see
    `build_canonical_cbom`'s docstring and the HBOM precedent it cites).
    """
    raw, _ = extract_crypto_assets(cyclonedx([ALGORITHM]))

    first = build_canonical_cbom(raw)
    second = build_canonical_cbom(raw)

    assert first["crypto_assets"] == second["crypto_assets"]
    assert first["coverage"] == second["coverage"]
    assert first["provenance"]["alias_snapshot_id"] != second["provenance"]["alias_snapshot_id"]


def test_a_custom_ruleset_version_is_carried_through() -> None:
    raw, _ = extract_crypto_assets(cyclonedx([ALGORITHM]))
    doc = build_canonical_cbom(raw, ruleset_version="test-ruleset-9")
    assert doc["ruleset_version"] == "test-ruleset-9"
