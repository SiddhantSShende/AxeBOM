"""build_canonical_cbom: pure-function assembly, no database needed.

Uses the same hand-built CycloneDX fixtures `test_crypto_normalize.py` already
exercises the extractor and `normalize_all` against — this module tests the
one additional step on top of those: assembling the document `bulk.plan()`
and `write_bom_document` expect. Live-Postgres write coverage lives in
`libs/py-shared/axebom_shared/normalize/test_bulk.py` and `test_writer.py`.
"""

from __future__ import annotations

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

    # ⚠ None IS THE CBOM-SHAPED ANSWER, AND THE KEY MUST STILL BE PRESENT.
    # bom_documents.alias_snapshot_id became nullable with a real FK in
    # migration 0012, so CBOM stopped minting a throwaway uuid to satisfy NOT
    # NULL. writer.py's _optional_uuid accepts None and still rejects a
    # malformed string, so what this asserts is that the key exists and carries
    # the honest value — not that the key was quietly dropped.
    assert "alias_snapshot_id" in doc["provenance"]
    assert doc["provenance"]["alias_snapshot_id"] is None


def test_assembly_keeps_what_crypto_py_decided_for_every_cert_in_column() -> None:
    """With nothing to merge (four distinct assets), every CERT-In column on the
    document is exactly what crypto.py produced for that asset. The identity and
    merge stages add identity, evidence and provenance; they change nothing else.
    (This test used to assert the WHOLE asset was unchanged, which stopped being
    true the moment assets gained an identity.)"""
    from workers.cbom.normalize.crypto import TYPE_COLUMNS

    raw, _ = extract_crypto_assets(cyclonedx([ALGORITHM, KEY, PROTOCOL, CERTIFICATE]))
    expected = {a["name"]: a for a in normalize_all(raw)[0]}

    doc = build_canonical_cbom(raw)

    assert len(doc["crypto_assets"]) == 4
    for asset in doc["crypto_assets"]:
        want = expected[asset["name"]]
        for column in TYPE_COLUMNS[asset["asset_type"]]:
            if column in {"signature_algo_ref", "subject_public_key_ref"}:
                # Resolved to a name, or diagnosed, by certificate resolution.
                continue
            got, expected_value = asset.get(column), want.get(column)
            if isinstance(expected_value, list):
                # The merge unions list fields in sorted order, so two engines'
                # lists combine deterministically; the membership is what matters.
                got, expected_value = sorted(got or []), sorted(expected_value)
            assert got == expected_value, (asset["name"], column)
        assert asset["asset_key"]
        assert asset["identity_rule"]


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
    from axebom_shared.crypto.reference import derivation_sources
    from axebom_shared.normalize.crypto_status import derived_counts, scored_entity

    raw, _ = extract_crypto_assets(cyclonedx([ALGORITHM, KEY, PROTOCOL, CERTIFICATE]))
    assets, _ = normalize_all(raw)
    expected = score_crypto([scored_entity(a) for a in assets], FIELD_SETS).as_dict()
    # The derived tally and its citations ride on the same breakdown, from the
    # same shared helpers — still one scoring implementation, never two.
    counts = derived_counts(assets)
    for field in expected["fields"]:
        field["derived"] = counts.get(field["field_id"], 0)
    expected["derivation_sources"] = derivation_sources(assets)

    doc = build_canonical_cbom(raw)

    assert doc["coverage"] == expected


def test_derived_values_are_counted_and_cited_in_the_breakdown() -> None:
    """User decision 2026-09-11: derive + count, labelled. An exactly identified
    algorithm gets its Table 9 level and OID from the cited table, and the
    breakdown says how many values were derived and from which source."""
    aes = {
        "type": "cryptographic-asset",
        "name": "AES-256-GCM",
        "bom-ref": "a1",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {"primitive": "ae", "mode": "gcm"},
        },
    }
    raw, _ = extract_crypto_assets(cyclonedx([aes]))
    doc = build_canonical_cbom(raw)

    (asset,) = doc["crypto_assets"]
    assert asset["classical_security_level"] == 256
    assert asset["oid"] == "2.16.840.1.101.3.4.1.46"

    by_id = {f["field_id"]: f for f in doc["coverage"]["fields"]}
    assert by_id["certin.crypto.algo.security_level"]["derived"] == 1
    assert by_id["certin.crypto.algo.oid"]["derived"] == 1
    assert set(doc["coverage"]["derivation_sources"]) == {
        "nist-sp800-57p1r5-table2",
        "nist-csor-aes",
    }


def test_the_reference_table_is_pinned_to_the_ruleset_version() -> None:
    """⚠ Editing the reference table changes output for unchanged input. Bump
    RULESET_VERSION and update REFERENCE_DIGEST together (invariant 10)."""
    from workers.cbom.normalize.pipeline import REFERENCE_DIGEST, RULESET_VERSION

    from axebom_shared.crypto.reference import table_digest

    assert table_digest() == REFERENCE_DIGEST, (
        f"the reference table changed; bump RULESET_VERSION (now {RULESET_VERSION}) "
        f"and set REFERENCE_DIGEST = {table_digest()!r}"
    )


def test_a_list_valued_field_the_engine_reported_is_scored_present() -> None:
    """⚠ CRYPTO FUNCTIONS SCORED ZERO ON EVERY CBOM, THROUGH THIS FUNCTION.

    `profile_fields` passed the profile's `crypto_asset.crypto_functions[]`
    through verbatim, so the scorer looked the value up under a key no asset
    carries — while the stored field_status said `provided`.
    """
    raw, _ = extract_crypto_assets(cyclonedx([ALGORITHM, PROTOCOL]))
    doc = build_canonical_cbom(raw)

    by_id = {f["field_id"]: f for f in doc["coverage"]["fields"]}
    for field_id in ("certin.crypto.algo.crypto_functions", "certin.crypto.proto.cipher_suites"):
        assert by_id[field_id]["present"] == 1, field_id


def test_both_numbers_differ_when_the_engine_left_a_field_unknown() -> None:
    """⚠ declaration_pct WAS ALWAYS EQUAL TO completeness_pct (live: 60.14 / 60.14).

    Every field of an identified asset's type is declared — a value, or the
    explicit `not-provided` its stored field_status records — so the two numbers
    must differ whenever the engine left something unknown (invariant 3). The
    ALGORITHM fixture reports no mode.
    """
    raw, _ = extract_crypto_assets(cyclonedx([ALGORITHM]))
    doc = build_canonical_cbom(raw)

    assert doc["coverage"]["declaration_pct"] == 100.0
    assert doc["coverage"]["completeness_pct"] < doc["coverage"]["declaration_pct"]


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


def test_two_calls_over_the_same_input_are_byte_identical() -> None:
    """⚠ THIS TEST USED TO ASSERT THE OPPOSITE, AND THE INVERSION IS THE POINT.

    It previously required that repeated calls mint DIFFERENT
    `alias_snapshot_id`s — a documented exception to CLAUDE.md invariant 10,
    which exists only because the column was `uuid NOT NULL` and CBOM had no
    snapshot to put in it, so the pipeline invented one per call.

    `migrations/normalize/0012_bom_document_provenance.sql` made the column
    nullable and gave it a real foreign key. The exception has no reason to
    exist any more, so the whole document now replays byte-for-byte — which is
    what invariant 10 asked for all along.
    """
    raw, _ = extract_crypto_assets(cyclonedx([ALGORITHM]))

    first = build_canonical_cbom(raw)
    second = build_canonical_cbom(raw)

    assert first == second
    assert first["provenance"]["alias_snapshot_id"] is None


def test_a_custom_ruleset_version_is_carried_through() -> None:
    raw, _ = extract_crypto_assets(cyclonedx([ALGORITHM]))
    doc = build_canonical_cbom(raw, ruleset_version="test-ruleset-9")
    assert doc["ruleset_version"] == "test-ruleset-9"
