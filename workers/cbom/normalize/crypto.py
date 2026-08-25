"""Canonical crypto assets: CycloneDX `cryptoProperties` -> CryptoAsset.

⚠ THE ASSET TYPE DECIDES WHICH COLUMNS ARE POPULATED, AND THAT IS THE WHOLE
POINT OF THIS MODULE.

CERT-In Table 9 is type-discriminated: Algorithms, Keys, Protocols and
Certificates have DIFFERENT field sets — 8, 7, 5 and 10 fields respectively.
Writing every value into every asset would look harmless and then be scored
against the union, which reports every CBOM at roughly 30% coverage. Falsely,
in a document shown to a regulator.

So the mapping branches on `asset_type` and writes only that type's columns.
The rest stay absent, which is what makes `score_crypto` able to use the right
denominator.

⚠ THE THREE ANALYSIS FIELDS ARE NOT CERT-In FIELDS.

`quantum_vulnerable`, `pqc_recommendation` and `deprecation_status` carry
`scored: false` in the profile and are excluded from both coverage numbers. If
they counted, a customer's compliance score would move because we shipped a new
rule — with no change to their software.
"""

from __future__ import annotations

from typing import Any

from axebom_shared.crypto import assess_deprecation, assess_quantum, readiness_group, recommend_pqc

#: Columns that belong to each asset type, mirroring CERT-In Table 9.
#:
#: ⚠ THE SOURCE OF TRUTH IS THE COMPLIANCE PROFILE, NOT THIS MAP. These are the
#: canonical-model columns the profile's `canonical_path` entries point at;
#: `test_crypto_normalize.py` asserts the two agree, so a profile revision that
#: adds a field fails a test rather than silently going unpopulated.
TYPE_COLUMNS: dict[str, tuple[str, ...]] = {
    "algorithm": (
        "name",
        "primitive",
        "mode",
        "crypto_functions",
        "classical_security_level",
        "oid",
        "algorithm_list",
    ),
    "key": (
        "name",
        "key_id",
        "key_state",
        "key_size",
        "creation_date",
        "activation_date",
    ),
    "protocol": (
        "name",
        "protocol_version",
        "cipher_suites",
        "oid",
    ),
    "certificate": (
        "name",
        "cert_subject",
        "cert_issuer",
        "not_valid_before",
        "not_valid_after",
        "signature_algo_ref",
        "subject_public_key_ref",
        "cert_format",
        "cert_extension",
    ),
}

#: `asset_type` itself is a scored field for every type, so it is never in the
#: per-type list above — it would be duplicated four times.
ALWAYS = ("asset_type",)


def normalize_crypto_asset(raw: dict[str, Any]) -> dict[str, Any]:
    """Turn one extracted asset into a canonical crypto asset row.

    The input is what `cbomkit_theia.extract_crypto_assets` produced: a flat
    dict with every field the engine reported, whatever its type.
    """
    asset_type = str(raw.get("asset_type") or "").strip().lower()
    if asset_type not in TYPE_COLUMNS:
        raise ValueError(
            f"unknown crypto asset type {asset_type!r}; "
            f"the extractor must classify or drop an asset, never pass it through"
        )

    out: dict[str, Any] = {"asset_type": asset_type}

    # ⚠ ONLY THIS TYPE'S COLUMNS. A certificate carrying a `key_size` would be
    # scored against a field the guideline does not ask a certificate for.
    for column in TYPE_COLUMNS[asset_type]:
        value = raw.get(column)
        if value not in (None, "", [], {}):
            out[column] = value

    # A key size can arrive in `parameterSetIdentifier` when the engine did not
    # populate `size`. Read as a fallback and only for a key.
    if asset_type == "key" and "key_size" not in out:
        size = _size_from_parameter_set(raw.get("parameter_set"))
        if size is not None:
            out["key_size"] = size

    out["component_key"] = raw.get("component_key") or ""
    out.update(analyse(out, raw))
    return out


def analyse(asset: dict[str, Any], raw: dict[str, Any]) -> dict[str, Any]:
    """Run the three AxeBOM analyses over a normalized asset.

    ⚠ THE INPUTS COME FROM BOTH THE NORMALIZED ASSET AND THE RAW ONE, on
    purpose. `primitive` belongs to an algorithm and is dropped from a
    certificate's columns — but a certificate's signature algorithm is still
    worth assessing, and the raw record still has it. Dropping a column from the
    COVERAGE model is not the same as forgetting it exists.
    """
    name = str(asset.get("name") or raw.get("name") or "")
    primitive = str(raw.get("primitive") or "")
    functions = list(raw.get("crypto_functions") or [])
    key_size = asset.get("key_size") or raw.get("key_size")
    asset_type = str(asset.get("asset_type") or "algorithm")

    # For a certificate, the interesting primitive is what SIGNED it.
    if asset_type == "certificate":
        signature = str(raw.get("signature_algo_ref") or "")
        if signature:
            primitive = f"{primitive} {signature}".strip()

    quantum = assess_quantum(
        name=name,
        primitive=primitive,
        key_size=key_size if isinstance(key_size, int) else None,
        classical_security_level=_int(raw.get("classical_security_level")),
        asset_type=asset_type,
    )
    deprecation = assess_deprecation(
        name=name,
        primitive=primitive,
        key_size=key_size if isinstance(key_size, int) else None,
        crypto_functions=functions,
        asset_type=asset_type,
    )
    pqc = recommend_pqc(
        family=quantum.family,
        quantum_vulnerable=quantum.quantum_vulnerable,
        crypto_functions=functions,
        name=name,
    )

    out: dict[str, Any] = {
        "quantum_vulnerable": quantum.quantum_vulnerable,
        # ⚠ THE FAMILY IS CARRIED SO NOTHING DOWNSTREAM HAS TO READ THE PROSE.
        #
        # The QBOM readiness view first classified post-quantum assets by
        # substring-matching `quantum_rationale` — the same "branch on the
        # message text" mistake the error taxonomy exists to prevent. A copy
        # edit to the rationale would have silently emptied the "already
        # post-quantum" list, and nothing would have failed.
        "quantum_family": quantum.family,
        "deprecation_status": deprecation.status,
        # The rationales are what make a flag actionable. A boolean with no
        # reason is an alarm a security team learns to silence.
        "quantum_rationale": quantum.rationale,
        "deprecation_rationale": deprecation.rationale,
        "deprecation_reference": deprecation.reference,
    }
    if quantum.grover_note:
        out["grover_note"] = quantum.grover_note
    if quantum.effective_quantum_bits is not None:
        out["effective_quantum_bits"] = quantum.effective_quantum_bits
    if pqc is not None:
        out["pqc_recommendation"] = pqc.summary()

    # ⚠ COMPUTED HERE, ONCE, AND STORED (migrations/normalize/0005) — never
    # re-derived by a report renderer. See axebom_shared.crypto.readiness_group's
    # own docstring for why a second implementation of this branch is the
    # mistake that lets the CBOM and the QBOM disagree about the same asset.
    group = readiness_group(
        quantum_vulnerable=quantum.quantum_vulnerable,
        grover_note=quantum.grover_note,
        quantum_family=quantum.family,
    )
    if group is not None:
        out["quantum_readiness_group"] = group

    diagnostics = list(quantum.diagnostics)
    if diagnostics:
        out["analysis_diagnostics"] = diagnostics

    return out


def normalize_all(
    raw_assets: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Normalize a whole document's worth, keeping the failures visible."""
    out: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []

    for raw in raw_assets:
        try:
            out.append(normalize_crypto_asset(raw))
        except ValueError as exc:
            # One unclassifiable asset must not lose the other four hundred.
            diagnostics.append(
                {
                    "severity": "warn",
                    "code": "NORMALIZE_CRYPTO_ASSET_TYPE_UNKNOWN",
                    "message": str(exc),
                }
            )

    return out, diagnostics


def _size_from_parameter_set(value: Any) -> int | None:
    """Read a key size out of `RSA-2048` or `ML-KEM-768`.

    ⚠ ONLY WHEN THE WHOLE TRAILING TOKEN IS DIGITS. `secp256r1` ends in `r1`
    and its 256 is a curve size, not a key size in the sense this column means;
    coercing it would put a number in a field a reviewer reads as an RSA modulus.
    """
    text = str(value or "").strip()
    if not text:
        return None
    tail = text.rsplit("-", 1)[-1]
    return int(tail) if tail.isdigit() and len(tail) >= 3 else None


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None
