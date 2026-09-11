"""Cited reference values for CERT-In crypto fields an engine did not report.

User decision (2026-09-11): DERIVE + COUNT, LABELLED. When an engine identifies an
algorithm exactly — `AES-256-GCM`, `SHA-256`, `ML-KEM-768` — but leaves a CERT-In
Table 9 field empty, AxeBOM fills it from this table. The value is a property of
the named algorithm, not a guess about the customer's deployment, so it counts as
present; `derivations` records which columns were filled and from which source,
and every report footnotes them.

⚠ CLOSED AND CITED. Every value below carries a reference id, and every reference
id names a published source that was read to check it. Nothing is filled from
"common knowledge". A value this table does not hold stays `not-provided`.

⚠ ONLY EXACT STATEMENTS. Bare `RSA` gets no security level — the modulus decides
it. `AES-256` gets a level but no OID, because the OID encodes the mode. RSA-4096
is not a row of SP 800-57 Table 2, so it gets nothing rather than an
interpolation. Sources that state a value only approximately are not used:
Table 2's lowest row reads "≤ 80"; RFC 7919 and SP 800-56A give the ffdhe groups
different figures; RFC 7748 puts X25519 at "~128" and "slightly under the
standard 128-bit level". Ed25519 and Ed448 ARE used, because RFC 8032 §8.5 states
a nominal strength outright.

⚠ NEVER OVERWRITES. An engine's own value wins. Where the engine and this table
disagree, the engine value is kept and the conflict is diagnosed — a silent
override would put AxeBOM's lookup where an engine's measurement was.

⚠ VERSIONED. `table_digest()` is pinned beside the CBOM RULESET_VERSION
(workers/cbom/normalize/pipeline.py); editing this table without bumping the
ruleset fails a test, because a changed table changes output for unchanged input
(invariant 10).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any

from .identity import Canonical, canonicalize

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

SP800_57_TABLE2 = "nist-sp800-57p1r5-table2"
RFC8032 = "rfc8032-s8.5"
CSOR_AES = "nist-csor-aes"
CSOR_HASH = "nist-csor-hash"
CSOR_PQC = "nist-csor-pqc"
RFC8017 = "rfc8017-appendix-c"
RFC5758 = "rfc5758-s3.2"
RFC3279 = "rfc3279-s2"
RFC8410 = "rfc8410-s3"
RFC8018 = "rfc8018"

#: reference id -> the citation every report prints. Checked against the
#: published documents on 2026-09-11: SP 800-57 Table 2 read from the PDF's own
#: text, the NIST CSOR identifiers from the register, RFC 8032 from its text.
REFERENCES: dict[str, str] = {
    SP800_57_TABLE2: (
        "NIST SP 800-57 Part 1 Rev. 5, §5.6.1.1, Table 2 “Comparable security "
        "strengths of symmetric block cipher and asymmetric-key algorithms” (pp. 54-55)"
    ),
    RFC8032: "RFC 8032, §8.5 — Ed25519 nominal strength 128 bits; Ed448 224",
    CSOR_AES: "NIST Computer Security Objects Register — AES identifiers (2.16.840.1.101.3.4.1)",
    CSOR_HASH: "NIST Computer Security Objects Register — hash identifiers (2.16.840.1.101.3.4.2)",
    CSOR_PQC: (
        "NIST Computer Security Objects Register — ML-KEM (2.16.840.1.101.3.4.4) and "
        "ML-DSA / SLH-DSA (2.16.840.1.101.3.4.3) identifiers"
    ),
    RFC8017: "RFC 8017 (PKCS #1 v2.2), Appendix C — ASN.1 module",
    RFC5758: "RFC 5758, §3.2 — ECDSA with SHA-224, SHA-256, SHA-384 and SHA-512",
    RFC3279: "RFC 3279, §2 — MD5, SHA-1, RSA, DSA and ECDSA-with-SHA1 identifiers",
    RFC8410: "RFC 8410, §3 — X25519, X448, Ed25519 and Ed448 identifiers",
    RFC8018: "RFC 8018 (PKCS #5 v2.1), Appendices A and B — PBKDF2, HMAC and DES-EDE3-CBC identifiers",
}

# ---------------------------------------------------------------------------
# Classical security strength (bits)
# ---------------------------------------------------------------------------

#: SP 800-57 Table 2, symmetric column: (family, key bits) -> strength.
_SYMMETRIC_STRENGTH: dict[tuple[str, int], int] = {
    ("aes", 128): 128,
    ("aes", 192): 192,
    ("aes", 256): 256,
    # 3TDEA — the THREE-key option only. Table 2's footnote 68 records it as
    # deprecated through 2023 and then disallowed; the deprecation verdict says so.
    ("3des", 168): 112,
}

#: SP 800-57 Table 2, IFC (RSA) k and FFC (DSA) L -> strength. Only stated rows.
_MODULUS_STRENGTH: dict[int, int] = {2048: 112, 3072: 128, 7680: 192, 15360: 256}
_MODULUS_FAMILIES = frozenset({"rsa", "dsa"})

#: SP 800-57 Table 2, ECC column (ECDSA, EdDSA, DH, MQV) by key size f.
_CURVE_STRENGTH: dict[str, int] = {
    "p-224": 112,
    "p-256": 128,
    "secp256k1": 128,
    "brainpoolp256r1": 128,
    "p-384": 192,
    "brainpoolp384r1": 192,
    "p-521": 256,
    "brainpoolp512r1": 256,
}
_ECC_FAMILIES = frozenset({"ecdsa", "ecdh", "ec"})

#: RFC 8032 §8.5: "Ed25519 and Ed25519ph have a nominal strength of 128 bits,
#: whereas Ed448 and Ed448ph have the strength of 224."
_EDWARDS_STRENGTH: dict[str, int] = {"ed25519": 128, "ed448": 224}

# ---------------------------------------------------------------------------
# Object identifiers
# ---------------------------------------------------------------------------

_AES_ARC = "2.16.840.1.101.3.4.1"
#: mode -> final arc for AES-128; +20 for AES-192, +40 for AES-256 (NIST CSOR).
_AES_MODE_ARC: dict[str, int] = {
    "ecb": 1,
    "cbc": 2,
    "ofb": 3,
    "cfb": 4,
    "kw": 5,
    "gcm": 6,
    "ccm": 7,
}
_AES_KEY_OFFSET: dict[int, int] = {128: 0, 192: 20, 256: 40}

_HASH_ARC = "2.16.840.1.101.3.4.2"
_SHA2_OID: dict[int, str] = {224: "4", 256: "1", 384: "2", 512: "3"}
_SHA512_T_OID: dict[str, str] = {"sha512/224": "5", "sha512/256": "6"}
_SHA3_OID: dict[int, str] = {224: "7", 256: "8", 384: "9", 512: "10"}
_SHAKE_OID: dict[int, str] = {128: "11", 256: "12"}

_RSA_ARC = "1.2.840.113549.1.1"
#: Hash-and-sign RSA (PKCS #1 v1.5 signatures): digest -> final arc.
_RSA_SIGNATURE_ARC: dict[tuple[str, int], str] = {
    ("md5", 128): "4",
    ("sha1", 160): "5",
    ("sha2", 256): "11",
    ("sha2", 384): "12",
    ("sha2", 512): "13",
    ("sha2", 224): "14",
}

#: ECDSA with a digest. SHA-1 is RFC 3279; the SHA-2 family is RFC 5758.
_ECDSA_OID: dict[tuple[str, int], tuple[str, str]] = {
    ("sha1", 160): ("1.2.840.10045.4.1", RFC3279),
    ("sha2", 224): ("1.2.840.10045.4.3.1", RFC5758),
    ("sha2", 256): ("1.2.840.10045.4.3.2", RFC5758),
    ("sha2", 384): ("1.2.840.10045.4.3.3", RFC5758),
    ("sha2", 512): ("1.2.840.10045.4.3.4", RFC5758),
}

_EDWARDS_OID: dict[str, str] = {
    "x25519": "1.3.101.110",
    "x448": "1.3.101.111",
    "ed25519": "1.3.101.112",
    "ed448": "1.3.101.113",
}

_HMAC_OID: dict[tuple[str, int], str] = {
    ("sha1", 160): "1.2.840.113549.2.7",
    ("sha2", 224): "1.2.840.113549.2.8",
    ("sha2", 256): "1.2.840.113549.2.9",
    ("sha2", 384): "1.2.840.113549.2.10",
    ("sha2", 512): "1.2.840.113549.2.11",
}

_ML_KEM_OID: dict[str, str] = {
    "512": "2.16.840.1.101.3.4.4.1",
    "768": "2.16.840.1.101.3.4.4.2",
    "1024": "2.16.840.1.101.3.4.4.3",
}
_ML_DSA_OID: dict[str, str] = {
    "44": "2.16.840.1.101.3.4.3.17",
    "65": "2.16.840.1.101.3.4.3.18",
    "87": "2.16.840.1.101.3.4.3.19",
}
_SLH_DSA_OID: dict[str, str] = {
    "sha2-128s": "2.16.840.1.101.3.4.3.20",
    "sha2-128f": "2.16.840.1.101.3.4.3.21",
    "sha2-192s": "2.16.840.1.101.3.4.3.22",
    "sha2-192f": "2.16.840.1.101.3.4.3.23",
    "sha2-256s": "2.16.840.1.101.3.4.3.24",
    "sha2-256f": "2.16.840.1.101.3.4.3.25",
    "shake-128s": "2.16.840.1.101.3.4.3.26",
    "shake-128f": "2.16.840.1.101.3.4.3.27",
    "shake-192s": "2.16.840.1.101.3.4.3.28",
    "shake-192f": "2.16.840.1.101.3.4.3.29",
    "shake-256s": "2.16.840.1.101.3.4.3.30",
    "shake-256f": "2.16.840.1.101.3.4.3.31",
}

_SINGLE_OID: dict[str, tuple[str, str]] = {
    "sha1": ("1.3.14.3.2.26", RFC3279),
    "md5": ("1.2.840.113549.2.5", RFC3279),
    "pbkdf2": ("1.2.840.113549.1.5.12", RFC8018),
}

#: Which algorithm columns this module may fill. Both are CERT-In Table 9
#: algorithm fields; nothing outside them is ever touched.
DERIVABLE_COLUMNS: tuple[str, ...] = ("classical_security_level", "oid")


def lookup(c: Canonical) -> dict[str, tuple[Any, str]]:
    """Every value this table holds for one canonical algorithm: {column: (value, ref)}."""
    found: dict[str, tuple[Any, str]] = {}

    strength = _strength(c)
    if strength is not None:
        found["classical_security_level"] = strength

    oid = _oid(c)
    if oid is not None:
        found["oid"] = oid

    return found


def _strength(c: Canonical) -> tuple[int, str] | None:
    value: int | None = None
    source = SP800_57_TABLE2
    if c.family in {"aes", "3des"} and c.bits is not None:
        value = _SYMMETRIC_STRENGTH.get((c.family, c.bits))
    elif c.family in _MODULUS_FAMILIES and c.bits is not None:
        value = _MODULUS_STRENGTH.get(c.bits)
    elif c.family in _ECC_FAMILIES and c.curve:
        value = _CURVE_STRENGTH.get(c.curve)
    elif c.family == "eddsa" and c.curve:
        value, source = _EDWARDS_STRENGTH.get(c.curve), RFC8032
    return (value, source) if value is not None else None


def _oid(c: Canonical) -> tuple[str, str] | None:
    family = c.family
    if family == "aes" and c.bits in _AES_KEY_OFFSET and c.mode in _AES_MODE_ARC:
        arc = _AES_KEY_OFFSET[c.bits] + _AES_MODE_ARC[c.mode]
        return f"{_AES_ARC}.{arc}", CSOR_AES
    if family == "sha2" and c.digest is not None:
        if c.scheme in _SHA512_T_OID:
            return f"{_HASH_ARC}.{_SHA512_T_OID[c.scheme]}", CSOR_HASH
        if c.digest in _SHA2_OID:
            return f"{_HASH_ARC}.{_SHA2_OID[c.digest]}", CSOR_HASH
    if family == "sha3" and c.digest in _SHA3_OID:
        return f"{_HASH_ARC}.{_SHA3_OID[c.digest]}", CSOR_HASH
    if family == "shake" and c.digest in _SHAKE_OID:
        return f"{_HASH_ARC}.{_SHAKE_OID[c.digest]}", CSOR_HASH
    if family in _SINGLE_OID:
        return _SINGLE_OID[family]
    if family == "rsa":
        return _rsa_oid(c)
    if family == "ecdsa" and c.digest_family and c.digest is not None:
        return _ECDSA_OID.get((c.digest_family, c.digest))
    if family in {"eddsa", "xdh"} and c.curve in _EDWARDS_OID:
        return _EDWARDS_OID[c.curve], RFC8410
    if family == "dsa" and c.digest is None:
        return "1.2.840.10040.4.1", RFC3279
    if family == "hmac" and c.digest_family and c.digest is not None:
        oid = _HMAC_OID.get((c.digest_family, c.digest))
        return (oid, RFC8018) if oid else None
    if family == "3des" and c.bits == 168 and c.mode == "cbc":
        return "1.2.840.113549.3.7", RFC8018
    if family == "ml-kem" and c.parameter in _ML_KEM_OID:
        return _ML_KEM_OID[c.parameter], CSOR_PQC
    if family == "ml-dsa" and c.parameter in _ML_DSA_OID:
        return _ML_DSA_OID[c.parameter], CSOR_PQC
    if family == "slh-dsa" and c.parameter in _SLH_DSA_OID:
        return _SLH_DSA_OID[c.parameter], CSOR_PQC
    return None


def _rsa_oid(c: Canonical) -> tuple[str, str] | None:
    if c.scheme == "pss":
        return f"{_RSA_ARC}.10", RFC8017
    if c.scheme == "oaep":
        return f"{_RSA_ARC}.7", RFC8017
    if c.digest_family and c.digest is not None:
        arc = _RSA_SIGNATURE_ARC.get((c.digest_family, c.digest))
        return (f"{_RSA_ARC}.{arc}", RFC8017) if arc else None
    if c.primitive == "pke":
        # rsaEncryption: RSA as a public-key ENCRYPTION algorithm. Never derived
        # for a bare "RSA" signature, whose OID depends on the hash.
        return f"{_RSA_ARC}.1", RFC8017
    return None


def derive_reference_values(asset: dict[str, Any], raw: dict[str, Any]) -> None:
    """Fill an ALGORITHM asset's empty derivable columns from the table, in place.

    Records `asset["derivations"] = {column: reference_id}` for every value it
    fills. Never overwrites a value the engine reported; a disagreement between
    the engine and the table is appended to `analysis_diagnostics` instead.
    Called after `analyse()`, so its diagnostics are appended, never replaced.
    """
    if asset.get("asset_type") != "algorithm":
        return

    canonical = canonicalize(
        str(asset.get("name") or raw.get("name") or ""),
        str(raw.get("primitive") or ""),
        mode=str(asset.get("mode") or raw.get("mode") or ""),
        padding=str(raw.get("padding") or ""),
        curve=str(raw.get("curve") or ""),
        parameter_set=str(raw.get("parameter_set") or ""),
        key_size=raw.get("key_size") if isinstance(raw.get("key_size"), int) else None,
    )
    if not canonical.recognised:
        return

    derivations: dict[str, str] = {}
    for column, (value, reference) in lookup(canonical).items():
        existing = asset.get(column)
        if existing in (None, "", [], {}):
            asset[column] = value
            derivations[column] = reference
        elif str(existing).strip().lower() != str(value).strip().lower():
            asset.setdefault("analysis_diagnostics", []).append(
                f"NORMALIZE_CRYPTO_REFERENCE_CONFLICT: {column} is {existing!r} from the "
                f"engine and {value!r} per {reference}; the engine value is kept"
            )

    if derivations:
        asset["derivations"] = derivations


def derivation_sources(assets: Iterable[dict[str, Any]]) -> dict[str, str]:
    """{reference_id: citation} for every reference any asset in a document used."""
    used = {
        reference
        for asset in assets
        for reference in (asset.get("derivations") or {}).values()
        if reference in REFERENCES
    }
    return {reference: REFERENCES[reference] for reference in sorted(used)}


def table_digest() -> str:
    """A stable digest of every value and citation in this module."""
    payload = {
        "references": REFERENCES,
        "symmetric": sorted([list(k), v] for k, v in _SYMMETRIC_STRENGTH.items()),
        "modulus": sorted(_MODULUS_STRENGTH.items()),
        "curve": sorted(_CURVE_STRENGTH.items()),
        "edwards_strength": sorted(_EDWARDS_STRENGTH.items()),
        "aes": [_AES_ARC, sorted(_AES_MODE_ARC.items()), sorted(_AES_KEY_OFFSET.items())],
        "hash": [_HASH_ARC, sorted(_SHA2_OID.items()), sorted(_SHA512_T_OID.items())],
        "sha3": sorted(_SHA3_OID.items()),
        "shake": sorted(_SHAKE_OID.items()),
        "rsa": [_RSA_ARC, sorted([list(k), v] for k, v in _RSA_SIGNATURE_ARC.items())],
        "ecdsa": sorted([list(k), list(v)] for k, v in _ECDSA_OID.items()),
        "edwards": sorted(_EDWARDS_OID.items()),
        "hmac": sorted([list(k), v] for k, v in _HMAC_OID.items()),
        "ml_kem": sorted(_ML_KEM_OID.items()),
        "ml_dsa": sorted(_ML_DSA_OID.items()),
        "slh_dsa": sorted(_SLH_DSA_OID.items()),
        "single": sorted([k, list(v)] for k, v in _SINGLE_OID.items()),
    }
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()
