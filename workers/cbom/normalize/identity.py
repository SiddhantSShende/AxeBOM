"""The crypto-asset identity ladder: `asset_key`, docs/03-NORMALIZER-SPEC.md §1.6.

⚠ A CRYPTO ASSET HAD NO IDENTITY, so a second engine could only duplicate it.
`component_key` held the engine's own bom-ref — for cbomkit-theia a random UUID
minted per run — so nothing could say whether two rows were the same RSA key.
This is the crypto counterpart of `component_key` (§1.2) and `model_key` (§1.5).

Every tier is PREFIXED, so two tiers can never collide:

    algorithm:<family>;<param>=<value>;…      the canonical algorithm (high/medium)
    name:algorithm/<name>;primitive=<p>        unrecognised algorithm (low)
    key:fp:<alg>:<hex>                         public-key / material fingerprint (high)
    key:<material>;alg=…;size=…;path=<p>       key at a location, no fingerprint (medium)
    cert:fp:<alg>:<hex>                        certificate fingerprint (high)
    cert:issuer-serial:<issuer>/<serial>       issuer + serial (high)
    cert:<subject>;issuer=…;from=…;to=…        subject + issuer + validity (medium)
    protocol:<name>;version=<v>                protocol + version
    opaque:<engine>:<native ref>               nothing better; never merges (low)

⚠ NEVER A NAME ALONE FOR A RECOGNISED ALGORITHM. theia reports two assets named
"RSA" from one certificate — one `signature`, one `pke` — and they are different
uses. The primitive is part of the key.

⚠ PRIVATE-KEY MATERIAL IS NEVER AN INPUT. A private key is identified by where it
was committed, never by its bytes (which are never read — see cyclonedx_crypto).

⚠ LOCATION IS EVIDENCE, NOT IDENTITY (§1.4), except for a key with no
fingerprint: two private-key files at two paths are two keys, and the path is the
only thing that says so.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from axebom_shared.crypto.identity import canonicalize

#: Every rule this module can produce. `migrations/normalize/0020` mirrors it in a
#: CHECK constraint; test_identity_keys.py holds the two together.
IDENTITY_RULES = frozenset(
    {
        "algorithm",
        "algorithm-name",
        "key-fingerprint",
        "key-location",
        "certificate-fingerprint",
        "certificate-issuer-serial",
        "certificate-subject-issuer-validity",
        "protocol",
        "name",
        "opaque",
    }
)


@dataclass(frozen=True)
class AssetIdentity:
    key: str
    rule: str
    confidence: str


def asset_identity(raw: dict[str, Any], engine_id: str = "") -> AssetIdentity:
    """The merge key for one raw crypto asset."""
    asset_type = str(raw.get("asset_type") or "")
    if asset_type == "algorithm":
        found = _algorithm(raw)
    elif asset_type == "key":
        found = _key(raw)
    elif asset_type == "certificate":
        found = _certificate(raw)
    elif asset_type == "protocol":
        found = _protocol(raw)
    else:
        found = None
    return found or _opaque(raw, engine_id)


def _algorithm(raw: dict[str, Any]) -> AssetIdentity | None:
    name = _s(raw.get("name"))
    primitive = _norm(raw.get("primitive"))
    canonical = canonicalize(
        name,
        primitive,
        mode=_s(raw.get("mode")),
        padding=_s(raw.get("padding")),
        curve=_s(raw.get("curve")),
        parameter_set=_s(raw.get("parameter_set")),
    )
    if canonical.recognised:
        digest = f"{canonical.digest_family}-{canonical.digest}" if canonical.digest else ""
        scheme, padding = canonical.scheme, canonical.padding
        if canonical.family == "rsa" and canonical.digest and scheme in {"", "pkcs1v15"}:
            # ⚠ HASH-AND-SIGN RSA IS PKCS#1 v1.5 UNLESS IT SAYS PSS. JCA's
            # `SHA256withRSA` means v1.5 without saying so; theia labels the same
            # algorithm `SHA256-RSA` with `padding: pkcs1v15`. Keyed on the
            # literal padding, one algorithm from two engines never merged.
            scheme, padding = "pkcs1v15", ""
        parts = [
            ("bits", str(canonical.bits or "")),
            ("digest", digest),
            ("mode", canonical.mode),
            ("padding", padding),
            ("curve", canonical.curve),
            ("param", canonical.parameter),
            ("scheme", scheme),
            ("primitive", primitive),
        ]
        specific = any(v for k, v in parts if k in {"bits", "digest", "curve", "param"})
        return AssetIdentity(
            key=_join(f"algorithm:{canonical.family}", parts),
            rule="algorithm",
            confidence="high" if specific else "medium",
        )
    if name:
        return AssetIdentity(
            key=_join(f"name:algorithm/{_norm(name)}", [("primitive", primitive)]),
            rule="algorithm-name",
            confidence="low",
        )
    return None


def _key(raw: dict[str, Any]) -> AssetIdentity | None:
    fingerprint = _s(raw.get("public_key_fingerprint")) or _s(raw.get("material_fingerprint"))
    if fingerprint:
        return AssetIdentity(
            key=f"key:fp:{fingerprint.lower()}", rule="key-fingerprint", confidence="high"
        )

    locations = sorted(
        (e["path"], e.get("line") or 0) for e in raw.get("evidence") or [] if e.get("path")
    )
    if locations:
        # ⚠ THE LINE IS PART OF A KEY'S LOCATION. Two keys a source file
        # generates on lines 15 and 30 are two keys; keyed on the file alone
        # they merged into one. A key FILE has no line, and keys on its path.
        path, line = locations[0]
        # A key's own name (`RSA-2048`) or, when that names nothing (`key`), the
        # algorithm its engine says it belongs to (pipeline._with_algorithm_names).
        family = (
            canonicalize(_s(raw.get("name"))).family
            or canonicalize(_s(raw.get("algorithm_name"))).family
        )
        parts = [
            ("alg", family),
            ("size", str(raw.get("key_size") or "")),
            ("path", f"{path}:{line}" if line else path),
        ]
        material = _norm(raw.get("material_type")) or "key"
        return AssetIdentity(
            key=_join(f"key:{material}", parts), rule="key-location", confidence="medium"
        )
    return None


def _certificate(raw: dict[str, Any]) -> AssetIdentity | None:
    fingerprint = _s(raw.get("cert_fingerprint"))
    if fingerprint:
        return AssetIdentity(
            key=f"cert:fp:{fingerprint.lower()}", rule="certificate-fingerprint", confidence="high"
        )
    issuer = _norm(raw.get("cert_issuer"))
    serial = _norm(raw.get("cert_serial"))
    if issuer and serial:
        return AssetIdentity(
            key=f"cert:issuer-serial:{issuer}/{serial}",
            rule="certificate-issuer-serial",
            confidence="high",
        )
    subject = _norm(raw.get("cert_subject"))
    not_after = _norm(raw.get("not_valid_after"))
    if subject and not_after:
        parts = [
            ("issuer", issuer),
            ("from", _norm(raw.get("not_valid_before"))),
            ("to", not_after),
        ]
        return AssetIdentity(
            key=_join(f"cert:{subject}", parts),
            rule="certificate-subject-issuer-validity",
            confidence="medium",
        )
    return None


#: Protocol families, so `TLSv1.2`, `TLS 1.2` and `TLS` + version `1.2` share a key.
_PROTOCOL_FAMILY = re.compile(r"\b(dtls|tls|ssl|ssh|ike|ipsec|quic|wpa)", re.I)
_TRAILING_VERSION = re.compile(r"v?(\d+(?:\.\d+)?)\s*$", re.I)


def _protocol(raw: dict[str, Any]) -> AssetIdentity | None:
    """`protocol:<family>;version=<v>`.

    ⚠ THE NAME IS NOT THE KEY. cbomkit-action names TLS 1.2 `TLSv1.2`; another
    engine says `TLS` with `version: 1.2`. Keyed on the raw name the same
    protocol from two engines never merged — so the family is read out of the
    name and the version out of the field, or out of the name when the field is
    empty.
    """
    name = _norm(raw.get("name"))
    if not name:
        return None
    family_match = _PROTOCOL_FAMILY.search(name)
    family = family_match.group(1).lower() if family_match else name
    version = _norm(raw.get("protocol_version"))
    if not version:
        trailing = _TRAILING_VERSION.search(name)
        version = trailing.group(1) if trailing and family_match else ""
    return AssetIdentity(
        key=_join(f"protocol:{family}", [("version", version)]),
        rule="protocol",
        confidence="high" if version else "medium",
    )


def _opaque(raw: dict[str, Any], engine_id: str) -> AssetIdentity:
    """Never merges with anything. Deterministic on replay: the native ref comes
    from the stored, immutable raw artifact."""
    ref = _s(raw.get("native_ref")) or _norm(raw.get("observed_name")) or _norm(raw.get("name"))
    return AssetIdentity(
        key=f"opaque:{engine_id or 'unknown'}:{ref}", rule="opaque", confidence="low"
    )


def _join(head: str, parts: list[tuple[str, str]]) -> str:
    tail = ";".join(f"{k}={v}" for k, v in parts if v)
    return f"{head};{tail}" if tail else head


def _s(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _norm(value: Any) -> str:
    """Lower-cased, whitespace collapsed — for keys, never for display."""
    return re.sub(r"\s+", " ", _s(value)).lower()
