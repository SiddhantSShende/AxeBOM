"""CycloneDX `cryptoProperties` -> raw crypto assets, for EVERY engine that emits them.

⚠ ONE READER FOR ONE FORMAT. cbomkit-theia, cbomkit-action (sonar-cryptography)
and cdxgen's `cbom` preset all write CycloneDX crypto components. This parser
lived inside the theia adapter; a second engine would have needed a copy, and two
copies of a defensive parser drift in exactly the fields that matter.

⚠ 1.6 AND 1.7, BOTH SPELLINGS. theia and cbomkit-action emit 1.6; cdxgen emits
1.7 by default. 1.7 renamed `curve` to `ellipticCurve`, added `algorithmFamily`,
certificate `serialNumber` / `fingerprint` / `certificateFileExtension`, material
`fingerprint`, and replaced `signatureAlgorithmRef` / `subjectPublicKeyRef` /
`algorithmRef` with `relatedCryptographicAssets`. Every one is read; nothing
defaults.

⚠ KEY MATERIAL IS NEVER READ. A `related-crypto-material` component may carry
the key itself in `value`. A private or secret key's `value` is never read,
copied or hashed — storing it would turn a CBOM into a credential leak. A PUBLIC
key's `value` is hashed (SHA-256 over the decoded DER) into a fingerprint, the
strongest identity a key has, and the value is then discarded.

⚠ DEFENSIVE, AS THE SCHEMA IS YOUNG. Unknown fields are ignored; expected fields
that are missing are diagnosed, never defaulted; no shape raises. A crash loses a
whole scan, a diagnosed gap loses one field and says so. What this must never do
is default a missing `assetType` to `algorithm` — that scores the asset against
the wrong CERT-In field set and reports a false coverage number (invariant 5).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any

from axebom_shared.evidence import occurrences

#: The four CERT-In Table 9 asset types. CycloneDX spells three of them the same
#: way; its `related-crypto-material` becomes `key` only when it is a key.
KNOWN_ASSET_TYPES = frozenset({"algorithm", "key", "protocol", "certificate"})

#: CycloneDX `related-crypto-material` covers keys and several other things.
#: Mapped to `key` only when the material type says so — see map_asset_type.
_MATERIAL_KEY_TYPES = frozenset(
    {"private-key", "public-key", "secret-key", "symmetric-key", "key", "additional-data"}
)

#: Material whose `value` is a secret. Never read.
_SECRET_MATERIAL = frozenset({"private-key", "secret-key", "symmetric-key", "key"})


def extract_crypto_assets(
    payload: dict[str, Any], *, label: str = "the engine"
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Pull crypto assets out of a CycloneDX document, defensively.

    Returns `(assets, diagnostics)`. Never raises on a shape it did not expect:
    a scan that crashes on one malformed component loses every other asset in
    the document. `label` names the engine in diagnostics.
    """
    assets: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    missing_type = 0
    skipped = 0

    components = payload.get("components")
    if components is None:
        # ⚠ AN EMPTY RESULT, NOT A MALFORMED DOCUMENT. theia writes
        # `"components": null` whenever no plugin found anything, and CycloneDX
        # allows the key to be absent when there is nothing to list.
        return [], []
    if not isinstance(components, list):
        return [], [
            {
                "severity": "warn",
                "code": "ENGINE_OUTPUT_UNEXPECTED",
                "message": f"{label} output's `components` is not an array",
            }
        ]

    for raw in components:
        if not isinstance(raw, dict):
            skipped += 1
            continue
        if raw.get("type") != "cryptographic-asset":
            # An ordinary software component. Some engines emit those too; they
            # belong to the SBOM, not the CBOM.
            continue

        props = raw.get("cryptoProperties")
        if not isinstance(props, dict):
            missing_type += 1
            continue

        asset_type = map_asset_type(props)
        if asset_type is None:
            # ⚠ NOT DEFAULTED TO `algorithm` — see the module docstring.
            missing_type += 1
            continue

        assets.append(_build_asset(raw, props, asset_type))

    _link_keys_to_algorithms(assets, payload.get("dependencies"))

    if missing_type:
        diagnostics.append(
            {
                "severity": "warn",
                "code": "ENGINE_PARTIAL_ECOSYSTEM",
                "message": (
                    f"{missing_type} crypto asset(s) reported no usable assetType "
                    f"and were not classified"
                ),
                "hint": (
                    "counted as unidentified rather than defaulted to `algorithm`, "
                    "which would score them against the wrong CERT-In field set"
                ),
            }
        )
    if skipped:
        diagnostics.append(
            {
                "severity": "warn",
                "code": "ENGINE_OUTPUT_UNEXPECTED",
                "message": f"{skipped} component entr(ies) were not objects and were skipped",
            }
        )

    return assets, diagnostics


def map_asset_type(props: dict[str, Any]) -> str | None:
    """Map CycloneDX `assetType` onto a CERT-In Table 9 type.

    ⚠ RETURNS None RATHER THAN GUESSING. The four Table 9 types have DIFFERENT
    field sets, and scoring a certificate against `key_size` reports every CBOM
    at roughly 30% coverage — falsely, in a compliance document.

    CycloneDX's `related-crypto-material` is the awkward one: it covers keys,
    but also nonces, seeds, salts and ciphertext. Only the key-ish material
    types become `key`.
    """
    raw = props.get("assetType")
    if not isinstance(raw, str):
        return None

    value = raw.strip().lower()
    if value in KNOWN_ASSET_TYPES:
        return value

    if value == "related-crypto-material":
        material = props.get("relatedCryptoMaterialProperties")
        material_type = ""
        if isinstance(material, dict):
            material_type = str(material.get("type") or "").strip().lower()
        if material_type in _MATERIAL_KEY_TYPES:
            return "key"
        # A nonce or a salt is crypto material and is not a Table 9 key. It has
        # no field set here, so it is not classified.
        return None

    return None


def _build_asset(raw: dict[str, Any], props: dict[str, Any], asset_type: str) -> dict[str, Any]:
    """Flatten one CycloneDX crypto component into the raw-asset shape.

    Every read is `.get` with a type check; a KeyError here costs the document.
    Keys that are not CERT-In columns (`native_ref`, `evidence`, `padding`, …)
    ride along for identity, analysis and provenance and never become columns.
    """
    name = _string(raw.get("name"))
    asset: dict[str, Any] = {
        "asset_type": asset_type,
        "name": name or _string(props.get("oid")) or "",
        "observed_name": name,
        "oid": _string(props.get("oid")),
        # The engine's own reference. ⚠ NEVER AN IDENTITY: theia mints a fresh
        # random bom-ref on every run. Used only to resolve references inside
        # this one document, and kept as provenance.
        "native_ref": _string(raw.get("bom-ref")),
        "description": _string(raw.get("description")),
        "surface": _discovery_surface(raw),
        "evidence": occurrences(raw),
        "related_refs": _related_refs(props),
    }

    algo = props.get("algorithmProperties")
    if isinstance(algo, dict):
        asset["primitive"] = _string(algo.get("primitive"))
        asset["mode"] = _string(algo.get("mode"))
        asset["crypto_functions"] = _string_list(algo.get("cryptoFunctions"))
        asset["classical_security_level"] = _int(algo.get("classicalSecurityLevel"))
        # Its meaning depends on the family (key bits for AES, digest for SHA,
        # a named set for SLH-DSA); axebom_shared.crypto.identity interprets it.
        asset["parameter_set"] = _string(algo.get("parameterSetIdentifier"))
        asset["padding"] = _string(algo.get("padding"))
        asset["curve"] = _string(algo.get("ellipticCurve")) or _string(algo.get("curve"))
        asset["algorithm_family"] = _string(algo.get("algorithmFamily"))
        level = _int(algo.get("nistQuantumSecurityLevel"))
        # The schema bounds it to 0..6 (0 = no NIST category met).
        asset["nist_quantum_security_level"] = (
            level if level is not None and 0 <= level <= 6 else None
        )
        asset["execution_environment"] = _string(algo.get("executionEnvironment"))
        asset["implementation_platform"] = _string(algo.get("implementationPlatform"))
        asset["certification_level"] = _string_list(algo.get("certificationLevel"))

    material = props.get("relatedCryptoMaterialProperties")
    if isinstance(material, dict):
        material_type = _string(material.get("type")).lower()
        asset["material_type"] = material_type
        asset["key_id"] = _string(material.get("id"))
        asset["key_state"] = _key_state(material.get("state"))
        asset["key_size"] = _int(material.get("size"))
        asset["creation_date"] = _string(material.get("creationDate"))
        asset["activation_date"] = _string(material.get("activationDate"))
        asset["expiration_date"] = _string(material.get("expirationDate"))
        asset["material_format"] = _string(material.get("format"))
        asset["key_algorithm_ref"] = _string(material.get("algorithmRef")) or _related(
            asset["related_refs"], "algorithm"
        )
        asset["material_fingerprint"] = _fingerprint(material.get("fingerprint"))
        # ⚠ ONLY A PUBLIC KEY'S VALUE IS EVER TOUCHED, and only to hash it.
        if material_type == "public-key":
            asset["public_key_fingerprint"] = _public_key_fingerprint(material.get("value"))

    protocol = props.get("protocolProperties")
    if isinstance(protocol, dict):
        asset["protocol_version"] = _string(protocol.get("version"))
        asset["cipher_suites"] = _cipher_suites(protocol.get("cipherSuites"))
        asset["protocol_type"] = _string(protocol.get("type"))

    cert = props.get("certificateProperties")
    if isinstance(cert, dict):
        asset["cert_subject"] = _string(cert.get("subjectName"))
        asset["cert_issuer"] = _string(cert.get("issuerName"))
        asset["not_valid_before"] = _string(cert.get("notValidBefore"))
        asset["not_valid_after"] = _string(cert.get("notValidAfter"))
        asset["signature_algo_ref"] = _string(cert.get("signatureAlgorithmRef")) or _related(
            asset["related_refs"], "signature"
        )
        asset["subject_public_key_ref"] = _string(cert.get("subjectPublicKeyRef")) or _related(
            asset["related_refs"], "key"
        )
        asset["cert_format"] = _string(cert.get("certificateFormat"))
        asset["cert_extension"] = _string(cert.get("certificateExtension")) or _string(
            cert.get("certificateFileExtension")
        )
        asset["cert_serial"] = _string(cert.get("serialNumber"))
        asset["cert_fingerprint"] = _fingerprint(cert.get("fingerprint"))

    return asset


def _link_keys_to_algorithms(assets: list[dict[str, Any]], dependencies: Any) -> None:
    """A key's algorithm from the document's dependency graph, when that is where
    the engine stated it.

    ⚠ cbomkit-action NEVER FILLS `algorithmRef`. It says the key from
    `KeyPairGenerator.getInstance("RSA")` belongs to RSA-2048 with a CycloneDX
    dependency (`key dependsOn RSA-2048`) instead. Unread, the key was analysed on
    its name alone — `key` — and an RSA key was reported NOT quantum-vulnerable:
    a false negative in a migration plan. Only an unambiguous edge is used, a key
    depending on exactly one algorithm; anything else leaves the key as it was.
    """
    if not isinstance(dependencies, list):
        return
    algorithms = {
        a["native_ref"] for a in assets if a["asset_type"] == "algorithm" and a.get("native_ref")
    }
    edges: dict[str, set[str]] = {}
    for entry in dependencies:
        if not isinstance(entry, dict):
            continue
        ref = _string(entry.get("ref"))
        depends_on = entry.get("dependsOn")
        if not ref or not isinstance(depends_on, list):
            continue
        edges.setdefault(ref, set()).update(
            target for target in (_string(d) for d in depends_on) if target in algorithms
        )
    for asset in assets:
        if asset["asset_type"] != "key" or asset.get("key_algorithm_ref"):
            continue
        targets = edges.get(asset.get("native_ref") or "", set())
        if len(targets) == 1:
            (asset["key_algorithm_ref"],) = targets


def _related_refs(props: dict[str, Any]) -> list[dict[str, str]]:
    """CycloneDX 1.7 `relatedCryptographicAssets`: [{type, ref}], defensively."""
    value = props.get("relatedCryptographicAssets")
    for container in (
        "certificateProperties",
        "relatedCryptoMaterialProperties",
        "protocolProperties",
    ):
        nested = props.get(container)
        if value is None and isinstance(nested, dict):
            value = nested.get("relatedCryptographicAssets")
    if not isinstance(value, list):
        return []
    out: list[dict[str, str]] = []
    for entry in value:
        if isinstance(entry, str) and entry.strip():
            out.append({"type": "", "ref": entry.strip()})
        elif isinstance(entry, dict):
            ref = _string(entry.get("ref")) or _string(entry.get("bom-ref"))
            if ref:
                out.append({"type": _string(entry.get("type")).lower(), "ref": ref})
    return out


def _related(refs: list[dict[str, str]], kind: str) -> str:
    """The first 1.7 related ref whose type mentions `kind` (signature / key / algorithm)."""
    for entry in refs:
        if kind in entry.get("type", ""):
            return entry["ref"]
    return ""


def _fingerprint(value: Any) -> str:
    """A CycloneDX hash object `{alg, content}` as `alg:content`, lower-cased."""
    if isinstance(value, dict):
        content = _string(value.get("content")).lower()
        alg = _string(value.get("alg")).lower()
        return f"{alg}:{content}" if content else ""
    if isinstance(value, str):
        return value.strip().lower()
    return ""


def _public_key_fingerprint(value: Any) -> str:
    """SHA-256 over a PUBLIC key's decoded DER, or "" when it cannot be decoded."""
    if not isinstance(value, str) or not value.strip():
        return ""
    body = "".join(line for line in value.strip().splitlines() if not line.startswith("-----"))
    try:
        der = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        return ""
    return "sha256:" + hashlib.sha256(der).hexdigest() if der else ""


def _discovery_surface(raw: dict[str, Any]) -> str:
    """Where the asset was found — source, a certificate file, a TLS config.

    Derived from the evidence path rather than asserted: no engine reports a
    surface field, and inventing one would be a claim we cannot support.
    """
    found = occurrences(raw)
    if not found:
        return "source"
    lowered = found[0]["path"].lower()
    if lowered.endswith((".pem", ".crt", ".cer", ".der", ".p12", ".pfx", ".key")):
        return "certificates"
    if "java.security" in lowered or lowered.endswith(".jks"):
        return "java-security"
    if "ssl" in lowered or "tls" in lowered or lowered.endswith((".conf", ".cnf")):
        return "tls-config"
    return "source"


def _key_state(value: Any) -> str:
    """Map CycloneDX key state onto our enum.

    ⚠ AN UNRECOGNISED STATE BECOMES `unknown`, NOT `active`. Defaulting to
    active would report a revoked key as live in a compliance document, which
    is the wrong direction for a value a reviewer acts on.
    """
    state = _string(value).lower()
    if state in {"active", "revoked", "expired"}:
        return state
    if state in {"pre-activation", "suspended", "deactivated", "destroyed", "compromised"}:
        # Real CycloneDX states with no column of their own. `unknown` is
        # honest; mapping `compromised` to `active` would not be.
        return "unknown"
    return "unknown" if state else ""


def _cipher_suites(value: Any) -> list[str]:
    """Read cipher-suite names from CycloneDX's object-or-string list."""
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for entry in value:
        if isinstance(entry, str):
            out.append(entry)
        elif isinstance(entry, dict):
            name = _string(entry.get("name"))
            if name:
                out.append(name)
    return out


def _string(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [v.strip() for v in value if isinstance(v, str) and v.strip()]


def _int(value: Any) -> int | None:
    """Read an integer, refusing a string that only looks like one.

    A `"2048"` from a schema that promised a number is worth accepting; a
    `"2048 bits"` is not, and coercing it would produce a key size of 2048 from
    a field that might have said something else entirely.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


#: Kept only so no reader has to know which keys are secret; see the module
#: docstring. Exposed for the no-key-material test.
SECRET_MATERIAL_TYPES = _SECRET_MATERIAL
