"""cbomkit-theia — cryptographic asset discovery.

⚠ CONTAINER-ONLY, AND NOT AS A PREFERENCE.

v1.1.2 ships NO binary assets — the releases are source-only. The container is
the only distributed artifact, so there is no local-binary fallback to write
and none should be added (OSINT/tools.manifest.yaml, ADR-0002).

⚠ ITS OUTPUT SCHEMA IS EARLY AND MOVING, SO EVERY READ IS DEFENSIVE.

CycloneDX 1.6 `cryptoProperties` is a young part of a young spec, and theia's
emission of it has changed between releases. This adapter therefore:

  - ignores fields it does not recognise, rather than failing;
  - DIAGNOSES fields it expected and did not find, rather than defaulting them;
  - never raises on a shape it did not anticipate.

The direction of that trade is deliberate. A crash loses a whole scan; a
diagnosed gap loses one field and says so in the report. What it must never do
is default a missing `assetType` to `algorithm` — that would score the asset
against the wrong CERT-In field set and report a false coverage number.
"""

from __future__ import annotations

from typing import Any

from encorebom_shared.adapters.base import Capabilities, GenerateResult, ResultStatus, ScanTarget
from encorebom_shared.sandbox import SandboxResult, WorkspaceLayout

from ...sbom.adapters.common import SandboxedAdapter

CAPABILITIES = Capabilities(
    engine_id="cbomkit-theia",
    families=("cbom", "qbom"),
    source_kinds=("git", "upload", "image"),
    produces=("crypto_assets",),
    native_format="cyclonedx-json-1.6",
    # ⚠ NOT PACKAGE ECOSYSTEMS. theia finds crypto in source, configuration and
    # certificates, so its "coverage" is a set of discovery surfaces rather than
    # the npm/pypi/maven vocabulary the SBOM engines use. Reusing that
    # vocabulary here would make Engine Coverage claim theia covered `npm`,
    # which would be read as "it scanned the npm dependencies" — it did not.
    ecosystems=("source", "certificates", "tls-config", "java-security"),
    default_weight=3,
)

#: The four CERT-In Table 9 asset types. CycloneDX spells them the same way.
KNOWN_ASSET_TYPES = frozenset({"algorithm", "key", "protocol", "certificate"})

#: CycloneDX `related-crypto-material` covers keys and several other things.
#: Mapped to `key` only when the material type says so — see map_asset_type.
_MATERIAL_KEY_TYPES = frozenset(
    {"private-key", "public-key", "secret-key", "symmetric-key", "key", "additional-data"}
)


class CBOMkitTheiaAdapter(SandboxedAdapter):
    """Runs cbomkit-theia over a directory or an image."""

    media_type = "application/vnd.cyclonedx+json; version=1.6"
    #: No vulnerability database: theia discovers, it does not match advisories.
    requires_db_version = False

    def __init__(self, mode: str = "dir", **kwargs: Any) -> None:
        if mode not in {"dir", "image"}:
            raise ValueError(f"cbomkit-theia mode must be dir or image, not {mode!r}")
        self.mode = mode
        super().__init__(CAPABILITIES, **kwargs)

    def build_argv(self, target: ScanTarget, layout: WorkspaceLayout) -> list[str]:
        """Discover crypto assets and write CycloneDX to stdout.

        The sandbox has no writable host mount — every mount is read-only,
        deliberately — so stdout is the only channel out.
        """
        if self.mode == "image":
            # ScanTarget has image_digest, never image_ref. This read
            # `target.image_ref`, which raises AttributeError rather than
            # returning None — the `or ""` fallback next to it could never fire.
            # Image mode had simply never been executed; the dir-mode tests all
            # take the branch below.
            digest = target.image_digest
            if not digest:
                raise ValueError(
                    "cbomkit-theia image mode requires an image digest; none was supplied"
                )
            if "@sha256:" not in digest:
                # Same rule as trivy-image, for the same reason: a tag is
                # mutable, so a report naming one cannot say what was examined.
                raise ValueError(
                    f"cbomkit-theia requires a DIGEST-pinned reference, got {digest!r}"
                )
            return ["image", "get", digest, "--quiet"]
        return ["dir", "get", layout.container_source, "--quiet"]

    def interpret(
        self,
        target: ScanTarget,
        payload: Any,
        result: SandboxResult,
        base: GenerateResult,
    ) -> GenerateResult:
        if not isinstance(payload, dict):
            base.status = ResultStatus.FAILED
            base.diagnostics.append(
                {
                    "severity": "error",
                    "code": "ENGINE_OUTPUT_UNEXPECTED",
                    "message": "cbomkit-theia returned a document that is not a JSON object",
                }
            )
            return base

        assets, diagnostics = extract_crypto_assets(payload)
        base.diagnostics.extend(diagnostics)

        # Discovery surfaces, not package ecosystems.
        base.ecosystems_covered = sorted({a["surface"] for a in assets if a.get("surface")})

        if not assets:
            # ⚠ ZERO CRYPTO ASSETS IS `partial`, NOT `succeeded`.
            #
            # A project with no cryptography at all is rare enough that an empty
            # result is far more often "theia could not read this source layout"
            # than "there is no crypto here". Reporting it as a clean success
            # would put a confident empty CBOM in front of a customer.
            base.status = ResultStatus.PARTIAL
            base.diagnostics.append(self.zero_result_diagnostic("crypto assets"))
            return base

        unknown = sum(1 for a in assets if a["asset_type"] not in KNOWN_ASSET_TYPES)
        base.status = ResultStatus.PARTIAL if unknown else ResultStatus.SUCCEEDED
        return base


def extract_crypto_assets(
    payload: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Pull crypto assets out of a CycloneDX document, defensively.

    Returns `(assets, diagnostics)`. Never raises on a shape it did not expect:
    a scan that crashes on one malformed component loses every other asset in
    the document.
    """
    assets: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    missing_type = 0
    skipped = 0

    components = payload.get("components")
    if not isinstance(components, list):
        return [], [
            {
                "severity": "warn",
                "code": "ENGINE_OUTPUT_UNEXPECTED",
                "message": "cbomkit-theia output has no `components` array",
            }
        ]

    for raw in components:
        if not isinstance(raw, dict):
            skipped += 1
            continue
        if raw.get("type") != "cryptographic-asset":
            # An ordinary software component. theia emits those too; they belong
            # to the SBOM, not the CBOM.
            continue

        props = raw.get("cryptoProperties")
        if not isinstance(props, dict):
            missing_type += 1
            continue

        asset_type = map_asset_type(props)
        if asset_type is None:
            # ⚠ NOT DEFAULTED TO `algorithm`. Coverage is scored against the
            # field set for the asset's TYPE, so a wrong type produces a
            # confident false percentage in a compliance document. An
            # unassignable asset is counted as unidentified instead.
            missing_type += 1
            continue

        assets.append(_build_asset(raw, props, asset_type))

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
    """Flatten one CycloneDX crypto component into our canonical shape.

    Every read is `.get` with a type check. theia's emission has changed between
    releases, and a KeyError here costs the whole document.
    """
    asset: dict[str, Any] = {
        "asset_type": asset_type,
        "name": _string(raw.get("name")) or _string(props.get("oid")) or "",
        "oid": _string(props.get("oid")),
        "component_key": _string(raw.get("bom-ref")),
        "surface": _discovery_surface(raw),
    }

    algo = props.get("algorithmProperties")
    if isinstance(algo, dict):
        asset["primitive"] = _string(algo.get("primitive"))
        asset["mode"] = _string(algo.get("mode"))
        asset["crypto_functions"] = _string_list(algo.get("cryptoFunctions"))
        asset["classical_security_level"] = _int(algo.get("classicalSecurityLevel"))
        # `parameterSetIdentifier` carries the key size for several primitives
        # (ML-KEM-768, RSA-2048). Read as a fallback, never as the primary.
        asset["parameter_set"] = _string(algo.get("parameterSetIdentifier"))

    material = props.get("relatedCryptoMaterialProperties")
    if isinstance(material, dict):
        asset["key_id"] = _string(material.get("id"))
        asset["key_state"] = _key_state(material.get("state"))
        asset["key_size"] = _int(material.get("size"))
        asset["creation_date"] = _string(material.get("creationDate"))
        asset["activation_date"] = _string(material.get("activationDate"))

    protocol = props.get("protocolProperties")
    if isinstance(protocol, dict):
        asset["protocol_version"] = _string(protocol.get("version"))
        asset["cipher_suites"] = _cipher_suites(protocol.get("cipherSuites"))

    cert = props.get("certificateProperties")
    if isinstance(cert, dict):
        asset["cert_subject"] = _string(cert.get("subjectName"))
        asset["cert_issuer"] = _string(cert.get("issuerName"))
        asset["not_valid_before"] = _string(cert.get("notValidBefore"))
        asset["not_valid_after"] = _string(cert.get("notValidAfter"))
        asset["signature_algo_ref"] = _string(cert.get("signatureAlgorithmRef"))
        asset["subject_public_key_ref"] = _string(cert.get("subjectPublicKeyRef"))
        asset["cert_format"] = _string(cert.get("certificateFormat"))
        asset["cert_extension"] = _string(cert.get("certificateExtension"))

    return asset


def _discovery_surface(raw: dict[str, Any]) -> str:
    """Where the asset was found — source, a certificate file, a TLS config.

    Derived from the evidence path rather than asserted, because theia does not
    report a surface field and inventing one would be a claim we cannot support.
    """
    evidence = raw.get("evidence")
    if not isinstance(evidence, dict):
        return "source"

    occurrences = evidence.get("occurrences")
    if not isinstance(occurrences, list) or not occurrences:
        return "source"

    first = occurrences[0]
    location = _string(first.get("location")) if isinstance(first, dict) else ""
    lowered = location.lower()

    if lowered.endswith((".pem", ".crt", ".cer", ".der", ".p12", ".pfx")):
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
