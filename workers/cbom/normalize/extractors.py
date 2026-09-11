"""Which CBOM engines the normalizer reads, and the extractor for each.

⚠ THIS REPLACES A HARD GATE. The consumer read `CBOM_ENGINES = {"cbomkit-theia"}`
and took only the first artifact of each engine, so a second crypto engine's
output would have been stored, triggered, and silently never normalized. An
engine is read exactly when it is listed here, and `CBOM_ENGINES` is derived from
this map so the two cannot disagree. The adapters read their own output through
this same map, so the counts an engine reports and the assets the normalizer
writes come from one parse.

Every engine listed emits CycloneDX crypto components and shares one reader
(cyclonedx_crypto). What differs per engine is what it gets WRONG, measured
against the pinned images on 2026-09-11 — corrected here, in normalization,
never by editing the stored raw artifact (invariant 10).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from axebom_shared.evidence import occurrences

from .cyclonedx_crypto import extract_crypto_assets

Extractor = Callable[[dict[str, Any]], tuple[list[dict[str, Any]], list[dict[str, Any]]]]

#: The material types theia's Secret Detection Plugin assigns from a gitleaks
#: rule id. `private-key` is deliberately absent: a private key is crypto
#: material, and it stays in the inventory (flagged as found in the source).
_SECRET_TYPES = frozenset({"key", "token", "password", "unknown"})

#: How many locations a secrets diagnostic names before summarising the rest.
_SHOWN = 20


def split_secret_findings(
    payload: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Separate theia's secret-detection hits from its crypto material.

    ⚠ A GITLEAKS HIT IS A CREDENTIAL, NOT A CRYPTOGRAPHIC KEY. theia 1.1.2's
    Secret Detection Plugin (`scanner/plugins/secrets/secrets.go`,
    `getGenericSecretComponent`) names each finding after its gitleaks rule id
    and types it `key` whenever the id CONTAINS "key": `generic-api-key` in a
    README became a CERT-In Table 9 key. On 1MansiS/JavaCrypto, 27 of 32 "keys"
    were such strings, mostly in Markdown, scored against the key field set
    (live, 2026-09-11). Its tokens and passwords were dropped as "no usable
    assetType" instead — the same findings, lost the other way.

    Recognised by the component that function builds and nothing else does: no
    `bom-ref`, and material properties carrying only a `type`. The certificate
    plugin's keys always have a bom-ref, a size and an algorithm reference.
    """
    components = payload.get("components")
    if not isinstance(components, list):
        return payload, []
    kept: list[Any] = []
    secrets: list[dict[str, Any]] = []
    for component in components:
        if _is_secret_finding(component):
            secrets.append(component)
        else:
            kept.append(component)
    if not secrets:
        return payload, []
    return {**payload, "components": kept}, secrets


def _is_secret_finding(component: Any) -> bool:
    if not isinstance(component, dict) or component.get("bom-ref"):
        return False
    props = component.get("cryptoProperties")
    if not isinstance(props, dict) or props.get("assetType") != "related-crypto-material":
        return False
    material = props.get("relatedCryptoMaterialProperties")
    if not isinstance(material, dict) or set(material) - {"type"}:
        return False
    return str(material.get("type") or "").strip().lower() in _SECRET_TYPES


def secrets_diagnostic(secrets: list[dict[str, Any]]) -> dict[str, Any]:
    """One finding for every possible secret: the rules that fired, and where.

    The matched value is never in theia's output and never read here.
    """
    by_rule: dict[str, int] = {}
    places: list[str] = []
    for component in secrets:
        rule = str(component.get("name") or "unnamed rule")
        by_rule[rule] = by_rule.get(rule, 0) + 1
        for place in occurrences(component):
            places.append(f"{place['path']}:{place['line']}" if place["line"] else place["path"])
    rules = ", ".join(f"{rule} ({count})" for rule, count in sorted(by_rule.items()))
    places = sorted(set(places))
    shown = ", ".join(places[:_SHOWN])
    if len(places) > _SHOWN:
        shown += f" and {len(places) - _SHOWN} more"
    return {
        "severity": "warn",
        "code": "CBOM_SECRET_IN_SOURCE",
        "message": (
            f"{len(secrets)} possible secret(s) found by cbomkit-theia's secret detection "
            f"({rules}): {shown or 'no location reported'}"
        ),
        "hint": (
            "a credential, not a cryptographic key, so it is kept out of the CERT-In key "
            "inventory. Review each location: gitleaks rules also match examples and "
            "placeholders, and a real secret must be rotated and removed, including from "
            "history. AxeBOM never reads or stores the matched value."
        ),
    }


#: cbomkit-action names key material `secret-key@df59b848-…`: a random UUID per
#: run, so the same key would have a different name on every scan.
_RUN_UUID_SUFFIX = re.compile(r"@[0-9a-fA-F][0-9a-fA-F-]{7,}$")

#: Files whose contents cbomkit-theia reads and classifies.
_KEY_OR_CERT_FILE = (".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx", ".jks", ".p7b")


def _theia(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    crypto, secrets = split_secret_findings(payload)
    assets, diagnostics = extract_crypto_assets(crypto, label="cbomkit-theia")
    if secrets:
        diagnostics.append(secrets_diagnostic(secrets))
    return assets, diagnostics


def _cbomkit_action(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    assets, diagnostics = extract_crypto_assets(payload, label="cbomkit-action")
    for asset in assets:
        # The display name loses the run UUID; `observed_name` keeps it verbatim.
        asset["name"] = _RUN_UUID_SUFFIX.sub("", str(asset.get("name") or ""))
    return assets, diagnostics


def _cdxgen_cbom(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """cdxgen's JS/TS call sites, without its key-file "certificates".

    ⚠ IT TYPES EVERY `.pem` AS A CERTIFICATE, private keys included, with no line.
    Kept, a private key would enter the CBOM as a certificate — the wrong type,
    scored against the wrong field set, and never flagged. cbomkit-theia reads
    those same files and classifies them, so they are left to it and counted.
    """
    assets, diagnostics = extract_crypto_assets(payload, label="cdxgen-cbom")
    kept: list[dict[str, Any]] = []
    deferred = 0
    for asset in assets:
        evidence = asset.get("evidence") or []
        file_only = bool(evidence) and all(
            entry.get("line") is None
            and str(entry.get("path", "")).lower().endswith(_KEY_OR_CERT_FILE)
            for entry in evidence
        )
        if file_only:
            deferred += 1
            continue
        kept.append(asset)
    if deferred:
        diagnostics.append(
            {
                "severity": "info",
                "code": "NORMALIZE_CRYPTO_FILE_FINDING_DEFERRED",
                "message": (
                    f"{deferred} key or certificate file finding(s) from cdxgen-cbom were "
                    f"left to cbomkit-theia"
                ),
                "hint": (
                    "cdxgen types every .pem file, private keys included, as a certificate; "
                    "cbomkit-theia reads those files and classifies them correctly"
                ),
            }
        )
    return kept, diagnostics


#: engine id -> extractor. Add an engine here in the same change that adds its
#: adapter to workers/cbom/runner.py.
EXTRACTORS: dict[str, Extractor] = {
    "cbomkit-theia": _theia,
    "cbomkit-action": _cbomkit_action,
    "cdxgen-cbom": _cdxgen_cbom,
}

CBOM_ENGINES: frozenset[str] = frozenset(EXTRACTORS)
