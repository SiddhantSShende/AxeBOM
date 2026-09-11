"""Per-engine extraction: what each engine gets wrong, corrected in normalization."""

from __future__ import annotations

import json
from typing import Any

from workers.cbom.normalize.extractors import EXTRACTORS


def secret(rule: str, material_type: str, path: str, line: int) -> dict[str, Any]:
    """Exactly the component theia 1.1.2's `getGenericSecretComponent` builds:
    no bom-ref, and a material type derived from the gitleaks rule id."""
    return {
        "type": "cryptographic-asset",
        "name": rule,
        "description": "Detected a Generic API Key, potentially exposing access.",
        "evidence": {"occurrences": [{"location": path, "line": line}]},
        "cryptoProperties": {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {"type": material_type},
        },
    }


def certificate_plugin_key() -> dict[str, Any]:
    """A key theia's Certificate File Plugin reads from a PEM: a bom-ref, a size,
    an algorithm reference."""
    return {
        "type": "cryptographic-asset",
        "name": "RSA-2048",
        "bom-ref": "5e1c8f0a-7d2b-4c3e-9f10-2a3b4c5d6e7f",
        "evidence": {"occurrences": [{"location": "certs/server.pem"}]},
        "cryptoProperties": {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {
                "type": "public-key",
                "size": 2048,
                "algorithmRef": "a1",
                "format": "PEM",
            },
        },
    }


def theia(*components: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return EXTRACTORS["cbomkit-theia"](
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": list(components)}
    )


def test_a_gitleaks_hit_is_a_secret_not_a_cert_in_key() -> None:
    """⚠ `generic-api-key` in a README was stored as a Table 9 key: 27 of 32
    "keys" on 1MansiS/JavaCrypto (live, 2026-09-11)."""
    assets, diagnostics = theia(
        secret("generic-api-key", "key", "ReadMe.md", 107),
        secret("generic-api-key", "key", "doc/api/encryption.md", 36),
        secret("github-pat", "token", "ci/deploy.sh", 4),
        secret("hashicorp-tf-password", "password", "infra/main.tf", 9),
        certificate_plugin_key(),
    )

    assert [a["name"] for a in assets] == ["RSA-2048"]
    (finding,) = [d for d in diagnostics if d["code"] == "CBOM_SECRET_IN_SOURCE"]
    assert "4 possible secret(s)" in finding["message"]
    assert "generic-api-key (2)" in finding["message"]
    assert "ReadMe.md:107" in finding["message"]
    assert "infra/main.tf:9" in finding["message"]
    # Tokens and passwords were dropped as "no usable assetType" — the same
    # findings, lost the other way. They are secrets now, and nothing else.
    assert not any(d["code"] == "ENGINE_PARTIAL_ECOSYSTEM" for d in diagnostics)


def test_a_private_key_theia_could_not_parse_stays_in_the_inventory() -> None:
    """A private key is crypto material; it is flagged, never moved out."""
    assets, diagnostics = theia(secret("private-key", "private-key", "deploy/key.pem", 1))

    (asset,) = assets
    assert asset["material_type"] == "private-key"
    assert not any(d["code"] == "CBOM_SECRET_IN_SOURCE" for d in diagnostics)


def test_no_secret_value_can_reach_the_diagnostic() -> None:
    """theia's secret component carries no value; the diagnostic is built from
    the rule id and the location alone."""
    _, diagnostics = theia(secret("generic-api-key", "key", "ReadMe.md", 1))

    text = json.dumps(diagnostics)
    assert "ReadMe.md:1" in text
    assert "Detected a Generic API Key" not in text


def test_a_document_without_secrets_is_unchanged() -> None:
    assets, diagnostics = theia(certificate_plugin_key())

    assert len(assets) == 1
    assert not diagnostics
