"""cbomkit-theia's adapter: what an empty result means, and when it is an error.

⚠ theia is a FILE-PATTERN scanner — certificate files, key files, OpenSSL
configuration, java.security. "This tree holds none of those" is a true,
checkable negative, so a clean empty result succeeds, with an explicit info
diagnostic naming what was examined. It used to be `partial`, which made every
CBOM scan of a repository without PEM files `completed_with_errors`. Anything
malformed on the way to nothing still stays `partial`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from workers.cbom.adapters.cbomkit_theia import CBOMkitTheiaAdapter
from workers.sbom.adapters.common import EngineImage

from axebom_shared.adapters.base import GenerateResult, ResultStatus, ScanTarget
from axebom_shared.sandbox import SandboxResult

FIXTURE = (
    Path(__file__).resolve().parents[2] / "fixtures" / "crypto-mixed" / "raw" / "cbomkit-theia.json"
)

#: The metadata block every live theia 1.1.2 run carried (stored artifacts of
#: 2026-09-03). The plugin list is what the empty-result note repeats back.
LIVE_METADATA: dict[str, Any] = {
    "tools": {
        "services": [
            {
                "provider": {"name": "PQCA"},
                "name": "cbomkit-theia",
                "version": "edge",
                "services": [
                    {"name": "Certificate File Plugin"},
                    {"name": "Secret Detection Plugin"},
                    {"name": "OpenSSL Config Plugin"},
                    {"name": "Problematic CA Detection Plugin"},
                ],
            }
        ]
    }
}


class StubResolver:
    def image_for(self, engine_id: str) -> EngineImage:
        return EngineImage(
            reference=f"example.invalid/{engine_id}:1.0.0", version="1.0.0", digest_pinned=True
        )


def interpret(tmp_path: Path, payload: Any) -> GenerateResult:
    ws = tmp_path / "src"
    ws.mkdir(exist_ok=True)
    target = ScanTarget(scan_id="s", job_id="j", kind="git", workspace=ws)
    return CBOMkitTheiaAdapter(resolver=StubResolver()).interpret(
        target,
        payload,
        SandboxResult(exit_code=0, stdout=json.dumps(payload)),
        GenerateResult(status=ResultStatus.SUCCEEDED),
    )


def codes(result: GenerateResult) -> list[str]:
    return [d.get("code") for d in result.diagnostics]


def note(result: GenerateResult) -> dict[str, Any]:
    return next(d for d in result.diagnostics if d.get("code") == "ENGINE_NO_CRYPTO_MATERIAL")


def test_theia_s_live_empty_form_is_a_clean_success(tmp_path: Path) -> None:
    """The exact shape every live run over a tree with no key or cert files wrote."""
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": LIVE_METADATA,
        "components": None,
    }
    result = interpret(tmp_path, payload)

    assert result.status is ResultStatus.SUCCEEDED
    assert "ENGINE_NO_CRYPTO_MATERIAL" in codes(result)
    assert "ENGINE_OUTPUT_UNEXPECTED" not in codes(result)
    assert "ENGINE_ZERO_RESULTS" not in codes(result)


def test_the_empty_result_says_what_was_examined_and_what_was_not(tmp_path: Path) -> None:
    """⚠ The negative must not be read wider than it is: theia never reads code."""
    diagnostic = note(interpret(tmp_path, {"metadata": LIVE_METADATA, "components": None}))

    assert diagnostic["severity"] == "info"
    assert "Certificate File Plugin" in diagnostic["hint"]
    assert "does not read source code" in diagnostic["hint"]


def test_an_absent_components_key_is_empty_too(tmp_path: Path) -> None:
    """CycloneDX allows omitting `components` when there is nothing to list."""
    result = interpret(tmp_path, {"bomFormat": "CycloneDX"})

    assert result.status is ResultStatus.SUCCEEDED
    assert "did not report which plugins ran" in note(result)["hint"]


@pytest.mark.parametrize("components", ["not a list", {"an": "object"}, 42])
def test_a_components_value_that_is_not_an_array_stays_partial(
    tmp_path: Path, components: Any
) -> None:
    result = interpret(tmp_path, {"components": components})

    assert result.status is ResultStatus.PARTIAL
    assert "ENGINE_OUTPUT_UNEXPECTED" in codes(result)
    assert "ENGINE_NO_CRYPTO_MATERIAL" not in codes(result)


def test_secrets_alone_are_a_finding_not_a_degraded_run(tmp_path: Path) -> None:
    """⚠ On 1MansiS/JavaCrypto theia's only hits were gitleaks strings in docs.
    Counted as a failure, the run went `partial` and the scan
    `completed_with_errors` (live, 2026-09-11). They are a finding about the
    source; the run itself was clean."""
    secret = {
        "type": "cryptographic-asset",
        "name": "generic-api-key",
        "evidence": {"occurrences": [{"location": "ReadMe.md", "line": 107}]},
        "cryptoProperties": {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {"type": "key"},
        },
    }
    result = interpret(tmp_path, {"metadata": LIVE_METADATA, "components": [secret]})

    assert result.status is ResultStatus.SUCCEEDED
    assert "CBOM_SECRET_IN_SOURCE" in codes(result)
    assert "ENGINE_NO_CRYPTO_MATERIAL" in codes(result)


def test_an_unclassifiable_asset_is_not_a_clean_empty_result(tmp_path: Path) -> None:
    """Something WAS found. Calling that "nothing here" would be the silent
    zero the info note exists to rule out."""
    payload = {
        "components": [
            {"type": "cryptographic-asset", "cryptoProperties": {"assetType": "nonsense"}}
        ]
    }
    result = interpret(tmp_path, payload)

    assert result.status is ResultStatus.PARTIAL
    assert "ENGINE_NO_CRYPTO_MATERIAL" not in codes(result)


def test_the_committed_fixture_still_succeeds_with_its_assets(tmp_path: Path) -> None:
    result = interpret(tmp_path, json.loads(FIXTURE.read_text()))

    assert result.status is ResultStatus.SUCCEEDED
    assert result.summary.as_dict()["crypto_assets"] > 0
    assert "ENGINE_NO_CRYPTO_MATERIAL" not in codes(result)
