"""The CBOM normalize consumer's reading of a trigger's stored artifacts."""

from __future__ import annotations

import json
from pathlib import Path

from workers.cbom.normalize.extractors import CBOM_ENGINES
from workers.cbom.normalize_consumer import _native_payloads


def trigger(*engines: dict) -> dict:
    return {"scan_id": "s", "tenant_id": "t", "engines": list(engines)}


def engine(engine_id: str, status: str, uri: str) -> dict:
    return {
        "engine_id": engine_id,
        "engine_version": "1.0",
        "status": status,
        "artifacts": [{"role": "native_output", "uri": uri, "sha256": "a" * 64}],
    }


def test_a_timed_out_engine_left_no_result_not_a_malformed_one(tmp_path: Path) -> None:
    """⚠ cdxgen-cbom killed at its deadline stored an empty stdout, reported as
    "not valid JSON" — as if the engine had emitted garbage (live, 2026-09-11)."""
    (tmp_path / "empty.json").write_bytes(b"")
    (tmp_path / "theia.json").write_text(json.dumps({"components": []}))

    payloads, diagnostics = _native_payloads(
        trigger(
            engine("cdxgen-cbom", "timeout", "empty.json"),
            engine("cbomkit-theia", "succeeded", "theia.json"),
        ),
        tmp_path,
        CBOM_ENGINES,
    )

    assert [source.engine_id for source, _ in payloads] == ["cbomkit-theia"]
    codes = {d["code"] for d in diagnostics}
    assert codes == {"NORMALIZE_ENGINE_NO_RESULT"}
    assert "timeout" in diagnostics[0]["message"]


def test_a_partial_run_is_still_a_result(tmp_path: Path) -> None:
    (tmp_path / "out.json").write_text(json.dumps({"components": []}))

    payloads, diagnostics = _native_payloads(
        trigger(engine("cbomkit-action", "partial", "out.json")), tmp_path, CBOM_ENGINES
    )

    assert len(payloads) == 1
    assert not diagnostics


def test_genuinely_malformed_output_is_still_reported(tmp_path: Path) -> None:
    (tmp_path / "bad.json").write_text("{not json")

    _, diagnostics = _native_payloads(
        trigger(engine("cbomkit-action", "succeeded", "bad.json")), tmp_path, CBOM_ENGINES
    )

    assert [d["code"] for d in diagnostics] == ["NORMALIZE_ARTIFACT_UNPARSEABLE"]
