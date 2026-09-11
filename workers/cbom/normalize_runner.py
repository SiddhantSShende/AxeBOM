"""Normalize a CBOM fixture's stored engine artifacts into the canonical model.

⚠ THIS READS STORED ARTIFACTS. IT NEVER RUNS A SCANNER.

That is ADR-0003: normalization is a pure function of the raw output, so a
normalizer fix is a re-normalization of what is already on disk, never a re-scan.
Each `raw/<engine_id>.json` is one engine's stored native output, read through
that engine's own extractor and stamped with its artifact's sha256 — exactly what
`workers/cbom/normalize_consumer.py` does with a live scan's artifacts.

Usage::

    python -m workers.cbom.normalize_runner fixtures/crypto-mixed
    python -m workers.cbom.normalize_runner fixtures/crypto-mixed --write-expected
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from workers.cbom.normalize.extractors import EXTRACTORS
from workers.cbom.normalize.pipeline import build_canonical_cbom

#: What a CBOM golden pins, one file each.
EXPECTED_FILES = ("crypto_assets.json", "coverage.json", "diagnostics.json")


def load_assets(raw_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Every engine's stored output, extracted and stamped as the consumer does."""
    assets: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    for engine_id in sorted(EXTRACTORS):
        path = raw_dir / f"{engine_id}.json"
        if not path.exists():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        found, extraction_diagnostics = EXTRACTORS[engine_id](payload)
        sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        version = _engine_version(payload)
        for asset in found:
            asset["engine_id"] = engine_id
            asset["engine_version"] = version
            asset["artifact_sha256"] = sha256
        assets.extend(found)
        diagnostics.extend(extraction_diagnostics)
    return assets, diagnostics


def _engine_version(payload: Any) -> str:
    """The version the engine stamped into its own document, if any."""
    metadata = payload.get("metadata") if isinstance(payload, dict) else None
    tools = metadata.get("tools") if isinstance(metadata, dict) else None
    candidates: list[Any] = []
    if isinstance(tools, list):
        candidates = tools
    elif isinstance(tools, dict):
        candidates = [*(tools.get("components") or []), *(tools.get("services") or [])]
    for tool in candidates:
        if isinstance(tool, dict) and tool.get("version"):
            return str(tool["version"])
    return ""


def normalize_fixture(fixture_dir: Path) -> dict[str, Any]:
    """Normalize one fixture and return the canonical CBOM document."""
    assets, diagnostics = load_assets(fixture_dir / "raw")
    canonical = build_canonical_cbom(assets)
    canonical["diagnostics"] = [*canonical["diagnostics"], *diagnostics]
    return canonical


def expected_view(canonical: dict[str, Any]) -> dict[str, Any]:
    """The pinned view: assets, the coverage breakdown, and the diagnostics."""
    diagnostics = sorted(
        canonical["diagnostics"],
        key=lambda d: (str(d.get("code", "")), str(d.get("message", ""))),
    )
    return {
        "crypto_assets.json": canonical["crypto_assets"],
        "coverage.json": canonical["coverage"],
        "diagnostics.json": diagnostics,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m workers.cbom.normalize_runner",
        description="Normalize stored CBOM engine artifacts into the canonical model.",
    )
    parser.add_argument("fixture", type=Path, nargs="+", help="fixture directory")
    parser.add_argument(
        "--write-expected",
        action="store_true",
        help="write expected/*.json — a DELIBERATE, REVIEWED act",
    )
    args = parser.parse_args(argv)

    failures = 0
    for fixture in args.fixture:
        if not (fixture / "raw").is_dir():
            print(f"{fixture}: no raw/ directory", file=sys.stderr)
            failures += 1
            continue

        canonical = normalize_fixture(fixture)

        if args.write_expected:
            # ⚠ Changing a golden requires an explicit justification in the
            # commit message. A golden updated without review is no guardrail.
            expected_dir = fixture / "expected"
            expected_dir.mkdir(parents=True, exist_ok=True)
            for name, value in expected_view(canonical).items():
                (expected_dir / name).write_text(
                    json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )

        by_type: dict[str, int] = {}
        for asset in canonical["crypto_assets"]:
            by_type[asset["asset_type"]] = by_type.get(asset["asset_type"], 0) + 1
        print(
            json.dumps(
                {
                    "fixture": fixture.name,
                    "crypto_assets": by_type,
                    "completeness_pct": canonical["coverage"]["completeness_pct"],
                    "declaration_pct": canonical["coverage"]["declaration_pct"],
                    "diagnostics": sorted({d.get("code", "") for d in canonical["diagnostics"]}),
                },
                indent=2,
            )
        )

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
