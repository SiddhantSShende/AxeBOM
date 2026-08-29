"""Normalize a scan's stored artifacts into the canonical model.

⚠ THIS READS STORED ARTIFACTS. IT NEVER RUNS A SCANNER.

That is the whole of ADR-0003: normalization is a pure function of the raw
output, so fixing a normalizer bug means re-normalizing what is already on disk
rather than re-scanning a customer's repository. It also makes the golden corpus
fast, offline and stable — the tests replay `fixtures/*/raw/*.json` and never
touch Docker.

Usage::

    python -m workers.sbom.normalize_runner fixtures/npm-simple
    python -m workers.sbom.normalize_runner fixtures/npm-simple --write-expected
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from axebom_shared.logging import get_logger
from axebom_shared.normalize.coverage import Field, fields_from_profile
from axebom_shared.normalize.pipeline import Artifact, normalize

log = get_logger("normalize")

#: The compliance profile. Field ids, weights and the count all come from here —
#: nothing downstream may hardcode any of them (invariant 2).
PROFILE_PATH = Path("docs/reference/certin-v2.0.yaml")

#: Engine id -> the raw artifact filename Phase 7 writes.
ARTIFACTS = {
    "syft": "syft.json",
    "syft-spdx": "syft-spdx.json",
    "trivy-fs": "trivy-fs.json",
    "grype": "grype.json",
    "osv-scanner": "osv-scanner.json",
    "dependency-check": "dependency-check.json",
}


def sbom_fields(profile_path: Path | None = None) -> list[Field]:
    """The SBOM data fields, read from the profile.

    ⚠ The COUNT is never written down. It is whatever the profile says, so a
    CERT-In revision is a data change rather than a code change.
    """
    path = profile_path or PROFILE_PATH
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = ((data.get("sbom") or {}).get("data_fields")) or []
    return fields_from_profile(entries)


def load_artifacts(raw_dir: Path) -> list[Artifact]:
    """Read every stored artifact in a fixture's `raw/` directory."""
    artifacts: list[Artifact] = []

    for engine, filename in sorted(ARTIFACTS.items()):
        path = raw_dir / filename
        if not path.exists():
            # ⚠ ABSENT IS NOT AN ERROR — it is `unavailable`, and it must reach
            # the Engine Coverage table. An engine that silently contributes
            # nothing is exactly the gap invariant 12 exists to surface.
            artifacts.append(Artifact(engine=engine, payload={}, status="unavailable"))
            continue

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning(
                "stored artifact is unreadable", extra={"engine": engine, "cause": str(exc)}
            )
            artifacts.append(Artifact(engine=engine, payload={}, status="failed"))
            continue

        artifacts.append(
            Artifact(
                engine=engine,
                payload=payload,
                engine_version=_engine_version(payload, engine),
                status="succeeded",
                sha256=_sha256(path),
                uri=str(path),
            )
        )

    return artifacts


def _engine_version(payload: Any, engine: str) -> str:
    """Recover the engine version from its own output.

    Read from the artifact rather than the manifest so that a re-normalization
    reports what ACTUALLY produced the data, not what is pinned today. Those
    differ precisely when a report is being defended after a tool upgrade.
    """
    if not isinstance(payload, dict):
        return ""

    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        for tool in _iter_tools(metadata):
            if isinstance(tool, dict) and tool.get("version"):
                return str(tool["version"])

    descriptor = payload.get("descriptor")
    if isinstance(descriptor, dict) and descriptor.get("version"):
        return str(descriptor["version"])

    creation = payload.get("creationInfo")
    if isinstance(creation, dict):
        for creator in creation.get("creators", []) or []:
            if isinstance(creator, str) and "-" in creator:
                return creator.rsplit("-", 1)[-1]

    return ""


def _iter_tools(metadata: dict[str, Any]):
    tools = metadata.get("tools")
    if isinstance(tools, list):
        yield from tools
    elif isinstance(tools, dict):
        yield from tools.get("components", []) or []


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize_fixture(fixture_dir: Path, *, profile_path: Path | None = None) -> dict[str, Any]:
    """Normalize one fixture and return the canonical model."""
    raw_dir = fixture_dir / "raw"
    artifacts = load_artifacts(raw_dir)

    result = normalize(
        artifacts,
        # ⚠ Derived from the fixture NAME, not from a uuid or a clock. The
        # canonical output has to be byte-identical across runs and machines.
        scan_id=f"fixture-{fixture_dir.name}",
        fields=sbom_fields(profile_path),
        alias_snapshot_id=f"fixture-{fixture_dir.name}-aliases",
    )
    return result.as_dict()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m workers.sbom.normalize_runner",
        description="Normalize stored scan artifacts into the canonical model.",
    )
    parser.add_argument("fixture", type=Path, nargs="+", help="fixture directory")
    parser.add_argument(
        "--write-expected",
        action="store_true",
        help="write expected/canonical.json — a DELIBERATE, REVIEWED act",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    failures = 0
    for fixture in args.fixture:
        if not (fixture / "raw").is_dir():
            log.error("no raw/ directory", extra={"fixture": str(fixture)})
            failures += 1
            continue

        canonical = normalize_fixture(fixture)

        if args.write_expected:
            # ⚠ Changing a golden requires an explicit justification in the
            # commit message. Goldens are the guardrail against silently wrong
            # output; a golden updated without review is no guardrail at all.
            expected_dir = fixture / "expected"
            expected_dir.mkdir(parents=True, exist_ok=True)
            (expected_dir / "canonical.json").write_text(
                json.dumps(canonical, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            log.info("wrote expected", extra={"fixture": fixture.name})

        if not args.quiet:
            print(
                json.dumps(
                    {
                        "fixture": fixture.name,
                        "components": canonical["component_count"],
                        "findings": canonical["finding_count"],
                        "clusters": len(canonical["vuln_clusters"]),
                        "completeness_pct": canonical["coverage"]["completeness_pct"],
                        "declaration_pct": canonical["coverage"]["declaration_pct"],
                        "roots": len(canonical["graph"]["roots"]),
                        "orphans": len(canonical["graph"]["orphans"]),
                    },
                    indent=2,
                )
            )

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
