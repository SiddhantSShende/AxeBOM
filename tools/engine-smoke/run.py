"""Run every SBOM engine against a real fixture, through the real sandbox.

WHY THIS EXISTS, given there are already 74 worker tests

Those tests replay recorded scanner output from `fixtures/*/raw/*.json`. That is
the right default — it makes normalization deterministic, offline and stable
across upstream releases. But it means the tests pass whether or not a single
engine can actually start on this machine.

This is the other half: it starts real containers, against a real provisioned
database, over a real source tree, and reports what each engine did. It is an
operator command, not a test, and it is expected to be slow.

    python -m tools.engine-smoke.run                 # every engine
    python -m tools.engine-smoke.run --engine syft   # just one

Run it inside the worker container, where the docker socket and the engine
databases are mounted:

    docker compose ... exec sbom-worker python /app/tools/engine-smoke/run.py
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import uuid
from pathlib import Path
from typing import Any

from workers.sbom.runner import ADAPTERS, DEPENDS_ON, SBOMWorker

from axebom_shared.enginedb import database_root

#: Four ecosystems in one tree — maven, go, pypi and npm. Chosen because a
#: single-ecosystem fixture cannot distinguish "the engine works" from "the
#: engine works for the one language I tried".
DEFAULT_FIXTURE = "fixtures/monorepo-multiroot/repo"

#: Ordered so grype runs after syft: it matches against OUR SBOM rather than
#: re-scanning the tree, and DEPENDS_ON records that.
ORDER = ["syft", "syft-spdx", "trivy-fs", "osv-scanner", "grype", "trivy-image", "dependency-check"]

#: Engines whose source kind is an image, not a tree. They need --image.
IMAGE_ONLY = {"trivy-image"}


def repo_root() -> Path:
    here = Path(__file__).resolve()
    for candidate in here.parents:
        if (candidate / "go.mod").exists():
            return candidate
    return Path.cwd()


def stage_workspace(fixture: Path, workspace: Path) -> None:
    """Copy the fixture into a path the DAEMON can see.

    The sandbox mounts the workspace into the engine container, and the daemon
    resolves that path on the host. A workspace under /tmp inside this
    container would mount as an empty directory and every engine would honestly
    report finding nothing.
    """
    if workspace.exists():
        shutil.rmtree(workspace)
    shutil.copytree(fixture, workspace)
    # Engines run as uid 65534 and must be able to read the tree.
    workspace.chmod(0o755)
    for child in workspace.rglob("*"):
        child.chmod(0o755 if child.is_dir() else 0o644)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run SBOM engines against a real fixture.")
    parser.add_argument("--engine", action="append", help="engine id (repeatable); default all")
    parser.add_argument("--fixture", default=DEFAULT_FIXTURE, help="source tree to scan")
    parser.add_argument("--json", action="store_true", help="emit machine-readable results")
    parser.add_argument(
        "--image",
        help="digest-pinned image@sha256:... for the image-mode engines (trivy-image)",
    )
    args = parser.parse_args(argv)

    root = repo_root()
    fixture = (root / args.fixture).resolve()
    if not fixture.is_dir():
        print(f"fixture not found: {fixture}", file=sys.stderr)
        return 2

    engines = args.engine or [e for e in ORDER if e in ADAPTERS]

    # Image-mode engines need an image, not a directory. Running them against a
    # source tree is not a meaningful test of the engine — it just raises. Skip
    # them unless one was supplied, and SAY SO rather than quietly dropping
    # them: a silently shortened engine list is the exact failure this whole
    # tool exists to detect.
    if not args.image:
        skipped_image_engines = [e for e in engines if e in IMAGE_ONLY]
        engines = [e for e in engines if e not in IMAGE_ONLY]
    else:
        skipped_image_engines = []

    worker = SBOMWorker()
    scan_id = str(uuid.uuid4())
    workspace = worker._workspace_root / scan_id
    workspace.parent.mkdir(parents=True, exist_ok=True)
    stage_workspace(fixture, workspace)

    print(f"fixture   {fixture}")
    print(f"workspace {workspace}")
    print(f"databases {database_root()}")
    print()

    results: list[dict[str, Any]] = []

    for engine in engines:
        job = {
            "job_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "tenant_id": "00000000-0000-0000-0000-000000000000",
            "engine": engine,
            "source_meta": (
                {"kind": "image", "image_digest": args.image}
                if engine in IMAGE_ONLY
                else {"kind": "git", "commit_sha": "0" * 40}
            ),
        }

        result = worker.handle(job)
        status = result.get("status", "?")
        diags = result.get("diagnostics") or []
        artifacts = result.get("artifacts") or []

        # syft writes the SBOM grype consumes. Promote it into the workspace
        # under the name _build_target looks for, or grype is skipped for
        # missing input rather than actually exercised.
        if engine == "syft" and status in {"succeeded", "partial"}:
            if not promote_sbom(artifacts, workspace):
                print("        ! syft produced no native_output; grype will be skipped")

        row = {
            "engine": engine,
            "status": status,
            "counts": result.get("counts") or {},
            "engine_db_version": result.get("engine_db_version") or "",
            "diagnostics": [f"{d.get('code')}: {d.get('message')}" for d in diags],
            "depends_on": DEPENDS_ON.get(engine),
        }
        results.append(row)
        report_one(row)

    print()
    if skipped_image_engines:
        print(f"not run (no --image supplied): {', '.join(skipped_image_engines)}")
    summary(results)

    if args.json:
        print()
        print(json.dumps(results, indent=2, sort_keys=True))

    # An engine that is honestly `unavailable` is NOT a failure — that is the
    # documented outcome for an unprovisioned database or a missing key, and
    # treating it as an error would push people toward hiding the gap.
    broken = [r for r in results if r["status"] in {"failed", "error"}]
    return 1 if broken else 0


def promote_sbom(artifacts: list[dict[str, Any]], workspace: Path) -> bool:
    """Put syft's CycloneDX where _build_target looks for it.

    grype matches against OUR SBOM rather than re-cataloguing the tree, so
    without this it is correctly `skipped` for missing input and never actually
    exercised.

    The envelope field is `uri`, not `path` — ScanResultV1 carries artifact
    REFERENCES. Reading the wrong key yields "" and the copy silently does
    nothing, which looks exactly like syft not having produced an SBOM.
    """
    for art in artifacts:
        if art.get("role") != "native_output":
            continue
        src = Path(str(art.get("uri", "")))
        if src.exists():
            shutil.copyfile(src, workspace / "sbom.cdx.json")
            (workspace / "sbom.cdx.json").chmod(0o644)
            return True
    return False


def report_one(row: dict[str, Any]) -> None:
    mark = {
        "succeeded": "  ok ",
        "partial": " part",
        "unavailable": " gap ",
        "skipped": " skip",
    }.get(row["status"], " FAIL")

    counts = row["counts"]
    detail = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()) if v) or "-"
    print(f"{mark}  {row['engine']:<18} {row['status']:<12} {detail}")

    if row["engine_db_version"]:
        print(f"        db: {row['engine_db_version']}")
    for d in row["diagnostics"]:
        print(f"        {d}")


def summary(results: list[dict[str, Any]]) -> None:
    by = {}
    for r in results:
        by[r["status"]] = by.get(r["status"], 0) + 1
    print("  ".join(f"{k}={v}" for k, v in sorted(by.items())))
    gaps = [r for r in results if r["status"] == "unavailable"]
    if gaps:
        print()
        print("Stated gaps (an engine that cannot run says so; it never reports a clean project):")
        for r in gaps:
            reason = r["diagnostics"][0] if r["diagnostics"] else "no reason recorded"
            print(f"  {r['engine']:<18} {reason}")


if __name__ == "__main__":
    raise SystemExit(main())
