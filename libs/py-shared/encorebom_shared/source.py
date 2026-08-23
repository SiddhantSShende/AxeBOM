"""Materialize a scan's source archive into the worker's workspace.

# The gap this closes

The fetcher uploads a content-addressed ``source.tar.zst`` and the orchestrator
pins ``source_archive_ref``, then fans out one job per engine carrying
``workspace.artifact_uri``. Nothing downloaded it, so every engine ran against
an empty directory and reported honestly on nothing — syft and trivy-fs
``partial``, osv-scanner ``failed``. The dispatch chain was complete; the source
never reached the engines.

# Why this shells out instead of extracting in Python

The archive is untrusted content — a customer's repository. Extracting it safely
needs path-traversal, size, inode and inflation guards, and those already exist,
hardened and tested, in ``fetcher.ExtractTar``. A second implementation in
Python would be a second thing to get right, and the second one would be the
weaker. The workers already shell out to the same binary for the sandbox bridge.

# ⚠ ONE WORKSPACE, SIX ENGINES, POSSIBLY CONCURRENT

A scan fans out one job per engine and they all read the same tree. The CLI is
idempotent and publishes by atomic rename, so a worker that loses the race finds
the winner's finished tree rather than a half-written one. Nothing here needs a
lock, and there is no lock file to leak when a worker is killed mid-extraction.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .errors import EngineUnavailableError
from .logging import get_logger

log = get_logger(__name__)

#: Generous, because it covers a download as well as an extraction. A large
#: monorepo over a slow link legitimately takes minutes, and killing it early
#: turns a slow scan into a failed one.
DEFAULT_TIMEOUT_SEC = 900


def _binary() -> str:
    """Locate the encorebom CLI, matching the sandbox bridge's rules."""
    override = os.environ.get("ENCOREBOM_BIN")
    if override:
        return override
    return shutil.which("encorebom") or "encorebom"


def workspace_ref(job: dict[str, Any]) -> tuple[str, str]:
    """Pull the archive reference out of a ScanJobV1.

    Returns (artifact_uri, sha256); either may be empty. The field is
    ``workspace``, populated by the orchestrator's fan-out from the scan row the
    fetcher pinned.
    """
    ws = job.get("workspace") or {}
    return str(ws.get("artifact_uri") or ""), str(ws.get("sha256") or "")


def materialize(
    job: dict[str, Any],
    dest: Path,
    *,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
) -> bool:
    """Ensure the scan's source tree is present at `dest`.

    Returns True when a tree is available, False when the job carries no archive
    reference at all.

    ⚠ RAISES EngineUnavailableError ON FAILURE, RATHER THAN RETURNING FALSE.

    The two outcomes are not the same and must not collapse into one. A job with
    no archive reference is a legitimate shape — an upload-based or manual scan
    has nothing to fetch — and the engine should proceed against whatever the
    workspace already holds. An archive that is named but cannot be materialized
    is a REAL failure, and letting the engine run anyway would scan an empty
    directory and report a clean project. That is the single worst outcome this
    codebase guards against.
    """
    engine = str(job.get("engine") or "unknown")
    uri, sha = workspace_ref(job)
    if not uri:
        log.info(
            "job carries no source archive; scanning the workspace as-is",
            extra={"job_id": job.get("job_id"), "engine": job.get("engine")},
        )
        return False

    argv = [
        _binary(),
        "source",
        "materialize",
        "--uri",
        uri,
        "--dest",
        str(dest),
    ]
    if sha:
        argv += ["--sha256", sha]

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise EngineUnavailableError(
            engine, f"materializing the source archive timed out after {timeout_sec}s"
        ) from exc
    except OSError as exc:
        raise EngineUnavailableError(
            engine, f"the encorebom binary ({_binary()}) could not be run: {exc}"
        ) from exc

    if proc.returncode != 0:
        # stderr carries the CLI's own reason — a digest mismatch, a missing
        # object, an extraction guard. Passing it through means the scan result
        # names the real cause instead of "the engine found nothing".
        detail = (proc.stderr or proc.stdout or "").strip()[-600:]
        raise EngineUnavailableError(
            engine, f"the source archive could not be materialized: {detail}"
        )

    log.info(
        "source materialized",
        extra={
            "job_id": job.get("job_id"),
            "dest": str(dest),
            "detail": (proc.stdout or "").strip()[-200:],
        },
    )
    return True
