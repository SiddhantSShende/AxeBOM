"""The sandbox client.

⚠ THERE IS EXACTLY ONE SANDBOX, AND IT IS NOT THIS FILE.

The policy — ``--network=none``, read-only rootfs, dropped capabilities,
non-root, seccomp, every quota — lives in ``libs/go-shared/sandbox`` with the
twelve-case escape suite from Phase 5. This module SHELLS OUT to it via
``axebom sandbox run``.

The alternative was a Python implementation using the Docker SDK. That would
mean two implementations of a security control, and the Python one would have
no escape suite behind it — so the first time somebody changed a quota in one
and not the other, the difference would be invisible until an incident.

The cost is one process spawn per engine run, which is noise next to a
container start. The benefit is that "is the sandbox correctly configured?" has
ONE answer, provable in ONE place.

Note what this module cannot express: there is no way to ask for a writable
rootfs, a network, root, or a credential. Those fields do not exist in the
bridge's input schema, so a worker cannot weaken the sandbox even by mistake.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from axebom_shared.errors import EngineUnavailableError


@dataclass(frozen=True)
class SandboxLimits:
    """Resource quotas for one engine run.

    Defaults mirror ``.env.example``. Each bounds a specific denial of service,
    and a job exceeding one is KILLED AND REPORTED, never silently truncated —
    a scan that quietly produced half a BOM is worse than one that failed,
    because the half looks complete.
    """

    wall_clock_sec: int = 900
    cpu_millis: int = 2000
    memory_mb: int = 4096
    disk_mb: int = 20480
    pids_max: int = 512
    max_output_bytes: int = 256 * 1024 * 1024

    def as_dict(self) -> dict[str, int]:
        return {
            "wall_clock_sec": self.wall_clock_sec,
            "cpu_millis": self.cpu_millis,
            "memory_mb": self.memory_mb,
            "disk_mb": self.disk_mb,
            "pids_max": self.pids_max,
            "max_output_bytes": self.max_output_bytes,
        }


@dataclass(frozen=True)
class Mount:
    """A host path exposed to the container. Always read-only — the sandbox
    enforces that, it is not a flag a caller can unset."""

    source: str
    target: str


@dataclass
class SandboxResult:
    """What an engine run produced."""

    exit_code: int
    stdout: str = ""
    stderr: str = ""

    timed_out: bool = False
    oom_killed: bool = False
    output_truncated: bool = False

    #: The registry manifest digest the reference RESOLVED to, read back from
    #: the daemon. Empty when the image has no registry digest at all.
    image_digest: str = ""

    #: ⚠ THESE BRACKET EXACTLY THE INTERVAL ``duration_ms`` MEASURES.
    #:
    #: They travel together on purpose. A reader who cannot reconcile
    #: finished - started against duration cannot trust any of the three, and
    #: provenance that cannot be checked is not provenance. None means the run
    #: was never attempted — inventing a timestamp would be worse.
    started_at: datetime | None = None
    finished_at: datetime | None = None

    duration_ms: int = 0
    disk_quota_enforced: bool = True
    container_id: str = ""

    #: Set when the run could not be ATTEMPTED — a refused policy, a forbidden
    #: command, a missing image. Distinct from a non-zero ``exit_code``, which
    #: means the engine ran and failed. Adapters must not conflate them: one is
    #: our misconfiguration, the other is the engine's verdict.
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.error == "" and self.exit_code == 0 and not self.timed_out

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> SandboxResult:
        """Build from the bridge's output, tolerating unknown fields.

        Defensive by the same rule that governs engine output: a newer bridge
        adding a field must not break an older worker.
        """
        return cls(
            exit_code=int(payload.get("exit_code", -1)),
            stdout=str(payload.get("stdout", "")),
            stderr=str(payload.get("stderr", "")),
            timed_out=bool(payload.get("timed_out", False)),
            oom_killed=bool(payload.get("oom_killed", False)),
            output_truncated=bool(payload.get("output_truncated", False)),
            image_digest=str(payload.get("image_digest", "")),
            started_at=_parse_ts(payload.get("started_at")),
            finished_at=_parse_ts(payload.get("finished_at")),
            duration_ms=int(payload.get("duration_ms", 0)),
            disk_quota_enforced=bool(payload.get("disk_quota_enforced", True)),
            container_id=str(payload.get("container_id", "")),
            error=str(payload.get("error", "")),
        )


def _parse_ts(raw: Any) -> datetime | None:
    """Read an RFC3339 timestamp from the bridge, defensively.

    Returns None rather than raising on anything unreadable: a timestamp is
    provenance, and losing a scan's results because a clock field drifted would
    trade something that matters for something that does not.
    """
    if not isinstance(raw, str) or not raw:
        return None
    try:
        # fromisoformat handles the trailing Z from Python 3.11 on.
        return datetime.fromisoformat(raw).astimezone(UTC)
    except ValueError:
        return None


class Sandbox:
    """Runs commands through the ``axebom sandbox`` bridge."""

    def __init__(self, binary: str | None = None) -> None:
        self._binary = binary or self._locate()

    @staticmethod
    def _locate() -> str:
        """Find the axebom binary.

        ``AXEBOM_BIN`` wins, then PATH, then a repo-relative build. The
        explicit override exists because a worker container ships the binary at
        a known path while a developer runs it from a checkout.
        """
        override = os.environ.get("AXEBOM_BIN")
        if override:
            return override
        found = shutil.which("axebom")
        if found:
            return found
        return "axebom"

    def check(self) -> dict[str, Any]:
        """Report whether the sandbox is usable.

        Called ONCE at worker startup. A worker that cannot reach Docker should
        say so clearly once, rather than failing every job with the same error
        and burying the cause.
        """
        try:
            proc = subprocess.run(
                [self._binary, "sandbox", "check"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise EngineUnavailableError(
                f"the sandbox bridge ({self._binary}) could not be run: {exc}"
            ) from exc

        if proc.returncode != 0:
            raise EngineUnavailableError(
                f"the sandbox is not usable: {proc.stdout.strip() or proc.stderr.strip()}"
            )
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise EngineUnavailableError(
                f"the sandbox bridge returned unreadable output: {exc}"
            ) from exc

    def run(
        self,
        *,
        image: str,
        argv: list[str],
        entrypoint: list[str] | None = None,
        working_dir: str | None = None,
        env: dict[str, str] | None = None,
        mounts: list[Mount] | None = None,
        limits: SandboxLimits | None = None,
        labels: dict[str, str] | None = None,
        pull: bool = False,
    ) -> SandboxResult:
        """Run one command in the sandbox.

        ⚠ NOTE WHAT CANNOT BE PASSED: no network flag, no policy, no
        credential. Those are not parameters here because they are not fields
        in the bridge's input schema — a worker cannot weaken the sandbox.
        """
        spec: dict[str, Any] = {
            "image": image,
            "argv": argv,
            "limits": (limits or SandboxLimits()).as_dict(),
        }
        if entrypoint:
            spec["entrypoint"] = entrypoint
        if working_dir:
            spec["working_dir"] = working_dir
        if env:
            spec["env"] = env
        if mounts:
            spec["mounts"] = [{"source": m.source, "target": m.target} for m in mounts]
        if labels:
            spec["labels"] = labels

        args = [self._binary, "sandbox", "run"]
        if pull:
            args.append("-pull")

        # The subprocess timeout is the wall clock PLUS slack. The sandbox
        # enforces the real limit and kills the container; this is only a
        # backstop against the bridge itself wedging, and it must be LONGER or
        # it would cut off a legitimate run.
        timeout = (limits or SandboxLimits()).wall_clock_sec + 120

        try:
            proc = subprocess.run(
                args,
                input=json.dumps(spec),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                exit_code=-1,
                timed_out=True,
                error=f"the sandbox bridge did not return within {timeout}s",
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return SandboxResult(exit_code=-1, error=f"could not run the sandbox bridge: {exc}")

        if not proc.stdout.strip():
            return SandboxResult(
                exit_code=proc.returncode,
                error=f"the sandbox bridge produced no output: {proc.stderr.strip()[:400]}",
            )

        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            return SandboxResult(
                exit_code=-1,
                error=f"the sandbox bridge returned unreadable output: {exc}",
            )

        return SandboxResult.from_json(payload)


@dataclass
class WorkspaceLayout:
    """Where an engine reads, and how its output comes back.

    ⚠ THERE IS NO WRITABLE MOUNT, AND THAT IS DELIBERATE.

    The sandbox forces EVERY host mount read-only (see ``mountsFor`` in
    libs/go-shared/sandbox): a writable host mount is how a container escape
    becomes host compromise. So an engine cannot write its report to a shared
    directory, and output comes back through STDOUT instead, captured and
    bounded by ``max_output_bytes``.

    Most engines support this natively — syft, grype, trivy and osv-scanner all
    write to stdout. The ones that insist on a file (dependency-check) write
    into the container's own writable tmpfs workspace and the command ends with
    ``cat``, which is why ``file_output_command`` exists below.

    An engine that could modify what it is scanning could also make a report
    describe something the customer never wrote, so the source mount being
    read-only matters for correctness as well as for containment.
    """

    source: Path
    #: Path inside the container. Fixed rather than derived, so an argv is
    #: reproducible across hosts — the provenance manifest records it.
    container_source: str = "/src"
    #: The container's writable tmpfs, for engines that need scratch space.
    container_scratch: str = "/workspace"

    def mounts(self) -> list[Mount]:
        return [Mount(source=str(self.source.resolve()), target=self.container_source)]

    def ensure(self) -> None:
        self.source.mkdir(parents=True, exist_ok=True)


def file_output_command(tool_argv: list[str], produced_file: str) -> list[str]:
    """Wrap a command whose tool insists on writing a file.

    Runs the tool, then ``cat``s the file to stdout so the result comes back
    through the one channel that exists. Used only where a tool has no stdout
    mode — dependency-check is the current example.

    The file is written into the container's tmpfs, which is destroyed with the
    container, so nothing persists on the host.
    """
    quoted = " ".join(_shell_quote(a) for a in tool_argv)
    return ["sh", "-c", f"{quoted} && cat {_shell_quote(produced_file)}"]


def _shell_quote(arg: str) -> str:
    """Single-quote an argument for the container shell.

    The argv is built from engine configuration and a workspace path, not from
    repository content — but quoting is the cheap half of never finding out
    that assumption was wrong.
    """
    return "'" + arg.replace("'", """'\''""") + "'"
