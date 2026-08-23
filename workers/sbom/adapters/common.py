"""Shared machinery for the SBOM engine adapters.

Every adapter here does the same five things, and doing them in one place is
what keeps the differences between engines visible:

    1. resolve the pinned image from OSINT/tools.manifest.yaml
    2. build an argv and REDACT it
    3. run it in the sandbox (never directly — see encorebom_shared.sandbox)
    4. classify the outcome, including the statuses that are not failures
    5. write the raw artifact, which is Phase 8's input and is never mutated

⚠ THE TWO CLASSIFICATION RULES THAT MATTER MOST:

    ZERO COMPONENTS IS `partial` WITH A DIAGNOSTIC, NOT `succeeded`.
    Zero is a claim. A scan that found nothing and says "succeeded" renders as
    a clean report, which is indistinguishable from a real empty project and is
    exactly the false negative this product exists to avoid.

    AN ENGINE THAT CANNOT RUN IS `unavailable`, NEVER A SCAN FAILURE.
    It is recorded in Engine Coverage so the customer sees which engine was
    requested, that it did not run, and why.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from encorebom_shared.adapters.base import (
    Availability,
    Capabilities,
    EngineMode,
    GenerateResult,
    RawArtifact,
    ResultStatus,
    ScanTarget,
    ToolAdapterBase,
)
from encorebom_shared.enginedb import EngineDatabase, database_root
from encorebom_shared.enginedb import resolve as enginedb_resolve
from encorebom_shared.sandbox import Mount, Sandbox, SandboxLimits, SandboxResult, WorkspaceLayout


#: Where the pinned engine versions and images live. ONE source of truth for
#: what actually runs — a hardcoded image tag in an adapter would drift from the
#: manifest the supply-chain checks verify.
def _default_manifest_path() -> Path:
    """Locate OSINT/tools.manifest.yaml regardless of the working directory.

    This was the bare relative Path("OSINT/tools.manifest.yaml"), resolved
    against the CWD. The failure mode is the dangerous kind: _load() catches
    OSError and returns an empty map, so a wrong CWD does not raise — it
    reports EVERY ENGINE UNAVAILABLE, which reads as a correctly-detected gap
    rather than as a misconfiguration.

    Resolution order matches registry.py, which already did this properly:
      1. $OSINT_MANIFEST, if set
      2. the repo root, found by walking up to the directory holding go.mod
      3. the CWD-relative path, so an unusual layout still has a last resort
    """
    override = os.environ.get("OSINT_MANIFEST", "").strip()
    if override:
        return Path(override)

    here = Path(__file__).resolve()
    for candidate in here.parents:
        if (candidate / "go.mod").exists():
            return candidate / "OSINT" / "tools.manifest.yaml"

    return Path("OSINT/tools.manifest.yaml")


MANIFEST_PATH = _default_manifest_path()


@dataclass
class EngineImage:
    """A resolved container image for one engine."""

    reference: str
    version: str
    #: True when the reference is a digest. A TAG IS MUTABLE, and a mutable
    #: reference in a compliance product means the provenance recorded in a
    #: report may not describe what actually ran.
    digest_pinned: bool = False


class ManifestResolver:
    """Reads pinned images out of the OSINT manifest."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or MANIFEST_PATH
        self._cache: dict[str, EngineImage] | None = None

    def _load(self) -> dict[str, EngineImage]:
        if self._cache is not None:
            return self._cache

        out: dict[str, EngineImage] = {}
        try:
            data = yaml.safe_load(self._path.read_text(encoding="utf-8")) or {}
        except OSError:
            # A missing manifest means every engine reports unavailable, which
            # is recorded and visible — better than a hardcoded fallback that
            # silently runs an unpinned image.
            self._cache = out
            return out

        for entry in data.get("tools", []) or []:
            engine_id = entry.get("id")
            if not engine_id:
                continue
            container = entry.get("container") or {}
            image = container.get("image")
            if not image:
                continue

            # ⚠ DIGEST WINS OVER TAG, ALWAYS.
            #
            # A tag is mutable: the same tag scanned twice can be two different
            # binaries, and a compliance report naming a tag cannot say what
            # actually ran. `toolctl pin` fills image_digest; until it does, the
            # tag is used and `digest_pinned` is False so the gap is visible in
            # Engine Coverage rather than assumed away.
            digest = container.get("image_digest")
            if digest:
                ref = f"{image}@{digest}"
                pinned = True
            else:
                tag = container.get("image_tag") or "latest"
                ref = f"{image}:{tag}"
                pinned = False

            out[engine_id] = EngineImage(
                reference=ref,
                version=str(entry.get("version", "")),
                digest_pinned=pinned,
            )

        self._cache = out
        return out

    def image_for(self, engine_id: str) -> EngineImage | None:
        return self._load().get(engine_id)


#: Patterns that must never reach `argv_redacted`, which is stored, published in
#: the provenance manifest, and rendered in reports.
#:
#: argv is also world-readable in /proc, so a token there is visible to every
#: process on the host — but this redaction is about what we PERSIST.
#: (pattern, replacement) pairs.
#:
#: Each carries its own replacement rather than sharing one, because what should
#: SURVIVE redaction differs: a flag keeps its name, a URL keeps its host and
#: path, and a raw vendor token keeps nothing. A redacted argv that has lost the
#: repository it pointed at cannot be used to diagnose the run it came from,
#: which is the only reason it is stored at all.
_SECRET_PATTERNS = [
    (re.compile(r"(?i)(--?(?:nvd)?api[-_]?key[= ])(\S+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(--?token[= ])(\S+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(--?password[= ])(\S+)"), r"\1[REDACTED]"),
    (re.compile(r"(ghp_|gho_|ghu_|ghs_|glpat-|hvs\.|AKIA)[A-Za-z0-9_\-]{8,}"), "[REDACTED]"),
    # ⚠ CREDENTIALS EMBEDDED IN A URL: https://user:hunter2@host/repo.git
    #
    # The exact shape of a git clone URL carrying a password. It matches no flag
    # name and no vendor prefix, so every pattern above misses it entirely.
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1[REDACTED]@"),
    # Bearer/Basic authorization values. A JWT is dot-separated base64 and
    # carries none of the vendor prefixes above.
    (re.compile(r"(?i)\b(bearer\s+|basic\s+)[A-Za-z0-9._\-+/=]{8,}"), r"\1[REDACTED]"),
]


def redact_argv(argv: list[str]) -> list[str]:
    """Strip anything credential-shaped from an argv before it is stored.

    Redacts by PATTERN as well as by flag name: the mistake this catches is a
    key passed positionally, or under a flag nobody thought to list.
    """
    out: list[str] = []
    redact_next = False

    for arg in argv:
        if redact_next:
            out.append("[REDACTED]")
            redact_next = False
            continue

        # A bare flag whose VALUE is the next argument.
        if re.fullmatch(r"(?i)--?(nvd)?api[-_]?key|--?token|--?password", arg):
            out.append(arg)
            redact_next = True
            continue

        cleaned = arg
        for pattern, replacement in _SECRET_PATTERNS:
            cleaned = pattern.sub(replacement, cleaned)
        out.append(cleaned)

    return out


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class ArtifactWriter:
    """Writes raw engine output to disk, immutably.

    Raw artifacts are COMPLIANCE EVIDENCE (ADR-0003): written once, never
    mutated, and re-parsed rather than re-scanned when a parser bug is fixed.
    """

    output_dir: Path

    def write(
        self, name: str, content: bytes, media_type: str, role: str = "native_output"
    ) -> RawArtifact:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / name

        # Refuse to overwrite. An artifact that changed after the fact is not
        # evidence, and the output prefix already embeds job_id so a retry
        # writes somewhere new.
        if path.exists():
            existing = path.read_bytes()
            if existing != content:
                raise FileExistsError(
                    f"{path} already exists with different content; raw artifacts are immutable"
                )
        else:
            path.write_bytes(content)

        return RawArtifact(
            role=role,
            path=path,
            media_type=media_type,
            sha256=sha256_of(content),
            size_bytes=len(content),
        )


class SandboxedAdapter(ToolAdapterBase):
    """Base for engines that run as a container in the sandbox."""

    #: Media type of this engine's native output.
    media_type = "application/json"
    #: Engines that match vulnerabilities MUST report a dated database.
    requires_db_version = False
    #: Which provisioned database this engine reads, if any. Set on every
    #: engine with ``requires_db_version``; see :mod:`encorebom_shared.enginedb`
    #: for why the two travel together.
    database_id: str | None = None
    #: Where the provisioned database is mounted inside the container.
    database_target = "/enginedb"

    def __init__(
        self,
        capabilities: Capabilities,
        *,
        sandbox: Sandbox | None = None,
        resolver: ManifestResolver | None = None,
        artifact_dir: Path | None = None,
        database_root: Path | None = None,
    ) -> None:
        super().__init__(capabilities)
        self._sandbox = sandbox or Sandbox()
        self._resolver = resolver or ManifestResolver()
        #: Where raw output is written. None means the caller collects it from
        #: the result instead — used by the fixture generator and by tests.
        self._artifact_dir = artifact_dir
        self._database_root = database_root

    def classify_nonzero(self, result: SandboxResult) -> tuple[ResultStatus, str, str] | None:
        """Reclassify an unacceptable exit code, if this engine knows better.

        Returns (status, code, message), or None to accept the default
        `failed` / ENGINE_NONZERO_EXIT. Overridden by engines whose error codes
        are ambiguous — see OSVScannerAdapter.
        """
        _ = result
        return None

    def input_gap(self, target: ScanTarget) -> str | None:
        """Why this engine cannot run against this target, if it cannot.

        Returns None when the engine has everything it needs. Overridden by
        engines that depend on an artefact the fetcher produces — currently
        trivy-image, which needs an exported image tarball because a sandboxed
        container can reach neither the daemon nor a registry.
        """
        _ = target
        return None

    # -- availability -------------------------------------------------------

    def available(self) -> Availability:
        """Report whether this engine can run.

        NEVER raises. An engine that cannot run is `unavailable`, which is
        recorded in Engine Coverage; raising would fail the whole scan and cost
        every other engine's output too.
        """
        image = self._resolver.image_for(self.engine_id)
        if image is None:
            return Availability(
                available=False,
                mode=EngineMode.UNAVAILABLE,
                detail=f"{self.engine_id} has no container image pinned in {MANIFEST_PATH}",
            )

        try:
            self._sandbox.check()
        except Exception as exc:
            return Availability(
                available=False,
                mode=EngineMode.UNAVAILABLE,
                version=image.version,
                detail=f"the sandbox is not usable: {exc}",
            )

        return Availability(
            available=True,
            mode=EngineMode.CONTAINER,
            version=image.version,
            detail="" if image.digest_pinned else "image is tag-pinned, not digest-pinned",
        )

    # -- generation ---------------------------------------------------------

    def build_argv(self, target: ScanTarget, layout: WorkspaceLayout) -> list[str]:
        """Return the command to run. Implemented per engine."""
        raise NotImplementedError

    def entrypoint(self) -> list[str] | None:
        """Override the image's ENTRYPOINT.

        Needed more often than it looks: an image whose entrypoint is the tool
        itself turns an argv of ``["syft", ...]`` into ``syft syft ...``.
        """
        return None

    def limits(self) -> SandboxLimits:
        return SandboxLimits()

    def acceptable_exit_codes(self) -> frozenset[int]:
        """Exit codes that mean the engine did its job.

        ⚠ NOT EVERY ENGINE USES 0 FOR SUCCESS. osv-scanner exits 1 when it FINDS
        VULNERABILITIES — a successful scan of a vulnerable project. Treating
        that as a failure would mark every scan that found something as
        `failed`, so the only scans reported as succeeding would be the ones
        that found nothing.

        That inverts the product: the more vulnerable the project, the cleaner
        the report. It stayed invisible only because the engine had no database
        and so never found anything to exit 1 over.
        """
        return frozenset({0})

    #: File name to publish this engine's native output under, inside the SHARED
    #: per-scan workspace, when another engine consumes it.
    #:
    #: ⚠ THE WORKSPACE, NOT THE OUTPUT DIRECTORY, AND THE DIFFERENCE IS THE BUG.
    #:
    #: Raw artifacts go to <output_root>/<job_id>/, which is per-JOB — grype has
    #: its own job id and cannot know syft's. The workspace is per-SCAN and is
    #: what _build_target reads, so an engine whose output another engine needs
    #: must publish it there. Until it did, grype was `skipped` on every real
    #: scan with ENGINE_INPUT_MISSING while syft's SBOM sat one directory away.
    #:
    #: None means nothing else reads this engine's output.
    workspace_artifact_name: str | None = None

    def artifact_name(self) -> str:
        """File name for this engine's raw output."""
        return f"{self.engine_id}.json"

    # -- the provisioned database ------------------------------------------

    def database(self) -> EngineDatabase | None:
        """The provisioned database this engine will read, if there is one."""
        if not self.database_id:
            return None
        return enginedb_resolve(self.database_id, self._database_root)

    def database_env(self, database: EngineDatabase) -> dict[str, str]:
        """Environment that points the engine at the mounted database.

        Per engine, because every one of them names this differently:
        ``XDG_CACHE_HOME``, ``GRYPE_DB_CACHE_DIR``, ``TRIVY_CACHE_DIR``.
        """
        return {}

    def extra_env(self, layout: WorkspaceLayout) -> dict[str, str]:
        """Environment an engine needs regardless of any database.

        ⚠ THE COMMON CASE IS `TMPDIR`.

        The sandbox gives every engine a READ-ONLY ROOTFS, so `/tmp` does not
        exist to write into. That is deliberate and not negotiable — we execute
        third-party binaries over untrusted user code. Engines that need scratch
        space must be pointed at the writable tmpfs instead, and an engine that
        is not fails with an error that looks nothing like the real cause:

            unable to create temporary directory: read-only file system
        """
        return {}

    def generate(self, target: ScanTarget) -> GenerateResult:
        """Run the engine and produce raw artifacts.

        Never raises. Every failure mode becomes a STATUS plus a diagnostic,
        because an exception here would take down a worker and lose the results
        of every other engine in flight.
        """
        availability = self.available()
        if not availability.available:
            return GenerateResult(
                status=ResultStatus.UNAVAILABLE,
                diagnostics=[
                    {
                        "severity": "warn",
                        "code": "ENGINE_UNAVAILABLE",
                        "message": f"{self.engine_id} did not run: {availability.detail}",
                        "hint": "the scan continues; this appears in Engine Coverage",
                    }
                ],
                engine_version=availability.version,
            )

        image = self._resolver.image_for(self.engine_id)
        if image is None:
            # available() already checked, so reaching here means the manifest
            # changed between the two calls. An explicit branch rather than an
            # assert: asserts are stripped under -O, and this one would then
            # become an attribute error on None deep inside a worker.
            return GenerateResult(
                status=ResultStatus.UNAVAILABLE,
                diagnostics=[
                    {
                        "severity": "error",
                        "code": "ENGINE_UNAVAILABLE",
                        "message": f"{self.engine_id} lost its pinned image between the "
                        f"availability check and the run",
                    }
                ],
            )

        # ⚠ NO REQUIRED INPUT, NO RUN — and `unavailable`, not `failed`.
        #
        # Some engines need something the fetcher must produce first. Letting
        # them start anyway means the engine fails deep inside its own error
        # handling, and what reaches the report is a bare
        # "ENGINE_NONZERO_EXIT: exited 1" that names neither the missing input
        # nor who was supposed to supply it.
        #
        # A stated gap is the useful outcome here: a `failed` engine reads as a
        # defect to debug, while `unavailable` with a reason reads as reduced
        # coverage, which is what it actually is.
        gap = self.input_gap(target)
        if gap is not None:
            return GenerateResult(
                status=ResultStatus.UNAVAILABLE,
                diagnostics=[
                    {
                        "severity": "warn",
                        "code": "ENGINE_INPUT_MISSING",
                        "message": gap,
                        "hint": "the scan continues; this appears in Engine Coverage",
                    }
                ],
                engine_version=availability.version,
            )

        # ⚠ NO DATABASE, NO RUN. CHECKED BEFORE THE CONTAINER STARTS.
        #
        # A vulnerability engine with no database does not fail — it matches
        # against nothing and reports a clean project. osv-scanner does exactly
        # that: it parses every lockfile, finds every package, prints
        # `{"results": []}` and exits 0. No exit code, no stderr line and no
        # output shape separates that from a project with genuinely no known
        # vulnerabilities.
        #
        # So this is not inferred from the run afterwards; the run is refused.
        # Classifying output after the fact would mean deciding whether an empty
        # result was real, and that decision cannot be made correctly. Refusing
        # up front turns the gap into a line in Engine Coverage, which is a
        # reduced-coverage statement rather than a false all-clear.
        database = self.database()
        if self.requires_db_version and database is None:
            return GenerateResult(
                status=ResultStatus.UNAVAILABLE,
                engine_version=availability.version,
                diagnostics=[
                    self.db_stale_diagnostic(
                        f"no provisioned {self.database_id!r} database was found under "
                        f"{database_root(self._database_root)}"
                    ),
                    {
                        "severity": "warn",
                        "code": "ENGINE_DB_NOT_PROVISIONED",
                        "message": (
                            f"{self.engine_id} was not run because it had no vulnerability "
                            f"database to match against"
                        ),
                        "hint": (
                            "provision it with `python -m workers.sbom.dbsync"
                            f" {self.database_id}`; running without one would report zero "
                            "vulnerabilities, which is indistinguishable from a clean project"
                        ),
                    },
                ],
            )

        layout = WorkspaceLayout(source=target.workspace)
        layout.ensure()

        argv = self.build_argv(target, layout)
        redacted = redact_argv(argv)

        mounts = layout.mounts()
        env: dict[str, str] = dict(self.extra_env(layout))
        if database is not None:
            # Read-only, like every mount the sandbox allows. The engine reads
            # the database; only the provisioner writes it.
            mounts = [
                *mounts,
                Mount(source=str(database.path.resolve()), target=self.database_target),
            ]
            env.update(self.database_env(database))

        result = self._sandbox.run(
            image=image.reference,
            argv=argv,
            entrypoint=self.entrypoint(),
            env=env or None,
            mounts=mounts,
            limits=self.limits(),
            labels={"encorebom.engine": self.engine_id, "encorebom.job": target.job_id},
        )

        generated = self.classify(target, result, redacted, image, database)

        # ⚠ THE RAW ARTIFACT IS WRITTEN FOR EVERY OUTCOME THAT PRODUCED OUTPUT,
        # including `partial` and `failed`.
        #
        # Raw output is Phase 8's INPUT and the evidence a report rests on
        # (ADR-0003): normalization is a pure function of it, so a parser bug is
        # fixed by re-parsing rather than re-scanning. Discarding the output of a
        # failed run would make that run undiagnosable — and a partial run's
        # output is real findings that must not be thrown away.
        if self._artifact_dir is not None and result.stdout.strip():
            try:
                writer = ArtifactWriter(output_dir=self._artifact_dir)
                generated.artifacts.append(
                    writer.write(
                        self.artifact_name(),
                        result.stdout.encode("utf-8"),
                        self.media_type,
                    )
                )
            except OSError as exc:
                # The scan is not failed over a storage problem, but the gap is
                # recorded: without the artifact, Phase 8 has nothing to parse.
                generated.diagnostics.append(
                    {
                        "severity": "error",
                        "code": "ARTIFACT_NOT_STORED",
                        "message": f"{self.engine_id} output could not be written: {exc}",
                        "hint": "normalization has no input for this engine",
                    }
                )

        return generated

    # -- classification -----------------------------------------------------

    def classify(
        self,
        target: ScanTarget,
        result: SandboxResult,
        argv_redacted: list[str],
        image: EngineImage,
        database: EngineDatabase | None = None,
    ) -> GenerateResult:
        """Turn a sandbox result into a GenerateResult."""
        base = GenerateResult(
            status=ResultStatus.FAILED,
            engine_version=image.version,
            duration_ms=result.duration_ms,
            exit_code=result.exit_code,
            argv_redacted=argv_redacted,
        )
        # ⚠ THE VINTAGE COMES FROM OUR STAMP, NOT FROM THE ENGINE.
        #
        # An engine reporting its own database version is reporting a claim we
        # cannot check. The stamp was written by the provisioner at download
        # time, so it is the one statement about staleness we can stand behind.
        # An adapter may still overwrite this when the engine emits something
        # more precise — but it starts from evidence, not from a default.
        if database is not None:
            base.engine_db_version = database.describe()

        if result.timed_out:
            base.status = ResultStatus.TIMEOUT
            base.diagnostics.append(
                {
                    "severity": "error",
                    "code": "ENGINE_TIMEOUT",
                    "message": f"{self.engine_id} exceeded its wall clock and was killed",
                    "hint": "the container was removed; raise the limit or narrow the scan",
                }
            )
            return base

        if result.error:
            # The run could not be ATTEMPTED — our misconfiguration, not the
            # engine's verdict. Distinguishing the two is what stops a bad
            # image tag being reported as "this project has no dependencies".
            base.status = ResultStatus.UNAVAILABLE
            base.diagnostics.append(
                {
                    "severity": "error",
                    "code": "ENGINE_UNAVAILABLE",
                    "message": f"{self.engine_id} could not be started: {result.error}",
                }
            )
            return base

        if result.exit_code not in self.acceptable_exit_codes():
            # ⚠ A MISSING VULNERABILITY DATABASE IS `unavailable`, NOT `failed`.
            #
            # A DB-backed engine with no database cannot match anything. Reporting
            # that as `failed` is wrong in a subtle and dangerous way: `failed`
            # invites a retry, and a retry cannot help — the sandbox runs with
            # --network=none, so the database can only arrive by being pre-warmed
            # out of band.
            #
            # Reporting it as `unavailable` puts it in Engine Coverage, where a
            # reader sees that the engine was requested and did not run. What must
            # NEVER happen is an empty result that reads as "no vulnerabilities".
            if self.requires_db_version:
                reason = missing_database_reason(result.stderr)
                if reason:
                    base.status = ResultStatus.UNAVAILABLE
                    base.diagnostics.append(self.db_stale_diagnostic(reason))
                    return base

            # An engine may know that one of its own error codes is not
            # actually an error for this project. osv-scanner's 128 is the
            # case: "no package sources found" covers both a repository that
            # commits no lockfile and a workspace the engine could not read,
            # and those deserve opposite statuses.
            #
            # Only the adapter can tell them apart, and only from the stderr —
            # so the decision is delegated rather than guessed at here. A
            # non-answer falls through to `failed`, which overstates the
            # problem visibly rather than understating it.
            special = self.classify_nonzero(result)
            if special is not None:
                status, code, message = special
                base.status = status
                base.diagnostics.append(
                    {
                        "severity": "error" if status is ResultStatus.FAILED else "warn",
                        "code": code,
                        "message": message,
                        "hint": _tail(result.stderr),
                    }
                )
                return base

            base.status = ResultStatus.FAILED
            base.diagnostics.append(
                {
                    "severity": "error",
                    "code": "ENGINE_NONZERO_EXIT",
                    "message": f"{self.engine_id} exited {result.exit_code}",
                    "hint": _tail(result.stderr),
                }
            )
            return base

        payload = self.parse_stdout(result.stdout)
        if payload is None:
            base.status = ResultStatus.FAILED
            base.diagnostics.append(
                {
                    "severity": "error",
                    "code": "ENGINE_OUTPUT_UNPARSEABLE",
                    "message": f"{self.engine_id} exited 0 but its output was not valid JSON",
                    "hint": _tail(result.stdout),
                }
            )
            return base

        return self.interpret(target, payload, result, base)

    def parse_stdout(self, stdout: str) -> Any | None:
        """Parse the engine's stdout, defensively.

        Returns None rather than raising: a tool that changes its output shape
        must degrade to reduced coverage LOUDLY, not crash a worker.
        """
        text = stdout.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Some tools print a banner before the JSON. Recover the document
            # rather than discarding a whole scan over a log line.
            start = text.find("{")
            if start > 0:
                try:
                    return json.loads(text[start:])
                except json.JSONDecodeError:
                    return None
            return None

    def interpret(
        self,
        target: ScanTarget,
        payload: Any,
        result: SandboxResult,
        base: GenerateResult,
    ) -> GenerateResult:
        """Turn parsed output into a status, per engine."""
        raise NotImplementedError

    # -- shared helpers -----------------------------------------------------

    def zero_result_diagnostic(self, what: str) -> dict[str, Any]:
        """⚠ ZERO IS A CLAIM, AND IT NEEDS TO BE AN EXPLICIT ONE.

        An engine that found nothing and reports `succeeded` renders as a clean
        report — indistinguishable from a real empty project. `partial` plus
        this diagnostic makes the claim visible so a reader can judge it.
        """
        return {
            "severity": "warn",
            "code": "ENGINE_ZERO_RESULTS",
            "message": f"{self.engine_id} found no {what}",
            "hint": (
                "reported as partial rather than succeeded: zero is a claim, and a "
                "silent zero is indistinguishable from a project with no dependencies"
            ),
        }

    def db_stale_diagnostic(self, detail: str) -> dict[str, Any]:
        """A vulnerability database too old or too new for the pinned binary.

        Marked UNAVAILABLE rather than emitting stale matches: reduced coverage
        stated plainly beats confident wrongness in a compliance document.
        """
        return {
            "severity": "error",
            "code": "ENGINE_DB_STALE",
            "message": f"{self.engine_id}'s vulnerability database is unusable: {detail}",
            "hint": "marked unavailable rather than emitting stale matches",
        }


#: Phrases that mean "this engine has no usable vulnerability database".
#:
#: Matched on TEXT because none of these tools give the condition a distinct
#: exit code. Fragile against upstream rewording, which is why a miss degrades
#: to `failed` — visible and retried — rather than to a silent empty result.
_MISSING_DB_MARKERS = [
    "database does not exist",
    "failed to load vulnerability db",
    "cannot be specified on the first run",
    "no such file or directory: /root/.cache/trivy",
    "db file not found",
    "unable to load vulnerability database",
    "vulnerability database is not initialized",
]


def missing_database_reason(stderr: str) -> str:
    """Return why the vulnerability database is unusable, or "" if it is fine.

    The distinction this draws is the whole point: an engine that COULD NOT
    MATCH is different from an engine that MATCHED NOTHING, and only the second
    means the project is clean.
    """
    lowered = stderr.lower()
    for marker in _MISSING_DB_MARKERS:
        if marker in lowered:
            return (
                f"no vulnerability database is present ({marker!r}); the sandbox runs "
                "with --network=none, so the database must be pre-warmed out of band"
            )
    return ""


def _tail(text: str, limit: int = 400) -> str:
    """Bound engine output before it reaches a diagnostic.

    Scanner output is attacker-influenced — it can contain repository content —
    and a diagnostic ends up in a database column, a log and a UI.
    """
    cleaned = text.strip().replace("\n", " ").replace("\r", " ")
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[-limit:]


def ecosystems_from_purls(purls: list[str]) -> list[str]:
    """Extract ecosystems from a list of PURLs.

    Feeds `scan.ecosystems_detected`, whose gap rows are the honest denominator
    of the Engine Coverage section.
    """
    out: set[str] = set()
    for purl in purls:
        if not purl.startswith("pkg:"):
            continue
        rest = purl[4:]
        ecosystem = rest.split("/", 1)[0].split("@", 1)[0]
        if ecosystem:
            out.add(ecosystem.lower())
    return sorted(out)
