"""How each outcome of an engine run is classified.

⚠ THE CLASSIFICATION IS THE PRODUCT.

Running a scanner is easy. Deciding what its output MEANS is where a BOM
platform is right or wrong, because most of the interesting outcomes are not
"succeeded" or "failed":

    zero components        might be an empty project, or a parser that failed
    a non-zero exit        might be a crash, or "I found vulnerabilities"
    a missing database     looks exactly like a clean project
    one broken manifest    must not discard eleven good ecosystems

Each test here pins one of those distinctions. They are written against
observable status and diagnostics, so removing the code that draws the
distinction makes them fail.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from axebom_shared.adapters.base import ResultStatus, ScanTarget
from axebom_shared.sandbox import SandboxResult

from .adapters.common import (
    EngineImage,
    ecosystems_from_purls,
    missing_database_reason,
    redact_argv,
)
from .adapters.syft import SyftAdapter
from .adapters.trivy_fs import TrivyFSAdapter, partial_ecosystems


class StubResolver:
    def image_for(self, engine_id: str) -> EngineImage:
        return EngineImage(
            reference=f"example.invalid/{engine_id}:1.0.0",
            version="1.0.0",
            digest_pinned=True,
        )


IMAGE = StubResolver().image_for("syft")


def target(tmp_path: Path) -> ScanTarget:
    ws = tmp_path / "src"
    ws.mkdir(exist_ok=True)
    return ScanTarget(scan_id="s", job_id="j", kind="git", workspace=ws)


def syft() -> SyftAdapter:
    return SyftAdapter(resolver=StubResolver())


# -- zero is a claim ------------------------------------------------------


def test_zero_components_is_partial_not_succeeded(tmp_path: Path) -> None:
    """⚠ A clean report and an unscanned project must not look identical.

    `succeeded` with no components renders as "this project has no
    dependencies". That is occasionally true and usually means the parser found
    nothing it understood. `partial` forces the claim to be visible.
    """
    result = syft().classify(
        target(tmp_path),
        SandboxResult(exit_code=0, stdout='{"components": []}'),
        [],
        IMAGE,
    )
    assert result.status is ResultStatus.PARTIAL
    assert result.status is not ResultStatus.SUCCEEDED
    assert any(d.get("code") == "ENGINE_ZERO_RESULTS" for d in result.diagnostics)


def test_components_found_is_succeeded(tmp_path: Path) -> None:
    """The distinction is only meaningful if the normal case still passes."""
    # syft is configured to emit CycloneDX, so the key is `components`.
    stdout = (
        '{"components": [{"name": "lodash", "version": "4.17.21", '
        '"purl": "pkg:npm/lodash@4.17.21"}]}'
    )
    result = syft().classify(target(tmp_path), SandboxResult(exit_code=0, stdout=stdout), [], IMAGE)
    assert result.status is ResultStatus.SUCCEEDED
    assert result.ecosystems_covered == ["npm"]


# -- failure modes are distinguished --------------------------------------


def test_a_missing_components_key_is_a_shape_change_not_a_crash(tmp_path: Path) -> None:
    """An output shape that changed upstream must be reported, not guessed at.

    Treated as zero components AND flagged: silently defaulting to zero is how
    a tool upgrade turns every scan into a clean report.
    """
    result = syft().classify(target(tmp_path), SandboxResult(exit_code=0, stdout="{}"), [], IMAGE)
    assert result.status is ResultStatus.PARTIAL
    assert any(d.get("code") == "ENGINE_FIELD_MISSING" for d in result.diagnostics)


def test_a_timeout_is_timeout_not_failed(tmp_path: Path) -> None:
    """A timeout is retryable; a crash is not. Conflating them either burns
    delivery attempts or drops work that would have succeeded."""
    result = syft().classify(
        target(tmp_path),
        SandboxResult(exit_code=-1, timed_out=True),
        [],
        IMAGE,
    )
    assert result.status is ResultStatus.TIMEOUT
    assert any(d.get("code") == "ENGINE_TIMEOUT" for d in result.diagnostics)


def test_a_run_that_could_not_start_is_unavailable_not_failed(tmp_path: Path) -> None:
    """⚠ Our misconfiguration must not be reported as the engine's verdict.

    A bad image tag reported as `failed` reads, downstream, as "this engine ran
    and found nothing".
    """
    result = syft().classify(
        target(tmp_path),
        SandboxResult(exit_code=-1, error="no such image"),
        [],
        IMAGE,
    )
    assert result.status is ResultStatus.UNAVAILABLE
    assert any(d.get("code") == "ENGINE_UNAVAILABLE" for d in result.diagnostics)


def test_exit_zero_with_unparseable_output_is_failed(tmp_path: Path) -> None:
    """Silence dressed as success. A truncated document is not zero findings."""
    result = syft().classify(
        target(tmp_path),
        SandboxResult(exit_code=0, stdout="{not json at all"),
        [],
        IMAGE,
    )
    assert result.status is ResultStatus.FAILED
    assert any(d.get("code") == "ENGINE_OUTPUT_UNPARSEABLE" for d in result.diagnostics)


def test_a_nonzero_exit_is_failed_with_the_stderr_tail(tmp_path: Path) -> None:
    result = syft().classify(
        target(tmp_path),
        SandboxResult(exit_code=2, stdout="", stderr="something went wrong"),
        [],
        IMAGE,
    )
    assert result.status is ResultStatus.FAILED
    diag = next(d for d in result.diagnostics if d.get("code") == "ENGINE_NONZERO_EXIT")
    assert "something went wrong" in diag["hint"]


# -- one broken ecosystem must not discard the others ---------------------


def test_a_malformed_manifest_is_partial_naming_the_ecosystem() -> None:
    """⚠ One bad pom.xml among four ecosystems is `partial`, not `failed`.

    Failing the run would throw away three good ecosystems' findings to report
    one parse error — and the customer would see nothing at all rather than
    most of the truth plus a named gap.
    """
    stderr = (
        "2026-08-16T00:00:00Z\tWARN\tFailed to parse pom.xml: unexpected EOF\n"
        "2026-08-16T00:00:01Z\tINFO\tNumber of language-specific files: 3\n"
    )
    found = partial_ecosystems(stderr)
    assert "maven" in found, "a skipped ecosystem must be named, not merely counted"


def test_a_clean_run_reports_no_partial_ecosystems() -> None:
    """The warning only means something if it is absent when things are fine."""
    assert partial_ecosystems("INFO Number of language-specific files: 3") == {}


def test_trivy_partial_status_when_an_ecosystem_was_skipped(tmp_path: Path) -> None:
    adapter = TrivyFSAdapter(resolver=StubResolver())
    payload = {
        "metadata": {"properties": [{"name": "trivy:DBUpdatedAt", "value": "2026-08-15"}]},
        "components": [{"purl": "pkg:npm/lodash@4.17.21", "name": "lodash"}],
    }
    base = adapter.classify(
        target(tmp_path),
        SandboxResult(exit_code=0, stdout="{}", stderr="WARN Failed to parse pom.xml"),
        [],
        IMAGE,
    )
    result = adapter.interpret(
        target(tmp_path),
        payload,
        SandboxResult(exit_code=0, stdout="{}", stderr="WARN Failed to parse pom.xml"),
        base,
    )
    assert result.status is ResultStatus.PARTIAL
    assert any(d.get("code") == "ENGINE_PARTIAL_ECOSYSTEM" for d in result.diagnostics)


# -- database detection ---------------------------------------------------


@pytest.mark.parametrize(
    "stderr",
    [
        "ERROR failed to load vulnerability db: database does not exist",
        "FATAL --skip-db-update cannot be specified on the first run",
        "unable to load vulnerability database",
    ],
)
def test_missing_database_messages_are_recognised(stderr: str) -> None:
    assert missing_database_reason(stderr) != ""


def test_an_ordinary_error_is_not_mistaken_for_a_missing_database() -> None:
    """Over-matching would convert real crashes into `unavailable`, which is
    not retried — quietly dropping work that a retry would have completed."""
    assert missing_database_reason("panic: runtime error: index out of range") == ""


def test_quiet_flags_must_not_hide_the_reason_a_run_failed() -> None:
    """⚠ grype's -q suppressed the stderr line naming a missing database.

    With it, a missing database was indistinguishable from a crash and was
    reported `failed` instead of `unavailable`. The flag is gone; this pins it.
    """
    from .adapters.grype import GrypeAdapter

    adapter = GrypeAdapter(resolver=StubResolver())
    tgt = ScanTarget(
        scan_id="s", job_id="j", kind="git", workspace=Path(), sbom_path=Path("sbom.cdx.json")
    )

    class Layout:
        container_source = "/src"
        container_scratch = "/workspace"

    argv = adapter.build_argv(tgt, Layout())  # type: ignore[arg-type]
    assert "-q" not in argv and "--quiet" not in argv


# -- redaction ------------------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [
        "ghp_deadbeefdeadbeefdeadbeefdeadbeef",
        "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
        "https://user:hunter2@example.invalid/repo.git",
    ],
)
def test_secrets_are_redacted_from_argv(secret: str) -> None:
    """argv is world-readable in /proc and is persisted in the manifest."""
    redacted = " ".join(redact_argv(["engine", "--flag", secret]))
    assert "hunter2" not in redacted
    assert "deadbeef" not in redacted
    assert "eyJhbGciOiJIUzI1NiJ9" not in redacted


def test_redaction_keeps_the_command_legible() -> None:
    """A fully redacted argv would be useless for diagnosing a bad invocation."""
    redacted = redact_argv(["syft", "dir:/src", "-o", "cyclonedx-json"])
    assert redacted == ["syft", "dir:/src", "-o", "cyclonedx-json"]


# -- ecosystem extraction -------------------------------------------------


def test_ecosystems_come_from_purl_type_not_from_the_name() -> None:
    """⚠ npm/lodash and maven/lodash are different components.

    Deriving the ecosystem from anything but the PURL type is how they get
    merged — the most common dedup bug in SBOM tooling.
    """
    assert ecosystems_from_purls(["pkg:npm/lodash@4.17.21", "pkg:maven/org.apache/lodash@1.0"]) == [
        "maven",
        "npm",
    ]


def test_malformed_purls_are_skipped_not_guessed() -> None:
    assert ecosystems_from_purls(["lodash@4.17.21", "", "not-a-purl"]) == []


def test_scoped_npm_names_do_not_break_ecosystem_extraction() -> None:
    assert ecosystems_from_purls(["pkg:npm/%40acme/api@2.1.0"]) == ["npm"]


# -- osv-scanner must prove it matched against something ------------------


def test_osv_reports_which_databases_it_opened() -> None:
    from .adapters.osv_scanner import loaded_local_databases

    stderr = (
        "Loaded npm local db from /enginedb/osv-scalibr/npm/all.zip\n"
        "Loaded PyPI local db from /enginedb/osv-scalibr/PyPI/all.zip\n"
    )
    assert loaded_local_databases(stderr) == {"npm", "pypi"}


def test_osv_that_scanned_packages_but_opened_no_database_is_unavailable(
    tmp_path: Path,
) -> None:
    """⚠ THE FLAG THAT LOOKED RIGHT AND SILENTLY DID NOTHING.

    `--offline-vulnerabilities` is documented as using already-cached local
    databases. With a fully populated cache mounted it loaded none of them,
    matched nothing, printed `{"results": []}` and exited 0 — a clean bill of
    health for an unchecked project. `--offline` on the same mount returns real
    findings.

    The provisioning guard cannot catch this: the database WAS present and
    mounted. Only the engine's own account of what it opened can.
    """
    from .adapters.osv_scanner import OSVScannerAdapter

    adapter = OSVScannerAdapter(resolver=StubResolver())
    stderr = "Scanned /src/package-lock.json file and found 2 packages\n"
    sandbox_result = SandboxResult(exit_code=0, stdout='{"results": []}', stderr=stderr)

    base = adapter.classify(target(tmp_path), sandbox_result, [], IMAGE)
    result = adapter.interpret(target(tmp_path), {"results": []}, sandbox_result, base)

    assert result.status is ResultStatus.UNAVAILABLE
    assert result.status is not ResultStatus.SUCCEEDED
    assert any(d.get("code") == "ENGINE_DB_STALE" for d in result.diagnostics)


def test_osv_with_no_packages_at_all_is_not_a_database_problem(tmp_path: Path) -> None:
    """A tree with nothing to scan is legitimately empty.

    Reporting that as a database failure would cry wolf on every project with
    no lockfiles, and a warning that fires constantly stops being read.
    """
    from .adapters.osv_scanner import OSVScannerAdapter

    adapter = OSVScannerAdapter(resolver=StubResolver())
    sandbox_result = SandboxResult(exit_code=0, stdout='{"results": []}', stderr="0 dirs visited\n")

    base = adapter.classify(target(tmp_path), sandbox_result, [], IMAGE)
    base.engine_db_version = "osv 2.5.0 provisioned 2026-08-16T20:40:07Z"
    result = adapter.interpret(target(tmp_path), {"results": []}, sandbox_result, base)

    assert result.status is ResultStatus.SUCCEEDED


def test_osv_uses_the_full_offline_flag(tmp_path: Path) -> None:
    """Pins the flag itself: the wrong one produces silent false negatives."""
    from .adapters.osv_scanner import OSVScannerAdapter

    class Layout:
        container_source = "/src"
        container_scratch = "/workspace"

    argv = OSVScannerAdapter(resolver=StubResolver()).build_argv(
        target(tmp_path),
        Layout(),  # type: ignore[arg-type]
    )
    assert "--offline" in argv
    assert "--offline-vulnerabilities" not in argv
    assert "-r" in argv, "without -r only one directory is visited"
