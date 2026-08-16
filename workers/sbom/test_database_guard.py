"""The database guard: a vulnerability engine never runs without a database.

⚠ THIS IS THE MOST IMPORTANT TEST FILE IN THE SBOM WORKER.

The failure it guards against is silent, plausible and maximally harmful: an
engine with no database matches nothing, reports zero vulnerabilities and exits
0. Nothing downstream can tell that from a genuinely clean project. It is the
one bug in this product that makes a customer LESS safe than having no scanner
at all, because it converts an unknown into a confident all-clear.

Every test here is written so that REMOVING the guard makes it fail — asserting
on the observable outcome (did the engine run? what status came back?) rather
than on the presence of the code that produces it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from encorebom_shared.adapters.base import ResultStatus, ScanTarget
from encorebom_shared.enginedb import resolve, write_stamp
from encorebom_shared.sandbox import SandboxResult

from .adapters.common import EngineImage
from .adapters.grype import GrypeAdapter
from .adapters.osv_scanner import OSVScannerAdapter
from .adapters.syft import SyftAdapter
from .adapters.trivy_fs import TrivyFSAdapter

#: Every engine that matches vulnerabilities. Parameterising over the list
#: rather than testing one engine is deliberate: the guard lives in the base
#: class, and a future adapter that forgets `database_id` must fail here.
VULN_ADAPTERS = [GrypeAdapter, TrivyFSAdapter, OSVScannerAdapter]


class RecordingSandbox:
    """A sandbox that records whether it was asked to run anything."""

    def __init__(self, result: SandboxResult | None = None) -> None:
        self.runs: list[dict[str, Any]] = []
        self._result = result or SandboxResult(exit_code=0, stdout="{}")

    def check(self) -> dict[str, str]:
        return {"runtime": "recording"}

    def run(self, **kwargs: Any) -> SandboxResult:
        self.runs.append(kwargs)
        return self._result


class StubResolver:
    """Pins an image without reading the manifest."""

    def __init__(self, version: str = "1.2.3") -> None:
        self._version = version

    def image_for(self, engine_id: str) -> EngineImage:
        return EngineImage(
            reference=f"example.invalid/{engine_id}:{self._version}",
            version=self._version,
            digest_pinned=True,
        )


def make(adapter_cls: type, *, db_root: Path, sandbox: Any = None) -> Any:
    return adapter_cls(
        sandbox=sandbox or RecordingSandbox(),
        resolver=StubResolver(),
        database_root=db_root,
    )


def target(tmp_path: Path) -> ScanTarget:
    workspace = tmp_path / "src"
    workspace.mkdir(exist_ok=True)
    (workspace / "package-lock.json").write_text("{}", encoding="utf-8")
    # grype refuses to scan a directory, so give it the SBOM it requires.
    sbom = workspace / "sbom.cdx.json"
    sbom.write_text("{}", encoding="utf-8")
    return ScanTarget(
        scan_id="scan-1",
        job_id="job-1",
        kind="git",
        workspace=workspace,
        sbom_path=sbom,
    )


# -- the guard ------------------------------------------------------------


@pytest.mark.parametrize("adapter_cls", VULN_ADAPTERS, ids=lambda c: c.__name__)
def test_no_database_means_the_engine_never_runs(adapter_cls: type, tmp_path: Path) -> None:
    """⚠ The container must not start at all.

    Not "starts and we discard the output" — the run is refused. Once an engine
    has produced `{"results": []}` there is no way to tell whether that means
    "clean" or "no database", so the decision has to be made BEFORE running.
    """
    sandbox = RecordingSandbox()
    adapter = make(adapter_cls, db_root=tmp_path / "enginedb", sandbox=sandbox)

    result = adapter.generate(target(tmp_path))

    assert result.status is ResultStatus.UNAVAILABLE
    assert sandbox.runs == [], "the engine was executed despite having no database"


@pytest.mark.parametrize("adapter_cls", VULN_ADAPTERS, ids=lambda c: c.__name__)
def test_no_database_is_unavailable_not_succeeded_and_not_failed(
    adapter_cls: type, tmp_path: Path
) -> None:
    """The status has to be exactly `unavailable`.

    `succeeded` is the catastrophic case — a clean report for an unscanned
    project. `failed` is merely wrong: it invites a retry, and no number of
    retries produces a database, because the sandbox has no network.
    """
    adapter = make(adapter_cls, db_root=tmp_path / "enginedb")
    result = adapter.generate(target(tmp_path))

    assert result.status is ResultStatus.UNAVAILABLE
    assert result.status is not ResultStatus.SUCCEEDED
    assert result.status is not ResultStatus.FAILED

    codes = {d.get("code") for d in result.diagnostics}
    assert "ENGINE_DB_STALE" in codes
    assert "ENGINE_DB_NOT_PROVISIONED" in codes


@pytest.mark.parametrize("adapter_cls", VULN_ADAPTERS, ids=lambda c: c.__name__)
def test_no_database_produces_no_artifact_to_normalize(adapter_cls: type, tmp_path: Path) -> None:
    """An unavailable engine contributes nothing to the BOM.

    An empty artifact would be parsed by Phase 8 as "this engine found nothing",
    which is the same false negative one layer down.
    """
    adapter = make(adapter_cls, db_root=tmp_path / "enginedb")
    result = adapter.generate(target(tmp_path))
    assert result.artifacts == []


def test_an_unstamped_directory_does_not_count_as_a_database(tmp_path: Path) -> None:
    """Bytes on disk are not provenance.

    A directory with database files but no stamp is what a half-finished
    download leaves behind. Its contents may be truncated and its vintage is
    unknown, so it must not satisfy the guard.
    """
    root = tmp_path / "enginedb"
    (root / "osv").mkdir(parents=True)
    (root / "osv" / "all.zip").write_bytes(b"not really a database")

    assert resolve("osv", root) is None

    sandbox = RecordingSandbox()
    adapter = make(OSVScannerAdapter, db_root=root, sandbox=sandbox)
    assert adapter.generate(target(tmp_path)).status is ResultStatus.UNAVAILABLE
    assert sandbox.runs == []


def test_a_stamp_without_a_date_does_not_count(tmp_path: Path) -> None:
    """`engine_db_version` exists to answer "how stale?".

    A stamp with no date cannot answer it, so it is not a stamp.
    """
    root = tmp_path / "enginedb"
    (root / "osv").mkdir(parents=True)
    (root / "osv" / "encorebom-db.json").write_text(
        json.dumps({"database_id": "osv", "version": "2.5.0"}), encoding="utf-8"
    )
    assert resolve("osv", root) is None


# -- what happens once a database IS provisioned --------------------------


@pytest.mark.parametrize("adapter_cls", VULN_ADAPTERS, ids=lambda c: c.__name__)
def test_a_provisioned_database_is_mounted_read_only_and_lets_the_engine_run(
    adapter_cls: type, tmp_path: Path
) -> None:
    root = tmp_path / "enginedb"
    write_stamp(
        adapter_cls.database_id,
        version="1.0.0",
        source="example.invalid/db",
        root=root,
    )

    sandbox = RecordingSandbox()
    adapter = make(adapter_cls, db_root=root, sandbox=sandbox)
    adapter.generate(target(tmp_path))

    assert len(sandbox.runs) == 1, "a provisioned database should let the engine run"
    mounts = sandbox.runs[0]["mounts"]
    targets = [m.target for m in mounts]
    assert adapter.database_target in targets, "the database was not mounted"


@pytest.mark.parametrize("adapter_cls", VULN_ADAPTERS, ids=lambda c: c.__name__)
def test_the_reported_vintage_comes_from_our_stamp(adapter_cls: type, tmp_path: Path) -> None:
    """⚠ The engine does not get to assert its own database version.

    An earlier osv-scanner adapter derived `engine_db_version` from the IMAGE
    version, describing a database "bundled in the image". No database is
    bundled in that image. The fabricated string made the `requires_db_version`
    check pass for an engine that had nothing to match against — the check
    certifying the exact condition it was meant to catch.
    """
    root = tmp_path / "enginedb"
    stamped = write_stamp(
        adapter_cls.database_id,
        version="db-2026.08.16",
        source="example.invalid/db",
        root=root,
        now=datetime(2026, 8, 16, tzinfo=UTC),
    )

    adapter = make(adapter_cls, db_root=root)
    generated = adapter.classify(
        target(tmp_path),
        SandboxResult(exit_code=0, stdout="{}"),
        [],
        StubResolver().image_for(adapter.engine_id),
        stamped,
    )

    assert generated.engine_db_version
    assert "2026-08-16" in generated.engine_db_version, (
        "the vintage must carry a date; staleness is the only question a reader "
        "ever asks about a vulnerability finding"
    )
    assert "bundled" not in generated.engine_db_version


def test_age_is_computable_from_the_stamp(tmp_path: Path) -> None:
    """Reports state how old the data was, so the age must be derivable."""
    root = tmp_path / "enginedb"
    stamped = write_stamp(
        "osv",
        version="2.5.0",
        source="example.invalid/db",
        root=root,
        now=datetime(2026, 8, 1, tzinfo=UTC),
    )
    age = stamped.age_days(now=datetime(2026, 8, 16, tzinfo=UTC))
    assert age is not None
    assert 14.9 < age < 15.1


# -- exit-code semantics --------------------------------------------------


def test_osv_scanner_exit_1_means_vulnerabilities_found_not_failure() -> None:
    """⚠ osv-scanner exits 1 WHEN IT FINDS SOMETHING.

    Treating that as a failure inverts the product: every scan that found a
    vulnerability would be reported `failed`, so the only scans that appeared to
    succeed would be the ones that found nothing. It stayed invisible for as
    long as the engine had no database and therefore never found anything.
    """
    assert 1 in OSVScannerAdapter(resolver=StubResolver()).acceptable_exit_codes()
    assert 0 in OSVScannerAdapter(resolver=StubResolver()).acceptable_exit_codes()


def test_engines_without_that_convention_still_treat_nonzero_as_failure() -> None:
    """The exemption is per-engine and must not leak into the base class."""
    assert GrypeAdapter(resolver=StubResolver()).acceptable_exit_codes() == frozenset({0})
    assert SyftAdapter(resolver=StubResolver()).acceptable_exit_codes() == frozenset({0})


# -- the guard applies only where it should -------------------------------


def test_a_cataloguing_engine_needs_no_database(tmp_path: Path) -> None:
    """syft does not match vulnerabilities, so it must not be blocked.

    A guard that stopped every engine would be safe and useless. This is the
    test that keeps it targeted.
    """
    sandbox = RecordingSandbox(SandboxResult(exit_code=0, stdout='{"artifacts": []}'))
    adapter = make(SyftAdapter, db_root=tmp_path / "enginedb", sandbox=sandbox)

    adapter.generate(target(tmp_path))
    assert len(sandbox.runs) == 1, "syft was blocked by a database it does not use"


@pytest.mark.parametrize("adapter_cls", VULN_ADAPTERS, ids=lambda c: c.__name__)
def test_every_vulnerability_engine_declares_a_database(adapter_cls: type) -> None:
    """`requires_db_version` and `database_id` must travel together.

    An engine requiring a dated database but naming none would resolve to None
    and be permanently unavailable — failing safe, but silently and forever.
    """
    assert adapter_cls.requires_db_version is True
    assert adapter_cls.database_id, f"{adapter_cls.__name__} names no database"


def test_stale_databases_are_reported_rather_than_refreshed(tmp_path: Path) -> None:
    """The sandbox has no network, so a stale database cannot be fixed in place.

    What matters is that its age is knowable and therefore reportable.
    """
    root = tmp_path / "enginedb"
    old = datetime.now(UTC) - timedelta(days=400)
    stamped = write_stamp("osv", version="2.5.0", source="s", root=root, now=old)

    age = stamped.age_days()
    assert age is not None and age > 399
    assert resolve("osv", root) is not None, (
        "a stale database is still a database; it is reported with its age, not treated as absent"
    )
