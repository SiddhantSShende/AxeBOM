"""When an engine ran, not just how long it took.

⚠ THE BUG THIS PINS: `invocation.started_at` AND `finished_at` WERE NEVER SENT.

The worker built the invocation block with argv, exit code and duration and
nothing else, so `scan.engine_runs.started_at` and `finished_at` were NULL on
every run ever recorded. `GET /v1/scans/{id}` rendered `null` for both. A report
could say an engine took 41 seconds and never say when — and "matched against
vulnerability data as of X" is only half of a datable result if nobody knows
when the matching happened.

⚠ AND THE INVARIANT THAT MAKES THEM WORTH SENDING.

started_at, finished_at and duration_ms describe ONE interval. The sandbox
measures the container; the worker measures the whole job, which is wider. Take
the duration from one and the timestamps from the other and
`finished - started != duration_ms` — at which point a reader cannot verify any
of the three, and provenance that cannot be checked is not provenance.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from axebom_shared.adapters.base import ResultStatus
from axebom_shared.sandbox import SandboxResult

from . import runner as runner_mod
from .runner import SBOMWorker
from .test_runner import FakeSandbox, job


def worker(tmp_path: Path, sandbox: Any = None) -> SBOMWorker:
    return SBOMWorker(
        workspace_root=tmp_path / "ws",
        output_root=tmp_path / "out",
        sandbox=sandbox or FakeSandbox(),
    )


@pytest.fixture(autouse=True)
def _no_source(monkeypatch: pytest.MonkeyPatch) -> None:
    """These tests are about clocks, not about fetching."""
    monkeypatch.setattr(runner_mod.source, "materialize", lambda *a, **k: False)


def parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


# ---------------------------------------------------------------------------
# The fields exist at all
# ---------------------------------------------------------------------------


def test_the_envelope_says_when_the_engine_ran(tmp_path: Path) -> None:
    before = datetime.now(UTC)
    result = worker(tmp_path).handle(job("syft", scan_id="s1", job_id="j1"))
    after = datetime.now(UTC)

    inv = result["invocation"]
    assert "started_at" in inv, (
        "the invocation block has no started_at; every engine run would record "
        "NULL and a report could not say when the scan happened"
    )
    assert "finished_at" in inv

    started, finished = parse(inv["started_at"]), parse(inv["finished_at"])

    # The published stamps are truncated to whole milliseconds, matching
    # duration_ms's resolution, so a stamp can round up to 1ms before `before`.
    slack = timedelta(milliseconds=1)
    assert before - slack <= started <= finished <= after + slack, (
        f"the stamps fall outside the call: {started} .. {finished}"
    )


@pytest.mark.parametrize("field", ["started_at", "finished_at"])
def test_the_timestamps_are_utc_with_a_literal_z(tmp_path: Path, field: str) -> None:
    """CLAUDE.md §Conventions: UTC, RFC3339, literal Z. No local time, ever.

    Python renders UTC as `+00:00`, which Go parses happily — so this would
    never fail a round trip, and would quietly leave the stored provenance
    formatted two different ways for a human to reconcile by eye.
    """
    result = worker(tmp_path).handle(job("syft", scan_id="s2", job_id="j2"))
    value = result["invocation"][field]

    assert value.endswith("Z"), f"{field} = {value!r}, want a literal Z"
    assert "+00:00" not in value
    assert parse(value).utcoffset() == timedelta(0)


# ---------------------------------------------------------------------------
# ⚠ The reconciliation invariant
# ---------------------------------------------------------------------------


def test_finished_minus_started_equals_the_duration(tmp_path: Path) -> None:
    """All three describe one interval, or none of them can be trusted."""
    result = worker(tmp_path).handle(job("syft", scan_id="s3", job_id="j3"))
    inv = result["invocation"]

    elapsed_ms = (parse(inv["finished_at"]) - parse(inv["started_at"])).total_seconds() * 1000

    # The envelope rounds to whole milliseconds, so allow a millisecond of slack
    # and nothing more: a disagreement larger than that means two clocks.
    assert abs(elapsed_ms - inv["duration_ms"]) <= 2, (
        f"finished - started is {elapsed_ms:.1f}ms but duration_ms is "
        f"{inv['duration_ms']}ms — these came from different intervals"
    )


def test_the_sandbox_clock_wins_over_the_workers(tmp_path: Path) -> None:
    """⚠ THE SANDBOX'S INTERVAL IS THE NARROWER, TRUER ONE.

    The worker's clock brackets image resolution, the database check and
    artifact persistence as well as the container. When the sandbox reported
    the run, its stamps are what reach the envelope — and the duration must
    come from the same place, which is the whole point.
    """
    started = datetime(2026, 8, 23, 12, 0, 0, tzinfo=UTC)
    finished = started + timedelta(milliseconds=41211)

    sandbox = FakeSandbox(
        SandboxResult(
            exit_code=0,
            stdout='{"components": [{"type": "library", "name": "x", "purl": "pkg:npm/x@1"}]}',
            started_at=started,
            finished_at=finished,
            duration_ms=41211,
        )
    )
    result = worker(tmp_path, sandbox).handle(job("syft", scan_id="s4", job_id="j4"))
    inv = result["invocation"]

    assert parse(inv["started_at"]) == started, (
        "the worker's own clock overwrote the sandbox's; the published interval "
        "is now wider than the run it claims to describe"
    )
    assert parse(inv["finished_at"]) == finished
    assert inv["duration_ms"] == 41211


def test_a_sandbox_that_reported_no_clock_falls_back_on_all_three(tmp_path: Path) -> None:
    """An older bridge sends no timestamps. Fall back TOGETHER, never partly.

    Keeping the sandbox's duration next to the worker's timestamps would break
    the reconciliation above while looking entirely reasonable in the code.
    """
    sandbox = FakeSandbox(SandboxResult(exit_code=0, stdout='{"components": []}', duration_ms=999))
    result = worker(tmp_path, sandbox).handle(job("syft", scan_id="s5", job_id="j5"))
    inv = result["invocation"]

    elapsed_ms = (parse(inv["finished_at"]) - parse(inv["started_at"])).total_seconds() * 1000
    assert abs(elapsed_ms - inv["duration_ms"]) <= 2
    assert inv["duration_ms"] != 999, (
        "the stale sandbox duration survived next to worker timestamps"
    )


# ---------------------------------------------------------------------------
# A run that never happened has no time
# ---------------------------------------------------------------------------


def test_an_engine_that_was_never_invoked_reports_no_timestamps(tmp_path: Path) -> None:
    """⚠ OMITTED, NOT ZEROED.

    Go decodes a missing time to the zero value and HandleResult already skips
    it, so an absent stamp stays NULL. Sending `0001-01-01T00:00:00Z` instead
    would put year 1 in a provenance record — a value that looks like data.
    """
    result = worker(tmp_path).handle(job("no-such-engine", scan_id="s6", job_id="j6"))

    assert result["status"] == ResultStatus.SKIPPED.value
    inv = result["invocation"]
    assert "started_at" not in inv, (
        "a skipped engine published a start time for a run that never began"
    )
    assert "finished_at" not in inv
    assert inv["duration_ms"] == 0, "no invocation, no duration — all three agree or none do"


def test_a_refused_run_is_still_timed_when_the_adapter_was_consulted(tmp_path: Path) -> None:
    """`unavailable` from the adapter means real work happened and was refused.

    dependency-check checks for a provisioned database and declines before the
    container starts. That decision took time and is worth dating — unlike an
    engine this worker does not implement, which was never consulted at all.
    """
    result = worker(tmp_path).handle(job("dependency-check", scan_id="s7", job_id="j7"))

    inv = result["invocation"]
    assert result["status"] in {
        ResultStatus.UNAVAILABLE.value,
        ResultStatus.FAILED.value,
    }, result["status"]
    assert "started_at" in inv and "finished_at" in inv
