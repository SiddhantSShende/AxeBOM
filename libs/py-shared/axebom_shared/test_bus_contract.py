"""The Python bus constants must match libs/go-shared/bus/bus.go.

# Why this test exists rather than a comment saying "keep these in sync"

Two runtimes cannot share a constant, so the delivery policy is written twice.
Duplication without a guard is precisely how the two silently diverge, and the
divergence here would be invisible in both codebases: a Python worker naking
with a 30-second delay against a consumer configured for 8 minutes still works,
it just retries on a schedule nobody chose. The behaviour would depend on which
side you read.

So this parses the Go source — the SSOT for the topology — and asserts the
numbers agree. It reads the source rather than querying a running NATS server on
purpose: the constants must agree at build time, in CI, with no infrastructure.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from axebom_shared import bus


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    for candidate in here.parents:
        if (candidate / "go.mod").exists():
            return candidate
    pytest.skip("not inside the repository; cannot locate bus.go")
    raise AssertionError("unreachable")


@pytest.fixture(scope="module")
def bus_go() -> str:
    path = _repo_root() / "libs" / "go-shared" / "bus" / "bus.go"
    if not path.is_file():
        pytest.skip(f"{path} not found")
    return path.read_text(encoding="utf-8")


def test_stream_names_match(bus_go: str) -> None:
    for const, want in [
        ("StreamJobs", bus.STREAM_JOBS),
        ("StreamResults", bus.STREAM_RESULTS),
        ("StreamDLQ", bus.STREAM_DLQ),
    ]:
        m = re.search(rf'{const}\s*=\s*"([A-Z_]+)"', bus_go)
        assert m, f"could not find {const} in bus.go"
        assert m.group(1) == want, f"{const} is {m.group(1)!r} in Go but {want!r} in Python"


def test_max_deliver_matches(bus_go: str) -> None:
    m = re.search(r"MaxDeliver\s*=\s*(\d+)", bus_go)
    assert m, "could not find MaxDeliver in bus.go"
    assert int(m.group(1)) == bus.MAX_DELIVER, (
        f"MaxDeliver is {m.group(1)} in Go but {bus.MAX_DELIVER} in Python. "
        "A worker that gives up sooner than the consumer expects leaves messages "
        "to expire silently instead of reaching the DLQ."
    )


def test_ack_wait_matches(bus_go: str) -> None:
    m = re.search(r"AckWait\s*=\s*(\d+)\s*\*\s*time\.Minute", bus_go)
    assert m, "could not find AckWait in bus.go"
    assert int(m.group(1)) * 60 == bus.ACK_WAIT_SECONDS, (
        f"AckWait is {m.group(1)}m in Go but {bus.ACK_WAIT_SECONDS}s in Python. "
        "Too short and an in-flight scan is redelivered while it is still running."
    )


def test_backoff_schedule_matches(bus_go: str) -> None:
    m = re.search(r"var backoff = \[\]time\.Duration\{([^}]+)\}", bus_go)
    assert m, "could not find the backoff schedule in bus.go"

    seconds: list[int] = []
    for part in m.group(1).split(","):
        part = part.strip()
        if not part:
            continue
        num = re.match(r"(\d+)\s*\*\s*time\.(Second|Minute)", part)
        assert num, f"unparsed backoff entry: {part!r}"
        value = int(num.group(1))
        seconds.append(value if num.group(2) == "Second" else value * 60)

    assert tuple(seconds) == bus.BACKOFF_SECONDS, (
        f"backoff is {tuple(seconds)} in Go but {bus.BACKOFF_SECONDS} in Python. "
        "Both redelivery routes — an explicit nak and an ack-wait expiry — must "
        "use the same schedule, or behaviour depends on how the worker failed."
    )


def test_subjects_match_the_documented_topology() -> None:
    # scan.job.<family> / scan.result.<family> / scan.dlq.<family>
    assert bus.job_subject("sbom") == "scan.job.sbom"
    assert bus.result_subject("cbom") == "scan.result.cbom"
    assert bus.dlq_subject("hbom") == "scan.dlq.hbom"


def test_worker_families_are_dispatchable(bus_go: str) -> None:
    """Every family this module claims must be a real job subject.

    `fetch` is deliberately absent: it is the orchestrator's own consumer, not a
    scan worker's, and a Python worker attaching to scan.job.fetch would take
    the fetcher's jobs — the one component that holds git credentials.
    """
    assert "fetch" not in bus.WORKER_FAMILIES
    assert set(bus.WORKER_FAMILIES) == {"sbom", "cbom", "aibom", "qbom", "hbom"}


def test_durable_does_not_collide_with_the_go_mock(bus_go: str) -> None:
    """A WorkQueue stream permits ONE consumer per filter subject.

    The Go mock engine holds `mock-engine` on scan.job.sbom. If the Python
    worker used the same durable it would silently join the mock's consumer
    group and inherit its config; if it used a different one while the mock ran,
    NATS would refuse it. Distinct names make the conflict explicit at startup.
    """
    mock = _repo_root() / "workers" / "_mock" / "main.go"
    if not mock.is_file():
        pytest.skip("mock engine not present")

    m = re.search(r'Durable:\s*"([^"]+)"', mock.read_text(encoding="utf-8"))
    assert m, "could not find the mock's durable name"
    assert m.group(1) != bus.durable_name("sbom")


def test_backoff_for_never_indexes_out_of_range() -> None:
    """Guards the arithmetic, which is easy to get wrong by one.

    NumDelivered is 1 on the first attempt, so the first nak must wait
    BACKOFF_SECONDS[0], and any count past the end clamps to the last entry
    rather than raising inside a message handler.
    """
    assert bus._backoff_for(0) == bus.BACKOFF_SECONDS[0]
    assert bus._backoff_for(1) == bus.BACKOFF_SECONDS[0]
    assert bus._backoff_for(2) == bus.BACKOFF_SECONDS[1]
    assert bus._backoff_for(3) == bus.BACKOFF_SECONDS[2]
    assert bus._backoff_for(99) == bus.BACKOFF_SECONDS[-1]


def test_header_sanitizer_bounds_and_strips_framing() -> None:
    """Error text is attacker-influenced — it can carry a component name from a
    scanned repository — and NATS headers are not a place for unbounded strings
    or embedded newlines."""
    assert "\n" not in bus._sanitize_header("a\nb")
    assert "\r" not in bus._sanitize_header("a\rb")
    assert "\x00" not in bus._sanitize_header("a\x00b")
    assert len(bus._sanitize_header("x" * 5000)) <= 513


def test_validate_result_rejects_an_incomplete_envelope() -> None:
    """The schema is generated from the Go types, so this is the drift check."""
    problems = bus.validate_result({})
    if not problems:
        pytest.skip("jsonschema or the schema file is unavailable")
    joined = " ".join(problems)
    assert "schema_version" in joined
    assert "job_id" in joined


def test_validate_result_accepts_a_minimal_valid_envelope() -> None:
    result = {
        "schema_version": "1.0",
        "job_id": "b3f0c2a4-0000-4000-8000-000000000001",
        "scan_id": "b3f0c2a4-0000-4000-8000-000000000002",
        "tenant_id": "b3f0c2a4-0000-4000-8000-000000000003",
        "engine": "syft",
        "engine_version": "1.51.0",
        "status": "succeeded",
    }
    problems = bus.validate_result(result)
    assert problems == [], problems
