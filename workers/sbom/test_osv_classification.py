"""osv-scanner's exit 128 means two opposite things.

"No package sources found" is emitted both when a repository genuinely commits
no lockfile — express, for one — and when the workspace was never materialized
or could not be read. Both were observed on this stack; the second while the
source archive was being mounted from a tmpfs the daemon could not see.

Reporting the first as `failed` puts a false alarm in a compliance document.
Reporting the second as merely zero coverage would hide a real defect. The only
signal that separates them is the walk count in stderr.
"""

from __future__ import annotations

import pytest

from axebom_shared.adapters.base import ResultStatus
from axebom_shared.sandbox import SandboxResult

from .adapters.osv_scanner import OSVScannerAdapter

WALKED = (
    "Scanning dir /workspace/src\n"
    "Starting filesystem walk for root: /\n"
    "End status: 69 dirs visited, 283 inodes visited, 0 Extract calls\n"
    "No package sources found, --help for usage information."
)

EMPTY = (
    "Scanning dir /warm\n"
    "Starting filesystem walk for root: /\n"
    "End status: 1 dirs visited, 1 inodes visited, 0 Extract calls\n"
    "No package sources found, --help for usage information."
)


def adapter() -> OSVScannerAdapter:
    return OSVScannerAdapter()


def test_a_real_tree_with_no_lockfiles_is_a_coverage_gap_not_a_failure() -> None:
    got = adapter().classify_nonzero(SandboxResult(exit_code=128, stdout="", stderr=WALKED))
    assert got is not None, "exit 128 was left as a bare ENGINE_NONZERO_EXIT"
    status, code, message = got
    assert status is ResultStatus.PARTIAL, status
    assert code == "ENGINE_ZERO_RESULTS"
    assert "lockfiles" in message, message


def test_an_empty_walk_is_a_failure_because_the_source_never_arrived() -> None:
    """⚠ THIS IS THE HALF THAT MUST NOT BE SOFTENED.

    An engine that walked nothing did not scan the project. Calling that a
    coverage gap would let a broken workspace mount look like a project with no
    dependencies.
    """
    got = adapter().classify_nonzero(SandboxResult(exit_code=128, stdout="", stderr=EMPTY))
    assert got is not None
    status, code, _ = got
    assert status is ResultStatus.FAILED, status
    assert code == "ENGINE_INPUT_UNREADABLE"


@pytest.mark.parametrize(
    ("exit_code", "stderr"),
    [
        (127, "command not found"),
        (2, "some other failure"),
        (128, "a different message entirely"),
    ],
)
def test_everything_else_keeps_the_default_failure(exit_code: int, stderr: str) -> None:
    """Unrecognised failures must NOT be reinterpreted.

    The reclassification is narrow on purpose: it applies to one exit code with
    one message. Anything else falls through to `failed`, which overstates the
    problem visibly rather than understating it.
    """
    assert (
        adapter().classify_nonzero(SandboxResult(exit_code=exit_code, stdout="", stderr=stderr))
        is None
    )


def test_unparsed_walk_count_falls_through_to_failed() -> None:
    """If upstream rewords the summary line, fail loudly rather than guess."""
    reworded = "No package sources found, --help for usage information."
    got = adapter().classify_nonzero(SandboxResult(exit_code=128, stdout="", stderr=reworded))
    assert got is not None
    status, code, _ = got
    assert status is ResultStatus.FAILED, (
        "an unparseable walk count was treated as a coverage gap; a reworded "
        "upstream message would silently hide an unreadable workspace"
    )
    assert code == "ENGINE_INPUT_UNREADABLE"
