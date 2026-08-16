"""Error taxonomy for scan workers.

Mirrors the Go `platform/errs` package. Contract: docs/02-CONTRACTS.md §9.

The ENGINE_* and NORMALIZE_* codes here are usually attached to a
`ScanResultV1` as a diagnostic rather than raised as an exception — a scanner
that fails on one of twelve ecosystems produced useful output plus a known gap,
and both must survive into the report. Losing the gap is worse than losing the
output: it turns an unknown into a false negative the customer trusts.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    """Stable machine-readable codes. Never reuse one with a new meaning."""

    # Engine — attached to a result as a diagnostic
    ENGINE_UNAVAILABLE = "ENGINE_UNAVAILABLE"
    ENGINE_PARTIAL_ECOSYSTEM = "ENGINE_PARTIAL_ECOSYSTEM"
    ENGINE_TIMEOUT = "ENGINE_TIMEOUT"
    ENGINE_DB_STALE = "ENGINE_DB_STALE"
    ENGINE_OUTPUT_MALFORMED = "ENGINE_OUTPUT_MALFORMED"
    ENGINE_CRASHED = "ENGINE_CRASHED"

    # Normalizer
    NORMALIZE_IDENTITY_OPAQUE = "NORMALIZE_IDENTITY_OPAQUE"
    NORMALIZE_ALIAS_CLUSTER_OVERSIZE = "NORMALIZE_ALIAS_CLUSTER_OVERSIZE"
    NORMALIZE_LICENSE_AMBIGUOUS = "NORMALIZE_LICENSE_AMBIGUOUS"
    NORMALIZE_NO_VERSION_COMPARATOR = "NORMALIZE_NO_VERSION_COMPARATOR"
    NORMALIZE_COMPONENT_CAP_EXCEEDED = "NORMALIZE_COMPONENT_CAP_EXCEEDED"

    # Fetch — the untrusted-input boundary (docs/05-SECURITY-MODEL.md §4)
    FETCH_ARCHIVE_TOO_LARGE = "FETCH_ARCHIVE_TOO_LARGE"
    FETCH_INFLATION_RATIO_EXCEEDED = "FETCH_INFLATION_RATIO_EXCEEDED"
    FETCH_TOO_MANY_FILES = "FETCH_TOO_MANY_FILES"
    FETCH_PATH_TRAVERSAL = "FETCH_PATH_TRAVERSAL"
    FETCH_SYMLINK_ESCAPE = "FETCH_SYMLINK_ESCAPE"

    INTERNAL_UNEXPECTED = "INTERNAL_UNEXPECTED"


class Severity(StrEnum):
    WARN = "warn"
    ERROR = "error"


class EncoreBOMError(Exception):
    """Base error carrying a stable code and structured detail."""

    code: ErrorCode = ErrorCode.INTERNAL_UNEXPECTED

    def __init__(
        self,
        message: str,
        *,
        code: ErrorCode | None = None,
        retryable: bool = False,
        **detail: Any,
    ) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code
        # Whether the orchestrator should redeliver. Getting this wrong is
        # costly in both directions: a non-retryable failure marked retryable
        # burns four delivery attempts on a corrupt archive, and a transient
        # network failure marked non-retryable silently loses an engine's
        # coverage from the report.
        self.retryable = retryable
        self.detail = detail

    def as_diagnostic(self, severity: Severity = Severity.ERROR) -> dict[str, Any]:
        """Render as a ScanResultV1 diagnostic entry."""
        return {
            "severity": severity.value,
            "code": self.code.value,
            "message": self.message,
            **self.detail,
        }

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code.value!r}, message={self.message!r})"


class EngineError(EncoreBOMError):
    """A scanner failed or produced unusable output."""

    code = ErrorCode.ENGINE_CRASHED


class EngineUnavailableError(EngineError):
    """A scanner could not be resolved.

    Never fatal to a scan. The engine is recorded as `unavailable` and appears
    in the report's Engine Coverage section (docs/02-CONTRACTS.md §6). Losing
    one engine costs that engine's coverage, visibly — not the whole scan.
    """

    code = ErrorCode.ENGINE_UNAVAILABLE

    def __init__(self, engine: str, reason: str) -> None:
        super().__init__(
            f"engine {engine!r} unavailable: {reason}",
            retryable=False,
            engine=engine,
            reason=reason,
        )


class EngineTimeoutError(EngineError):
    """A scanner exceeded its wall-clock budget."""

    code = ErrorCode.ENGINE_TIMEOUT

    def __init__(self, engine: str, seconds: float) -> None:
        super().__init__(
            f"engine {engine!r} exceeded its {seconds:.0f}s budget",
            retryable=True,
            engine=engine,
            wall_clock_sec=seconds,
        )


class EngineOutputMalformedError(EngineError):
    """A scanner's output could not be parsed.

    Raised only when output is unusable. A *missing* field is a diagnostic, not
    an exception: adapters parse defensively so an upstream schema change
    degrades coverage loudly rather than crashing a worker or, worse, silently
    producing an empty inventory that renders as a clean report.
    """

    code = ErrorCode.ENGINE_OUTPUT_MALFORMED

    def __init__(self, engine: str, reason: str, *, artifact: str | None = None) -> None:
        super().__init__(
            f"engine {engine!r} produced unparseable output: {reason}",
            retryable=False,
            engine=engine,
            artifact=artifact,
        )


class NormalizeError(EncoreBOMError):
    """Normalization could not complete."""

    code = ErrorCode.NORMALIZE_IDENTITY_OPAQUE


class FetchError(EncoreBOMError):
    """Source materialization failed or was refused.

    Most subclasses represent a REFUSED input rather than a broken one — a
    decompression bomb, a path-traversal entry, a symlink escape. Those are
    never retryable: the input will be just as hostile next time.
    """

    code = ErrorCode.FETCH_PATH_TRAVERSAL
