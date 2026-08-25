"""Shared library for AxeBOM scan workers.

Workers run third-party scanners over untrusted user code inside a sandbox and
hold no credentials (docs/ADR/0008). Everything here is written with that in
mind: no secret handling, no network egress helpers, no database access.

Contracts this package implements:
  docs/02-CONTRACTS.md      job / event / result envelopes
  docs/04-OSINT-INTEGRATION.md   the ToolAdapter interface
  docs/03-NORMALIZER-SPEC.md     normalization (Phase 8)
"""

from axebom_shared.errors import (
    AxeBOMError,
    EngineError,
    EngineTimeoutError,
    EngineUnavailableError,
    ErrorCode,
    NormalizeError,
)
from axebom_shared.logging import configure_logging, get_logger, redact
from axebom_shared.timeutil import to_rfc3339, utc_now

__version__ = "0.1.0"

__all__ = [
    "AxeBOMError",
    "EngineError",
    "EngineTimeoutError",
    "EngineUnavailableError",
    "ErrorCode",
    "NormalizeError",
    "__version__",
    "configure_logging",
    "get_logger",
    "redact",
    "to_rfc3339",
    "utc_now",
]
