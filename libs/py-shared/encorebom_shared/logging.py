"""Structured logging with secret redaction.

Mirrors the Go `platform/obs` package, and for the same reason: redaction lives
in the log PROCESSOR, not at call sites. A call site will eventually be added
without it; a processor cannot be bypassed.

docs/05-SECURITY-MODEL.md §7 — nothing secret in a log. Workers additionally
must not log component or finding detail: BOM content is confidential under
CERT-In §5.3, and worker logs are the noisiest thing in the system.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

import structlog

# Redacted wherever they appear as a key, case-insensitively, as a substring.
_SENSITIVE_KEYS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "credential",
    "authorization",
    "cookie",
    "session",
    "private_key",
    "client_secret",
    "access_key",
    "refresh",
    "signature",
    "jwt",
    "dsn",
    "connection_string",
    "conn_str",
)

# Secret-SHAPED values, redacted regardless of key name. This is the half that
# catches a credential embedded in a free-text error message from a scanner.
_URL_CREDENTIALS = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^:/?#\s]+):([^@/?#\s]+)@")
_VALUE_PATTERNS = (
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)

REDACTED = "[REDACTED]"


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(s in lowered for s in _SENSITIVE_KEYS)


def redact(value: str) -> str:
    """Remove secret-shaped substrings from a string.

    A URL keeps its scheme, user and host so the log still says WHICH host
    failed — "postgres://app:[REDACTED]@db:5432" is far more useful when
    debugging than a bare "[REDACTED]".
    """
    value = _URL_CREDENTIALS.sub(lambda m: f"{m.group(1)}:{REDACTED}@", value)
    for pattern in _VALUE_PATTERNS:
        value = pattern.sub(REDACTED, value)
    return value


def _redact_processor(_logger: Any, _method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """structlog processor applying both redaction mechanisms."""
    for key, val in list(event_dict.items()):
        if _is_sensitive_key(key):
            event_dict[key] = REDACTED
        elif isinstance(val, str):
            event_dict[key] = redact(val)
        elif isinstance(val, dict):
            event_dict[key] = {
                k: (REDACTED if _is_sensitive_key(k) else redact(v) if isinstance(v, str) else v)
                for k, v in val.items()
            }
    return event_dict


def configure_logging(
    service: str,
    level: str = "info",
    fmt: str = "json",
) -> None:
    """Install the shared logging configuration.

    Call once at worker startup, before anything else logs.
    """
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
    )

    renderer: Any = (
        structlog.processors.JSONRenderer() if fmt == "json" else structlog.dev.ConsoleRenderer()
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            # UTC with a literal Z. CLAUDE.md §Conventions: no local time
            # anywhere. A worker container's local time is arbitrary, and a
            # BOM timestamp in it is a compliance-artifact defect.
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _redact_processor,  # ← must run before the renderer
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    structlog.contextvars.bind_contextvars(service=service)


def get_logger(name: str | None = None) -> Any:
    """Return a bound logger."""
    return structlog.get_logger(name) if name else structlog.get_logger()
