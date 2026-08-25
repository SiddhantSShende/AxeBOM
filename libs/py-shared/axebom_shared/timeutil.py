"""Time handling.

CLAUDE.md §Conventions: all timestamps are UTC RFC3339 with a literal Z. No
local time anywhere, ever.

This is not pedantry. A scan worker runs in a container whose local timezone is
whatever the base image happened to set. A BOM `timestamp` field (CERT-In data
field 17) rendered in that timezone is wrong in a compliance artifact, and no
test catches it because the value looks perfectly well-formed.

`datetime.now()` without a tzinfo is banned by ruff's DTZ rules; use utc_now().
"""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now() -> datetime:
    """Current time, timezone-aware, in UTC."""
    return datetime.now(UTC)


def to_rfc3339(dt: datetime) -> str:
    """Render as RFC3339 with a literal Z.

    Python emits '+00:00' for UTC; RFC3339 permits it, but every other producer
    in this system emits 'Z', and mixed representations of the same instant
    make golden-file diffs noisy for no reason.

    A naive datetime is rejected rather than assumed to be UTC. Assuming is how
    a local-time value silently becomes a UTC one.
    """
    if dt.tzinfo is None:
        raise ValueError("refusing to serialize a naive datetime; use utc_now() or attach tzinfo")
    return dt.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def from_rfc3339(value: str) -> datetime:
    """Parse an RFC3339 timestamp, accepting either 'Z' or an explicit offset."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
