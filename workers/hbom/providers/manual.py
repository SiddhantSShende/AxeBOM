"""The default provider: no external lookup at all.

⚠ THIS IS NOT A STUB OR A PLACEHOLDER. It is the shipping default and the path
the tests exercise.

A customer recording the hardware they own does not need a third-party parts
database to do it, and requiring one would make HBOM unusable for anybody who
has not signed up to Nexar. `manual` returning nothing is the correct behaviour
for the common case, not a degraded one — the data came from the customer, which
for a compliance document is the better provenance anyway.
"""

from __future__ import annotations

from .base import Enrichment


class ManualProvider:
    """Looks nothing up. Always configured, because it needs nothing."""

    name = "manual"

    def configured(self) -> bool:
        return True

    def lookup(self, mpns: list[str]) -> dict[str, Enrichment]:
        # Deliberately empty rather than raising: callers treat a missing key as
        # "not found", so an empty result is a valid answer rather than a
        # failure they have to special-case.
        return {}
