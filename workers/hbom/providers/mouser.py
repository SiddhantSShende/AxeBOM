"""Mouser part lookup.

⚠ COMMERCIAL, KEYED, AND OPTIONAL — the same rules as Nexar.

Mouser is the second provider because `django-bom`'s README now emphasises it
over Octopart, which moved behind Nexar's paid quota. That README is the ONLY
thing taken from `django-bom`: it is GPL-3.0, it is a Django application rather
than a library, and it is never installed or imported (CLAUDE.md invariant 9).

⚠ THIS ADAPTER HAS NEVER BEEN RUN AGAINST THE LIVE API. Its parsing is tested
against hand-built responses; that is not the same as working. See the same
warning on the Nexar adapter.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .base import Enrichment

MOUSER_URL = "https://api.mouser.com/api/v1/search/keyword"

#: Mouser's keyword search takes one term per call, so batching is a loop rather
#: than a multi-query. The dedup in `providers.base.mpns` matters more here.
MAX_LOOKUPS = 100


@dataclass
class MouserProvider:
    """Looks up parts through Mouser's search API."""

    api_key: str = ""
    timeout: float = 15.0
    name: str = "mouser"

    @classmethod
    def from_env(cls) -> MouserProvider:
        return cls(api_key=os.environ.get("MOUSER_API_KEY", "").strip())

    def configured(self) -> bool:
        return bool(self.api_key)

    def lookup(self, mpns: list[str]) -> dict[str, Enrichment]:
        if not self.configured() or not mpns:
            return {}

        found: dict[str, Enrichment] = {}
        # ⚠ CAPPED. A 5,000-line BOM would otherwise issue 5,000 billable calls
        # from one import. The remainder is simply not enriched, which is a
        # smaller problem than an unexpected invoice.
        for mpn in mpns[:MAX_LOOKUPS]:
            try:
                found.update(self._query(mpn))
            except (urllib.error.URLError, TimeoutError, ValueError):
                # Enrichment failure is not import failure. See NexarProvider.
                continue
        return found

    def _query(self, mpn: str) -> dict[str, Enrichment]:
        payload = json.dumps(
            {"SearchByKeywordRequest": {"keyword": mpn, "records": 1, "startingRecord": 0}}
        ).encode()

        request = urllib.request.Request(  # noqa: S310 — a fixed https endpoint
            f"{MOUSER_URL}?apiKey={self.api_key}",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
            return self.parse(json.loads(response.read().decode()))

    @staticmethod
    def parse(body: Mapping[str, Any]) -> dict[str, Enrichment]:
        """Turn a Mouser response into enrichments."""
        out: dict[str, Enrichment] = {}
        parts = ((body.get("SearchResults") or {}).get("Parts")) or []

        for part in parts:
            mpn = (part.get("ManufacturerPartNumber") or "").strip()
            if not mpn:
                continue

            attributes = {
                (a.get("AttributeName") or ""): a.get("AttributeValue", "")
                for a in part.get("ProductAttributes") or []
            }

            compliance: list[str] = []
            if str(part.get("ROHSStatus", "")).lower().startswith("rohs"):
                compliance.append("RoHS")

            out[mpn.lower()] = Enrichment(
                mpn=mpn,
                manufacturer_name=part.get("Manufacturer", "") or "",
                compliance=compliance,
                lifecycle=str(part.get("LifecycleStatus", "") or ""),
                datasheet_url=part.get("DataSheetUrl", "") or "",
                technology_node=str(attributes.get("Process Geometry", "") or ""),
                source="mouser",
            )
        return out
