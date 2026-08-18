"""Nexar (Altium, formerly Octopart) part lookup.

⚠ COMMERCIAL, QUOTA-LIMITED, AND OPTIONAL. Octopart's free API is gone; Nexar
requires an account, an OAuth client credential, and bills against a query
budget. It is never a hard dependency — `resolve()` falls back to `manual`.

⚠ THIS ADAPTER HAS NEVER BEEN RUN AGAINST THE LIVE API.

It is written against Nexar's published GraphQL schema and its parsing is
tested against hand-built responses. Phase 7 is the precedent for why that is
not the same as working: an adapter that parses a fixture correctly can still
send a malformed query, mis-handle a paging cursor, or discover that a field it
depends on is behind a higher tier. Until it has run, `configured()` returning
False is the honest state and the one the product ships in.
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

#: Nexar's GraphQL endpoint.
NEXAR_URL = "https://api.nexar.com/graphql"

#: How many part numbers go in one query.
#:
#: ⚠ BATCHED BECAUSE THE QUOTA IS PER REQUEST. A 400-line BOM looked up one part
#: at a time is 400 billable calls to learn what twenty could have told us.
BATCH_SIZE = 20

_QUERY = """
query MultiMatch($queries: [SupPartMatchQuery!]!) {
  supMultiMatch(queries: $queries) {
    parts {
      mpn
      manufacturer { name }
      specs { attribute { shortname } displayValue }
      bestDatasheet { url }
      medianPrice1000 { price }
    }
  }
}
"""


@dataclass
class NexarProvider:
    """Looks up parts through Nexar.

    Credentials come from the environment rather than a constructor default, so
    a misconfiguration is an absent provider rather than a call with an empty
    token.
    """

    token: str = ""
    timeout: float = 15.0
    name: str = "nexar"

    @classmethod
    def from_env(cls) -> NexarProvider:
        return cls(token=os.environ.get("NEXAR_TOKEN", "").strip())

    def configured(self) -> bool:
        # ⚠ THE ONLY GATE. An empty token means this provider does not exist as
        # far as the rest of the system is concerned — no call, no 401, no
        # support ticket about a feature nobody enabled.
        return bool(self.token)

    def lookup(self, mpns: list[str]) -> dict[str, Enrichment]:
        if not self.configured() or not mpns:
            return {}

        found: dict[str, Enrichment] = {}
        for start in range(0, len(mpns), BATCH_SIZE):
            batch = mpns[start : start + BATCH_SIZE]
            try:
                found.update(self._query(batch))
            except (urllib.error.URLError, TimeoutError, ValueError):
                # ⚠ ENRICHMENT FAILURE IS NOT IMPORT FAILURE. The customer's own
                # data is already complete and correct; a parts database being
                # unreachable must not lose it. The gap is visible as absent
                # enrichment rather than as a failed import.
                continue
        return found

    def _query(self, mpns: list[str]) -> dict[str, Enrichment]:
        payload = json.dumps(
            {
                "query": _QUERY,
                "variables": {"queries": [{"mpn": m, "limit": 1} for m in mpns]},
            }
        ).encode()

        request = urllib.request.Request(
            NEXAR_URL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}",
            },
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
            body = json.loads(response.read().decode())

        return self.parse(body)

    @staticmethod
    def parse(body: Mapping[str, Any]) -> dict[str, Enrichment]:
        """Turn a Nexar response into enrichments.

        Separated from the transport so it is testable without a network, which
        is the only part of this adapter that currently has coverage.
        """
        out: dict[str, Enrichment] = {}
        results = (body.get("data") or {}).get("supMultiMatch") or []

        for match in results:
            for part in match.get("parts") or []:
                mpn = (part.get("mpn") or "").strip()
                if not mpn:
                    continue

                specs = {
                    (s.get("attribute") or {}).get("shortname", ""): s.get("displayValue", "")
                    for s in part.get("specs") or []
                }

                compliance: list[str] = []
                if str(specs.get("rohsstatus", "")).lower().startswith("rohs"):
                    compliance.append("RoHS")
                if specs.get("reachsvhc"):
                    compliance.append("REACH")

                out[mpn.lower()] = Enrichment(
                    mpn=mpn,
                    manufacturer_name=(part.get("manufacturer") or {}).get("name", ""),
                    technology_node=str(specs.get("processgeometry", "") or ""),
                    compliance=compliance,
                    lifecycle=str(specs.get("lifecyclestatus", "") or ""),
                    datasheet_url=(part.get("bestDatasheet") or {}).get("url", ""),
                    source="nexar",
                )
        return out
