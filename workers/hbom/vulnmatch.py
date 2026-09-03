"""Advisory CVE matching for hardware components (CERT-In element 24).

⚠ THIS MODULE'S OUTPUT IS ADVISORY AND THE REPORT SAYS SO IN THOSE WORDS.

For software, a finding is an assertion: the lockfile named `lodash@4.17.20`,
the advisory names `lodash < 4.17.21`, so the finding is a fact about the
build. For hardware there is no lockfile. There is a manufacturer string and a
part number, and NVD's own vendor/product vocabulary that nobody reconciled
with either — so every match here is a STRING MATCH between two independently
maintained naming schemes.

That is worth doing. It is not worth asserting. So each finding carries the
`match_basis` it was found on and a `match_confidence`, and the report renders
both next to the CVE rather than presenting a bare severity.

⚠ THE STATUS MATTERS AS MUCH AS THE FINDINGS, AND FOR ELEMENT 24 IT MATTERS
MORE. Four outcomes are distinguished, and collapsing any two of them into
"no vulnerabilities" is how this feature would start lying:

  matched        we searched and found entries
  no-match       we searched and found nothing        ← a real, reassuring result
  no-cpe         the component states too little to search on
  not-attempted  no NVD credential; we never looked   ← NOT the same as no-match

A component with an empty findings list is meaningless without the status
beside it. `not-attempted` rendered as "no known vulnerabilities" is a false
negative the customer would act on.

⚠ NEVER RUN AGAINST THE LIVE NVD API. Parsing is tested against hand-built
responses shaped from NVD's published 2.0 schema. Per the Nexar precedent in
`providers/nexar.py`: an adapter that parses a fixture correctly can still send
a malformed query or mis-handle paging. Until it has run, `configured()`
returning False is the honest state and the one the product ships in.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .cpe import Candidate, candidates

#: NVD's CVE API 2.0.
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

#: ⚠ NVD's DOCUMENTED RATE LIMIT IS 50 REQUESTS PER 30 SECONDS WITH A KEY
#: (5 WITHOUT). We pace well under it: a parts list is not urgent, and being
#: rate-limited mid-run would leave half a BOM `not-attempted` for a reason
#: that has nothing to do with the hardware.
REQUEST_INTERVAL_SECONDS = 0.75

#: How many CVEs one candidate may contribute. A wildcarded vendor on a generic
#: product can return hundreds; a hundred low-confidence rows against one
#: resistor buries the finding that matters.
MAX_RESULTS_PER_CANDIDATE = 25

#: Terminal statuses. Mirrors the CHECK on
#: `normalize.hardware_components.vuln_match_status`.
MATCHED = "matched"
NO_MATCH = "no-match"
NO_CPE = "no-cpe"
NOT_ATTEMPTED = "not-attempted"


@dataclass
class HardwareFinding:
    """One advisory CVE match against one component."""

    cve_id: str
    cpe23: str
    match_basis: str
    match_confidence: str
    severity: str = ""
    cvss_score: float | None = None
    cvss_vector: str = ""
    description: str = ""
    source: str = "nvd"
    source_version: str = "2.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "cpe23": self.cpe23,
            "match_basis": self.match_basis,
            "match_confidence": self.match_confidence,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "description": self.description,
            "source": self.source,
            "source_version": self.source_version,
        }


@dataclass
class MatchOutcome:
    """What happened when we tried to match one component.

    ⚠ `findings` IS MEANINGLESS WITHOUT `status`. See the module docstring.
    """

    status: str
    cpe23_candidates: list[str] = field(default_factory=list)
    findings: list[HardwareFinding] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)


@dataclass
class NVDMatcher:
    """Searches NVD for entries matching a component's CPE candidates."""

    api_key: str = ""
    timeout: float = 20.0
    name: str = "nvd"
    #: Set by tests to a callable taking a URL and returning parsed JSON.
    _fetch: Any = None
    _last_request: float = 0.0

    @classmethod
    def from_env(cls) -> NVDMatcher:
        return cls(api_key=os.environ.get("NVD_API_KEY", "").strip())

    def configured(self) -> bool:
        # ⚠ NVD's API IS USABLE WITHOUT A KEY, AND WE STILL REQUIRE ONE.
        #
        # Keyless access is 5 requests per 30 seconds, shared across everyone
        # on the egress IP. A single 200-line BOM would take twenty minutes and
        # would rate-limit every other tenant scanning at the same time. A
        # feature that degrades into a shared-resource denial of service is one
        # that should announce itself as unconfigured instead.
        return bool(self.api_key)

    def match_component(
        self,
        *,
        manufacturer: str,
        model_number: str,
        product_name: str = "",
        version: str = "",
        firmware_version: str = "",
    ) -> MatchOutcome:
        """Search for one component. Never raises."""
        found = candidates(
            manufacturer=manufacturer,
            model_number=model_number,
            product_name=product_name,
            version=version,
            firmware_version=firmware_version,
        )
        cpes = [c.cpe23 for c in found]

        if not found:
            # ⚠ RECORDED, NOT SILENT. "This component states too little to
            # search on" is actionable — it tells the customer which BOM lines
            # need a manufacturer or part number before element 24 can mean
            # anything.
            return MatchOutcome(status=NO_CPE)

        if not self.configured():
            # ⚠ CANDIDATES ARE STILL RETURNED. They are what the search WOULD
            # have used, so the report can show the customer exactly what
            # enabling a key would buy them.
            return MatchOutcome(
                status=NOT_ATTEMPTED,
                cpe23_candidates=cpes,
                diagnostics=["NVD_API_KEY is not configured; no lookup was performed"],
            )

        findings: list[HardwareFinding] = []
        diagnostics: list[str] = []
        attempted = 0
        for candidate in found:
            try:
                payload = self._request(candidate.cpe23)
            except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
                # ⚠ ONE FAILED CANDIDATE IS NOT A FAILED COMPONENT, BUT IT IS
                # ALSO NOT A CLEAN "no-match". It is recorded so a transport
                # failure cannot masquerade as an absence of vulnerabilities.
                diagnostics.append(f"lookup failed for {candidate.cpe23}: {type(exc).__name__}")
                continue
            attempted += 1
            findings.extend(parse_response(payload, candidate))

        if attempted == 0:
            return MatchOutcome(
                status=NOT_ATTEMPTED,
                cpe23_candidates=cpes,
                diagnostics=diagnostics or ["every NVD lookup failed; no conclusion can be drawn"],
            )

        deduped = _dedupe(findings)
        return MatchOutcome(
            status=MATCHED if deduped else NO_MATCH,
            cpe23_candidates=cpes,
            findings=deduped,
            diagnostics=diagnostics,
        )

    def _request(self, cpe23: str) -> dict[str, Any]:
        if self._fetch is not None:
            return self._fetch(cpe23)

        # ⚠ PACED BEFORE THE CALL, NOT AFTER A 429. Reacting to a rate-limit
        # response means the limit was already hit, and NVD's throttle is per
        # source IP — shared with every other tenant on this egress.
        elapsed = time.monotonic() - self._last_request
        if elapsed < REQUEST_INTERVAL_SECONDS:
            time.sleep(REQUEST_INTERVAL_SECONDS - elapsed)
        self._last_request = time.monotonic()

        # ⚠ `virtualMatchString`, NOT `cpeName`. `cpeName` requires a concrete
        # CPE that exists in NVD's dictionary; our candidates carry wildcards
        # by construction, and `cpeName` would return nothing for all of them.
        query = urllib.parse.urlencode(
            {"virtualMatchString": cpe23, "resultsPerPage": MAX_RESULTS_PER_CANDIDATE}
        )
        request = urllib.request.Request(  # noqa: S310 — fixed https host
            f"{NVD_URL}?{query}",
            headers={"apiKey": self.api_key, "User-Agent": "AxeBOM"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
            return json.loads(response.read().decode("utf-8"))


def parse_response(payload: dict[str, Any], candidate: Candidate) -> list[HardwareFinding]:
    """Turn one NVD 2.0 response into findings. Tolerant of missing fields."""
    out: list[HardwareFinding] = []
    for entry in payload.get("vulnerabilities", []) or []:
        cve = (entry or {}).get("cve") or {}
        cve_id = str(cve.get("id") or "").strip()
        if not cve_id:
            continue
        score, severity, vector = _best_metric(cve.get("metrics") or {})
        out.append(
            HardwareFinding(
                cve_id=cve_id,
                cpe23=candidate.cpe23,
                match_basis=candidate.basis,
                match_confidence=candidate.confidence,
                severity=severity,
                cvss_score=score,
                cvss_vector=vector,
                description=_english(cve.get("descriptions") or []),
            )
        )
        if len(out) >= MAX_RESULTS_PER_CANDIDATE:
            break
    return out


def _best_metric(metrics: dict[str, Any]) -> tuple[float | None, str, str]:
    """The most recent CVSS version present, preferred newest-first.

    ⚠ VERSIONS ARE NOT AVERAGED OR CONVERTED. A v2 score and a v3.1 score are
    different scales; blending them produces a number that is not a CVSS score
    of any version, in a document an auditor reads as one.
    """
    for key, has_severity in (
        ("cvssMetricV40", True),
        ("cvssMetricV31", True),
        ("cvssMetricV30", True),
        ("cvssMetricV2", False),
    ):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = (entries[0] or {}).get("cvssData") or {}
        score = data.get("baseScore")
        severity = (
            data.get("baseSeverity") if has_severity else (entries[0] or {}).get("baseSeverity")
        )
        return (
            float(score) if isinstance(score, (int, float)) else None,
            str(severity or "").lower(),
            str(data.get("vectorString") or ""),
        )
    return None, "", ""


def _english(descriptions: list[Any]) -> str:
    for item in descriptions:
        if isinstance(item, dict) and str(item.get("lang", "")).lower().startswith("en"):
            return str(item.get("value") or "").strip()
    return ""


def _dedupe(findings: list[HardwareFinding]) -> list[HardwareFinding]:
    """One row per CVE, keeping the strongest evidence for it.

    ⚠ THE SAME CVE FOUND BY TWO CANDIDATES IS ONE FINDING. Reporting it twice
    — once at `vendor+product+version` and once at `vendor+product` — would
    inflate every hardware vulnerability count by the number of candidates that
    happened to match, which is an artefact of our search strategy and not a
    fact about the hardware.
    """
    rank = {"high": 3, "medium": 2, "low": 1}
    best: dict[str, HardwareFinding] = {}
    for finding in findings:
        current = best.get(finding.cve_id)
        if current is None or rank.get(finding.match_confidence, 0) > rank.get(
            current.match_confidence, 0
        ):
            best[finding.cve_id] = finding
    return sorted(
        best.values(),
        key=lambda f: (-(f.cvss_score or 0.0), f.cve_id),
    )


def annotate(roots: list[Any], matcher: NVDMatcher | None = None) -> list[str]:
    """Match every component in place and return diagnostics.

    ⚠ THIS IS THE ONLY PART OF HBOM NORMALIZATION THAT TOUCHES THE NETWORK, AND
    IT DELIBERATELY RUNS BEFORE `build_canonical_hbom` RATHER THAN INSIDE IT.

    `build_canonical_hbom` is documented as a pure function of its input and the
    ruleset version, which is what makes invariant 10's replay work: the same
    stored artifact re-normalizes to byte-identical output. An NVD lookup inside
    it would make that false — NVD's answer changes daily — and re-normalizing
    last quarter's scan would silently produce a different document from the one
    the customer was shown.

    So the match happens here, on the way in, and its RESULT is stored as part
    of the artifact. Re-normalization then replays the stored verdict rather
    than asking again.

    ⚠ ALSO WHY A CACHE IS KEYED ON CPE, NOT COMPONENT. A parts list repeats the
    same MPN across assemblies; searching each placement separately would spend
    the rate limit on an answer we already have.
    """
    matcher = matcher or NVDMatcher.from_env()
    diagnostics: list[str] = []
    cache: dict[tuple[str, ...], MatchOutcome] = {}

    for root in roots:
        for _depth, node in root.walk():
            key = (
                node.manufacturer_name,
                node.model_number,
                node.product_name,
                node.product_version,
                node.firmware_version,
            )
            outcome = cache.get(key)
            if outcome is None:
                outcome = matcher.match_component(
                    manufacturer=node.manufacturer_name,
                    model_number=node.model_number,
                    product_name=node.product_name,
                    version=node.product_version,
                    firmware_version=node.firmware_version,
                )
                cache[key] = outcome
                diagnostics.extend(outcome.diagnostics)

            node.vuln_match_status = outcome.status
            node.cpe23_candidates = list(outcome.cpe23_candidates)
            node.vuln_findings = list(outcome.findings)
            # ⚠ ELEMENT 24's VALUE IS DERIVED HERE AND NOWHERE ELSE, so the
            # scored element and the rendered Vulnerabilities sheet cannot drift
            # apart into two different answers about the same component.
            node.findings = [f.cve_id for f in outcome.findings]

    # Deduplicate diagnostics while keeping order — one unconfigured matcher
    # would otherwise emit the same line once per component.
    seen: set[str] = set()
    return [d for d in diagnostics if not (d in seen or seen.add(d))]
