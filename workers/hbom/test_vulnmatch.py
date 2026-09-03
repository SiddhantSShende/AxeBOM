"""Tests for CPE construction and advisory CVE matching.

⚠ THE STATUS TESTS ARE THE POINT OF THIS FILE. Parsing a CVE out of a fixture
is easy; what would actually hurt a customer is `not-attempted` rendering as
"no known vulnerabilities", so that distinction is pinned from four directions.
"""

from __future__ import annotations

from workers.hbom.cpe import candidates, normalize_value, normalize_vendor
from workers.hbom.vulnmatch import (
    MATCHED,
    NO_CPE,
    NO_MATCH,
    NOT_ATTEMPTED,
    NVDMatcher,
    parse_response,
)

# ---------------------------------------------------------------------------
# CPE construction
# ---------------------------------------------------------------------------


def test_a_corporate_suffix_folds_but_a_descriptive_word_survives():
    """⚠ THE REGRESSION THAT SHIPPED FOR ABOUT FIVE MINUTES.

    "Microelectronics" was in the suffix list, so "ST Microelectronics" folded
    to `st` — not a CPE vendor, matching nothing, and silently. Legal forms
    strip; words that carry the company's identity never do.
    """
    assert normalize_vendor("Yageo Corporation") == normalize_vendor("Yageo") == "yageo"
    assert normalize_vendor("Analog Devices, Inc.") == "analog_devices"
    assert normalize_vendor("ST Microelectronics") == "st_microelectronics"
    assert normalize_vendor("Vishay Semiconductor") == "vishay_semiconductor"
    assert normalize_vendor("Murata Electronics") == "murata_electronics"


def test_cpe_special_characters_are_escaped():
    assert normalize_value("RC0402FR-07/10KL") == "rc0402fr-07_10kl"
    assert "*" not in normalize_value("part*number")


def test_no_product_yields_no_candidates_rather_than_a_wildcard():
    """⚠ `cpe:2.3:h:yageo:*:*` MATCHES EVERY YAGEO PART EVER PUBLISHED.

    Reporting those against one line item would bury a real finding under a
    hundred irrelevant ones. Silence is the correct output.
    """
    assert candidates(manufacturer="Yageo", model_number="", product_name="") == []


def test_a_missing_manufacturer_still_searches_on_the_part_number():
    """A distinctive MPN finds real entries; refusing to look because a column
    was blank would lose findings over a spreadsheet omission."""
    found = candidates(manufacturer="", model_number="STM32H753ZI")
    assert len(found) == 1
    assert found[0].cpe23.startswith("cpe:2.3:h:*:stm32h753zi:")
    assert found[0].confidence == "low"


def test_hardware_uses_part_h_and_firmware_uses_part_o():
    """⚠ NVD FILES FIRMWARE UNDER `o`, NOT `h`. Searching the wrong part
    attribute silently returns nothing."""
    found = candidates(
        manufacturer="STMicroelectronics", model_number="STM32H753ZI", firmware_version="4.2.1"
    )
    by_basis = {c.basis: c for c in found}
    assert by_basis["vendor+product"].cpe23.startswith("cpe:2.3:h:")
    assert by_basis["firmware-version"].cpe23.startswith("cpe:2.3:o:")


def test_the_best_evidence_comes_first():
    found = candidates(
        manufacturer="Cisco", model_number="RV340", version="1.0", firmware_version="1.0.03.24"
    )
    assert found[0].basis == "vendor+product+version"
    assert found[0].confidence == "medium"


def test_no_candidate_is_ever_marked_high_confidence():
    """⚠ THERE IS NO HIGH-CONFIDENCE HARDWARE CPE MATCH. Every one of these is
    a string match between two vocabularies nobody reconciled."""
    found = candidates(
        manufacturer="Cisco", model_number="RV340", version="1.0", firmware_version="1.0.03.24"
    )
    assert {c.confidence for c in found} <= {"medium", "low"}


# ---------------------------------------------------------------------------
# The four statuses
# ---------------------------------------------------------------------------


def test_an_unconfigured_matcher_reports_not_attempted_never_no_match():
    """⚠ THE DEFECT THIS WHOLE MODULE IS SHAPED AROUND.

    With no NVD key we did not look. Reporting that as "no vulnerabilities
    found" is a false negative the customer would act on.
    """
    outcome = NVDMatcher(api_key="").match_component(manufacturer="Cisco", model_number="RV340")
    assert outcome.status == NOT_ATTEMPTED
    assert outcome.findings == []
    assert outcome.cpe23_candidates, "the candidates we would have searched are still reported"
    assert any("NVD_API_KEY" in d for d in outcome.diagnostics)


def test_a_component_with_nothing_to_search_on_reports_no_cpe():
    outcome = NVDMatcher(api_key="k").match_component(manufacturer="Yageo", model_number="")
    assert outcome.status == NO_CPE
    assert outcome.cpe23_candidates == []


def test_a_clean_search_with_no_hits_reports_no_match():
    """⚠ DISTINCT FROM `not-attempted`, AND THE ONLY REASSURING RESULT OF THE
    FOUR. We looked, and there was nothing."""
    matcher = NVDMatcher(api_key="k", _fetch=lambda cpe: {"vulnerabilities": []})
    outcome = matcher.match_component(manufacturer="Yageo", model_number="RC0402FR-0710KL")
    assert outcome.status == NO_MATCH
    assert outcome.findings == []


def test_a_transport_failure_never_becomes_no_match():
    """⚠ A NETWORK ERROR IS NOT AN ABSENCE OF VULNERABILITIES."""

    def explode(cpe: str):
        raise TimeoutError("connect timed out")

    matcher = NVDMatcher(api_key="k", _fetch=explode)
    outcome = matcher.match_component(manufacturer="Cisco", model_number="RV340")
    assert outcome.status == NOT_ATTEMPTED
    assert outcome.diagnostics


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-1472",
                "descriptions": [
                    {"lang": "es", "value": "no"},
                    {"lang": "en", "value": "Command injection in the web management interface."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        }
                    ],
                    "cvssMetricV2": [{"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}],
                },
            }
        }
    ]
}


def test_parsing_extracts_the_english_description_and_v31_metric():
    matcher = NVDMatcher(api_key="k", _fetch=lambda cpe: _RESPONSE)
    outcome = matcher.match_component(manufacturer="Cisco", model_number="RV340")
    assert outcome.status == MATCHED
    finding = outcome.findings[0]
    assert finding.cve_id == "CVE-2021-1472"
    assert finding.cvss_score == 9.8
    assert finding.severity == "critical"
    assert finding.description.startswith("Command injection")
    assert finding.match_confidence in {"medium", "low"}


def test_cvss_versions_are_preferred_newest_first_and_never_blended():
    """⚠ v2 AND v3.1 ARE DIFFERENT SCALES. Averaging 7.5 and 9.8 produces a
    number that is not a CVSS score of any version."""
    matcher = NVDMatcher(api_key="k", _fetch=lambda cpe: _RESPONSE)
    finding = matcher.match_component(manufacturer="Cisco", model_number="RV340").findings[0]
    assert finding.cvss_score == 9.8
    assert finding.cvss_vector.startswith("CVSS:3.1/")


def test_a_v2_only_entry_still_parses():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2014-0001",
                    "metrics": {
                        "cvssMetricV2": [{"baseSeverity": "MEDIUM", "cvssData": {"baseScore": 5.0}}]
                    },
                }
            }
        ]
    }
    matcher = NVDMatcher(api_key="k", _fetch=lambda cpe: payload)
    finding = matcher.match_component(manufacturer="Cisco", model_number="RV340").findings[0]
    assert finding.cvss_score == 5.0
    assert finding.severity == "medium"


def test_a_response_with_no_metrics_at_all_still_yields_the_cve():
    """A CVE with no CVSS block is still a CVE. Dropping it because it lacks a
    score would hide a reserved or newly published entry."""
    payload = {"vulnerabilities": [{"cve": {"id": "CVE-2025-0001"}}]}
    matcher = NVDMatcher(api_key="k", _fetch=lambda cpe: payload)
    outcome = matcher.match_component(manufacturer="Cisco", model_number="RV340")
    assert outcome.status == MATCHED
    assert outcome.findings[0].cvss_score is None


def test_malformed_entries_are_skipped_not_fatal():
    payload = {"vulnerabilities": [{}, {"cve": {}}, {"cve": {"id": "CVE-2020-9999"}}]}
    matcher = NVDMatcher(api_key="k", _fetch=lambda cpe: payload)
    outcome = matcher.match_component(manufacturer="Cisco", model_number="RV340")
    assert [f.cve_id for f in outcome.findings] == ["CVE-2020-9999"]


def test_the_same_cve_found_by_two_candidates_is_one_finding():
    """⚠ OTHERWISE EVERY COUNT INFLATES BY OUR SEARCH STRATEGY.

    Cisco/RV340/1.0 produces three candidates; all three matching one CVE must
    not report it three times. The strongest basis is the one kept.
    """
    matcher = NVDMatcher(api_key="k", _fetch=lambda cpe: _RESPONSE)
    outcome = matcher.match_component(
        manufacturer="Cisco", model_number="RV340", version="1.0", firmware_version="1.0.03.24"
    )
    assert len(outcome.cpe23_candidates) >= 3
    assert [f.cve_id for f in outcome.findings] == ["CVE-2021-1472"]
    assert outcome.findings[0].match_confidence == "medium"


def test_findings_sort_worst_first():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-A",
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 4.0}}]},
                }
            },
            {
                "cve": {
                    "id": "CVE-B",
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.1}}]},
                }
            },
        ]
    }
    matcher = NVDMatcher(api_key="k", _fetch=lambda cpe: payload)
    outcome = matcher.match_component(manufacturer="Cisco", model_number="RV340")
    assert [f.cve_id for f in outcome.findings] == ["CVE-B", "CVE-A"]


def test_the_candidate_that_found_it_is_recorded_on_the_finding():
    """⚠ WITHOUT THIS THE READER CANNOT WEIGH THE MATCH. A CVE found on a
    wildcarded vendor is weaker evidence than one found on all three parts."""
    matcher = NVDMatcher(api_key="k", _fetch=lambda cpe: _RESPONSE)
    finding = matcher.match_component(manufacturer="", model_number="RV340").findings[0]
    assert finding.match_basis == "vendor+product"
    assert finding.cpe23.startswith("cpe:2.3:h:*:rv340:")
    assert finding.source == "nvd"


def test_parse_response_tolerates_a_null_vulnerabilities_key():
    from workers.hbom.cpe import Candidate

    assert parse_response({"vulnerabilities": None}, Candidate("cpe", "b", "low")) == []
    assert parse_response({}, Candidate("cpe", "b", "low")) == []


# ---------------------------------------------------------------------------
# The tree pass
# ---------------------------------------------------------------------------


def _tree():
    from workers.hbom.model import HardwareComponent

    board = HardwareComponent(
        product_name="Mainboard", model_number="RV340", manufacturer_name="Cisco"
    )
    board.local_id = "1"
    for i, mpn in enumerate(["RC0402FR-0710KL", "RC0402FR-0710KL"], start=1):
        child = HardwareComponent(
            product_name="Resistor", model_number=mpn, manufacturer_name="Yageo"
        )
        child.local_id = f"1.{i}"
        child.parent_local_id = "1"
        board.children.append(child)
    return [board]


def test_annotate_sets_status_on_every_node():
    from workers.hbom.vulnmatch import annotate

    roots = _tree()
    annotate(roots, NVDMatcher(api_key="k", _fetch=lambda cpe: {"vulnerabilities": []}))
    statuses = [n.vuln_match_status for _d, n in roots[0].walk()]
    assert statuses == [NO_MATCH, NO_MATCH, NO_MATCH]


def test_element_24_is_derived_from_the_findings_never_set_apart_from_them():
    """⚠ ONE SOURCE FOR THE SCORED VALUE AND THE RENDERED DETAIL. Two writers
    would eventually give two different answers about one component."""
    from workers.hbom.vulnmatch import annotate

    roots = _tree()
    annotate(roots, NVDMatcher(api_key="k", _fetch=lambda cpe: _RESPONSE))
    for _d, node in roots[0].walk():
        assert node.findings == [f.cve_id for f in node.vuln_findings]
        assert node.vuln_match_status == MATCHED


def test_a_repeated_part_number_is_looked_up_once():
    """⚠ THE RATE LIMIT IS THE SCARCE RESOURCE. A 400-line BOM with 40 distinct
    MPNs must cost 40 lookups, not 400."""
    from workers.hbom.vulnmatch import annotate

    calls: list[str] = []

    def counting(cpe: str):
        calls.append(cpe)
        return {"vulnerabilities": []}

    roots = _tree()
    annotate(roots, NVDMatcher(api_key="k", _fetch=counting))
    # Two distinct components (board + one repeated resistor), one candidate each.
    assert len(calls) == 2
    assert len({n.model_number for _d, n in roots[0].walk()}) == 2


def test_annotate_with_no_key_leaves_every_node_not_attempted():
    """⚠ THE STATE THIS PRODUCT ACTUALLY SHIPS IN. No NVD credential is
    configured in any environment yet, so this is the path a customer hits."""
    from workers.hbom.vulnmatch import annotate

    roots = _tree()
    diagnostics = annotate(roots, NVDMatcher(api_key=""))
    for _d, node in roots[0].walk():
        assert node.vuln_match_status == NOT_ATTEMPTED
        assert node.findings == []
        assert node.cpe23_candidates
    assert len(diagnostics) == 1, "the same diagnostic must not repeat per component"
