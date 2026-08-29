"""Ingestion parsers: CycloneDX `vulnerabilities[]` and dependency-check.

Both were silently absent until this file existed: `_ingest_cyclonedx` parsed
`components` only, so trivy-fs/trivy-image's real findings were discarded, and
`dependency-check` had no parser registered at all. See `ingest.py`'s own
`_cyclonedx_vulnerabilities`/`_ingest_dependency_check` docstrings for why.
"""

from __future__ import annotations

from .ingest import ingest


def cyclonedx_component(ref: str, purl: str) -> dict:
    return {"bom-ref": ref, "type": "library", "purl": purl, "name": purl}


def cyclonedx_rating(*, method: str, score: float, severity: str, source: str) -> dict:
    return {
        "source": {"name": source},
        "score": score,
        "severity": severity,
        "method": method,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }


def cyclonedx_vuln(vuln_id: str, *, ref: str, ratings: list[dict], **kwargs) -> dict:
    return {
        "id": vuln_id,
        "source": {"name": "ghsa"},
        "ratings": ratings,
        "affects": [{"ref": ref, "versions": [{"version": "1.0.0", "status": "affected"}]}],
        **kwargs,
    }


def test_cyclonedx_vulnerabilities_are_no_longer_dropped() -> None:
    payload = {
        "components": [cyclonedx_component("comp-1", "pkg:npm/lodash@4.17.15")],
        "vulnerabilities": [
            cyclonedx_vuln(
                "CVE-2021-23337",
                ref="comp-1",
                ratings=[
                    cyclonedx_rating(
                        method="CVSSv31", score=7.2, severity="high", source="nvd"
                    )
                ],
                description="command injection via template",
            )
        ],
    }

    out = ingest("trivy-fs", payload, scan_id="s1")

    assert len(out.findings) == 1
    finding = out.findings[0]
    assert finding.vuln_id == "CVE-2021-23337"
    assert finding.component_key == "purl:pkg:npm/lodash@4.17.15"
    assert finding.engine == "trivy-fs"
    assert finding.ecosystem == "npm"
    assert finding.description.startswith("command injection")
    assert len(finding.cvss) == 1
    assert finding.cvss[0].version == "3.1"
    assert finding.cvss[0].score == 7.2
    assert finding.cvss[0].source == "nvd"
    # Never guessed: CycloneDX's affects[].versions[].status has no clean
    # "fixed" event, so this must stay empty rather than invent an ordering.
    assert finding.fixed_versions == []


def test_cyclonedx_vulnerabilities_with_no_recognised_cvss_method_keep_the_vendor_severity() -> (
    None
):
    payload = {
        "components": [cyclonedx_component("comp-1", "pkg:npm/left-pad@1.3.0")],
        "vulnerabilities": [
            cyclonedx_vuln(
                "GHSA-test-0000",
                ref="comp-1",
                ratings=[{"source": {"name": "cbl-mariner"}, "severity": "medium"}],
            )
        ],
    }

    out = ingest("trivy-image", payload, scan_id="s1")

    assert len(out.findings) == 1
    assert out.findings[0].severity == "medium"
    assert out.findings[0].cvss == []


def test_a_dangling_affects_ref_is_diagnosed_not_silently_dropped() -> None:
    payload = {
        "components": [cyclonedx_component("comp-1", "pkg:npm/lodash@4.17.15")],
        "vulnerabilities": [
            cyclonedx_vuln(
                "CVE-9999-0001",
                ref="comp-does-not-exist",
                ratings=[cyclonedx_rating(method="CVSSv31", score=5.0, severity="medium", source="nvd")],
            )
        ],
    }

    out = ingest("trivy-fs", payload, scan_id="s1")

    assert out.findings == []
    codes = {d["code"] for d in out.diagnostics}
    assert "ENGINE_FIELD_MISSING" in codes


def test_syft_never_sets_vulnerabilities_and_still_ingests_components_only() -> None:
    payload = {"components": [cyclonedx_component("comp-1", "pkg:npm/lodash@4.17.15")]}

    out = ingest("syft", payload, scan_id="s1")

    assert out.findings == []
    assert len(out.contributions) == 1


# -- dependency-check -------------------------------------------------------


def dc_dependency(*, packages=None, vulnerability_ids=None, vulnerabilities=None, **kwargs) -> dict:
    return {
        "fileName": kwargs.pop("file_name", "tomcat.jar"),
        "filePath": kwargs.pop("file_path", "/src/lib/tomcat.jar"),
        "sha256": kwargs.pop("sha256", "a" * 64),
        "packages": packages or [],
        "vulnerabilityIds": vulnerability_ids or [],
        "vulnerabilities": vulnerabilities or [],
        **kwargs,
    }


def test_dependency_check_uses_the_purl_when_one_is_reported() -> None:
    payload = {
        "dependencies": [
            dc_dependency(
                packages=[{"id": "pkg:maven/org.apache.tomcat/tomcat@9.0.71", "confidence": "HIGHEST"}],
                vulnerabilities=[
                    {
                        "name": "CVE-2023-12345",
                        "severity": "HIGH",
                        "cvssv3": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N"},
                        "description": "a real advisory",
                    }
                ],
            )
        ]
    }

    out = ingest("dependency-check", payload, scan_id="s1")

    assert len(out.contributions) == 1
    identity = out.contributions[0].identity
    assert identity.rule == "purl"
    assert identity.key == "purl:pkg:maven/org.apache.tomcat/tomcat@9.0.71"

    assert len(out.findings) == 1
    finding = out.findings[0]
    assert finding.vuln_id == "CVE-2023-12345"
    assert finding.component_key == identity.key
    # 3.0 and 3.1 are structurally identical in this block — "3.1" here comes
    # from the real `CVSS:3.1/...` vector prefix, not an assumed default.
    assert finding.cvss[0].version == "3.1"
    assert finding.cvss[0].score == 7.5
    # dependency-check has no structured "fixed version" concept.
    assert finding.fixed_versions == []


def test_dependency_check_cvss_v3_version_reads_the_explicit_field_when_the_vector_lacks_one() -> None:
    """⚠ REGRESSION GUARD. `cvssData.version` (the newer, NVD-schema-mirroring
    report shape) must be read even when no vector string is present to
    cross-check it against."""
    payload = {
        "dependencies": [
            dc_dependency(
                packages=[{"id": "pkg:maven/org.example/lib@1.0.0", "confidence": "HIGHEST"}],
                vulnerabilities=[
                    {
                        "name": "CVE-2024-00001",
                        "severity": "HIGH",
                        "cvssv3": {"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH", "version": "3.0"}},
                        "description": "an advisory scored under the newer report shape",
                    }
                ],
            )
        ]
    }

    out = ingest("dependency-check", payload, scan_id="s1")

    assert out.findings[0].cvss[0].version == "3.0"


def test_dependency_check_cvss_v3_version_is_never_fabricated() -> None:
    """⚠ REGRESSION GUARD — this replaces a real bug: the version was
    previously hardcoded to "3.1" unconditionally. 3.0 and 3.1 are
    structurally identical in Dependency-Check's `cvssv3` block; when neither
    the vector string nor an explicit `version` field states which one, the
    honest answer is an empty version, never a guess (CLAUDE.md: never
    fabricate a value the source data doesn't actually contain)."""
    payload = {
        "dependencies": [
            dc_dependency(
                packages=[{"id": "pkg:maven/org.example/other@2.0.0", "confidence": "HIGHEST"}],
                vulnerabilities=[
                    {
                        "name": "CVE-2024-00002",
                        "severity": "HIGH",
                        # No vectorString, no cvssData.version — the score is
                        # real, the point release is genuinely unknown.
                        "cvssv3": {"baseScore": 8.8, "baseSeverity": "HIGH"},
                    }
                ],
            )
        ]
    }

    out = ingest("dependency-check", payload, scan_id="s1")

    assert out.findings[0].cvss[0].score == 8.8
    assert out.findings[0].cvss[0].version == ""


def test_dependency_check_falls_back_to_a_candidate_cpe_without_a_purl() -> None:
    """⚠ THE POINT OF THIS ADAPTER. A CPE-only match resolves via identity
    rule 2 (medium confidence, a `cpe:` key) — a DIFFERENT namespace from any
    `purl:` key, so it structurally cannot merge into a PURL-identified
    component even though nothing here explicitly refuses the merge.
    """
    payload = {
        "dependencies": [
            dc_dependency(
                packages=[],
                vulnerability_ids=[
                    {"id": "cpe:2.3:a:apache:tomcat:9.0.71:*:*:*:*:*:*:*", "confidence": "LOW"}
                ],
                vulnerabilities=[{"name": "CVE-2023-99999", "severity": "MEDIUM"}],
            )
        ]
    }

    out = ingest("dependency-check", payload, scan_id="s1")

    assert len(out.contributions) == 1
    identity = out.contributions[0].identity
    assert identity.rule == "cpe"
    assert identity.key.startswith("cpe:")
    assert not identity.key.startswith("purl:")

    assert out.findings[0].component_key == identity.key


def test_dependency_check_cvssv2_only_is_still_captured() -> None:
    payload = {
        "dependencies": [
            dc_dependency(
                packages=[{"id": "pkg:npm/left-pad@1.3.0", "confidence": "HIGHEST"}],
                vulnerabilities=[
                    {
                        "name": "CVE-2010-0001",
                        "cvssv2": {"score": 5.0, "severity": "MEDIUM", "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
                    }
                ],
            )
        ]
    }

    out = ingest("dependency-check", payload, scan_id="s1")

    assert len(out.findings[0].cvss) == 1
    assert out.findings[0].cvss[0].version == "2.0"
    assert out.findings[0].cvss[0].score == 5.0


def test_dependency_check_with_no_dependencies_array_is_diagnosed() -> None:
    out = ingest("dependency-check", {}, scan_id="s1")
    assert out.contributions == []
    assert out.findings == []
    codes = {d["code"] for d in out.diagnostics}
    assert "ENGINE_FIELD_MISSING" in codes


def test_dependency_check_dependency_with_no_identity_evidence_contributes_nothing() -> None:
    payload = {"dependencies": [dc_dependency(packages=[], vulnerability_ids=[])]}

    out = ingest("dependency-check", payload, scan_id="s1")

    assert out.contributions == []
    assert out.findings == []


def test_dependency_check_is_registered_for_the_engine_it_names() -> None:
    from .ingest import _PARSERS, supported_engines

    assert "dependency-check" in _PARSERS
    assert "dependency-check" in supported_engines()


def test_github_dependency_graph_sbom_reuses_the_spdx_parser() -> None:
    """The fetcher unwraps GitHub's `{"sbom": {...}}` envelope before ever
    storing the artifact (services/fetcher/internal/work/work.go), so what
    reaches this dispatch is genuine SPDX 2.3 JSON — identical in shape to
    what syft-spdx already produces. No bespoke parser exists for it, and this
    pins that the registration points at the real, shared one rather than
    silently resolving to no parser at all."""
    from .ingest import _PARSERS, _ingest_spdx, supported_engines

    assert _PARSERS["github-dependency-graph-sbom"] is _ingest_spdx
    assert "github-dependency-graph-sbom" in supported_engines()

    payload = {
        "packages": [
            {
                "SPDXID": "SPDXRef-lodash",
                "name": "lodash",
                "versionInfo": "4.17.21",
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.21"}
                ],
            }
        ]
    }
    out = ingest("github-dependency-graph-sbom", payload, scan_id="s1")
    assert len(out.contributions) == 1
    assert out.contributions[0].identity.purl == "pkg:npm/lodash@4.17.21"


def test_webrecon_fingerprint_is_registered_for_the_engine_it_names() -> None:
    from .ingest import _PARSERS, _ingest_webrecon_fingerprint, supported_engines

    assert _PARSERS["webrecon-fingerprint"] is _ingest_webrecon_fingerprint
    assert "webrecon-fingerprint" in supported_engines()


def test_webrecon_fingerprint_produces_a_contribution_per_library() -> None:
    """AxeBOM's own JSON shape, not CycloneDX/SPDX — services/webrecon has no
    "native" format to reuse a parser from, unlike github-dependency-graph-
    sbom."""
    payload = {
        "schema_version": "axebom-webrecon-json-1",
        "root_url": "https://example.com/",
        "discovery_enabled": True,
        "hosts": [
            {
                "host": "example.com",
                "fetched_url": "https://example.com/",
                "status": "succeeded",
                "libraries": [
                    {"name": "jquery", "version": "3.5.1", "npm_purl": "pkg:npm/jquery@3.5.1"}
                ],
            }
        ],
    }
    out = ingest("webrecon-fingerprint", payload, scan_id="s1")
    assert len(out.contributions) == 1
    c = out.contributions[0]
    assert c.identity.purl == "pkg:npm/jquery@3.5.1"
    assert c.observation.engine == "webrecon-fingerprint"
    assert c.locations[0].path == "https://example.com/"


def test_webrecon_fingerprint_produces_a_finding_from_a_vulnerability() -> None:
    """Version-range evaluation already happened in Go
    (services/webrecon/internal/fingerprint/retire.go's vulnerableAt) before
    this JSON was written — every vulnerabilities[] entry here is already
    applicable, not re-evaluated by this parser."""
    payload = {
        "hosts": [
            {
                "host": "example.com",
                "fetched_url": "https://example.com/",
                "status": "succeeded",
                "libraries": [
                    {
                        "name": "jquery",
                        "version": "1.6.2",
                        "npm_purl": "pkg:npm/jquery@1.6.2",
                        "vulnerabilities": [
                            {
                                "severity": "medium",
                                "cve": ["CVE-2011-4969"],
                                "summary": "XSS with location.hash",
                            }
                        ],
                    }
                ],
            }
        ],
    }
    out = ingest("webrecon-fingerprint", payload, scan_id="s1")
    assert len(out.findings) == 1
    finding = out.findings[0]
    assert finding.vuln_id == "CVE-2011-4969"
    assert finding.component_key == out.contributions[0].identity.key
    assert finding.severity == "medium"


def test_webrecon_fingerprint_falls_back_to_ghsa_when_no_cve_is_present() -> None:
    payload = {
        "hosts": [
            {
                "host": "example.com",
                "fetched_url": "https://example.com/",
                "status": "succeeded",
                "libraries": [
                    {
                        "name": "jquery",
                        "version": "1.6.2",
                        "npm_purl": "pkg:npm/jquery@1.6.2",
                        "vulnerabilities": [{"severity": "medium", "ghsa": "GHSA-579v-mp3v-rrw5"}],
                    }
                ],
            }
        ],
    }
    out = ingest("webrecon-fingerprint", payload, scan_id="s1")
    assert len(out.findings) == 1
    assert out.findings[0].vuln_id == "GHSA-579v-mp3v-rrw5"


def test_webrecon_fingerprint_reports_a_gap_when_the_document_has_no_hosts_array() -> None:
    out = ingest("webrecon-fingerprint", {"schema_version": "axebom-webrecon-json-1"}, scan_id="s1")
    assert out.contributions == []
    assert any(d["code"] == "ENGINE_FIELD_MISSING" for d in out.diagnostics)


def test_webrecon_fingerprint_is_a_finding_engine() -> None:
    """Shared with cluster_store.py's pre-pass — see FINDING_ENGINES' own
    doc comment on why the two modules must not independently drift."""
    from .ingest import FINDING_ENGINES

    assert "webrecon-fingerprint" in FINDING_ENGINES
