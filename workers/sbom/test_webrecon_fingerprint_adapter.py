"""webrecon-fingerprint — real discovery, never an import, no sandbox.

The adapter has no sandbox and no container, so it is tested directly against
ScanTarget rather than through the sandbox-invocation machinery every other
SBOM adapter's tests exercise — the same shape
test_github_dependency_graph_adapter.py already established for the sibling
that is closest to this one architecturally.
"""

from __future__ import annotations

import json
from pathlib import Path

from axebom_shared.adapters.base import ResultStatus, ScanTarget

from .adapters.webrecon_fingerprint import CAPABILITIES, WebreconFingerprintAdapter


def target(tmp_path: Path, native_sbom_path: Path | None) -> ScanTarget:
    return ScanTarget(
        scan_id="scan-1",
        job_id="job-1",
        kind="url",
        workspace=tmp_path / "ws",
        native_sbom_path=native_sbom_path,
    )


def adapter(tmp_path: Path) -> WebreconFingerprintAdapter:
    return WebreconFingerprintAdapter(sandbox=None, artifact_dir=tmp_path / "out")


def webrecon_doc(hosts: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": "axebom-webrecon-json-1",
        "root_url": "https://example.com/",
        "discovery_enabled": True,
        "hosts": hosts,
    }


def host_with_library(name: str, version: str, **extra: object) -> dict[str, object]:
    return {
        "host": "example.com",
        "fetched_url": "https://example.com/",
        "status": "succeeded",
        "libraries": [
            {
                "name": name,
                "version": version,
                "npm_purl": f"pkg:npm/{name}@{version}",
                **extra,
            }
        ],
    }


# -- available() --------------------------------------------------------


def test_available_is_always_true_it_is_an_environment_fact_not_a_per_job_one(
    tmp_path: Path,
) -> None:
    """Whether THIS scan's document was staged is answered in generate(), not
    here — available() is about the environment, which never lacks this
    "engine": services/webrecon already did the work, this adapter just
    reads it back.
    """
    assert adapter(tmp_path).available().available is True


# -- generate(): missing input --------------------------------------------


def test_generate_reports_unavailable_when_no_document_was_staged(tmp_path: Path) -> None:
    result = adapter(tmp_path).generate(target(tmp_path, None))
    assert result.status == ResultStatus.UNAVAILABLE
    assert result.diagnostics[0]["code"] == "ENGINE_INPUT_MISSING"


def test_generate_reports_unavailable_when_the_staged_path_does_not_exist(tmp_path: Path) -> None:
    missing = tmp_path / "never-written.json"
    result = adapter(tmp_path).generate(target(tmp_path, missing))
    assert result.status == ResultStatus.UNAVAILABLE
    assert result.diagnostics[0]["code"] == "ENGINE_INPUT_MISSING"


# -- generate(): happy path ------------------------------------------------


def test_generate_succeeds_and_counts_libraries_across_hosts(tmp_path: Path) -> None:
    doc = webrecon_doc(
        [
            host_with_library("jquery", "3.5.1"),
            {
                "host": "sub.example.com",
                "fetched_url": "https://sub.example.com/",
                "status": "succeeded",
                "libraries": [
                    {"name": "lodash", "version": "4.17.15", "npm_purl": "pkg:npm/lodash@4.17.15"}
                ],
            },
        ]
    )
    staged = tmp_path / "webrecon.json"
    staged.write_text(json.dumps(doc))

    result = adapter(tmp_path).generate(target(tmp_path, staged))

    assert result.status == ResultStatus.SUCCEEDED
    assert result.summary is not None
    assert result.summary.components == 2
    assert len(result.artifacts) == 1


def test_generate_carries_vulnerabilities_through_unmodified(tmp_path: Path) -> None:
    """The adapter itself does not re-evaluate version ranges — that already
    happened in Go — it only stages the document. This proves the artifact
    (what _ingest_webrecon_fingerprint later reads) still has the
    vulnerability the fixture put there.
    """
    doc = webrecon_doc(
        [
            host_with_library(
                "jquery",
                "1.6.2",
                vulnerabilities=[
                    {
                        "severity": "medium",
                        "cve": ["CVE-2011-4969"],
                        "summary": "XSS with location.hash",
                    }
                ],
            )
        ]
    )
    staged = tmp_path / "webrecon.json"
    staged.write_text(json.dumps(doc))

    result = adapter(tmp_path).generate(target(tmp_path, staged))
    assert result.status == ResultStatus.SUCCEEDED

    written = json.loads((tmp_path / "out" / "webrecon-fingerprint.json").read_bytes())
    lib = written["hosts"][0]["libraries"][0]
    assert lib["vulnerabilities"][0]["cve"] == ["CVE-2011-4969"]


# -- generate(): honest degradation ----------------------------------------


def test_generate_is_partial_not_succeeded_when_zero_libraries_found(tmp_path: Path) -> None:
    doc = webrecon_doc(
        [
            {
                "host": "example.com",
                "fetched_url": "https://example.com/",
                "status": "succeeded",
                "libraries": [],
            }
        ]
    )
    staged = tmp_path / "webrecon.json"
    staged.write_text(json.dumps(doc))

    result = adapter(tmp_path).generate(target(tmp_path, staged))

    assert result.status == ResultStatus.PARTIAL
    assert result.summary.components == 0
    assert any(d["code"] == "ENGINE_ZERO_RESULTS" for d in result.diagnostics)


def test_generate_notes_unreachable_hosts_without_failing_the_scan(tmp_path: Path) -> None:
    doc = webrecon_doc(
        [
            host_with_library("jquery", "3.5.1"),
            {
                "host": "down.example.com",
                "fetched_url": "https://down.example.com/",
                "status": "unreachable",
                "error": "connection refused",
                "libraries": [],
            },
        ]
    )
    staged = tmp_path / "webrecon.json"
    staged.write_text(json.dumps(doc))

    result = adapter(tmp_path).generate(target(tmp_path, staged))

    assert result.status == ResultStatus.SUCCEEDED  # one host still succeeded
    assert any(d["code"] == "WEBRECON_HOST_UNREACHABLE" for d in result.diagnostics)


def test_generate_fails_cleanly_on_unparseable_json(tmp_path: Path) -> None:
    staged = tmp_path / "webrecon.json"
    staged.write_text("{not valid json")

    result = adapter(tmp_path).generate(target(tmp_path, staged))

    assert result.status == ResultStatus.FAILED
    assert result.diagnostics[0]["code"] == "ENGINE_OUTPUT_UNPARSEABLE"


def test_generate_reports_the_gap_when_the_document_has_no_hosts_array(tmp_path: Path) -> None:
    staged = tmp_path / "webrecon.json"
    staged.write_text(json.dumps({"schema_version": "axebom-webrecon-json-1"}))

    result = adapter(tmp_path).generate(target(tmp_path, staged))

    assert result.status == ResultStatus.PARTIAL
    assert result.diagnostics[0]["code"] == "ENGINE_FIELD_MISSING"


# -- capabilities -----------------------------------------------------------


def test_capabilities_declare_url_source_and_no_import_claim() -> None:
    """RequiresImport is deliberately absent — this is real discovery, not an
    import of a foreign document. See the module docstring and
    services/scan-orchestrator/internal/policy/registry.go's own comment on
    this exact distinction.
    """
    assert CAPABILITIES.source_kinds == ("url",)
    assert CAPABILITIES.engine_id == "webrecon-fingerprint"
