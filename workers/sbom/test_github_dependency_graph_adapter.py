"""github-dependency-graph-sbom — an import, not discovery, and never required.

The adapter has no sandbox and no container, so it is tested directly against
ScanTarget rather than through the sandbox-invocation machinery every other
SBOM adapter's tests exercise.
"""

from __future__ import annotations

import json
from pathlib import Path

from axebom_shared.adapters.base import ResultStatus, ScanTarget

from .adapters.github_dependency_graph import CAPABILITIES, GitHubDependencyGraphAdapter


def target(tmp_path: Path, native_sbom_path: Path | None) -> ScanTarget:
    return ScanTarget(
        scan_id="scan-1",
        job_id="job-1",
        kind="git",
        workspace=tmp_path / "ws",
        native_sbom_path=native_sbom_path,
    )


def adapter(tmp_path: Path) -> GitHubDependencyGraphAdapter:
    return GitHubDependencyGraphAdapter(sandbox=None, artifact_dir=tmp_path / "out")


def spdx_document(packages: list[dict[str, object]]) -> dict[str, object]:
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "com.github.acme/widgets",
        "packages": packages,
    }


def with_purl(name: str, version: str, purl: str) -> dict[str, object]:
    return {
        "SPDXID": f"SPDXRef-{name}",
        "name": name,
        "versionInfo": version,
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        ],
    }


# -- available() --------------------------------------------------------


def test_available_is_always_true_it_is_an_environment_fact_not_a_per_job_one(
    tmp_path: Path,
) -> None:
    """Whether THIS scan's document was staged is answered in generate(), not
    here — available() is about the environment, which never lacks this
    "engine": it is an API call the fetcher already made, not a tool to
    install."""
    a = adapter(tmp_path)
    availability = a.available()
    assert availability.available is True
    assert availability.mode.value == "internal"


# -- generate(): the input-missing path ----------------------------------


def test_generate_reports_unavailable_when_no_document_was_staged(tmp_path: Path) -> None:
    """The overwhelmingly common case: not a GitHub repo, Dependency Graph
    disabled, or the fetcher's API call failed. Must read as a stated gap, not
    a scan failure."""
    a = adapter(tmp_path)
    result = a.generate(target(tmp_path, native_sbom_path=None))

    assert result.status == ResultStatus.UNAVAILABLE
    codes = [d["code"] for d in result.diagnostics]
    assert "ENGINE_INPUT_MISSING" in codes
    assert result.artifacts == []


def test_generate_reports_unavailable_when_the_staged_path_does_not_exist(tmp_path: Path) -> None:
    """native_sbom_path can be set but the fetch that was supposed to produce
    it can still have failed after the fact — is_file() is checked, not just
    None-ness."""
    a = adapter(tmp_path)
    missing = tmp_path / "never-written.json"
    result = a.generate(target(tmp_path, native_sbom_path=missing))

    assert result.status == ResultStatus.UNAVAILABLE
    assert [d["code"] for d in result.diagnostics] == ["ENGINE_INPUT_MISSING"]


# -- generate(): a real staged document -----------------------------------


def test_generate_succeeds_and_counts_only_packages_with_a_purl(tmp_path: Path) -> None:
    doc = spdx_document(
        [
            with_purl("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),
            with_purl("left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0"),
            # The document root: names the repo itself, carries no PURL —
            # must not be counted as a dependency.
            {"SPDXID": "SPDXRef-DOCUMENT", "name": "com.github.acme/widgets"},
        ]
    )
    staged = tmp_path / "staged.json"
    staged.write_text(json.dumps(doc), encoding="utf-8")

    a = adapter(tmp_path)
    result = a.generate(target(tmp_path, native_sbom_path=staged))

    assert result.status == ResultStatus.SUCCEEDED, result.diagnostics
    assert result.summary.components == 2
    assert len(result.artifacts) == 1
    assert result.artifacts[0].role == "native_output"
    assert result.artifacts[0].media_type == "application/spdx+json"
    # The stored artifact is the document AS STAGED, verbatim — no
    # re-serialization that could silently change what the evidence says.
    assert json.loads(result.artifacts[0].path.read_bytes()) == doc


def test_generate_is_partial_not_succeeded_when_zero_packages_have_a_purl(tmp_path: Path) -> None:
    """Zero is a claim. A document that parses fine but names nothing
    resolvable must not read as a clean, fully-covered result."""
    doc = spdx_document([{"SPDXID": "SPDXRef-DOCUMENT", "name": "com.github.acme/widgets"}])
    staged = tmp_path / "staged.json"
    staged.write_text(json.dumps(doc), encoding="utf-8")

    a = adapter(tmp_path)
    result = a.generate(target(tmp_path, native_sbom_path=staged))

    assert result.status == ResultStatus.PARTIAL
    assert result.summary.components == 0
    assert any(d["code"] == "ENGINE_ZERO_RESULTS" for d in result.diagnostics)


def test_generate_fails_cleanly_on_unparseable_json(tmp_path: Path) -> None:
    """A tool that changes its output shape must degrade loudly, never crash
    the worker — the contract every parser in this codebase honors."""
    staged = tmp_path / "staged.json"
    staged.write_text("{not valid json", encoding="utf-8")

    a = adapter(tmp_path)
    result = a.generate(target(tmp_path, native_sbom_path=staged))

    assert result.status == ResultStatus.FAILED
    assert [d["code"] for d in result.diagnostics] == ["ENGINE_OUTPUT_UNPARSEABLE"]
    # The unparseable bytes are still preserved as evidence.
    assert len(result.artifacts) == 1


def test_generate_reports_the_gap_when_the_document_has_no_packages_array(tmp_path: Path) -> None:
    staged = tmp_path / "staged.json"
    staged.write_text(json.dumps({"spdxVersion": "SPDX-2.3"}), encoding="utf-8")

    a = adapter(tmp_path)
    result = a.generate(target(tmp_path, native_sbom_path=staged))

    assert result.status == ResultStatus.PARTIAL
    assert [d["code"] for d in result.diagnostics] == ["ENGINE_FIELD_MISSING"]


# -- capabilities honesty -------------------------------------------------


def test_capabilities_declare_import_only_source_kinds() -> None:
    """git only: GitHub's Dependency Graph has no meaning for an upload or a
    bare image, and offering it there would be a combination that can never
    actually produce a document."""
    assert CAPABILITIES.source_kinds == ("git",)
    assert CAPABILITIES.produces == ("components",)
