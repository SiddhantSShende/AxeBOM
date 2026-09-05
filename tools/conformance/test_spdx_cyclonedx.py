"""Validate AxeBOM's exported documents against the OFFICIAL SPDX and
CycloneDX schemas/validators — not our own serializer's opinion of itself.

WHY THIS IS SEPARATE FROM `task test`

`cyclonedx-python-lib` and `spdx-tools` are real, useful, and NOT something
every contributor's machine needs installed to run the ordinary test suite —
the same reasoning `workers/*/test_golden.py` is only run via a dedicated
Taskfile target, never by the default `pytest libs/py-shared` invocation.
Install the extra with:

    pip install -e ".[conformance]"

then run:

    task test:conformance

WHAT THIS PROVES AND WHAT IT DOES NOT

These are the golden fixtures `services/report/internal/export` already
produces byte-reproducibly (ADR-0003) — this does not re-render anything, it
validates what the exporter is already committed to shipping. A pass here
means "a real SPDX/CycloneDX tool accepts this file"; it says nothing about
whether the CONTENT is complete (that is `task profile:lint` and the coverage
numbers) — only that the SYNTAX is one an official consumer will parse.
"""

from pathlib import Path

import pytest

GOLDEN_DIR = Path(__file__).resolve().parents[2] / "services" / "report" / "testdata" / "golden"

cyclonedx_validation = pytest.importorskip(
    "cyclonedx.validation.json",
    reason='cyclonedx-python-lib[json-validation] not installed — pip install -e ".[conformance]"',
)
cyclonedx_schema = pytest.importorskip("cyclonedx.schema")

spdx_parser = pytest.importorskip(
    "spdx_tools.spdx.parser.parse_anything",
    reason='spdx-tools not installed — pip install -e ".[conformance]"',
)
spdx_validator = pytest.importorskip("spdx_tools.spdx.validation.document_validator")


#: Every committed document, discovered rather than listed.
#:
#: ⚠ THIS USED TO NAME TWO FILES, AND BOTH WERE SOFTWARE BOMs. The CBOM, AIBOM
#: and QBOM exports did not exist at all — SPDX and CycloneDX emitted a valid,
#: EMPTY document for those three types — and when they were built, a
#: hand-listed set here would have been the second place to forget them. A glob
#: cannot be forgotten; a list can.
CDX_GOLDENS = sorted(GOLDEN_DIR.glob("*.cdx.json"))
SPDX_GOLDENS = sorted(GOLDEN_DIR.glob("*.spdx.json"))


def test_the_golden_directory_is_not_empty():
    """⚠ A GLOB THAT MATCHES NOTHING PARAMETRIZES ZERO TESTS AND REPORTS GREEN.

    Every assertion below would silently stop running if the directory moved or
    the naming changed, and the suite would keep passing. This is the check that
    the checks are running.
    """
    assert len(CDX_GOLDENS) >= 4, f"only {len(CDX_GOLDENS)} CycloneDX goldens found"
    assert len(SPDX_GOLDENS) >= 4, f"only {len(SPDX_GOLDENS)} SPDX goldens found"


@pytest.mark.parametrize("path", CDX_GOLDENS, ids=lambda p: p.name)
def test_the_cyclonedx_golden_fixture_validates_against_the_official_schema(path):
    validator = cyclonedx_validation.JsonStrictValidator(cyclonedx_schema.SchemaVersion.V1_6)

    result = validator.validate_str(path.read_text())

    assert result is None, f"{path.name}: CycloneDX 1.6 schema violations:\n{result}"


@pytest.mark.parametrize("path", SPDX_GOLDENS, ids=lambda p: p.name)
def test_the_spdx_golden_fixture_validates_against_the_official_spec(path):
    document = spdx_parser.parse_file(str(path))
    errors = spdx_validator.validate_full_spdx_document(document)

    assert not errors, f"{path.name}:\n" + "\n".join(str(e) for e in errors)
