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


def test_the_cyclonedx_golden_fixture_validates_against_the_official_schema():
    validator = cyclonedx_validation.JsonStrictValidator(cyclonedx_schema.SchemaVersion.V1_6)
    document = (GOLDEN_DIR / "fixture.cdx.json").read_text()

    result = validator.validate_str(document)

    assert result is None, f"CycloneDX 1.6 schema violations:\n{result}"


# ⚠ THIS IS EXPECTED TO FAIL, ON PURPOSE, UNTIL THE EXPORTER IS FIXED.
#
# services/report/internal/export builds every protobom Node's Id straight
# from the canonical component_key (export.go's toNode, fed by
# render.Component.Key) — which is deliberately shaped like `purl:pkg:...`
# for the NORMALIZER's own dedup purposes, not for SPDX's identifier syntax.
# The SPDX 2.3 spec allows an SPDXID at most ONE colon, reserved for the
# `DocumentRef-X:SPDXRef-Y` external-reference form; ours carries two or more,
# because a PURL itself contains colons. CycloneDX's `bom-ref` has no such
# restriction, which is exactly why the test above passes on the SAME
# underlying key and this one does not — the bug is SPDX-specific.
#
# xfail, not skip: a silent pass here the day someone fixes toNode's id
# generation is a signal worth seeing (XPASS), not something to miss because
# the test was never running.
@pytest.mark.xfail(
    reason="export.go's toNode() feeds the raw component_key (colon-bearing, "
    "e.g. 'purl:pkg:maven/...') straight into the protobom Node.Id used for "
    "every SPDX PackageSPDXIdentifier/relationship reference. SPDX 2.3 permits "
    "at most one colon in an SPDXID. Found by this conformance check; not yet "
    "fixed — see docs/STATE.md.",
    strict=True,
)
def test_the_spdx_golden_fixture_validates_against_the_official_spec():
    document = spdx_parser.parse_file(str(GOLDEN_DIR / "fixture.spdx.json"))
    errors = spdx_validator.validate_full_spdx_document(document)

    assert not errors, "\n".join(str(e) for e in errors)
