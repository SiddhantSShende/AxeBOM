"""SPDX 3.0 AI profile conversion.

⚠ THE PLAN RECORDED THIS AS BLOCKED, AND THE ASSUMPTION WAS WRONG. It said
"our pinned `spdx-tools` 0.8.x cannot write 3.0.1" and pre-authorised a
LIMITATIONS entry as the fallback. Checked against the installed package:
0.8.5 ships `spdx_tools.spdx3` with `model.ai.AIPackage` and a JSON-LD writer,
and it produces a real document. These tests are the evidence, so the next
session starts from a working converter rather than from the same assumption.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from workers.aibom.spdx3 import NAMESPACE, PROFILES, convert

_REPO = pathlib.Path(__file__).resolve().parents[2]
_MLBOM = _REPO / "services/report/testdata/golden/fixture-aibom.mlbom.cdx.json"

# ⚠ SKIPPED WITHOUT spdx-tools, WHICH IS IN THE `conformance` EXTRA — the same
# posture tools/conformance takes for the CycloneDX and SPDX 2.3 validators. A
# contributor's machine should not need every validator installed to run the
# ordinary suite.
spdx_tools = pytest.importorskip(
    "spdx_tools.spdx3.model.ai",
    reason='spdx-tools not installed — pip install -e ".[conformance]"',
)


def _mlbom() -> dict:
    return json.loads(_MLBOM.read_text(encoding="utf-8"))


def _packages(document: dict) -> list[dict]:
    return [e for e in document.get("@graph") or [] if e.get("@type") == "AIPackage"]


def test_the_mlbom_golden_converts_to_a_real_spdx3_ai_document() -> None:
    """⚠ AGAINST THE COMMITTED ML-BOM, NOT A HAND-BUILT FIXTURE. The input is the
    exact document the report service ships, so a mapping change on either side
    surfaces here rather than in a customer's validator."""
    document = convert(_mlbom())

    packages = _packages(document)
    assert len(packages) == 1, [e.get("@type") for e in document.get("@graph") or []]

    pkg = packages[0]
    assert pkg["creationInfo"]["specVersion"] == "3.0.0"
    assert pkg["creationInfo"]["profile"] == list(PROFILES)
    assert pkg["primaryPurpose"] == "model"


def test_the_fields_spdx_has_and_cyclonedx_does_not_are_populated() -> None:
    """⚠ THIS IS THE ENTIRE REASON FOR A SECOND EXPORT TARGET.

    `typeOfModel`, `informationAboutApplication` and `limitation` are
    first-class in the SPDX AI profile and have no CycloneDX equivalent — in
    CycloneDX the same facts live in `modelCard.considerations`, which is a
    different shape a different set of tools reads. A reviewer asking "what is
    this model FOR, and what must it not do" gets a structured answer here.
    """
    pkg = _packages(convert(_mlbom()))[0]

    assert pkg["typeOfModel"] == ["text-generation"]
    assert "internal triage only" in pkg["informationAboutApplication"]
    assert "never for medical advice" in pkg["limitation"]
    # ⚠ `domain`, NOT `typeOfModel`. An architecture family is not a task, and
    # folding them would put `MatrixForCausalLM` where a consumer expects
    # `text-generation`.
    assert pkg["domain"] == ["MatrixForCausalLM"]


def test_the_discovery_provenance_survives_the_conversion() -> None:
    """SPDX has no field for "which engines found this", and dropping it would
    leave a document that says what a model IS with nothing about how well we
    know it. It travels as a comment rather than being lost."""
    pkg = _packages(convert(_mlbom()))[0]

    comment = pkg.get("comment", "")
    for want in ("found_by=ai-bom, airom", "verified=true", "identity_rule=hf_repo"):
        assert want in comment, comment


def test_nothing_is_invented_where_the_mlbom_says_nothing() -> None:
    """⚠ `NOASSERTION` IS THE FORMAT'S OWN "NOT ASSERTED", AND IT IS NOT A CLAIM.

    SPDX requires `downloadLocation`; we have none for a model discovered in
    source. Emitting a plausible Hugging Face URL would assert a location we
    never found — a document that validates and says something false.
    """
    mlbom = _mlbom()
    for c in mlbom["components"]:
        if c.get("type") == "machine-learning-model":
            c.pop("purl", None)
            c.pop("authors", None)
            c.pop("version", None)

    pkg = _packages(convert(mlbom))[0]

    assert pkg["downloadLocation"] == "NOASSERTION"
    assert pkg["packageVersion"] == "NOASSERTION"
    assert "packageUrl" not in pkg
    # The writer omits an empty list entirely rather than emitting `[]`, which is
    # the same statement in JSON-LD and is the library's own choice.
    assert not pkg.get("suppliedBy")


def test_an_mlbom_with_no_models_is_refused_rather_than_converted() -> None:
    """⚠ IT WOULD DECLARE THE AI PROFILE AND CONTAIN NO AIPackage — a document
    that validates and asserts the project has no AI. The exact failure the
    CycloneDX side already made once, in a second format."""
    with pytest.raises(ValueError, match="contains none"):
        convert({"bomFormat": "CycloneDX", "components": []})


def test_the_conversion_is_deterministic() -> None:
    """⚠ NOT A CLOCK READ. Two conversions of one document must produce the same
    bytes — the rule ADR-0003 puts on every other export, and the reason the
    report worker passes the scan's time everywhere rather than reading `now`."""
    first = json.dumps(convert(_mlbom()), sort_keys=True)
    second = json.dumps(convert(_mlbom()), sort_keys=True)
    assert first == second


def test_every_identifier_is_a_uri_and_none_pretends_to_resolve() -> None:
    """An SPDX id has to be a URI. Minting an `https://` one would imply a
    document a reader can fetch; `urn:` says the opposite, honestly."""
    pkg = _packages(convert(_mlbom()))[0]

    assert pkg["@id"].startswith(NAMESPACE)
    assert NAMESPACE.startswith("urn:")
    for agent in pkg["suppliedBy"]:
        assert agent.startswith("urn:")
