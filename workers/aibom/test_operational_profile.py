"""The AIBOM operational surface — a second scored field set, and its guardrails.

⚠ THE ONE THING THAT MUST NEVER HAPPEN IS THAT THIS NUMBER TOUCHES THE OTHER
TWO. `completeness_pct` and `declaration_pct` answer "how much of what CERT-In
requires is present" and are what a customer hands to a regulator. This profile
answers "how much of the AI system's operational shape did we manage to see",
with AxeBOM's authority behind it and nobody else's.
"""

from __future__ import annotations

import json
import pathlib

import yaml
from workers.aibom.adapters.airom import extract_airom_discovery
from workers.aibom.normalize.pipeline import build_canonical_aibom
from workers.aibom.profile import operational_fields, operational_meta

from axebom_shared.model.generated_certin import AIBOM_FIELDS

_REPO = pathlib.Path(__file__).resolve().parents[2]
_PROFILE = _REPO / "docs/reference/aibom-operational-v1.yaml"


def _discovery() -> dict:
    raw = json.loads(
        (pathlib.Path(__file__).parent / "testdata" / "airom-ai-langchain.cdx.json").read_text(
            encoding="utf-8"
        )
    )
    found = extract_airom_discovery(raw)
    for bucket in ("models", "frameworks", "assets"):
        for item in found[bucket]:
            item["source_engine"] = "airom"
    return {
        "models": found["models"],
        "frameworks": found["frameworks"],
        "assets": found["assets"],
    }


def test_the_operational_score_never_touches_the_compliance_numbers() -> None:
    """⚠ TWO SCORES FROM ONE DOCUMENT, AND ONLY ONE OF THEM IS COMPLIANCE.

    Merging them would let a customer's diligence about vector stores raise a
    percentage they hand to a regulator — the same failure
    `hbom-manufacturing-v1.yaml` exists to prevent on the hardware side.
    """
    canonical = build_canonical_aibom(_discovery(), {})

    compliance = canonical["coverage"]
    supplementary = canonical["supplementary_coverage"]["aibom-operational-v1"]

    assert supplementary["is_compliance"] is False
    assert supplementary["label"] == "AI operational surface"
    # Different questions, different answers. Equal by coincidence would be
    # fine; the assertion that matters is that the operational one is REPORTED
    # separately and carries its own identity.
    assert supplementary["profile_id"] == "aibom-operational-v1"
    assert set(compliance) & {"completeness_pct", "declaration_pct"}
    assert "completeness_pct" in supplementary


def test_the_operational_score_reflects_what_the_engines_actually_found() -> None:
    """A repository with prompts, a vector store and a RAG pipeline scores above
    one with none of them. If it did not, the number would be measuring nothing.
    """
    rich = build_canonical_aibom(_discovery(), {})
    bare = build_canonical_aibom(
        {
            "models": [{"model_ref": "org/m", "name": "m", "provider": "huggingface"}],
            "frameworks": [],
            "assets": [],
        },
        {},
    )

    rich_pct = rich["supplementary_coverage"]["aibom-operational-v1"]["completeness_pct"]
    bare_pct = bare["supplementary_coverage"]["aibom-operational-v1"]["completeness_pct"]
    assert rich_pct > bare_pct, (rich_pct, bare_pct)


def test_an_operators_declaration_is_scored_and_never_inferred() -> None:
    """⚠ THE EU AI ACT TIER COMES FROM A PERSON OR IT DOES NOT EXIST.

    Whether a system is high-risk depends on what it is USED FOR, which no
    repository shows. Deriving a tier from an import statement would manufacture
    a legal conclusion out of a dependency graph. So the element scores zero
    until somebody declares one — and rises when they do.
    """
    discovery = _discovery()
    without = build_canonical_aibom(discovery, {})
    with_tag = build_canonical_aibom(
        discovery,
        {},
        governance_by_identity={
            "": {
                "eu_ai_act_tier": "limited",
                "nist_ai_rmf": ["GOVERN"],
                "iso_42001": ["A.5 Assessing impacts of AI systems"],
                "attestation_verified": True,
            }
        },
    )

    a = without["supplementary_coverage"]["aibom-operational-v1"]["completeness_pct"]
    b = with_tag["supplementary_coverage"]["aibom-operational-v1"]["completeness_pct"]
    assert b > a, (a, b)


def test_no_operational_element_shares_an_id_with_a_certin_element() -> None:
    """⚠ A SHARED ID WOULD MAKE ONE NUMBER SILENTLY OVERWRITE THE OTHER'S ENTRY.

    Both scores are dictionaries keyed by field id, and they are rendered side
    by side. Two fields with one id is a report where a compliance element's
    coverage is quietly replaced by an AxeBOM one's.
    """
    certin = {f.id for f in AIBOM_FIELDS}
    operational = {f.id for f in operational_fields()}
    assert not (certin & operational)
    # And the prefixes make the distinction visible to a reader, not only to a
    # set operation.
    assert all(f.id.startswith("axebom.") for f in operational_fields())
    assert all(f.id.startswith("certin.") for f in AIBOM_FIELDS)


def test_the_profile_is_copied_into_the_image_that_reads_it() -> None:
    """⚠ IT IS READ AT RUNTIME, SO A MISSING COPY IS A CRASH ON THE FIRST TRIGGER.

    `workers/aibom/profile.py` reads this YAML from disk. The normalize-consumer
    container has no copy of `docs/` unless the Dockerfile puts one there, and
    the failure mode is `FileNotFoundError` on the first AIBOM normalization in
    production rather than anything at build time — the identical trap the HBOM
    manufacturing profile's own COPY line records.
    """
    dockerfile = (_REPO / "deploy/docker/Dockerfile.normalize-consumer").read_text(encoding="utf-8")
    assert "docs/reference/aibom-operational-v1.yaml" in dockerfile


def test_every_element_is_something_that_can_actually_be_filled() -> None:
    """⚠ A FIELD NOTHING CAN FILL MEASURES US, NOT THE CUSTOMER.

    It scores zero for everyone for ever, and it reads on the report as the
    customer's gap. The profile's own header lists what was deliberately left
    out for this reason; this asserts the positive half — every element's
    canonical path is one the pipeline actually produces.
    """
    produced = {
        "ai_model.model_key",
        "ai_model.identity_confidence",
        "ai_model.found_by",
        "ai_model.evidence",
        "ai_model.verified",
        "ai_model.dependencies",
        "ai_assets.prompt",
        "ai_assets.vector_store",
        "ai_assets.rag_pipeline",
        "ai_assets.agent",
        "ai_assets.endpoint",
        "ai_model.eu_ai_act_tier",
        "ai_model.nist_ai_rmf",
        "ai_model.iso_42001",
        "ai_model.attestation_verified",
    }
    declared = {f.canonical_path for f in operational_fields()}
    assert declared == produced, {
        "in the profile but never produced": sorted(declared - produced),
        "produced but not scored": sorted(produced - declared),
    }


def test_the_profile_declares_itself_operational() -> None:
    """`kind: operational` is what stops the compliance linter holding this file
    to rules it has no authority behind — and, conversely, what makes the linter
    refuse it if it ever grows a CERT-In section."""
    raw = yaml.safe_load(_PROFILE.read_text(encoding="utf-8"))
    assert raw["profile"]["kind"] == "operational"
    assert raw["profile"]["authority"] == "AxeBOM"
    # No PDF to cite, and claiming one would be a provenance claim with nothing
    # behind it.
    assert "source_document" not in raw["profile"]
    assert operational_meta()["is_compliance"] is False
