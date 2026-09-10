"""The AIBOM normalization pipeline — discovery + enrichment in, canonical model out.

⚠ THE MERGE STEP ALREADY EXISTS, AND IT IS NOT THE SBOM PIPELINE'S MERGE STEP
IN DISGUISE. `../merge.py` reconciles TWO ENGINES that answer different
questions (`ai-bom` discovery: what the code USES; `aibom-generator`
enrichment: what the model IS) — that reconciliation is this BOM type's whole
merge stage, already built before this pipeline module existed. There is no
SBOM-style dependency graph or vulnerability-alias closure to add on top: an AI
model is not a package with transitive dependencies in the SBOM sense, and a
model card is not a CVE. So, like `workers/cbom/normalize/pipeline.py`, this
module has few stages: merge (already done elsewhere), normalize each merged
model into a canonical row (`.ai` already does this), link dependencies against
the SBOM's cataloged components, then score coverage.

⚠ DETERMINISTIC OVER EVERY FIELD, same discipline as CBOM's pipeline and for
the same reason (CLAUDE.md invariant 10): re-normalizing the same discovery +
enrichment output at the same ruleset version must produce byte-identical
`ai_models` and `coverage`, so a normalizer bug fix is a re-normalization pass
over stored artifacts, never a re-scan.

⚠ THE ONE EXCEPTION THAT USED TO LIVE HERE IS GONE.
`provenance.alias_snapshot_id` is now `None` rather than a minted uuid4 —
migration 0012 made the column nullable and gave it a real FK. See
`build_canonical_cbom`'s docstring.

See `docs/03-NORMALIZER-SPEC.md` and `docs/04-OSINT-INTEGRATION.md` for what
`ai-bom`/`aibom-generator` are and how their output maps to canonical.
"""

from __future__ import annotations

from typing import Any

from axebom_shared.model.generated_certin import AIBOM_FIELDS
from axebom_shared.normalize.coverage import CoverageResult, Field, score

from .. import merge
from ..adapters.aibom_generator import ModelCard
from ..profile import operational_fields, operational_meta
from .ai import dependency_scope, link_dependencies, normalize_model

#: Bumped whenever a rule change in THIS package (`ai.py`'s `normalize_model`,
#: `../merge.py`, or this module's assembly) alters output for unchanged input.
#:
#: ⚠ A SEPARATE COUNTER FROM `axebom_shared.normalize.RULESET_VERSION` and from
#: `workers.cbom.normalize.pipeline.RULESET_VERSION`, for the same reason both
#: of those are separate from each other: each BOM type's ruleset evolves on
#: its own schedule, recorded per-document in `normalize.bom_documents
#: .ruleset_version`, and a change to AIBOM's merge/enrichment rules must not
#: be recorded under a version number that also claims something about SBOM or
#: CBOM behaviour it never touched.
RULESET_VERSION = "2026.08.1"

#: The 19 CERT-In Table 10 elements, converted once at import time into the
#: shape `coverage.score` needs. `AIBOM_FIELDS` already excludes the two
#: AxeBOM extensions (`risk_score`, `owasp_llm_top10`) — `.ai`'s
#: `normalize_model` writes those outside its `AIBOM_FIELDS` loop for exactly
#: this reason (its own module docstring) — so no extra filtering is needed
#: here the way CBOM's `profile_fields` filters `CRYPTO_FIELDS_BY_ASSET_TYPE`
#: down to `scored: true` entries.
FIELDS: list[Field] = [
    Field(id=f.id, name=f.name, canonical_path=f.canonical_path, weight=f.weight)
    for f in AIBOM_FIELDS
]


def _flatten(row: dict[str, Any]) -> dict[str, Any]:
    """Map one `normalize_model()` row back onto `coverage.score`'s expected keys.

    The profile's canonical paths for AI model fields are all `ai_model.*`
    (e.g. `ai_model.model_name`); `normalize_model` strips that prefix when it
    builds column names for the `normalize.ai_models` table (see its own
    `column = f.canonical_path.removeprefix("ai_model.")...` line), so scoring
    has to put the prefix back rather than read the bare column name — mirrors
    `workers.cbom.normalize.pipeline._flatten` doing the same job for crypto
    assets against `crypto_asset.*` paths.
    """
    out: dict[str, Any] = {}
    for f in AIBOM_FIELDS:
        column = f.canonical_path.removeprefix("ai_model.").removesuffix("[]")
        out[f.canonical_path.removesuffix("[]")] = row.get(column)
    return out


#: Resolved once at import. The profile is a file on disk that does not change
#: between triggers, and re-reading it per document would put a filesystem read
#: in the hot path for a value that cannot have moved.
_OPERATIONAL_META = operational_meta()


def _flatten_operational(
    row: dict[str, Any],
    assets: list[dict[str, Any]],
    governance: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """One model's row for the OPERATIONAL score.

    ⚠ THE ASSETS ARE DOCUMENT-LEVEL AND ARE SCORED PER MODEL ON PURPOSE. A
    prompt belongs to the repository, not to one model — nothing in any engine's
    output says which model a given prompt is fed to. So a project with prompts
    scores that element for every model in it, which is the honest reading of the
    question being asked: "did we see this AI system's operational shape", where
    the shape is shared. Attributing a prompt to one model would be inventing a
    relationship no tool reported.
    """
    by_type: dict[str, list[str]] = {}
    for asset in assets:
        by_type.setdefault(str(asset.get("asset_type") or ""), []).append(
            str(asset.get("name") or asset.get("asset_key") or "")
        )

    # ⚠ THE PROJECT-WIDE DECLARATION IS THE FALLBACK, NOT THE DEFAULT. An
    # operator who classified the whole project has said something true about
    # every model in it; one who classified a specific model has said something
    # more specific, and that wins. The empty key is where the consumer puts the
    # project-wide entry.
    declared = governance.get(str(row.get("_identity") or "")) or governance.get("") or {}

    return {
        "ai_model.model_key": row.get("_identity"),
        "ai_model.identity_confidence": row.get("identity_confidence"),
        "ai_model.found_by": [
            p.get("engine_id") for p in (row.get("_provenance") or []) if p.get("engine_id")
        ],
        "ai_model.evidence": row.get("evidence"),
        # ⚠ A BOOLEAN False IS A STATED FACT AND COUNTS AS COVERED —
        # `coverage.is_substantive` treats it that way deliberately. "We looked
        # and it did not resolve upstream" is knowledge; absence is not.
        "ai_model.verified": row.get("verified"),
        "ai_model.dependencies": row.get("_dependencies"),
        "ai_assets.prompt": by_type.get("prompt"),
        "ai_assets.vector_store": by_type.get("vector_store"),
        "ai_assets.rag_pipeline": by_type.get("rag_pipeline"),
        # One element covers agents, tools and MCP servers together: the
        # governance question — "through what can this model take an action" —
        # is the same for all three, and three near-empty elements would report
        # three gaps where there is one.
        "ai_assets.agent": (
            (by_type.get("agent") or [])
            + (by_type.get("tool") or [])
            + (by_type.get("mcp_server") or [])
        )
        or None,
        "ai_assets.endpoint": by_type.get("endpoint"),
        "ai_model.eu_ai_act_tier": declared.get("eu_ai_act_tier"),
        "ai_model.nist_ai_rmf": declared.get("nist_ai_rmf"),
        "ai_model.iso_42001": declared.get("iso_42001"),
        "ai_model.attestation_verified": declared.get("attestation_verified"),
    }


def build_canonical_aibom(
    discovery: dict[str, Any],
    cards: dict[str, ModelCard],
    *,
    sbom_component_keys: set[str] | None = None,
    user_values_by_identity: dict[str, dict[str, Any]] | None = None,
    governance_by_identity: dict[str, dict[str, Any]] | None = None,
    ruleset_version: str = RULESET_VERSION,
    scan_id: str = "",
) -> dict[str, Any]:
    """Turn discovery + enrichment output into a canonical AIBOM document
    shaped for `axebom_shared.normalize.writer.write_bom_document`.

    `discovery` is `ai_bom.extract_discovery(...)`'s FULL return value, not
    just its `models` list. This matters: `discovery["frameworks"]` is a
    SCAN-WIDE list of every discovered agent-framework/LLM-provider component,
    not a per-model field, and `.ai.link_dependencies` needs it attached to
    EACH model before it can tell which of that model's framework usages the
    SBOM already catalogues — exactly the shape `test_aibom.py`'s own
    `test_an_ai_dependency_links_to_an_existing_sbom_component` builds by hand
    (`model["frameworks"] = found["frameworks"]`). Building that per-model
    view is this function's job, not the caller's, so every real caller does
    it once instead of each reimplementing the same three-line join.

    `cards` is `enrich_models(...).cards`, keyed by model reference.
    `sbom_component_keys` is the CURRENT SBOM's component key set
    (`purl:...` / bare purl); an empty set (the default) is correct when no
    SBOM exists yet for the project — every dependency is then reported
    `unlinked`, an honest answer rather than a wrong one.
    `user_values_by_identity` carries the four user-supplied Table 10
    elements per model, keyed by `merge.identity()`.

    ⚠ EACH MODEL ROW CARRIES FOUR UNDERSCORE-PREFIXED KEYS
    (`_identity`, `_datasets`, `_dependencies`, `_provenance`) THAT ARE NOT
    `normalize.ai_models` COLUMNS. `bulk._ai_models_batch` must exclude them from the
    columns it writes; `bulk._ai_datasets_batch`/`_ai_model_dependencies_batch`
    read them back off the SAME row list to build their own tables' rows,
    exactly the way `bulk._locations_batch` reads `component.get("locations")`
    off the same `components` list `_components_batch` writes from, rather
    than through a second top-level canonical list. There is nothing else in
    this canonical model that needs to reference an AI model's row (no
    third table joins on it), so — like crypto assets, unlike SBOM components —
    the row's OWN surrogate id is minted here only so its children can carry
    it; `normalize.ai_models.id` itself keeps its schema `DEFAULT
    app.uuid_v7()`, and `_identity` is discarded by `_ai_models_batch`, never
    written to a column.
    """
    sbom_component_keys = sbom_component_keys or set()
    user_values_by_identity = user_values_by_identity or {}
    # What a PERSON declared about each model — the EU AI Act tier, the NIST
    # functions, the ISO categories, whether a recorded attestation verified.
    # Held by `services/aibom` and read by the consumer; never inferred here.
    governance_by_identity = governance_by_identity or {}
    frameworks = discovery.get("frameworks") or []
    # ⚠ THE THINGS THAT ARE NEITHER MODELS NOR DEPENDENCIES, AND THEY USED TO
    # HAVE NOWHERE TO GO. airom and cdxgen-ai report prompts, vector stores, RAG
    # pipelines and inference endpoints; before `normalize.ai_assets` existed
    # (migration 0018) they were extracted and dropped, which invariant 12 rates
    # as worse than not looking. Merged across engines here, on a per-kind key —
    # see `merge.merge_assets` for why a prompt keys on WHERE and a vector store
    # keys on WHAT.
    ai_assets = merge.merge_assets(discovery.get("assets") or [])

    merged, diagnostics = merge.merge(discovery.get("models") or [], cards, scan_id=scan_id)
    # Discovery-level diagnostics (malformed component entries, and so on)
    # must not be silently dropped just because this function's job is
    # normalization, not discovery — a reader of THIS output has no other
    # place to learn a discovery-time parse issue happened at all.
    diagnostics = list(discovery.get("diagnostics") or []) + list(diagnostics)

    models: list[dict[str, Any]] = []
    for model in merged:
        # ⚠ READ, NOT RECOMPUTED. `merge` already derived this and merged on it;
        # deriving it a second time here is what made an opaque-tier model merge
        # under one key and store under another.
        identity = model["_model_key"]
        rule = model["_identity_rule"]
        confidence = model["_identity_confidence"]
        row, datasets, _gaps = normalize_model(
            model, user_values=user_values_by_identity.get(identity)
        )
        linked, unlinked = link_dependencies(
            {**model, "frameworks": frameworks}, sbom_component_keys
        )

        # ⚠ THE MERGE KEY IS NOW STORED, NOT JUST USED. `_identity` used to be
        # transport-only — `bulk.py` read it to mint the row id and then dropped it,
        # so nothing in the database could say whether two rows were the same model.
        # `bulk._ai_models_batch` now persists it as `model_key`; the rule and
        # confidence that produced it are recorded here beside it, because only the
        # ladder knows which tier fired. See migrations/normalize/0016.
        row["identity_rule"] = rule
        row["identity_confidence"] = confidence
        # ⚠ SINGULAR HERE, PLURAL IN `normalize.ai_model_provenance`. This names
        # the engine whose observation this row was BUILT from — the first
        # sighting, which supplied the fields the later ones only confirmed. It
        # is not the whole answer to "who found this model" and must never be
        # rendered as if it were: three engines converge on the same key for the
        # same model, and the provenance table is where all three are recorded.
        row["source_engine"] = model.get("source_engine") or ""
        row["evidence"] = list(model.get("locations") or [])
        # ⚠ NEVER DEFAULTS TO TRUE. `verified` means an engine confirmed the model
        # resolves upstream — today only enrichment can establish that, and
        # enrichment sets it. An unenriched model is unverified, not presumed real.
        row["verified"] = bool(model.get("enriched"))

        row["_identity"] = identity
        row["_datasets"] = datasets
        row["_dependencies"] = linked
        # ⚠ EVERY ENGINE THAT SAW THIS MODEL, NOT JUST THE ONE THAT BUILT THE ROW.
        # Written to `normalize.ai_model_provenance` by `bulk`. Without this key
        # the table stays empty and `source_engine` is the only answer available —
        # which is one answer to a question that has up to three.
        row["_provenance"] = list(model.get("_provenance") or [])
        row["_dependency_scope"] = dependency_scope(model)
        models.append(row)

        if unlinked:
            # ⚠ REPORTED, NOT DROPPED. A framework the model depends on that
            # the SBOM scan did not catalogue is a gap in the SBOM, not a
            # reason to silently omit the dependency from this AIBOM.
            diagnostics.append(
                {
                    "severity": "info",
                    "code": "AIBOM_DEPENDENCY_NOT_IN_SBOM",
                    "message": (
                        f"{row.get('name') or identity}: "
                        f"{len(unlinked)} dependenc{'y' if len(unlinked) == 1 else 'ies'} "
                        f"not catalogued in the SBOM: {', '.join(unlinked)}"
                    ),
                    "hint": "run or re-run an SBOM scan for this project to close the gap",
                }
            )

    # ⚠ SAY WHICH KIND OF CLAIM ELEMENT 06 IS MAKING. When no engine attributed
    # a calling framework to any model, every model's dependency list IS the
    # project's AI library set — which is useful and is not the same statement as
    # "the engine saw this model use these". One diagnostic per document rather
    # than one per model: it is a property of the scan, and repeating it per row
    # would bury the per-model findings around it.
    project_scoped = [m for m in models if m.get("_dependency_scope") == "project"]
    if project_scoped and any(m.get("_dependencies") for m in project_scoped):
        diagnostics.append(
            {
                "severity": "info",
                "code": "AIBOM_DEPENDENCY_SCOPE_PROJECT",
                "message": (
                    f"no engine attributed a calling framework to "
                    f"{len(project_scoped)} of {len(models)} model(s), so their "
                    f"software dependencies are the project's AI libraries rather "
                    f"than libraries observed calling that specific model"
                ),
                "hint": (
                    "the dependency is real and present in this project; what is "
                    "not established is which model uses it"
                ),
            }
        )

    coverage: CoverageResult = score([_flatten(m) for m in models], FIELDS)

    # ⚠ A SECOND NUMBER, AND IT MUST NEVER TOUCH THE FIRST. `coverage` answers
    # "how much of what CERT-In requires is present". This answers "how much of
    # the AI system's operational shape did we manage to see" — a different
    # question with a different authority behind it (ours, not CERT-In's), and
    # merging them would let a customer's diligence about vector stores raise a
    # percentage they hand to a regulator.
    operational = score(
        [_flatten_operational(m, ai_assets, governance_by_identity) for m in models],
        operational_fields(),
    )

    return {
        "ai_models": models,
        # ⚠ NOT SCORED INTO `coverage`, DELIBERATELY. CERT-In Table 10 asks about
        # MODELS; a prompt or a vector store is not one of its elements, and
        # letting these rows move `completeness_pct` would change a compliance
        # percentage by finding something the guideline does not ask for. They
        # are inventory and evidence, rendered in their own section. The
        # operational profile (`aibom-operational-v1.yaml`, M4) is where they
        # will be scored, under its own label and never into these two numbers.
        "ai_assets": ai_assets,
        "coverage": coverage.as_dict(),
        # ⚠ A DIFFERENT NUMBER, UNDER A DIFFERENT KEY, CARRYING ITS OWN LABEL AND
        # AN `is_compliance` FLAG. Keyed by profile id, so a third operational
        # profile needs no schema change, and flagged so no consumer has to know
        # which profile ids are standards. Same shape HBOM's manufacturing score
        # already uses.
        "supplementary_coverage": {
            _OPERATIONAL_META["profile_id"]: {
                **_OPERATIONAL_META,
                **operational.as_dict(),
            }
        },
        "ruleset_version": ruleset_version,
        # AIBOM carries no SPDX license-list concept of its own — `licensing`
        # is a free-text Table 10 element, not an SPDX expression. Empty
        # string, not None: same convention `build_canonical_cbom` uses for
        # this same field, itself matching bulk.py's `_text()` "no value"
        # convention throughout this package.
        "spdx_license_list_version": "",
        "unidentified_count": coverage.unidentified_count,
        # ⚠ None, not a minted uuid4 — see build_canonical_cbom's docstring.
        # migration 0012 made this column nullable and gave it a real FK, so a
        # fabricated id is now rejected as well as meaningless. AIBOM runs no
        # alias closure; None is the value that says so.
        "provenance": {"alias_snapshot_id": None},
        "diagnostics": diagnostics,
    }
