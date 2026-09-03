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
from .ai import link_dependencies, normalize_model

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


def build_canonical_aibom(
    discovery: dict[str, Any],
    cards: dict[str, ModelCard],
    *,
    sbom_component_keys: set[str] | None = None,
    user_values_by_identity: dict[str, dict[str, Any]] | None = None,
    ruleset_version: str = RULESET_VERSION,
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

    ⚠ EACH MODEL ROW CARRIES THREE UNDERSCORE-PREFIXED KEYS
    (`_identity`, `_datasets`, `_dependencies`) THAT ARE NOT `normalize
    .ai_models` COLUMNS. `bulk._ai_models_batch` must exclude them from the
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
    frameworks = discovery.get("frameworks") or []

    merged, diagnostics = merge.merge(discovery.get("models") or [], cards)
    # Discovery-level diagnostics (malformed component entries, and so on)
    # must not be silently dropped just because this function's job is
    # normalization, not discovery — a reader of THIS output has no other
    # place to learn a discovery-time parse issue happened at all.
    diagnostics = list(discovery.get("diagnostics") or []) + list(diagnostics)

    models: list[dict[str, Any]] = []
    for model in merged:
        identity = merge.identity(model)
        row, datasets, _gaps = normalize_model(
            model, user_values=user_values_by_identity.get(identity)
        )
        linked, unlinked = link_dependencies(
            {**model, "frameworks": frameworks}, sbom_component_keys
        )

        row["_identity"] = identity
        row["_datasets"] = datasets
        row["_dependencies"] = linked
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

    coverage: CoverageResult = score([_flatten(m) for m in models], FIELDS)

    return {
        "ai_models": models,
        "coverage": coverage.as_dict(),
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
