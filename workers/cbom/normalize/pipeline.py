"""The CBOM normalization pipeline — raw crypto assets in, canonical model out.

⚠ THIS IS THE SBOM PIPELINE'S ROLE, DELIBERATELY SHRUNK.

`libs/py-shared/axebom_shared/normalize/pipeline.py` runs seven ordered stages
(ingest, merge, graph, alias closure, findings, coverage, provenance) because
software components genuinely need deduplication across engines, a dependency
graph, and vulnerability alias closure. A crypto asset needs none of that:
`cbomkit-theia` is the only engine that produces `cryptoProperties` today, so
there is nothing to merge two engines' views of, no dependency edges between
crypto assets, and no vulnerability-alias concept — a certificate is not a CVE.
So this module has exactly two stages: normalize each asset (crypto.py already
does this, type-discrimination and all), then score coverage. Do not add a
merge/graph/alias step here just to mirror the SBOM shape; add one only when a
second crypto-discovery engine actually exists and two engines' assets need
reconciling.

⚠ DETERMINISTIC OVER EVERY FIELD, same discipline as the SBOM pipeline and for
the same reason (CLAUDE.md invariant 10): re-normalizing the same raw
`cbomkit-theia` output at the same ruleset version must produce byte-identical
`crypto_assets` and `coverage`, so a normalizer bug fix is a re-normalization
pass over stored artifacts, never a re-scan.

⚠ THERE USED TO BE ONE EXCEPTION, AND THERE NO LONGER IS.
`provenance.alias_snapshot_id` was minted fresh with `uuid.uuid4()` on every
call, because the column was `uuid NOT NULL` and CBOM has no alias snapshot to
point at. `migrations/normalize/0012_bom_document_provenance.sql` made it
nullable with a real foreign key, so the field is now `None` and this pipeline
replays byte-for-byte in every field. See `build_canonical_cbom`'s docstring.

See `docs/03-NORMALIZER-SPEC.md` and `docs/04-OSINT-INTEGRATION.md` for what
`cbomkit-theia` is and how its output maps to canonical.
"""

from __future__ import annotations

from typing import Any

from axebom_shared.model.generated_certin import CRYPTO_FIELDS_BY_ASSET_TYPE
from axebom_shared.normalize.coverage import CoverageResult, Field, score_crypto

from .crypto import normalize_all

#: Bumped whenever a rule change in THIS package (crypto.py's analyse(), or
#: this module's assembly) alters output for unchanged input.
#:
#: ⚠ A SEPARATE COUNTER FROM axebom_shared.normalize.RULESET_VERSION, ON
#: PURPOSE. That constant versions the SBOM pipeline's merge/graph/alias
#: rules; CBOM has none of those stages, so a change to (say) the quantum-
#: vulnerability heuristics in axebom_shared.crypto must not be recorded
#: under a version number that also claims something about SBOM dedup
#: behaviour it never touched. Each BOM type's ruleset evolves on its own
#: schedule and is recorded in normalize.bom_documents.ruleset_version
#: per-document, which is exactly the field this feeds.
RULESET_VERSION = "2026.08.1"


def profile_fields(asset_type: str) -> list[Field]:
    """Build the scored `Field` objects for one CERT-In Table 9 asset type.

    ⚠ DERIVED FROM THE COMPLIANCE PROFILE, NEVER HAND-TYPED (CLAUDE.md
    invariant 2). This used to be a test-only helper duplicated inside
    `test_crypto_normalize.py`; it is real pipeline code now because
    `build_canonical_cbom` needs the exact same field sets `score_crypto`
    scores against — computing them only in a test module would leave the
    actual write path with no coverage numbers to publish at all.

    `CRYPTO_FIELDS_BY_ASSET_TYPE` is already pre-filtered to `scored: true`
    entries only (see its own comment in generated_certin.py) — the three
    AxeBOM analysis columns (`quantum_vulnerable`, `pqc_recommendation`,
    `deprecation_status`) never appear here, which is what keeps them out of
    both coverage numbers.
    """
    return [
        Field(id=f.id, name=f.name, canonical_path=f.canonical_path, weight=f.weight)
        for f in CRYPTO_FIELDS_BY_ASSET_TYPE[asset_type]
    ]


#: One `Field` list per `asset_type`, built once at import time from the
#: profile. `score_crypto` needs this shape — `dict[asset_type, list[Field]]`
#: — to score each asset against only ITS type's field set (CLAUDE.md
#: invariant 5); scoring every asset against the union would report every
#: CBOM at roughly 30% coverage, falsely, in a compliance document.
FIELD_SETS: dict[str, list[Field]] = {
    asset_type: profile_fields(asset_type) for asset_type in CRYPTO_FIELDS_BY_ASSET_TYPE
}


def _flatten(asset: dict[str, Any]) -> dict[str, Any]:
    """Flatten one canonical crypto asset onto `score_crypto`'s expected keys.

    The profile's canonical paths for crypto fields are all `crypto_asset.*`
    (e.g. `crypto_asset.key_size`) — see `CRYPTO_FIELDS_BY_ASSET_TYPE` — so
    scoring needs that prefix rather than the bare column name `crypto.py`
    stores the value under. This mirrors `axebom_shared.normalize.pipeline
    ._flatten` doing the same job for components against `component.*` paths.
    """
    return {f"crypto_asset.{key}": value for key, value in asset.items()}


def build_canonical_cbom(
    raw_assets: list[dict[str, Any]],
    *,
    ruleset_version: str = RULESET_VERSION,
) -> dict[str, Any]:
    """Turn `cbomkit_theia.extract_crypto_assets`'s output into a canonical CBOM
    document shaped for `axebom_shared.normalize.writer.write_bom_document`.

    ⚠ NO MERGE, NO GRAPH, NO ALIAS CLOSURE — see the module docstring for why
    CBOM genuinely does not need the SBOM pipeline's other five stages today.

    ⚠ `alias_snapshot_id` IS `None`, AND IT USED TO BE A MINTED UUID.

    CBOM has no alias-closure concept at all — that machinery reconciles
    vulnerability identifiers across scanners (`CVE-2021-44228` ==
    `GHSA-jfh8-c2jp-5v3q`), an SBOM idea with nothing to correspond to in a
    certificate or an algorithm. The column was `uuid NOT NULL` for every
    `bom_type`, so this function (and the AIBOM one, and the Go QBOM/HBOM
    writers) minted a fresh uuid4 that satisfied the constraint and meant
    nothing.

    `migrations/normalize/0012_bom_document_provenance.sql` made the column
    nullable and gave it the foreign key it never had. Both halves matter: a
    fabricated id would now be REJECTED rather than merely meaningless, and
    `None` is the honest value — it declines to assert, where a minted id
    asserted to anyone joining `bom_documents -> alias_snapshot` that a
    snapshot had been consulted.

    It also makes this function deterministic in every field, which is what
    CLAUDE.md invariant 10 actually asks for — the previous behaviour was a
    documented exception that no longer needs to exist.
    """
    assets, asset_diagnostics = normalize_all(raw_assets)
    _resolve_certificate_analysis(assets, asset_diagnostics)

    coverage: CoverageResult = score_crypto([_flatten(a) for a in assets], FIELD_SETS)

    return {
        "crypto_assets": assets,
        "coverage": coverage.as_dict(),
        "ruleset_version": ruleset_version,
        # CBOM carries no SPDX license concept — no crypto asset field is a
        # license. Empty string, not None: the column is `text NOT NULL`
        # (migrations/normalize/0001_bom_components.sql), same convention
        # bulk.py's own `_text()` uses for "no value" everywhere else in this
        # package.
        "spdx_license_list_version": "",
        "unidentified_count": coverage.unidentified_count,
        "provenance": {"alias_snapshot_id": None},
        # ⚠ NOT YET WIRED TO ANYTHING. bulk.plan() (SBOM side) never reads a
        # top-level canonical["diagnostics"] either — see its own module for
        # where scan-level diagnostics actually surface today. Carried here
        # so the extraction/normalization diagnostics are not silently
        # dropped by whatever caller assembles this dict, even though nothing
        # downstream in THIS phase persists them yet.
        "diagnostics": asset_diagnostics,
    }


#: Copied from the referenced signing algorithm onto its certificate. Every
#: one of these is an AxeBOM-analysis key `crypto.py:analyse()` already
#: produces per-asset — see `_resolve_certificate_analysis` for why the
#: certificate's OWN copy of them, computed by `analyse()` before this
#: function ever runs, is wrong in practice and must be overwritten.
_INHERITED_ANALYSIS_KEYS = (
    "quantum_vulnerable",
    "quantum_family",
    "quantum_rationale",
    "deprecation_status",
    "deprecation_rationale",
    "deprecation_reference",
    "quantum_readiness_group",
    "pqc_recommendation",
    "grover_note",
    "effective_quantum_bits",
)


def _resolve_certificate_analysis(
    assets: list[dict[str, Any]], diagnostics: list[dict[str, Any]]
) -> None:
    """Give a certificate the quantum/deprecation verdict of what SIGNED it,
    and rewrite its `signature_algo_ref`/`subject_public_key_ref` from
    cbomkit-theia's internal `bom-ref` to the referenced asset's name.

    ⚠ FOUND ONLY BY RUNNING AGAINST REAL ENGINE OUTPUT, NOT A HAND-BUILT
    FIXTURE, AND IT IS THE MORE SERIOUS OF TWO BUGS THAT SHAPE.

    `crypto.py:analyse()` already intends exactly this — its own comment says
    "For a certificate, the interesting primitive is what SIGNED it" — but it
    tries to do it by reading `signature_algo_ref` OFF THE RAW, UN-NORMALIZED
    ASSET and pattern-matching it as if it were an algorithm name. That works
    by accident against `test_crypto_normalize.py`'s hand-built fixture,
    which sets `signatureAlgorithmRef` to a readable string
    (`"crypto/algorithm/sha256-rsa"`, which contains "rsa" and happens to
    match `assess_quantum`'s regex). Real cbomkit-theia output sets it to the
    engine's own internal `bom-ref` — an opaque UUID like
    `"b21f7408-6344-4ea2-a317-541fa2579d3e"` — which matches no rule at all.
    The result on a live, openssl-generated, SHA256-RSA-signed certificate:
    `quantum_vulnerable=False`, `deprecation_status="current"`, and a buried
    diagnostic saying "not assessed" — which is invariant-12's exact false-
    negative failure mode, not a rendering nicety. `analyse()` cannot fix this
    itself: it normalizes one asset at a time and has no view of the sibling
    algorithm asset the reference points to. Fixing it needs a document-level
    pass, which is what this function is, run once `normalize_all` has
    produced every asset in the document.

    Overwrites the certificate's own (wrong) analysis with the REFERENCED
    algorithm's already-correct one — never re-derives it — for the same
    reason `derive.py`'s `readiness_group` centralization exists elsewhere in
    this package: one computation of a verdict, never two that can disagree.
    A dangling or unresolved reference leaves the certificate's own
    (unassessed) verdict alone and adds a diagnostic, rather than guessing.

    The display-name rewrite of the two ref fields runs SECOND, using the raw
    bom-ref to look the referenced asset up one more time — doing it first
    would destroy the key this function's own lookup depends on.
    """
    asset_by_ref = {asset["component_key"]: asset for asset in assets if asset.get("component_key")}
    name_by_ref = {ref: asset["name"] for ref, asset in asset_by_ref.items() if asset.get("name")}

    for asset in assets:
        if asset.get("asset_type") != "certificate":
            continue

        signer_ref = asset.get("signature_algo_ref")
        signer = asset_by_ref.get(signer_ref) if signer_ref else None
        if signer is not None:
            for key in _INHERITED_ANALYSIS_KEYS:
                if key in signer:
                    asset[key] = signer[key]
                else:
                    asset.pop(key, None)
            # ⚠ CLEARED, NOT CARRIED OVER. This is the certificate's OWN
            # per-asset analyse() diagnostic — almost always "no quantum rule
            # matches" the raw bom-ref it tried and failed to pattern-match —
            # and it no longer describes anything true once the line above
            # replaces that failed guess with the signer's real verdict. A
            # stale "not assessed" note sitting next to `quantum_vulnerable:
            # true` reads as the tool contradicting itself.
            asset.pop("analysis_diagnostics", None)
        elif signer_ref:
            diagnostics.append(
                {
                    "severity": "warn",
                    "code": "NORMALIZE_CRYPTO_ASSET_REF_UNRESOLVED",
                    "message": (
                        f"certificate {asset.get('name') or asset.get('component_key')!r} "
                        f"references signature_algo_ref={signer_ref!r}, which does not "
                        f"match any asset in this document"
                    ),
                    "hint": (
                        "its own quantum/deprecation verdict is left as unassessed "
                        "rather than guessed"
                    ),
                }
            )

        # ⚠ NAME REWRITE COMES AFTER THE ANALYSIS INHERITANCE ABOVE, which
        # keys on the RAW bom-ref (`signer_ref`) to find `signer` in
        # `asset_by_ref`. Rewriting `signature_algo_ref` to a display name
        # first would make that lookup fail on every certificate.
        for field in ("signature_algo_ref", "subject_public_key_ref"):
            ref = asset.get(field)
            if not ref:
                continue
            resolved = name_by_ref.get(ref)
            if resolved is not None:
                asset[field] = resolved
            else:
                diagnostics.append(
                    {
                        "severity": "warn",
                        "code": "NORMALIZE_CRYPTO_ASSET_REF_UNRESOLVED",
                        "message": (
                            f"certificate {asset.get('name') or asset.get('component_key')!r} "
                            f"references {field}={ref!r}, which does not match any "
                            f"asset in this document"
                        ),
                        "hint": "left as the raw bom-ref rather than blanked",
                    }
                )
