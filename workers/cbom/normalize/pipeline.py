"""The CBOM normalization pipeline — every engine's raw crypto assets in, one canonical model out.

⚠ FOUR STAGES, AND THE MERGE IS NEW.

    1. identity   each raw asset gets an `asset_key` (identity.py; 03 §1.6)
    2. merge      raw assets sharing a key become one: evidence kept per engine,
                  list fields unioned, scalars taken by a per-engine trust order,
                  every disagreement diagnosed — never silently resolved
    3. normalize  crypto.py once per MERGED asset: type-discriminated columns,
                  the analysis, and the cited reference values — so a verdict is
                  computed from everything every engine reported, once
    4. assemble   certificate inheritance by asset key, provenance, coverage

There was no merge while cbomkit-theia was the only engine, and the module used to
say "add one only when a second crypto-discovery engine actually exists". Source
discovery (cbomkit-action, cdxgen's cbom preset) is that engine: without this
stage an algorithm both engines report would be listed twice, with two verdicts
and no way to tell they were the same thing.

⚠ DETERMINISTIC OVER EVERY FIELD (CLAUDE.md invariant 10): the same raw artifacts
at the same ruleset produce byte-identical `crypto_assets` and `coverage`, in any
input order, so a normalizer fix is a re-normalization of stored artifacts, never
a re-scan. Every collection below is sorted before it is emitted.

⚠ `alias_snapshot_id` IS `None`. CBOM has no alias-closure concept; migration 0012
made the column nullable, so nothing is minted to satisfy it.

See docs/03-NORMALIZER-SPEC.md §1.6 (identity) and §5.3 (coverage), and
docs/04-OSINT-INTEGRATION.md for each engine.
"""

from __future__ import annotations

from typing import Any

from axebom_shared.crypto.reference import derivation_sources
from axebom_shared.model.generated_certin import CRYPTO_FIELDS_BY_ASSET_TYPE
from axebom_shared.normalize.coverage import CoverageResult, Field, score_crypto
from axebom_shared.normalize.crypto_status import derived_counts, scored_entity, scored_path

from .crypto import TYPE_COLUMNS, normalize_crypto_asset
from .identity import AssetIdentity, asset_identity

#: Bumped whenever a rule change in THIS package (crypto.py's analyse(), or
#: this module's assembly) alters output for unchanged input.
#:
#: ⚠ A SEPARATE COUNTER FROM axebom_shared.normalize.RULESET_VERSION, ON
#: PURPOSE. That constant versions the SBOM pipeline's merge/graph/alias rules;
#: each BOM type's ruleset evolves on its own schedule and is recorded in
#: normalize.bom_documents.ruleset_version per document.
#:
#: 2026.09.1 — list-valued fields scored (the `[]` suffix), `not-provided`
#: counted as declared, post-quantum/EdDSA/ECB/PKCS#1 v1.5/protocol-version and
#: `unassessed` deprecation verdicts, CERT-In values derived from the cited
#: reference table (user decision 2026-09-11: derive + count, labelled), and the
#: asset_key identity, cross-engine merge, evidence and per-engine provenance.
RULESET_VERSION = "2026.09.1"

#: ⚠ PINNED TO RULESET_VERSION. The reference table (axebom_shared.crypto
#: .reference) changes output for unchanged input, so editing it must bump
#: RULESET_VERSION; test_pipeline.py fails until this digest is updated WITH a
#: new version (invariant 10: replay must be reproducible per ruleset).
REFERENCE_DIGEST = "a29ab64ee4def4fe6f3f1a75f0857ad596b60f7017c15a02dcff253762c54b76"


def profile_fields(asset_type: str) -> list[Field]:
    """Build the scored `Field` objects for one CERT-In Table 9 asset type.

    ⚠ DERIVED FROM THE COMPLIANCE PROFILE, NEVER HAND-TYPED (invariant 2).
    `CRYPTO_FIELDS_BY_ASSET_TYPE` is pre-filtered to `scored: true` entries, so
    the AxeBOM analysis columns never appear here and never move either number.
    """
    return [
        # ⚠ `scored_path`, NOT `f.canonical_path`. The profile writes list-valued
        # paths as `crypto_asset.crypto_functions[]`, and the `[]` is notation.
        # Passed through verbatim, `score_crypto` looked every list field up
        # under a key no asset carries: Crypto Functions, the algorithm List and
        # Cipher Suites scored zero on every CBOM while the stored field_status
        # (which did strip the suffix) said `provided`.
        Field(
            id=f.id,
            name=f.name,
            canonical_path=scored_path(f.canonical_path),
            weight=f.weight,
        )
        for f in CRYPTO_FIELDS_BY_ASSET_TYPE[asset_type]
    ]


#: One `Field` list per `asset_type` — each asset is scored against only ITS
#: type's field set (invariant 5); the union would report every CBOM at ~30%.
FIELD_SETS: dict[str, list[Field]] = {
    asset_type: profile_fields(asset_type) for asset_type in CRYPTO_FIELDS_BY_ASSET_TYPE
}


def _flatten(asset: dict[str, Any]) -> dict[str, Any]:
    """The mapping `score_crypto` reads for one asset — `crypto_status.scored_entity`.

    ⚠ IT USED TO PASS ONLY THE VALUES `crypto.py` KEPT, so a field the stored
    `field_status` records as `not-provided` never counted as declared, and every
    CBOM published `declaration_pct == completeness_pct`. The writer and this
    scorer input now come from one module.
    """
    return scored_entity(asset)


#: Which engine's value wins a scalar disagreement, per asset type.
#:
#: ⚠ A RANKING OF WHO READ THE THING, NOT OF WHICH TOOL IS "BETTER". Code is where
#: an algorithm's parameters are chosen, so an engine that read
#: `Cipher.getInstance("AES/GCM/NoPadding")` knows the mode better than one that
#: saw a certificate. A key or a certificate is read from the file that holds it,
#: which theia does. Unknown engines rank after these, alphabetically.
_TRUST: dict[str, tuple[str, ...]] = {
    "algorithm": ("cbomkit-action", "cdxgen-cbom", "cbomkit-theia"),
    "protocol": ("cbomkit-action", "cdxgen-cbom", "cbomkit-theia"),
    "key": ("cbomkit-theia", "cbomkit-action", "cdxgen-cbom"),
    "certificate": ("cbomkit-theia", "cbomkit-action", "cdxgen-cbom"),
}

#: Unioned, never picked: two engines seeing different functions of one
#: algorithm are both right.
_LIST_FIELDS = ("crypto_functions", "cipher_suites", "algorithm_list", "certification_level")

#: Per-contribution facts that are merged by their own rules below, never as
#: ordinary scalars.
_PER_CONTRIBUTION = frozenset(
    {
        "evidence",
        "related_refs",
        "native_ref",
        "observed_name",
        "engine_id",
        "engine_version",
        "artifact_sha256",
        "description",
        "surface",
    }
)

#: Fields whose disagreement is worth a diagnostic: the CERT-In columns and the
#: inputs that decide a verdict.
_CONFLICT_FIELDS = frozenset(
    {column for columns in TYPE_COLUMNS.values() for column in columns}
    | {"padding", "curve", "parameter_set", "material_type"}
) - {"name", *_LIST_FIELDS}

#: Non-CERT-In facts kept on the row as `attributes` — evidence, never scored.
_ATTRIBUTE_FIELDS = (
    "padding",
    "curve",
    "parameter_set",
    "algorithm_family",
    "nist_quantum_security_level",
    "execution_environment",
    "implementation_platform",
    "certification_level",
    "material_type",
    "material_format",
    "expiration_date",
    "protocol_type",
    "cert_serial",
    "cert_fingerprint",
    "public_key_fingerprint",
    "material_fingerprint",
)

_EMPTY: tuple[Any, ...] = (None, "", [], {})


def build_canonical_cbom(
    raw_assets: list[dict[str, Any]],
    *,
    ruleset_version: str = RULESET_VERSION,
) -> dict[str, Any]:
    """Turn every engine's extracted crypto assets into one canonical CBOM
    document shaped for `axebom_shared.normalize.writer.write_bom_document`.

    Each raw asset may carry `engine_id`, `engine_version` and `artifact_sha256`
    (the consumer stamps them); without them it is treated as one unnamed engine.
    """
    diagnostics: list[dict[str, Any]] = []

    raw_assets = _with_algorithm_names(raw_assets)
    identities = [asset_identity(raw, _engine(raw)) for raw in raw_assets]

    # An engine's references (a certificate's signatureAlgorithmRef) point at its
    # OWN bom-refs, which are random per run — so they are resolved to asset keys
    # here, inside the document that minted them, and never stored raw.
    ref_to_key: dict[tuple[str, str], str] = {}
    for raw, identity in zip(raw_assets, identities, strict=True):
        ref = raw.get("native_ref")
        if ref:
            ref_to_key.setdefault((_engine(raw), ref), identity.key)

    groups: dict[str, list[dict[str, Any]]] = {}
    identity_by_key: dict[str, AssetIdentity] = {}
    for raw, identity in zip(raw_assets, identities, strict=True):
        groups.setdefault(identity.key, []).append(raw)
        identity_by_key.setdefault(identity.key, identity)

    assets: list[dict[str, Any]] = []
    for key in sorted(groups, key=lambda k: (str(groups[k][0].get("asset_type")), k)):
        contributions = sorted(groups[key], key=_order)
        merged, conflicts = _merge(key, contributions)
        diagnostics.extend(conflicts)
        _resolve_refs(merged, contributions, ref_to_key)

        try:
            asset = normalize_crypto_asset(merged)
        except ValueError as exc:
            diagnostics.append(
                {
                    "severity": "warn",
                    "code": "NORMALIZE_CRYPTO_ASSET_TYPE_UNKNOWN",
                    "message": str(exc),
                }
            )
            continue

        identity = identity_by_key[key]
        asset["asset_key"] = key
        asset["identity_rule"] = identity.rule
        asset["identity_confidence"] = identity.confidence
        asset["evidence"] = _evidence(contributions)
        asset["attributes"] = _attributes(merged, contributions)
        asset["_provenance"] = _provenance(contributions)
        for transport in ("_signature_key", "_public_key_key", "_algorithm_key"):
            if merged.get(transport):
                asset[transport] = merged[transport]
        assets.append(asset)

    _resolve_certificate_analysis(assets, diagnostics)
    _flag_private_keys(assets, diagnostics)

    coverage: CoverageResult = score_crypto([_flatten(a) for a in assets], FIELD_SETS)

    # ⚠ DERIVED VALUES ARE COUNTED AND CITED IN THE BREAKDOWN, FOR CBOM ONLY.
    # A value filled from the reference table counts as present (user decision
    # 2026-09-11), so the reader must see how many of each field's "present" came
    # from AxeBOM's lookup and from which source. Added here rather than in
    # coverage.py because the SBOM breakdown shape is pinned by its goldens.
    breakdown = coverage.as_dict()
    counts = derived_counts(assets)
    for field in breakdown["fields"]:
        field["derived"] = counts.get(field["field_id"], 0)
    breakdown["derivation_sources"] = derivation_sources(assets)

    return {
        "crypto_assets": assets,
        "coverage": breakdown,
        "ruleset_version": ruleset_version,
        # CBOM carries no SPDX license concept. Empty string, not None: the
        # column is `text NOT NULL`.
        "spdx_license_list_version": "",
        "unidentified_count": coverage.unidentified_count,
        "provenance": {"alias_snapshot_id": None},
        "diagnostics": diagnostics,
    }


def _engine(raw: dict[str, Any]) -> str:
    return str(raw.get("engine_id") or "")


def _with_algorithm_names(raw_assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Copies of the raw assets, each key carrying the NAME of the algorithm its
    engine says it belongs to, as `algorithm_name`.

    ⚠ A KEY IS OFTEN NAMED FOR NOTHING. cbomkit-action calls the key from
    `KeyPairGenerator.getInstance("RSA")` just `key`; its algorithm is known only
    through the reference. The name feeds the key's identity (`alg=`) and its
    analysis — an RSA key judged on the word `key` was reported not
    quantum-vulnerable. Resolved per engine: a reference means something only
    inside the document that minted it. The inputs are never mutated.
    """
    names = {
        (_engine(raw), str(raw["native_ref"])): str(raw.get("name") or "")
        for raw in raw_assets
        if raw.get("native_ref") and raw.get("asset_type") == "algorithm"
    }
    out: list[dict[str, Any]] = []
    for raw in raw_assets:
        copy = dict(raw)
        ref = raw.get("key_algorithm_ref")
        if raw.get("asset_type") == "key" and ref:
            name = names.get((_engine(raw), str(ref)), "")
            if name:
                copy["algorithm_name"] = name
        out.append(copy)
    return out


def _order(raw: dict[str, Any]) -> tuple[int, str, str, str]:
    """Trust rank for the asset's type, then a stable tie-break."""
    trust = _TRUST.get(str(raw.get("asset_type") or ""), ())
    engine = _engine(raw)
    rank = trust.index(engine) if engine in trust else len(trust)
    return (rank, engine, str(raw.get("native_ref") or ""), str(raw.get("observed_name") or ""))


def _merge(
    key: str, contributions: list[dict[str, Any]]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """One raw asset from every contribution sharing `key`, in trust order."""
    merged: dict[str, Any] = {}
    source: dict[str, str] = {}
    conflicts: list[dict[str, Any]] = []

    for contribution in contributions:
        engine = _engine(contribution) or "unnamed engine"
        for field, value in contribution.items():
            if field in _PER_CONTRIBUTION or field.startswith("_"):
                continue
            if field in _LIST_FIELDS:
                merged[field] = sorted(set(merged.get(field) or []) | set(value or []))
                continue
            if value in _EMPTY:
                continue
            if merged.get(field) in _EMPTY:
                merged[field] = value
                source[field] = engine
            elif field in _CONFLICT_FIELDS and _differs(merged[field], value):
                conflicts.append(
                    {
                        "severity": "warn",
                        "code": "NORMALIZE_CRYPTO_FIELD_CONFLICT",
                        "message": (
                            f"{key}: {field} is {merged[field]!r} from {source[field]} and "
                            f"{value!r} from {engine}; {source[field]}'s value is kept"
                        ),
                        "hint": (
                            "the engine ranked first for this asset type wins, and the "
                            "disagreement is reported rather than resolved silently"
                        ),
                    }
                )

    merged["native_ref"] = contributions[0].get("native_ref") or ""
    return merged, conflicts


def _differs(a: Any, b: Any) -> bool:
    return str(a).strip().lower() != str(b).strip().lower()


def _resolve_refs(
    merged: dict[str, Any],
    contributions: list[dict[str, Any]],
    ref_to_key: dict[tuple[str, str], str],
) -> None:
    """Resolve a certificate's and a key's references to asset keys, per engine."""
    targets = (
        ("signature_algo_ref", "_signature_key"),
        ("subject_public_key_ref", "_public_key_key"),
        ("key_algorithm_ref", "_algorithm_key"),
    )
    for field, transport in targets:
        for contribution in contributions:
            ref = contribution.get(field)
            resolved = ref_to_key.get((_engine(contribution), ref)) if ref else None
            if resolved:
                merged[transport] = resolved
                break


def _evidence(contributions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every location every engine saw this asset at: [{path, line, engine}]."""
    seen: set[tuple[str, int | None, str]] = set()
    for contribution in contributions:
        for entry in contribution.get("evidence") or []:
            path = entry.get("path") or ""
            if path:
                seen.add((path, entry.get("line"), _engine(contribution)))
    return [
        {"path": path, "line": line, "engine": engine}
        for path, line, engine in sorted(seen, key=lambda t: (t[0], t[1] or 0, t[2]))
    ]


def _attributes(merged: dict[str, Any], contributions: list[dict[str, Any]]) -> dict[str, Any]:
    """Non-CERT-In facts about the asset. Evidence only; never scored."""
    attributes = {f: merged[f] for f in _ATTRIBUTE_FIELDS if merged.get(f) not in _EMPTY}
    surfaces = sorted({str(c["surface"]) for c in contributions if c.get("surface")})
    if surfaces:
        attributes["surfaces"] = surfaces
    # ⚠ ONLY AN ENGINE THAT READS KEY FILES CAN SAY A KEY IS IN THE SOURCE.
    # cbomkit-action reports `KeyPairGenerator.getInstance("RSA")` as `secret-key`
    # material with a size — a key the code GENERATES at runtime, not one sitting
    # in the repository (measured on crypto-mixed, 2026-09-11). Flagging that
    # would accuse a repository of committing a key it never contained.
    material = str(merged.get("material_type") or "")
    read_from_a_file = any(_engine(c) in _MATERIAL_ENGINES for c in contributions)
    if read_from_a_file and material == "private-key":
        attributes["private_key_in_source"] = True
    elif read_from_a_file and material in {"secret-key", "symmetric-key"}:
        attributes["secret_key_in_source"] = True
    return attributes


#: Engines that find key MATERIAL in files (cbomkit-theia's certificate and
#: secrets plugins), as opposed to key USE in code.
_MATERIAL_ENGINES = frozenset({"cbomkit-theia"})


def _provenance(contributions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One entry per engine: what it called the asset and where it saw it."""
    by_engine: dict[str, dict[str, Any]] = {}
    for contribution in contributions:
        engine = _engine(contribution) or "unknown"
        entry = by_engine.setdefault(
            engine,
            {
                "engine_id": engine,
                "engine_version": str(contribution.get("engine_version") or ""),
                "artifact_sha256": str(contribution.get("artifact_sha256") or ""),
                "native_refs": set(),
                "observed_names": set(),
                "evidence": set(),
            },
        )
        if contribution.get("native_ref"):
            entry["native_refs"].add(str(contribution["native_ref"]))
        if contribution.get("observed_name"):
            entry["observed_names"].add(str(contribution["observed_name"]))
        for item in contribution.get("evidence") or []:
            if item.get("path"):
                entry["evidence"].add((item["path"], item.get("line")))

    return [
        {
            "engine_id": engine,
            "engine_version": entry["engine_version"],
            "artifact_sha256": entry["artifact_sha256"],
            "native_ref": min(entry["native_refs"]) if entry["native_refs"] else "",
            "observed_name": min(entry["observed_names"]) if entry["observed_names"] else "",
            "evidence": [
                {"path": path, "line": line}
                for path, line in sorted(entry["evidence"], key=lambda t: (t[0], t[1] or 0))
            ],
        }
        for engine, entry in sorted(by_engine.items())
    ]


#: Copied from the referenced signing algorithm onto its certificate. Every one
#: of these is an AxeBOM-analysis key `crypto.py:analyse()` produces per asset.
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
    """Give a certificate the verdict of what SIGNED it, and name its references.

    ⚠ FOUND ONLY BY RUNNING AGAINST REAL ENGINE OUTPUT. A certificate's own
    analyse() pattern-matches its raw `signature_algo_ref`, which for real
    cbomkit-theia output is an opaque bom-ref UUID that matches no rule — so an
    RSA-signed certificate came back `quantum_vulnerable=False`, the false
    negative invariant 12 exists to prevent. The reference is resolved to the
    sibling's asset key (see `_resolve_refs`), and the sibling's already-correct
    verdict is copied — one computation of a verdict, never two.

    A dangling reference leaves the certificate's own (unassessed) verdict alone,
    keeps the raw reference as evidence, and adds a diagnostic rather than guessing.
    """
    by_key = {asset["asset_key"]: asset for asset in assets}

    for asset in assets:
        algorithm_key = asset.pop("_algorithm_key", "")
        if algorithm_key in by_key:
            asset["attributes"]["algorithm_key"] = algorithm_key

        if asset.get("asset_type") != "certificate":
            continue

        signer_key = asset.pop("_signature_key", "")
        public_key_key = asset.pop("_public_key_key", "")
        signer = by_key.get(signer_key) if signer_key else None

        if signer is not None:
            for key in _INHERITED_ANALYSIS_KEYS:
                if key in signer:
                    asset[key] = signer[key]
                else:
                    asset.pop(key, None)
            # ⚠ CLEARED, NOT CARRIED OVER: the certificate's own failed-match
            # note no longer describes anything true once the signer's real
            # verdict replaces it.
            asset.pop("analysis_diagnostics", None)
            asset["signature_algo_ref"] = signer.get("name") or asset.get("signature_algo_ref")
            asset["attributes"]["signature_algorithm_key"] = signer_key
        elif asset.get("signature_algo_ref"):
            diagnostics.append(_unresolved(asset, "signature_algo_ref"))

        target = by_key.get(public_key_key) if public_key_key else None
        if target is not None:
            asset["subject_public_key_ref"] = target.get("name") or asset.get(
                "subject_public_key_ref"
            )
            asset["attributes"]["subject_public_key_key"] = public_key_key
        elif asset.get("subject_public_key_ref"):
            diagnostics.append(_unresolved(asset, "subject_public_key_ref"))


def _unresolved(asset: dict[str, Any], field: str) -> dict[str, Any]:
    return {
        "severity": "warn",
        "code": "NORMALIZE_CRYPTO_ASSET_REF_UNRESOLVED",
        "message": (
            f"certificate {asset.get('name') or asset.get('asset_key')!r} references "
            f"{field}={asset.get(field)!r}, which does not match any asset in this document"
        ),
        "hint": "left as the raw reference and its verdict left unassessed, rather than guessed",
    }


def _flag_private_keys(assets: list[dict[str, Any]], diagnostics: list[dict[str, Any]]) -> None:
    """⚠ A PRIVATE KEY IN THE SCANNED SOURCE IS A FINDING, not just an inventory row.

    cbomkit-theia said so in its own words ("Identified a Private Key, which may
    compromise cryptographic security") and the description was dropped. The key
    material itself is never read or stored; the paths are the finding.
    """
    paths = sorted(
        {
            entry["path"]
            for asset in assets
            if asset["attributes"].get("private_key_in_source")
            for entry in asset["evidence"]
        }
    )
    count = sum(1 for a in assets if a["attributes"].get("private_key_in_source"))
    if not count:
        return
    shown = ", ".join(paths[:20]) + (f" and {len(paths) - 20} more" if len(paths) > 20 else "")
    diagnostics.append(
        {
            "severity": "warn",
            "code": "CBOM_PRIVATE_KEY_IN_SOURCE",
            "message": f"{count} private key(s) found in the scanned source: {shown or 'no path reported'}",
            "hint": (
                "a private key in a repository, upload or image is readable by everyone "
                "who can read that source; rotate it and remove it, including from "
                "history. AxeBOM never reads or stores the key material itself."
            ),
        }
    )
