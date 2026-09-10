"""Bulk insertion of the canonical model.

⚠ 50k+ COMPONENTS AND 200k+ FINDINGS PER SCAN IS NORMAL for a large monorepo.

Row-by-row INSERT at that size is not slow, it is unusable — and the failure
mode is a scan that appears to hang.

⚠ AND `COPY` DOES NOT EXIST AS AN OPTION HERE, WHICH IS NOT OBVIOUS UNTIL YOU
TRY IT.

Postgres refuses `COPY FROM` outright against any table with row-level
security enabled — `FeatureNotSupported: COPY FROM not supported with
row-level security. HINT: Use INSERT statements instead.` This is not a
version quirk or a permissions gap to work around: it is permanent, and RLS
is FORCE-enabled on every tenant table in this system (CLAUDE.md invariant
6), which every table this module writes to is. So `COPY` was never actually
available for this write path, regardless of anything in this file.

The workable shape instead is a CHUNKED, multi-row `INSERT ... VALUES (...),
(...), ...` — still one round trip per few hundred rows rather than one per
row, and, unlike `COPY`, it runs the ordinary INSERT path RLS's `WITH CHECK`
evaluates per row. This module only PLANS the batches — see
`libs/py-shared/axebom_shared/normalize/writer.py` for where they turn
into chunked INSERT statements and get executed.

⚠ AND THE CAP IS LOUD, NEVER SILENT.

Above the ceiling the run is REFUSED with a diagnostic rather than truncated.
A silently truncated BOM is the worst possible artifact: it looks complete, it
is smaller than the truth, and every component past the cut-off is a false
negative the customer trusts.

⚠ HOSTILE VALUES ARE SANITIZED HERE, at the storage boundary.

A NUL byte silently truncates a Postgres text value — the row inserts, nothing
errors, and the stored string is a prefix of the real one. By the time it is
read back the information is gone, so it has to be cleaned before the write.

See `docs/03-NORMALIZER-SPEC.md` §8.
"""

from __future__ import annotations

import datetime
import json
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from .identity import normalize_path

#: Namespace for surrogate row ids this module mints itself. Arbitrary and
#: fixed — see `_component_id` for why it has to be fixed at all.
_SURROGATE_NAMESPACE = uuid.UUID("f3cb4a2b-3d98-4d07-94d6-75efd23b2f4b")

#: Refuse rather than truncate above this many components.
MAX_COMPONENTS = 250_000

#: Hardware components in one document.
#:
#: Lower than MAX_COMPONENTS by two orders of magnitude, and deliberately: a
#: parts list is human-authored. The largest real electromechanical assemblies
#: run to a few thousand line items; 100,000 is far past any of them and short
#: of the point where a runaway `level` column could exhaust memory.
MAX_HARDWARE_COMPONENTS = 100_000

#: And above this many findings. A monorepo with 50k components routinely has
#: several hundred thousand findings.
MAX_FINDINGS = 1_000_000

#: Crypto assets are discovered per algorithm/key/protocol/certificate
#: occurrence, not per dependency edge — the same rough order of magnitude as
#: components, not findings. Same ceiling as MAX_COMPONENTS pending real
#: engine output suggesting a different one is warranted.
MAX_CRYPTO_ASSETS = 250_000

#: AI models are discovered per distinct model reference after
#: `merge.merge()`'s identity-based dedup — a repository referencing the same
#: dozen foundation models from a hundred call sites is a dozen rows, not a
#: hundred. Nowhere near component/finding volume; the ceiling exists for the
#: same "refuse rather than truncate" reason as the others, not because real
#: output is expected to approach it.
MAX_AI_MODELS = 10_000

#: Longest text value stored. Beyond this the value is truncated WITH A MARKER,
#: so a reader can tell a shortened string from a real one.
MAX_TEXT = 8192


@dataclass
class CopyBatch:
    """One table's rows, ready for `COPY`."""

    table: str
    columns: tuple[str, ...]
    rows: list[tuple[Any, ...]] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.rows)


@dataclass
class BulkPlan:
    """Everything to write for one normalization, plus what was refused."""

    batches: list[CopyBatch] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    refused: bool = False

    def batch(self, table: str) -> CopyBatch | None:
        for candidate in self.batches:
            if candidate.table == table:
                return candidate
        return None

    def total_rows(self) -> int:
        return sum(len(b) for b in self.batches)


def plan(
    canonical: dict[str, Any],
    *,
    tenant_id: str,
    bom_document_id: str,
) -> BulkPlan:
    """Turn a canonical model into COPY batches.

    Returns a refusal rather than a partial plan when a cap is exceeded: a
    half-written BOM is worse than none, because nothing downstream can tell it
    is half-written.
    """
    out = BulkPlan()

    components = canonical.get("components") or []
    findings = canonical.get("findings") or []
    crypto_assets = canonical.get("crypto_assets") or []
    hardware_components = canonical.get("hardware_components") or []

    if len(components) > MAX_COMPONENTS:
        out.refused = True
        out.diagnostics.append(
            {
                "severity": "error",
                "code": "NORMALIZE_COMPONENT_CAP_EXCEEDED",
                "message": (f"{len(components)} components exceeds the {MAX_COMPONENTS} ceiling"),
                "hint": (
                    "the scan is refused rather than truncated: a truncated BOM looks "
                    "complete and every component past the cut-off becomes a false "
                    "negative the customer trusts"
                ),
            }
        )
        return out

    if len(hardware_components) > MAX_HARDWARE_COMPONENTS:
        out.refused = True
        out.diagnostics.append(
            {
                "severity": "error",
                "code": "NORMALIZE_HARDWARE_COMPONENT_CAP_EXCEEDED",
                "message": f"{len(hardware_components)} hardware components exceeds the "
                f"{MAX_HARDWARE_COMPONENTS} ceiling",
                "hint": "refused rather than truncated, same as every other cap here: a "
                "truncated parts list looks complete, and every part past the cut-off "
                "becomes a component the customer believes was accounted for",
            }
        )
        return out

    if len(findings) > MAX_FINDINGS:
        out.refused = True
        out.diagnostics.append(
            {
                "severity": "error",
                "code": "NORMALIZE_FINDING_CAP_EXCEEDED",
                "message": f"{len(findings)} findings exceeds the {MAX_FINDINGS} ceiling",
                "hint": "refused rather than truncated",
            }
        )
        return out

    if len(crypto_assets) > MAX_CRYPTO_ASSETS:
        out.refused = True
        out.diagnostics.append(
            {
                "severity": "error",
                "code": "NORMALIZE_CRYPTO_ASSET_CAP_EXCEEDED",
                "message": (
                    f"{len(crypto_assets)} crypto assets exceeds the {MAX_CRYPTO_ASSETS} ceiling"
                ),
                "hint": "refused rather than truncated, same reasoning as the component cap",
            }
        )
        return out

    ai_models = canonical.get("ai_models") or []

    if len(ai_models) > MAX_AI_MODELS:
        out.refused = True
        out.diagnostics.append(
            {
                "severity": "error",
                "code": "NORMALIZE_AI_MODEL_CAP_EXCEEDED",
                "message": f"{len(ai_models)} AI models exceeds the {MAX_AI_MODELS} ceiling",
                "hint": "refused rather than truncated, same reasoning as the component cap",
            }
        )
        return out

    # ⚠ MINTED ONCE, SHARED BY EVERY BATCH BELOW.
    #
    # normalize.components.id has no way to be read back from a COPY — COPY
    # does not support RETURNING — so a client-generated id is the only way
    # component_locations, findings and component_dependencies can reference
    # the row this same plan() call is about to insert. See _component_id.
    component_ids = _component_ids(components, bom_document_id)

    out.batches.append(_components_batch(components, tenant_id, bom_document_id, component_ids))
    out.batches.append(_locations_batch(components, tenant_id, bom_document_id, component_ids))
    # Both of these had no writer at all and two live readers — see each
    # function's own comment for what that cost.
    out.batches.append(_provenance_batch(components, tenant_id, bom_document_id, component_ids))
    out.batches.append(
        _candidate_identities_batch(components, tenant_id, bom_document_id, component_ids)
    )

    findings_batch, findings_diagnostics = _findings_batch(
        findings, tenant_id, bom_document_id, component_ids
    )
    out.batches.append(findings_batch)
    out.diagnostics.extend(findings_diagnostics)

    deps_batch, deps_diagnostics = _dependencies_batch(
        canonical, tenant_id, bom_document_id, component_ids
    )
    out.batches.append(deps_batch)
    out.diagnostics.extend(deps_diagnostics)

    # ⚠ NO component_ids DEPENDENCY, UNLIKE EVERY BATCH ABOVE.
    #
    # normalize.crypto_assets.component_key is a plain `text` column, not a
    # uuid foreign key into normalize.components (contrast normalize.findings
    # .component_id) — see _crypto_assets_batch's own docstring. Nothing else
    # in this same write needs to reference a crypto asset's row id either, so
    # unlike _component_id there is no client-side id to mint here at all:
    # normalize.crypto_assets.id keeps its schema DEFAULT app.uuid_v7().
    out.batches.append(_crypto_assets_batch(crypto_assets, tenant_id, bom_document_id))

    # ⚠ MINTED FOR THE SAME REASON AS component_ids, and it is what wires the
    # recursive parent_id. See _hardware_component_id.
    if hardware_components:
        hardware_ids = _hardware_component_ids(hardware_components, bom_document_id)
        out.batches.append(
            _hardware_components_batch(
                hardware_components, tenant_id, bom_document_id, hardware_ids
            )
        )
        out.batches.append(_hardware_alternates_batch(hardware_components, tenant_id, hardware_ids))
        findings_batch, findings_diagnostics = _hardware_findings_batch(
            hardware_components, tenant_id, bom_document_id, hardware_ids
        )
        out.batches.append(findings_batch)
        out.diagnostics.extend(findings_diagnostics)

    # ⚠ MINTED FOR THE SAME REASON AS component_ids: `_ai_datasets_batch` and
    # `_ai_model_dependencies_batch` below need to reference the parent AI
    # model's row from WITHIN THIS SAME transaction, before Postgres has
    # assigned it a real id — see `_ai_model_ids`.
    ai_model_ids = _ai_model_ids(ai_models, bom_document_id)

    out.batches.append(_ai_models_batch(ai_models, tenant_id, bom_document_id, ai_model_ids))
    out.batches.append(_ai_datasets_batch(ai_models, tenant_id, bom_document_id, ai_model_ids))
    out.batches.append(
        _ai_model_dependencies_batch(ai_models, tenant_id, bom_document_id, ai_model_ids)
    )
    out.batches.append(
        _ai_model_provenance_batch(ai_models, tenant_id, bom_document_id, ai_model_ids)
    )
    out.batches.append(
        _ai_assets_batch(canonical.get("ai_assets") or [], tenant_id, bom_document_id)
    )

    return out


def _component_id(bom_document_id: str, component_key: str) -> str:
    """Mint the surrogate id one component row will be inserted with.

    ⚠ uuid5, NOT uuid4. Normalization must be replayable (CLAUDE.md invariant
    10) — the same (document, component) pair has to mint the same id on
    every run, the same reason identity.py's opaque-identity rule uses uuid5
    rather than a random one. A random id here would make every
    re-normalization of the same raw artifacts produce different component
    ids for identical components, breaking that guarantee silently.
    """
    return str(uuid.uuid5(_SURROGATE_NAMESPACE, f"component:{bom_document_id}:{component_key}"))


def _component_ids(components: Sequence[dict[str, Any]], bom_document_id: str) -> dict[str, str]:
    """One surrogate id per component, keyed by its SANITIZED component_key.

    Keyed by the sanitized (`_text()`-passed) value because that is what
    `_components_batch` actually stores in the `component_key` column — a
    lookup keyed by the raw value would silently miss whenever a key needed
    NUL-stripping or truncation.
    """
    return {
        _text(c.get("component_key")): _component_id(bom_document_id, _text(c.get("component_key")))
        for c in components
    }


def _lookup_component_id(
    component_ids: dict[str, str],
    component_key: Any,
    *,
    context: str,
    diagnostics: list[dict[str, Any]],
) -> str | None:
    """Resolve a component_key to its surrogate id, or record why it could not.

    ⚠ A MISSING KEY IS A BUG ELSEWHERE IN THE PIPELINE, NOT A USER ERROR —
    every finding and every dependency edge is supposed to reference a
    component from THIS SAME canonical model. It is handled defensively
    anyway, because the alternative to skipping the row is either inserting a
    NULL into a NOT NULL column (the whole COPY batch fails, and one bad edge
    takes every good one down with it) or crashing normalization entirely
    over a single dangling reference. A visible diagnostic is the middle
    ground CLAUDE.md's "never silently drop" principle asks for.
    """
    key = _text(component_key)
    resolved = component_ids.get(key)
    if resolved is None:
        diagnostics.append(
            {
                "severity": "warn",
                "code": "NORMALIZE_DANGLING_COMPONENT_REFERENCE",
                "message": f"{context} references component_key {key!r}, which is not "
                "among this scan's components",
                "hint": "the row was dropped rather than written with a missing "
                "foreign key; this points at a bug upstream in the pipeline, "
                "since every reference is expected to resolve within the "
                "same canonical model",
            }
        )
    return resolved


def _components_batch(
    components: Sequence[dict[str, Any]],
    tenant_id: str,
    bom_document_id: str,
    component_ids: dict[str, str],
) -> CopyBatch:
    batch = CopyBatch(
        table="normalize.components",
        columns=(
            "id",
            "tenant_id",
            "bom_document_id",
            "component_key",
            "identity_rule",
            "identity_confidence",
            "purl",
            "ecosystem",
            "name",
            "version_raw",
            "license_declared",
            "license_concluded",
            "license_effective",
            "license_rule",
            "license_ambiguous",
            "patch_status",
            "scope",
            "is_direct",
            "hashes",
            "author_of_sbom_data",
            "field_status",
        ),
    )

    for component in components:
        key = _text(component.get("component_key"))
        batch.rows.append(
            (
                component_ids[key],
                tenant_id,
                bom_document_id,
                key,
                _text(component.get("identity_rule")),
                _text(component.get("identity_confidence")),
                _text(component.get("purl")) or None,
                _text(component.get("ecosystem")) or None,
                _text(component.get("name")),
                _text(component.get("version_raw")),
                _text(component.get("license_declared")) or None,
                _text(component.get("license_concluded")) or None,
                _text(component.get("license_effective")) or None,
                _text(component.get("license_rule")) or None,
                bool(component.get("license_ambiguous")),
                # ⚠ `or None`, NOT the bare string. The CHECK constraint
                # (migrations/normalize/0001_bom_components.sql) permits NULL or
                # one of four CERT-In enum values — "" is neither, and an unset
                # patch_status is exactly the common case (any component with no
                # findings). Without this the whole COPY batch fails.
                _text(component.get("patch_status")) or None,
                _text(component.get("scope")) or "required",
                bool(component.get("is_direct")),
                json.dumps(component.get("hashes") or []),
                ", ".join(
                    sorted({o.get("engine", "") for o in component.get("observed_by") or []})
                ),
                # ⚠ Per-field provided/not-provided drives BOTH coverage
                # numbers, so it is stored rather than recomputed at render —
                # a report must not be able to disagree with itself.
                json.dumps(_field_status(component)),
            )
        )

    return batch


def _field_status(component: dict[str, Any]) -> dict[str, str]:
    """Record which fields held a substantive value.

    Stored explicitly because `not-provided` is REPORTED but not covered. An
    omitted field and an explicitly-unknown one are different claims, and the
    difference is exactly what separates the two coverage numbers.
    """
    from .coverage import is_substantive

    status: dict[str, str] = {}
    for key in ("name", "version_raw", "purl", "ecosystem", "license_effective"):
        value = component.get(key)
        status[key] = (
            "provided" if is_substantive(value, is_license="license" in key) else "not-provided"
        )
    return status


def _locations_batch(
    components: Sequence[dict[str, Any]],
    tenant_id: str,
    bom_document_id: str,
    component_ids: dict[str, str],
) -> CopyBatch:
    """⚠ Identity is the package; locations are 1:N.

    The same jar vendored at two paths is one component row and two location
    rows. Putting the path in the component key inflates every count.

    ⚠ component_id, NOT component_key. normalize.component_locations
    references normalize.components by its surrogate uuid — the merge key is
    a string with no place in a foreign key. No lookup can miss here: this
    walks `components` directly, so the id for the CURRENT component is
    always already in `component_ids`.
    """
    batch = CopyBatch(
        table="normalize.component_locations",
        columns=("tenant_id", "bom_document_id", "component_id", "path", "layer", "sha256"),
    )

    for component in components:
        key = _text(component.get("component_key"))
        for location in component.get("locations") or []:
            batch.rows.append(
                (
                    tenant_id,
                    bom_document_id,
                    component_ids[key],
                    normalize_path(str(location.get("path", ""))),
                    _text(location.get("layer")),
                    _text(location.get("sha256")),
                )
            )

    return batch


def _provenance_batch(
    components: Sequence[dict[str, Any]],
    tenant_id: str,
    bom_document_id: str,
    component_ids: dict[str, str],
) -> CopyBatch:
    """Which engine reported each component, and what it called it.

    ⚠ THIS TABLE HAD NO WRITER AT ALL, AND IT HAS TWO LIVE READERS.

    `services/project/internal/store/dependencies.go` powers the per-component
    "where did this line in this report come from?" panel — the thing that makes
    a report defensible six months later — and it returned an empty list for
    EVERY component. Worse, `loadComponentProvenanceEngines` swallows its error
    with a `//nolint:nilerr`, so an empty answer and a broken query looked
    identical from the outside.

    ⚠ THE DATA WAS ALREADY HERE. `merge.MergedComponent.observed_by` carries one
    `Observation` per engine that saw the component — engine, version, native id
    and confidence — and `as_dict()` has always serialised it into the canonical
    document. Nothing consumed it. This is a write of facts the normalizer had
    computed and then discarded.

    ⚠ `observed_at` IS LEFT TO THE COLUMN DEFAULT ON PURPOSE. A normalization is
    replayable (invariant 10): re-normalizing the same artifacts must produce the
    same rows, and stamping a clock here would make every replay differ from the
    last. The honest observation time is the SCAN's, which the bom_document
    already carries.
    """
    batch = CopyBatch(
        table="normalize.component_provenance",
        columns=(
            "tenant_id",
            "bom_document_id",
            "component_id",
            "engine_id",
            "engine_version",
            "confidence",
            "rule_id",
        ),
    )

    for component in components:
        key = _text(component.get("component_key"))
        component_id = component_ids.get(key)
        if component_id is None:
            continue
        for observation in component.get("observed_by") or []:
            engine = _text(observation.get("engine"))
            if not engine:
                # An observation with no engine names nothing. Skipping it is
                # right; recording it would put a blank row in the one table a
                # customer consults to ask "who said this?".
                continue
            batch.rows.append(
                (
                    tenant_id,
                    bom_document_id,
                    component_id,
                    engine,
                    _text(observation.get("engine_version")) or None,
                    _confidence(observation.get("confidence")),
                    # The engine's OWN id for this component — syft's package
                    # id, dependency-check's dependency ref. It is what lets
                    # somebody go back to the raw artifact and find the row.
                    _text(observation.get("native_id")) or None,
                )
            )

    return batch


def _candidate_identities_batch(
    components: Sequence[dict[str, Any]],
    tenant_id: str,
    bom_document_id: str,
    component_ids: dict[str, str],
) -> CopyBatch:
    """Identity claims recorded WITHOUT merging.

    ⚠ THE POINT OF THIS TABLE IS THAT THESE CLAIMS DID NOT CHANGE ANYTHING.
    A low-confidence CPE from dependency-check is real information a reviewer
    may well confirm — and it must not silently pull in another component's
    findings, which is why merge.py keeps it here instead of on the component.
    Writing it is what lets a human make that call; not writing it threw the
    evidence away and left the decision unmakeable.

    Also writerless until now, with a live reader in dependencies.go.
    """
    batch = CopyBatch(
        table="normalize.component_candidate_identities",
        columns=(
            "tenant_id",
            "bom_document_id",
            "component_id",
            "kind",
            "value",
            "source_engine",
            "confidence",
        ),
    )

    for component in components:
        key = _text(component.get("component_key"))
        component_id = component_ids.get(key)
        if component_id is None:
            continue
        for candidate in component.get("candidate_identities") or []:
            kind = _text(candidate.get("kind"))
            value = _text(candidate.get("value"))
            engine = _text(candidate.get("source_engine"))
            # ⚠ EVERY ONE OF THESE IS NOT NULL WITH A CHECK CONSTRAINT. A row
            # missing any of them fails the COPY and takes the whole
            # transaction with it — so an incomplete claim is dropped here,
            # where it costs one candidate, rather than at execute time where
            # it costs the entire normalization.
            if not kind or not value or not engine:
                continue
            if kind not in _CANDIDATE_KINDS:
                continue
            batch.rows.append(
                (
                    tenant_id,
                    bom_document_id,
                    component_id,
                    kind,
                    value,
                    engine,
                    _confidence(candidate.get("confidence")) or "low",
                )
            )

    return batch


#: The CHECK constraint on component_candidate_identities.kind.
_CANDIDATE_KINDS = frozenset({"cpe", "swid", "purl", "hash", "name"})


def _confidence(value: Any) -> str | None:
    """Map a confidence onto the CHECK constraint, or to NULL.

    ⚠ THE COLUMN ALLOWS high/medium/low AND NOTHING ELSE. An engine that reports
    "HIGH", or a value this codebase has not seen, would abort the COPY — so an
    unrecognised confidence becomes NULL, which reads as "not stated" rather
    than as a level nobody asserted.
    """
    text = _text(value).lower()
    return text if text in ("high", "medium", "low") else None


def license_refs(components: Sequence[dict[str, Any]]) -> list[tuple[str, str]]:
    """Licence strings this product could not map to SPDX, deduped.

    ⚠ NOT A CopyBatch, AND THAT IS FORCED BY THE SCHEMA. `normalize.license_refs`
    is `UNIQUE (tenant_id, slug)` and COPY cannot express ON CONFLICT — so the
    second scan of a project with an unmappable licence would abort the entire
    normalization write. It goes through a plain INSERT in writer.py, the same
    way bom_documents does.

    ⚠ TENANT-SCOPED, NOT DOCUMENT-SCOPED. One unmapped licence string is one
    thing a human maps ONCE, not once per scan.

    ⚠ THE TABLE HAD NO WRITER AND `Resolution.raw` EXISTS ONLY TO FILL IT. Its
    own comment says the text is "preserved for normalize.license_refs, so a
    human can map it later without re-running the scan" — and it reached no
    serialiser, so re-running the scan was the only way to get it back.
    """
    seen: dict[str, str] = {}
    for component in components:
        for ref in component.get("license_refs") or []:
            slug = _text(ref.get("slug"))
            raw = _text(ref.get("raw_text"))
            if slug and raw:
                seen.setdefault(slug, raw)
    return sorted(seen.items())


def _findings_batch(
    findings: Sequence[dict[str, Any]],
    tenant_id: str,
    bom_document_id: str,
    component_ids: dict[str, str],
) -> tuple[CopyBatch, list[dict[str, Any]]]:
    """⚠ THREE COLUMN NAMES HERE USED TO NOT EXIST IN THE SCHEMA.

    `vuln_cluster_id`, `component_key` and `severity_rule` were the Python
    canonical model's OWN field names, copied straight into the COPY column
    list as though they were the database's — they are not.
    normalize.findings calls them `cluster_id`, `component_id` (a uuid, not
    the merge-key string) and `severity_source`. Every COPY this function
    planned would have failed at execute time; nothing caught it because
    nothing had ever executed one (see writer.py).
    """
    batch = CopyBatch(
        table="normalize.findings",
        columns=(
            "tenant_id",
            "bom_document_id",
            "cluster_id",
            "component_id",
            "display_id_at_render",
            "severity_effective",
            "severity_source",
            "severity_conflict",
            "detected_by",
            "cvss_vectors",
            "fixed_versions",
            "fixed_in_min",
            "fix_version_ordering",
        ),
    )
    diagnostics: list[dict[str, Any]] = []

    for finding in findings:
        component_id = _lookup_component_id(
            component_ids,
            finding.get("component_key"),
            context=f"finding {finding.get('display_id', '')!r}",
            diagnostics=diagnostics,
        )
        if component_id is None:
            continue

        # cluster_id is a uuid column. In production, pipeline.normalize()'s
        # `vuln_cluster_id` IS ALREADY a real, durable normalize.vuln_clusters
        # uuid — cluster_store.py resolved/minted it and fed it back in via
        # normalize()'s existing_clusters/cluster_ids parameters (ADR-0005:
        # never derived from content, so it survives a re-scan and a report
        # issued against it keeps resolving). Pass it through unchanged.
        #
        # ⚠ THE uuid5 DERIVATION BELOW IS A FALLBACK, NOT THE NORMAL PATH.
        # It only fires for callers that never wired cluster_store at all —
        # fixtures and tests via normalize_runner.py's `_default_ids`, which
        # documents itself as carrying "no cross-scan meaning." A real,
        # correctly-wired scan should never take this branch; if one does,
        # that is a wiring regression worth being loud about rather than
        # silently reproducing the exact non-durable-id trap ADR-0005 exists
        # to prevent.
        raw_cluster_id = _text(finding.get("vuln_cluster_id"))
        if _is_uuid(raw_cluster_id):
            cluster_id = raw_cluster_id
        else:
            diagnostics.append(
                {
                    "severity": "warn",
                    "code": "NORMALIZE_CLUSTER_ID_NOT_DURABLE",
                    "message": (
                        f"finding {finding.get('display_id', '')!r} carries a non-durable "
                        f"cluster id {raw_cluster_id!r}; falling back to a per-document "
                        "derived id"
                    ),
                    "hint": (
                        "normalize() was called without existing_clusters/cluster_ids wired "
                        "to normalize.vuln_clusters — expected from a fixture or test, a real "
                        "bug if this fired from a live scan (see cluster_store.py)"
                    ),
                }
            )
            cluster_id = str(
                uuid.uuid5(
                    _SURROGATE_NAMESPACE,
                    f"cluster:{bom_document_id}:{raw_cluster_id}",
                )
            )

        batch.rows.append(
            (
                tenant_id,
                bom_document_id,
                cluster_id,
                component_id,
                # ⚠ PINNED. A report issued in March still says CVE-2021-44228
                # in September, even after the cluster absorbs more aliases.
                _text(finding.get("display_id")),
                # ⚠ `or None`, NOT bare _text(). severity_effective has a CHECK
                # constraint permitting NULL or one of six enum values — never
                # an empty string. _text(None) returns "", and a finding with
                # no resolved severity is the NORMAL case the NotProvided
                # bucket exists for (see orchestr.SeverityCounts on the Go
                # side) — every one of them would have failed this CHECK and
                # taken the whole batch down with it.
                _text(finding.get("severity_effective")) or None,
                _text(finding.get("severity_rule")) or None,
                bool(finding.get("severity_conflict")),
                # ⚠ NATIVE LISTS, NOT json.dumps(). detected_by and
                # fixed_versions are `text[]` columns — Postgres ARRAYS, using
                # `{...}` literal syntax, not JSON's `[...]`. Sending
                # '["grype"]' where Postgres expects '{"grype"}' fails with
                # "malformed array literal" at execute time; the psycopg
                # driver adapts a plain Python list to a real array on its
                # own. cvss_vectors, two lines down, is genuinely `jsonb` —
                # that one DOES need json.dumps().
                _text_list(finding.get("detected_by")),
                json.dumps(finding.get("cvss_vectors") or []),
                _text_list(finding.get("fixed_versions")),
                _text(finding.get("fixed_in_min")),
                _text(finding.get("fix_version_ordering")),
            )
        )

    return batch, diagnostics


def _dependencies_batch(
    canonical: dict[str, Any],
    tenant_id: str,
    bom_document_id: str,
    component_ids: dict[str, str],
) -> tuple[CopyBatch, list[dict[str, Any]]]:
    """`from_key`/`to_key` used to name columns component_dependencies does not
    have — it is `from_component_id`/`to_component_id`, and both are uuids
    referencing normalize.components, not the merge-key strings the graph
    module works in.
    """
    batch = CopyBatch(
        table="normalize.component_dependencies",
        columns=(
            "tenant_id",
            "bom_document_id",
            "from_component_id",
            "to_component_id",
            "relationship",
            "scope",
            "owning_engine",
            "confidence",
        ),
    )
    diagnostics: list[dict[str, Any]] = []

    for edge in (canonical.get("graph") or {}).get("edges") or []:
        from_id = _lookup_component_id(
            component_ids, edge.get("from"), context="dependency edge", diagnostics=diagnostics
        )
        to_id = _lookup_component_id(
            component_ids, edge.get("to"), context="dependency edge", diagnostics=diagnostics
        )
        if from_id is None or to_id is None:
            continue

        batch.rows.append(
            (
                tenant_id,
                bom_document_id,
                from_id,
                to_id,
                _text(edge.get("relationship")) or "depends_on",
                _text(edge.get("scope")) or "required",
                _text(edge.get("owning_engine")),
                _text(edge.get("confidence")) or "medium",
            )
        )

    return batch, diagnostics


#: Every column `normalize.crypto_assets` has beyond `id`/`tenant_id`
#: /`bom_document_id`/`created_at` — the union of migrations 0003 and 0005.
#: `workers/cbom/normalize/crypto.py`'s `normalize_crypto_asset` only ever
#: POPULATES the subset that belongs to a given `asset_type`
#: (`TYPE_COLUMNS`), so most rows leave most of these `None` — that sparseness
#: is the entire point of the type-discriminated schema (CLAUDE.md invariant
#: 5), not a bug in this list.
_CRYPTO_ASSET_COLUMNS: tuple[str, ...] = (
    "component_key",
    "asset_type",
    "name",
    # ---- algorithm ----
    "primitive",
    "mode",
    "crypto_functions",
    "classical_security_level",
    "algorithm_list",
    # ---- key ----
    "key_id",
    "key_state",
    "key_size",
    "creation_date",
    "activation_date",
    # ---- protocol ----
    "protocol_version",
    "cipher_suites",
    # ---- shared by algorithm and protocol ----
    "oid",
    # ---- certificate ----
    "cert_subject",
    "cert_issuer",
    "not_valid_before",
    "not_valid_after",
    "signature_algo_ref",
    "subject_public_key_ref",
    "cert_format",
    "cert_extension",
    # ---- AxeBOM analysis (migrations 0003 + 0005): NOT CERT-In fields,
    # excluded from both coverage numbers (crypto.py's own module docstring).
    "quantum_vulnerable",
    "pqc_recommendation",
    "deprecation_status",
    "quantum_family",
    "grover_note",
    "quantum_rationale",
    "deprecation_rationale",
    "deprecation_reference",
    "effective_quantum_bits",
    "analysis_diagnostics",
    "quantum_readiness_group",
    "field_status",
)

#: text[] columns on normalize.crypto_assets — see the module docstring's
#: "NATIVE LISTS, NOT json.dumps()" note on _findings_batch for why these must
#: go through `_text_list` (a plain Python list the driver adapts to a real
#: Postgres array) rather than `json.dumps()` (which would produce a JSON
#: array literal Postgres refuses for an array-typed column).
_CRYPTO_ARRAY_COLUMNS = frozenset({"crypto_functions", "algorithm_list", "cipher_suites"})

#: int columns. Distinguished from the text columns because `_text()` would
#: stringify a real integer, and an absent one must reach Postgres as NULL,
#: never as `""` (which satisfies no integer column and would fail the write).
_CRYPTO_INT_COLUMNS = frozenset({"classical_security_level", "key_size", "effective_quantum_bits"})


def _crypto_assets_batch(
    assets: Sequence[dict[str, Any]],
    tenant_id: str,
    bom_document_id: str,
) -> CopyBatch:
    """Plan the `normalize.crypto_assets` batch.

    ⚠ NO SURROGATE ID MINTED HERE, UNLIKE `_components_batch`.

    `normalize.components.id` has to be minted client-side (see
    `_component_id`) because `component_locations`, `findings` and
    `component_dependencies` all need to reference a component row from
    WITHIN THIS SAME transaction, before Postgres has assigned it a real id.
    Nothing in this canonical model references a crypto asset's row the same
    way — `crypto_assets.component_key` is a plain `text` column carrying
    whatever string `crypto.py` put there (today, the asset's OWN CycloneDX
    `bom-ref`, used by `workers/qbom/derive.py`'s cross-referencing — never a
    foreign key into `normalize.components`) — so there is nothing to look up
    and no reason to mint an id in Python at all. The column keeps its schema
    `DEFAULT app.uuid_v7()`.

    ⚠ DATES AND TIMESTAMPS TRAVEL AS PLAIN STRINGS, DELIBERATELY.

    `creation_date`/`activation_date` (`date`) and `not_valid_before`
    /`not_valid_after` (`timestamptz`) arrive from `crypto.py` as ISO-8601
    strings (`"2024-01-02"`, `"2024-01-01T00:00:00Z"`). Postgres performs its
    ordinary implicit text-to-typed-column cast on a bound parameter exactly
    as it would for a literal in the SQL text, so `_text(value) or None`
    (verified against a live connection) is sufficient — there is no need to
    parse these into `datetime.date`/`datetime.datetime` objects in Python
    first, and doing so would just be a second place an ISO-8601 parsing bug
    could live.
    """
    batch = CopyBatch(
        table="normalize.crypto_assets",
        columns=("tenant_id", "bom_document_id", *_CRYPTO_ASSET_COLUMNS),
    )

    for asset in assets:
        row: list[Any] = [tenant_id, bom_document_id]
        for column in _CRYPTO_ASSET_COLUMNS:
            if column == "field_status":
                row.append(json.dumps(_crypto_field_status(asset)))
            elif column == "analysis_diagnostics":
                row.append(json.dumps(asset.get("analysis_diagnostics") or []))
            elif column == "quantum_vulnerable":
                # NOT NULL DEFAULT false — crypto.py's analyse() always sets
                # this, but coerced defensively rather than trusting that.
                row.append(bool(asset.get("quantum_vulnerable")))
            elif column in _CRYPTO_ARRAY_COLUMNS:
                row.append(_text_list(asset.get(column)))
            elif column in _CRYPTO_INT_COLUMNS:
                row.append(_int_or_none(asset.get(column)))
            elif column in ("name", "asset_type"):
                # NOT NULL text columns. crypto.py guarantees asset_type is
                # one of the four known values before a row is ever produced
                # (normalize_crypto_asset raises otherwise) — _text() still
                # runs for NUL-safety and the length cap like every other
                # text value here.
                row.append(_text(asset.get(column)))
            else:
                # Every other column is nullable text (or text-shaped: dates
                # and timestamps, see the docstring above) — `_text() or
                # None` turns both "never set" and "set to empty" into NULL
                # rather than storing "", the same convention _components_batch
                # uses for every nullable text column.
                row.append(_text(asset.get(column)) or None)
        batch.rows.append(tuple(row))

    return batch


def _crypto_field_status(asset: dict[str, Any]) -> dict[str, str]:
    """Record which of THIS asset's TYPE's CERT-In fields held a substantive
    value — the crypto-asset analogue of `_field_status` above.

    ⚠ WHY THIS EARNS ITS KEEP RATHER THAN BEING SKIPPED (a real decision, not
    an oversight): most crypto columns are either a real value or absent, so a
    reader could usually infer coverage from column nullness alone and never
    need this. `key_state` is the one field where that inference is WRONG:
    `cbomkit_theia._key_state` maps an unrecognised or compromised key state to
    the literal string `"unknown"` rather than leaving the column NULL (its own
    docstring: "defaulting to active would report a revoked key as live in a
    compliance document"), and `"unknown"` is declared but NOT substantive
    (`coverage.NON_SUBSTANTIVE`). A report renderer that inferred per-field
    coverage from "is this column NULL" would count `key_state = 'unknown'` as
    present, which is exactly the kind of false-positive coverage claim
    CLAUDE.md invariant 3 exists to prevent. Storing the real answer here means
    that decision is made once, in the language that already owns
    `is_substantive`, rather than re-implemented (and inevitably drifting) in
    whatever eventually renders a CBOM report.

    ⚠ DERIVED FROM THE COMPLIANCE PROFILE, NOT FROM `workers/cbom/normalize
    /crypto.py`'s `TYPE_COLUMNS`. `libs/py-shared` is a dependency of every
    worker, never the other way around (CLAUDE.md invariant 11's Go-side rule
    applied to this package too) — importing `workers.cbom` from here would
    invert that. `CRYPTO_FIELDS_BY_ASSET_TYPE` is the same profile-generated
    source `TYPE_COLUMNS` is itself validated against
    (`test_crypto_normalize.py::test_the_column_map_agrees_with_the_compliance
    _profile`), so reading it here instead of mirroring `TYPE_COLUMNS` by hand
    avoids restating that list a second time in a second file — restated specs
    drift (CLAUDE.md invariant 1), and this module already sits close enough
    to that risk with `_CRYPTO_ASSET_COLUMNS` above.

    Only the CERT-In-scored fields for the asset's own type are recorded — the
    three AxeBOM analysis columns and `field_status`/`created_at` themselves
    are never in `CRYPTO_FIELDS_BY_ASSET_TYPE`, so they never appear here,
    exactly mirroring their exclusion from both coverage numbers.
    """
    from axebom_shared.model.generated_certin import CRYPTO_FIELDS_BY_ASSET_TYPE

    from .coverage import is_substantive

    asset_type = str(asset.get("asset_type") or "")
    fields = CRYPTO_FIELDS_BY_ASSET_TYPE.get(asset_type, [])

    status: dict[str, str] = {}
    for f in fields:
        column = f.canonical_path.removeprefix("crypto_asset.").removesuffix("[]")
        status[column] = "provided" if is_substantive(asset.get(column)) else "not-provided"
    return status


def _ai_model_id(bom_document_id: str, identity: str) -> str:
    """Mint the surrogate id one `normalize.ai_models` row will be inserted
    with — the AI-model analogue of `_component_id`, and for the same reason:
    `_ai_datasets_batch` and `_ai_model_dependencies_batch` both need to
    reference this row from WITHIN THIS SAME transaction, before Postgres has
    assigned it a real id. `identity` is `workers.aibom.merge.identity()`'s
    merge key (a model reference like `meta-llama/Llama-3-8B` where one
    exists, never the bare display name alone — see that function's own
    docstring for why), not any column `normalize.ai_models` actually stores;
    uuid5 (not uuid4) for the same replayability reason `_component_id` uses
    it.
    """
    return str(uuid.uuid5(_SURROGATE_NAMESPACE, f"ai_model:{bom_document_id}:{identity}"))


def _ai_model_ids(models: Sequence[dict[str, Any]], bom_document_id: str) -> dict[str, str]:
    """One surrogate id per AI model, keyed by the `_identity` pipeline key
    `workers.aibom.normalize.pipeline.build_canonical_aibom` attaches to each
    row (see that function's docstring on why three underscore-prefixed keys
    ride along on each model dict without becoming columns)."""
    return {
        _text(m.get("_identity")): _ai_model_id(bom_document_id, _text(m.get("_identity")))
        for m in models
    }


#: Every real column `normalize.ai_models` has beyond `id`/`tenant_id`
#: /`bom_document_id`/`created_at`. `_identity`/`_datasets`/`_dependencies`
#: are NOT in this list on purpose — they are pipeline-only keys `build_
#: canonical_aibom` attaches to each row so this module and `_ai_datasets_batch`
#: /`_ai_model_dependencies_batch` below can find a model's children, and
#: writing them to a column here would be an error (no such columns exist).
#: Some of `AIBOM_FIELDS`' 19 canonical paths — `software_dependencies`,
#: `findings`, `data_sets` — ALSO never appear here for a different reason:
#: `workers.aibom.normalize.ai.normalize_model` still populates them (so
#: coverage scoring sees them), but they are Table 10 elements this schema
#: represents via a RELATED table or column (`ai_model_dependencies`,
#: `normalize.findings`, `ai_datasets.name` respectively) rather than a column
#: of their own on `ai_models` — writing them again here would just be a
#: second, driftable copy of the same fact.
_AI_MODEL_COLUMNS: tuple[str, ...] = (
    # ⚠ IDENTITY FIRST, AND IT USED NOT TO BE HERE AT ALL. The merge key lived only
    # in the transport-only `_identity` key this function reads and drops, so nothing
    # in the database could say whether two rows were the same model — which is how
    # one model became three. See migrations/normalize/0016.
    "model_key",
    "identity_rule",
    "identity_confidence",
    "source_engine",
    "evidence",
    "verified",
    "model_name",
    "model_version",
    "model_type",
    "model_developer",
    "licensing",
    "ml_models_algorithms",
    "performance_metrics",
    "data_source",
    "hardware",
    "security_requirements",
    "input",
    "output",
    "intended_usage",
    "out_of_scope_usage",
    "environmental_impact",
    "attestation_signature",
    # ---- AxeBOM extensions (migration 0003): NOT CERT-In fields, excluded
    # from both coverage numbers (ai.py's own module docstring). ----
    "risk_score",
    "owasp_llm_top10",
    "field_status",
)

#: text[] columns on normalize.ai_models — see `_findings_batch`'s "NATIVE
#: LISTS, NOT json.dumps()" note for why these go through `_text_list`.
_AI_MODEL_ARRAY_COLUMNS = frozenset({"ml_models_algorithms", "owasp_llm_top10"})


def _ai_models_batch(
    models: Sequence[dict[str, Any]],
    tenant_id: str,
    bom_document_id: str,
    ai_model_ids: dict[str, str],
) -> CopyBatch:
    """Plan the `normalize.ai_models` batch.

    ⚠ id IS WRITTEN EXPLICITLY, UNLIKE `_crypto_assets_batch`. Unlike a crypto
    asset, an AI model's row IS referenced by two sibling tables in this same
    transaction (`ai_datasets.ai_model_id`, `ai_model_dependencies
    .ai_model_id`), so — like `_components_batch` — the id has to be minted
    client-side and written explicitly rather than left to the column's
    `DEFAULT app.uuid_v7()`.
    """
    batch = CopyBatch(
        table="normalize.ai_models",
        columns=("id", "tenant_id", "bom_document_id", *_AI_MODEL_COLUMNS),
    )

    for model in models:
        model_id = ai_model_ids[_text(model.get("_identity"))]
        row: list[Any] = [model_id, tenant_id, bom_document_id]
        for column in _AI_MODEL_COLUMNS:
            if column == "field_status":
                row.append(json.dumps(model.get("field_status") or {}))
            elif column == "performance_metrics":
                row.append(json.dumps(model.get("performance_metrics") or {}))
            elif column == "model_key":
                # ⚠ DERIVED FROM `_identity`, NEVER A SECOND COPY OF IT. `_identity`
                # already mints this row's surrogate id (`_ai_model_id`), so reading
                # the same value here makes the stored key and the id agree by
                # construction. Two independently-written fields that must match are
                # two fields that will eventually not match.
                row.append(_text(model.get("_identity")))
            elif column == "evidence":
                # Where each engine says it saw this model, verbatim. jsonb, because
                # it grows a shape (engine, path, line) as engines that report one
                # land; a text[] would have to be migrated to gain it.
                row.append(json.dumps(_text_list(model.get("evidence"))))
            elif column == "verified":
                row.append(bool(model.get("verified")))
            elif column == "risk_score":
                row.append(_numeric_or_none(model.get("risk_score")))
            elif column in _AI_MODEL_ARRAY_COLUMNS:
                row.append(_text_list(model.get(column)))
            elif column == "model_name":
                # NOT NULL text — `_text()` still runs for NUL-safety and the
                # length cap like every other text value here.
                row.append(_text(model.get(column)))
            else:
                # Every other column is nullable text — `_text() or None`
                # turns both "never set" and "set to empty" into NULL rather
                # than storing "", the same convention `_components_batch` and
                # `_crypto_assets_batch` both use for nullable text columns.
                row.append(_text(model.get(column)) or None)
        batch.rows.append(tuple(row))

    return batch


def _ai_datasets_batch(
    models: Sequence[dict[str, Any]],
    tenant_id: str,
    bom_document_id: str,
    ai_model_ids: dict[str, str],
) -> CopyBatch:
    """Plan the `normalize.ai_datasets` batch.

    Walks `models` directly and reads each model's OWN `_datasets` list — the
    pipeline-attached, not-a-column key `build_canonical_aibom` puts there —
    exactly the way `_locations_batch` reads `component.get("locations")` off
    the same `components` list `_components_batch` writes from, rather than
    through a second top-level canonical list.

    ⚠ `format` COMES FROM A DATASET'S `type` KEY, NOT A `format` KEY.
    `workers.aibom.adapters.aibom_generator._datasets` (what actually
    populates a merged model's `datasets`) emits `{name, type, license,
    source}` — no `version` or `limitations` key exists anywhere upstream, so
    those two columns are correctly always NULL until a future tool or the UI
    populates them; `type` is the closest existing column to what a dataset
    "type" (text, image, tabular, ...) actually means.
    """
    batch = CopyBatch(
        table="normalize.ai_datasets",
        columns=(
            "tenant_id",
            "ai_model_id",
            "name",
            "version",
            "format",
            "limitations",
            "license",
            "source",
        ),
    )

    for model in models:
        model_id = ai_model_ids[_text(model.get("_identity"))]
        for dataset in model.get("_datasets") or []:
            name = _text(dataset.get("name"))
            if not name:
                # NOT NULL column. `_datasets()` upstream already drops any
                # dataset with no name (aibom_generator.py's own `if not
                # name: continue`), so this is a defensive skip, not the
                # expected path.
                continue
            batch.rows.append(
                (
                    tenant_id,
                    model_id,
                    name,
                    _text(dataset.get("version")) or None,
                    _text(dataset.get("type")) or None,
                    _text(dataset.get("limitations")) or None,
                    _text(dataset.get("license")) or None,
                    _text(dataset.get("source")) or None,
                )
            )

    return batch


def _ai_model_dependencies_batch(
    models: Sequence[dict[str, Any]],
    tenant_id: str,
    bom_document_id: str,
    ai_model_ids: dict[str, str],
) -> CopyBatch:
    """Plan the `normalize.ai_model_dependencies` batch.

    ⚠ `component_key` IS A PLAIN `text` COLUMN, NOT A FOREIGN KEY INTO
    `normalize.components` — checked against the migration, not assumed:
    `migrations/normalize/0003_specialized_boms.sql`'s `ai_model_dependencies`
    table has no `component_id` uuid column at all, only `component_key text
    NOT NULL`. This is exactly `crypto_assets.component_key`'s situation
    (`_crypto_assets_batch`'s own docstring): the referenced SBOM component
    usually lives in a DIFFERENT `bom_document_id` (a different `bom_type`
    entirely) than this AIBOM write, so there is no component surrogate id
    from THIS transaction to look up — a reader resolves the join by string
    match against `normalize.components.component_key` at read time instead,
    the same way QBOM's device form resolves its `crypto_asset_refs`.
    `_dependencies` (the pipeline-attached key, itself `merge.link_dependencies
    ()`'s `linked` list) already carries exactly the strings that column
    expects — `purl:pkg:...` or a bare purl.
    """
    batch = CopyBatch(
        table="normalize.ai_model_dependencies",
        columns=("tenant_id", "ai_model_id", "component_key"),
    )

    for model in models:
        model_id = ai_model_ids[_text(model.get("_identity"))]
        # UNIQUE (ai_model_id, component_key) — dict.fromkeys dedupes while
        # keeping order, cheaper than a second .index()/set() pass and
        # guards against `link_dependencies` ever returning a duplicate.
        for component_key in dict.fromkeys(model.get("_dependencies") or []):
            key = _text(component_key)
            if not key:
                continue
            batch.rows.append((tenant_id, model_id, key))

    return batch


def _ai_model_provenance_batch(
    models: Sequence[dict[str, Any]],
    tenant_id: str,
    bom_document_id: str,
    ai_model_ids: dict[str, str],
) -> CopyBatch:
    """Plan the `normalize.ai_model_provenance` batch — which engines saw each model.

    ⚠ `ai_models.source_engine` IS SINGULAR AND THE ANSWER IS NOT. Three AIBOM
    engines discover independently and converge on the same `model_key`, so a
    model legitimately has three finders — and "found by one engine, missed by
    two" is the single most useful fact for a reviewer weighing how much to trust
    a row. This is the AI counterpart of `_provenance_batch` above, which has
    recorded exactly this for SBOM components since migration 0001.

    Reads the pipeline-attached `_provenance` list, the same not-a-column
    convention `_datasets` and `_dependencies` use.
    """
    batch = CopyBatch(
        table="normalize.ai_model_provenance",
        columns=(
            "tenant_id",
            "ai_model_id",
            "engine_id",
            "observed_name",
            "confidence",
            "evidence",
        ),
    )

    for model in models:
        model_id = ai_model_ids[_text(model.get("_identity"))]
        seen: set[str] = set()
        for entry in model.get("_provenance") or []:
            engine_id = _text(entry.get("engine_id"))
            # UNIQUE (ai_model_id, engine_id). One engine reporting the same
            # model twice in one document is a duplicate sighting, already
            # folded by `merge._absorb_usage`; this guards the constraint
            # rather than relying on that.
            if not engine_id or engine_id in seen:
                continue
            seen.add(engine_id)
            batch.rows.append(
                (
                    tenant_id,
                    model_id,
                    engine_id,
                    _text(entry.get("observed_name")) or None,
                    _text(entry.get("confidence")) or None,
                    json.dumps(list(entry.get("evidence") or [])),
                )
            )

    return batch


def _ai_assets_batch(
    assets: Sequence[dict[str, Any]],
    tenant_id: str,
    bom_document_id: str,
) -> CopyBatch:
    """Plan the `normalize.ai_assets` batch — prompts, vector stores, RAG
    pipelines, inference endpoints.

    ⚠ WITHOUT THIS, THREE REAL DISCOVERIES ARE COMPUTED AND DROPPED. airom and
    cdxgen-ai both report AI components that are neither models nor software
    dependencies, and before migration 0018 there was nowhere to put any of
    them — the engines would have run, found them, and produced a report that
    mentioned none of it (CLAUDE.md invariant 12).

    ⚠ NO CLIENT-MINTED ID, UNLIKE `_ai_models_batch`. Nothing in this write
    references an asset's row, so `normalize.ai_assets.id` keeps its schema
    DEFAULT — the same reasoning `_crypto_assets_batch` records.
    """
    batch = CopyBatch(
        table="normalize.ai_assets",
        columns=(
            "tenant_id",
            "bom_document_id",
            "asset_type",
            "asset_key",
            "name",
            "provider",
            "evidence",
            "serves_model_key",
            "attributes",
        ),
    )

    seen: set[str] = set()
    for asset in assets:
        asset_key = _text(asset.get("asset_key"))
        asset_type = _text(asset.get("asset_type"))
        name = _text(asset.get("name"))
        # NOT NULL columns, and a UNIQUE (bom_document_id, asset_key). The
        # normalizer mints the key, so an empty one means a bug upstream — skip
        # rather than fail the whole write, which would lose the models too.
        if not asset_key or not asset_type or not name or asset_key in seen:
            continue
        seen.add(asset_key)
        batch.rows.append(
            (
                tenant_id,
                bom_document_id,
                asset_type,
                asset_key,
                name,
                _text(asset.get("provider")) or None,
                json.dumps(list(asset.get("evidence") or [])),
                _text(asset.get("serves_model_key")) or None,
                json.dumps(dict(asset.get("attributes") or {})),
            )
        )

    return batch


def _is_uuid(value: str) -> bool:
    """Whether value already parses as a uuid — used to tell a real, durable
    cluster id (from cluster_store.py, minted client-side as uuid7, or read
    back from normalize.vuln_clusters) apart from a fixture/test placeholder
    string like "fixture-npm-simple-cluster-0000"."""
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def _numeric_or_none(value: Any) -> float | None:
    """A real number reaches the column; anything else becomes NULL.

    Mirrors `_int_or_none` for `risk_score numeric(5,2)` — Trusera's ai-bom
    emits this as a float (or omits it entirely), never as a string, so unlike
    the text columns there is no `_text()` coercion that would help here: a
    string value would satisfy no `numeric` column, and an absent one must
    reach Postgres as NULL rather than as `""`.
    """
    if isinstance(value, bool):
        return None
    return float(value) if isinstance(value, (int, float)) else None


def _int_or_none(value: Any) -> int | None:
    """A real int reaches the column; anything else becomes NULL.

    ⚠ NOT `_text()`. `_text()` would turn a real integer into its string form
    (satisfying no `int` column) and an absent one into `""` (satisfying no
    `int` column either) — both fail the write, unlike the string columns
    `_text() or None` handles correctly.
    """
    return value if isinstance(value, int) and not isinstance(value, bool) else None


#: Characters that must never reach a Postgres text column.
_FORBIDDEN = {ord(c): None for c in "\x00"}


def _text(value: Any) -> str:
    """Make a value safe to store, and bound it.

    ⚠ A NUL BYTE SILENTLY TRUNCATES a Postgres text value. The row inserts, no
    error is raised, and the stored string is a prefix of the real one — so the
    cleaning must happen BEFORE the write, not after.
    """
    if value is None:
        return ""
    text = str(value).translate(_FORBIDDEN)
    if len(text) > MAX_TEXT:
        # The marker matters. A silently shortened value looks like a real,
        # shorter value.
        return text[: MAX_TEXT - 12] + "…[truncated]"
    return text


def _text_list(values: Any) -> list[str]:
    """`_text()`, applied per element, for a Postgres `text[]` column.

    A plain Python list is what the driver adapts into a real array — see
    the callers in `_findings_batch` for why this must never be
    `json.dumps()`'d instead.
    """
    return [_text(v) for v in (values or [])]


def iter_rows(batches: Iterable[CopyBatch]):
    """Yield (table, columns, row) for a driver to stream."""
    for batch in batches:
        for row in batch.rows:
            yield batch.table, batch.columns, row


# ---------------------------------------------------------------------------
# Hardware
# ---------------------------------------------------------------------------


def _hardware_component_id(bom_document_id: str, local_id: str) -> str:
    """Mint the surrogate id one `normalize.hardware_components` row is
    inserted with — the hardware analogue of `_component_id`, for both of the
    same reasons.

    ⚠ FIRST: `parent_id` and `hardware_component_alternates
    .hardware_component_id` both need to reference this row from WITHIN THE
    SAME write, before Postgres has assigned it an id — and `writer.py`'s
    chunked INSERT has no `RETURNING` to read one back.

    ⚠ SECOND: uuid5, NOT uuid4. Re-normalizing the same parsed tree at the same
    ruleset version must mint the same ids (invariant 10), or every
    re-normalization silently renumbers a customer's parts list and any
    reference anybody kept to a row becomes wrong.

    `local_id` is the importer's `row-<n>` or the ECAD adapter's `part-<n>` —
    stable within one document by construction, which is exactly what uuid5
    needs and what the raw artifact's committed row order guarantees.
    """
    return str(uuid.uuid5(_SURROGATE_NAMESPACE, f"hardware_component:{bom_document_id}:{local_id}"))


def _hardware_component_ids(
    components: Sequence[dict[str, Any]], bom_document_id: str
) -> dict[str, str]:
    """One surrogate id per node, keyed by `_local_id`."""
    return {
        _text(c.get("_local_id")): _hardware_component_id(
            bom_document_id, _text(c.get("_local_id"))
        )
        for c in components
    }


#: Canonical path -> column, for the flat hardware row `flatten()` produces.
#:
#: ⚠ DERIVED FROM THE PATHS, NOT HAND-LISTED TWICE. Both profiles express a
#: field as `hardware_component.<column>`, so the column IS the path minus its
#: prefix. A hand-written second copy is what drifts when a profile is revised.
_HARDWARE_PATH_PREFIX = "hardware_component."

#: Columns whose value is a Postgres array.
_HARDWARE_ARRAY_COLUMNS = frozenset({"compliance", "designators"})

#: Columns Postgres will cast from a string but which must be a real int/None.
_HARDWARE_INT_COLUMNS = frozenset({"quantity"})

#: numeric(18,6). Passed as a string; Postgres casts it. NEVER through a float
#: — see _numeric_or_none and the column comment in migration 0011.
_HARDWARE_NUMERIC_COLUMNS = frozenset({"unit_price"})

#: Boolean, where `False` is a stated fact rather than an absence.
_HARDWARE_BOOL_COLUMNS = frozenset({"do_not_populate"})

#: Every column `_hardware_components_batch` writes.
#:
#: ⚠ `extended_price` IS ABSENT, AND ITS ABSENCE IS REQUIRED. It is
#: `GENERATED ALWAYS AS (quantity * unit_price) STORED`, and Postgres rejects
#: an INSERT that names a generated column at all — not just one that gives it
#: a wrong value.
_HARDWARE_COLUMNS: tuple[str, ...] = (
    "id",
    "tenant_id",
    "bom_document_id",
    "parent_id",
    "product_name",
    "product_version",
    "product_details",
    "warranty_amc",
    "manufacturer_name",
    "manufacturer_location",
    "manufacturing_date",
    "supplier_info",
    "supplier_location",
    "model_number",
    "serial_number",
    "technical_specification",
    "component_supplier_info",
    "component_supplier_location",
    "technology_node",
    "compliance",
    "power_supply",
    "license_info",
    "test_result",
    "firmware_version",
    "origin",
    "criticality",
    "quantity",
    "designators",
    "package_footprint",
    "supplier_sku",
    "preferred_supplier",
    "unit_price",
    "currency",
    "do_not_populate",
    "assembly_type",
    "lifecycle_status",
    "datasheet_url",
    "enriched_fields",
    "field_status",
    "manufacturing_field_status",
    "source_engine",
    # ⚠ HOW ELEMENT 24 WAS ARRIVED AT. Without these two, an empty findings
    # list cannot be told from a search that never ran. See migration 0013.
    "vuln_match_status",
    "cpe23_candidates",
)


def _hardware_components_batch(
    components: Sequence[dict[str, Any]],
    tenant_id: str,
    bom_document_id: str,
    hardware_ids: dict[str, str],
) -> CopyBatch:
    """Plan the `normalize.hardware_components` batch.

    ⚠ PARENTS BEFORE CHILDREN, AND ALSO A DEFERRABLE CONSTRAINT.

    `flatten()` walks depth-first so a parent always precedes its children
    here, which keeps the common path fast. That ordering is NOT what makes
    this correct: `writer.py` chunks at 500 rows per INSERT and a
    non-deferrable self-FK is checked at the end of each statement, so a
    700-node assembly could split a parent from its child across chunks.
    Migration 0011 made the constraint DEFERRABLE INITIALLY DEFERRED for that
    reason. Ordering is the fast path; the constraint is the floor.
    """
    batch = CopyBatch(table="normalize.hardware_components", columns=_HARDWARE_COLUMNS)

    for component in components:
        local_id = _text(component.get("_local_id"))
        parent_local_id = _text(component.get("_parent_local_id"))
        row: list[Any] = [
            hardware_ids[local_id],
            tenant_id,
            bom_document_id,
            hardware_ids.get(parent_local_id) if parent_local_id else None,
        ]

        for column in _HARDWARE_COLUMNS[4:]:
            row.append(_hardware_value(component, column))

        batch.rows.append(tuple(row))

    return batch


def _hardware_value(component: dict[str, Any], column: str) -> Any:
    """One column's value out of a flat hardware row."""
    if column == "field_status":
        return json.dumps(_hardware_field_status(component, certin=True))
    if column == "manufacturing_field_status":
        return json.dumps(_hardware_field_status(component, certin=False))
    if column == "enriched_fields":
        raw = component.get("_enriched_fields")
        return json.dumps(raw if isinstance(raw, dict) else {})
    if column == "source_engine":
        return _text(component.get("_source_engine")) or None
    if column == "vuln_match_status":
        # ⚠ DEFAULTS TO `not-attempted`, NEVER TO NULL OR `no-match`. A row
        # written before this column existed, or by a path that does not match,
        # genuinely has not been searched — and `no-match` would render as
        # "clear" in a compliance document.
        status = _text(component.get("_vuln_match_status"))
        return status or "not-attempted"
    if column == "cpe23_candidates":
        raw = component.get("_cpe23_candidates")
        return [_text(v) for v in raw if _text(v)] if isinstance(raw, list) else []

    value = _hardware_lookup(component, column)

    if column in _HARDWARE_ARRAY_COLUMNS:
        # `not-provided` is the sentinel for an absent list. It is a real,
        # reported fact in `field_status`; the COLUMN gets an empty array,
        # because a text[] holding the literal string "not-provided" would be
        # read by every consumer as a compliance certification named
        # "not-provided".
        if not isinstance(value, list):
            return []
        return [_text(v) for v in value if _text(v)]

    if column in _HARDWARE_BOOL_COLUMNS:
        return bool(value) if isinstance(value, bool) else False

    if column in _HARDWARE_INT_COLUMNS:
        return _int_or_none(value)

    if column in _HARDWARE_NUMERIC_COLUMNS:
        return _hardware_price(value)

    if column == "manufacturing_date":
        return _hardware_date(value)

    if column == "product_name":
        # NOT NULL. Every path upstream guarantees one (csv_import._build falls
        # back to the part number, then to "unnamed component (row n)"), so
        # this is a defensive floor rather than the expected case.
        return _text(value) or "unnamed component"

    text = _text(value)
    if not text or text == "not-provided":
        # ⚠ NULL IN THE COLUMN, `not-provided` IN field_status. The gap is
        # REPORTED — that is what field_status is — while the column stays
        # queryable. Storing the literal string would make every `WHERE origin
        # IS NULL` miss and every rendered value read as a real answer.
        return None
    return text


def _hardware_lookup(component: dict[str, Any], column: str) -> Any:
    """Read one column out of a flat hardware row, either key spelling.

    ⚠ TWO SPELLINGS REACH THIS ROW, AND THAT IS NOT A BUG TO FIX HERE.

    A list-valued CERT-In element keeps the profile's `[]` notation in its key
    (`hardware_component.compliance[]`) because `HBOM_FIELDS` is generated
    verbatim from the YAML. A manufacturing element does not
    (`hardware_component.designators`) because `fields_from_profile` strips the
    suffix while building its `Field`s.

    Both are correct for SCORING — each field list matches the keys it wrote,
    which is why coverage has always been right. Only a consumer reading by
    column name, like this one, sees the difference. Normalising it in
    `flatten()` instead would change the keys `_SCORED` matches on and silently
    collapse CERT-In coverage to zero.

    So the writer accepts both. Found by the compliance array arriving empty in
    a real plan: `compliance` was looked up unbracketed, missed, and every
    RoHS/CE certification would have been dropped on write while `field_status`
    still recorded it as present.
    """
    if (key := _HARDWARE_PATH_PREFIX + column) in component:
        return component[key]
    return component.get(key + "[]")


def _hardware_field_status(component: dict[str, Any], *, certin: bool) -> dict[str, str]:
    """Which fields held a substantive value, and which were declared absent.

    ⚠ TWO SEPARATE MAPS, NOT ONE WITH NAMESPACED KEYS.

    `field_status` answers a CERT-In question; `manufacturing_field_status`
    answers an AxeBOM one. Nesting the second inside the first would make every
    reader parse a discriminator to find out whether a key it is looking at is
    a compliance fact — and one that guessed wrong would report an AxeBOM field
    as a CERT-In gap.
    """
    prefix_certin = "certin.hbom."
    out: dict[str, str] = {}
    for key, value in component.items():
        if not key.startswith(_HARDWARE_PATH_PREFIX):
            continue
        # Strip the profile's `[]` list notation: field_status keys are column
        # names, and `compliance[]` is not one.
        column = key[len(_HARDWARE_PATH_PREFIX) :].removesuffix("[]")
        is_manufacturing = column in _MANUFACTURING_COLUMNS
        if certin == is_manufacturing:
            continue
        out[column] = "not-provided" if _is_absent(value) else "present"
    if certin:
        out.setdefault("_profile", prefix_certin.rstrip("."))
    return out


#: Columns that belong to the manufacturing profile rather than CERT-In.
#:
#: ⚠ `product_details` IS ABSENT ON PURPOSE. Both profiles score it — CERT-In
#: element 3, and the manufacturing "Description" — because it is one stored
#: fact answering two questions. It is a CERT-In column, so it belongs in
#: `field_status`; the manufacturing profile scores the same value without
#: claiming the column.
_MANUFACTURING_COLUMNS = frozenset(
    {
        "quantity",
        "designators",
        "package_footprint",
        "supplier_sku",
        "preferred_supplier",
        "unit_price",
        "currency",
        "do_not_populate",
        "assembly_type",
        "lifecycle_status",
        "datasheet_url",
        "alternates",
    }
)


def _is_absent(value: Any) -> bool:
    """Whether a flat-row value carries no substantive content.

    Mirrors `coverage.is_substantive`'s answer without importing it — a
    boolean is always an answer, including False.
    """
    if isinstance(value, bool):
        return False
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip().lower() in ("", "not-provided", "unknown", "noassertion")
    if isinstance(value, (list, tuple, dict)):
        return not value
    return False


def _hardware_price(value: Any) -> str | None:
    """A unit price, passed to Postgres as a STRING for it to cast.

    ⚠ NOT `_numeric_or_none`, AND THE DIFFERENCE SILENTLY NULLED EVERY PRICE.

    `_numeric_or_none` exists for `ai_models.risk_score`, which Trusera's ai-bom
    emits as a real float; it rejects strings on purpose, because a string
    satisfies no numeric column there. Hardware prices are the opposite case:
    `csv_import._parse_price` keeps them as strings ALL THE WAY HERE precisely
    so they never pass through a Python float, because binary floating point
    cannot represent 0.10 and the error accumulates across a 4000-line BOM into
    an extended total somebody procures against.

    So the string goes to Postgres and `numeric(18,6)` parses it exactly. What
    this function adds is the same protection `_hardware_date` gives: a cell
    that will not parse is DROPPED rather than sent, because one bad price
    would otherwise fail the entire batch and take a 400-row parts list with
    it.

    Found by a live loader read returning empty prices for a CSV that plainly
    had them.
    """
    text = _text(value)
    if not text or text == "not-provided":
        return None
    try:
        if float(text) < 0:
            return None
    except ValueError:
        return None
    return text


def _hardware_date(value: Any) -> str | None:
    """A manufacturing date, or None.

    ⚠ A DATE COLUMN FED FROM A SPREADSHEET CELL, WHICH IS THE WHOLE PROBLEM.

    `_crypto_assets_batch` can pass dates through as plain strings because
    `crypto.py` guarantees ISO-8601. Hardware dates come from a customer's
    export, where "Q3 2024", "week 32" and "2024-13-45" are all things people
    actually type. Handing any of those to Postgres fails the ENTIRE batch —
    one bad cell taking down a 400-row parts list.

    So an unparseable value is DROPPED, matching `services/project/internal
    /store/hbom.go`'s `parseManufacturingDate`, which already does exactly this
    on the Go side. The gap is still reported through `field_status`.
    """
    text = _text(value)
    if not text or text == "not-provided":
        return None
    try:
        datetime.date.fromisoformat(text[:10])
    except ValueError:
        return None
    return text[:10]


def _hardware_alternates_batch(
    components: Sequence[dict[str, Any]],
    tenant_id: str,
    hardware_ids: dict[str, str],
) -> CopyBatch:
    """Plan the `normalize.hardware_component_alternates` batch.

    Reads each row's own `hardware_component.alternates` list, the same way
    `_ai_datasets_batch` reads a model's `_datasets` rather than a second
    top-level canonical list.
    """
    batch = CopyBatch(
        table="normalize.hardware_component_alternates",
        columns=(
            "tenant_id",
            "hardware_component_id",
            "ordinal",
            "manufacturer_name",
            "model_number",
            "supplier_info",
            "supplier_sku",
            "lifecycle_status",
            "equivalence",
            "approval_note",
        ),
    )

    for component in components:
        alternates = component.get(_HARDWARE_PATH_PREFIX + "alternates")
        if not isinstance(alternates, list):
            continue
        component_id = hardware_ids[_text(component.get("_local_id"))]
        for index, alternate in enumerate(alternates):
            if not isinstance(alternate, dict):
                continue
            manufacturer = _text(alternate.get("manufacturer_name"))
            model_number = _text(alternate.get("model_number"))
            sku = _text(alternate.get("supplier_sku"))
            if not (manufacturer or model_number or sku):
                # Mirrors the `hardware_alternate_identifiable` CHECK. Skipped
                # rather than sent, so one unnamed alternate cannot fail the
                # whole batch.
                continue
            batch.rows.append(
                (
                    tenant_id,
                    component_id,
                    _int_or_none(alternate.get("ordinal")) or index,
                    manufacturer or None,
                    model_number or None,
                    _text(alternate.get("supplier_info")) or None,
                    sku or None,
                    _text(alternate.get("lifecycle_status")) or None,
                    _text(alternate.get("equivalence")) or "unverified",
                    _text(alternate.get("approval_note")) or None,
                )
            )

    return batch


def _hardware_findings_batch(
    components: Sequence[dict[str, Any]],
    tenant_id: str,
    bom_document_id: str,
    hardware_ids: dict[str, str],
) -> tuple[CopyBatch, list[dict[str, Any]]]:
    """Plan the `normalize.hardware_findings` batch — CERT-In element 24.

    ⚠ EVERY ROW HERE IS ADVISORY, AND THE COLUMNS SAY SO RATHER THAN A
    FOOTNOTE SAYING SO. `match_basis` and `match_confidence` travel with the
    finding all the way to the report, because a CVE reached through a
    wildcarded vendor is weaker evidence than one reached through all three
    parts, and a reader shown only a severity cannot tell them apart.

    ⚠ SEVERITIES HERE ARE NEVER SUMMED INTO THE COUNTS AN SBOM REPORT QUOTES.
    An SBOM finding is keyed on a purl the ecosystem minted; this one is keyed
    on a CPE built from a manufacturer string somebody typed. Blending them
    would give a single "3 critical" figure of which some part is a fact and
    some part is a guess, with nothing saying which.
    """
    batch = CopyBatch(
        table="normalize.hardware_findings",
        columns=(
            "tenant_id",
            "bom_document_id",
            "hardware_component_id",
            "cluster_id",
            "display_id",
            "cpe23",
            "match_basis",
            "match_confidence",
            "severity",
            "cvss_score",
            "cvss_vector",
            "description",
            "source",
            "source_version",
        ),
    )
    diagnostics: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    unresolved = 0

    for component in components:
        findings = component.get("_vuln_findings")
        if not isinstance(findings, list):
            continue
        component_id = hardware_ids[_text(component.get("_local_id"))]
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            cluster_id = _text(finding.get("cluster_id"))
            cve_id = _text(finding.get("cve_id"))
            cpe23 = _text(finding.get("cpe23"))
            if not (cve_id and cpe23):
                continue
            if not _is_uuid(cluster_id):
                # ⚠ SKIPPED AND COUNTED, NEVER SKIPPED SILENTLY. cluster_id is
                # NOT NULL with a foreign key; a row without one would abort
                # the whole COPY and take the entire hardware BOM with it.
                # Dropping it quietly would instead under-report element 24 —
                # so the document carries a diagnostic saying how many.
                unresolved += 1
                continue

            # Mirrors UNIQUE (hardware_component_id, cluster_id, cpe23). COPY
            # has no ON CONFLICT, so a duplicate inside one batch aborts it.
            key = (component_id, cluster_id, cpe23)
            if key in seen:
                continue
            seen.add(key)

            batch.rows.append(
                (
                    tenant_id,
                    bom_document_id,
                    component_id,
                    cluster_id,
                    cve_id,
                    cpe23,
                    _text(finding.get("match_basis")) or "vendor+product",
                    # ⚠ FLOORS AT `low`, THE SAME DEFAULT THE COLUMN CARRIES.
                    # A default that flatters a guess is how an advisory
                    # becomes a claim somebody acts on.
                    _text(finding.get("match_confidence")) or "low",
                    _hardware_severity(finding.get("severity")),
                    _numeric_or_none(finding.get("cvss_score")),
                    _text(finding.get("cvss_vector")) or None,
                    _text(finding.get("description")) or None,
                    _text(finding.get("source")) or "nvd",
                    _text(finding.get("source_version")) or None,
                )
            )

    if unresolved:
        diagnostics.append(
            {
                "severity": "warn",
                "code": "NORMALIZE_HARDWARE_FINDING_UNCLUSTERED",
                "message": (
                    f"{unresolved} hardware vulnerability match(es) had no resolved cluster id "
                    "and were not stored; element 24 under-reports for this document"
                ),
            }
        )

    return batch, diagnostics


#: The severities `normalize.hardware_findings.severity` accepts.
_HARDWARE_SEVERITIES = frozenset({"critical", "high", "medium", "low", "none", "unknown"})


def _hardware_severity(value: Any) -> str | None:
    """Fold a source's severity label to the column's CHECK, or NULL.

    ⚠ AN UNRECOGNIZED SEVERITY BECOMES NULL, NOT `unknown` AND NOT `low`.
    NULL means "the source did not give us one we understand"; `unknown` is a
    value a source can itself assert. Collapsing them would make a parsing gap
    indistinguishable from NVD's own uncertainty.
    """
    text = _text(value).lower()
    return text if text in _HARDWARE_SEVERITIES else None
