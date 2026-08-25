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

        # cluster_id is a uuid column; the canonical model's vuln_cluster_id is
        # a string (see pipeline.py's _default_ids / normalize.vuln_clusters).
        # Deriving it the same way _component_id derives a component's row id
        # keeps the two consistent and keeps this deterministic — the same
        # cluster string always mints the same uuid for a given document.
        cluster_id = str(
            uuid.uuid5(
                _SURROGATE_NAMESPACE,
                f"cluster:{bom_document_id}:{_text(finding.get('vuln_cluster_id'))}",
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
