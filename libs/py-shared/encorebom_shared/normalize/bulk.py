"""Bulk insertion of the canonical model.

⚠ 50k+ COMPONENTS AND 200k+ FINDINGS PER SCAN IS NORMAL for a large monorepo.

Row-by-row INSERT at that size is not slow, it is unusable — and the failure
mode is a scan that appears to hang. `COPY` is the only workable shape, so this
module emits COPY-ready tuples rather than statements.

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
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from .identity import normalize_path

#: Refuse rather than truncate above this many components.
MAX_COMPONENTS = 250_000

#: And above this many findings. A monorepo with 50k components routinely has
#: several hundred thousand findings.
MAX_FINDINGS = 1_000_000

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

    out.batches.append(_components_batch(components, tenant_id, bom_document_id))
    out.batches.append(_locations_batch(components, bom_document_id))
    out.batches.append(_findings_batch(findings, tenant_id, bom_document_id))
    out.batches.append(_dependencies_batch(canonical, tenant_id, bom_document_id))

    return out


def _components_batch(
    components: Sequence[dict[str, Any]], tenant_id: str, bom_document_id: str
) -> CopyBatch:
    batch = CopyBatch(
        table="normalize.components",
        columns=(
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
        batch.rows.append(
            (
                tenant_id,
                bom_document_id,
                _text(component.get("component_key")),
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


def _locations_batch(components: Sequence[dict[str, Any]], bom_document_id: str) -> CopyBatch:
    """⚠ Identity is the package; locations are 1:N.

    The same jar vendored at two paths is one component row and two location
    rows. Putting the path in the component key inflates every count.
    """
    batch = CopyBatch(
        table="normalize.component_locations",
        columns=("bom_document_id", "component_key", "path", "layer", "sha256"),
    )

    for component in components:
        for location in component.get("locations") or []:
            batch.rows.append(
                (
                    bom_document_id,
                    _text(component.get("component_key")),
                    normalize_path(str(location.get("path", ""))),
                    _text(location.get("layer")),
                    _text(location.get("sha256")),
                )
            )

    return batch


def _findings_batch(
    findings: Sequence[dict[str, Any]], tenant_id: str, bom_document_id: str
) -> CopyBatch:
    batch = CopyBatch(
        table="normalize.findings",
        columns=(
            "tenant_id",
            "bom_document_id",
            "vuln_cluster_id",
            "component_key",
            "display_id_at_render",
            "severity_effective",
            "severity_rule",
            "severity_conflict",
            "detected_by",
            "cvss_vectors",
            "fixed_versions",
            "fixed_in_min",
            "fix_version_ordering",
        ),
    )

    for finding in findings:
        batch.rows.append(
            (
                tenant_id,
                bom_document_id,
                _text(finding.get("vuln_cluster_id")),
                _text(finding.get("component_key")),
                # ⚠ PINNED. A report issued in March still says CVE-2021-44228
                # in September, even after the cluster absorbs more aliases.
                _text(finding.get("display_id")),
                _text(finding.get("severity_effective")),
                _text(finding.get("severity_rule")),
                bool(finding.get("severity_conflict")),
                json.dumps(finding.get("detected_by") or []),
                json.dumps(finding.get("cvss_vectors") or []),
                json.dumps(finding.get("fixed_versions") or []),
                _text(finding.get("fixed_in_min")),
                _text(finding.get("fix_version_ordering")),
            )
        )

    return batch


def _dependencies_batch(
    canonical: dict[str, Any], tenant_id: str, bom_document_id: str
) -> CopyBatch:
    batch = CopyBatch(
        table="normalize.component_dependencies",
        columns=(
            "tenant_id",
            "bom_document_id",
            "from_key",
            "to_key",
            "relationship",
            "scope",
            "owning_engine",
            "confidence",
        ),
    )

    for edge in (canonical.get("graph") or {}).get("edges") or []:
        batch.rows.append(
            (
                tenant_id,
                bom_document_id,
                _text(edge.get("from")),
                _text(edge.get("to")),
                _text(edge.get("relationship")) or "depends_on",
                _text(edge.get("scope")) or "required",
                _text(edge.get("owning_engine")),
                _text(edge.get("confidence")) or "medium",
            )
        )

    return batch


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


def copy_statement(batch: CopyBatch) -> str:
    """The COPY statement for a batch.

    Column names are interpolated because they are OUR identifiers from a
    literal tuple above, never user input. Every VALUE goes through the driver's
    parameter binding, which is where injection would otherwise enter.
    """
    columns = ", ".join(batch.columns)
    return f"COPY {batch.table} ({columns}) FROM STDIN"


def iter_rows(batches: Iterable[CopyBatch]):
    """Yield (table, columns, row) for a driver to stream."""
    for batch in batches:
        for row in batch.rows:
            yield batch.table, batch.columns, row
