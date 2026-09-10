"""Executes a normalization result against a real Postgres connection.

⚠ THIS MODULE IS NOT WIRED INTO ANY DEPLOYED WORKER, AND THAT IS DELIBERATE.

`axebom_shared.config`'s own words: "WORKERS HOLD NO CREDENTIALS... no
database password here... If a future change appears to need a credential in
a worker, the design has gone wrong; route the work through the fetcher
instead." Giving a live, deployed worker a Postgres credential is a real
security-architecture decision — which trust boundary that credential lives
behind, whether it belongs to the process that also parses adversarial
scanner JSON, how normalization gets TRIGGERED for a live scan at all — none
of which this module decides. It exists so `bulk.plan()`'s output is
genuinely executable and testable rather than, in its own words, "never
executed by anything but its own test." The caller supplies an already-open
connection; this module never loads a credential itself.

⚠ THE CALLER'S CONNECTION SHOULD USE `autocommit=True` — psycopg's own
recommended default, and not merely a style preference here.
`with conn.transaction():` behaves differently depending on whether a
transaction is ALREADY open on the connection: fresh, it is a real
BEGIN/COMMIT; if the caller already left one open with a bare
`cur.execute()` elsewhere, it silently downgrades to a SAVEPOINT instead.
The write inside that savepoint looks committed to the same session
(read-your-own-writes) and then evaporates the moment the connection closes
or rolls back its still-open outer transaction — a write that appears to
have succeeded and was never durable. This is exactly the bug
`test_writer.py`'s `pg_conn` fixture hit and documents in full.

⚠ SET LOCAL, NOT SET — mirrors libs/go-shared/platform/db/tenant.go exactly.

`SELECT set_config('app.current_tenant_id', %s, true)` — the third argument is
`is_local`, so the setting reverts at COMMIT or ROLLBACK and can never leak
onto a pooled connection's next, differently-tenanted use. Parameterized, not
interpolated: tenant_id reaches here from a trusted caller today, but string-
building it into SQL would make any future path that forgets to validate it an
injection point.

⚠ CHUNKED MULTI-ROW INSERT, NOT COPY — bulk.py's own docstring explains why:
Postgres refuses `COPY FROM` outright against any row-level-security-enabled
table, permanently, and every table this module writes to has RLS FORCED
(CLAUDE.md invariant 6). `_CHUNK_SIZE` rows go into one `INSERT ... VALUES
(...), (...), ...` statement — Postgres's own bind-parameter ceiling
(65535) is the hard reason there is a limit at all; 500 is comfortably under
it for even the widest table here (normalize.components, 21 columns) and
keeps each statement's own size reasonable.

See `docs/03-NORMALIZER-SPEC.md` §8 and `libs/py-shared/axebom_shared/
normalize/bulk.py`.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

from . import bulk

#: Rows per INSERT statement. See the module docstring for why this exists
#: and how the number was chosen.
_CHUNK_SIZE = 500


class Cursor(Protocol):
    def execute(self, query: str, params: Any = None) -> Any: ...
    def fetchone(self) -> Any: ...


class Connection(Protocol):
    """The slice of a psycopg Connection this module actually uses.

    A Protocol, not an import of `psycopg.Connection`, so a caller's test
    double does not have to be a real connection — only shaped like one.
    """

    def cursor(self) -> Cursor: ...
    def transaction(self) -> Any: ...


class RefusedError(Exception):
    """Raised when bulk.plan() refused the write — see BulkPlan.refused.

    Never caught and silently downgraded: a refusal means a cap was exceeded,
    and writing nothing is the correct behavior bulk.py already chose. This
    exception exists only to stop write_bom_document from committing a
    transaction it should not have opened rows for in the first place.
    """

    def __init__(self, diagnostics: list[dict[str, Any]]):
        self.diagnostics = diagnostics
        codes = ", ".join(sorted({d.get("code", "") for d in diagnostics}))
        super().__init__(f"normalization plan was refused: {codes}")


@dataclass
class WriteResult:
    """What a write actually did."""

    bom_document_id: str
    #: Every diagnostic bulk.plan() produced, INCLUDING on a successful write —
    #: a dropped dangling reference does not fail the write, but the caller
    #: must still be able to see it happened. Never inspect only on failure.
    diagnostics: list[dict[str, Any]] = field(default_factory=list)


def write_bom_document(
    conn: Connection,
    *,
    tenant_id: str,
    scan_id: str,
    bom_type: str,
    normalization_version: int,
    canonical: dict[str, Any],
) -> WriteResult:
    """Insert one normalize.bom_documents row and everything bulk.plan()
    produces from `canonical`, all inside one tenant-scoped transaction.

    ⚠ THE HEADER ROW IS INSERTED FIRST, WITH `RETURNING id` — NOT LAST.

    It is the one insert in this module that is naturally a SINGLE row, so a
    plain `INSERT ... RETURNING id` is simplest — and its id is exactly the
    bom_document_id every chunked batch below needs to embed. Minting it any
    other way — a second, disconnected uuid generated here in Python — would
    require a follow-up UPDATE to reconcile the two, for no benefit.

    Raises RefusedError if bulk.plan() refuses (a cap was exceeded) — nothing
    is written; the transaction is left to roll back.
    """
    alias_snapshot_id = _optional_uuid(
        (canonical.get("provenance") or {}).get("alias_snapshot_id"),
        field_name="canonical['provenance']['alias_snapshot_id']",
    )

    # ⚠ NULL IS LEGAL FOR THE BOM TYPES THAT HAVE NO ALIAS CLOSURE, AND ONLY
    # FOR THOSE. migration 0012 made alias_snapshot_id nullable so CBOM, AIBOM,
    # QBOM and HBOM could stop minting a meaningless uuid to satisfy NOT NULL.
    # SBOM is the one type the column exists FOR: its snapshot is what makes a
    # finding's alias clustering explainable months later (ADR-0005).
    #
    # Without this guard, an SBOM path that silently stopped minting a snapshot
    # would lose exactly that provenance with nothing failing anywhere — the
    # column would just accept NULL. That is the failure mode dropping a NOT
    # NULL always risks, so the constraint moves here rather than disappearing.
    if bom_type == "SBOM" and alias_snapshot_id is None:
        raise ValueError(
            "canonical['provenance']['alias_snapshot_id'] is required for an "
            "SBOM: the alias snapshot is what makes a finding's cluster "
            "explainable at re-normalization time. It is optional only for the "
            "BOM types that run no alias closure (CBOM, AIBOM, QBOM, HBOM)."
        )

    coverage = canonical.get("coverage") or {}

    # ⚠ SCORED FIELD SETS THAT ARE NOT COMPLIANCE, KEPT OUT OF THE TWO COLUMNS
    # THAT ARE.
    #
    # completeness_pct and declaration_pct answer "how much of what CERT-In
    # requires is present". A supplementary profile — HBOM's manufacturing
    # readiness today — answers a different question with a different authority
    # behind it, so it lands in its own column, keyed by profile id, carrying
    # its own label and an is_compliance flag. Nothing here can move the two
    # numbers above; see migration 0012's comment for why this is a keyed jsonb
    # rather than another pair of numeric columns.
    #
    # Empty for every BOM type that has no supplementary profile, which is all
    # of them except HBOM.
    supplementary = canonical.get("supplementary_coverage") or {}

    with conn.transaction():
        cur = conn.cursor()
        cur.execute("SELECT set_config('app.current_tenant_id', %s, true)", (tenant_id,))

        cur.execute(
            """
            INSERT INTO normalize.bom_documents
                (tenant_id, scan_id, bom_type, normalization_version,
                 ruleset_version, alias_snapshot_id, spdx_license_list_version,
                 completeness_pct, declaration_pct, coverage_breakdown,
                 unidentified_count, project_id, supplementary_coverage,
                 normalize_diagnostics)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                tenant_id,
                scan_id,
                bom_type,
                normalization_version,
                canonical.get("ruleset_version") or "",
                alias_snapshot_id,
                canonical.get("spdx_license_list_version") or "",
                coverage.get("completeness_pct"),
                coverage.get("declaration_pct"),
                json.dumps(coverage),
                canonical.get("unidentified_count") or 0,
                # ⚠ HBOM's SECOND LINEAGE KEY. An imported hardware BOM has no
                # scan, so services/project borrows scan_id for the project id;
                # a SCANNED one carries a real scan_id. Both set project_id,
                # which is what resolveHBOMDocument reads — see migration 0012.
                # None for every other BOM type, which resolves by scan_id.
                canonical.get("project_id"),
                json.dumps(supplementary),
                # ⚠ THIS USED TO BE COMPUTED AND DISCARDED. Every normalize
                # consumer (aibom, cbom, hbom) sets `canonical["diagnostics"]`
                # and nothing read it, so every statement the normalizer made
                # about what it could NOT resolve died at this boundary — a
                # direct CLAUDE.md invariant 12 failure, product-wide.
                # See migrations/normalize/0017.
                json.dumps(canonical.get("diagnostics") or []),
            ),
        )
        row = cur.fetchone()
        bom_document_id = str(row[0])

        # ⚠ A PLAIN INSERT, NOT A CopyBatch, AND THE SCHEMA FORCES IT.
        # normalize.license_refs is UNIQUE (tenant_id, slug) and COPY cannot
        # express ON CONFLICT — so the second scan of a project with an
        # unmappable licence would abort the whole normalization.
        #
        # ⚠ DO NOTHING, NOT DO UPDATE. `first_seen_scan_id` means what it says:
        # a later scan re-reporting the same slug must not overwrite where it
        # first appeared, or "when did we first see this?" stops being
        # answerable — which is the question the column exists for.
        for slug, raw_text in bulk.license_refs(canonical.get("components") or []):
            cur.execute(
                """
                INSERT INTO normalize.license_refs
                    (tenant_id, slug, raw_text, first_seen_scan_id)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (tenant_id, slug) DO NOTHING
                """,
                (tenant_id, slug, raw_text, scan_id),
            )

        result = bulk.plan(canonical, tenant_id=tenant_id, bom_document_id=bom_document_id)
        if result.refused:
            # Raising inside the `with conn.transaction()` block rolls the
            # header row insert back too — a bom_documents row with nothing
            # under it would resolve as a real, empty document to every
            # reader that queries by (scan_id, bom_type), which is a worse
            # lie than not existing at all.
            raise RefusedError(result.diagnostics)

        for batch in result.batches:
            _insert_batch(cur, batch)

    return WriteResult(bom_document_id=bom_document_id, diagnostics=result.diagnostics)


def _insert_batch(cur: Cursor, batch: bulk.CopyBatch) -> None:
    """Write one table's rows as chunked `INSERT ... VALUES (...), (...)`.

    ⚠ NOT COPY — see the module docstring for why COPY is not an option
    against an RLS-enabled table at all, ever.

    Column names are interpolated because they are OUR identifiers, from the
    literal tuples bulk.py builds — never user input. Every VALUE goes
    through the driver's parameter binding, which is where injection would
    otherwise enter; the same discipline bulk.py's own docstring states for
    the COPY form this replaced.
    """
    if not batch.rows:
        # A scan with no dependency edges is entirely normal (a leaf
        # package) — not a reason to touch the network.
        return

    columns = ", ".join(batch.columns)
    placeholder_row = "(" + ", ".join(["%s"] * len(batch.columns)) + ")"

    rows = batch.rows
    for start in range(0, len(rows), _CHUNK_SIZE):
        chunk = rows[start : start + _CHUNK_SIZE]
        placeholders = ", ".join([placeholder_row] * len(chunk))
        flat_params = [value for row in chunk for value in row]
        # table and columns are OUR OWN identifiers from bulk.CopyBatch, never
        # user input — every value is bound through the parameter list below,
        # which is where injection would otherwise enter.
        cur.execute(
            f"INSERT INTO {batch.table} ({columns}) VALUES {placeholders}",  # noqa: S608
            flat_params,
        )


def _optional_uuid(value: Any, *, field_name: str) -> str | None:
    """Normalize a uuid-or-absent field, failing with a message naming it.

    ⚠ None IS A LEGITIMATE ANSWER, AND A MALFORMED STRING STILL IS NOT.

    alias_snapshot_id is nullable as of
    migrations/normalize/0012_bom_document_provenance.sql: the BOM types with
    no alias-closure pipeline (CBOM, AIBOM, QBOM, HBOM) have no snapshot to
    point at, and they used to mint a throwaway uuid purely to satisfy NOT
    NULL. None says the true thing; the column's new foreign key would reject
    the throwaway anyway.

    What has NOT changed is the error for a value that is present but is not a
    uuid. Production values come from normalize.alias_snapshot, but fixture and
    test callers routinely pass a human-readable placeholder like
    "fixture-npm-simple-aliases", and "invalid input syntax for type uuid:
    fixture-npm-simple-aliases" from three network round trips away is a worse
    first message than this one.
    """
    if value is None:
        return None
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError(
            f"{field_name} must be a real uuid (got {value!r}); a fixture-style "
            "placeholder string will fail the alias_snapshot_id uuid column "
            "with a much less legible Postgres error"
        ) from exc
