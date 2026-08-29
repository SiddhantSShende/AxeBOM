"""writer.py against a REAL Postgres connection.

⚠ INTEGRATION TESTS, SKIPPED WHEN THE STACK IS DOWN — same convention the Go
side uses (`newFixture` in orchestrator_test.go): try to connect, `pytest.skip`
with a message naming the fix, never fail a clean checkout that has not run
`task dev` yet.

The schema-agreement test below is the one that matters most in this file: it
is what would have caught EVERY column-name bug bulk.py had before this
change, mechanically, rather than by a human re-reading two files side by
side and hoping to notice a mismatch.

⚠ THIS FILE CONNECTS AS `axebom_app`, NOT AS A TEST-ONLY SUPERUSER.

The point is to prove the write works under the SAME RLS-respecting,
non-superuser privileges any real caller would have — not under a role that
happens to bypass the exact policies this write depends on.
"""

from __future__ import annotations

import os
import uuid

import pytest

from .test_bulk import ai_model, component, crypto_asset, model
from .writer import RefusedError, _require_uuid, write_bom_document

psycopg = pytest.importorskip("psycopg")


#: (table, the column that names a document) — deletion order matters only in
#: that bom_documents must go last; nothing here has a real FK to enforce it,
#: but leaving orphaned children behind on a partial failure would still be
#: wrong.
_CHILD_TABLES = (
    "normalize.component_dependencies",
    "normalize.component_locations",
    "normalize.findings",
    "normalize.components",
    "normalize.crypto_assets",
)


@pytest.fixture
def pg_conn():
    try:
        conn = psycopg.connect(
            host=os.environ.get("POSTGRES_HOST", "localhost"),
            port=int(os.environ.get("POSTGRES_PORT", "55432")),
            dbname=os.environ.get("POSTGRES_DB", "axebom"),
            user=os.environ.get("POSTGRES_APP_ROLE", "axebom_app"),
            password=os.environ.get("POSTGRES_APP_PASSWORD", "axebom_app"),
            connect_timeout=5,
            # ⚠ AUTOCOMMIT, DELIBERATELY — see write_bom_document's docstring
            # for the trap this avoids. Without it, a bare cur.execute() this
            # file runs OUTSIDE a `with conn.transaction():` block (every
            # assertion query after a write) leaves an ambient, uncommitted
            # transaction open. write_bom_document's OWN
            # `with conn.transaction():` still commits correctly the FIRST
            # time it runs on a fresh connection — but the CLEANUP fixture's
            # LATER `with conn.transaction():` then finds a transaction
            # already in progress and silently downgrades to a SAVEPOINT
            # instead of a real commit. The DELETE looks committed to the
            # session that ran it (read-your-own-writes) and then vanishes
            # the moment conn.close() discards the still-open outer
            # transaction — a cleanup that reports success and leaves the row
            # behind. autocommit means every bare statement commits on its
            # own and `with conn.transaction():` is always the real, explicit
            # kind — psycopg's own recommended default, not a test-only fix.
            autocommit=True,
        )
    except psycopg.OperationalError as exc:
        pytest.skip(f"database unavailable ({exc}) — run `task dev`")
    yield conn
    conn.close()


#: A real, fixed cluster id — canonical_model()'s findings carry this as
#: their vuln_cluster_id, and ensure_test_cluster below guarantees a
#: matching normalize.vuln_clusters row exists before any test writes a
#: finding referencing it. Fixed rather than minted per-test because
#: vuln_clusters is GLOBAL reference data (no tenant_id, no RLS, migration
#: 0002's own precedent) — one shared row, inserted idempotently, is the
#: correct shape here, not one-row-per-test cleanup.
_TEST_CLUSTER_ID = "01900000-0000-7000-8000-0000000000c1"


@pytest.fixture
def ensure_test_cluster(pg_conn):
    """Guarantees normalize.vuln_clusters has a row for _TEST_CLUSTER_ID.

    ⚠ REQUIRED SINCE findings_cluster_id_fkey (migration
    normalize/0007_findings_cluster_fk.sql). Before that FK existed, a
    finding could reference any cluster_id at all; now Postgres enforces
    that the row is real, which is the whole point of the FK — but it means
    this fixture, not bulk.py, is what makes canonical_model()'s fixture
    data representative of a real write path.
    """
    cur = pg_conn.cursor()
    cur.execute(
        "INSERT INTO normalize.vuln_clusters (id, display_id) VALUES (%s, %s) "
        "ON CONFLICT (id) DO NOTHING",
        (_TEST_CLUSTER_ID, "CVE-2024-0001"),
    )


@pytest.fixture
def written(pg_conn):
    """Tracks (tenant_id, bom_document_id) pairs a test wrote, and deletes
    every row under them on teardown — the same "tests must leave the
    database as they found it" discipline orchestrator_test.go's
    cleanupScan enforces on the Go side."""
    created: list[tuple[str, str]] = []
    yield created
    for tenant_id, doc_id in created:
        with pg_conn.transaction():
            cur = pg_conn.cursor()
            cur.execute("SELECT set_config('app.current_tenant_id', %s, true)", (tenant_id,))
            for table in _CHILD_TABLES:
                # table is one of our own fixed literals in _CHILD_TABLES above,
                # never user input.
                cur.execute(f"DELETE FROM {table} WHERE bom_document_id = %s", (doc_id,))  # noqa: S608
            cur.execute("DELETE FROM normalize.bom_documents WHERE id = %s", (doc_id,))


def canonical_model(tenant_suffix: str = "") -> dict:
    """A small but real canonical model — real enough to exercise every
    batch, small enough to read in one screen."""
    return {
        **model(
            components=[
                component(f"purl:pkg:npm/left{tenant_suffix}@1"),
                component(f"purl:pkg:npm/right{tenant_suffix}@1", locations=[{"path": "a.js"}]),
            ],
            findings=[
                {
                    # A real uuid — see _TEST_CLUSTER_ID and
                    # ensure_test_cluster, the fixture that gives it a
                    # matching normalize.vuln_clusters row.
                    "vuln_cluster_id": _TEST_CLUSTER_ID,
                    "component_key": f"purl:pkg:npm/left{tenant_suffix}@1",
                    "display_id": "CVE-2024-0001",
                    "severity_effective": "critical",
                    "severity_rule": "cvss-v4",
                    # ⚠ REQUIRED. Finding.fix_version_ordering has no default
                    # in the real dataclass — every finding a real pipeline
                    # run produces sets it — and the DB CHECK constraint only
                    # accepts 'known'/'unknown', never "" (bulk.py's `_text()`
                    # of an absent value). A fixture omitting it is not
                    # representative of anything normalize() actually emits.
                    "fix_version_ordering": "unknown",
                }
            ],
            edges=[
                {
                    "from": f"purl:pkg:npm/left{tenant_suffix}@1",
                    "to": f"purl:pkg:npm/right{tenant_suffix}@1",
                }
            ],
            # ⚠ bulk.plan() ALWAYS PRODUCES A normalize.crypto_assets BATCH,
            # regardless of `bom_type` — one row here is what gives the
            # schema-agreement test below something to check for that table
            # too, the same reason it would have caught `crypto_assets`'
            # column names being wrong the way it already caught findings'.
            # A real scan never mixes SBOM components and crypto assets in
            # one document; this fixture does, deliberately, exactly the way
            # it already exercises every OTHER table in one small model.
            crypto_assets=[crypto_asset("algorithm", primitive="pke")],
            # ⚠ SAME REASONING AS crypto_assets ABOVE, extended to all three
            # AI-model tables at once: one model with one dataset and one
            # dependency is what gives the schema-agreement test below
            # something to check for `ai_models`/`ai_datasets`
            # /`ai_model_dependencies` too.
            ai_models=[
                ai_model(
                    f"model-ref{tenant_suffix}",
                    model_name=f"model{tenant_suffix}",
                    datasets=[{"name": "fixture-dataset", "type": "text", "license": "MIT"}],
                    dependencies=[f"purl:pkg:npm/left{tenant_suffix}@1"],
                    risk_score=5.0,
                    owasp_llm_top10=["LLM01"],
                )
            ],
        ),
        "ruleset_version": "test-ruleset-1",
        "spdx_license_list_version": "3.24",
        "unidentified_count": 0,
        "coverage": {"completeness_pct": 42.5, "declaration_pct": 80.0},
        "provenance": {"alias_snapshot_id": str(uuid.uuid4())},
    }


# --------------------------------------------------------------------------
# Schema agreement — the test that would have caught every renamed column
# --------------------------------------------------------------------------


def test_every_planned_column_exists_in_the_live_schema(pg_conn, written, ensure_test_cluster) -> None:
    """For every table bulk.plan() writes to, every column it declares must
    be a real column in the live database. This is a MECHANICAL check
    against information_schema, not a human re-reading two files and hoping
    to spot a mismatch — which is exactly how `vuln_cluster_id`,
    `component_key` (as a findings column) and `severity_rule` went
    unnoticed: nothing had ever executed the COPY they described.
    """
    tenant_id = str(uuid.uuid4())
    canonical = canonical_model()

    result = write_bom_document(
        pg_conn,
        tenant_id=tenant_id,
        scan_id=str(uuid.uuid4()),
        bom_type="SBOM",
        normalization_version=1,
        canonical=canonical,
    )
    written.append((tenant_id, result.bom_document_id))

    from . import bulk

    plan = bulk.plan(canonical, tenant_id=tenant_id, bom_document_id=result.bom_document_id)
    assert not plan.refused

    cur = pg_conn.cursor()
    for batch in plan.batches:
        assert batch.rows, f"{batch.table} has no rows in this fixture; nothing would be checked"
        schema, table = batch.table.split(".")
        cur.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = %s AND table_name = %s",
            (schema, table),
        )
        live_columns = {row[0] for row in cur.fetchall()}
        missing = set(batch.columns) - live_columns
        assert not missing, (
            f"{batch.table} declares columns {sorted(missing)} that do not "
            f"exist in the live schema — live columns are {sorted(live_columns)}"
        )

    # bom_documents is written by a plain INSERT, not a CopyBatch, so its
    # column list lives in writer.py's SQL literal rather than in a
    # bulk.CopyBatch. Checked against the same live introspection anyway —
    # this is the one place a rename in the migration and a rename in the
    # INSERT could silently drift apart.
    cur.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'normalize' AND table_name = 'bom_documents'"
    )
    live_columns = {row[0] for row in cur.fetchall()}
    written_columns = {
        "tenant_id",
        "scan_id",
        "bom_type",
        "normalization_version",
        "ruleset_version",
        "alias_snapshot_id",
        "spdx_license_list_version",
        "completeness_pct",
        "declaration_pct",
        "coverage_breakdown",
        "unidentified_count",
    }
    missing = written_columns - live_columns
    assert not missing, f"normalize.bom_documents is missing {sorted(missing)}"


# --------------------------------------------------------------------------
# The write actually works
# --------------------------------------------------------------------------


def test_a_live_write_round_trips(pg_conn, written, ensure_test_cluster) -> None:
    tenant_id = str(uuid.uuid4())
    canonical = canonical_model()

    result = write_bom_document(
        pg_conn,
        tenant_id=tenant_id,
        scan_id=str(uuid.uuid4()),
        bom_type="SBOM",
        normalization_version=1,
        canonical=canonical,
    )
    written.append((tenant_id, result.bom_document_id))
    assert not result.diagnostics

    cur = pg_conn.cursor()
    # ⚠ SESSION-level (false), not is_local — these are bare statements
    # under an autocommit connection, each its own transaction, so an
    # is_local setting would revert before the very next statement.
    # Session scope is fine here: this connection belongs to one test
    # only, never pooled across tenants, unlike the request-scoped
    # connections write_bom_document and libs/go-shared/platform/db
    # actually serve.
    cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))

    cur.execute(
        "SELECT completeness_pct, declaration_pct FROM normalize.bom_documents WHERE id = %s",
        (result.bom_document_id,),
    )
    completeness, declaration = cur.fetchone()
    assert float(completeness) == 42.5
    assert float(declaration) == 80.0

    cur.execute(
        "SELECT count(*) FROM normalize.components WHERE bom_document_id = %s",
        (result.bom_document_id,),
    )
    assert cur.fetchone()[0] == 2

    # THE POINT OF THIS WHOLE PHASE: a real severity count, grouped exactly
    # the way GET /v1/scans/{id}/findings-summary groups it on the Go side.
    cur.execute(
        "SELECT severity_effective, count(*) FROM normalize.findings "
        "WHERE bom_document_id = %s GROUP BY severity_effective",
        (result.bom_document_id,),
    )
    counts = dict(cur.fetchall())
    assert counts == {"critical": 1}

    cur.execute(
        "SELECT count(*) FROM normalize.component_dependencies WHERE bom_document_id = %s",
        (result.bom_document_id,),
    )
    assert cur.fetchone()[0] == 1


def test_a_refused_plan_writes_nothing(pg_conn, written) -> None:
    """A refused plan must leave no trace — not even the header row. A
    bom_documents row with nothing under it would resolve as a real, empty
    document to any reader querying by (scan_id, bom_type), which is a worse
    lie than the document not existing at all."""
    from .bulk import MAX_COMPONENTS

    too_many = [component(f"purl:pkg:npm/x{i}@1") for i in range(MAX_COMPONENTS + 1)]
    canonical = {
        **canonical_model(),
        "components": too_many,
        "findings": [],
        "graph": {"edges": []},
    }
    scan_id = str(uuid.uuid4())
    tenant_id = str(uuid.uuid4())

    with pytest.raises(RefusedError):
        write_bom_document(
            pg_conn,
            tenant_id=tenant_id,
            scan_id=scan_id,
            bom_type="SBOM",
            normalization_version=1,
            canonical=canonical,
        )

    cur = pg_conn.cursor()
    # ⚠ SESSION-level (false), not is_local — these are bare statements
    # under an autocommit connection, each its own transaction, so an
    # is_local setting would revert before the very next statement.
    # Session scope is fine here: this connection belongs to one test
    # only, never pooled across tenants, unlike the request-scoped
    # connections write_bom_document and libs/go-shared/platform/db
    # actually serve.
    cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))
    cur.execute("SELECT count(*) FROM normalize.bom_documents WHERE scan_id = %s", (scan_id,))
    assert cur.fetchone()[0] == 0


def test_the_write_is_tenant_scoped(pg_conn, written, ensure_test_cluster) -> None:
    """RLS, not a WHERE clause this code could forget to write — the same
    property orchestrator_test.go's TestScansAreInvisibleAcrossTenants
    proves on the Go side, proven here for the write path instead of a read."""
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())

    result = write_bom_document(
        pg_conn,
        tenant_id=tenant_a,
        scan_id=str(uuid.uuid4()),
        bom_type="SBOM",
        normalization_version=1,
        canonical=canonical_model(),
    )
    written.append((tenant_a, result.bom_document_id))

    cur = pg_conn.cursor()
    # ⚠ SESSION-level (false), not is_local — these are bare statements
    # under an autocommit connection, each its own transaction, so an
    # is_local setting would revert before the very next statement.
    # Session scope is fine here: this connection belongs to one test
    # only, never pooled across tenants, unlike the request-scoped
    # connections write_bom_document and libs/go-shared/platform/db
    # actually serve.
    cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_b,))
    cur.execute(
        "SELECT count(*) FROM normalize.bom_documents WHERE id = %s", (result.bom_document_id,)
    )
    assert cur.fetchone()[0] == 0, "tenant B's session could see tenant A's document"

    cur.execute(
        "SELECT count(*) FROM normalize.components WHERE bom_document_id = %s",
        (result.bom_document_id,),
    )
    assert cur.fetchone()[0] == 0, "tenant B's session could see tenant A's components"


# --------------------------------------------------------------------------
# CBOM — CLAUDE.md invariant 5: type-discriminated coverage, proven live
# --------------------------------------------------------------------------


def cbom_canonical_model() -> dict:
    """A small but real CBOM document — one asset of each of three Table 9
    types, real enough that a certificate genuinely has no `key_size` and a
    key genuinely has no `cert_subject` rather than the test asserting that
    by construction."""
    return {
        "crypto_assets": [
            crypto_asset("algorithm", primitive="pke", oid="1.2.840.113549.1.1.1"),
            crypto_asset("key", key_id="kid-7", key_state="active", key_size=2048),
            crypto_asset("certificate", cert_subject="CN=example.com", cert_format="X.509"),
        ],
        "ruleset_version": "test-cbom-ruleset-1",
        "spdx_license_list_version": "",
        "unidentified_count": 0,
        "coverage": {"completeness_pct": 55.0, "declaration_pct": 100.0},
        "provenance": {"alias_snapshot_id": str(uuid.uuid4())},
    }


def test_a_cbom_write_round_trips_with_type_discriminated_columns(pg_conn, written) -> None:
    """⚠ THE CORRECTNESS REQUIREMENT OF THIS PHASE, PROVEN AGAINST LIVE
    POSTGRES, NOT JUST A PYTHON DICT.

    `workers/cbom/test_crypto_normalize.py` and `test_bulk.py` already prove
    this at the normalizer and the write-PLAN level; this is the same claim
    one layer further out — after a real chunked INSERT and a real read back,
    a certificate's `key_size` column is NULL and a key's `cert_subject` is
    NULL, not merely absent from an in-memory dict that never touched
    Postgres.
    """
    tenant_id = str(uuid.uuid4())
    canonical = cbom_canonical_model()

    result = write_bom_document(
        pg_conn,
        tenant_id=tenant_id,
        scan_id=str(uuid.uuid4()),
        bom_type="CBOM",
        normalization_version=1,
        canonical=canonical,
    )
    written.append((tenant_id, result.bom_document_id))
    assert not result.diagnostics

    cur = pg_conn.cursor()
    cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))

    cur.execute(
        "SELECT asset_type, primitive, key_size, cert_subject FROM normalize.crypto_assets "
        "WHERE bom_document_id = %s ORDER BY asset_type",
        (result.bom_document_id,),
    )
    rows = {row[0]: row for row in cur.fetchall()}
    assert set(rows) == {"algorithm", "certificate", "key"}

    _asset_type, primitive, key_size, cert_subject = rows["algorithm"]
    assert primitive == "pke"
    assert key_size is None
    assert cert_subject is None

    _asset_type, primitive, key_size, cert_subject = rows["key"]
    assert key_size == 2048
    assert primitive is None
    assert cert_subject is None

    # ⚠ THE ONE ASSERTION THE TASK NAMES DIRECTLY: a certificate has NO
    # key_size column value at all, in the live schema, after a real write.
    _asset_type, primitive, key_size, cert_subject = rows["certificate"]
    assert cert_subject == "CN=example.com"
    assert key_size is None
    assert primitive is None

    cur.execute(
        "SELECT completeness_pct, declaration_pct FROM normalize.bom_documents WHERE id = %s",
        (result.bom_document_id,),
    )
    completeness, declaration = cur.fetchone()
    assert float(completeness) == 55.0
    assert float(declaration) == 100.0


# --------------------------------------------------------------------------
# Pure validation — no database needed
# --------------------------------------------------------------------------


def test_alias_snapshot_id_must_be_a_real_uuid() -> None:
    """A fixture-style placeholder ("fixture-npm-simple-aliases") is exactly
    what normalize_runner.py's offline path uses — this must fail HERE, with
    a message naming the field, rather than three network round trips later
    as an opaque Postgres type-cast error."""
    with pytest.raises(ValueError, match="alias_snapshot_id"):
        _require_uuid(
            "fixture-npm-simple-aliases", field_name="canonical['provenance']['alias_snapshot_id']"
        )
