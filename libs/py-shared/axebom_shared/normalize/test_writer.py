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

from .bulk import _ai_model_id
from .test_bulk import ai_model, component, crypto_asset, model
from .writer import RefusedError, _optional_uuid, write_bom_document

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
    # ⚠ ORDER MATTERS: hardware_findings references hardware_components, so it
    # goes first even though both also cascade from bom_documents.
    #
    # hardware_component_alternates is DELIBERATELY ABSENT — it has no
    # `bom_document_id` column (it hangs off the component, not the document),
    # so the DELETE below would fail on it. It cascades from
    # hardware_components, which is here.
    "normalize.hardware_findings",
    "normalize.hardware_components",
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

#: An SBOM canonical model must carry a REAL alias snapshot as of
#: migrations/normalize/0012_bom_document_provenance.sql, which gave
#: bom_documents.alias_snapshot_id the foreign key it never had. Same
#: situation _TEST_CLUSTER_ID is in, for the same reason, so it gets the
#: same treatment: a fixed id and a fixture that guarantees the row.
_TEST_ALIAS_SNAPSHOT_ID = "01900000-0000-7000-8000-0000000000a1"


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
def ensure_test_alias_snapshot(pg_conn):
    """Guarantees normalize.alias_snapshot has a row for _TEST_ALIAS_SNAPSHOT_ID.

    ⚠ REQUIRED SINCE bom_documents_alias_snapshot_id_fkey (migration
    normalize/0012_bom_document_provenance.sql). Exactly the ensure_test_cluster
    story one table over: the column used to accept any uuid at all, so every
    caller minted a throwaway; now Postgres enforces that the row is real, which
    is the whole point of the FK — and it means this fixture, not writer.py, is
    what keeps canonical_model()'s SBOM fixture representative of a real write.

    CBOM/AIBOM/QBOM/HBOM need no such fixture: they run no alias closure and
    pass None, which the same migration made legal.
    """
    cur = pg_conn.cursor()
    cur.execute(
        "INSERT INTO normalize.alias_snapshot (id, ruleset_version) VALUES (%s, %s) "
        "ON CONFLICT (id) DO NOTHING",
        (_TEST_ALIAS_SNAPSHOT_ID, "test-ruleset-1"),
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
            # ⚠ SAME REASONING AS crypto_assets ABOVE, extended to every
            # AI table at once: one model with one dataset, one dependency and
            # one engine sighting is what gives the schema-agreement test below
            # something to check for `ai_models`/`ai_datasets`
            # /`ai_model_dependencies`/`ai_model_provenance` too.
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
        # ⚠ AND `normalize.ai_assets`, WHICH IS A TOP-LEVEL CANONICAL LIST
        # rather than a per-model one: a prompt or a vector store belongs to the
        # repository, not to a model. One row here for the same reason as every
        # other table in this fixture — a batch with no rows checks nothing.
        "ai_assets": [
            {
                "asset_type": "prompt",
                "asset_key": f"prompt:src/app.py:9{tenant_suffix}",
                "name": "system-prompt",
                "provider": "",
                "evidence": ["src/app.py:9"],
                "serves_model_key": "",
                "attributes": {"found_by": ["airom"]},
            }
        ],
        "ruleset_version": "test-ruleset-1",
        "spdx_license_list_version": "3.24",
        "unidentified_count": 0,
        "coverage": {"completeness_pct": 42.5, "declaration_pct": 80.0},
        # A real snapshot row, not a minted uuid — see ensure_test_alias_snapshot.
        "provenance": {"alias_snapshot_id": _TEST_ALIAS_SNAPSHOT_ID},
    }


# --------------------------------------------------------------------------
# Schema agreement — the test that would have caught every renamed column
# --------------------------------------------------------------------------


def test_every_planned_column_exists_in_the_live_schema(
    pg_conn, written, ensure_test_cluster, ensure_test_alias_snapshot
) -> None:
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


def test_a_live_write_round_trips(
    pg_conn, written, ensure_test_cluster, ensure_test_alias_snapshot
) -> None:
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


def test_a_refused_plan_writes_nothing(pg_conn, written, ensure_test_alias_snapshot) -> None:
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


def test_the_write_is_tenant_scoped(
    pg_conn, written, ensure_test_cluster, ensure_test_alias_snapshot
) -> None:
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
        # ⚠ None, and that is the CBOM-shaped answer: no alias closure runs,
        # so there is no snapshot. Legal since migration 0012; before it,
        # this had to be a throwaway uuid to satisfy NOT NULL.
        "provenance": {"alias_snapshot_id": None},
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
        _optional_uuid(
            "fixture-npm-simple-aliases", field_name="canonical['provenance']['alias_snapshot_id']"
        )


def test_alias_snapshot_id_may_be_absent_but_a_bad_value_still_fails() -> None:
    """⚠ THE TWO HALVES ARE ONE RULE, AND KEEPING THEM TOGETHER IS THE POINT.

    migration 0012 made the column nullable so the BOM types with no
    alias-closure pipeline (CBOM, AIBOM, QBOM, HBOM) could stop minting a
    throwaway uuid to satisfy NOT NULL. The easy mistake when relaxing a
    constraint is to relax it too far — to start accepting a malformed string
    as "absent enough" — which would put the opaque Postgres cast error back.

    Absent is fine. Present-but-not-a-uuid is still an error.
    """
    field = "canonical['provenance']['alias_snapshot_id']"
    assert _optional_uuid(None, field_name=field) is None
    with pytest.raises(ValueError, match="alias_snapshot_id"):
        _optional_uuid("", field_name=field)


# --------------------------------------------------------------------------
# Hardware — the batches that had never been executed against a real schema
# --------------------------------------------------------------------------

#: A fixed cluster for the hardware finding, on the same reasoning as
#: _TEST_CLUSTER_ID: vuln_clusters is global reference data.
_TEST_HW_CLUSTER_ID = "01900000-0000-7000-8000-0000000000c2"


@pytest.fixture
def ensure_test_hw_cluster(pg_conn):
    cur = pg_conn.cursor()
    cur.execute(
        "INSERT INTO normalize.vuln_clusters (id, display_id) VALUES (%s, %s) "
        "ON CONFLICT (id) DO NOTHING",
        (_TEST_HW_CLUSTER_ID, "CVE-2021-1472"),
    )


def hardware_canonical() -> dict:
    """A two-level hardware BOM with an alternate and an advisory finding.

    Small, but it exercises every hardware batch: the recursive parent_id
    within one COPY, the alternates child table, and hardware_findings.
    """
    return {
        "hardware_components": [
            {
                "_local_id": "1",
                "_parent_local_id": None,
                "_depth": 0,
                "_enriched_fields": {},
                "_source_engine": "hbom-ecad",
                "_vuln_match_status": "matched",
                "_cpe23_candidates": ["cpe:2.3:h:cisco:rv340:*:*:*:*:*:*:*:*"],
                "_vuln_findings": [
                    {
                        "cve_id": "CVE-2021-1472",
                        "cluster_id": _TEST_HW_CLUSTER_ID,
                        "cpe23": "cpe:2.3:h:cisco:rv340:*:*:*:*:*:*:*:*",
                        "match_basis": "vendor+product",
                        "match_confidence": "low",
                        "severity": "critical",
                        "cvss_score": 9.8,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "description": "Command injection.",
                        "source": "nvd",
                        "source_version": "2.0",
                    }
                ],
                "hardware_component.product_name": "Mainboard",
                "hardware_component.manufacturer_name": "Cisco",
                "hardware_component.model_number": "RV340",
                "hardware_component.compliance[]": ["RoHS"],
                "hardware_component.quantity": 1,
                "hardware_component.alternates": "not-provided",
            },
            {
                "_local_id": "1.1",
                "_parent_local_id": "1",
                "_depth": 1,
                "_enriched_fields": {"datasheet_url": "nexar"},
                "_source_engine": "hbom-ecad",
                "_vuln_match_status": "no-match",
                "_cpe23_candidates": ["cpe:2.3:h:yageo:rc0402fr-0710kl:*:*:*:*:*:*:*:*"],
                "_vuln_findings": [],
                "hardware_component.product_name": "Resistor 10k",
                "hardware_component.manufacturer_name": "Yageo",
                "hardware_component.model_number": "RC0402FR-0710KL",
                "hardware_component.quantity": 12,
                "hardware_component.designators": ["R1", "R4", "R17"],
                "hardware_component.unit_price": "0.0034",
                "hardware_component.currency": "USD",
                "hardware_component.do_not_populate": False,
                "hardware_component.assembly_type": "smt",
                "hardware_component.lifecycle_status": "active",
                "hardware_component.alternates": [
                    {
                        "ordinal": 0,
                        "manufacturer_name": "Panasonic",
                        "model_number": "ERJ-2RKF1002X",
                        "supplier_info": "Digi-Key",
                        "supplier_sku": "P10.0KDACT-ND",
                        "lifecycle_status": "active",
                        "equivalence": "unverified",
                        "approval_note": "",
                    }
                ],
            },
        ],
        "coverage": {"completeness_pct": 30.0, "declaration_pct": 100.0},
        "supplementary_coverage": {},
        "ruleset_version": "test-ruleset-1",
        "spdx_license_list_version": "",
        "unidentified_count": 0,
        "project_id": None,
        "provenance": {"alias_snapshot_id": None},
        "diagnostics": [],
    }


def test_a_live_hardware_write_round_trips(pg_conn, written, ensure_test_hw_cluster) -> None:
    """⚠ NO HARDWARE BATCH HAD EVER BEEN EXECUTED AGAINST THE REAL SCHEMA.

    The SBOM path has had this check since the session that found three
    renamed columns by running it. Hardware gained a manufacturing column set
    (migration 0011), an alternates table, and now hardware_findings (0013) —
    all planned, none ever COPYed. This is the same mechanical check, and it
    is the one that catches a column that exists in bulk.py and not in
    Postgres.
    """
    tenant_id = str(uuid.uuid4())
    canonical = hardware_canonical()

    result = write_bom_document(
        pg_conn,
        tenant_id=tenant_id,
        scan_id=str(uuid.uuid4()),
        bom_type="HBOM",
        normalization_version=1,
        canonical=canonical,
    )
    written.append((tenant_id, result.bom_document_id))

    cur = pg_conn.cursor()
    # ⚠ SESSION scope (false), not transaction-local — the reason the SBOM
    # round-trip above gives: these are bare statements on an autocommit
    # connection, so an is_local setting reverts before the next one and every
    # read below would fail RLS's uuid cast on an empty string.
    cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))

    cur.execute(
        "SELECT product_name, quantity, designators, unit_price, extended_price, "
        "       vuln_match_status, cpe23_candidates, parent_id IS NOT NULL "
        "FROM normalize.hardware_components WHERE bom_document_id = %s "
        "ORDER BY product_name",
        (result.bom_document_id,),
    )
    rows = cur.fetchall()
    assert len(rows) == 2

    board = rows[0]
    assert board[0] == "Mainboard"
    assert board[5] == "matched"
    assert board[6] == ["cpe:2.3:h:cisco:rv340:*:*:*:*:*:*:*:*"]
    assert board[7] is False, "the root has no parent"

    resistor = rows[1]
    assert resistor[1] == 12
    assert resistor[2] == ["R1", "R4", "R17"]
    # ⚠ extended_price IS GENERATED ALWAYS. Asserting it here is what proves
    # the column is computed by Postgres and never written by us — a stored
    # total that drifts from its own inputs is worse than an absent one.
    #
    # ⚠ COMPARED AS Decimal, NOT float. This assertion was written with
    # `float()` first and failed: 0.0034 * 12 is 0.040800000000000006 in binary
    # floating point, not 0.0408. That is the exact reason unit_price is
    # numeric(18,6) and is carried as a STRING all the way to the writer — a
    # test that reaches for float here is reintroducing the bug the column
    # design exists to prevent.
    assert resistor[4] == resistor[3] * 12
    assert resistor[5] == "no-match", "searched and clear is not the same as never searched"
    assert resistor[7] is True, "the child references its parent within the same COPY"

    cur.execute(
        "SELECT a.manufacturer_name, a.model_number, a.supplier_sku, a.equivalence "
        "FROM normalize.hardware_component_alternates a "
        "JOIN normalize.hardware_components c ON c.id = a.hardware_component_id "
        "WHERE c.bom_document_id = %s",
        (result.bom_document_id,),
    )
    assert cur.fetchall() == [("Panasonic", "ERJ-2RKF1002X", "P10.0KDACT-ND", "unverified")]

    cur.execute(
        "SELECT display_id, cpe23, match_basis, match_confidence, severity, cvss_score, source "
        "FROM normalize.hardware_findings WHERE bom_document_id = %s",
        (result.bom_document_id,),
    )
    findings = cur.fetchall()
    assert len(findings) == 1
    assert findings[0][0] == "CVE-2021-1472"
    assert findings[0][2] == "vendor+product"
    assert findings[0][3] == "low", "an advisory match never defaults to a confidence it lacks"
    assert float(findings[0][5]) == 9.8


def test_every_planned_hardware_column_exists_in_the_live_schema(
    pg_conn, written, ensure_test_hw_cluster
) -> None:
    """The hardware twin of the schema-agreement test above."""
    tenant_id = str(uuid.uuid4())
    canonical = hardware_canonical()

    result = write_bom_document(
        pg_conn,
        tenant_id=tenant_id,
        scan_id=str(uuid.uuid4()),
        bom_type="HBOM",
        normalization_version=1,
        canonical=canonical,
    )
    written.append((tenant_id, result.bom_document_id))

    from . import bulk

    plan = bulk.plan(canonical, tenant_id=tenant_id, bom_document_id=result.bom_document_id)
    assert not plan.refused

    hardware_batches = [b for b in plan.batches if "hardware" in b.table]
    assert len(hardware_batches) == 3, "components, alternates and findings"

    cur = pg_conn.cursor()
    for batch in hardware_batches:
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
            f"{batch.table} declares columns {sorted(missing)} that do not exist in the "
            f"live schema — live columns are {sorted(live_columns)}"
        )


def test_provenance_and_candidate_identities_actually_land(pg_conn, written):
    """⚠ TWO TABLES WITH LIVE READERS AND NO WRITER AT ALL.

    `services/project/internal/store/dependencies.go` reads both — the
    per-component "where did this line in this report come from?" panel is what
    makes a report defensible six months later — and it returned an empty list
    for EVERY component in the product's history. `loadComponentProvenanceEngines`
    swallows its error with a `//nolint:nilerr`, so a broken query and an honest
    absence looked identical from the outside.

    The data was never missing: `merge.MergedComponent.observed_by` and
    `.candidate_identities` have always been computed and serialised into the
    canonical document. Nothing consumed them.

    This asserts against REAL POSTGRES, because "the batch has rows" was already
    true of a plan that could never execute — see `_findings_batch`'s own comment
    about three column names that did not exist.
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

    cur = pg_conn.cursor()
    # ⚠ SESSION SCOPE (`false`), NOT TRANSACTION SCOPE. The connection is in
    # autocommit, so a `true` here applies to a transaction that ends before the
    # next statement — and the read then fails with
    # `invalid input syntax for type uuid: ""` because current_setting returns
    # empty. The same trap this file's SBOM round-trip already documents.
    cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))
    cur.execute(
        "SELECT engine_id, engine_version, rule_id, confidence "
        "  FROM normalize.component_provenance WHERE bom_document_id = %s",
        (result.bom_document_id,),
    )
    provenance = cur.fetchall()
    assert provenance, "no provenance was written; the panel stays empty"
    engines = {row[0] for row in provenance}
    assert engines == {"syft"}, engines
    # The engine's own id for the component is what lets somebody go back to the
    # raw artifact and find the row it came from.
    assert all(row[2] for row in provenance), f"native ids were dropped: {provenance}"

    cur.execute(
        "SELECT kind, value, source_engine, confidence "
        "  FROM normalize.component_candidate_identities WHERE bom_document_id = %s",
        (result.bom_document_id,),
    )
    candidates = cur.fetchall()
    assert candidates, "no candidate identity was written"
    for kind, value, engine, confidence in candidates:
        assert kind == "cpe"
        assert value.startswith("cpe:2.3:")
        assert engine == "dependency-check"
        # ⚠ IT MUST STAY `low`. That is the whole reason this row is here
        # rather than on the component: a low-confidence CPE must not merge and
        # pull in another package's findings.
        assert confidence == "low"


def test_an_unknown_confidence_becomes_null_rather_than_aborting_the_copy(pg_conn, written):
    """⚠ THE COLUMN'S CHECK ACCEPTS high/medium/low AND NOTHING ELSE.

    An engine reporting "HIGH", or a value this codebase has not seen, would
    abort the COPY and take the entire normalization with it — losing every
    component to record one confidence nobody can use. NULL reads as "not
    stated", which is what it is.
    """
    tenant_id = str(uuid.uuid4())
    canonical = canonical_model()
    canonical["components"][0]["observed_by"] = [
        {"engine": "syft", "confidence": "VERY SURE INDEED"}
    ]

    result = write_bom_document(
        pg_conn,
        tenant_id=tenant_id,
        scan_id=str(uuid.uuid4()),
        bom_type="SBOM",
        normalization_version=1,
        canonical=canonical,
    )
    written.append((tenant_id, result.bom_document_id))

    cur = pg_conn.cursor()
    cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))
    cur.execute(
        "SELECT confidence FROM normalize.component_provenance "
        " WHERE bom_document_id = %s AND engine_id = 'syft'",
        (result.bom_document_id,),
    )
    rows = cur.fetchall()
    assert rows, "the write was lost entirely"
    assert any(row[0] is None for row in rows), rows


def test_an_unmappable_licence_keeps_its_raw_text(pg_conn, written):
    """⚠ `Resolution.raw` EXISTS ONLY TO FILL THIS TABLE, AND NOTHING WROTE IT.

    Its own comment says the text is "preserved for normalize.license_refs, so a
    human can map it later without re-running the scan" — and it reached no
    serialiser, so the table stayed empty and re-running the scan was the only
    way to get the text back. The exact opposite of what the field is for.
    """
    tenant_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    canonical = canonical_model()
    canonical["components"][0]["license_refs"] = [
        {"slug": "LicenseRef-acme-eula", "raw_text": "Acme Internal EULA v3, see LEGAL.txt"}
    ]

    result = write_bom_document(
        pg_conn,
        tenant_id=tenant_id,
        scan_id=scan_id,
        bom_type="SBOM",
        normalization_version=1,
        canonical=canonical,
    )
    written.append((tenant_id, result.bom_document_id))

    cur = pg_conn.cursor()
    cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))
    cur.execute(
        "SELECT raw_text, first_seen_scan_id FROM normalize.license_refs "
        " WHERE tenant_id = %s AND slug = %s",
        (tenant_id, "LicenseRef-acme-eula"),
    )
    row = cur.fetchone()
    assert row, "the unmappable licence text was thrown away"
    assert row[0] == "Acme Internal EULA v3, see LEGAL.txt"
    assert str(row[1]) == scan_id

    # ⚠ A SECOND SCAN MUST NOT ABORT THE WRITE, and must not overwrite where the
    # licence was FIRST seen. The table is UNIQUE (tenant_id, slug), so COPY
    # could never have carried it — and DO UPDATE would make
    # `first_seen_scan_id` mean "last seen", which is the question nobody asked.
    second_scan = str(uuid.uuid4())
    second = write_bom_document(
        pg_conn,
        tenant_id=tenant_id,
        scan_id=second_scan,
        bom_type="SBOM",
        normalization_version=2,
        canonical=canonical,
    )
    written.append((tenant_id, second.bom_document_id))

    cur.execute(
        "SELECT first_seen_scan_id FROM normalize.license_refs  WHERE tenant_id = %s AND slug = %s",
        (tenant_id, "LicenseRef-acme-eula"),
    )
    assert str(cur.fetchone()[0]) == scan_id, "a re-scan overwrote the first sighting"


def test_a_models_merge_key_lands_in_the_column_that_mints_its_id(
    pg_conn, written, ensure_test_cluster, ensure_test_alias_snapshot
) -> None:
    """`model_key` must equal the `_identity` the row's own surrogate id derives from.

    ⚠ THIS IS THE COLUMN `normalize.ai_models` SPENT ITS WHOLE LIFE WITHOUT. The merge
    key existed only for the length of one Python dict, so nothing stored could say
    whether two rows were the same model — which is how one Hugging Face model was
    recorded as three separate AI models under three spellings of a library's name.

    Asserted against live Postgres rather than the plan, because a planned column that
    does not exist is exactly what `test_every_planned_column_exists_in_the_live_schema`
    was written to catch, and this is the value inside it.
    """
    tenant_id = str(uuid.uuid4())

    result = write_bom_document(
        pg_conn,
        tenant_id=tenant_id,
        scan_id=str(uuid.uuid4()),
        bom_type="AIBOM",
        normalization_version=1,
        canonical=canonical_model(),
    )
    written.append((tenant_id, result.bom_document_id))
    doc_id = result.bom_document_id

    cur = pg_conn.cursor()
    cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))
    cur.execute(
        """
        SELECT id, model_key, identity_rule, identity_confidence, verified
          FROM normalize.ai_models
         WHERE bom_document_id = %s
        """,
        (doc_id,),
    )
    rows = cur.fetchall()

    assert len(rows) == 1
    row_id, model_key, rule, confidence, verified = rows[0]

    assert model_key, "model_key is NOT NULL and must never be written empty"
    assert model_key == "model-ref"
    assert rule == "name"
    assert confidence == "low"

    # Unverified until something actually confirmed the model resolves upstream.
    assert verified is False

    # The stored key and the surrogate id agree by construction: bulk derives both
    # from `_identity`. A row whose id says one model and whose key says another
    # would dedup one way and render the other.
    assert str(row_id) == _ai_model_id(doc_id, model_key)
