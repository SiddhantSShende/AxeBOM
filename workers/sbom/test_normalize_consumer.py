"""normalize_consumer.py against a REAL Postgres connection and a REAL
captured fixture — the end-to-end proof that a NormalizeTriggerV1's shape,
cluster_store.persist_clusters, pipeline.normalize and writer.write_bom_document
actually compose correctly, not just individually.

⚠ INTEGRATION TEST, SKIPPED WHEN THE STACK IS DOWN — same convention
test_writer.py and test_cluster_store.py already use.

⚠ CONNECTS AS `axebom_normalize_writer`, matching what the real deployed
consumer holds — see test_cluster_store.py's module docstring for why this
matters (a test under `axebom_app` would prove the SQL is well-formed and
say nothing about whether it runs under the real, restricted grants).
"""

from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path

import pytest

from .normalize_consumer import handle_trigger

psycopg = pytest.importorskip("psycopg")

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "npm-simple" / "raw"


@pytest.fixture
def pg_conn():
    try:
        conn = psycopg.connect(
            host=os.environ.get("POSTGRES_HOST", "localhost"),
            port=int(os.environ.get("POSTGRES_PORT", "55432")),
            dbname=os.environ.get("POSTGRES_DB", "axebom"),
            user=os.environ.get("POSTGRES_NORMALIZE_WRITER_ROLE", "axebom_normalize_writer"),
            password=os.environ.get(
                "POSTGRES_NORMALIZE_WRITER_PASSWORD", "axebom_normalize_writer"
            ),
            connect_timeout=5,
            autocommit=True,
        )
    except psycopg.OperationalError as exc:
        pytest.skip(f"database unavailable as axebom_normalize_writer ({exc}) — run `task dev`")
    yield conn
    conn.close()


@pytest.fixture
def cleanup(pg_conn, tenant_id):
    """Deletes the written bom_documents row and its children through a
    separate axebom_app connection — same reasoning as
    test_cluster_store.py's `cleanup` fixture: axebom_normalize_writer has
    no DELETE grant anywhere, so it cannot tear down its own test data."""
    created: list[str] = []
    yield created
    admin = psycopg.connect(
        host=os.environ.get("POSTGRES_HOST", "localhost"),
        port=int(os.environ.get("POSTGRES_PORT", "55432")),
        dbname=os.environ.get("POSTGRES_DB", "axebom"),
        user=os.environ.get("POSTGRES_APP_ROLE", "axebom_app"),
        password=os.environ.get("POSTGRES_APP_PASSWORD", "axebom_app"),
        connect_timeout=5,
        autocommit=True,
    )
    try:
        cur = admin.cursor()
        cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))
        for table in (
            "normalize.component_dependencies",
            "normalize.component_locations",
            "normalize.findings",
            "normalize.components",
        ):
            for doc_id in created:
                cur.execute(f"DELETE FROM {table} WHERE bom_document_id = %s", (doc_id,))  # noqa: S608
        for doc_id in created:
            cur.execute("DELETE FROM normalize.bom_documents WHERE id = %s", (doc_id,))
    finally:
        admin.close()


@pytest.fixture
def tenant_id():
    return str(uuid.uuid4())


def trigger_for_fixture(scan_id: str, tenant_id: str) -> dict:
    """A NormalizeTriggerV1-shaped dict pointing at the real, committed
    npm-simple golden fixture's raw artifacts — the same files
    workers/sbom/test_golden.py replays offline, here read through the
    consumer's real trigger-driven path instead of normalize_runner's
    fixture-directory convention."""
    engines = []
    for engine_id, filename in (
        ("syft", "syft.json"),
        ("grype", "grype.json"),
        ("osv-scanner", "osv-scanner.json"),
        ("trivy-fs", "trivy-fs.json"),
    ):
        path = _FIXTURE / filename
        engines.append(
            {
                "engine_id": engine_id,
                "engine_version": "test",
                "status": "succeeded",
                "artifacts": [{"role": "native_output", "uri": str(path), "sha256": "test"}],
            }
        )

    return {
        "schema_version": "scan.normalize/v1",
        "trigger_id": str(uuid.uuid4()),
        "scan_id": scan_id,
        "tenant_id": tenant_id,
        "project_id": str(uuid.uuid4()),
        "family": "sbom",
        "normalization_version": 1,
        "source_commit_sha": "abc123",
        "workspace_archive_sha256": "def456",
        "ecosystems_without_engine": [],
        "issued_at": "2026-01-01T00:00:00Z",
        "engines": engines,
    }


def test_a_real_trigger_writes_a_real_bom_document(pg_conn, cleanup, tenant_id) -> None:
    scan_id = str(uuid.uuid4())
    trigger = trigger_for_fixture(scan_id, tenant_id)

    # asyncio.run, not pytest-asyncio — this repo has no async test runner
    # dependency, and handle_trigger's only actual `await` is a to_thread
    # call around synchronous DB work, so a plain event loop is sufficient.
    asyncio.run(handle_trigger(pg_conn, trigger, artifacts_root=_FIXTURE))

    cur = pg_conn.cursor()
    cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))
    cur.execute(
        "SELECT id, completeness_pct, declaration_pct FROM normalize.bom_documents "
        "WHERE scan_id = %s AND bom_type = 'SBOM'",
        (scan_id,),
    )
    row = cur.fetchone()
    assert row is not None, "handle_trigger did not write a bom_documents row"
    bom_document_id, completeness_pct, declaration_pct = row
    cleanup.append(bom_document_id)

    assert completeness_pct is not None
    assert declaration_pct is not None
    assert float(declaration_pct) >= float(completeness_pct), (
        "declaration_pct counts explicit not-provided too; it must never be LOWER "
        "than completeness_pct (CLAUDE.md invariant 3)"
    )

    cur.execute(
        "SELECT count(*) FROM normalize.components WHERE bom_document_id = %s", (bom_document_id,)
    )
    component_count = cur.fetchone()[0]
    assert component_count > 0, "the real npm-simple fixture has real components"

    # Findings from grype/osv-scanner (and now trivy-fs's vulnerabilities[]
    # array, Gap A) all reached normalize.findings with a REAL, durable,
    # FK-valid cluster_id — not the uuid5(bom_document_id + ...) fallback
    # bulk.py used before cluster_store.py existed.
    cur.execute(
        "SELECT f.cluster_id FROM normalize.findings f WHERE f.bom_document_id = %s LIMIT 1",
        (bom_document_id,),
    )
    finding_row = cur.fetchone()
    if finding_row is not None:
        cur.execute("SELECT count(*) FROM normalize.vuln_clusters WHERE id = %s", (finding_row[0],))
        assert cur.fetchone()[0] == 1, "the finding's cluster_id has no matching vuln_clusters row"


def test_replaying_the_same_trigger_is_idempotent(pg_conn, cleanup, tenant_id) -> None:
    scan_id = str(uuid.uuid4())
    trigger = trigger_for_fixture(scan_id, tenant_id)

    asyncio.run(handle_trigger(pg_conn, trigger, artifacts_root=_FIXTURE))

    cur = pg_conn.cursor()
    cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))
    cur.execute(
        "SELECT id FROM normalize.bom_documents WHERE scan_id = %s AND bom_type = 'SBOM'",
        (scan_id,),
    )
    bom_document_id = cur.fetchone()[0]
    cleanup.append(bom_document_id)

    # A redelivered trigger (same scan_id, same normalization_version) must
    # be a no-op, not a second document or an error.
    asyncio.run(handle_trigger(pg_conn, trigger, artifacts_root=_FIXTURE))

    cur.execute(
        "SELECT count(*) FROM normalize.bom_documents WHERE scan_id = %s AND bom_type = 'SBOM'",
        (scan_id,),
    )
    assert cur.fetchone()[0] == 1, (
        "a redelivered trigger must not create a second bom_documents row"
    )
