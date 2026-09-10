"""`workers.aibom.normalize_consumer` against a REAL Postgres connection and the
REAL captured `ai-bom` artifact — the end-to-end proof that a NormalizeTriggerV1's
shape, `extract_discovery`, `build_canonical_aibom` and `writer.write_bom_document`
actually compose, not just individually.

⚠ THIS MODULE HAD NO TESTS AT ALL, AND IT IS WHERE THE HONESTY LIVES. Two of the
defects fixed in this area were consumer-only: the `datasets` key it gathered that
`extract_discovery` has never returned, and — more seriously — the discovery
diagnostics it computed and dropped before they could reach a report. Neither was
reachable from `test_pipeline.py`, which starts one layer down.

⚠ INTEGRATION TEST, SKIPPED WHEN THE STACK IS DOWN — the convention
`workers/sbom/test_normalize_consumer.py`, `test_writer.py` and
`test_cluster_store.py` already use. CI has no Postgres service, so this suite is
skipped there and is a `task dev` check, not a merge gate.

⚠ CONNECTS AS `axebom_normalize_writer`, matching what the real deployed consumer
holds. A test under `axebom_app` would prove the SQL is well-formed and say nothing
about whether it runs under the real, restricted grants.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from pathlib import Path

import pytest

from .normalize_consumer import handle_trigger

psycopg = pytest.importorskip("psycopg")

_ARTIFACT = Path(__file__).resolve().parent / "testdata" / "ai-bom-langchain-llama3.cdx.json"


def _connect(role_env: str, role_default: str, password_default: str):
    return psycopg.connect(
        host=os.environ.get("POSTGRES_HOST", "localhost"),
        port=int(os.environ.get("POSTGRES_PORT", "55432")),
        dbname=os.environ.get("POSTGRES_DB", "axebom"),
        user=os.environ.get(role_env, role_default),
        password=os.environ.get(role_env + "_PASSWORD", password_default),
        connect_timeout=5,
        autocommit=True,
    )


@pytest.fixture
def pg_conn():
    try:
        conn = _connect(
            "POSTGRES_NORMALIZE_WRITER_ROLE",
            "axebom_normalize_writer",
            "axebom_normalize_writer",
        )
    except psycopg.OperationalError as exc:
        pytest.skip(f"database unavailable as axebom_normalize_writer ({exc}) — run `task dev`")
    yield conn
    conn.close()


@pytest.fixture
def tenant_id():
    return str(uuid.uuid4())


@pytest.fixture
def cleanup(tenant_id):
    """`axebom_normalize_writer` has no DELETE grant anywhere, so it cannot tear
    down its own test data — same reasoning as the SBOM consumer's fixture."""
    created: list[str] = []
    yield created
    admin = _connect("POSTGRES_APP_ROLE", "axebom_app", "axebom_app")
    try:
        cur = admin.cursor()
        cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))
        for doc_id in created:
            cur.execute(
                "DELETE FROM normalize.ai_model_dependencies WHERE ai_model_id IN "
                "(SELECT id FROM normalize.ai_models WHERE bom_document_id = %s)",
                (doc_id,),
            )
            cur.execute(
                "DELETE FROM normalize.ai_datasets WHERE ai_model_id IN "
                "(SELECT id FROM normalize.ai_models WHERE bom_document_id = %s)",
                (doc_id,),
            )
            cur.execute("DELETE FROM normalize.ai_models WHERE bom_document_id = %s", (doc_id,))
            cur.execute("DELETE FROM normalize.bom_documents WHERE id = %s", (doc_id,))
    finally:
        admin.close()


def trigger_for(scan_id: str, tenant_id: str) -> dict:
    """A NormalizeTriggerV1-shaped dict pointing at the committed real artifact."""
    return {
        "schema_version": "scan.normalize/v1",
        "trigger_id": str(uuid.uuid4()),
        "scan_id": scan_id,
        "tenant_id": tenant_id,
        "project_id": str(uuid.uuid4()),
        "family": "aibom",
        "normalization_version": 1,
        "issued_at": "2026-01-01T00:00:00Z",
        "engines": [
            {
                "engine_id": "ai-bom",
                "engine_version": "3.1.0",
                "status": "succeeded",
                "artifacts": [{"role": "native_output", "uri": str(_ARTIFACT), "sha256": "test"}],
            }
        ],
    }


def _document(pg_conn, scan_id: str, tenant_id: str) -> tuple[str, list, list]:
    cur = pg_conn.cursor()
    cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))
    cur.execute(
        "SELECT id, normalize_diagnostics FROM normalize.bom_documents "
        "WHERE scan_id = %s AND bom_type = 'AIBOM'",
        (scan_id,),
    )
    row = cur.fetchone()
    assert row is not None, "the consumer wrote no bom_documents row"
    doc_id, diagnostics = row

    cur.execute(
        "SELECT model_name, model_key, identity_rule, evidence "
        "FROM normalize.ai_models WHERE bom_document_id = %s",
        (doc_id,),
    )
    return doc_id, cur.fetchall(), diagnostics or []


def test_the_real_artifact_normalizes_to_one_model_through_the_consumer(
    pg_conn, cleanup, tenant_id
) -> None:
    """⚠ THIS EXACT FILE PRODUCED THREE ROWS IN PRODUCTION.

    Three labels for one Python library, while `meta-llama/Llama-3-8B` — the only
    model the repository uses — was recorded nowhere.
    """
    scan_id = str(uuid.uuid4())
    asyncio.run(handle_trigger(pg_conn, trigger_for(scan_id, tenant_id), Path("/")))

    doc_id, models, _diagnostics = _document(pg_conn, scan_id, tenant_id)
    cleanup.append(doc_id)

    assert len(models) == 1, [m[0] for m in models]
    name, model_key, rule, evidence = models[0]
    assert name == "Llama-3-8B"
    assert model_key == "purl:pkg:huggingface/meta-llama/Llama-3-8B"
    assert rule == "hf_repo"
    # ⚠ THE SANDBOX MOUNT IS STRIPPED — `discovery.repo_path`. The captured
    # response says `/src/app.py:13` because `/src` is where the runner mounts
    # the tree for every engine; airom reports the same file as `src/app.py`,
    # and a model both engines found otherwise carried two spellings of one path.
    assert evidence == ["app.py:13"]


def test_the_reclassification_reaches_the_document_not_just_the_log(
    pg_conn, cleanup, tenant_id
) -> None:
    """A model count that changes with no stated reason is unaccountable.

    The consumer used to build a fresh discovery dict carrying only `models` and
    `frameworks`, so every content-level diagnostic died there — including the
    record of which components were stored as dependencies instead of models.
    """
    scan_id = str(uuid.uuid4())
    asyncio.run(handle_trigger(pg_conn, trigger_for(scan_id, tenant_id), Path("/")))

    doc_id, _models, diagnostics = _document(pg_conn, scan_id, tenant_id)
    cleanup.append(doc_id)

    codes = [d.get("code") for d in diagnostics]
    assert codes.count("AIBOM_MODEL_RECLASSIFIED") == 2, diagnostics
    blob = json.dumps(diagnostics)
    assert "transformers" in blob


def test_replaying_the_same_trigger_is_idempotent(pg_conn, cleanup, tenant_id) -> None:
    """Redelivery is normal — `MaxDeliver=4` with backoff — so a second delivery
    must not write a second document."""
    scan_id = str(uuid.uuid4())
    trigger = trigger_for(scan_id, tenant_id)

    asyncio.run(handle_trigger(pg_conn, trigger, Path("/")))
    asyncio.run(handle_trigger(pg_conn, trigger, Path("/")))

    cur = pg_conn.cursor()
    cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))
    cur.execute(
        "SELECT id FROM normalize.bom_documents WHERE scan_id = %s AND bom_type = 'AIBOM'",
        (scan_id,),
    )
    rows = cur.fetchall()
    cleanup.extend(str(r[0]) for r in rows)

    assert len(rows) == 1


def _enriched_trigger(scan_id: str, tenant_id: str, cards_path: Path) -> dict:
    """A trigger carrying BOTH engines' artifacts, the way a real enriched scan does."""
    trigger = trigger_for(scan_id, tenant_id)
    trigger["engines"].append(
        {
            "engine_id": "aibom-generator",
            "engine_version": "test",
            "status": "succeeded",
            "artifacts": [{"role": "native_output", "uri": str(cards_path), "sha256": "test"}],
        }
    )
    return trigger


def test_enrichment_actually_reaches_the_stored_model(
    pg_conn, cleanup, tenant_id, tmp_path
) -> None:
    """⚠ `cards` WAS HARDCODED EMPTY, SO THIS PATH HAS NEVER RUN.

    Every enrichment-only Table 10 element was `not-provided` on every scan no
    matter what Hugging Face said. This is the first time a stored card reaches a
    row in `normalize.ai_models`.
    """
    cards_path = tmp_path / "aibom-generator.json"
    cards_path.write_text(
        json.dumps(
            {
                # One stored enrichment response, in the shape the fetcher writes:
                # aibom-generator's document AND what the Hub itself said, kept
                # apart. The licence and the datasets come from the Hub half —
                # see `aibom_generator._resolved_license`.
                "meta-llama/Llama-3-8B": {
                    "aibom_generator": {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.6",
                        "components": [
                            {
                                "type": "machine-learning-model",
                                "name": "Meta Llama 3 8B",
                                "licenses": [{"license": {"id": "Apache-2.0"}}],
                                "authors": [{"name": "Meta"}],
                                "modelCard": {
                                    "modelParameters": {
                                        "task": "text-generation",
                                        "datasets": [{"name": "the-pile", "type": "dataset"}],
                                    }
                                },
                            }
                        ],
                    },
                    "huggingface": {
                        "id": "meta-llama/Llama-3-8B",
                        "requested_id": "meta-llama/Llama-3-8B",
                        "sha": "0123456789abcdef0123456789abcdef01234567",
                        "card_data": {"license": "Apache-2.0", "datasets": ["the-pile"]},
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    scan_id = str(uuid.uuid4())
    asyncio.run(
        handle_trigger(pg_conn, _enriched_trigger(scan_id, tenant_id, cards_path), Path("/"))
    )

    cur = pg_conn.cursor()
    cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))
    cur.execute(
        "SELECT id, completeness_pct FROM normalize.bom_documents "
        "WHERE scan_id = %s AND bom_type = 'AIBOM'",
        (scan_id,),
    )
    doc_id, completeness = cur.fetchone()
    cleanup.append(doc_id)

    cur.execute(
        "SELECT model_name, licensing, model_type, verified FROM normalize.ai_models "
        "WHERE bom_document_id = %s",
        (doc_id,),
    )
    name, licensing, model_type, verified = cur.fetchone()

    # The publisher's own name beats both the reference and the engine's label.
    assert name == "Meta Llama 3 8B"
    assert licensing == "Apache-2.0"
    assert model_type == "text-generation"
    # ⚠ `verified` is true only because an engine confirmed the model upstream.
    assert verified is True

    # The dataset the card named is stored, not just counted.
    cur.execute(
        "SELECT name FROM normalize.ai_datasets WHERE ai_model_id IN "
        "(SELECT id FROM normalize.ai_models WHERE bom_document_id = %s)",
        (doc_id,),
    )
    assert [r[0] for r in cur.fetchall()] == ["the-pile"]

    # The whole point: coverage moved because the DATA is real.
    assert completeness > 5.88, f"enrichment did not move coverage (got {completeness})"


def test_an_operators_own_answers_survive_a_renormalization(pg_conn, cleanup, tenant_id) -> None:
    """⚠ RE-NORMALIZING USED TO DELETE THEM.

    `services/project` writes intended usage, out-of-scope usage, security
    requirements, environmental impact and attestations straight onto
    `normalize.ai_models` — the elements no tool can report. The next
    normalization built a fresh row from engine output alone and wrote
    `not-provided` over every one, because `user_values_by_identity` was
    populated by no caller. The customer's own answers, and the coverage they
    earned, vanished the next time the project was scanned.
    """
    project_id = str(uuid.uuid4())

    first = trigger_for(str(uuid.uuid4()), tenant_id)
    first["project_id"] = project_id
    asyncio.run(handle_trigger(pg_conn, first, Path("/")))

    cur = pg_conn.cursor()
    cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))
    cur.execute("SELECT id FROM normalize.bom_documents WHERE scan_id = %s", (first["scan_id"],))
    first_doc = cur.fetchone()[0]
    cleanup.append(first_doc)

    # The operator answers the questions no tool can. `axebom_normalize_writer`
    # has no UPDATE grant on this table — services/project does this write — so
    # the edit goes through the app role, exactly as production does.
    admin = _connect("POSTGRES_APP_ROLE", "axebom_app", "axebom_app")
    try:
        acur = admin.cursor()
        acur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))
        acur.execute(
            """
            UPDATE normalize.ai_models
               SET intended_usage = 'internal chat assistant',
                   environmental_impact = '900 kWh estimated'
             WHERE bom_document_id = %s
            """,
            (first_doc,),
        )
    finally:
        admin.close()

    # A second scan of the same project — a new document, built from the same
    # engine output, which knows nothing about any of that.
    second = trigger_for(str(uuid.uuid4()), tenant_id)
    second["project_id"] = project_id
    asyncio.run(handle_trigger(pg_conn, second, Path("/")))

    cur.execute("SELECT id FROM normalize.bom_documents WHERE scan_id = %s", (second["scan_id"],))
    second_doc = cur.fetchone()[0]
    cleanup.append(second_doc)

    cur.execute(
        "SELECT intended_usage, environmental_impact, field_status "
        "FROM normalize.ai_models WHERE bom_document_id = %s",
        (second_doc,),
    )
    intended, environmental, status = cur.fetchone()

    assert intended == "internal chat assistant", "the operator's answer was overwritten"
    assert environmental == "900 kWh estimated"
    # ⚠ AND THE COVERAGE THEY EARNED SURVIVES WITH THEM. A value restored into
    # the row but left `not-provided` in field_status would score zero.
    assert status["certin.aibom.15.intended_usage"] == "provided"
    assert status["certin.aibom.17.environmental_impact"] == "provided"


def test_an_operators_answer_in_the_owning_schema_reaches_the_new_document(
    pg_conn, cleanup, tenant_id
) -> None:
    """⚠ THE ANSWER NOW LIVES WHERE THE SERVICE THAT COLLECTED IT PUT IT.

    `services/project` used to write these five elements onto
    `normalize.ai_models` with an UPDATE — a mutation of normalized data, which
    invariant 10 says never happens — and this consumer read the PREVIOUS
    document back to rescue them. A rescue is not a design: it broke silently
    whenever the chain did, including on the first normalization after somebody
    answered, which is the most likely moment of all.

    `services/aibom` writes to `aibom.model_user_values`, keyed by
    `(project, model_key)`, and this reads it. The answer survives by
    construction rather than by recovery.
    """
    project_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())

    # ⚠ WRITTEN AS `axebom_app`, WHICH IS THE POINT. `services/aibom` holds that
    # role; the consumer holds `axebom_normalize_writer`, which has SELECT on
    # this table and nothing else. If the grant in migrations/aibom/0001 were
    # missing, this test would fail at the READ rather than passing quietly.
    app = _connect("POSTGRES_APP_ROLE", "axebom_app", "axebom_app")
    try:
        cur = app.cursor()
        cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))
        cur.execute(
            "INSERT INTO aibom.model_user_values "
            "(tenant_id, project_id, model_key, intended_usage, out_of_scope_usage, updated_by) "
            "VALUES (%s,%s,%s,%s,%s,%s)",
            (
                tenant_id,
                project_id,
                "purl:pkg:huggingface/meta-llama/Llama-3-8B",
                "internal support triage only",
                "never for medical or legal advice",
                str(uuid.uuid4()),
            ),
        )
        app.commit()

        trigger = trigger_for(scan_id, tenant_id)
        trigger["project_id"] = project_id
        asyncio.run(handle_trigger(pg_conn, trigger, Path("/")))

        doc_id, _models, _diagnostics = _document(pg_conn, scan_id, tenant_id)
        cleanup.append(doc_id)

        cur = pg_conn.cursor()
        cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))
        cur.execute(
            "SELECT intended_usage, out_of_scope_usage, field_status->>%s "
            "FROM normalize.ai_models WHERE bom_document_id = %s",
            ("certin.aibom.15.intended_usage", doc_id),
        )
        intended, out_of_scope, status = cur.fetchone()

        assert intended == "internal support triage only"
        assert out_of_scope == "never for medical or legal advice"
        # ⚠ AND IT COUNTS. An answer that reached the row but not `field_status`
        # would leave the element scoring zero — the coverage number is what a
        # customer sees, and the whole point of asking was to move it.
        assert status == "provided"
    finally:
        cur = app.cursor()
        cur.execute("SELECT set_config('app.current_tenant_id', %s, false)", (tenant_id,))
        cur.execute("DELETE FROM aibom.model_user_values WHERE project_id = %s", (project_id,))
        app.commit()
        app.close()
