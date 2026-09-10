"""Consumes scan.normalize.aibom and writes one scan's AI inventory.

⚠ THIS CLOSES A GAP THAT MADE AIBOM SCANS LOOK SUCCESSFUL AND WRITE NOTHING.

`ai-bom` has discovered and stored raw output for a long time, and
`build_canonical_aibom` has produced a writable document for just as long —
but nothing consumed the trigger, so `normalize.ai_models` stayed empty while the
scan reported `completed` and the Engine Coverage panel showed a green engine.
docs/STATE.md recorded it empirically: `scan.normalize_triggers` held zero
aibom rows against any real scan, ever.

⚠ THE CREDENTIAL EXCEPTION APPLIES HERE TOO. This process holds a Postgres role
that no other worker does. `axebom_normalize_writer` is scoped to the
`normalize` schema and to SELECT/INSERT only — no UPDATE, no DELETE — so it
structurally cannot overwrite normalized data in place (invariant 10), even by
application bug. RLS applies to it exactly as to any other role.

The consume loop is `axebom_shared.normalize.consumer_runtime`; the credential
loading deliberately is not — see ConsumerConfigEnv.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from workers.aibom.adapters.ai_bom import extract_discovery
from workers.aibom.adapters.aibom_generator import ModelCard, parse_model_card
from workers.aibom.adapters.aibom_import import extract_import_discovery
from workers.aibom.adapters.airom import extract_airom_discovery
from workers.aibom.adapters.cdxgen_ai import extract_cdxgen_ai_discovery
from workers.aibom.normalize.pipeline import build_canonical_aibom

from axebom_shared.logging import get_logger
from axebom_shared.normalize import writer
from axebom_shared.normalize.consumer_runtime import Retry, run_consumer


def _extract_toml_artifact(payload: dict[str, Any]) -> dict[str, Any]:
    """`aibom-toml`'s artifact is already the discovery shape.

    ⚠ IT IS THE ONE ENGINE WHOSE ARTIFACT IS NOT A THIRD PARTY'S DOCUMENT. There
    is no single source file to keep byte for byte — a monorepo may declare
    several `aibom.toml` files — so the adapter writes the parsed result plus the
    paths it came from, and this reads it back. Everything else on this map
    parses a document some other tool wrote.
    """
    return {
        "models": list(payload.get("models") or []),
        "frameworks": [],
        "assets": list(payload.get("assets") or []),
        "surfaces": set(),
        "diagnostics": [],
    }


#: Engines whose output describes WHAT THE REPOSITORY USES, and the extractor
#: that reads each one's dialect.
#:
#: ⚠ THREE DIALECTS OF ONE FORMAT, AND ONE PARSER WOULD LOSE MOST OF IT. All
#: three emit CycloneDX and all three put the model id, the provider and the
#: evidence somewhere different — measured against real captured output in
#: `testdata/`, not read off a README. Running `extract_discovery` (ai-bom's) over
#: airom's document would find its models under a property name airom never
#: writes, and would file its vector store as a framework and drop both its
#: prompts, because airom types those `application` and `data`. The engine id on
#: the trigger is what says which parser to use; nothing about the document
#: itself does.
DISCOVERY_EXTRACTORS = {
    "ai-bom": extract_discovery,
    "airom": extract_airom_discovery,
    "cdxgen-ai": extract_cdxgen_ai_discovery,
    # ⚠ TWO OF THESE READ A DOCUMENT THE CUSTOMER PRODUCED, AND ONE READS A
    # DECLARATION THEY WROTE. They dispatch here like any other engine because
    # the normalizer's job is the same either way — but `ai_model_provenance`
    # records which engine found each model, so a reviewer can tell a row three
    # engines observed in source from one a person typed into `aibom.toml`.
    "aibom-toml": _extract_toml_artifact,
    "aibom-k8s-runtime": extract_import_discovery,
    "aibom-glaas": extract_import_discovery,
}

#: Engines whose output describes WHAT THE REPOSITORY USES.
DISCOVERY_ENGINES = set(DISCOVERY_EXTRACTORS)

#: Engines whose output describes WHAT THOSE MODELS ARE.
#:
#: ⚠ THE TWO SETS ARE SEPARATE BECAUSE THEIR ARTIFACTS ARE DIFFERENT SHAPES.
#: A discovery artifact is one CycloneDX document to run `extract_discovery` over.
#: An enrichment artifact is a MAPPING of model reference -> that model's own
#: CycloneDX card, written by `workers/aienrich`. Reading one as the other would
#: silently yield zero models — the failure mode this whole area keeps producing.
ENRICHMENT_ENGINES = {"aibom-generator"}

#: Every engine this consumer reads. Kept as a name because it is the set the
#: trigger's engine list is filtered against elsewhere.
AIBOM_ENGINES = DISCOVERY_ENGINES | ENRICHMENT_ENGINES

log = get_logger("aibom-normalize-consumer")

SUBJECT = "scan.normalize.aibom"
DLQ_SUBJECT = "scan.dlq.normalize.aibom"
DURABLE = "normalize-consumer-aibom"


@dataclass(frozen=True)
class ConsumerConfigEnv:
    """Configuration for this process only.

    ⚠ DELIBERATELY NOT `axebom_shared.config.WorkerConfig`, and duplicated from
    `workers/sbom/normalize_consumer.py` on purpose.

    WorkerConfig is constructed by five other processes that hold NO database
    credential at all; adding a Postgres password field to it to serve this
    exception would put that field on every one of them. Keeping a small local
    loader per consumer keeps the exception visibly contained to the processes
    that actually need it — which is the entire argument for why the exception
    is acceptable. The shared consume loop lives in
    `axebom_shared.normalize.consumer_runtime`; the credential loading
    deliberately does not.
    """

    nats_url: str
    postgres_dsn: str
    artifacts_root: Path

    @staticmethod
    def load() -> ConsumerConfigEnv:
        missing = [
            name for name in ("POSTGRES_NORMALIZE_WRITER_PASSWORD",) if not os.environ.get(name)
        ]
        if missing:
            raise RuntimeError(
                f"aibom-normalize-consumer configuration error: missing required env var(s) "
                f"{', '.join(missing)} — see .env.example"
            )

        host = os.environ.get("POSTGRES_HOST", "localhost")
        port = os.environ.get("POSTGRES_PORT", "55432")
        db = os.environ.get("POSTGRES_DB", "axebom")
        user = os.environ.get("POSTGRES_NORMALIZE_WRITER_ROLE", "axebom_normalize_writer")
        password = os.environ["POSTGRES_NORMALIZE_WRITER_PASSWORD"]
        sslmode = os.environ.get("POSTGRES_SSLMODE", "disable")

        return ConsumerConfigEnv(
            nats_url=os.environ.get("NATS_URL", "nats://localhost:54222"),
            postgres_dsn=(
                f"host={host} port={port} dbname={db} user={user} "
                f"password={password} sslmode={sslmode}"
            ),
            artifacts_root=Path(os.environ.get("AXEBOM_OUTPUT_ROOT", "/var/lib/axebom/artifacts")),
        )


async def handle_trigger(
    conn: writer.Connection, trigger: dict[str, Any], artifacts_root: Path
) -> None:
    """Normalize and write one scan's AI inventory.

    ⚠ `cards` ARE READ FROM `aibom-generator`'s STORED ARTIFACT, NOT RE-FETCHED.

    This used to pass an empty mapping, so every enrichment-only Table 10 element
    was `not-provided` on every scan no matter what Hugging Face said. Enrichment
    is now a real engine run (`workers/aienrich`, on `scan.job.aibom.enrich`) that
    writes what the API returned as an immutable raw artifact under its own output
    prefix — so normalization reads a file, holds no network, and a
    re-normalization replays the same responses instead of asking again
    (ADR-0003, CLAUDE.md invariant 10).

    An absent artifact still means empty cards, and that is still honest: the
    enrichment run says why in Engine Coverage, and the elements it would have
    filled stay `not-provided` rather than guessed.
    """
    scan_id = str(trigger["scan_id"])
    tenant_id = str(trigger["tenant_id"])
    project_id = str(trigger.get("project_id") or "")
    normalization_version = int(trigger.get("normalization_version", 1))

    if await asyncio.to_thread(
        _already_written, conn, tenant_id, scan_id, "AIBOM", normalization_version
    ):
        log.info("trigger already normalized; skipping", extra={"scan_id": scan_id})
        return

    payloads, diagnostics = _native_payloads(trigger, artifacts_root, DISCOVERY_ENGINES)
    card_payloads, card_diagnostics = _native_payloads(trigger, artifacts_root, ENRICHMENT_ENGINES)
    diagnostics = [*diagnostics, *card_diagnostics]
    cards = _parse_cards([payload for _engine, payload in card_payloads])

    # ⚠ PARSED BY THE ENGINE THAT WROTE IT, AND STAMPED WITH ITS NAME.
    #
    # `source_engine` travels on every discovered model, framework and asset from
    # here — it is the ONLY point in the pipeline that still knows which artifact
    # a finding came out of, and `merge` folds it into the per-engine provenance
    # a reviewer reads to weigh a row ("found by one engine, missed by two").
    # Before this, `normalize.ai_models.source_engine` was written empty on every
    # single row: the column existed, nothing set it, and nothing noticed.
    discoveries = []
    for engine_id, payload in payloads:
        found = DISCOVERY_EXTRACTORS[engine_id](payload)
        for bucket in ("models", "frameworks", "assets"):
            for item in found.get(bucket) or []:
                item["source_engine"] = engine_id
        discoveries.append(found)

    models = [m for d in discoveries for m in (d.get("models") or [])]
    frameworks = [f for d in discoveries for f in (d.get("frameworks") or [])]
    assets = [a for d in discoveries for a in (d.get("assets") or [])]

    # ⚠ THE ENGINE'S OWN DIAGNOSTICS TRAVEL WITH ITS FINDINGS, AND THEY USED NOT TO.
    #
    # Only `_native_payloads`' artifact-level diagnostics were carried; everything
    # `extract_discovery` reported about the CONTENT was computed and dropped on the
    # floor. That includes `AIBOM_MODEL_RECLASSIFIED` — the record of a component the
    # engine called a model being stored as a dependency instead. A model count that
    # changes with no diagnostic beside it is a number nobody can account for, which
    # is the failure CLAUDE.md invariant 12 exists to prevent.
    diagnostics = [
        *diagnostics,
        *(d for disc in discoveries for d in (disc.get("diagnostics") or [])),
    ]

    if not models and not frameworks:
        log.warning(
            "no AI models or frameworks in any artifact; nothing to normalize",
            extra={"scan_id": scan_id, "diagnostics": [d.get("code") for d in diagnostics]},
        )
        return

    # ⚠ ZERO MODELS IS A RESULT, NOT AN ABSENCE, once anything AI-shaped was found.
    #
    # A repository that imports LangChain but names no resolvable model produces a
    # document with no models and a full framework inventory. Returning early there
    # would write NO `bom_documents` row at all — so the report would have nothing to
    # render and Engine Coverage nothing to explain, which reads as "we did not look".
    # `build_canonical_aibom` handles the empty case and is tested for it.

    # ⚠ MERGED INTO ONE discovery, NOT NORMALIZED ONCE PER ARTIFACT.
    #
    # `frameworks` is a SCAN-WIDE list, and build_canonical_aibom joins it onto
    # every model to work out which of that model's framework usages the SBOM
    # already catalogues. Normalizing per artifact would give each model only the
    # frameworks that happened to be in its own file.
    #
    # ⚠ THERE IS NO `datasets` KEY, AND THERE NEVER WAS. This used to gather
    # `d.get("datasets")` from every discovery; `extract_discovery` returns exactly
    # `models`, `frameworks`, `surfaces` and `diagnostics`, and nothing downstream
    # reads a top-level `datasets`. Dataset facts arrive from enrichment, per model.
    discovery: dict[str, Any] = {
        "models": models,
        "frameworks": frameworks,
        # Prompts, vector stores, RAG pipelines and inference endpoints. Only
        # `airom` and `cdxgen-ai` report any; `ai-bom` returns none, so this is
        # empty on a scan that ran only the original engine.
        "assets": assets,
    }

    # Filled by `_do_write` so the log line below can report what was actually
    # WRITTEN. `canonical` is built inside that closure, on the worker thread.
    written: dict[str, int] = {}

    def _do_write() -> writer.WriteResult:
        # ⚠ READ BEFORE WRITING, or a re-normalization deletes the operator's own
        # answers. See load_prior_user_values.
        user_values = load_prior_user_values(conn, tenant_id, project_id)
        canonical = build_canonical_aibom(
            discovery,
            cards,
            scan_id=scan_id,
            user_values_by_identity=user_values,
            governance_by_identity=load_governance(conn, tenant_id, project_id),
        )
        # ⚠ AIBOM DOCUMENTS NOW CARRY THEIR PROJECT, AND THEY DID NOT BEFORE.
        #
        # `bom_documents.project_id` was populated only by HBOM imports; every
        # other type resolved by scan_id, which `services/project` does in two
        # queries across two schemas (invariant 11 forbids the JOIN). This
        # consumer CANNOT do that: `axebom_normalize_writer` is scoped to the
        # `normalize` schema and cannot read `scan.scans` at all — so without a
        # project id on the document there is no way to find the operator's
        # previous answers, and every re-normalization silently deleted them.
        # The trigger has carried project_id since it was defined.
        canonical["project_id"] = project_id or None
        canonical["diagnostics"] = [*canonical.get("diagnostics", []), *diagnostics]
        written["ai_models"] = len(canonical.get("ai_models") or [])
        written["ai_assets"] = len(canonical.get("ai_assets") or [])
        return writer.write_bom_document(
            conn,
            tenant_id=tenant_id,
            scan_id=scan_id,
            bom_type="AIBOM",
            normalization_version=normalization_version,
            canonical=canonical,
        )

    try:
        result = await asyncio.to_thread(_do_write)
    except writer.RefusedError:
        raise
    except Exception as exc:
        if _is_transient(exc):
            raise Retry(str(exc)) from exc
        raise

    log.info(
        "aibom written",
        extra={
            "scan_id": scan_id,
            "bom_document_id": result.bom_document_id,
            # ⚠ WHAT WAS WRITTEN, NOT WHAT WAS FOUND. This counted the
            # pre-merge discovery list, so a scan where three engines each
            # reported the same two models logged `ai_models: 6` next to a
            # document holding 3 — a number nobody could reconcile with the
            # table.
            **written,
        },
    )


def _resolve(uri: str, artifacts_root: Path) -> Path:
    """The artifact's path on this worker's disk.

    A trigger's artifact `uri` is a local path today, not an s3:// reference —
    the same gap docs/STATE.md records for the SBOM consumer.
    """
    path = Path(uri)
    return path if path.is_absolute() else artifacts_root / uri


#: The operator-supplied Table 10 columns, in the order both queries below
#: select them. One tuple rather than two lists, because the two sources have to
#: produce identically-shaped dicts and a per-query column list is how they drift.
_USER_VALUE_COLUMNS = (
    "security_requirements",
    "intended_usage",
    "out_of_scope_usage",
    "environmental_impact",
    "attestation_signature",
)


def load_prior_user_values(
    conn: writer.Connection, tenant_id: str, project_id: str
) -> dict[str, dict[str, Any]]:
    """Operator-entered Table 10 elements, from the service that owns them.

    ⚠ THE SOURCE OF TRUTH IS `aibom.model_user_values`, NOT THE PREVIOUS
    DOCUMENT, AND THAT CHANGE IS THE POINT.

    `services/project` used to write these five elements straight onto
    `normalize.ai_models` with an UPDATE — a mutation of normalized data, which
    CLAUDE.md invariant 10 says never happens. Re-normalizing then built a fresh
    row from engine output alone and wrote `not-provided` over every one of them,
    so this function existed to read the PREVIOUS document back and rescue them.

    A rescue is not a design. It failed silently whenever the chain broke: a
    model whose identity changed between passes, a first normalization after
    somebody answered, a document that never got written. Operator input now
    lives in `services/aibom`'s own schema, keyed by `(project, model_key)`, and
    survives every re-normalization by construction rather than by recovery.

    ⚠ THE PRIOR-DOCUMENT READ IS KEPT AS A FALLBACK, AND ONLY AS ONE. Values
    entered before the migration are still sitting on live `normalize.ai_models`
    rows, and dropping them would lose real customer text on the next scan. The
    owning table wins wherever both have an answer.

    ⚠ READ-ONLY AND BEST-EFFORT. This role holds SELECT and nothing else on
    `aibom` (see `migrations/aibom/0001_init.sql`'s grant, and why it does not
    weaken invariant 10). A failure here degrades to "no prior values": losing an
    operator's text is bad, and failing the whole normalization because one
    lookup failed is worse.
    """
    # No project, nothing to look up. A blank id would also fail the uuid cast
    # and land in the except branch, which would log an error where there is
    # none — there is no previous answer, that is all.
    if not project_id:
        return {}

    out = _query_user_values(
        conn,
        tenant_id,
        project_id,
        """
        SELECT m.model_key, m.security_requirements, m.intended_usage,
               m.out_of_scope_usage, m.environmental_impact, m.attestation_signature
          FROM normalize.ai_models m
          JOIN normalize.bom_documents d ON d.id = m.bom_document_id
         WHERE d.bom_type = 'AIBOM'
           AND d.project_id = %s
         ORDER BY d.generated_at DESC, d.normalization_version DESC
        """,
        source="the previous AIBOM document",
    )
    # The owning table is applied second so it wins on every key it answers.
    out.update(
        _query_user_values(
            conn,
            tenant_id,
            project_id,
            """
            SELECT model_key, security_requirements, intended_usage,
                   out_of_scope_usage, environmental_impact, attestation_signature
              FROM aibom.model_user_values
             WHERE project_id = %s
            """,
            source="aibom.model_user_values",
        )
    )
    return out


def load_governance(
    conn: writer.Connection, tenant_id: str, project_id: str
) -> dict[str, dict[str, Any]]:
    """What a PERSON declared about each model, from `services/aibom`.

    ⚠ NEVER INFERRED, AND THAT IS THE WHOLE REASON IT COMES FROM A TABLE. A risk
    tier under the EU AI Act depends on what a system is USED FOR, which no
    repository shows; deriving one from an import statement would manufacture a
    legal conclusion out of a dependency graph, and a customer would carry it
    into an audit. These values exist only because a named person entered them.

    ⚠ THE ATTESTATION IS A VERIFICATION RESULT, NOT A SIGNATURE. `verified` is
    read from a `model_signing` run the CUSTOMER performed — AxeBOM never holds
    model weights and cannot run it — and `false` is recorded as `false` rather
    than being quietly absent. The newest record per model wins.

    ⚠ READ-ONLY AND BEST-EFFORT, the same posture as the operator values above.
    This role holds SELECT on `aibom` and nothing else.
    """
    if not project_id:
        return {}

    out: dict[str, dict[str, Any]] = {}
    try:
        with conn.transaction():
            cur = conn.cursor()
            cur.execute("SELECT set_config('app.current_tenant_id', %s, true)", (tenant_id,))
            cur.execute(
                """
                SELECT model_key, eu_ai_act_tier, nist_ai_rmf, iso_42001
                  FROM aibom.compliance_tags
                 WHERE project_id = %s
                """,
                (project_id,),
            )
            for model_key, tier, nist, iso in cur.fetchall():
                # A project-wide tag carries an empty model key. Applied to every
                # model below rather than dropped — it is the operator saying
                # "this whole project is limited-risk", which is a real answer
                # for each model in it.
                out.setdefault(model_key or "", {}).update(
                    {
                        "eu_ai_act_tier": tier,
                        "nist_ai_rmf": list(nist or []),
                        "iso_42001": list(iso or []),
                    }
                )
            cur.execute(
                """
                SELECT DISTINCT ON (model_key) model_key, verified
                  FROM aibom.attestations
                 WHERE project_id = %s
                 ORDER BY model_key, created_at DESC
                """,
                (project_id,),
            )
            for model_key, verified in cur.fetchall():
                out.setdefault(model_key or "", {})["attestation_verified"] = verified
    except Exception as exc:
        log.warning(
            "could not read operator-declared governance; those elements stay "
            "unanswered in the operational score",
            extra={"project_id": project_id, "cause": str(exc)},
        )
        return {}

    project_wide = out.pop("", None)
    if project_wide:
        for model_key in list(out):
            # A per-model tag is the more specific statement and wins.
            out[model_key] = {**project_wide, **out[model_key]}
        # ⚠ KEPT UNDER THE EMPTY KEY TOO. `build_canonical_aibom` looks up by
        # model key; a project-wide declaration has to reach models that have no
        # tag of their own, and the pipeline falls back to this entry.
        out[""] = project_wide
    return out


def _query_user_values(
    conn: writer.Connection, tenant_id: str, project_id: str, sql: str, *, source: str
) -> dict[str, dict[str, Any]]:
    """One source of operator values, keyed by `model_key`.

    ⚠ A VALUE THAT ASSERTS NOTHING IS NOT A VALUE (invariant 3). `not-provided`,
    an empty string and whitespace all mean "nobody answered", and carrying one
    forward as if it were an answer would let a cleared field masquerade as a
    filled one — and, worse, would let the fallback source shadow a real answer
    in the owning table with an empty one.
    """
    try:
        with conn.transaction():
            cur = conn.cursor()
            cur.execute("SELECT set_config('app.current_tenant_id', %s, true)", (tenant_id,))
            cur.execute(sql, (project_id,))
            rows = cur.fetchall()
    except Exception as exc:
        log.warning(
            "could not read operator-supplied values; the elements they would "
            "have filled stay not-provided",
            extra={"project_id": project_id, "source": source, "cause": str(exc)},
        )
        return {}

    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        model_key = row[0]
        # The prior-document query orders newest first, so the first row for a
        # key wins; the owning table has one row per key and never collides.
        if not model_key or model_key in out:
            continue
        values = {
            column: value
            for column, value in zip(_USER_VALUE_COLUMNS, row[1:], strict=False)
            if isinstance(value, str) and value.strip() and value != "not-provided"
        }
        if values:
            out[model_key] = values
    return out


def _parse_cards(payloads: list[dict[str, Any]]) -> dict[str, ModelCard]:
    """Turn `workers/aienrich`'s stored artifacts into parsed model cards.

    ⚠ ONE BAD CARD NEVER LOSES THE OTHERS, and never loses the scan. A card that
    will not parse leaves that model's enrichment-only elements `not-provided` —
    true, and visible in the coverage number — rather than aborting a
    normalization that has real discovery data to write.
    """
    cards: dict[str, ModelCard] = {}
    for payload in payloads:
        for model_ref, raw in payload.items():
            if not isinstance(model_ref, str) or not isinstance(raw, dict):
                continue
            try:
                cards[model_ref] = parse_model_card(model_ref, "", raw)
            except Exception as exc:
                log.warning(
                    "a stored model card did not parse; that model stays unenriched",
                    extra={"model_ref": model_ref, "cause": str(exc)},
                )
    return cards


def _native_payloads(
    trigger: dict[str, Any], artifacts_root: Path, engine_ids: set[str]
) -> tuple[list[tuple[str, dict[str, Any]]], list[dict[str, Any]]]:
    """Read every named engine's stored native output, paired with its engine id.

    ⚠ THE ENGINE ID IS RETURNED, NOT DISCARDED. Three engines write documents in
    the same format and different dialects, so the caller has to know which
    parser to run — and nothing in the document itself reliably says. It is also
    the only place `source_engine` can come from.

    ⚠ ABSENT OR UNREADABLE IS A DIAGNOSTIC, NEVER AN EXCEPTION. A missing
    artifact must reach the report's Engine Coverage section (invariant 12), not
    crash the consumer — an engine that produced nothing is a stated gap, and a
    crashed consumer is a scan that never normalizes at all.
    """
    payloads: list[tuple[str, dict[str, Any]]] = []
    diagnostics: list[dict[str, Any]] = []

    for engine in trigger.get("engines", []):
        engine_id = str(engine.get("engine_id", ""))
        if engine_id not in engine_ids:
            continue
        native = next(
            (a for a in engine.get("artifacts", []) if a.get("role") == "native_output"), None
        )
        if native is None:
            diagnostics.append(
                {
                    "severity": "info",
                    "code": "NORMALIZE_ARTIFACT_ABSENT",
                    "message": f"{engine_id} produced no artifact "
                    f"(status {engine.get('status') or 'unknown'})",
                }
            )
            continue
        try:
            payload = json.loads(_resolve(str(native.get("uri", "")), artifacts_root).read_bytes())
        except OSError as exc:
            diagnostics.append(
                {
                    "severity": "warn",
                    "code": "NORMALIZE_ARTIFACT_UNREADABLE",
                    "message": f"{engine_id}'s artifact could not be read: {exc}",
                }
            )
            continue
        except (json.JSONDecodeError, ValueError) as exc:
            diagnostics.append(
                {
                    "severity": "warn",
                    "code": "NORMALIZE_ARTIFACT_UNPARSEABLE",
                    "message": f"{engine_id}'s artifact is not valid JSON: {exc}",
                }
            )
            continue
        if isinstance(payload, dict):
            payloads.append((engine_id, payload))

    return payloads, diagnostics


def _already_written(
    conn: writer.Connection, tenant_id: str, scan_id: str, bom_type: str, version: int
) -> bool:
    """⚠ INSIDE A REAL TRANSACTION. `set_config(..., true)` is transaction-local,
    and under autocommit a bare statement is its own transaction that reverts the
    setting the instant it completes — the next statement would then fail RLS's
    `current_setting(...)::uuid` cast on an empty string. The same trap
    write_bom_document documents for the write path, here on the read path."""
    with conn.transaction():
        cur = conn.cursor()
        cur.execute("SELECT set_config('app.current_tenant_id', %s, true)", (tenant_id,))
        cur.execute(
            "SELECT id FROM normalize.bom_documents "
            "WHERE scan_id = %s AND bom_type = %s AND normalization_version = %s",
            (scan_id, bom_type, version),
        )
        return cur.fetchone() is not None


def _is_transient(exc: BaseException) -> bool:
    """Narrow on purpose: a lost connection will succeed on a retry; a constraint
    violation will not, and calling it transient hides a real bug behind three
    retries and a DLQ entry that says only "retries exhausted"."""
    import psycopg

    return isinstance(exc, (psycopg.OperationalError, psycopg.errors.SerializationFailure))


def main() -> int:
    cfg = ConsumerConfigEnv.load()
    try:
        asyncio.run(
            run_consumer(
                subject=SUBJECT,
                dlq_subject=DLQ_SUBJECT,
                durable=DURABLE,
                handler=handle_trigger,
                nats_url=cfg.nats_url,
                postgres_dsn=cfg.postgres_dsn,
                artifacts_root=cfg.artifacts_root,
            )
        )
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        log.error("aibom normalize consumer exited", extra={"cause": str(exc)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
