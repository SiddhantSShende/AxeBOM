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
from workers.aibom.normalize.pipeline import build_canonical_aibom

from axebom_shared.logging import get_logger
from axebom_shared.normalize import writer
from axebom_shared.normalize.consumer_runtime import Retry, run_consumer

#: Engines whose native output this consumer knows how to read.
#:
#: ⚠ aibom-generator IS ABSENT because it is an ENRICHMENT fetcher, not
#: a discovery engine — it produces model cards over the Hugging Face
#: API, not a scan artifact, and is not live-wired. See handle_trigger.
AIBOM_ENGINES = {"ai-bom"}

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

    ⚠ `cards` IS EMPTY, AND THAT IS THE HONEST STATE OF THE PRODUCT.

    Model cards come from `aibom-generator`, which calls the Hugging Face API and
    is deliberately NOT live-wired — workers/aibom/runner.py's own docstring
    records three unresolved design questions about when enrichment runs, whether
    the HF response must become a stored raw artifact under ADR-0003, and how a
    rate limit interacts with redelivery. Passing an empty mapping means the
    enrichment-only Table 10 fields stay `not-provided`: reported, never guessed.
    """
    scan_id = str(trigger["scan_id"])
    tenant_id = str(trigger["tenant_id"])
    normalization_version = int(trigger.get("normalization_version", 1))

    if await asyncio.to_thread(
        _already_written, conn, tenant_id, scan_id, "AIBOM", normalization_version
    ):
        log.info("trigger already normalized; skipping", extra={"scan_id": scan_id})
        return

    payloads, diagnostics = _native_payloads(trigger, artifacts_root, AIBOM_ENGINES)

    discoveries = [extract_discovery(payload) for payload in payloads]
    models = [m for d in discoveries for m in (d.get("models") or [])]
    if not models:
        log.warning(
            "no AI models in any artifact; nothing to normalize",
            extra={"scan_id": scan_id, "diagnostics": [d.get("code") for d in diagnostics]},
        )
        return

    # ⚠ MERGED INTO ONE discovery, NOT NORMALIZED ONCE PER ARTIFACT.
    #
    # `frameworks` is a SCAN-WIDE list, and build_canonical_aibom joins it onto
    # every model to work out which of that model's framework usages the SBOM
    # already catalogues. Normalizing per artifact would give each model only the
    # frameworks that happened to be in its own file.
    discovery: dict[str, Any] = {
        "models": models,
        "frameworks": [f for d in discoveries for f in (d.get("frameworks") or [])],
        "datasets": [s for d in discoveries for s in (d.get("datasets") or [])],
    }

    def _do_write() -> writer.WriteResult:
        canonical = build_canonical_aibom(discovery, {})
        canonical["diagnostics"] = [*canonical.get("diagnostics", []), *diagnostics]
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
            "ai_models": len(models),
        },
    )


def _resolve(uri: str, artifacts_root: Path) -> Path:
    """The artifact's path on this worker's disk.

    A trigger's artifact `uri` is a local path today, not an s3:// reference —
    the same gap docs/STATE.md records for the SBOM consumer.
    """
    path = Path(uri)
    return path if path.is_absolute() else artifacts_root / uri


def _native_payloads(
    trigger: dict[str, Any], artifacts_root: Path, engine_ids: set[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Read every named engine's stored native output.

    ⚠ ABSENT OR UNREADABLE IS A DIAGNOSTIC, NEVER AN EXCEPTION. A missing
    artifact must reach the report's Engine Coverage section (invariant 12), not
    crash the consumer — an engine that produced nothing is a stated gap, and a
    crashed consumer is a scan that never normalizes at all.
    """
    payloads: list[dict[str, Any]] = []
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
            payloads.append(payload)

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
