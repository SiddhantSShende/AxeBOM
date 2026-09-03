"""Consumes scan.normalize.hbom and writes one scan's hardware BOM.

⚠ THIS CLOSES THE GAP THAT WOULD OTHERWISE MAKE AN HBOM SCAN LOOK SUCCESSFUL
AND WRITE NOTHING.

`hbom-ecad` parses design files and stores a raw artifact. Without a consumer
on the other end of the trigger, that scan reaches `completed`, the Engine
Coverage section shows a green engine, and `normalize.hardware_components` stays
empty — a completed scan with no results and no error anywhere. It is the exact
failure SBOM had before its consumer was built (docs/STATE.md, 2026-08-26), and
`normalizedFamilies` in `normalize_trigger.go` exists so a family cannot be
triggered before its consumer is deployed.

⚠ THE CREDENTIAL EXCEPTION, RESTATED BECAUSE IT APPLIES HERE TOO.

This process holds a Postgres role, which every other worker deliberately does
not. `axebom_normalize_writer` is scoped to the `normalize` schema and to
SELECT/INSERT only — no UPDATE, no DELETE anywhere except one column list —
so it structurally cannot overwrite normalized data in place (invariant 10),
even by application bug. RLS applies to it exactly as to any other role.

⚠ A CONSEQUENCE OF INSERT-ONLY WORTH STATING: everything this writes must be
computed BEFORE the insert. There is no follow-up UPDATE available, which is
why `build_canonical_hbom` produces the complete document — both coverage
numbers included — rather than writing rows and scoring them afterwards.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from axebom_shared.logging import get_logger
from axebom_shared.normalize import writer
from axebom_shared.normalize.consumer_runtime import Retry, run_consumer

from .ingest import ingest
from .model import HardwareComponent
from .normalize import build_canonical_hbom

log = get_logger("hbom-normalize-consumer")

SUBJECT = "scan.normalize.hbom"
DLQ_SUBJECT = "scan.dlq.normalize.hbom"
DURABLE = "normalize-consumer-hbom"


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
                f"hbom-normalize-consumer configuration error: missing required env var(s) "
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


def load_roots(
    trigger: dict[str, Any], artifacts_root: Path
) -> tuple[list[HardwareComponent], list[dict[str, Any]]]:
    """Read every engine's stored artifact back into component trees.

    ⚠ ABSENT OR UNREADABLE IS A DIAGNOSTIC, NEVER AN EXCEPTION. A missing
    artifact has to reach the report's Engine Coverage section (invariant 12),
    not crash the consumer — an engine that produced nothing is a stated gap,
    and a crashed consumer is a scan that never normalizes at all.

    ⚠ TREES CONCATENATE ACROSS ENGINES RATHER THAN MERGING. `hbom-ecad` and
    `hbom-cdxgen-host` describe genuinely different things — a board's designed
    parts list, and a host machine's self-reported inventory — and merging them
    would assert that a component appearing in both is one part. It is not; the
    two documents are about different objects, so each contributes its own root.
    """
    roots: list[HardwareComponent] = []
    diagnostics: list[dict[str, Any]] = []

    for engine in trigger.get("engines", []):
        engine_id = str(engine.get("engine_id", ""))
        status = str(engine.get("status", ""))

        native = next(
            (a for a in engine.get("artifacts", []) if a.get("role") == "native_output"), None
        )
        if native is None:
            diagnostics.append(
                {
                    "severity": "info",
                    "code": "NORMALIZE_ARTIFACT_ABSENT",
                    "message": f"{engine_id} produced no artifact (status {status or 'unknown'})",
                }
            )
            continue

        path = _resolve(str(native.get("uri", "")), artifacts_root)
        try:
            payload = json.loads(path.read_bytes())
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

        engine_roots, engine_diagnostics = ingest(engine_id, payload)
        for d in engine_diagnostics:
            d.setdefault("engine", engine_id)
        roots.extend(engine_roots)
        diagnostics.extend(engine_diagnostics)

    return roots, diagnostics


def _resolve(uri: str, artifacts_root: Path) -> Path:
    """The artifact's path on this worker's disk.

    Mirrors the SBOM consumer: a trigger's artifact `uri` is a local path
    today, not an s3:// reference — see docs/STATE.md's note that raw-artifact
    storage is local-disk while the contract describes object storage.
    """
    path = Path(uri)
    return path if path.is_absolute() else artifacts_root / uri


async def handle_trigger(
    conn: writer.Connection, trigger: dict[str, Any], artifacts_root: Path
) -> None:
    """Normalize and write one scan's hardware BOM.

    ⚠ IDEMPOTENT: pre-checks `(scan_id, bom_type, normalization_version)`
    before doing any real work, and the table's own UNIQUE constraint is the
    backstop for the racing case — two replicas processing overlapping
    redeliveries of the same trigger.
    """
    scan_id = str(trigger["scan_id"])
    tenant_id = str(trigger["tenant_id"])
    project_id = str(trigger.get("project_id") or "") or None
    normalization_version = int(trigger.get("normalization_version", 1))

    # ⚠ INSIDE A REAL TRANSACTION. `set_config(..., true)` is transaction-local,
    # and under autocommit a bare statement is its own transaction that reverts
    # the setting the instant it completes — the next statement would then fail
    # RLS's `current_setting(...)::uuid` cast on an empty string. The same trap
    # write_bom_document documents for the write path, here on the read path.
    already_written = False
    with conn.transaction():
        cur = conn.cursor()
        cur.execute("SELECT set_config('app.current_tenant_id', %s, true)", (tenant_id,))
        cur.execute(
            "SELECT id FROM normalize.bom_documents "
            "WHERE scan_id = %s AND bom_type = 'HBOM' AND normalization_version = %s",
            (scan_id, normalization_version),
        )
        already_written = cur.fetchone() is not None

    if already_written:
        log.info("trigger already normalized; skipping", extra={"scan_id": scan_id})
        return

    roots, diagnostics = load_roots(trigger, artifacts_root)
    if not roots:
        # ⚠ NOT AN ERROR, AND NOT A SILENT RETURN EITHER. Every engine may
        # legitimately have found no design files — a repository with no
        # hardware in it is a normal thing to scan. Writing no document is
        # correct; saying nothing about it is not, because "no hardware BOM
        # exists for this scan" and "the consumer never ran" look identical
        # from the outside.
        log.warning(
            "no hardware components in any artifact; nothing to normalize",
            extra={
                "scan_id": scan_id,
                "diagnostics": [d.get("code") for d in diagnostics],
            },
        )
        return

    def _do_write() -> writer.WriteResult:
        canonical = build_canonical_hbom(roots, project_id=project_id)
        canonical["diagnostics"] = [*canonical.get("diagnostics", []), *diagnostics]
        return writer.write_bom_document(
            conn,
            tenant_id=tenant_id,
            scan_id=scan_id,
            bom_type="HBOM",
            normalization_version=normalization_version,
            canonical=canonical,
        )

    try:
        # Off the event loop: the writer is synchronous, and this loop has to
        # keep answering NATS pings while a large parts list is written — the
        # same reasoning worker_runtime gives for engine-job handlers.
        result = await asyncio.to_thread(_do_write)
    except writer.RefusedError as exc:
        # A cap was exceeded. Permanent — retrying writes the same rows again.
        log.error("hardware bulk write refused", extra={"scan_id": scan_id, "cause": str(exc)})
        raise
    except Exception as exc:
        # ⚠ A CONNECTION FAILURE IS TRANSIENT AND EVERYTHING ELSE IS NOT.
        # Raising Retry for an unknown failure would spend the whole retry
        # budget on something that will never succeed; the shared runtime's
        # default is permanent for exactly that reason.
        if _is_transient(exc):
            raise Retry(str(exc)) from exc
        raise

    log.info(
        "hardware bom written",
        extra={
            "scan_id": scan_id,
            "bom_document_id": result.bom_document_id,
            "components": len(roots),
        },
    )


def _is_transient(exc: BaseException) -> bool:
    """Whether a write failure is worth another delivery.

    Narrow on purpose: a lost connection or a serialization conflict will
    succeed on a retry; a constraint violation or a schema mismatch will not,
    and treating it as transient would hide a real bug behind three retries and
    a DLQ entry that says "retries exhausted" rather than what went wrong.
    """
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
        log.error("hbom normalize consumer exited", extra={"cause": str(exc)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
