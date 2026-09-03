"""Consumes scan.normalize.cbom and writes one scan's crypto inventory.

⚠ THIS CLOSES A GAP THAT MADE CBOM SCANS LOOK SUCCESSFUL AND WRITE NOTHING.

`cbomkit-theia` has discovered and stored raw output for a long time, and
`build_canonical_cbom` has produced a writable document for just as long —
but nothing consumed the trigger, so `normalize.crypto_assets` stayed empty while the
scan reported `completed` and the Engine Coverage panel showed a green engine.
docs/STATE.md recorded it empirically: `scan.normalize_triggers` held zero
cbom rows against any real scan, ever.

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

from workers.cbom.adapters.cbomkit_theia import extract_crypto_assets
from workers.cbom.normalize.pipeline import build_canonical_cbom

from axebom_shared.logging import get_logger
from axebom_shared.normalize import writer
from axebom_shared.normalize.consumer_runtime import Retry, run_consumer

#: Engines whose native output this consumer knows how to read.
#:
#: ⚠ cbomkit AND sonar-cryptography ARE ABSENT ON PURPOSE. Both are
#: `enabled: false` in the manifest with a stated reason (a managed
#: service and a SonarQube plugin, neither a CLI this worker can
#: invoke), so neither ever produces an artifact to read.
CBOM_ENGINES = {"cbomkit-theia"}

log = get_logger("cbom-normalize-consumer")

SUBJECT = "scan.normalize.cbom"
DLQ_SUBJECT = "scan.dlq.normalize.cbom"
DURABLE = "normalize-consumer-cbom"


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
                f"cbom-normalize-consumer configuration error: missing required env var(s) "
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
    """Normalize and write one scan's crypto inventory.

    ⚠ IDEMPOTENT: pre-checks `(scan_id, bom_type, normalization_version)` before
    doing any real work; the table's UNIQUE constraint is the backstop for two
    replicas racing overlapping redeliveries of the same trigger.
    """
    scan_id = str(trigger["scan_id"])
    tenant_id = str(trigger["tenant_id"])
    normalization_version = int(trigger.get("normalization_version", 1))

    if await asyncio.to_thread(
        _already_written, conn, tenant_id, scan_id, "CBOM", normalization_version
    ):
        log.info("trigger already normalized; skipping", extra={"scan_id": scan_id})
        return

    payloads, diagnostics = _native_payloads(trigger, artifacts_root, CBOM_ENGINES)

    assets: list[dict[str, Any]] = []
    for payload in payloads:
        found, extraction_diagnostics = extract_crypto_assets(payload)
        assets.extend(found)
        diagnostics.extend(extraction_diagnostics)

    if not assets:
        # ⚠ NOT AN ERROR, AND NOT A SILENT RETURN EITHER. A project with no
        # cryptography in it is a normal thing to scan, so writing no document is
        # correct. Saying nothing about it is not: "no CBOM exists for this scan"
        # and "the consumer never ran" look identical from the outside, and the
        # second is the failure this module was written to end.
        log.warning(
            "no crypto assets in any artifact; nothing to normalize",
            extra={"scan_id": scan_id, "diagnostics": [d.get("code") for d in diagnostics]},
        )
        return

    def _do_write() -> writer.WriteResult:
        canonical = build_canonical_cbom(assets)
        canonical["diagnostics"] = [*canonical.get("diagnostics", []), *diagnostics]
        return writer.write_bom_document(
            conn,
            tenant_id=tenant_id,
            scan_id=scan_id,
            bom_type="CBOM",
            normalization_version=normalization_version,
            canonical=canonical,
        )

    try:
        # Off the event loop: the writer is synchronous and this loop must keep
        # answering NATS pings while a large document is written.
        result = await asyncio.to_thread(_do_write)
    except writer.RefusedError:
        # A cap was exceeded. Permanent — a retry writes the same rows again.
        raise
    except Exception as exc:
        if _is_transient(exc):
            raise Retry(str(exc)) from exc
        raise

    log.info(
        "cbom written",
        extra={
            "scan_id": scan_id,
            "bom_document_id": result.bom_document_id,
            "crypto_assets": len(assets),
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
        log.error("cbom normalize consumer exited", extra={"cause": str(exc)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
