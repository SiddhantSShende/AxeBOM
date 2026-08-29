"""The normalize consumer: turns a NormalizeTriggerV1 into a written
`normalize.bom_documents` row.

⚠ THIS IS THE ONE DELIBERATE EXCEPTION TO "WORKERS HOLD NO CREDENTIALS"
(`axebom_shared.config`'s module docstring). Every other worker in this repo
runs third-party scanners over untrusted user code and must never hold a
secret an attacker who escaped the sandbox could use. This process is
different in kind: it never runs a scanner and never touches a scanned
repository's contents — it only reads already-stored, already-validated raw
artifacts (JSON scanner output already sitting on disk) and writes canonical
rows to Postgres. Its credential is scoped to exactly that:
`axebom_normalize_writer`, SELECT/INSERT-only on the `normalize` schema plus
one narrow column-scoped UPDATE on `vuln_clusters`
(`migrations/normalize/0006_alias_snapshot.sql`) — see
`docs/02-CONTRACTS.md` §6a.

⚠ NOT BUILT ON `axebom_shared.bus.WorkerBus`. That class is hard-wired to the
engine-job/result shape (a `ScanJobV1` in on `scan.job.<family>`, a
`ScanResultV1` out on `scan.result.<family>`) — this consumer is
fire-and-forget: read a trigger, write to Postgres, ack. A small,
purpose-built asyncio loop instead, structured in parallel to `WorkerBus`'s
own conventions (durable name, `NakWithDelay` backoff, DLQ) so it reads as
"the same discipline, a different shape," not a one-off.

Usage::

    python -m workers.sbom.normalize_consumer
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import nats
import psycopg
from nats.js.api import ConsumerConfig, DeliverPolicy
from nats.js.errors import NotFoundError

from axebom_shared.logging import get_logger
from axebom_shared.normalize import RULESET_VERSION, cluster_store, writer
from axebom_shared.normalize.pipeline import Artifact, normalize

from .normalize_runner import sbom_fields

log = get_logger("normalize-consumer")

STREAM_NORMALIZE = "NORMALIZE_JOBS"
SUBJECT = "scan.normalize.sbom"
DLQ_SUBJECT = "scan.dlq.normalize.sbom"
DURABLE = "normalize-consumer-sbom"

#: Total attempts, matching bus.go's MaxDeliver — three retries after the
#: first.
MAX_DELIVER = 4

#: Seconds. Deliberately SHORTER than the 30-minute sandbox-sized ack_wait
#: every SCAN_JOBS consumer uses — normalization is in-process CPU work, not
#: a container run. Sized for the documented worst case: bulk-inserting
#: hundreds of thousands of findings for one very large monorepo scan.
ACK_WAIT_SECONDS = 15 * 60

#: Redelivery schedule in seconds — same shape as bus.go's/bus.py's, not the
#: same numbers: normalization failures are almost always a real bug (a bad
#: artifact, a schema mismatch), not "the node is rolling," so there is
#: little value in waiting minutes between attempts.
BACKOFF_SECONDS = (10, 30, 90)


class Retry(Exception):  # noqa: N818 — a control-flow signal, not an error report
    """Raised to request redelivery with backoff. Anything else raised is
    treated as PERMANENT and goes straight to the DLQ — the same default
    axebom_shared.bus.Retry documents, and for the same reason: retrying an
    unknown failure is a guess, and a wrong guess costs the whole retry
    budget."""


@dataclass(frozen=True)
class ConsumerConfigEnv:
    """This consumer's own configuration.

    ⚠ DELIBERATELY NOT `axebom_shared.config.WorkerConfig` — that type is
    the shared shape every OTHER worker loads, and it has no database
    fields by design (its own docstring: "WORKERS HOLD NO CREDENTIALS").
    Adding one there to serve this single, deliberate exception would put a
    Postgres credential field on a type five other processes construct too.
    This is a small, separate, local loader instead — the exception stays
    visibly contained to the one process that needs it.
    """

    nats_url: str
    postgres_dsn: str
    artifacts_root: Path

    @staticmethod
    def load() -> ConsumerConfigEnv:
        missing = [
            name
            for name in ("POSTGRES_NORMALIZE_WRITER_PASSWORD",)
            if not os.environ.get(name)
        ]
        if missing:
            raise RuntimeError(
                f"normalize-consumer configuration error: missing required env var(s) "
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
            artifacts_root=Path(
                os.environ.get("AXEBOM_OUTPUT_ROOT", "/var/lib/axebom/artifacts")
            ),
        )


def load_artifacts(trigger: dict[str, Any], artifacts_root: Path) -> list[Artifact]:
    """Build the pipeline.Artifact list a NormalizeTriggerV1 describes.

    ⚠ MIRRORS normalize_runner.load_artifacts' EXISTING LOGIC — absent or
    unreadable is `unavailable`/`failed`, never an exception, because a
    missing artifact must reach the Engine Coverage table (CLAUDE.md
    invariant 12), not crash the consumer. The difference is the SOURCE: the
    trigger's own `engines[]` list (from the orchestrator, which already
    knows what actually ran), not a hardcoded ARTIFACTS filename dict and a
    fixture directory.
    """
    out: list[Artifact] = []

    for engine in trigger.get("engines", []):
        engine_id = str(engine.get("engine_id", ""))
        status = str(engine.get("status", ""))
        engine_version = str(engine.get("engine_version", ""))
        engine_db_version = str(engine.get("engine_db_version", ""))

        native = next(
            (a for a in engine.get("artifacts", []) if a.get("role") == "native_output"), None
        )
        if native is None:
            out.append(
                Artifact(
                    engine=engine_id, payload={}, engine_version=engine_version,
                    engine_db_version=engine_db_version, status=status or "unavailable",
                )
            )
            continue

        path = Path(str(native.get("uri", "")))
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning(
                "raw artifact is unreadable", extra={"engine": engine_id, "path": str(path), "cause": str(exc)}
            )
            out.append(
                Artifact(
                    engine=engine_id, payload={}, engine_version=engine_version,
                    engine_db_version=engine_db_version, status="failed",
                )
            )
            continue

        out.append(
            Artifact(
                engine=engine_id,
                payload=payload,
                engine_version=engine_version,
                engine_db_version=engine_db_version,
                status=status or "succeeded",
                sha256=str(native.get("sha256", "")),
                uri=str(path),
            )
        )

    return out


def _mint_alias_snapshot(conn: writer.Connection, edge_count: int) -> str:
    """Insert one normalize.alias_snapshot row and return its id — the
    versioned provenance marker normalize.bom_documents.alias_snapshot_id
    (NOT NULL) requires. `source='scan-local'` is the honest label: today's
    edges are derived scan-locally by cluster_store's pre-pass, not read
    from a persisted, independently-versioned global snapshot — see
    migrations/normalize/0006_alias_snapshot.sql's own comment on this.
    """
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO normalize.alias_snapshot (edge_count, source, ruleset_version) "
        "VALUES (%s, %s, %s) RETURNING id",
        (edge_count, "scan-local", RULESET_VERSION),
    )
    return str(cur.fetchone()[0])


async def handle_trigger(conn: writer.Connection, trigger: dict[str, Any], artifacts_root: Path) -> None:
    """Normalize and write one scan's SBOM canonical model.

    ⚠ IDEMPOTENT: pre-checks `(scan_id, bom_type, normalization_version)`
    before doing any real work, and the table's own UNIQUE constraint
    (migrations/normalize/0001_bom_components.sql) is the correctness
    backstop for the racing case — two consumer replicas processing
    overlapping redeliveries of the same trigger.
    """
    scan_id = str(trigger["scan_id"])
    tenant_id = str(trigger["tenant_id"])
    normalization_version = int(trigger.get("normalization_version", 1))

    # ⚠ `is_local=true` (the third `set_config` argument) only holds for the
    # lifetime of a REAL transaction — under autocommit, a bare statement
    # outside `with conn.transaction():` is its own transaction that
    # commits (and reverts the LOCAL setting) the instant it completes.
    # Without this block, the very next statement would see
    # app.current_tenant_id already unset again and fail RLS's
    # `current_setting(...)::uuid` cast on an empty string — exactly the
    # trap write_bom_document's own docstring documents for the write path;
    # this is the same trap on the read path.
    already_written = False
    with conn.transaction():
        cur = conn.cursor()
        cur.execute("SELECT set_config('app.current_tenant_id', %s, true)", (tenant_id,))
        cur.execute(
            "SELECT id FROM normalize.bom_documents "
            "WHERE scan_id = %s AND bom_type = 'SBOM' AND normalization_version = %s",
            (scan_id, normalization_version),
        )
        already_written = cur.fetchone() is not None

    if already_written:
        log.info("trigger already normalized; skipping", extra={"scan_id": scan_id})
        return

    artifacts = load_artifacts(trigger, artifacts_root)

    # Run in a worker thread: cluster_store/pipeline/writer are all
    # synchronous, and this loop must keep answering NATS pings while a
    # large scan's bulk write runs — the same reasoning
    # axebom_shared.worker_runtime's module docstring gives for running
    # engine-job handlers off the event loop.
    def _do_write() -> writer.WriteResult:
        cluster_uuid_map = cluster_store.persist_clusters(conn, artifacts)
        alias_snapshot_id = _mint_alias_snapshot(conn, edge_count=len(cluster_uuid_map))

        result = normalize(
            artifacts,
            scan_id=scan_id,
            fields=sbom_fields(),
            existing_clusters=cluster_uuid_map,
            # ⚠ SHOULD NEVER FIRE. cluster_store.persist_clusters already
            # resolved a durable id for every member it touched — by the
            # time normalize() runs, existing_clusters covers every vuln id
            # this scan has. If this mint iterator IS invoked, that is a
            # wiring regression (a member cluster_store never saw), not a
            # normal path — logged loudly rather than silently minting a
            # non-durable id the way normalize_runner's `_default_ids`
            # fixture fallback does.
            cluster_ids=_loud_unexpected_mint(scan_id),
            alias_snapshot_id=alias_snapshot_id,
            source_commit_sha=str(trigger.get("source_commit_sha", "")),
            workspace_archive_sha256=str(trigger.get("workspace_archive_sha256", "")),
            normalization_version=normalization_version,
            ecosystems_without_engine=trigger.get("ecosystems_without_engine") or (),
        )

        return writer.write_bom_document(
            conn,
            tenant_id=tenant_id,
            scan_id=scan_id,
            bom_type="SBOM",
            normalization_version=normalization_version,
            canonical=result.as_dict(),
        )

    try:
        write_result = await asyncio.to_thread(_do_write)
    except writer.RefusedError as exc:
        # Permanent: retrying will not shrink the scan. Logged loudly —
        # per the plan's own admitted gap, there is not yet a visible API
        # signal distinguishing "refused, cap exceeded" from "not
        # normalized yet"; this log line is the only trace today.
        log.error(
            "normalization refused — a cap was exceeded",
            extra={"scan_id": scan_id, "diagnostics": exc.diagnostics},
        )
        return

    log.info(
        "wrote a normalize.bom_documents row",
        extra={
            "scan_id": scan_id,
            "bom_document_id": write_result.bom_document_id,
            "diagnostics": len(write_result.diagnostics),
        },
    )


def _loud_unexpected_mint(scan_id: str):
    i = 0
    while True:
        log.error(
            "cluster_ids mint fired from a live trigger — cluster_store.py should have "
            "resolved every member already; this indicates a wiring regression",
            extra={"scan_id": scan_id, "n": i},
        )
        yield f"UNEXPECTED-MINT-{scan_id}-{i:04d}"
        i += 1


# ---------------------------------------------------------------------------
# The consumer loop — parallel to axebom_shared.bus.WorkerBus's shape
# ---------------------------------------------------------------------------


async def _run(cfg: ConsumerConfigEnv) -> None:
    stopping = asyncio.Event()

    nc = await nats.connect(
        cfg.nats_url, name="axebom-normalize-consumer",
        max_reconnect_attempts=-1, reconnect_time_wait=2,
    )
    js = nc.jetstream()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stopping.set)

    await _await_stream(js)

    try:
        await js.add_consumer(
            STREAM_NORMALIZE,
            ConsumerConfig(
                durable_name=DURABLE,
                filter_subject=SUBJECT,
                ack_wait=ACK_WAIT_SECONDS,
                max_deliver=MAX_DELIVER,
                max_ack_pending=4,
                deliver_policy=DeliverPolicy.ALL,
            ),
        )
    except Exception as exc:
        raise RuntimeError(
            f"could not attach consumer {DURABLE!r} to {SUBJECT!r}: {exc}"
        ) from exc

    sub = await js.pull_subscribe(SUBJECT, durable=DURABLE, stream=STREAM_NORMALIZE)
    log.info("normalize consumer ready", extra={"subject": SUBJECT})

    conn = await asyncio.to_thread(psycopg.connect, cfg.postgres_dsn, autocommit=True)
    try:
        while not stopping.is_set():
            try:
                msgs = await sub.fetch(batch=1, timeout=5)
            except TimeoutError:
                continue
            for msg in msgs:
                await _dispatch(msg, conn, cfg.artifacts_root, js)
    finally:
        conn.close()
        await nc.drain()


async def _await_stream(js: Any, attempts: int = 30, delay: float = 2.0) -> None:
    for attempt in range(1, attempts + 1):
        try:
            await js.stream_info(STREAM_NORMALIZE)
            return
        except NotFoundError:
            if attempt == attempts:
                raise RuntimeError(
                    f"stream {STREAM_NORMALIZE} does not exist after {attempts} attempts — "
                    "it is created by the Go scan-orchestrator on boot"
                ) from None
            await asyncio.sleep(delay)


async def _dispatch(msg: Any, conn: writer.Connection, artifacts_root: Path, js: Any) -> None:
    delivered = _delivery_count(msg)

    try:
        trigger = json.loads(msg.data)
    except json.JSONDecodeError as exc:
        log.error("trigger is not valid JSON; sending to DLQ", extra={"error": str(exc)})
        await _to_dlq(js, msg, f"invalid JSON: {exc}", delivered)
        await msg.term()
        return

    scan_id = str(trigger.get("scan_id", ""))
    try:
        await handle_trigger(conn, trigger, artifacts_root)
    except Retry as exc:
        if delivered >= MAX_DELIVER:
            log.error("retries exhausted; sending to DLQ", extra={"scan_id": scan_id, "delivered": delivered})
            await _to_dlq(js, msg, f"retries exhausted: {exc}", delivered)
            await msg.ack()
            return
        delay = _backoff_for(delivered)
        log.warning("transient failure; redelivering", extra={"scan_id": scan_id, "delay_s": delay})
        await msg.nak(delay=delay)
        return
    except Exception as exc:
        log.exception("handler raised; treating as permanent", extra={"scan_id": scan_id})
        await _to_dlq(js, msg, f"{type(exc).__name__}: {exc}", delivered)
        await msg.term()
        return

    await msg.ack()


async def _to_dlq(js: Any, msg: Any, reason: str, delivered: int) -> None:
    try:
        await js.publish(
            DLQ_SUBJECT, msg.data,
            headers={
                "Axebom-Dlq-Reason": _sanitize_header(reason),
                "Axebom-Original-Subject": msg.subject,
                "Axebom-Delivery-Count": str(delivered),
            },
        )
    except Exception:
        log.exception("could not write to the DLQ")


def _delivery_count(msg: Any) -> int:
    try:
        return int(msg.metadata.num_delivered)
    except Exception:
        return 1


def _backoff_for(delivered: int) -> int:
    if delivered < 1:
        return BACKOFF_SECONDS[0]
    if delivered > len(BACKOFF_SECONDS):
        return BACKOFF_SECONDS[-1]
    return BACKOFF_SECONDS[delivered - 1]


def _sanitize_header(s: str) -> str:
    s = re.sub(r"[\r\n\x00]", " ", s)
    return s[:512] + "…" if len(s) > 512 else s


def main() -> int:
    cfg = ConsumerConfigEnv.load()
    try:
        asyncio.run(_run(cfg))
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        log.error("normalize consumer exited", extra={"cause": str(exc)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
