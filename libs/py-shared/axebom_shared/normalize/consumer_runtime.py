"""The NATS consume loop every normalize consumer shares.

⚠ EXTRACTED FROM workers/sbom/normalize_consumer.py, WHICH KEEPS ITS OWN
CREDENTIAL LOADING. That split is deliberate and worth stating.

What moved here is the LOOP: stream wait, durable attach, pull-subscribe,
per-message dispatch, the retry/DLQ decision, backoff, header sanitisation.
None of it is family-specific, and all of it is the kind of code that rots when
copied — one copy ends up acking before it has written, and each consumer still
passes its own tests.

What did NOT move is `ConsumerConfigEnv`. Its own docstring is explicit that it
is "DELIBERATELY NOT axebom_shared.config.WorkerConfig … a small, separate,
local loader instead — the exception stays visibly contained to the one process
that needs it." `libs/py-shared` sits on EVERY worker's dependency tree, and
moving credential loading here would weaken exactly the containment argument
that makes the normalize consumer's Postgres role an acceptable exception to
"workers hold no credentials". So each consumer keeps its own loader, and the
duplication is the point.

⚠ THE RETRY DEFAULT IS "PERMANENT". Anything other than `Retry` goes straight
to the DLQ, because retrying an unknown failure is a guess and a wrong guess
costs the whole retry budget on something that will never succeed.
"""

from __future__ import annotations

import asyncio
import json
import re
import signal
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import nats
import psycopg
from nats.js.api import ConsumerConfig, DeliverPolicy
from nats.js.errors import NotFoundError

from axebom_shared.logging import get_logger

from . import writer

log = get_logger("normalize-consumer")

STREAM_NORMALIZE = "NORMALIZE_JOBS"

#: Total attempts, matching bus.go's MaxDeliver — three retries after the first.
MAX_DELIVER = 4

#: Seconds. Deliberately SHORTER than the 30-minute sandbox-sized ack_wait
#: every SCAN_JOBS consumer uses — normalization is in-process CPU work, not a
#: container run. Sized for the documented worst case: bulk-inserting hundreds
#: of thousands of findings for one very large monorepo scan.
ACK_WAIT_SECONDS = 15 * 60

#: Redelivery schedule in seconds — the same shape as bus.go's/bus.py's, not
#: the same numbers: a normalization failure is almost always a real bug (a bad
#: artifact, a schema mismatch), not "the node is rolling," so there is little
#: value in waiting minutes between attempts.
BACKOFF_SECONDS = (10, 30, 90)


class Retry(Exception):  # noqa: N818 — a control-flow signal, not an error report
    """Raised to request redelivery with backoff.

    Anything else raised is treated as PERMANENT and goes straight to the DLQ —
    the same default `axebom_shared.bus.Retry` documents, for the same reason.
    """


#: What a family supplies: given an open connection, the decoded trigger and
#: the artifacts root, write one normalization. Raise Retry for transient
#: failure; raise anything else for permanent.
TriggerHandler = Callable[[writer.Connection, dict[str, Any], Path], Awaitable[None]]


async def run_consumer(
    *,
    subject: str,
    dlq_subject: str,
    durable: str,
    handler: TriggerHandler,
    nats_url: str,
    postgres_dsn: str,
    artifacts_root: Path,
    max_ack_pending: int = 4,
) -> None:
    """Consume one normalize subject until interrupted."""
    stopping = asyncio.Event()

    nc = await nats.connect(
        nats_url,
        name=f"axebom-{durable}",
        max_reconnect_attempts=-1,
        reconnect_time_wait=2,
    )
    js = nc.jetstream()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stopping.set)

    await await_stream(js)

    try:
        await js.add_consumer(
            STREAM_NORMALIZE,
            ConsumerConfig(
                durable_name=durable,
                filter_subject=subject,
                ack_wait=ACK_WAIT_SECONDS,
                max_deliver=MAX_DELIVER,
                max_ack_pending=max_ack_pending,
                deliver_policy=DeliverPolicy.ALL,
            ),
        )
    except Exception as exc:
        raise RuntimeError(f"could not attach consumer {durable!r} to {subject!r}: {exc}") from exc

    sub = await js.pull_subscribe(subject, durable=durable, stream=STREAM_NORMALIZE)
    log.info("normalize consumer ready", extra={"subject": subject})

    conn = await asyncio.to_thread(psycopg.connect, postgres_dsn, autocommit=True)
    try:
        while not stopping.is_set():
            try:
                msgs = await sub.fetch(batch=1, timeout=5)
            except TimeoutError:
                continue
            for msg in msgs:
                await dispatch(
                    msg,
                    conn,
                    artifacts_root,
                    js,
                    handler=handler,
                    dlq_subject=dlq_subject,
                )
    finally:
        conn.close()
        await nc.drain()


async def await_stream(js: Any, attempts: int = 30, delay: float = 2.0) -> None:
    """Wait for the stream the Go scan-orchestrator creates on boot.

    ⚠ NEVER CREATES IT. Stream configuration — retention, MaxAge, WorkQueue vs
    limits — is owned on the Go side; a Python worker that created its own
    would race it and win sometimes, producing a stream with the wrong policy
    and no error anywhere.
    """
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


async def dispatch(
    msg: Any,
    conn: writer.Connection,
    artifacts_root: Path,
    js: Any,
    *,
    handler: TriggerHandler,
    dlq_subject: str,
) -> None:
    """Run one trigger, and decide ack / nak / DLQ."""
    delivered = delivery_count(msg)

    try:
        trigger = json.loads(msg.data)
    except json.JSONDecodeError as exc:
        log.error("trigger is not valid JSON; sending to DLQ", extra={"error": str(exc)})
        await to_dlq(js, msg, f"invalid JSON: {exc}", delivered, dlq_subject)
        await msg.term()
        return

    scan_id = str(trigger.get("scan_id", ""))
    try:
        await handler(conn, trigger, artifacts_root)
    except Retry as exc:
        if delivered >= MAX_DELIVER:
            log.error(
                "retries exhausted; sending to DLQ",
                extra={"scan_id": scan_id, "delivered": delivered},
            )
            await to_dlq(js, msg, f"retries exhausted: {exc}", delivered, dlq_subject)
            await msg.ack()
            return
        delay = backoff_for(delivered)
        log.warning(
            "transient failure; redelivering",
            extra={"scan_id": scan_id, "delay_s": delay},
        )
        await msg.nak(delay=delay)
        return
    except Exception as exc:
        log.exception("handler raised; treating as permanent", extra={"scan_id": scan_id})
        await to_dlq(js, msg, f"{type(exc).__name__}: {exc}", delivered, dlq_subject)
        await msg.term()
        return

    await msg.ack()


async def to_dlq(js: Any, msg: Any, reason: str, delivered: int, dlq_subject: str) -> None:
    try:
        await js.publish(
            dlq_subject,
            msg.data,
            headers={
                "Axebom-Dlq-Reason": sanitize_header(reason),
                "Axebom-Original-Subject": msg.subject,
                "Axebom-Delivery-Count": str(delivered),
            },
        )
    except Exception:
        log.exception("could not write to the DLQ")


def delivery_count(msg: Any) -> int:
    try:
        return int(msg.metadata.num_delivered)
    except Exception:
        return 1


def backoff_for(delivered: int) -> int:
    if delivered < 1:
        return BACKOFF_SECONDS[0]
    if delivered > len(BACKOFF_SECONDS):
        return BACKOFF_SECONDS[-1]
    return BACKOFF_SECONDS[delivered - 1]


def sanitize_header(s: str) -> str:
    """NATS headers are line-oriented; a newline in a reason would forge one."""
    s = re.sub(r"[\r\n\x00]", " ", s)
    return s[:512] + "…" if len(s) > 512 else s
