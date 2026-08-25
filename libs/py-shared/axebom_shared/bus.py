"""JetStream consumer loop for the Python scan workers.

# What this is, and what it deliberately is not

The topology is owned by ``libs/go-shared/bus/bus.go``, which implements
``docs/02-CONTRACTS.md`` §2. That document is the SSOT and this module does not
restate it: **nothing here creates or configures a stream.** Streams are created
by the Go services on boot, and a second definition in a second language is
exactly the drift CLAUDE.md warns about — the two would diverge, and the symptom
would be a retention or ack-wait setting that depends on which process started
first.

What this module does own is the *worker* side: attach a durable pull consumer
to a stream someone else created, run a handler over it, and decide each
message's fate.

# The three fates, and why the middle one is not the default

    ack        the work is done, remove it from the queue
    retry      transient — nak with the contract's backoff
    terminate  permanent — copy to the DLQ, do NOT burn the retry budget

Terminating on a permanent error is the half that is easy to get wrong. A job
whose engine id does not exist will never succeed; naking it four times costs
three container starts and ten minutes of backoff before failing anyway, and it
delays every job queued behind it.

# ⚠ NakWithDelay, never a bare Nak

A bare ``nak()`` redelivers immediately. The consumer's ``backoff`` governs
ack-wait *expiry* — a worker that died silently — not an explicit nak. Without a
delay a failing job spins as fast as the loop can turn and burns all four
delivery attempts in milliseconds, before whatever it is waiting on has had time
to blink. The Go side hit exactly this and records it in ``bus.go``.

# ⚠ One durable per filter subject on a WorkQueue stream

NATS refuses a second with *"filtered consumer not unique on workqueue stream"*.
That is correct for a work queue and it dictates the deployment shape: every
worker replica for a family shares ONE durable name and NATS distributes
messages between them. Giving each replica its own durable is rejected at
startup, which is the right place for that failure to appear.

# Idempotency is not optional

``ack_wait`` is thirty minutes, sized for a sandboxed container, and a worker can
be killed at any point. Redelivery is therefore normal, not exceptional. Every
handler must be safe to run twice — the SBOM worker HEADs its output manifest
first and re-emits the stored result rather than re-running the engine.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import nats
from nats.js import JetStreamContext
from nats.js.api import ConsumerConfig, DeliverPolicy
from nats.js.errors import NotFoundError

from .logging import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Contract constants
#
# These MIRROR libs/go-shared/bus/bus.go. They are duplicated because the two
# runtimes cannot share a constant, and duplication without a guard is how the
# two silently diverge — so test_bus.py parses bus.go and asserts they match.
# Change them there first.
# ---------------------------------------------------------------------------

STREAM_JOBS = "SCAN_JOBS"
STREAM_RESULTS = "SCAN_RESULTS"
STREAM_DLQ = "SCAN_DLQ"

#: Total attempts, so three retries after the first.
MAX_DELIVER = 4

#: Seconds. Matches the sandbox wall-clock ceiling.
ACK_WAIT_SECONDS = 30 * 60

#: Redelivery schedule in seconds: a restarting worker, a node rolling, a
#: dependency being redeployed. Deliberately not exponential-with-jitter —
#: these are minutes-long container jobs, not HTTP calls.
BACKOFF_SECONDS = (30, 120, 480)

#: Families with a worker. Mirrors events.AllFamilies() on the Go side, minus
#: `fetch`, which is the orchestrator's own.
WORKER_FAMILIES = ("sbom", "cbom", "aibom", "qbom", "hbom")


class Retry(Exception):  # noqa: N818 — a control-flow signal, not an error report
    """Raised by a handler to request redelivery with backoff.

    Anything else a handler raises is treated as PERMANENT and goes straight to
    the DLQ. That default is deliberate: retrying an unknown failure is a guess,
    and a wrong guess costs the whole retry budget plus the queue behind it.
    """


def job_subject(family: str) -> str:
    return f"scan.job.{family}"


def result_subject(family: str) -> str:
    return f"scan.result.{family}"


def dlq_subject(family: str) -> str:
    return f"scan.dlq.{family}"


def durable_name(family: str) -> str:
    """The one durable every replica of a family shares.

    Distinct from the Go mock's ``mock-engine`` on the same subject: two
    durables cannot both filter ``scan.job.sbom`` on a WorkQueue stream, so the
    mock and a real worker are mutually exclusive by construction. That is
    intended — running both would mean two things claiming the same jobs.
    """
    return f"worker-{family}"


#: Handler signature. Takes the decoded job, returns the result envelope.
JobHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


@dataclass
class BusConfig:
    url: str
    family: str
    name: str = "axebom-worker"
    #: How many messages this replica may hold unacked. The concurrency limit:
    #: a worker that can run one container must not be handed fifty jobs.
    max_ack_pending: int = 4
    #: Bounds the initial connection, in seconds.
    connect_timeout: int = 10


class WorkerBus:
    """Consumes scan jobs for one family and publishes results."""

    def __init__(self, cfg: BusConfig) -> None:
        self._cfg = cfg
        self._nc: Any = None
        self._js: JetStreamContext | None = None
        self._stopping = asyncio.Event()

    def _jetstream(self) -> JetStreamContext:
        """The JetStream handle, or a clear error.

        Not an assert: asserts are stripped under -O, and this one would then
        become an AttributeError on None deep inside a running worker — the
        same trap the Go side records in its own nil-check.
        """
        if self._js is None:
            raise RuntimeError("bus: connect() must be called before use")
        return self._js

    async def connect(self) -> None:
        # Reconnect forever. A bus outage must degrade into delayed jobs, never
        # into a worker that gave up and needs restarting by hand.
        self._nc = await nats.connect(
            self._cfg.url,
            name=self._cfg.name,
            connect_timeout=self._cfg.connect_timeout,
            max_reconnect_attempts=-1,
            reconnect_time_wait=2,
        )
        self._js = self._nc.jetstream()
        log.info("bus connected", extra={"url": self._cfg.url, "family": self._cfg.family})

    async def close(self) -> None:
        if self._nc is not None:
            # Drain, not close: let in-flight publishes finish, which matters on
            # a rolling deploy.
            await self._nc.drain()
            self._nc = None

    def stop(self) -> None:
        self._stopping.set()

    async def ensure_consumer(self) -> None:
        """Attach the durable pull consumer.

        The STREAM must already exist — a Go service creates it on boot. If it
        does not, this waits rather than creating one: a stream created here
        would carry this module's guesses about retention and storage instead of
        the contract's, and the first process to start would silently define the
        topology for everyone.
        """
        js = self._jetstream()
        family = self._cfg.family

        await self._await_stream()

        try:
            await js.add_consumer(
                STREAM_JOBS,
                ConsumerConfig(
                    durable_name=durable_name(family),
                    filter_subject=job_subject(family),
                    ack_wait=ACK_WAIT_SECONDS,
                    max_deliver=MAX_DELIVER,
                    # ⚠ NO CONSUMER-LEVEL `backoff`, DELIBERATELY.
                    #
                    # nats-server OVERRIDES AckWait with backoff[0] when a
                    # backoff list is set. Measured on this stack: a consumer
                    # configured ack_wait=30m + backoff=[30s,2m,8m] reports
                    #
                    #     Ack Wait: 30.00s
                    #
                    # while the same consumer without backoff reports 30m0s.
                    #
                    # A 30-second ack window is catastrophic for a SCAN JOB.
                    # Scans are minutes of container, so every job would be
                    # redelivered while the first worker was still running it:
                    # duplicate containers for the same job, and after four
                    # deliveries a DLQ entry for work that was succeeding.
                    # Idempotency does not save it either — the manifest is
                    # written LAST, precisely so a crash mid-run does not look
                    # complete, so a redelivery at 30s finds no manifest and
                    # starts the engine again.
                    #
                    # Nothing is lost by omitting it. BACKOFF_SECONDS is still
                    # the schedule, applied explicitly in _dispatch via
                    # nak(delay=...), which is the path that actually matters —
                    # a handler reporting a transient failure. The consumer-level
                    # setting only governed ack-wait expiry, and buying that at
                    # the cost of the ack window is a bad trade.
                    #
                    # The Go side has the same latent issue on any future job
                    # consumer; see docs/STATE.md.
                    max_ack_pending=self._cfg.max_ack_pending,
                    # A worker starting fresh must pick up work already queued,
                    # not only what arrives after it connects.
                    deliver_policy=DeliverPolicy.ALL,
                ),
            )
        except Exception as exc:
            # The most likely cause is worth naming, because the NATS message
            # ("filtered consumer not unique on workqueue stream") is accurate
            # and says nothing about what to do.
            raise RuntimeError(
                f"could not attach consumer {durable_name(family)!r} to "
                f"{job_subject(family)!r}: {exc}. A WorkQueue stream permits ONE "
                f"consumer per filter subject — check whether the Go mock engine "
                f"or a previous fleet still holds it"
            ) from exc

        log.info(
            "consumer ready",
            extra={
                "durable": durable_name(family),
                "subject": job_subject(family),
                "max_ack_pending": self._cfg.max_ack_pending,
            },
        )

    async def _await_stream(self, attempts: int = 30, delay: float = 2.0) -> None:
        """Wait for the Go side to declare the stream.

        Workers and services start together under compose, so losing the race is
        ordinary rather than exceptional. Failing immediately would make startup
        order significant, and `restart: unless-stopped` would paper over it with
        a crash loop that looks like a real fault.
        """
        js = self._jetstream()
        for attempt in range(1, attempts + 1):
            try:
                await js.stream_info(STREAM_JOBS)
                return
            except NotFoundError:
                if attempt == attempts:
                    raise RuntimeError(
                        f"stream {STREAM_JOBS} does not exist after {attempts} attempts. "
                        f"It is created by the Go services on boot; this worker does not "
                        f"create it, so that the topology has exactly one definition"
                    ) from None
                log.info(
                    "waiting for stream",
                    extra={"stream": STREAM_JOBS, "attempt": attempt},
                )
                await asyncio.sleep(delay)

    async def run(self, handler: JobHandler) -> None:
        """Pull jobs and run the handler until stop() is called."""
        js = self._jetstream()
        family = self._cfg.family

        sub = await js.pull_subscribe(
            job_subject(family),
            durable=durable_name(family),
            stream=STREAM_JOBS,
        )

        log.info("worker consuming", extra={"family": family})

        consecutive_failures = 0

        while not self._stopping.is_set():
            try:
                msgs = await sub.fetch(batch=1, timeout=5)
            except TimeoutError:
                # An idle queue is the normal case, not a problem.
                consecutive_failures = 0
                continue
            except Exception:
                # ⚠ RE-ESTABLISH, DO NOT MERELY RETRY.
                #
                # A durable consumer can vanish underneath a running worker — an
                # operator retiring a fleet, or an integration test claiming the
                # subject. Retrying fetch() against a subscription whose consumer
                # no longer exists fails forever, and the worker looks perfectly
                # healthy throughout: the process is up, the log says
                # "consuming", and not one job is ever handled.
                #
                # Observed exactly that: a test run deleted worker-sbom's
                # consumer and the worker sat dead until restarted by hand.
                consecutive_failures += 1
                log.exception(
                    "fetch failed",
                    extra={"family": family, "consecutive": consecutive_failures},
                )
                if consecutive_failures >= 3:
                    log.warning(
                        "re-establishing the consumer after repeated failures",
                        extra={"family": family},
                    )
                    try:
                        await self.ensure_consumer()
                        sub = await js.pull_subscribe(
                            job_subject(family),
                            durable=durable_name(family),
                            stream=STREAM_JOBS,
                        )
                        consecutive_failures = 0
                    except Exception:
                        log.exception("could not re-establish", extra={"family": family})
                await asyncio.sleep(2)
                continue

            consecutive_failures = 0
            for msg in msgs:
                await self._dispatch(msg, handler)

    async def _dispatch(self, msg: Any, handler: JobHandler) -> None:
        """Run one message through the handler and decide its fate."""
        delivered = _delivery_count(msg)

        try:
            job = json.loads(msg.data)
        except json.JSONDecodeError as exc:
            # Unparseable will never become parseable. Terminate immediately
            # rather than retrying a message that cannot succeed.
            log.error("job is not valid JSON; sending to DLQ", extra={"error": str(exc)})
            await self._to_dlq(msg, f"invalid JSON: {exc}", delivered)
            await msg.term()
            return

        job_id = str(job.get("job_id", ""))

        try:
            result = await handler(job)

        except Retry as exc:
            if delivered >= MAX_DELIVER:
                # Out of attempts. Route to the DLQ rather than letting the
                # message expire silently: a poison message that vanishes is a
                # production failure with no artifact to diagnose it from.
                log.error(
                    "retries exhausted; sending to DLQ",
                    extra={"job_id": job_id, "delivered": delivered},
                )
                await self._to_dlq(msg, f"retries exhausted: {exc}", delivered)
                await msg.ack()
                return

            delay = _backoff_for(delivered)
            log.warning(
                "transient failure; redelivering",
                extra={"job_id": job_id, "delivered": delivered, "delay_s": delay},
            )
            await msg.nak(delay=delay)
            return

        except Exception as exc:
            log.exception("handler raised; treating as permanent", extra={"job_id": job_id})
            await self._to_dlq(msg, f"{type(exc).__name__}: {exc}", delivered)
            await msg.term()
            return

        # Publish the result BEFORE acking. Acking first and then failing to
        # publish loses the result with no redelivery to recover it — the job is
        # gone from the queue and the orchestrator never hears an outcome.
        try:
            await self.publish_result(result)
        except Exception:
            log.exception(
                "could not publish result; leaving the job unacked", extra={"job_id": job_id}
            )
            await msg.nak(delay=_backoff_for(delivered))
            return

        await msg.ack()
        log.info(
            "job complete",
            extra={"job_id": job_id, "engine": job.get("engine"), "status": result.get("status")},
        )

    async def publish_result(self, result: dict[str, Any]) -> None:
        """Publish a ScanResultV1 to scan.result.<family>.

        The Nats-Msg-Id is the job id, so a worker that crashes between
        publishing and acking republishes harmlessly: JetStream deduplicates
        within its window. Without it, a redelivered job double-counts
        everything downstream.
        """
        js = self._jetstream()
        job_id = str(result.get("job_id", ""))
        payload = json.dumps(result, separators=(",", ":")).encode("utf-8")

        await js.publish(
            result_subject(self._cfg.family),
            payload,
            headers={"Nats-Msg-Id": job_id} if job_id else None,
        )

    async def _to_dlq(self, msg: Any, reason: str, delivered: int) -> None:
        """Copy a poison message to the dead-letter stream with its cause.

        Best effort. If this fails there is nothing further to do, and raising
        would turn a diagnosis aid into an outage.
        """
        js = self._jetstream()
        try:
            await js.publish(
                dlq_subject(self._cfg.family),
                msg.data,
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
        # Unknown delivery count: assume the first attempt. Guessing high would
        # send a first-attempt failure straight to the DLQ.
        return 1


def _backoff_for(delivered: int) -> int:
    """Delay before the next attempt, matching the consumer's own schedule.

    Both redelivery routes — an explicit nak and an ack-wait expiry — must use
    the same schedule, or observed behaviour depends on how the worker happened
    to fail.
    """
    if delivered < 1:
        return BACKOFF_SECONDS[0]
    if delivered > len(BACKOFF_SECONDS):
        return BACKOFF_SECONDS[-1]
    return BACKOFF_SECONDS[delivered - 1]


def _sanitize_header(s: str) -> str:
    """Bound a header value and strip what would break framing.

    Error text is attacker-influenced — it can carry a component name from a
    scanned repository — and NATS headers are not a place for unbounded strings
    or embedded newlines.
    """
    s = re.sub(r"[\r\n\x00]", " ", s)
    return s[:512] + "…" if len(s) > 512 else s


# ---------------------------------------------------------------------------
# Envelope validation
# ---------------------------------------------------------------------------


def _schema_path(name: str) -> Path | None:
    here = Path(__file__).resolve()
    for candidate in here.parents:
        p = candidate / "proto" / "schemas" / name
        if p.is_file():
            return p
    return None


def validate_result(result: dict[str, Any]) -> list[str]:
    """Check a result against the published envelope schema.

    The schema is GENERATED FROM THE GO TYPES, so this is what catches the
    worker and the orchestrator drifting apart at the envelope — a drift whose
    only other symptom is a result being silently dropped on the far side.

    Returns a list of problems; empty means valid. Returns empty when jsonschema
    or the schema file is unavailable, because a missing dev dependency must not
    stop a worker from doing its job.
    """
    path = _schema_path("scan-result-v1.schema.json")
    if path is None:
        return []
    try:
        import jsonschema
    except ImportError:
        return []

    schema = json.loads(path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    return [
        f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
        for e in validator.iter_errors(result)
    ]
