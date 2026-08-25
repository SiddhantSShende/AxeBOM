"""The process lifecycle every Python scan worker shares.

Five families run the same loop and differ only in which handler they call, so
the loop lives here rather than being copied five times. A copied loop is where
one worker ends up without signal handling, or acking before publishing, and
nothing catches it because each worker runs fine on its own.

# ⚠ handle() BLOCKS FOR MINUTES, AND THE EVENT LOOP MUST NOT

A scan starts a container and waits on it — up to the sandbox's thirty-minute
wall clock. Calling a synchronous handler directly from the asyncio loop would
freeze it for the whole run: no heartbeats, no second job, and the NATS client
unable to answer pings, so the server eventually decides the client is gone and
redelivers work that is actually in progress.

Handlers are therefore run in a worker thread. That is also why max_ack_pending
is small — the concurrency limit is how many containers this replica can
sensibly run, not how many messages NATS is willing to hand over.

# Preflight runs once, loudly, before any job

A worker that cannot reach Docker should say so once and clearly, rather than
failing every job with the same error for an hour.
"""

from __future__ import annotations

import asyncio
import signal
from collections.abc import Callable
from typing import Any

from .bus import BusConfig, WorkerBus, validate_result
from .config import load_worker_config
from .logging import get_logger

log = get_logger(__name__)

#: A synchronous job handler: takes a ScanJobV1 dict, returns a ScanResultV1.
SyncHandler = Callable[[dict[str, Any]], dict[str, Any]]

#: An optional one-shot readiness check, run before consuming.
Preflight = Callable[[], dict[str, Any]]


async def _serve(
    family: str,
    handler: SyncHandler,
    *,
    nats_url: str,
    max_ack_pending: int,
) -> int:
    bus = WorkerBus(
        BusConfig(
            url=nats_url,
            family=family,
            name=f"axebom-{family}-worker",
            max_ack_pending=max_ack_pending,
        )
    )

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        # Stop CONSUMING, then let the in-flight job finish and ack. Cancelling
        # mid-job would leave the message unacked and the container orphaned;
        # redelivery would then re-run work that had almost completed.
        loop.add_signal_handler(sig, bus.stop)

    await bus.connect()
    try:
        await bus.ensure_consumer()

        async def run_one(job: dict[str, Any]) -> dict[str, Any]:
            # to_thread, not a direct call: see the module docstring.
            result = await asyncio.to_thread(handler, job)

            # Validate against the schema GENERATED FROM THE GO TYPES. This is
            # what catches worker/orchestrator envelope drift, whose only other
            # symptom is a result being silently dropped on the far side.
            problems = validate_result(result)
            if problems:
                log.error(
                    "result does not match scan-result-v1; publishing anyway",
                    extra={
                        "job_id": result.get("job_id"),
                        "problems": problems[:5],
                    },
                )
            return result

        await bus.run(run_one)
    finally:
        await bus.close()

    log.info("worker stopped", extra={"family": family})
    return 0


def run_worker(
    family: str,
    handler: SyncHandler,
    *,
    preflight: Preflight | None = None,
    max_ack_pending: int = 2,
) -> int:
    """Run one family's worker until SIGINT/SIGTERM.

    Returns a process exit code. A preflight failure is exit 1 and no consumer
    is attached — a worker that cannot run engines must not claim jobs it will
    only fail, because a WorkQueue delivers each job to exactly one consumer and
    claiming one hides it from a replica that could have done the work.
    """
    cfg = load_worker_config(f"{family}-worker")

    if preflight is not None:
        try:
            info = preflight()
        except Exception as exc:
            log.error(
                "preflight failed; refusing to consume",
                extra={"family": family, "cause": str(exc)},
            )
            return 1
        log.info("worker preflight ok", extra={"family": family, **_flat(info)})

    try:
        return asyncio.run(
            _serve(
                family,
                handler,
                nats_url=cfg.nats_url,
                max_ack_pending=max_ack_pending,
            )
        )
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        log.error("worker exited", extra={"family": family, "cause": str(exc)})
        return 1


def _flat(info: dict[str, Any]) -> dict[str, Any]:
    """Flatten a preflight dict into log-safe scalars."""
    return {k: v for k, v in info.items() if isinstance(v, str | int | float | bool)}
