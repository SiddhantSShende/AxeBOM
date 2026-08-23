"""AIBOM worker — consumes scan.job.aibom.

Code-level AI discovery: which LLM providers, agent frameworks, MCP servers and
model references a repository actually uses. Reuses the SBOM family's job path;
see workers/cbom/runner.py for why.

⚠ ONLY THE DISCOVERY HALF IS DISPATCHABLE

An AIBOM is two things merged (workers/aibom/merge.py):

    ai-bom           CODE-LEVEL discovery, sandboxed over the source tree.
                     This worker.
    aibom-generator  MODEL-METADATA enrichment — model card, licence,
                     completeness — for a Hugging Face model id.

The second is NOT a scanner and is deliberately not registered here. It makes an
outbound HTTP call and touches no user code, so it cannot run in a sandbox with
--network=none, and running it as a "scan" would misrepresent what it is. It is
enrichment driven by an injected Fetcher, and no concrete Fetcher exists yet —
so model metadata is currently a stated gap rather than a silent omission.
"""

from __future__ import annotations

from encorebom_shared.logging import get_logger
from encorebom_shared.worker_runtime import run_worker

from ..sbom.runner import SBOMWorker
from .adapters import AIBomAdapter

log = get_logger("aibom-worker")

ADAPTERS: dict[str, type] = {
    "ai-bom": AIBomAdapter,
}

DEPENDS_ON: dict[str, str] = {}


def main() -> int:
    worker = SBOMWorker(adapters=ADAPTERS, depends_on=DEPENDS_ON)

    return run_worker(
        "aibom",
        worker.handle,
        preflight=lambda: {**worker.sandbox.check(), "engines": len(ADAPTERS)},
        max_ack_pending=2,
    )


if __name__ == "__main__":
    raise SystemExit(main())
