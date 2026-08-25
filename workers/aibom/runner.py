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
enrichment driven by an injected Fetcher.

⚠ A CONCRETE FETCHER NOW EXISTS AND IS TESTED — IT IS STILL NOT LIVE-WIRED.

`workers/aibom/adapters/aibom_generator_fetch.fetch_model_card` is a real,
working `Fetcher` (installs and invokes `owasp-aibom-generator`, verified
against the real Hugging Face API and against a real captured fixture in
`workers/aibom/testdata/`). What it is NOT plugged into is a live scan path,
and that is a deliberate stop rather than an oversight:

`workers/aibom/normalize/pipeline.py::build_canonical_aibom` already takes
`cards: dict[str, ModelCard]` as a parameter — it expects its caller to have
already run `enrich_models(model_refs(...), fetch=...)` — but the only
current caller anywhere in the repo is `normalize/test_pipeline.py`. There is
no AIBOM equivalent of `workers/sbom/normalize_runner.py` (a CLI entry point)
or a NATS-consuming orchestrator that ties discovery -> `model_refs` ->
`enrich_models` -> `build_canonical_aibom` -> the bulk writer together for a
real scan. Building one is a bigger decision than adding a function, because
it has to answer things this module's existing code does not:

  - WHEN does enrichment run relative to the discovery job's lifecycle —
    inside this worker's job handler (giving a sandboxed, network-less
    pipeline a network dependency and an external rate limit inside its wall
    clock budget), or as a separate step triggered after discovery lands?
  - Enrichment's HTTP response is not currently a STORED raw artifact the way
    every scanner's output is (ADR-0003) — a re-normalization pass today would
    re-fetch from Hugging Face rather than replay history, which is a real
    deviation from CLAUDE.md invariant 10 ("normalization is a pure function
    of raw artifacts... re-run a normalizer bug fix by re-normalizing, never
    re-scanning"). Does live-wiring this need aibom-generator's raw response
    written immutably first, the way engine adapters write theirs?
  - How should a Hugging Face timeout or rate limit during that step interact
    with `axebom_shared.worker_runtime.run_worker`'s redelivery/ack model?

None of those have an existing answer to copy from another BOM family, so
this worker still only dispatches `ai-bom` discovery. Model metadata is a
stated gap in Engine Coverage, not a silent omission — and now, unlike before,
the enrichment half is one real integration decision away rather than a
missing Fetcher away.
"""

from __future__ import annotations

from axebom_shared.logging import get_logger
from axebom_shared.worker_runtime import run_worker

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
