"""HBOM worker — consumes scan.job.hbom.

⚠ THIS WORKER DID NOT EXIST, AND ITS ABSENCE WAS DELIBERATE UNTIL NOW.

HBOM was import-only: a CSV or a form, with no scan behind it, so a runner
would have had nothing to consume. `hbom-ecad` changed that — it parses the
customer's own hardware design files out of an upload or a connected
repository, which is a real scan producing real jobs.

⚠ WHAT DID NOT CHANGE IS THE HONEST LABEL. Neither engine here inspects a
physical device. One reads a schematic the customer committed; the other reads
a CycloneDX inventory the customer generated on their own machine. There is
still no open-source tool that enumerates the parts of a device by looking at
it, and nothing in this package says otherwise.

Reuses SBOMWorker's job path rather than copying it — idempotency check first,
unknown-engine handling, envelope construction, artifact persistence, manifest
written last. That sequence is identical for every family and is exactly what
rots when duplicated: one copy ends up acking before it has stored its
evidence, and each worker still passes its own tests. Only the engine map
differs, the same arrangement workers/cbom and workers/aibom already use.

⚠ WHAT THIS WORKER DOES NOT DO

It parses and stores the raw document. Turning that into
`normalize.hardware_components` rows, scoring them against CERT-In Table 11
plus §10.4.1.4, and scoring them SEPARATELY against the manufacturing profile,
is the normalizer's job — see `workers/hbom/normalize.py` and
`workers/hbom/normalize_consumer.py`.
"""

from __future__ import annotations

# ⚠ ABSOLUTE, FOR THE SAME REASON THE ADAPTERS ARE — see ecad.py's import.
# `workers` is a namespace package, so a relative import that crosses out of
# `workers.hbom` resolves at runtime and fails under pytest collection.
#
# workers/cbom/runner.py and workers/aibom/runner.py carry the identical
# `from ..sbom.runner import SBOMWorker` and have the same latent problem; it
# has never surfaced there because no test imports either module. Left alone
# rather than changed unasked — recorded in docs/STATE.md.
from workers.sbom.runner import SBOMWorker

from axebom_shared.logging import get_logger
from axebom_shared.worker_runtime import run_worker

from .adapters import CdxgenHostHBOMAdapter, ECADAdapter, HostReportAdapter

log = get_logger("hbom-worker")

#: The dispatchable HBOM engines.
#:
#: ⚠ `hbom-csv` IS ABSENT ON PURPOSE, AND IT IS NOT A GAP. It names the
#: interactive REST path (POST /v1/hbom/preview, then
#: /v1/hbom/{projectId}/import), not a job — which is why it declares no
#: source kind in the Go registry and can never be selected by fan-out. An
#: entry here would be an adapter nothing ever calls.
#:
#: `hbom-form` is likewise not here: a form submission is not a scan.
ADAPTERS: dict[str, type] = {
    "hbom-ecad": ECADAdapter,
    "hbom-cdxgen-host": CdxgenHostHBOMAdapter,
    "hbom-host-report": HostReportAdapter,
}

#: No engine here consumes another's output.
DEPENDS_ON: dict[str, str] = {}


def main() -> int:
    worker = SBOMWorker(adapters=ADAPTERS, depends_on=DEPENDS_ON)

    return run_worker(
        "hbom",
        worker.handle,
        # ⚠ NO worker.sandbox.check(), UNLIKE sbom/cbom/aibom.
        #
        # Both adapters are pure parsing with no container, so refusing to
        # attach a consumer because the Docker daemon happens to be down would
        # strand work that never needed Docker. Sandbox.__init__ only locates a
        # binary path, so constructing SBOMWorker probes nothing.
        preflight=lambda: {"engines": len(ADAPTERS)},
        # Higher than sbom/cbom's 2: that limit bounds concurrent CONTAINERS,
        # and this worker starts none. Each job is seconds of parsing.
        max_ack_pending=4,
    )


if __name__ == "__main__":
    raise SystemExit(main())
