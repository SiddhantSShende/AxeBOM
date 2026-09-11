"""CBOM worker — consumes scan.job.cbom.

Cryptographic discovery. Reuses the SBOM family's job path rather than copying
it: idempotency check first, unknown-engine handling, envelope construction,
artifact persistence, manifest written last. That sequence is identical for
every family and is exactly the kind of thing that rots when duplicated — one
copy ends up acking before it has stored its evidence, and each worker still
passes its own tests.

Only the engine map differs.

⚠ WHAT THIS WORKER DOES NOT DO

It discovers crypto assets and stores the raw CycloneDX. Turning those into
CERT-In Table 9 rows is the normalizer's job (workers/cbom/normalize/crypto.py),
and that scoring is TYPE-DISCRIMINATED — algorithms, keys, protocols and
certificates have different field sets. Scoring a certificate against `key_size`
reports every CBOM at roughly 30% coverage, falsely, in a compliance document.
"""

from __future__ import annotations

from axebom_shared.logging import get_logger
from axebom_shared.worker_runtime import run_worker

from ..sbom.runner import SBOMWorker
from .adapters import CBOMkitActionAdapter, CBOMkitTheiaAdapter, CdxgenCBOMAdapter

log = get_logger("cbom-worker")

#: The CBOM engines this worker runs, and what each one reads:
#:
#:   cbomkit-theia   key, certificate, secret and crypto-config FILES
#:   cbomkit-action  crypto API use in Java and Python SOURCE (sonar-cryptography
#:                   rules, embedded — no SonarQube server)
#:   cdxgen-cbom     crypto API use in JavaScript/TypeScript source
#:
#: `cbomkit` is a clone-and-scan SERVICE that needs network and credentials, and
#: stays registered-but-Disabled with that reason; the orchestrator's
#: adapter_parity_test fails if a dispatchable engine is missing from this map.
ADAPTERS: dict[str, type] = {
    "cbomkit-theia": CBOMkitTheiaAdapter,
    "cbomkit-action": CBOMkitActionAdapter,
    "cdxgen-cbom": CdxgenCBOMAdapter,
}

#: No engine here depends on another's output.
DEPENDS_ON: dict[str, str] = {}


def main() -> int:
    worker = SBOMWorker(adapters=ADAPTERS, depends_on=DEPENDS_ON)

    return run_worker(
        "cbom",
        worker.handle,
        preflight=lambda: {**worker.sandbox.check(), "engines": len(ADAPTERS)},
        max_ack_pending=2,
    )


if __name__ == "__main__":
    raise SystemExit(main())
