"""`aibom-generator` — Hugging Face model enrichment, outside the sandbox.

⚠ THIS IS THE ONLY COMPONENT IN THE AI PATH WITH OUTBOUND NETWORK, AND IT NEVER
SEES CUSTOMER SOURCE. It is handed model IDENTIFIERS — `meta-llama/Llama-3-8B` —
and asks a public API about them. That is why it may hold network at all, and it
is the same reasoning that makes the fetcher the only holder of git credentials
(ADR-0008): the component that runs third-party scanners over untrusted code holds
nothing, and the component that holds something runs no scanner.

Splitting it out of `workers/aibom` also keeps `owasp-aibom-generator` out of the
image that processes customer repositories — see the HF_TOKEN warning below for
why that specific package is one you want contained.

⚠ IT CONSUMES `scan.job.aibom.enrich`, NOT `scan.job.aibom`.
`workers/aibom`'s consumer filters on the exact three-token subject, which does
not match a four-token one — verified against the live server, not assumed. Both
consumers therefore coexist on the same WorkQueue stream with non-overlapping
filters. It REPORTS on `scan.result.aibom`, because `aibom-generator` is an AIBOM
engine and belongs in that family's Engine Coverage.

⚠ ITS FAILURE IS NEVER A FAILED SCAN. A Hugging Face timeout, a rate limit, or a
model that does not resolve degrades this engine to `partial` with a diagnostic —
Table 10's enrichment-only elements stay `not-provided`, which is a true statement
about what we could learn. Phase 12 says so explicitly, and CLAUDE.md invariant 12
makes it visible in Engine Coverage rather than silent in a coverage percentage.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from axebom_shared.adapters.base import ResultStatus
from axebom_shared.logging import get_logger
from axebom_shared.worker_runtime import run_worker

from ..aibom.adapters.ai_bom import extract_discovery
from ..aibom.adapters.aibom_generator import parse_model_card
from ..aibom.merge import lookup_plan
from .cache import CardCache

log = get_logger(__name__)

ENGINE_ID = "aibom-generator"
FAMILY = "aibom"

#: The subject this worker consumes. Four tokens, so the AIBOM worker's exact
#: `scan.job.aibom` filter never receives it.
JOB_SUBJECT = "scan.job.aibom.enrich"
DLQ_SUBJECT = "scan.dlq.aibom.enrich"
DURABLE = "worker-aibom-enrich"

#: Where `workers/aibom` publishes ai-bom's output for this worker to read — the
#: same per-scan workspace handoff grype uses to read syft's SBOM, rather than a
#: second copy of the artifact travelling through the job envelope.
DISCOVERY_ARTIFACT = "ai-bom.cdx.json"

#: The artifact this engine writes: model reference -> the raw response.
ARTIFACT_NAME = "aibom-generator.json"


@dataclass
class EnrichmentOutcome:
    """What one enrichment run learned, and what it could not."""

    cards: dict[str, Any]
    diagnostics: list[dict[str, Any]]
    cache_hits: int
    cache_misses: int
    attempted: int

    #: Models discovery found that this engine did not even ask about, with the
    #: reason for each. Never empty-and-silent: see `status`.
    declined: int = 0
    #: Discovery's output was not in the workspace at all, so this run could not
    #: begin. Distinct from "there was nothing to enrich" and reported as such.
    input_missing: bool = False

    @property
    def status(self) -> ResultStatus:
        # ⚠ NOTHING TO ENRICH IS A SUCCESS, NOT A PARTIAL. A repository that uses
        # no resolvable model is the common case, and reporting it as a degraded
        # run would train a reader to ignore the status that matters.
        #
        # ⚠ BUT A MODEL WE DECLINED TO LOOK UP IS NOT "NOTHING TO ENRICH".
        #
        # Observed live before this branch existed: a scan of a repository using
        # `distilbert-base-uncased` reported `aibom-generator: succeeded` with
        # zero components and zero diagnostics. The reference had been dropped by
        # a shape rule and nothing said so, so Engine Coverage — the section whose
        # whole job is stating what a report could not see — showed a clean run
        # over a model that was never asked about. `partial` is a first-class
        # status precisely for this (invariant 12).
        if self.input_missing:
            return ResultStatus.PARTIAL
        if self.attempted == 0:
            return ResultStatus.PARTIAL if self.declined else ResultStatus.SUCCEEDED
        if not self.cards or self.declined:
            return ResultStatus.PARTIAL
        return ResultStatus.PARTIAL if len(self.cards) < self.attempted else ResultStatus.SUCCEEDED


def assert_no_telemetry_token() -> None:
    """⚠ `HF_TOKEN` MUST NOT BE SET IN THIS PROCESS, AND THIS IS WHY.

    `owasp-aibom-generator` (`src/utils/analytics.py`) calls `push_to_hub` against
    a HARDCODED third-party dataset — `owasp-genai-security-project/aisbom-usage-log`
    in its own `src/config.py` — sending `{timestamp, "generated", model_id}` for
    every model it is asked about. It returns early only when the token is absent.

    So the obvious operational fix for Hugging Face's anonymous rate limit — set a
    token — silently publishes the name of every AI model in every customer
    repository AxeBOM scans to a public third-party dataset. Read out of the
    package's own source, not inferred.

    Anonymous access works for public models. If a token ever becomes necessary
    (private models, or rate limits that actually bite), it must arrive together
    with an egress policy that denies the upload path — not on its own.
    """
    if os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN"):
        raise RuntimeError(
            "HF_TOKEN is set in the enrichment worker. owasp-aibom-generator pushes "
            "every model id it is asked about to a hardcoded third-party Hugging Face "
            "dataset whenever a token is present, so this would publish the name of "
            "every AI model in every customer repository AxeBOM scans. Unset it, or "
            "add an egress policy that denies the upload before setting it."
        )


def load_discovery(workspace: Path) -> dict[str, Any] | None:
    """ai-bom's output, as the AIBOM worker staged it for us."""
    path = workspace / DISCOVERY_ARTIFACT
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        log.warning("discovery artifact unreadable", extra={"path": str(path), "cause": str(exc)})
        return None
    return payload if isinstance(payload, dict) else None


def enrich(
    refs: list[str],
    *,
    fetch: Any,
    cache: CardCache,
    revision: str = "",
) -> EnrichmentOutcome:
    """Resolve every model reference, cache-first.

    ⚠ ONE FAILURE NEVER LOSES THE OTHERS. Each lookup is isolated: a model that
    404s, rate-limits or times out degrades that model to `not-provided` and the
    rest still enrich. `aibom_generator.enrich_models` already takes this stance
    for the same reason; this is the same rule one layer out, where the network is.
    """
    cards: dict[str, Any] = {}
    diagnostics: list[dict[str, Any]] = []
    hits = misses = 0

    for ref in refs:
        cached = cache.get(ref, revision)
        if cached is not None:
            cards[ref] = cached
            hits += 1
            continue

        misses += 1
        try:
            raw = fetch(ref, revision)
        except Exception as exc:
            diagnostics.append(
                {
                    "severity": "warn",
                    "code": "ENGINE_PARTIAL_ECOSYSTEM",
                    "ecosystem": "huggingface",
                    "message": (
                        f"{ref} could not be enriched ({type(exc).__name__}); its "
                        f"enrichment-only Table 10 elements stay not-provided"
                    ),
                }
            )
            continue

        cards[ref] = raw
        try:
            cache.put(ref, revision, raw)
        except OSError as exc:
            # An uncacheable result is still a correct result.
            log.warning("could not cache a model card", extra={"ref": ref, "cause": str(exc)})

    return EnrichmentOutcome(
        cards=cards,
        diagnostics=diagnostics,
        cache_hits=hits,
        cache_misses=misses,
        attempted=len(refs),
    )


def declined_diagnostics(declined: list[dict[str, str]]) -> list[dict[str, Any]]:
    """One diagnostic per model this engine deliberately did not look up."""
    return [
        {
            "severity": "info",
            "code": "AIBOM_ENRICHMENT_NOT_ATTEMPTED",
            "ecosystem": "huggingface",
            "message": (
                f"{entry['ref']} was not looked up: {entry['reason']}; its "
                f"enrichment-only Table 10 elements stay not-provided"
            ),
        }
        for entry in declined
    ]


@dataclass
class EnrichmentWorker:
    """Handles one `scan.job.aibom.enrich` message."""

    workspace_root: Path
    output_root: Path
    cache: CardCache
    fetch: Any

    def handle(self, job: dict[str, Any]) -> dict[str, Any]:
        """Never raises: a crash here would redeliver the job four times and then
        dead-letter it, when the honest answer is an engine run that says what it
        could not do."""
        job_id = str(job.get("job_id") or "")
        scan_id = str(job.get("scan_id") or "")
        tenant_id = str(job.get("tenant_id") or "")

        # ⚠ A STRUCTURALLY INVALID JOB DEAD-LETTERS; IT DOES NOT BECOME A RESULT.
        #
        # Publishing a ScanResultV1 with an empty scan_id would put a phantom
        # `aibom-generator` engine run on the results stream for a scan that does
        # not exist — the orchestrator would reject it, and the only trace would
        # be a warning about a result nobody sent. Raising here is what routes it
        # to `scan.dlq.aibom.enrich` with the message intact, which is where
        # something malformed belongs.
        #
        # Observed for real: a leftover probe message on this subject was consumed
        # on first start and reported `succeeded` with no job and no scan.
        if not job_id or not scan_id or not tenant_id:
            raise ValueError(
                "enrichment job is missing job_id, scan_id or tenant_id; "
                f"got job_id={job_id!r} scan_id={scan_id!r} tenant_id={tenant_id!r}"
            )

        started = datetime.now(UTC)

        try:
            outcome, artifacts = self._run(scan_id, job_id)
        except Exception as exc:
            log.exception("enrichment failed", extra={"scan_id": scan_id, "job_id": job_id})
            return self._result(
                job_id,
                scan_id,
                tenant_id,
                started,
                ResultStatus.FAILED,
                [],
                [
                    {
                        "severity": "error",
                        "code": "ADAPTER_EXCEPTION",
                        "message": f"enrichment raised {type(exc).__name__}",
                    }
                ],
                models=0,
            )

        return self._result(
            job_id,
            scan_id,
            tenant_id,
            started,
            outcome.status,
            artifacts,
            outcome.diagnostics,
            models=len(outcome.cards),
        )

    def _run(self, scan_id: str, job_id: str) -> tuple[EnrichmentOutcome, list[dict[str, Any]]]:
        discovery_doc = load_discovery(self.workspace_root / scan_id)
        if discovery_doc is None:
            return (
                EnrichmentOutcome(
                    cards={},
                    diagnostics=[
                        {
                            "severity": "warn",
                            "code": "ENGINE_INPUT_MISSING",
                            "message": (
                                f"{ENGINE_ID} reads ai-bom's discovery output, which is "
                                f"not present in this scan's workspace"
                            ),
                        }
                    ],
                    cache_hits=0,
                    cache_misses=0,
                    attempted=0,
                    input_missing=True,
                ),
                [],
            )

        discovery = extract_discovery(discovery_doc)
        refs, declined = lookup_plan(discovery["models"])
        outcome = enrich(refs, fetch=self.fetch, cache=self.cache)
        outcome.declined = len(declined)
        outcome.diagnostics.extend(declined_diagnostics(declined))
        # ⚠ THE PARSER'S OWN REFUSALS TRAVEL WITH THE RUN. A card that resolved
        # but whose licence or training datasets were rejected as a prose scrape
        # (see `aibom_generator._resolved_datasets`) leaves elements
        # `not-provided`; without this the report would attribute that gap to the
        # publisher rather than to what we declined to believe.
        for ref, raw in outcome.cards.items():
            for note in parse_model_card(ref, "", raw).notes:
                outcome.diagnostics.append(
                    {
                        "severity": "info",
                        "code": "AIBOM_ENRICHMENT_VALUE_REJECTED",
                        "message": note,
                    }
                )

        artifacts: list[dict[str, Any]] = []
        if outcome.cards:
            artifacts.append(self._write_artifact(job_id, outcome.cards))

        log.info(
            "enrichment complete",
            extra={
                "scan_id": scan_id,
                "attempted": outcome.attempted,
                "enriched": len(outcome.cards),
                "cache_hits": outcome.cache_hits,
                "cache_misses": outcome.cache_misses,
            },
        )
        return outcome, artifacts

    def _write_artifact(self, job_id: str, cards: dict[str, Any]) -> dict[str, Any]:
        """The immutable raw artifact a re-normalization replays instead of re-fetching.

        ⚠ THIS IS WHAT MAKES ENRICHMENT REPLAYABLE (ADR-0003, invariant 10). The
        cache is an optimisation and may be empty; this file is the record of what
        Hugging Face actually said during THIS scan, and it is never rewritten.
        """
        import hashlib

        directory = self.output_root / job_id
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / ARTIFACT_NAME
        body = json.dumps(cards, sort_keys=True, indent=2).encode("utf-8")
        path.write_bytes(body)

        return {
            "role": "native_output",
            "uri": str(path),
            # ⚠ NOT CycloneDX. This file is a MAP of model reference to that
            # model's two upstream responses (see `aibom_generator_fetch`), not a
            # CycloneDX document — declaring otherwise would send a reader, or a
            # future importer, to a parser that cannot read it.
            "media_type": "application/json",
            "sha256": hashlib.sha256(body).hexdigest(),
            "size_bytes": len(body),
        }

    def _result(
        self,
        job_id: str,
        scan_id: str,
        tenant_id: str,
        started: datetime,
        status: ResultStatus,
        artifacts: list[dict[str, Any]],
        diagnostics: list[dict[str, Any]],
        *,
        models: int,
    ) -> dict[str, Any]:
        finished = datetime.now(UTC)
        return {
            "schema_version": "scan.result/v1",
            "job_id": job_id,
            "scan_id": scan_id,
            "tenant_id": tenant_id,
            "engine": ENGINE_ID,
            "engine_version": _engine_version(),
            "status": str(status),
            "invocation": {
                # ⚠ NO ARGV. This engine makes an API call; there is no command
                # line to redact, and inventing one would misdescribe the run.
                "argv_redacted": [],
                "started_at": _rfc3339z(started),
                "finished_at": _rfc3339z(finished),
                "exit_code": 0,
                "duration_ms": int((finished - started).total_seconds() * 1000),
            },
            "artifacts": artifacts,
            "ecosystems_covered": ["huggingface"] if models else [],
            # `components` counts enriched models. None would mean "not measured";
            # zero means "measured, none" — see events.Summary.
            "summary": {
                "components": models,
                "vulnerabilities": None,
                "licenses": None,
                "crypto_assets": None,
            },
            "diagnostics": diagnostics,
        }


def _rfc3339z(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _engine_version() -> str:
    """The pinned commit of owasp-aibom-generator, or `unknown`.

    ⚠ THE PACKAGE PUBLISHES NO RELEASES AND NO TAGS, so there is no version to
    report beyond the commit `toolctl pin` recorded — see `unpinned_reason` in
    OSINT/tools.manifest.yaml. Reporting a confident-looking version we do not
    have would put a false pin in a compliance report's Engine Coverage.
    """
    return os.environ.get("AIBOM_GENERATOR_REF", "") or "unknown"


def main() -> int:
    assert_no_telemetry_token()

    from ..aibom.adapters.aibom_generator_fetch import fetch_model_card

    workspace_root = Path(os.environ.get("AXEBOM_WORKSPACE_ROOT", "/var/lib/axebom/workspaces"))
    output_root = Path(os.environ.get("AXEBOM_OUTPUT_ROOT", "/var/lib/axebom/artifacts"))
    cache_root = Path(
        os.environ.get("AXEBOM_ENRICHMENT_CACHE_ROOT", "/var/lib/axebom/enrichment-cache")
    )

    worker = EnrichmentWorker(
        workspace_root=workspace_root,
        output_root=output_root,
        cache=CardCache(root=cache_root),
        fetch=fetch_model_card,
    )

    return run_worker(
        FAMILY,
        worker.handle,
        config_name="aienrich-worker",
        # ⚠ One at a time. Every job is a burst of outbound Hugging Face calls,
        # and the anonymous rate limit is the constraint, not CPU.
        max_ack_pending=1,
        bus_overrides={
            "job_subject_override": JOB_SUBJECT,
            "dlq_subject_override": DLQ_SUBJECT,
            "durable_override": DURABLE,
            # result_subject is deliberately NOT overridden: this reports as an
            # AIBOM engine on scan.result.aibom, which the orchestrator's existing
            # `orchestrator-aibom` durable already consumes.
        },
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
