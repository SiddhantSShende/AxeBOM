"""The adapter contract every scan engine implements.

docs/04-OSINT-INTEGRATION.md. Three methods, and the split between them is
deliberate:

    available()  can this engine run here, right now?
    generate()   run the tool, produce RAW artifacts
    parse()      turn raw artifacts into canonical objects

`generate` and `parse` are separate because they fail for different reasons.
Generation fails operationally — a missing container, a timeout, a stale
vulnerability database. Parsing fails semantically — upstream changed its
output shape. Debugging them together is much harder, and separating them is
also what makes normalization REPLAYABLE (ADR-0003): raw artifacts are stored
immutably, so a parser bug is fixed by re-parsing rather than re-scanning.

Phase 2 implements `available()` only. Phase 7 implements the rest.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from axebom_shared.errors import EngineUnavailableError

if TYPE_CHECKING:
    from .summary import EngineSummary


class EngineMode(StrEnum):
    """How an engine is executed. Resolved by `axebom toolctl`."""

    CONTAINER = "container"
    BINARY = "binary"
    PIP = "pip"
    INTERNAL = "internal"
    UNAVAILABLE = "unavailable"


class ResultStatus(StrEnum):
    """Terminal status of one engine run.

    `PARTIAL` is a FIRST-CLASS STATUS, not an error: an engine that covered 11
    of 12 ecosystems produced useful output plus a known gap, and both must
    reach the report. Collapsing partial into failure throws away the output;
    collapsing it into success throws away the gap, which is worse — it turns
    an unknown into a false negative the customer trusts.
    """

    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class Capabilities:
    """What an engine can do. Mirrors the manifest entry."""

    engine_id: str
    families: tuple[str, ...]
    source_kinds: tuple[str, ...]
    produces: tuple[str, ...]
    native_format: str | None = None
    ecosystems: tuple[str, ...] = ()
    db_backed: bool = False
    default_weight: int = 1
    # Higher wins when two engines supply a dependency graph for the same
    # ecosystem. Graphs are REPLACED per ecosystem, never unioned — unioning
    # invents phantom transitive edges and corrupts the direct-vs-transitive
    # counts a Top-Level report is built on.
    graph_trust: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class Availability:
    """Whether an engine can run, and why not if it cannot."""

    available: bool
    mode: EngineMode
    version: str | None = None
    detail: str = ""

    def as_diagnostic(self) -> dict[str, Any]:
        """Render for the report's Engine Coverage section.

        An unavailable engine is never silent: the customer sees which engine
        was requested, that it did not run, and why.
        """
        return {
            "engine": getattr(self, "engine_id", None),
            "available": self.available,
            "mode": self.mode.value,
            "version": self.version,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ScanTarget:
    """What an engine is pointed at.

    NOTE WHAT IS ABSENT: there is no credential field, and there never will be.
    The fetcher materializes source ONCE and holds the only credentials
    (ADR-0008); engines receive a content-addressed archive and nothing else.
    Compromising a scanner therefore yields the code it was already scanning —
    not a token, not another tenant's data.
    """

    scan_id: str
    job_id: str
    kind: str  # git | upload | image | sbom | model_ref | manual
    workspace: Path
    root_subpath: str = ""
    commit_sha: str | None = None
    image_digest: str | None = None
    sbom_path: Path | None = None
    #: A native SBOM document the FETCHER staged (e.g. a GitHub repository's
    #: own Dependency Graph SBOM) — distinct from `sbom_path`, which is
    #: another ENGINE's output shared through the per-scan workspace (see
    #: runner.py's grype-consumes-syft wiring). This one comes from an
    #: external source outside the scan pipeline entirely; only an engine
    #: with `ConsumesNativeSBOM` set in the Go registry ever sees it non-None.
    native_sbom_path: Path | None = None
    engine_config: dict[str, Any] = field(default_factory=dict)


@dataclass
class RawArtifact:
    """One file an engine produced. Immutable once written (ADR-0003)."""

    role: str  # native_output | log | stderr | sarif
    path: Path
    media_type: str
    sha256: str = ""
    size_bytes: int = 0


@dataclass
class GenerateResult:
    """The outcome of running an engine."""

    status: ResultStatus
    artifacts: list[RawArtifact] = field(default_factory=list)
    ecosystems_covered: list[str] = field(default_factory=list)
    #: Headline counts. Every field defaults to None — "not measured" — so a
    #: run that produced no output reports nothing rather than a row of zeros
    #: that reads as a clean result. Adapters set this in `interpret()`, where
    #: the payload is already parsed; see adapters/summary.py.
    summary: EngineSummary = field(default_factory=lambda: _EngineSummary())
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    #: ⚠ FINER-GRAINED THAN `summary`, AND FOR A DIFFERENT READER.
    #:
    #: `summary` carries the four dimensions docs/02-CONTRACTS.md §6 defines for
    #: every BOM type, and an AIBOM engine's models, prompts and vector stores
    #: all fold into `components` there — deliberately, because that is the
    #: figure a reader compares BETWEEN engines. It is useless to somebody
    #: watching a scan run: "11 components" says nothing they want to know,
    #: where "2 vector stores, 2 prompts, 1 RAG pipeline" says exactly it.
    #:
    #: ⚠ EMPTY MEANS "COUNTS NOTHING FINER", NOT "FOUND NONE". An engine that
    #: does not break its results down leaves this empty and the event stream
    #: reports its `summary` instead; a zero here would claim it looked for
    #: prompts and found none. Same nil-is-not-zero discipline `summary`'s
    #: Optional fields carry.
    #:
    #: ⚠ COUNTS ONLY, AND THE KEYS REACH A BROWSER. `events.SanitizeDiscoveries`
    #: drops any key that is not a plain lowercase identifier, because a key
    #: built from a filename would put a path into the advisory event stream
    #: through the one field nobody thought to check.
    discoveries: dict[str, int] = field(default_factory=dict)
    engine_version: str | None = None
    # REQUIRED for vulnerability engines. Without it a finding cannot be dated,
    # and a report that cannot say "matched against vulnerability data as of X"
    # is not defensible.
    engine_db_version: str | None = None
    #: Which image bytes actually ran. See sandbox.Result.ImageDigest for why
    #: this is read back from the daemon rather than copied from the reference.
    image_digest: str = ""

    #: ⚠ started_at, finished_at AND duration_ms DESCRIBE ONE INTERVAL.
    #:
    #: Set together or not at all. They come from the sandbox when the engine
    #: actually ran, and from the worker's own clock when it did not — but
    #: never one from each, because a reader who cannot reconcile
    #: finished - started against duration cannot trust any of the three.
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int = 0
    exit_code: int | None = None
    argv_redacted: list[str] = field(default_factory=list)


def _EngineSummary() -> Any:  # noqa: N802 - a factory named for what it builds
    """Build an empty EngineSummary without a circular import.

    summary.py imports Capabilities from this module, so the dependency can
    only run one way at import time. Deferring the import to first use keeps
    the default value real rather than making it a plain dict that would drift
    from the dataclass.
    """
    from .summary import EngineSummary

    return EngineSummary()


@runtime_checkable
class ToolAdapter(Protocol):
    """Structural interface. See ToolAdapterBase for the usable superclass."""

    capabilities: Capabilities

    def available(self) -> Availability: ...
    def generate(self, target: ScanTarget) -> GenerateResult: ...
    def parse(self, artifacts: list[RawArtifact]) -> list[Any]: ...


class ToolAdapterBase(ABC):
    """Base class for engine adapters.

    Subclasses implement `available()` in Phase 2 and the rest in Phase 7.
    """

    capabilities: Capabilities

    def __init__(self, capabilities: Capabilities) -> None:
        self.capabilities = capabilities

    @property
    def engine_id(self) -> str:
        return self.capabilities.engine_id

    @abstractmethod
    def available(self) -> Availability:
        """Report whether this engine can run here.

        Must NEVER raise: an engine that cannot run is `unavailable`, which is
        recorded in Engine Coverage. Raising would fail the whole scan and cost
        every other engine's output too.
        """

    def generate(self, target: ScanTarget) -> GenerateResult:
        """Run the tool. Phase 7."""
        raise NotImplementedError(
            f"{self.engine_id}.generate() lands in Phase 7 — "
            f"see docs/phases/PHASE-07-sbom-adapters.md"
        )

    def parse(self, artifacts: list[RawArtifact]) -> list[Any]:
        """Map raw output to canonical objects. Phase 7/8.

        Implementations parse DEFENSIVELY: ignore unknown fields, emit a
        diagnostic for missing expected ones, and never raise on shape drift.
        A tool that changes its output should degrade coverage loudly, not
        crash a worker or — far worse — silently yield an empty inventory that
        renders as a clean report.
        """
        raise NotImplementedError(
            f"{self.engine_id}.parse() lands in Phase 7 — see docs/phases/PHASE-07-sbom-adapters.md"
        )

    def require_available(self) -> Availability:
        """Raise if the engine cannot run. For call sites that need it present."""
        a = self.available()
        if not a.available:
            raise EngineUnavailableError(self.engine_id, a.detail or "not resolvable")
        return a
