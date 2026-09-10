"""airom (airomhq/airom) — AI discovery with real file:line evidence.

⚠ IT FINDS THINGS ai-bom CANNOT SEE, AND THAT IS WHY IT IS HERE.

Measured against `testdata/airom-ai-langchain.cdx.json`, a real capture over
`testdata/ai-langchain/`: airom reports the embedding model
`sentence-transformers/all-MiniLM-L6-v2`, a system prompt at `src/app.py:9`, a
prompt file, a Chroma vector store and a RAG pipeline — none of which appear
anywhere in ai-bom's output for the same tree. It also attributes `gpt-4o` to
`openai`, where ai-bom attributes it to `langchain`.

⚠ THE DISPATCH IS ON `airom:kind`, NEVER ON THE CycloneDX `type`, and that is
not a stylistic choice. Real airom output types its vector store and its RAG
pipeline as `application` and its prompts as `data`. The AIBOM classifier's
framework set contains `application`, so dispatching on `type` would file a
vector store as a software dependency, and `data` is in neither set, so both
prompts would be dropped without a word. `airom:kind` says exactly what each
component is: `hosted-llm`, `embedding-model`, `prompt`, `vector-db`,
`rag-pipeline`, `framework`, `library`.

⚠ THE NAME IS LOWERCASED AND THE TRUE CASING IS IN THE EVIDENCE.
`airom:model.id` and the component name both read `meta-llama/llama-3-8b`;
`evidence.identity[].concludedValue` reads `meta-llama/Llama-3-8B`. Hugging Face
repository ids are case-sensitive, so the lowercased form keys the same model
differently from ai-bom and cdxgen — storing one model as two — and is a
reference the Hub does not resolve. `discovery.concluded_identity` recovers it.

⚠ OFFLINE, AND HONEST ABOUT WHAT IT SKIPS. airom queries OSV.dev for advisories
when it can. Under `--network=none` it degrades: it writes a warning to stderr
and sets `airom:assurance.cve.unchecked`, which becomes a diagnostic here rather
than an absent vulnerability list nobody asked about (invariant 12).

Verified against the pinned image, non-root, read-only, no network:

    docker run --rm --user 65534:65534 --read-only --network none \\
      -v <fixture>:/src:ro axebom/airom-engine:dev fs /src -o cyclonedx

writes CycloneDX JSON to stdout and the OSV warning to stderr.
"""

from __future__ import annotations

from typing import Any

from axebom_shared.adapters.base import Capabilities, GenerateResult, ResultStatus, ScanTarget
from axebom_shared.adapters.summary import count_cyclonedx, summarize
from axebom_shared.sandbox import SandboxResult, WorkspaceLayout

from ...sbom.adapters.common import SandboxedAdapter
from .. import discovery as shared

CAPABILITIES = Capabilities(
    engine_id="airom",
    families=("aibom",),
    source_kinds=("git", "upload"),
    produces=("ai_models", "ai_dependencies", "ai_assets"),
    native_format="cyclonedx-json-1.6",
    # ⚠ DISCOVERY SURFACES, NOT PACKAGE ECOSYSTEMS — the same reasoning
    # ai_bom.py records. `prompts`, `vector-stores` and `rag-pipelines` are
    # surfaces only this engine covers today, which is exactly what Engine
    # Coverage exists to say.
    ecosystems=(
        "model-refs",
        "embeddings",
        "prompts",
        "vector-stores",
        "rag-pipelines",
        "agent-frameworks",
    ),
    default_weight=5,
)

#: `airom:kind` values that name a MODEL.
_MODEL_KINDS = frozenset({"hosted-llm", "local-llm", "embedding-model", "model"})

#: `airom:kind` values that name a software dependency.
_FRAMEWORK_KINDS = frozenset({"framework", "library", "sdk"})

#: `airom:kind` -> the `normalize.ai_assets.asset_type` it becomes.
_ASSET_KINDS = {
    "prompt": shared.ASSET_PROMPT,
    "prompt-template": shared.ASSET_PROMPT,
    "vector-db": shared.ASSET_VECTOR_STORE,
    "vector-store": shared.ASSET_VECTOR_STORE,
    "rag-pipeline": shared.ASSET_RAG_PIPELINE,
    "agent": shared.ASSET_AGENT,
    "tool": shared.ASSET_TOOL,
    "mcp-server": shared.ASSET_MCP_SERVER,
    "endpoint": shared.ASSET_ENDPOINT,
    "dataset": shared.ASSET_DATASET,
}

#: Which discovery surface each kind covers, for Engine Coverage.
_SURFACE_OF = {
    shared.ASSET_PROMPT: "prompts",
    shared.ASSET_VECTOR_STORE: "vector-stores",
    shared.ASSET_RAG_PIPELINE: "rag-pipelines",
    shared.ASSET_AGENT: "agents",
    shared.ASSET_TOOL: "tools",
    shared.ASSET_MCP_SERVER: "mcp-servers",
    shared.ASSET_ENDPOINT: "endpoints",
    shared.ASSET_DATASET: "datasets",
}


class AiromAdapter(SandboxedAdapter):
    """Runs airom over a source tree."""

    media_type = "application/vnd.cyclonedx+json; version=1.6"
    #: No vulnerability database of its own. It asks OSV.dev when it has a
    #: network, which in the sandbox it never does — see the module docstring.
    requires_db_version = False

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(CAPABILITIES, **kwargs)

    def build_argv(self, target: ScanTarget, layout: WorkspaceLayout) -> list[str]:
        # `fs <path> -o cyclonedx`. No `--output`: airom writes the document to
        # stdout, which is the one channel SandboxedAdapter reads, and its
        # OSV.dev warning to stderr where it does not corrupt the JSON.
        return ["fs", layout.container_source, "-o", "cyclonedx"]

    def interpret(
        self,
        target: ScanTarget,
        payload: Any,
        result: SandboxResult,
        base: GenerateResult,
    ) -> GenerateResult:
        if not isinstance(payload, dict):
            base.status = ResultStatus.FAILED
            base.diagnostics.append(
                {
                    "severity": "error",
                    "code": "ENGINE_OUTPUT_UNEXPECTED",
                    "message": "airom returned a document that is not a JSON object",
                }
            )
            return base

        found = extract_airom_discovery(payload)
        base.diagnostics.extend(found["diagnostics"])
        base.ecosystems_covered = sorted(found["surfaces"])
        base.discoveries = shared.counts(found)
        base.summary = summarize(self.capabilities, count_cyclonedx(payload))

        if not (found["models"] or found["frameworks"] or found["assets"]):
            # A repository with no AI in it is the common case — the same
            # reasoning ai_bom.py records for treating this as `succeeded`.
            base.status = ResultStatus.SUCCEEDED
            base.diagnostics.append(
                {
                    "severity": "info",
                    "code": "ENGINE_ZERO_RESULTS",
                    "message": "airom found no models, prompts, vector stores or AI frameworks",
                    "hint": (
                        "for most repositories this is correct. It is only a gap if "
                        "you expected AI usage here — check that the source archive "
                        "contains the application code and not only manifests."
                    ),
                }
            )
            return base

        base.status = ResultStatus.SUCCEEDED
        return base


def extract_airom_discovery(payload: dict[str, Any]) -> dict[str, Any]:
    """Read airom's CycloneDX document into the shared discovery shape.

    Returns `models`, `frameworks`, `assets`, `surfaces` and `diagnostics`. Every
    read is defensive: one malformed component must not lose the document.
    """
    models: list[dict[str, Any]] = []
    frameworks: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    surfaces: set[str] = set()
    unknown_kinds: dict[str, int] = {}
    skipped = 0

    components = payload.get("components")
    if not isinstance(components, list):
        return {
            "models": [],
            "frameworks": [],
            "assets": [],
            "surfaces": set(),
            "diagnostics": [
                {
                    "severity": "warn",
                    "code": "ENGINE_OUTPUT_UNEXPECTED",
                    "message": "airom output has no `components` array",
                }
            ],
        }

    for raw in components:
        if not isinstance(raw, dict):
            skipped += 1
            continue

        props = shared.properties(raw)
        kind = props.get("kind", "").strip().lower()

        if kind in _MODEL_KINDS:
            models.append(_model_usage(raw, props, kind))
            surfaces.add("embeddings" if kind == "embedding-model" else "model-refs")
        elif kind in _FRAMEWORK_KINDS:
            frameworks.append(_framework_usage(raw, props))
            surfaces.add("agent-frameworks")
        elif kind in _ASSET_KINDS:
            asset_type = _ASSET_KINDS[kind]
            assets.append(_asset(raw, props, asset_type))
            surfaces.add(_SURFACE_OF.get(asset_type, asset_type))
        elif kind:
            # ⚠ COUNTED AND REPORTED, NEVER DROPPED IN SILENCE. A kind airom
            # learns to emit that this mapping does not know is a discovery this
            # report did not carry, which is exactly what invariant 12 is about.
            unknown_kinds[kind] = unknown_kinds.get(kind, 0) + 1
        else:
            skipped += 1

    for kind, count in sorted(unknown_kinds.items()):
        diagnostics.append(
            {
                "severity": "warn",
                "code": "ENGINE_OUTPUT_UNEXPECTED",
                "message": (
                    f"airom reported {count} component(s) of kind {kind!r}, which "
                    f"AxeBOM does not yet map to a model, a dependency or an AI asset; "
                    f"they are not in this report"
                ),
            }
        )
    if skipped:
        diagnostics.append(
            {
                "severity": "warn",
                "code": "ENGINE_OUTPUT_UNEXPECTED",
                "message": f"{skipped} airom component(s) carried no `airom:kind` and were skipped",
            }
        )
    diagnostics.extend(_assurance_diagnostics(payload))

    return {
        "models": models,
        "frameworks": frameworks,
        "assets": assets,
        "surfaces": surfaces,
        "diagnostics": diagnostics,
    }


def _model_usage(raw: dict[str, Any], props: dict[str, str], kind: str) -> dict[str, Any]:
    """One model reference, as DISCOVERY sees it.

    The field names match `ai_bom._model_usage` exactly, because `merge.merge`
    and `identity.identify` read them without knowing which engine produced them.
    """
    # ⚠ THE CONCLUDED VALUE FIRST — see the module docstring. `airom:model.id`
    # and the component name are both lowercased; only the identity evidence
    # carries the casing Hugging Face actually resolves.
    asserted = (
        shared.concluded_identity(raw) or props.get("model.id", "") or shared.text(raw.get("name"))
    )
    purl = shared.text(raw.get("purl"))
    return {
        "model_ref": asserted if shared.looks_like_model_reference(asserted) else "",
        "model_id": asserted,
        "name": shared.text(raw.get("name")),
        "version": shared.text(raw.get("version")),
        "provider": props.get("model.provider", "") or props.get("provider", ""),
        # airom names no calling framework per model; the relationship it does
        # record (`airom:rel.*`) is between components, and reading it as a
        # framework attribution would be a guess.
        "framework": "",
        "locations": shared.occurrence_locations(raw),
        "purl": purl if shared.valid_purl(purl) else "",
        "bom_ref": shared.text(raw.get("bom-ref")),
        # ⚠ airom's own confidence, kept as evidence and EXCLUDED FROM SCORING —
        # the same treatment ai-bom's risk score gets. A third party changing its
        # heuristics must not move a compliance percentage.
        "engine_confidence": _float(props.get("confidence")),
        "airom_kind": kind,
    }


def _framework_usage(raw: dict[str, Any], props: dict[str, str]) -> dict[str, Any]:
    purl = shared.text(raw.get("purl"))
    return {
        "name": shared.text(raw.get("name")),
        "version": shared.text(raw.get("version")) or shared.concluded_identity(raw, "version"),
        "purl": purl if shared.valid_purl(purl) else "",
        "category": props.get("kind", ""),
        "provider": props.get("provider", ""),
        "surface": "agent-frameworks",
        "locations": shared.occurrence_locations(raw),
    }


def _asset(raw: dict[str, Any], props: dict[str, str], asset_type: str) -> dict[str, Any]:
    """A prompt, vector store, RAG pipeline or other non-model AI component."""
    return {
        "asset_type": asset_type,
        "name": shared.text(raw.get("name")),
        "provider": props.get("provider", ""),
        "locations": shared.occurrence_locations(raw),
        "bom_ref": shared.text(raw.get("bom-ref")),
        "engine_confidence": _float(props.get("confidence")),
    }


def _assurance_diagnostics(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """airom's own statement of what it could not check.

    ⚠ REPORTED, NOT INFERRED FROM THE SANDBOX. airom sets
    `airom:assurance.cve.unchecked` when it could not reach OSV.dev — which under
    `--network=none` is always, by design. Saying so is the difference between
    "no advisories were found" and "advisories were never looked for".
    """
    metadata = payload.get("metadata")
    props = shared.properties(metadata) if isinstance(metadata, dict) else {}
    unchecked = props.get("assurance.cve.unchecked", "")
    if not unchecked or unchecked in {"0", "false"}:
        return []
    return [
        {
            "severity": "info",
            "code": "ENGINE_PARTIAL_ECOSYSTEM",
            "ecosystem": "advisories",
            "message": (
                f"airom could not check {unchecked} component(s) against OSV.dev; "
                f"engines run with no network by design, so this scan reports AI "
                f"discovery only and asserts nothing about their vulnerabilities"
            ),
        }
    ]


def _float(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
