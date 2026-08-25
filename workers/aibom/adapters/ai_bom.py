"""ai-bom (Trusera) — code-level AI discovery.

⚠ THIS ENGINE FINDS *USAGE*, NOT MODELS.

It reads the repository and reports what it actually uses: LLM providers, agent
frameworks (LangChain, CrewAI, AutoGen, LlamaIndex, LangGraph), MCP servers,
model references and AI containers. It does not know what any of those models
are — that is `aibom-generator`'s job, and the split matters because the two
answer different questions and are merged on different fields.

⚠ `--llm-enrich` IS OFF BY DEFAULT AND STAYS OFF.

The flag resolves ambiguous model references by asking an LLM — which means
SENDING CODE CONTEXT TO A THIRD PARTY. That is a decision a customer makes per
project with their eyes open, not a global default they discover afterwards in
an egress log. `enable_llm_enrich` is threaded from the project setting, and
turning it on is audited.

It also cannot run inside the scan sandbox at all: engines run `--network=none`,
so a flag needing an API key would fail there anyway. The refusal below is what
makes that legible instead of surfacing as a timeout.
"""

from __future__ import annotations

from typing import Any

from axebom_shared.adapters.base import Capabilities, GenerateResult, ResultStatus, ScanTarget
from axebom_shared.adapters.summary import count_cyclonedx, summarize
from axebom_shared.sandbox import SandboxResult, WorkspaceLayout

from ...sbom.adapters.common import SandboxedAdapter

CAPABILITIES = Capabilities(
    engine_id="ai-bom",
    families=("aibom",),
    source_kinds=("git", "upload"),
    produces=("ai_models", "ai_dependencies"),
    native_format="cyclonedx-json-1.6",
    # ⚠ DISCOVERY SURFACES, NOT PACKAGE ECOSYSTEMS. Reusing the npm/pypi
    # vocabulary would make Engine Coverage claim ai-bom covered `pypi`, which a
    # reader takes as "it scanned the Python dependencies". It did not — it
    # looked for AI usage in them.
    ecosystems=("llm-providers", "agent-frameworks", "mcp-servers", "model-refs"),
    default_weight=5,
)


class AIBomAdapter(SandboxedAdapter):
    """Runs Trusera ai-bom over a source tree."""

    media_type = "application/vnd.cyclonedx+json; version=1.6"
    #: No vulnerability database: this discovers usage, it matches no advisories.
    requires_db_version = False

    def __init__(self, *, enable_llm_enrich: bool = False, **kwargs: Any) -> None:
        self.enable_llm_enrich = enable_llm_enrich
        super().__init__(CAPABILITIES, **kwargs)

    def build_argv(self, target: ScanTarget, layout: WorkspaceLayout) -> list[str]:
        # ⚠ NO `--output` FLAG, AND THAT WAS THE BUG.
        #
        # This built `--output -`, following the common Unix "-" means stdout
        # convention. ai-bom==3.1.0 does not honour it: `--output` is "a file
        # path" full stop (ai_bom/reporters/base.py does
        # `Path(path).write_text(...)` with no special case for "-"), so this
        # silently wrote a file literally named `-` into the workspace and left
        # stdout empty. The sandbox has no writable host mount (every mount is
        # read-only, deliberately — see WorkspaceLayout), so that file was not
        # even reachable, and `parse_stdout` failed the run with
        # ENGINE_OUTPUT_UNPARSEABLE on every scan. It had never been run against
        # the real package.
        #
        # Omitting `--output` entirely is the fix: for any non-`table` format
        # ai-bom prints the rendered report straight to stdout
        # (`ai_bom/cli.py::scan`, the final `else: print(output_str)` branch),
        # which is exactly the one channel SandboxedAdapter reads.
        #
        # Verified against the pinned image, non-root, read-only, no network:
        #   docker run --rm --user 65534:65534 --read-only --network none \
        #     -v <fixture>:/src:ro axebom/ai-bom-engine:dev \
        #     scan /src --format cyclonedx --quiet
        # returns valid CycloneDX JSON on stdout and nothing on stderr.
        argv = [
            "scan",
            layout.container_source,
            "--format",
            "cyclonedx",
            "--quiet",
        ]

        if self.enable_llm_enrich:
            # ⚠ REFUSED HERE RATHER THAN PASSED THROUGH.
            #
            # The sandbox runs with --network=none. Passing --llm-enrich would
            # produce a connection timeout deep inside the engine, reported as
            # a failed scan with no indication that a SETTING caused it. The
            # enrichment that needs a network happens outside the sandbox, in
            # aibom_generator.py.
            raise ValueError(
                "ai-bom --llm-enrich cannot run inside the scan sandbox: engines "
                "have no network by design. LLM-assisted model resolution belongs "
                "in the enrichment step, which runs outside the sandbox and is "
                "audited per project."
            )

        return argv

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
                    "message": "ai-bom returned a document that is not a JSON object",
                }
            )
            return base

        discovery = extract_discovery(payload)
        base.diagnostics.extend(discovery["diagnostics"])
        base.ecosystems_covered = sorted(discovery["surfaces"])
        # Models, frameworks and MCP servers each arrive as one CycloneDX
        # component, which is why the manifest's ai_models / ai_dependencies
        # both map onto `components` rather than inventing an envelope field.
        base.summary = summarize(self.capabilities, count_cyclonedx(payload))

        if not discovery["models"] and not discovery["frameworks"]:
            # ⚠ A REPOSITORY WITH NO AI IN IT IS THE COMMON CASE, so an empty
            # result is `succeeded` here rather than `partial` — unlike the CBOM
            # engine, where crypto is nearly universal and an empty result far
            # more often means the engine could not read the source.
            base.status = ResultStatus.SUCCEEDED
            base.diagnostics.append(
                {
                    "severity": "info",
                    "code": "ENGINE_ZERO_RESULTS",
                    "message": "ai-bom found no AI frameworks, providers or model references",
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


#: Component types ai-bom uses for the things it discovers.
#:
#: ⚠ `machine-learning-model` IS THE ONLY ONE THAT BECOMES AN AI MODEL. The
#: others are usage facts — a LangChain dependency is a library, not a model,
#: and recording it as one would put "langchain" in a Table 10 model inventory.
_MODEL_TYPES = frozenset({"machine-learning-model", "model"})
_FRAMEWORK_TYPES = frozenset({"library", "framework", "application", "platform"})


def extract_discovery(payload: dict[str, Any]) -> dict[str, Any]:
    """Pull usage facts out of ai-bom's CycloneDX document.

    Returns models, frameworks, providers, MCP servers and diagnostics. Every
    read is defensive: one malformed component must not lose the document.
    """
    models: list[dict[str, Any]] = []
    frameworks: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    surfaces: set[str] = set()
    skipped = 0

    components = payload.get("components")
    if not isinstance(components, list):
        return {
            "models": [],
            "frameworks": [],
            "surfaces": set(),
            "diagnostics": [
                {
                    "severity": "warn",
                    "code": "ENGINE_OUTPUT_UNEXPECTED",
                    "message": "ai-bom output has no `components` array",
                }
            ],
        }

    for raw in components:
        if not isinstance(raw, dict):
            skipped += 1
            continue

        kind = str(raw.get("type") or "").strip().lower()
        properties = _properties(raw)

        if kind in _MODEL_TYPES:
            models.append(_model_usage(raw, properties))
            surfaces.add("model-refs")
        elif kind in _FRAMEWORK_TYPES:
            entry = _framework_usage(raw, properties)
            frameworks.append(entry)
            surfaces.add(entry["surface"])

    if skipped:
        diagnostics.append(
            {
                "severity": "warn",
                "code": "ENGINE_OUTPUT_UNEXPECTED",
                "message": f"{skipped} component entr(ies) were not objects and were skipped",
            }
        )

    return {
        "models": models,
        "frameworks": frameworks,
        "surfaces": surfaces,
        "diagnostics": diagnostics,
    }


def _model_usage(raw: dict[str, Any], properties: dict[str, str]) -> dict[str, Any]:
    """One model reference, as DISCOVERY sees it.

    ⚠ USAGE FACTS ONLY. Where it is referenced, which framework calls it, which
    provider serves it. Nothing here claims to know the model's licence or its
    developer — that is enrichment's answer, and inventing it from a name would
    put a guess in a compliance document.
    """
    return {
        "model_ref": _model_reference(raw, properties),
        "name": _string(raw.get("name")),
        "version": _string(raw.get("version")),
        "provider": properties.get("provider", ""),
        "framework": properties.get("framework", ""),
        "locations": _locations(raw),
        "purl": _string(raw.get("purl")),
        "bom_ref": _string(raw.get("bom-ref")),
        # ⚠ AxeBOM EXTENSIONS, EXCLUDED FROM COVERAGE SCORING. Trusera's risk
        # score and OWASP LLM Top-10 mapping are analysis, not CERT-In Table 10
        # elements. Letting them count would move a compliance percentage
        # because a third party changed its heuristics.
        "risk_score": _float(properties.get("risk_score")),
        "owasp_llm_top10": _list(properties.get("owasp_llm_top10")),
    }


def _framework_usage(raw: dict[str, Any], properties: dict[str, str]) -> dict[str, Any]:
    name = _string(raw.get("name"))
    return {
        "name": name,
        "version": _string(raw.get("version")),
        "purl": _string(raw.get("purl")),
        "category": properties.get("category", ""),
        "surface": _surface_for(name, properties),
        "locations": _locations(raw),
    }


def _surface_for(name: str, properties: dict[str, str]) -> str:
    """Classify what kind of AI usage this is.

    Derived from the engine's own `category` property where it gives one, and
    from the name otherwise. Never guessed beyond that: an unclassifiable
    dependency lands in `agent-frameworks`, which is the broadest bucket rather
    than the most specific.
    """
    category = properties.get("category", "").lower()
    if "mcp" in category:
        return "mcp-servers"
    if "provider" in category or "llm" in category:
        return "llm-providers"

    lowered = name.lower()
    if "mcp" in lowered:
        return "mcp-servers"
    if any(p in lowered for p in ("openai", "anthropic", "cohere", "mistral", "bedrock", "vertex")):
        return "llm-providers"
    return "agent-frameworks"


def _model_reference(raw: dict[str, Any], properties: dict[str, str]) -> str:
    """The identity enrichment will look up.

    ⚠ A HUGGING FACE ID IS `org/name`, AND THAT IS WHAT ENRICHMENT NEEDS. A bare
    name resolves to nothing, so a reference we cannot form is left EMPTY rather
    than approximated — an approximate id fetches the wrong model card, and its
    licence would then be attributed to the customer's model.
    """
    explicit = properties.get("model_id") or properties.get("huggingface_id")
    if explicit:
        return explicit.strip()

    purl = _string(raw.get("purl"))
    if purl.startswith("pkg:huggingface/"):
        rest = purl.removeprefix("pkg:huggingface/").split("?", 1)[0]
        return rest.split("@", 1)[0]

    name = _string(raw.get("name"))
    return name if "/" in name else ""


def _properties(raw: dict[str, Any]) -> dict[str, str]:
    """Flatten CycloneDX `properties` into a dict.

    Names are lowercased and any vendor prefix is dropped, because ai-bom has
    used both `aibom:provider` and `provider` between releases and a reader
    keyed on one spelling silently loses the field.
    """
    out: dict[str, str] = {}
    props = raw.get("properties")
    if not isinstance(props, list):
        return out
    for p in props:
        if not isinstance(p, dict):
            continue
        name = _string(p.get("name")).lower()
        if not name:
            continue
        out[name.rsplit(":", 1)[-1]] = _string(p.get("value"))
    return out


def _locations(raw: dict[str, Any]) -> list[str]:
    evidence = raw.get("evidence")
    if not isinstance(evidence, dict):
        return []
    occurrences = evidence.get("occurrences")
    if not isinstance(occurrences, list):
        return []
    out = []
    for o in occurrences:
        if isinstance(o, dict):
            location = _string(o.get("location"))
            if location:
                out.append(location)
    return sorted(set(out))


def _string(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _float(value: Any) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [v.strip() for v in value.split(",") if v.strip()]
    return []
