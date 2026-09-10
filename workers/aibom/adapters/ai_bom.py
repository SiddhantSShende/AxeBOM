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
from .. import discovery as shared

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

    #: ⚠ STAGED FOR THE ENRICHMENT WORKER, the same per-scan workspace handoff
    #: grype uses to read syft's SBOM rather than re-scanning the tree.
    #: `workers/aienrich` runs in a different container with no access to this
    #: job's output directory, so the discovery it enriches has to be published
    #: somewhere both mount. Without this the enrichment engine reports
    #: ENGINE_INPUT_MISSING on every scan.
    workspace_artifact_name = "ai-bom.cdx.json"

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
        base.discoveries = shared.counts(discovery)
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

#: Package-URL types that name a SOFTWARE PACKAGE, never a model.
#:
#: ⚠ THE ENGINE'S `type` FIELD IS NOT TRUSTWORTHY ON ITS OWN, WHICH IS WHY THIS
#: EXISTS. ai-bom 3.1.0 labels the `transformers` PyPI library
#: `type: machine-learning-model` with `purl: pkg:pypi/transformers` — captured
#: output, not a hypothetical. Taking that at face value put a Python library in a
#: CERT-In Table 10 model inventory three times over, under three spellings of its
#: own name, while the one real model in the repository was never recorded at all.
#:
#: A purl minted by a package ecosystem is that ecosystem's own assertion about what
#: the thing IS, and it outranks a type field a scanner guessed. `pkg:huggingface`
#: is deliberately absent: that one does name a model.
_PACKAGE_PURL_TYPES = frozenset(
    {
        "pypi",
        "npm",
        "maven",
        "golang",
        "cargo",
        "gem",
        "nuget",
        "composer",
        "deb",
        "rpm",
        "apk",
        "conan",
        "cran",
        "hex",
        "pub",
        "swift",
        "generic",
    }
)


def package_purl_type(purl: str) -> str:
    """The ecosystem a purl names, or empty when it names none."""
    if not purl.startswith("pkg:"):
        return ""
    ptype = purl.removeprefix("pkg:").partition("/")[0].strip().lower()
    return ptype if ptype in _PACKAGE_PURL_TYPES else ""


def classify_component(raw: dict[str, Any], properties: dict[str, str]) -> tuple[str, str]:
    """Decide whether a component the engine typed as a model really is one.

    Returns `(kind, reason)` where kind is `"model"` or `"framework"`. The reason is
    empty unless the engine's own classification was overruled, in which case it is
    the sentence that goes into the diagnostic — a reclassification a reader cannot
    see is a silent edit of their inventory.

    The rule, in order:

    1. A resolvable model reference (`org/name`) makes it a model. That is positive
       evidence of model identity and nothing overrides it.
    2. Otherwise, a package-ecosystem purl makes it a framework. The ecosystem minted
       that identifier; a scanner's type field did not.
    3. Otherwise the engine's own type stands. We refuse a claim we can disprove, not
       every claim we cannot confirm.
    """
    purl = _string(raw.get("purl"))

    # ⚠ TWO DIFFERENT QUESTIONS, AND CONFLATING THEM DROPPED REAL MODELS.
    #
    # "Is this a model?" and "can enrichment look it up?" are not the same test.
    # `_model_reference` requires an `org/name` shape because a Hugging Face lookup
    # needs one. Requiring that shape HERE deleted every hosted-API model from the
    # inventory: ai-bom 3.1.0 maps `llm_provider` AND `model` alike to CycloneDX
    # `machine-learning-model` (`src/ai_bom/models.py` `ScanResult.to_cyclonedx`)
    # and ALWAYS mints a purl, defaulting to `pypi` (`_generate_purl`) — so a
    # project calling `client.chat.completions.create(model="gpt-4o")` produced a
    # component typed model, named `OpenAI Model`, carrying
    # `trusera:model_name: gpt-4o` and `purl: pkg:pypi/openai model`. No slash in
    # `gpt-4o`, a pypi purl, so it was demoted — and with no model surviving,
    # `_dependencies` is never built either, because the pipeline builds it inside
    # the per-model loop. The customer's GPT-4o usage existed nowhere in the
    # document.
    #
    # An asserted model identifier is positive evidence FULL STOP: the engine put
    # it in a dedicated property, which is a deliberate statement, not a guess.
    # The `name` fallback still does not count — a library published as
    # `huggingface/transformers` must not rescue itself with a slash in its own
    # display name.
    asserted = purl.startswith("pkg:huggingface/") or bool(asserted_model_id(properties))
    if asserted:
        return "model", ""

    name = _string(raw.get("name"))

    # A committed weights file is a model whatever its purl says. ai-bom's
    # model-file scanner names the component after the file, so the purl it then
    # derives (`pkg:pypi/model.safetensors`) describes no package at all.
    if _looks_like_weights_file(name):
        return "model", ""

    ecosystem = package_purl_type(purl)
    if not ecosystem and looks_like_model_reference(_model_reference(raw, properties)):
        # Nothing contradicts it, so the name-derived reference stands.
        return "model", ""

    # ⚠ ONLY A PURL THE ENGINE DID NOT INVENT COUNTS AS EVIDENCE.
    #
    # ai-bom mints every purl from the component's own display name
    # (`_generate_purl`: `component.name.lower().replace("_","-")`, type defaulting
    # to `pypi`), so `pkg:pypi/huggingface transformers` is not something PyPI
    # asserted — it is the label, lowercased, with a prefix. Treating that as "the
    # ecosystem's own claim about what this is" would be believing the engine twice
    # and calling it corroboration.
    #
    # So the demotion fires only when the purl adds NOTHING the name did not
    # already say. That is precisely the `transformers` case this rule was written
    # for, and it leaves alone a component whose purl genuinely points somewhere
    # else.
    if ecosystem and _purl_derived_from_name(purl, name):
        label = name or "an unnamed component"
        return "framework", (
            f"{label} was reported as a model but names no model, and its "
            f"{ecosystem} identifier ({purl}) is derived from that same name, so it "
            f"is recorded as an AI dependency rather than an AI model."
        )

    return "model", ""


#: Extensions that make a component a set of weights rather than a package.
_WEIGHTS_SUFFIXES = (
    ".safetensors",
    ".gguf",
    ".ggml",
    ".onnx",
    ".pt",
    ".pth",
    ".bin",
    ".h5",
    ".pb",
    ".tflite",
)


def _looks_like_weights_file(name: str) -> bool:
    return name.lower().endswith(_WEIGHTS_SUFFIXES)


def _purl_derived_from_name(purl: str, name: str) -> bool:
    """Did the engine mint this purl out of the component's own display name?

    Mirrors ai-bom 3.1.0's `_generate_purl` exactly — `name.lower().replace("_","-")`
    — because the question is not "is this a plausible package name" but "did this
    identifier come from anywhere other than the label we already have".
    """
    if not name:
        return False
    package = purl.removeprefix("pkg:").partition("/")[2].split("@", 1)[0].split("?", 1)[0]
    package = package.lower()
    normalized = name.lower().replace("_", "-")
    if package == normalized:
        return True
    # ⚠ ALSO THE LAST SEGMENT, so a library published under a slashed display name
    # cannot escape by making its own name look like an `org/name` reference:
    # `huggingface/transformers` against `pkg:pypi/transformers` is the same
    # package saying the same thing twice.
    return package == normalized.rsplit("/", 1)[-1]


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
            "assets": [],
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
            resolved, reason = classify_component(raw, properties)
            if reason:
                diagnostics.append(
                    {
                        "severity": "info",
                        "code": "AIBOM_MODEL_RECLASSIFIED",
                        "message": reason,
                    }
                )
            if resolved == "model":
                models.append(_model_usage(raw, properties))
                surfaces.add("model-refs")
            else:
                entry = _framework_usage(raw, properties)
                frameworks.append(entry)
                surfaces.add(entry["surface"])
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
        # ⚠ AN MCP SERVER IS BOTH, AND RECORDING IT ONLY AS A DEPENDENCY LOSES
        # THE HALF THAT MATTERS. It is a package, so it belongs in the software
        # dependency list; it is also the surface through which a model takes
        # ACTIONS rather than producing text, which is a governance question no
        # dependency row asks. ai-bom is the only engine that classifies them,
        # and before this they were invisible to `normalize.ai_assets` — so the
        # operational profile's agents/tools/MCP element could only ever read
        # zero, which measures us rather than the customer.
        "assets": [
            {
                "asset_type": shared.ASSET_MCP_SERVER,
                "name": f["name"],
                "provider": f.get("provider", ""),
                "locations": list(f.get("locations") or []),
            }
            for f in frameworks
            if f.get("surface") == "mcp-servers" and f.get("name")
        ],
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
        # The engine's own identifier for the model, any shape — `gpt-4o` as
        # readily as `meta-llama/Llama-3-8B`. The identity ladder's api tier and
        # Table 10 element 01 both prefer it over the component's display label.
        "model_id": asserted_model_id(properties),
        "name": _string(raw.get("name")),
        "version": _string(raw.get("version")),
        "provider": properties.get("provider", ""),
        "framework": properties.get("framework", ""),
        "locations": _locations(raw, properties),
        "purl": _usable_purl(raw),
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
        "purl": _usable_purl(raw),
        "category": properties.get("category", ""),
        "surface": _surface_for(name, properties),
        "locations": _locations(raw, properties),
    }


def _usable_purl(raw: dict[str, Any]) -> str:
    """The component's purl, or empty if it is not one. Never a malformed key."""
    purl = _string(raw.get("purl"))
    return purl if valid_purl(purl) else ""


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


#: Property names that have carried a model identifier across ai-bom releases.
#:
#: ⚠ `model_name` IS NOT OPTIONAL HERE, AND LEAVING IT OUT COST US EVERY LOOKUP.
#: ai-bom 3.1.0 emits the real Hugging Face id as `trusera:model_name` — verified
#: against captured output in `workers/aibom/testdata/`, where the only model in
#: the repository (`meta-llama/Llama-3-8B`) appeared under exactly that name and
#: under no other. Reading only `model_id`/`huggingface_id` meant `model_ref` was
#: always empty, enrichment had nothing to key on, and three components named
#: after the `transformers` LIBRARY were stored as three separate AI models.
_MODEL_REF_PROPERTIES = ("model_id", "huggingface_id", "model_name")


def looks_like_model_reference(value: str) -> bool:
    """Is this string shaped like a model identifier, rather than a display name?

    ⚠ THE `org/name` SHAPE IS THE WHOLE TEST, AND IT HAS TO BE, because
    `model_name` is a name in some tools and an id in others. `meta-llama/Llama-3-8B`
    is a reference; `HuggingFace Transformers Model` is a label somebody typed. A
    label sent to enrichment either resolves to nothing or — worse — resolves to a
    DIFFERENT model whose licence we would then attribute to the customer's.
    """
    if not value or "/" not in value:
        return False
    if any(c.isspace() for c in value):
        return False
    # `org/` and `/name` are both half an id, and half an id is not an id.
    org, _, name = value.partition("/")
    return bool(org and name)


def asserted_model_id(properties: dict[str, str]) -> str:
    """The model identifier the engine deliberately reported, whatever its shape.

    ⚠ NOT SHAPE-CONSTRAINED, UNLIKE `_model_reference`. `gpt-4o` is a complete and
    correct model identifier; it is simply not a Hugging Face repository path. This
    is what says "the engine told us which model"; `_model_reference` answers the
    narrower question of whether enrichment can resolve it upstream.
    """
    for key in _MODEL_REF_PROPERTIES:
        value = _string(properties.get(key))
        if value:
            return value
    return ""


def _model_reference(raw: dict[str, Any], properties: dict[str, str]) -> str:
    """The identity enrichment will look up.

    ⚠ A HUGGING FACE ID IS `org/name`, AND THAT IS WHAT ENRICHMENT NEEDS. A bare
    name resolves to nothing, so a reference we cannot form is left EMPTY rather
    than approximated — an approximate id fetches the wrong model card, and its
    licence would then be attributed to the customer's model.
    """
    for key in _MODEL_REF_PROPERTIES:
        candidate = _string(properties.get(key))
        if looks_like_model_reference(candidate):
            return candidate

    purl = _string(raw.get("purl"))
    if purl.startswith("pkg:huggingface/"):
        rest = purl.removeprefix("pkg:huggingface/").split("?", 1)[0]
        return rest.split("@", 1)[0]

    name = _string(raw.get("name"))
    return name if looks_like_model_reference(name) else ""


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


#: Property names ai-bom has used to say where it saw something.
_LOCATION_PROPERTIES = ("source_location", "location")


def _locations(raw: dict[str, Any], properties: dict[str, str] | None = None) -> list[str]:
    """Everywhere the engine says it saw this, from BOTH places it might say it.

    ⚠ ai-bom 3.1.0 EMITS NO `evidence` BLOCK AT ALL. It reports the position as a
    `trusera:source_location` property — `/src/app.py:4` in captured output. Reading
    only CycloneDX's standard `evidence.occurrences[].location` therefore discarded
    every location the engine gave us, on every scan, silently: the field is optional,
    so an empty list is indistinguishable from "the tool said nothing".

    Both are recorded verbatim except for the sandbox mount point, which is
    stripped — see `discovery.repo_path`. ai-bom echoes `/src/` (where the runner
    mounts the tree) and airom does not, so a model both engines found carried two
    spellings of one file and read like two. A value like `dependency files` is not
    a file:line and is not turned into one — it is what the engine said, rendered
    as the engine said it. Inventing a path we were not given is the failure this
    whole module guards.
    """
    out: list[str] = []

    evidence = raw.get("evidence")
    if isinstance(evidence, dict):
        occurrences = evidence.get("occurrences")
        if isinstance(occurrences, list):
            for o in occurrences:
                if isinstance(o, dict):
                    location = _string(o.get("location"))
                    if location:
                        out.append(shared.repo_path(location))

    for key in _LOCATION_PROPERTIES:
        location = _string((properties or {}).get(key))
        if location:
            out.append(shared.repo_path(location))

    return sorted(set(out))


def valid_purl(value: str) -> bool:
    """Is this a syntactically usable Package URL?

    ⚠ ai-bom EMITS PURLS CONTAINING LITERAL SPACES — `pkg:pypi/huggingface transformers`
    is verbatim from captured output. A purl is the merge key for everything downstream
    (CLAUDE.md invariant 4), so accepting one that no other engine could ever produce
    creates a component that can never match, never dedup, and never link to its SBOM
    entry — while looking exactly like a real identifier in the report.

    Deliberately a shape check, not a full grammar: the goal is to refuse what is
    obviously not a purl, not to reimplement the spec and reject something valid.
    """
    if not value.startswith("pkg:"):
        return False
    if any(c.isspace() for c in value):
        return False
    remainder = value.removeprefix("pkg:")
    ptype, sep, rest = remainder.partition("/")
    return bool(ptype and sep and rest.split("@", 1)[0].split("?", 1)[0])


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
