"""cdxgen `-t ai` — a second, independent AI inventory.

⚠ THE SAME BINARY AS THE SBOM ENGINE, A DIFFERENT ENGINE ID, AND THAT IS THE
ESTABLISHED PATTERN HERE. `syft` and `syft-spdx` already share one digest-pinned
image and differ only in argv; this is the third. Nothing new is pulled, nothing
new is pinned, and Engine Coverage still reports the two runs separately —
because they cover different things and can fail independently.

⚠ WHAT IT ADDS OVER ai-bom AND airom, measured on the same tree
(`testdata/cdxgen-ai-ai-langchain.cdx.json` against `testdata/ai-langchain/`):

  * it emits `pkg:huggingface/meta-llama/Llama-3-8B` — a real, correctly-cased
    model purl, which is tier 1 of the identity ladder. ai-bom emits no purl for
    that model and airom lowercases the name.
  * it attributes `gpt-4o` to `openai` (ai-bom says `langchain`), which is what
    puts that model on the ladder's `api:` tier instead of the `name:` tier.
  * it reports the INFERENCE SERVICES a repository talks to as `services[]`,
    which neither other engine emits at all.

⚠ ITS `pkg:generic/...` PURL IS NOT IDENTITY. `gpt-4o` arrives as
`pkg:generic/openai/gpt-4o` — cdxgen minting a purl for something that has no
package. `pkg:generic` is in `discovery.PACKAGE_PURL_TYPES` precisely so it
cannot be mistaken for a model identifier; the provider and the asserted model id
are what the ladder reads.

⚠ `--no-install-deps` IS MANDATORY, FOR THE REASON cdxgen.py RECORDS AT LENGTH:
the flag defaults to TRUE and the tool otherwise runs `npm install` over the
customer's source, which CLAUDE.md invariant 7 forbids outright and which cannot
work in a container with no network anyway.
"""

from __future__ import annotations

from typing import Any

from axebom_shared.adapters.base import Capabilities, GenerateResult, ResultStatus, ScanTarget
from axebom_shared.adapters.summary import count_cyclonedx, summarize
from axebom_shared.sandbox import SandboxResult, WorkspaceLayout

from ...sbom.adapters.common import SandboxedAdapter
from .. import discovery as shared

CAPABILITIES = Capabilities(
    engine_id="cdxgen-ai",
    families=("aibom",),
    source_kinds=("git", "upload"),
    produces=("ai_models", "ai_assets"),
    native_format="cyclonedx-json-1.6",
    ecosystems=("model-refs", "inference-services", "prompts"),
    default_weight=4,
)

#: `cdx:ai:kind` values that name a MODEL.
_MODEL_KINDS = frozenset({"model", "embedding-model", "llm"})

#: `cdx:ai:kind` -> the `normalize.ai_assets.asset_type` it becomes.
_ASSET_KINDS = {
    "prompt-config-file": shared.ASSET_PROMPT,
    "prompt": shared.ASSET_PROMPT,
    "prompt-template": shared.ASSET_PROMPT,
    "vector-store": shared.ASSET_VECTOR_STORE,
    "dataset": shared.ASSET_DATASET,
    "agent": shared.ASSET_AGENT,
    "tool": shared.ASSET_TOOL,
    "mcp-server": shared.ASSET_MCP_SERVER,
}

_SURFACE_OF = {
    shared.ASSET_PROMPT: "prompts",
    shared.ASSET_VECTOR_STORE: "vector-stores",
    shared.ASSET_DATASET: "datasets",
    shared.ASSET_AGENT: "agents",
    shared.ASSET_TOOL: "tools",
    shared.ASSET_MCP_SERVER: "mcp-servers",
}


class CdxgenAIAdapter(SandboxedAdapter):
    """Runs cdxgen in AI mode over a source tree."""

    media_type = "application/vnd.cyclonedx+json; version=1.6"
    requires_db_version = False

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(CAPABILITIES, **kwargs)

    def build_argv(self, target: ScanTarget, layout: WorkspaceLayout) -> list[str]:
        """`-t ai`, otherwise the SBOM adapter's argv verbatim — and for its reasons.

        `-o /dev/stdout` because every sandbox mount is read-only; the
        `--spec-version 1.6` pin because a newer spec parses into silently fewer
        fields downstream rather than failing; `--no-install-deps` because the
        flag defaults to true and the alternative is package-manager resolution
        over untrusted source.
        """
        return [
            "-r",
            layout.container_source,
            "-t",
            "ai",
            "-o",
            "/dev/stdout",
            "--spec-version",
            "1.6",
            "--no-banner",
            "--no-install-deps",
        ]

    def extra_env(self, layout: WorkspaceLayout) -> dict[str, str]:
        """Identical to the SBOM adapter's, and it has to be.

        Every variable there exists because a live run failed without it — a
        read-only rootfs, a hardcoded `/tmp/cdxgen-temp` fallback, a tool that
        deletes the temp directory it was handed, and a licence fetcher stalling
        against `--network=none`. None of that changes with `-t ai`;
        `workers/sbom/adapters/cdxgen.py::extra_env` carries the full account.
        """
        return {
            "FETCH_LICENSE": "false",
            "CDXGEN_DEBUG_MODE": "quiet",
            "TMPDIR": layout.container_scratch,
            "CDXGEN_TEMP_DIR": f"{layout.container_scratch}/cdxgen-temp",
            "CDXGEN_TMP_DIR": f"{layout.container_scratch}/cdxgen-temp",
            "CDXGEN_CACHE_DIR": f"{layout.container_scratch}/cdxgen-cache",
        }

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
                    "message": "cdxgen returned a document that is not a JSON object",
                }
            )
            return base

        found = extract_cdxgen_ai_discovery(payload)
        base.diagnostics.extend(found["diagnostics"])
        base.ecosystems_covered = sorted(found["surfaces"])
        base.discoveries = shared.counts(found)
        base.summary = summarize(self.capabilities, count_cyclonedx(payload))

        if not (found["models"] or found["assets"]):
            base.status = ResultStatus.SUCCEEDED
            base.diagnostics.append(
                {
                    "severity": "info",
                    "code": "ENGINE_ZERO_RESULTS",
                    "message": "cdxgen found no AI models, prompts or inference services",
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


def extract_cdxgen_ai_discovery(payload: dict[str, Any]) -> dict[str, Any]:
    """Read cdxgen's AI document into the shared discovery shape.

    Returns `models`, `frameworks`, `assets`, `surfaces` and `diagnostics`.
    `frameworks` is always empty: `-t ai` catalogues AI usage, and the software
    dependency graph is the SBOM family's answer, produced by the same binary in
    its other mode. Inventing dependencies here would duplicate a real inventory
    with a weaker one.
    """
    models: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    surfaces: set[str] = set()
    unknown_kinds: dict[str, int] = {}
    skipped = 0

    components = payload.get("components")
    if not isinstance(components, list):
        components = []
        diagnostics.append(
            {
                "severity": "warn",
                "code": "ENGINE_OUTPUT_UNEXPECTED",
                "message": "cdxgen AI output has no `components` array",
            }
        )

    for raw in components:
        if not isinstance(raw, dict):
            skipped += 1
            continue

        props = shared.properties(raw)
        kind = props.get("ai:kind", "") or props.get("kind", "")
        kind = kind.strip().lower()

        if kind in _MODEL_KINDS:
            models.append(_model_usage(raw, props))
            surfaces.add("model-refs")
        elif kind in _ASSET_KINDS:
            asset_type = _ASSET_KINDS[kind]
            assets.append(_asset(raw, props, asset_type))
            surfaces.add(_SURFACE_OF.get(asset_type, asset_type))
        elif kind:
            unknown_kinds[kind] = unknown_kinds.get(kind, 0) + 1
        else:
            skipped += 1

    for service in _services(payload):
        assets.append(service)
        surfaces.add("inference-services")

    for kind, count in sorted(unknown_kinds.items()):
        diagnostics.append(
            {
                "severity": "warn",
                "code": "ENGINE_OUTPUT_UNEXPECTED",
                "message": (
                    f"cdxgen reported {count} AI component(s) of kind {kind!r}, which "
                    f"AxeBOM does not yet map to a model or an AI asset; they are not "
                    f"in this report"
                ),
            }
        )
    if skipped:
        diagnostics.append(
            {
                "severity": "warn",
                "code": "ENGINE_OUTPUT_UNEXPECTED",
                "message": (
                    f"{skipped} cdxgen component(s) carried no `cdx:ai:kind` and were skipped"
                ),
            }
        )

    return {
        "models": models,
        "frameworks": [],
        "assets": assets,
        "surfaces": surfaces,
        "diagnostics": diagnostics,
    }


def _model_usage(raw: dict[str, Any], props: dict[str, str]) -> dict[str, Any]:
    """One model reference, in the shape `merge` and `identity` already read."""
    purl = shared.text(raw.get("purl"))
    usable_purl = purl if shared.valid_purl(purl) and not shared.package_purl_type(purl) else ""
    # ⚠ THE HUGGING FACE PURL IS THE BEST REFERENCE ANY ENGINE GIVES US for this
    # tree — correctly cased, where airom lowercases and ai-bom emits none.
    hf_ref = shared.huggingface_ref_from_purl(purl)
    name = shared.text(raw.get("name"))
    return {
        "model_ref": hf_ref,
        # cdxgen names the model without its namespace (`Llama-3-8B`), so the
        # purl's `org/name` outranks it wherever both exist.
        "model_id": hf_ref or name,
        "name": name,
        "version": shared.text(raw.get("version")),
        "provider": props.get("ai:provider", "") or props.get("provider", ""),
        "framework": "",
        "locations": shared.occurrence_locations(raw),
        "purl": usable_purl,
        "bom_ref": shared.text(raw.get("bom-ref")),
        "model_family": props.get("ai:modelFamily".lower(), "") or props.get("modelfamily", ""),
        "engine_confidence_label": props.get("ai:confidence", "") or props.get("confidence", ""),
    }


def _asset(raw: dict[str, Any], props: dict[str, str], asset_type: str) -> dict[str, Any]:
    return {
        "asset_type": asset_type,
        "name": shared.text(raw.get("name")),
        "provider": props.get("ai:provider", "") or props.get("provider", ""),
        "locations": shared.occurrence_locations(raw),
        "bom_ref": shared.text(raw.get("bom-ref")),
    }


def _services(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """`services[]` — the inference endpoints the code talks to.

    ⚠ NEITHER OTHER AI ENGINE EMITS THESE, and they are a Table 10 element 09
    ("data source") fact in the operational sense: an application that calls
    `api.openai.com` sends data there. Recorded as `endpoint` assets, with the
    model each service serves kept as an attribute rather than turned into a
    second model row — the model is already a component and merging on it here
    would double-count it.
    """
    services = payload.get("services")
    if not isinstance(services, list):
        return []

    out: list[dict[str, Any]] = []
    for svc in services:
        if not isinstance(svc, dict):
            continue
        props = shared.properties(svc)
        if (props.get("ai:kind", "") or props.get("kind", "")).strip().lower() not in {
            "inference-service",
            "ai-service",
        }:
            continue
        provider = svc.get("provider")
        out.append(
            {
                "asset_type": shared.ASSET_ENDPOINT,
                "name": shared.text(svc.get("name")),
                "provider": (
                    shared.text(provider.get("name")) if isinstance(provider, dict) else ""
                )
                or shared.text(svc.get("group")),
                # cdxgen leaves `endpoints` empty for an implicitly-deployed
                # service: it saw the SDK call, not a URL. Recording an invented
                # endpoint would be the fabrication this product forbids.
                "locations": [],
                "bom_ref": shared.text(svc.get("bom-ref")),
                "serves_model": props.get("ai:modelid", "") or props.get("modelid", ""),
                "deployment": props.get("ai:deployment", "") or props.get("deployment", ""),
                "transport_security": props.get("ai:transportsecurity", "")
                or props.get("transportsecurity", ""),
            }
        )
    return out
