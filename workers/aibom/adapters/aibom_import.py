"""AI BOM documents the CUSTOMER produced, imported rather than run.

⚠ THREE OF THE ELEVEN NAMED INTEGRATIONS ARE NOT SCANNERS, AND CALLING THEM
ONE WOULD MANUFACTURE COVERAGE OUT OF NOTHING.

    GoogleCloudPlatform/k8s-aibom   a Kubernetes CONTROLLER. It watches a live
                                    cluster and emits an `AIBOM` custom resource
                                    (CycloneDX 1.6). It has no scan CLI, it
                                    needs cluster credentials, and what it
                                    describes is a RUNNING deployment — which is
                                    the one thing a source scan cannot see.

    GLaaS + treqs/roar              `roar` traces a training run by EXECUTING
                                    the user's own command (`roar run python3
                                    train.py`). That is the single act CLAUDE.md
                                    invariant 7 forbids outright, and without a
                                    network it produces no BOM at all: the
                                    CycloneDX AI-BOM is generated server-side on
                                    glaas.ai, which has no public repository and
                                    is not self-hostable.

    0disoft/ai-bom-generator        discovers nothing. It reads an `aibom.toml`
                                    the customer WROTE and renders it. See
                                    `aibom_toml.py` — that one is a real scan of
                                    a committed file, so it lives apart from
                                    this.

An engine that reports back what the customer already told us, dressed as
discovery, is worse than no engine: invariant 12 rates a false negative a
customer trusts above an honest gap. So these arrive as UPLOADS, exactly the
shape `hbom-cdxgen-host` already established for a host inventory, and every
diagnostic says whose tool produced the document.

⚠ ONE PARSER, TWO ENGINE IDS, AND THAT IS NOT PADDING. Both documents are
CycloneDX with AI content, so writing two parsers would be two places for the
same bug. They are separate ids because they answer different questions — one
describes a RUNNING cluster, the other a TRAINING RUN — and Engine Coverage has
to be able to say which of those a report contains, and which it does not.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from workers.sbom.adapters.common import WORKSPACE_PUBLISHED_ARTIFACTS, ArtifactWriter

from axebom_shared.adapters.base import (
    Availability,
    Capabilities,
    EngineMode,
    GenerateResult,
    RawArtifact,
    ResultStatus,
    ScanTarget,
    ToolAdapterBase,
)
from axebom_shared.adapters.summary import summarize

from .. import discovery as shared

#: How the two origins describe themselves, so a document can be attributed to
#: the tool that made it rather than to whichever engine happened to read it.
#:
#: ⚠ MATCHED AGAINST `metadata.tools`, NOT ASSUMED FROM THE ENGINE ID. A
#: customer who uploads a roar export under the k8s engine gets told so, instead
#: of having their training-run BOM silently reported as a cluster inventory.
_PRODUCER_HINTS = {
    "aibom-k8s-runtime": ("k8s-aibom", "kubernetes", "aibom-controller"),
    "aibom-glaas": ("roar", "glaas", "treqs"),
}

#: Tool names that mean AxeBOM produced the document, not the customer.
#:
#: ⚠ THE SECOND HALF OF A FIX FOR A REAL FABRICATION, and it is deliberately
#: independent of the first. `WORKSPACE_PUBLISHED_ARTIFACTS` excludes by FILE
#: NAME, which is exact and cannot be argued with; this excludes by WHAT MADE
#: THE FILE, which survives a rename, a customer whose own upload happens to be
#: called `ai-bom.cdx.json`, and an engine that starts publishing somewhere new.
#: Either check alone would have caught the live failure; a scan is not the
#: place to find out which one was load-bearing.
#:
#: Matched against `metadata.tools` the same way `_PRODUCER_HINTS` is — these
#: are the names the engines AxeBOM runs write about themselves.
_OUR_OWN_TOOLS = ("trusera", "ai-bom", "airom", "cdxgen", "syft", "axebom")

#: Where a document may be found in an upload. Bounded: an upload is untrusted
#: and a full-tree walk over a hostile archive is a denial of service.
_MAX_FILES = 500

#: CycloneDX component types that carry AI content.
_AI_TYPES = frozenset({"machine-learning-model", "model", "data"})


def capabilities_for(engine_id: str, ecosystems: tuple[str, ...]) -> Capabilities:
    """One Capabilities per engine id, from one definition."""
    return Capabilities(
        engine_id=engine_id,
        families=("aibom",),
        # ⚠ UPLOAD ONLY. There is nothing to run and nothing to clone: the
        # document exists because the customer generated it somewhere AxeBOM
        # cannot reach — a live cluster, or a training run on their own machine.
        source_kinds=("upload",),
        produces=("ai_models", "ai_assets"),
        native_format="cyclonedx-json-1.6",
        ecosystems=ecosystems,
        db_backed=False,
        default_weight=2,
    )


class AIBOMImportAdapter(ToolAdapterBase):
    """Reads a customer-produced CycloneDX AI document."""

    media_type = "application/json"

    #: Set by each concrete subclass. Never defaulted: an importer that does not
    #: know which origin it is reporting cannot attribute the document.
    engine_id = ""
    origin_label = ""
    instruction = ""

    def __init__(self, *, artifact_dir: Any = None, **_: Any) -> None:
        super().__init__(capabilities_for(self.engine_id, self.ecosystems()))
        self._artifact_dir = artifact_dir

    @classmethod
    def ecosystems(cls) -> tuple[str, ...]:
        return ("model-refs",)

    def available(self) -> Availability:
        # ⚠ ALWAYS AVAILABLE, BECAUSE THERE IS NOTHING TO ACQUIRE. AxeBOM
        # implements this engine; the probe that resolves a container or a pip
        # package would report it unavailable while it works perfectly, which
        # shows in Engine Coverage as a false gap.
        return Availability(available=True, mode=EngineMode.INTERNAL)

    def generate(self, target: ScanTarget) -> GenerateResult:
        """Find and parse an uploaded CycloneDX AI document.

        Never raises. A missing, unreadable, non-JSON or non-AI document is a
        status plus a diagnostic naming exactly what was looked for and how to
        produce it.
        """
        document, raw, path, diagnostics = _locate(
            Path(target.workspace), target.root_subpath, self.engine_id
        )
        if document is None:
            return GenerateResult(
                status=ResultStatus.UNAVAILABLE,
                diagnostics=[
                    *diagnostics,
                    {
                        "severity": "warn",
                        "code": "ENGINE_INPUT_MISSING",
                        "message": (
                            f"no CycloneDX AI document was found in this upload for "
                            f"{self.origin_label}"
                        ),
                        "hint": self.instruction,
                    },
                ],
            )

        diagnostics.extend(_attribution(document, self.engine_id, self.origin_label, path))

        found = extract_import_discovery(document)
        diagnostics.extend(found["diagnostics"])
        artifact = self._write_artifact(raw)
        count = len(found["models"]) + len(found["assets"])

        if count == 0:
            return GenerateResult(
                status=ResultStatus.PARTIAL,
                artifacts=[artifact] if artifact else [],
                summary=summarize(self.capabilities, {"components": 0}),
                diagnostics=[
                    *diagnostics,
                    {
                        "severity": "warn",
                        "code": "ENGINE_ZERO_RESULTS",
                        "message": "the document declared no AI models or assets",
                        # ⚠ `partial`, NOT `succeeded`. Zero is a claim, and a
                        # silent zero is indistinguishable from a document whose
                        # shape we did not understand — the same reasoning
                        # `hbom-cdxgen-host` records for its own empty case.
                        "hint": (
                            "reported as partial rather than succeeded: an empty "
                            "AI document and one we failed to read look identical "
                            "from the outside"
                        ),
                    },
                ],
            )

        return GenerateResult(
            status=ResultStatus.SUCCEEDED,
            artifacts=[artifact] if artifact else [],
            ecosystems_covered=sorted(found["surfaces"]),
            summary=summarize(self.capabilities, {"components": count}),
            diagnostics=diagnostics,
        )

    def _write_artifact(self, raw: bytes) -> RawArtifact | None:
        if self._artifact_dir is None:
            return None
        try:
            # ⚠ THE CUSTOMER'S DOCUMENT, BYTE FOR BYTE. A re-serialized copy is
            # no longer the evidence they supplied, and evidence is what a raw
            # artifact IS (ADR-0003, invariant 10).
            return ArtifactWriter(output_dir=self._artifact_dir).write(
                f"{self.engine_id}.json", raw, self.media_type
            )
        except OSError:
            return None


class K8sAIBOMImportAdapter(AIBOMImportAdapter):
    """The `AIBOM` custom resource `GoogleCloudPlatform/k8s-aibom` emits."""

    engine_id = "aibom-k8s-runtime"
    origin_label = "a Kubernetes AIBOM controller"
    instruction = (
        "install GoogleCloudPlatform/k8s-aibom in the cluster you want documented, "
        "export the AIBOM custom resource it produces, and upload that file. AxeBOM "
        "does not reach your cluster and holds no cluster credentials."
    )

    @classmethod
    def ecosystems(cls) -> tuple[str, ...]:
        # ⚠ NAMED FOR WHAT IT COVERS: a RUNTIME deployment, which is the one
        # thing a source scan cannot see. Reusing `model-refs` alone would make
        # Engine Coverage claim the same surface a source engine already covers.
        return ("model-refs", "runtime-deployments")


class GLaaSImportAdapter(AIBOMImportAdapter):
    """A GLaaS / `roar` ML-BOM the customer downloaded."""

    engine_id = "aibom-glaas"
    origin_label = "GLaaS or the roar CLI"
    instruction = (
        "trace your training run with `roar run <command>` (set ROAR_NO_TELEMETRY=1), "
        "download the AI-BOM GLaaS generates, and upload that file. AxeBOM cannot run "
        "roar: it executes your own training command, which scan engines are forbidden "
        "from doing, and it produces nothing without network access to glaas.ai."
    )

    @classmethod
    def ecosystems(cls) -> tuple[str, ...]:
        return ("model-refs", "training-runs")


def extract_import_discovery(payload: dict[str, Any]) -> dict[str, Any]:
    """Read a customer-supplied CycloneDX AI document into the discovery shape.

    ⚠ THE SAME THREE BUCKETS EVERY OTHER AIBOM EXTRACTOR RETURNS. The normalize
    consumer dispatches on engine id and then treats every result identically;
    a fourth shape here would be a fourth thing for it to know.

    ⚠ AND NO `frameworks`. A runtime CR and a training trace describe models and
    the things around them; the software dependency graph is the SBOM family's
    answer, produced from the customer's own source. Inventing dependency rows
    from a document that was not a dependency scan would duplicate a real
    inventory with a weaker one.
    """
    models: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    surfaces: set[str] = set()
    skipped = 0

    components = payload.get("components")
    if not isinstance(components, list):
        components = []
        diagnostics.append(
            {
                "severity": "warn",
                "code": "ENGINE_OUTPUT_UNEXPECTED",
                "message": "the uploaded document has no `components` array",
            }
        )

    for raw in components:
        if not isinstance(raw, dict):
            skipped += 1
            continue
        kind = str(raw.get("type") or "").strip().lower()
        if kind not in _AI_TYPES:
            continue
        props = shared.properties(raw)

        if kind == "data":
            # A `data` component in an AI document is a dataset unless it says
            # otherwise. Recorded as an asset rather than guessed into a model.
            assets.append(
                {
                    "asset_type": shared.ASSET_DATASET,
                    "name": shared.text(raw.get("name")),
                    "provider": props.get("provider", ""),
                    "locations": shared.occurrence_locations(raw),
                }
            )
            surfaces.add("datasets")
            continue

        models.append(_imported_model(raw, props))
        surfaces.add("model-refs")

    for svc in payload.get("services") or []:
        if not isinstance(svc, dict):
            continue
        provider = svc.get("provider")
        assets.append(
            {
                "asset_type": shared.ASSET_ENDPOINT,
                "name": shared.text(svc.get("name")),
                "provider": (
                    shared.text(provider.get("name")) if isinstance(provider, dict) else ""
                )
                or shared.text(svc.get("group")),
                "locations": [],
            }
        )
        surfaces.add("inference-services")

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
        "frameworks": [],
        "assets": assets,
        "surfaces": surfaces,
        "diagnostics": diagnostics,
    }


def _imported_model(raw: dict[str, Any], props: dict[str, str]) -> dict[str, Any]:
    """One model, in the shape `merge` and `identity` already read."""
    purl = shared.text(raw.get("purl"))
    hf_ref = shared.huggingface_ref_from_purl(purl)
    name = shared.text(raw.get("name"))
    asserted = hf_ref or props.get("model.id", "") or props.get("modelid", "") or name
    return {
        "model_ref": asserted if shared.looks_like_model_reference(asserted) else "",
        "model_id": asserted,
        "name": name,
        "version": shared.text(raw.get("version")),
        "provider": props.get("provider", ""),
        "framework": "",
        # ⚠ EMPTY, AND THAT IS THE HONEST ANSWER. A cluster inventory and a
        # training trace have no source position to report — they never read the
        # repository. Minting one would be the fabrication this whole family
        # guards against.
        "locations": shared.occurrence_locations(raw),
        "purl": purl if shared.valid_purl(purl) and not shared.package_purl_type(purl) else "",
        "bom_ref": shared.text(raw.get("bom-ref")),
    }


def _attribution(
    document: dict[str, Any], engine_id: str, origin_label: str, path: str
) -> list[dict[str, Any]]:
    """Say which tool actually produced the document that was uploaded.

    ⚠ A DOCUMENT UPLOADED UNDER THE WRONG ENGINE IS STILL PARSED, AND SAID SO.
    Refusing it would lose real data over a filing mistake; parsing it silently
    would report a training-run BOM as a cluster inventory. The middle answer is
    to read it and name the mismatch.
    """
    tools = json.dumps((document.get("metadata") or {}).get("tools") or {}).lower()
    expected = _PRODUCER_HINTS.get(engine_id, ())
    if any(hint in tools for hint in expected):
        return []

    for other, hints in _PRODUCER_HINTS.items():
        if other != engine_id and any(hint in tools for hint in hints):
            return [
                {
                    "severity": "warn",
                    "code": "AIBOM_IMPORT_PRODUCER_MISMATCH",
                    "message": (
                        f"{path} names {other} as its producer, but it was imported as "
                        f"{origin_label}; it is parsed, and the two describe different "
                        f"things — a running deployment is not a training run"
                    ),
                }
            ]

    return [
        {
            "severity": "info",
            "code": "AIBOM_IMPORT_PRODUCER_UNKNOWN",
            "message": (
                f"{path} does not name a producer AxeBOM recognises in "
                f"`metadata.tools`; it is parsed as CycloneDX and attributed to "
                f"{origin_label} because that is the engine it was imported under"
            ),
        }
    ]


def _locate(
    root: Path, subpath: str, engine_id: str
) -> tuple[dict[str, Any] | None, bytes, str, list[dict[str, Any]]]:
    """Find the first CycloneDX document in the upload that carries AI content.

    ⚠ BOUNDED. An upload is untrusted, and an unbounded walk over a hostile
    archive is a denial of service against the worker — the same reasoning the
    fetcher's file-count cap already applies one step earlier.
    """
    base = root / subpath if subpath else root
    diagnostics: list[dict[str, Any]] = []
    if not base.is_dir():
        return None, b"", "", diagnostics

    seen = 0
    for path in sorted(base.rglob("*.json")):
        # ⚠ SKIPPED BEFORE IT IS EVEN READ, AND THIS IS NOT A TIDY-UP. The
        # customer's upload is extracted into the workspace ROOT, and the runner
        # publishes a producing engine's output right beside it — so
        # `ai-bom.cdx.json` sits in the same directory as their `README.md` and
        # is perfectly valid CycloneDX carrying machine-learning-model
        # components. Both import engines found it, imported it, and reported
        # AxeBOM's own discovery back as an independent customer-supplied
        # source: three raw artifacts with one sha256, and Engine Coverage
        # claiming surfaces nothing had looked at.
        if path.name in WORKSPACE_PUBLISHED_ARTIFACTS:
            continue
        seen += 1
        if seen > _MAX_FILES:
            diagnostics.append(
                {
                    "severity": "warn",
                    "code": "ENGINE_INPUT_TRUNCATED",
                    "message": (
                        f"stopped after examining {_MAX_FILES} JSON files; if the "
                        f"document is deeper in the archive, upload it on its own"
                    ),
                }
            )
            break
        try:
            raw = path.read_bytes()
            document = json.loads(raw)
        except (OSError, ValueError):
            continue
        if not isinstance(document, dict):
            continue
        if str(document.get("bomFormat") or "") != "CycloneDX":
            continue
        rel = str(path.relative_to(base))
        if _produced_by_axebom(document, engine_id):
            diagnostics.append(
                {
                    "severity": "warn",
                    "code": "AIBOM_IMPORT_IS_OUR_OWN_OUTPUT",
                    "message": (
                        f"{rel} was produced by an engine AxeBOM ran, not by your own "
                        f"tooling; it was skipped rather than imported"
                    ),
                    "hint": (
                        "an import engine reports what YOUR tooling found. Importing "
                        "our own output would show two engines agreeing when there is "
                        "only one"
                    ),
                }
            )
            continue
        if _carries_ai(document):
            return document, raw, rel, diagnostics
        diagnostics.append(
            {
                "severity": "info",
                "code": "AIBOM_IMPORT_NOT_AN_AI_DOCUMENT",
                "message": (
                    f"{rel} is CycloneDX but declares no AI components; it was "
                    f"skipped rather than reported as an empty AI BOM"
                ),
            }
        )

    return None, b"", "", diagnostics


def _produced_by_axebom(document: dict[str, Any], engine_id: str) -> bool:
    """Whether this document is an AxeBOM engine's own output.

    ⚠ A DOCUMENT WE MADE IS NOT EVIDENCE THE CUSTOMER SUPPLIED. Reading it back
    would report one engine's findings twice under two engine ids, which reads
    as corroboration and is not — and would light up `runtime-deployments` and
    `training-runs` in Engine Coverage for a scan that saw neither.

    ⚠ THE CUSTOMER'S OWN PRODUCER WINS. `roar` and `k8s-aibom` may well embed a
    generator we also run, and refusing a genuine upload because it mentions
    cdxgen would lose the customer real data over a substring. A document that
    names THIS engine's expected producer is theirs, whatever else it lists.
    """
    tools = json.dumps((document.get("metadata") or {}).get("tools") or {}).lower()
    if any(hint in tools for hint in _PRODUCER_HINTS.get(engine_id, ())):
        return False
    return any(name in tools for name in _OUR_OWN_TOOLS)


def _carries_ai(document: dict[str, Any]) -> bool:
    for c in document.get("components") or []:
        if isinstance(c, dict) and str(c.get("type") or "").lower() in _AI_TYPES:
            return True
    return bool(document.get("services"))
