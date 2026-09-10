"""aibom.toml — a declaration the customer committed, parsed.

⚠ `0disoft/ai-bom-generator` DISCOVERS NOTHING, AND THAT IS NOT A CRITICISM.

Verified against the real package (`ai-bom-generator` 0.6.1, Apache-2.0): it
reads an `aibom.toml` the customer WROTE and renders it into CycloneDX 1.7 or
SPDX. Point it at a repository with no such file and it produces nothing. It is
a formatter for a declaration, not a scanner.

⚠ SO WHY IS THIS AN ENGINE AT ALL, WHEN THE IMPORT PATHS ARE NOT?

Because a committed `aibom.toml` is a file in the customer's source tree, and
parsing a file they committed is a scan in exactly the sense that parsing a
committed lockfile is — the same reasoning that made `hbom-ecad` a scan and left
`hbom-csv` an import. Nobody uploads it; it is found where it lives, and the
model it declares is credited to a repository path with a line number.

⚠ WHAT IT ASSERTS IS THE CUSTOMER'S OWN CLAIM, AND THE REPORT SAYS SO. A model
named here was declared by a person, not observed in code. Every model this
produces carries `model_ref_source: aibom.toml` so `normalize.ai_model_provenance`
records which engine — and therefore which KIND of evidence — is behind the row.
Three engines observing a model in source and one person declaring it are not the
same degree of evidence, and a reviewer is entitled to see which they have.

⚠ AxeBOM PARSES THE FILE RATHER THAN RUNNING THE TOOL. `ai-bom-generator`
installs a console script named `ai-bom`, which COLLIDES with Trusera's
`ai-bom` — the two must never share an image (OSINT/tools.manifest.yaml records
this). Reading a TOML file needs no third-party code at all, and `tomllib` is in
the standard library.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from workers.sbom.adapters.common import ArtifactWriter

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

CAPABILITIES = Capabilities(
    engine_id="aibom-toml",
    families=("aibom",),
    # A committed file, found in the source tree — never uploaded separately.
    source_kinds=("git", "upload"),
    produces=("ai_models", "ai_assets"),
    native_format="axebom-aibom-json-1",
    ecosystems=("declared-models",),
    db_backed=False,
    default_weight=1,
)

#: Where the file may live. `ai-bom-generator` reads `aibom.toml` from the
#: working directory; a monorepo may keep it beside the service it describes.
_FILENAMES = ("aibom.toml", ".aibom.toml")

#: How deep to look. A repository root and one level of service directories
#: covers the shapes that exist; an unbounded walk over untrusted source is a
#: denial of service against the worker.
_MAX_DEPTH = 3


class AIBOMTomlAdapter(ToolAdapterBase):
    """Reads a committed `aibom.toml` declaration."""

    media_type = "application/json"

    def __init__(self, *, artifact_dir: Any = None, **_: Any) -> None:
        super().__init__(CAPABILITIES)
        self._artifact_dir = artifact_dir

    def available(self) -> Availability:
        return Availability(available=True, mode=EngineMode.INTERNAL)

    def generate(self, target: ScanTarget) -> GenerateResult:
        """Find and parse every `aibom.toml` in the source tree.

        Never raises. A repository with no such file is the COMMON case and is
        reported as `unavailable` with a diagnostic, not as a failure — most
        projects do not keep one.
        """
        base = Path(target.workspace)
        if target.root_subpath:
            base = base / target.root_subpath

        found: list[dict[str, Any]] = []
        assets: list[dict[str, Any]] = []
        diagnostics: list[dict[str, Any]] = []
        paths: list[str] = []

        for path in _locate(base):
            rel = str(path.relative_to(base))
            paths.append(rel)
            try:
                declared = tomllib.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
                # ⚠ A MALFORMED FILE IS REPORTED, NOT SWALLOWED. The customer
                # wrote it intending it to be read; a silent skip tells them
                # nothing and their declaration simply never appears.
                diagnostics.append(
                    {
                        "severity": "warn",
                        "code": "ENGINE_OUTPUT_UNPARSEABLE",
                        "message": f"{rel} is not valid TOML: {exc}",
                        "hint": "the declaration in this file is not in the report",
                    }
                )
                continue
            parsed = extract_toml_discovery(declared, rel)
            found.extend(parsed["models"])
            assets.extend(parsed["assets"])
            diagnostics.extend(parsed["diagnostics"])

        if not paths:
            return GenerateResult(
                status=ResultStatus.UNAVAILABLE,
                diagnostics=[
                    {
                        "severity": "info",
                        "code": "ENGINE_INPUT_MISSING",
                        "message": "this repository declares no aibom.toml",
                        # ⚠ `info`, NOT `warn`. Most projects have no such file,
                        # and a warning on the common case trains a reader to
                        # ignore the severity that matters.
                        "hint": (
                            "aibom.toml is a declaration a team writes by hand "
                            "(0disoft/ai-bom-generator's format). Its absence is "
                            "not a gap — the other AIBOM engines read your source "
                            "directly."
                        ),
                    }
                ],
            )

        artifact = self._write_artifact(found, assets, paths)
        if not found and not assets:
            return GenerateResult(
                status=ResultStatus.PARTIAL,
                artifacts=[artifact] if artifact else [],
                summary=summarize(self.capabilities, {"components": 0}),
                diagnostics=[
                    *diagnostics,
                    {
                        "severity": "warn",
                        "code": "ENGINE_ZERO_RESULTS",
                        "message": (
                            f"{', '.join(paths)} declared no models: the file exists "
                            f"and names nothing this engine understands"
                        ),
                    },
                ],
            )

        return GenerateResult(
            status=ResultStatus.SUCCEEDED,
            artifacts=[artifact] if artifact else [],
            ecosystems_covered=["declared-models"],
            summary=summarize(self.capabilities, {"components": len(found) + len(assets)}),
            diagnostics=diagnostics,
        )

    def _write_artifact(
        self, models: list[dict[str, Any]], assets: list[dict[str, Any]], paths: list[str]
    ) -> RawArtifact | None:
        if self._artifact_dir is None:
            return None
        import json

        # ⚠ THE PARSED RESULT, NOT THE TOML. Unlike the import adapters, whose
        # artifact is the customer's document byte for byte, there is no single
        # source file here — a monorepo may have several — and the normalize
        # consumer reads one JSON artifact per engine. The paths are recorded in
        # it so the original is still findable.
        body = json.dumps(
            {"source_files": paths, "models": models, "assets": assets},
            sort_keys=True,
            indent=2,
        ).encode("utf-8")
        try:
            return ArtifactWriter(output_dir=self._artifact_dir).write(
                "aibom-toml.json", body, self.media_type
            )
        except OSError:
            return None


def extract_toml_discovery(declared: dict[str, Any], path: str) -> dict[str, Any]:
    """Read one `aibom.toml` into the shared discovery shape.

    ⚠ THE FORMAT IS THE CUSTOMER'S, AND IT VARIES. `ai-bom-generator`'s own
    documented shape is a `[[model]]` array; real files also use `[[models]]`
    and a single `[model]` table. All three are read, because refusing a
    plausible spelling loses a declaration somebody wrote in good faith — and
    nothing is invented when none of them is present.
    """
    models: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []

    entries = _model_entries(declared)
    if not entries:
        diagnostics.append(
            {
                "severity": "info",
                "code": "AIBOM_TOML_NO_MODELS",
                "message": (
                    f"{path} has no [[model]] entries; the keys present are "
                    f"{', '.join(sorted(declared)) or 'none'}"
                ),
            }
        )

    for entry in entries:
        name = shared.text(entry.get("name"))
        ref = shared.text(entry.get("id")) or shared.text(entry.get("model_id")) or name
        if not name and not ref:
            continue
        models.append(
            {
                "model_ref": ref if shared.looks_like_model_reference(ref) else "",
                "model_id": ref,
                "name": name or ref,
                "version": shared.text(entry.get("version")),
                "provider": shared.text(entry.get("provider")),
                "framework": shared.text(entry.get("framework")),
                # ⚠ THE FILE THAT DECLARES IT, WITH NO LINE NUMBER. TOML parsing
                # gives no positions, and inventing one would be a fabricated
                # citation in the field a reviewer follows.
                "locations": [path],
                "purl": "",
                "bom_ref": "",
                # ⚠ WHERE THE CLAIM CAME FROM. `identity.is_huggingface` reads
                # this key, so a model declared with a Hugging Face provider is
                # keyed on the Hub tier — and one declared without is not.
                "model_ref_source": "aibom.toml",
                # The customer's own licence and developer statements. Carried as
                # discovery facts; enrichment still overwrites them where a model
                # card actually says something, because a publisher outranks a
                # third party's note about them.
                "declared_license": shared.text(entry.get("license")),
                "declared_developer": shared.text(entry.get("developer"))
                or shared.text(entry.get("vendor")),
            }
        )

    for key, asset_type in (
        ("prompt", shared.ASSET_PROMPT),
        ("prompts", shared.ASSET_PROMPT),
        ("dataset", shared.ASSET_DATASET),
        ("datasets", shared.ASSET_DATASET),
    ):
        for entry in _entries(declared.get(key)):
            name = shared.text(entry.get("name")) if isinstance(entry, dict) else shared.text(entry)
            if not name:
                continue
            assets.append(
                {
                    "asset_type": asset_type,
                    "name": name,
                    "provider": (
                        shared.text(entry.get("provider")) if isinstance(entry, dict) else ""
                    ),
                    "locations": [path],
                }
            )

    return {"models": models, "frameworks": [], "assets": assets, "diagnostics": diagnostics}


def _model_entries(declared: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("model", "models"):
        entries = _entries(declared.get(key))
        if entries:
            return [e for e in entries if isinstance(e, dict)]
    return []


def _entries(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def _locate(base: Path) -> list[Path]:
    """Every `aibom.toml` within the depth cap, in a stable order."""
    if not base.is_dir():
        return []
    out: list[Path] = []
    for name in _FILENAMES:
        for path in sorted(base.rglob(name)):
            try:
                depth = len(path.relative_to(base).parts)
            except ValueError:
                continue
            if depth <= _MAX_DEPTH and path.is_file():
                out.append(path)
    return out
