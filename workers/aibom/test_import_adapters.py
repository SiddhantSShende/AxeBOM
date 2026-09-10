"""An import engine may only read a document the CUSTOMER produced.

⚠ THIS FILE EXISTS BECAUSE THE OPPOSITE SHIPPED AND RAN. On a live AIBOM scan
of the ai-langchain fixture — which contains no GLaaS export and no Kubernetes
AIBOM custom resource — both `aibom-glaas` and `aibom-k8s-runtime` reported
`succeeded` with seven components. `scan.raw_artifacts` held three rows with one
identical sha256: `ai-bom`'s own output, imported twice more under two other
engine ids.

The cause is structural, not careless. The customer's upload is extracted into
the workspace ROOT, and `_publish_to_workspace` writes a producing engine's
output right beside it, so `ai-bom.cdx.json` sits next to their `README.md` and
is perfectly valid CycloneDX carrying `machine-learning-model` components. Every
check the importer had said yes.

What it costs is the whole point of an import engine. It exists to say "here is
what YOUR tooling reported"; echoing our own output manufactures agreement
between two engines that are one engine, and lights up `runtime-deployments` and
`training-runs` in Engine Coverage for a scan that saw neither. Invariant 12
rates a false negative a customer trusts above an honest gap.
"""

from __future__ import annotations

import json
from pathlib import Path

from workers.aibom.adapters import GLaaSImportAdapter, K8sAIBOMImportAdapter
from workers.sbom.adapters.common import WORKSPACE_PUBLISHED_ARTIFACTS

from axebom_shared.adapters.base import ResultStatus, ScanTarget

#: What `ai-bom` publishes into the shared workspace, in its own shape — the
#: producer AxeBOM ran, and AI components an importer is looking for.
_OUR_OUTPUT = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "metadata": {
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": "ai-bom",
                    "version": "3.1.0",
                    "manufacturer": {"name": "Trusera"},
                }
            ]
        }
    },
    "components": [
        {"type": "machine-learning-model", "name": "Llama-3-8B"},
        {"type": "machine-learning-model", "name": "gpt-4o"},
    ],
}

#: A real GLaaS export: the customer's own tool, naming itself.
_THEIR_EXPORT = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "metadata": {"tools": {"components": [{"type": "application", "name": "roar"}]}},
    "components": [{"type": "machine-learning-model", "name": "resnet-50"}],
}


def _workspace(tmp_path: Path, files: dict[str, dict]) -> ScanTarget:
    """A workspace shaped like a real one: the customer's source at the root."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("import langchain\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# an app\n", encoding="utf-8")
    for name, payload in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
    return ScanTarget(scan_id="s", job_id="j", kind="upload", workspace=tmp_path)


def test_our_own_engine_output_is_never_imported_as_the_customers(tmp_path) -> None:
    """The live failure, reproduced exactly."""
    target = _workspace(tmp_path, {"ai-bom.cdx.json": _OUR_OUTPUT})

    for adapter in (GLaaSImportAdapter(), K8sAIBOMImportAdapter()):
        result = adapter.generate(target)
        assert result.status is ResultStatus.UNAVAILABLE, (
            f"{adapter.engine_id} imported AxeBOM's own output and reported "
            f"{result.status}; on a live scan this produced three raw artifacts "
            f"with one sha256"
        )
        codes = {d.get("code") for d in result.diagnostics}
        assert "ENGINE_INPUT_MISSING" in codes, result.diagnostics


def test_the_rejection_survives_a_rename(tmp_path) -> None:
    """The name check and the producer check are independent on purpose.

    A customer whose own export happens to be called something else, or an
    engine that starts publishing under a new name, must not slip past — so the
    document is judged by what MADE it as well as by where it sits.
    """
    target = _workspace(tmp_path, {"exports/inventory.json": _OUR_OUTPUT})

    result = GLaaSImportAdapter().generate(target)
    assert result.status is ResultStatus.UNAVAILABLE, result.status
    codes = {d.get("code") for d in result.diagnostics}
    assert "AIBOM_IMPORT_IS_OUR_OWN_OUTPUT" in codes, result.diagnostics


def test_a_real_customer_export_is_still_imported(tmp_path) -> None:
    """The guard must not be so wide that the engine can never do its job.

    A rejection that swallowed genuine uploads would trade a fabricated claim
    for a silent gap, which is a different failure rather than a fix.
    """
    target = _workspace(tmp_path, {"glaas-export.json": _THEIR_EXPORT})

    result = GLaaSImportAdapter().generate(target)
    assert result.status is ResultStatus.SUCCEEDED, result.diagnostics
    # ⚠ THE SURFACES COME FROM THE DOCUMENT, NOT FROM THE ENGINE'S CAPABILITIES.
    # A GLaaS export that names one model covered model references and nothing
    # else; claiming `training-runs` because the ENGINE could in principle report
    # it would put a surface in Engine Coverage that this document never
    # described.
    assert result.ecosystems_covered == ["model-refs"], result.ecosystems_covered


def test_the_customers_own_producer_wins_over_a_shared_generator(tmp_path) -> None:
    """`roar` and `k8s-aibom` may embed a generator AxeBOM also runs.

    Refusing a genuine upload because it mentions cdxgen would lose real data
    over a substring, so naming THIS engine's expected producer settles it.
    """
    document = json.loads(json.dumps(_THEIR_EXPORT))
    document["metadata"]["tools"]["components"].append({"type": "application", "name": "cdxgen"})
    target = _workspace(tmp_path, {"glaas-export.json": document})

    result = GLaaSImportAdapter().generate(target)
    assert result.status is ResultStatus.SUCCEEDED, result.diagnostics


def test_our_output_beside_a_real_export_does_not_hide_it(tmp_path) -> None:
    """Skipping ours must not stop the walk.

    `_locate` returns the FIRST matching document, and `ai-bom.cdx.json` sorts
    before `glaas-export.json`. A `return` where a `continue` belongs would turn
    the fabrication into a silent gap — still wrong, and harder to notice.
    """
    target = _workspace(
        tmp_path,
        {"ai-bom.cdx.json": _OUR_OUTPUT, "glaas-export.json": _THEIR_EXPORT},
    )

    result = GLaaSImportAdapter().generate(target)
    assert result.status is ResultStatus.SUCCEEDED, result.diagnostics


def test_the_published_artifact_list_names_every_published_artifact() -> None:
    """The exclusion list must not drift behind the engines that publish.

    ⚠ THE DECLARATION IS `workspace_artifact_name` ON AN ADAPTER, and adding one
    is how a new engine shares its output. An engine that starts publishing under
    a name this set does not hold becomes importable again, silently — so the
    repository is read rather than trusted.
    """
    declared: set[str] = set()
    for path in Path("workers").rglob("*.py"):
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped.startswith("workspace_artifact_name"):
                continue
            _, _, value = stripped.partition("=")
            value = value.strip()
            if value.startswith(('"', "'")):
                declared.add(value.strip("\"'"))

    missing = declared - WORKSPACE_PUBLISHED_ARTIFACTS
    assert not missing, (
        f"these are published into the shared workspace and an import engine "
        f"would read them as customer documents: {sorted(missing)}"
    )
