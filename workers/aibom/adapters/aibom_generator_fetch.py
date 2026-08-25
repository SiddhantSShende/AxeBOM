"""The concrete `Fetcher` for `aibom_generator.enrich_models` — aibom-generator.

⚠ THIS RUNS OUTSIDE THE SCAN SANDBOX, LIKE THE MODULE IT FEEDS.

`aibom_generator.py`'s docstring already explains the boundary: this is a
network call to a public API over a model identifier, not a scan over
customer code, so `aibom-generator` (OWASP GenAI Security Project,
Apache-2.0) is installed as a TRUSTED dependency of the AIBOM worker's own
Python environment — see `deploy/docker/Dockerfile.worker` — never as
something the sandbox invokes.

`aibom-generator` publishes no console script or importable API worth calling
directly from here (see below); the documented invocation
(`docs/04-OSINT-INTEGRATION.md` §3) is a CLI call writing a file, exactly like
dependency-check's `file_output_command` pattern for sandboxed engines —
except here isolation is about the *subprocess*, not the sandbox: running it
out-of-process means a package installed under the top-level name `src`
(see below) never pollutes the worker's own long-lived interpreter, even
though it lives in the same site-packages.

⚠ TWO THINGS DISCOVERED BY ACTUALLY INSTALLING AND RUNNING THIS PACKAGE
(owasp-aibom-generator==1.0.2, commit 9b8056a66c03d4f6cf707059b83b21f97923c27b
of the `main` branch — there is no tagged release; see `unpinned_reason` in
OSINT/tools.manifest.yaml) THAT THE CODE BELOW EXISTS TO HANDLE:

1. IT FABRICATES A PLAUSIBLE-LOOKING COMPONENT FOR A MODEL THAT DOES NOT
   EXIST. `AIBOMService.generate_aibom()` never checks that the Hugging Face
   repository resolves before synthesising a component from guessed
   defaults — org parsed off the slug, architecture "transformer", task
   "text-generation", `version: "1.0"`, `supplier: {"name": "unknown"}`. Exit
   code 0, "Successfully generated CycloneDX 1.6 SBOM" logged, a real file
   written. Verified in this session against a deliberately nonexistent
   model id. Nothing in the CycloneDX shape distinguishes a fabricated
   component from a real one — `parse_model_card` cannot catch this after
   the fact — so this module verifies the model exists via
   `huggingface_hub.HfApi().model_info()` (the same SDK aibom-generator uses
   internally) BEFORE invoking aibom-generator at all.

2. THERE IS NO WAY TO PIN A REVISION, ANYWHERE. Not the CLI's argparse, not
   `CLIController.generate()`, not `AIBOMService.generate_aibom()` — all
   three were read against the real 1.0.2 source and none accepts a
   revision/ref/commit argument. It always reads the repository's default
   branch. `enrich_models` -> `ModelCache` already explains why serving the
   wrong revision's card is a compliance problem, not a convenience one
   ("a model at two revisions can carry two different licences"), so a
   `revision` other than "whatever is current" is refused here with a
   specific, diagnosable exception rather than silently served from the
   default branch under the pinned revision's name.

`enrich_models` (`aibom_generator.py:143`) already catches any exception
per-lookup and degrades that one model to `not-provided` without failing the
others or the scan — see its docstring — so nothing here needs its own
try/except swallowing. The two situations above are surfaced by simply
letting a clear, well-typed exception propagate.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from axebom_shared.errors import EngineOutputMalformedError, EngineUnavailableError

#: The documented invocation (docs/04-OSINT-INTEGRATION.md §3):
#: `python -m src.cli <hf-model-id> --output model.cdx.json`.
#:
#: Not a console-script name (`aibom`, per the package's own
#: `[project.scripts]`) and not an `import src...` in this process — see the
#: module docstring for why the subprocess boundary is deliberate here, not
#: incidental.
_MODULE = "src.cli"

_ENGINE_ID = "aibom-generator"

#: Revision spellings that mean "whatever the default branch currently is" —
#: the one thing aibom-generator can actually serve, since it never accepts a
#: revision argument at any layer.
_NO_PIN = frozenset({"", "main", "head"})


class RevisionNotSupportedError(EngineUnavailableError):
    """Raised when a caller asks aibom-generator to honour a specific revision.

    aibom-generator has no revision parameter anywhere in its public surface
    (checked against the real 1.0.2 source: the CLI's argparse, ``CLIController
    .generate``, and ``AIBOMService.generate_aibom`` all take a bare model id
    and nothing else) — it always reads the repository's default branch.
    Serving that data back under a DIFFERENT requested revision's name would
    attribute a licence or model card to the wrong point in the model's
    history, which is exactly the failure `ModelCache` already exists to
    prevent on the caching side. This is the same failure on the fetch side,
    refused rather than risked.
    """

    def __init__(self, model_ref: str, revision: str) -> None:
        super().__init__(
            _ENGINE_ID,
            f"cannot pin {model_ref!r} to revision {revision!r}: aibom-generator has no "
            "revision parameter at any layer (CLI, CLIController, AIBOMService) and always "
            "reads the repository's default branch",
        )


def fetch_model_card(model_ref: str, revision: str) -> dict[str, Any]:
    """The concrete `aibom_generator.Fetcher`: resolve one Hugging Face model
    id into aibom-generator's CycloneDX document.

    Matches the `Fetcher` protocol's `__call__(self, model_ref, revision)`
    signature exactly (as a bare function — `enrich_models` calls
    `fetch(ref, revision)`, and a function satisfies the protocol as well as a
    callable object does).

    Raises rather than returning a degraded result — see the module
    docstring for why both raise paths below (revision, existence) matter,
    and `aibom_generator.enrich_models` for why the caller does not need its
    own error handling around this.
    """
    pinned = (revision or "").strip()
    if pinned.lower() not in _NO_PIN:
        raise RevisionNotSupportedError(model_ref, pinned)

    _assert_model_exists(model_ref)

    with tempfile.TemporaryDirectory(prefix="aibom-generator-") as tmp:
        output_path = Path(tmp) / "model.cdx.json"
        proc = subprocess.run(
            [sys.executable, "-m", _MODULE, model_ref, "--output", str(output_path)],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )

        if not output_path.exists():
            stderr_tail = proc.stderr.strip()[-800:]
            if "No module named" in stderr_tail:
                # The package (or a stray same-name `src` shadowing it — see
                # the module docstring on why the top-level name is a genuine
                # risk) is not importable in this interpreter at all.
                raise EngineUnavailableError(
                    _ENGINE_ID,
                    "aibom-generator is not installed in this environment "
                    f"(`python -m {_MODULE}` failed: {stderr_tail or 'no output'})",
                )
            raise EngineOutputMalformedError(
                _ENGINE_ID,
                f"produced no output file for {model_ref!r} (exit {proc.returncode}): "
                f"{stderr_tail or 'no stderr'}",
            )

        try:
            return json.loads(output_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise EngineOutputMalformedError(
                _ENGINE_ID,
                f"output file for {model_ref!r} was not valid JSON: {exc}",
                artifact=str(output_path),
            ) from exc


def _assert_model_exists(model_ref: str) -> None:
    """Verify the model resolves on the Hub before aibom-generator runs.

    ⚠ THIS IS THE ONLY GUARD AGAINST THE FABRICATED-PLACEHOLDER BUG.

    `huggingface_hub` is already a transitive dependency of aibom-generator —
    it is the SDK aibom-generator itself uses to talk to the Hub — so nothing
    new is being introduced; this calls the identical library aibom-generator
    would use, ahead of it, purely to fail loudly on a model that does not
    exist instead of letting aibom-generator invent one that "succeeds".

    Raises the native `huggingface_hub` exception on a missing or gated
    repository (`RepositoryNotFoundError`, `GatedRepoError`, ...) rather than
    wrapping it: `enrich_models` reports `type(exc).__name__` in its
    diagnostic, and the native exception name is already the informative
    answer to "why didn't this model enrich".
    """
    try:
        from huggingface_hub import HfApi
    except ImportError as exc:
        raise EngineUnavailableError(
            _ENGINE_ID, f"huggingface_hub is not installed: {exc}"
        ) from exc

    HfApi().model_info(model_ref)
