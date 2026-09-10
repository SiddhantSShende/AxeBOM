"""The enrichment worker: cache behaviour, failure isolation, and the guard that
keeps a third-party telemetry push out of a compliance product.

Every test here runs offline — `fetch` is injected, exactly as
`aibom_generator.enrich_models` takes its `Fetcher`, so nothing in this suite
touches Hugging Face.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pytest
from workers.aienrich.cache import CardCache
from workers.aienrich.runner import (
    ARTIFACT_NAME,
    DISCOVERY_ARTIFACT,
    EnrichmentWorker,
    assert_no_telemetry_token,
    enrich,
)

REAL_DISCOVERY = (
    Path(__file__).resolve().parents[1] / "aibom" / "testdata" / "ai-bom-langchain-llama3.cdx.json"
)


@pytest.fixture
def tmp_root():
    root = Path(tempfile.mkdtemp())
    yield root
    shutil.rmtree(root, ignore_errors=True)


def card(ref: str) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "components": [{"type": "machine-learning-model", "name": ref}],
    }


# ---------------------------------------------------------------------------
# The telemetry guard
# ---------------------------------------------------------------------------


def test_a_hugging_face_token_is_refused_at_startup(monkeypatch) -> None:
    """⚠ `owasp-aibom-generator` PUSHES EVERY MODEL ID IT SEES TO A HARDCODED
    THIRD-PARTY DATASET WHEN A TOKEN IS PRESENT.

    Read out of its own `src/utils/analytics.py` and `src/config.py`, not
    inferred. Setting a token is the obvious fix for Hugging Face's anonymous
    rate limit, and doing it would publish the name of every AI model in every
    customer repository AxeBOM scans.
    """
    monkeypatch.setenv("HF_TOKEN", "hf_something")
    with pytest.raises(RuntimeError, match="third-party"):
        assert_no_telemetry_token()


def test_the_other_spelling_of_the_token_is_refused_too(monkeypatch) -> None:
    """`huggingface_hub` reads HUGGING_FACE_HUB_TOKEN as well; guarding one
    spelling and not the other would be a guard that looks present and is not."""
    monkeypatch.setenv("HUGGING_FACE_HUB_TOKEN", "hf_something")
    with pytest.raises(RuntimeError):
        assert_no_telemetry_token()


def test_no_token_is_the_normal_case(monkeypatch) -> None:
    monkeypatch.delenv("HF_TOKEN", raising=False)
    monkeypatch.delenv("HUGGING_FACE_HUB_TOKEN", raising=False)
    # No token, no exception: anonymous access is the supported posture.
    assert assert_no_telemetry_token() is None


# ---------------------------------------------------------------------------
# Caching — Phase 12: "a second scan of the same model does not re-fetch"
# ---------------------------------------------------------------------------


def test_a_second_scan_of_the_same_model_does_not_refetch(tmp_root) -> None:
    calls: list[str] = []

    def fetch(ref: str, revision: str) -> dict:
        calls.append(ref)
        return card(ref)

    cache = CardCache(root=tmp_root / "cache")
    first = enrich(["meta-llama/Llama-3-8B"], fetch=fetch, cache=cache)
    second = enrich(["meta-llama/Llama-3-8B"], fetch=fetch, cache=cache)

    assert calls == ["meta-llama/Llama-3-8B"], "the second scan re-fetched"
    assert first.cache_misses == 1 and first.cache_hits == 0
    assert second.cache_hits == 1 and second.cache_misses == 0
    assert second.cards == first.cards


def test_the_cache_is_keyed_on_the_revision_too(tmp_root) -> None:
    """A model at two revisions can carry two different licences."""
    cache = CardCache(root=tmp_root / "cache")
    cache.put("m/x", "abc", {"rev": "abc"})

    assert cache.get("m/x", "abc") == {"rev": "abc"}
    assert cache.get("m/x", "def") is None


def test_an_expired_entry_is_refetched_rather_than_served_stale(tmp_root) -> None:
    """A publisher can edit a model card in place; a licence correction must
    reach the next report rather than being served from last month."""
    import os
    import time

    cache = CardCache(root=tmp_root / "cache", ttl_seconds=60)
    cache.put("m/x", "", {"stale": True})
    assert cache.get("m/x", "") == {"stale": True}

    # Back-date the entry past its TTL — the real mechanism, not a sentinel.
    path = cache.path_for("m/x", "")
    old_time = time.time() - 3600
    os.utime(path, (old_time, old_time))

    assert cache.get("m/x", "") is None


def test_a_zero_ttl_means_never_expire_not_always_expire(tmp_root) -> None:
    """The sentinel is easy to get backwards, so it is pinned."""
    import os
    import time

    cache = CardCache(root=tmp_root / "cache", ttl_seconds=0)
    cache.put("m/y", "", {"kept": True})
    path = cache.path_for("m/y", "")
    old_time = time.time() - 10_000_000
    os.utime(path, (old_time, old_time))

    assert cache.get("m/y", "") == {"kept": True}


def test_a_corrupt_cache_entry_degrades_to_a_fetch(tmp_root) -> None:
    """A broken cache must never fail a scan."""
    cache = CardCache(root=tmp_root / "cache")
    path = cache.path_for("m/x", "")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")

    assert cache.get("m/x", "") is None


# ---------------------------------------------------------------------------
# Failure isolation — Phase 12: a network failure degrades, never fails the scan
# ---------------------------------------------------------------------------


def test_one_failed_lookup_does_not_lose_the_others(tmp_root) -> None:
    def fetch(ref: str, revision: str) -> dict:
        if ref == "broken/model":
            raise TimeoutError("hugging face timed out")
        return card(ref)

    outcome = enrich(
        ["good/one", "broken/model", "good/two"],
        fetch=fetch,
        cache=CardCache(root=tmp_root / "cache"),
    )

    assert set(outcome.cards) == {"good/one", "good/two"}
    assert [d["code"] for d in outcome.diagnostics] == ["ENGINE_PARTIAL_ECOSYSTEM"]
    assert "broken/model" in outcome.diagnostics[0]["message"]


def test_a_partial_enrichment_reports_partial_not_succeeded(tmp_root) -> None:
    def fetch(ref: str, revision: str) -> dict:
        raise TimeoutError("down")

    outcome = enrich(["a/b"], fetch=fetch, cache=CardCache(root=tmp_root / "cache"))
    assert str(outcome.status) == "partial"


def test_nothing_to_enrich_is_a_success_not_a_degraded_run(tmp_root) -> None:
    """A repository that uses no resolvable model is the common case. Reporting
    it as degraded would train a reader to ignore the status that matters."""
    outcome = enrich([], fetch=lambda r, v: card(r), cache=CardCache(root=tmp_root / "cache"))
    assert str(outcome.status) == "succeeded"


# ---------------------------------------------------------------------------
# End to end over the real captured discovery artifact
# ---------------------------------------------------------------------------


def _worker(tmp_root: Path, fetch) -> EnrichmentWorker:
    return EnrichmentWorker(
        workspace_root=tmp_root / "workspaces",
        output_root=tmp_root / "artifacts",
        cache=CardCache(root=tmp_root / "cache"),
        fetch=fetch,
    )


def test_the_real_discovery_artifact_yields_one_model_to_enrich(tmp_root) -> None:
    scan_id, job_id = "scan-1", "job-1"
    workspace = tmp_root / "workspaces" / scan_id
    workspace.mkdir(parents=True)
    shutil.copy(REAL_DISCOVERY, workspace / DISCOVERY_ARTIFACT)

    asked: list[str] = []

    def fetch(ref, revision):
        asked.append(ref)
        return card(ref)

    result = _worker(tmp_root, fetch).handle(
        {"job_id": job_id, "scan_id": scan_id, "tenant_id": "t"}
    )

    # The library components ai-bom mistyped as models are not looked up.
    assert asked == ["meta-llama/Llama-3-8B"]
    assert result["status"] == "succeeded"
    assert result["engine"] == "aibom-generator"
    assert result["summary"]["components"] == 1
    assert result["ecosystems_covered"] == ["huggingface"]

    written = json.loads((tmp_root / "artifacts" / job_id / ARTIFACT_NAME).read_text())
    assert list(written) == ["meta-llama/Llama-3-8B"]


def test_a_model_that_was_never_asked_about_is_never_a_clean_success(tmp_root) -> None:
    """⚠ OBSERVED LIVE, AND IT IS THE WORST SHAPE OF WRONG.

    A real scan of a repository whose only model was `distilbert-base-uncased`
    reported `aibom-generator: succeeded`, `components: 0`, no diagnostics. The
    reference had been dropped by a shape rule inside the engine, and Engine
    Coverage — the one section whose job is stating what a report could not see —
    showed a clean run over a model nobody had looked up.

    A declined reference now costs a diagnostic and the `partial` status, both.
    """
    scan_id, job_id = "scan-declined", "job-declined"
    workspace = tmp_root / "workspaces" / scan_id
    workspace.mkdir(parents=True)
    (workspace / DISCOVERY_ARTIFACT).write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "type": "machine-learning-model",
                        "name": "GPT-4o",
                        "properties": [
                            {"name": "trusera:model_name", "value": "gpt-4o"},
                            {"name": "trusera:provider", "value": "OpenAI"},
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    asked: list[str] = []

    def fetch(ref, revision):
        asked.append(ref)
        return card(ref)

    result = _worker(tmp_root, fetch).handle(
        {"job_id": job_id, "scan_id": scan_id, "tenant_id": "t"}
    )

    assert asked == [], "a hosted-API model must not be looked up on Hugging Face"
    assert result["status"] == "partial"
    assert [d["code"] for d in result["diagnostics"]] == ["AIBOM_ENRICHMENT_NOT_ATTEMPTED"]
    assert "gpt-4o" in result["diagnostics"][0]["message"]


def test_a_missing_discovery_artifact_is_reported_never_a_crash(tmp_root) -> None:
    """The AIBOM worker stages ai-bom's output for us. If ai-bom never ran, or
    failed, this engine has no input — and says so, in Engine Coverage.

    ⚠ `partial`, NOT `succeeded`. This asserted `succeeded` on the reasoning that
    nothing to enrich is not a failure — true, but this is not "nothing to
    enrich": it is "we could not begin". A green engine row over a scan whose
    discovery output never arrived tells a reader the model metadata was checked.
    invariant 12: `partial` is a first-class status.
    """
    result = _worker(tmp_root, lambda r, v: card(r)).handle(
        {"job_id": "j", "scan_id": "missing", "tenant_id": "t"}
    )

    assert result["status"] == "partial"
    assert [d["code"] for d in result["diagnostics"]] == ["ENGINE_INPUT_MISSING"]
    assert result["artifacts"] == []


def test_the_summary_distinguishes_measured_zero_from_not_measured(tmp_root) -> None:
    """`events.Summary` fields are pointers on the Go side: nil is "not measured",
    0 is "measured, none". This engine measures components and nothing else."""
    result = _worker(tmp_root, lambda r, v: card(r)).handle(
        {"job_id": "j", "scan_id": "missing", "tenant_id": "t"}
    )

    assert result["summary"]["components"] == 0
    assert result["summary"]["vulnerabilities"] is None


# ---------------------------------------------------------------------------
# The image's dependency surface
# ---------------------------------------------------------------------------


def test_the_enrichment_extra_excludes_the_ml_and_server_stacks() -> None:
    """⚠ THE UPSTREAM PACKAGE DECLARES 5.4GB OF DEPENDENCIES IT DOES NOT NEED HERE.

    `owasp-aibom-generator` lists torch, transformers, datasets, sentencepiece,
    fastapi, flask, gunicorn and uvicorn as HARD runtime dependencies. Honouring
    them built a 9.78GB image — measured — for a worker whose job is fetching JSON
    over HTTPS: 3.2GB of NVIDIA CUDA libraries, 1.2GB of torch, 897MB of triton.
    Installing the subset the CLI path actually imports brings it to 426MB.

    Two of those exclusions are security posture, not size:
      - torch/transformers/sentencepiece serve `--summarize`, which DOWNLOADS AND
        RUNS a model (facebook/bart-large-cnn). This worker must never do that.
      - flask/gunicorn/uvicorn serve the project's bundled web app on port 8000.
        Without them it cannot be started, even by accident. (fastapi alone is
        unavoidable: `src/utils/__init__.py` imports it on the CLI path.)

    Pinned here because a future `pip install -e .[aienrich]` that quietly drops
    `--no-deps` would restore all of it with nothing failing.
    """
    import tomllib

    root = Path(__file__).resolve().parents[2]
    with (root / "pyproject.toml").open("rb") as handle:
        pyproject = tomllib.load(handle)

    extra = pyproject["project"]["optional-dependencies"]["aienrich"]
    names = {spec.split(">=")[0].split("[")[0].split(" @ ")[0].strip().lower() for spec in extra}

    for forbidden in (
        "torch",
        "transformers",
        "datasets",
        "sentencepiece",
        "flask",
        "gunicorn",
        "uvicorn",
    ):
        assert forbidden not in names, (
            f"{forbidden} is back in the aienrich extra. It is not on the CLI path, "
            f"and torch alone brought 4.4GB of CUDA and triton with it."
        )

    # The generator itself is installed --no-deps in the Dockerfile, so it must
    # NOT be declared here — declaring it would let pip resolve its full tree.
    assert "owasp-aibom-generator" not in names, (
        "the generator must be installed --no-deps in the image, not resolved by pip"
    )

    dockerfile = (root / "deploy" / "docker" / "Dockerfile.aienrich").read_text(encoding="utf-8")
    assert "--no-deps" in dockerfile, "the generator install lost its --no-deps"


def test_a_malformed_job_dead_letters_instead_of_becoming_a_phantom_engine_run(
    tmp_root,
) -> None:
    """⚠ OBSERVED FOR REAL on first start: a leftover message on this subject was
    consumed and reported `succeeded` with no job and no scan.

    Publishing a result with an empty scan_id puts a phantom `aibom-generator`
    engine run on the results stream for a scan that does not exist. Raising is
    what routes the message to the DLQ with its content intact.
    """
    worker = _worker(tmp_root, lambda r, v: card(r))

    for missing in (
        {"scan_id": "s", "tenant_id": "t"},
        {"job_id": "j", "tenant_id": "t"},
        {"job_id": "j", "scan_id": "s"},
    ):
        with pytest.raises(ValueError, match="missing job_id, scan_id or tenant_id"):
            worker.handle(missing)
