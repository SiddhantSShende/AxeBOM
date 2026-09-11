"""Which image bytes produced this result.

⚠ THE BUG THIS PINS: `invocation.image_digest` WAS NEVER SENT, AND EVERY ENGINE
RUNS A MUTABLE TAG.

`OSINT/tools.manifest.yaml` carries `image_digest: null` for every engine, so
every reference is `repo:tag`. A tag is mutable — `anchore/syft:v1.51.0` today
and next month can be different binaries — and a compliance report naming a tag
cannot say what it examined. Meanwhile the envelope's `image_digest` field, which
docs/02-CONTRACTS.md §6 defines, was never populated at all, so nothing recorded
the resolution either.

Two separate statements, and the tests keep them separate:

    image_digest                  what actually ran, read back from the daemon
    ENGINE_IMAGE_NOT_PINNED       the reference was not reproducible in advance

Recording the first does not fix the second. A run is reproducible AFTER the
fact once the digest is stored; the reference only becomes reproducible in
advance when `toolctl pin` writes the digest into the manifest.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from axebom_shared.adapters.base import ScanTarget
from axebom_shared.sandbox import SandboxResult

from . import runner as runner_mod
from .adapters.common import EngineImage
from .adapters.syft import SyftAdapter
from .runner import SBOMWorker
from .test_runner import FakeSandbox, job

DIGEST = "sha256:" + "ab" * 32
SBOM = '{"components": [{"type": "library", "name": "x", "purl": "pkg:npm/x@1"}]}'


class Resolver:
    """A manifest resolver whose pinning can be dialled either way."""

    def __init__(self, *, pinned: bool) -> None:
        self.pinned = pinned

    def image_for(self, engine_id: str) -> EngineImage:
        if self.pinned:
            return EngineImage(
                reference=f"example.invalid/{engine_id}@{DIGEST}",
                version="1.0.0",
                digest_pinned=True,
            )
        return EngineImage(
            reference=f"example.invalid/{engine_id}:1.0.0",
            version="1.0.0",
            digest_pinned=False,
        )


def target(tmp_path: Path) -> ScanTarget:
    ws = tmp_path / "src"
    ws.mkdir(exist_ok=True)
    return ScanTarget(scan_id="s", job_id="j", kind="git", workspace=ws)


def classify(tmp_path: Path, *, pinned: bool, resolved: str) -> Any:
    resolver = Resolver(pinned=pinned)
    return SyftAdapter(resolver=resolver).classify(
        target(tmp_path),
        SandboxResult(exit_code=0, stdout=SBOM, image_digest=resolved),
        [],
        resolver.image_for("syft"),
    )


def codes(result: Any) -> list[str]:
    return [d.get("code") for d in result.diagnostics]


# ---------------------------------------------------------------------------
# What ran
# ---------------------------------------------------------------------------


def test_the_resolved_digest_is_recorded(tmp_path: Path) -> None:
    result = classify(tmp_path, pinned=True, resolved=DIGEST)
    assert result.image_digest == DIGEST


def test_the_digest_reaches_the_envelope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """End to end: what the daemon resolved is what the orchestrator receives."""
    monkeypatch.setattr(runner_mod.source, "materialize", lambda *a, **k: False)

    sandbox = FakeSandbox(SandboxResult(exit_code=0, stdout=SBOM, image_digest=DIGEST))
    worker = SBOMWorker(
        workspace_root=tmp_path / "ws", output_root=tmp_path / "out", sandbox=sandbox
    )
    result = worker.handle(job("syft", scan_id="s1", job_id="j1"))

    assert result["invocation"].get("image_digest") == DIGEST, (
        "the envelope carries no image_digest, so nothing records which image "
        "bytes produced this result"
    )


def test_an_unknown_digest_is_omitted_not_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """⚠ An empty string in a provenance field reads as a value."""
    monkeypatch.setattr(runner_mod.source, "materialize", lambda *a, **k: False)

    sandbox = FakeSandbox(SandboxResult(exit_code=0, stdout=SBOM, image_digest=""))
    worker = SBOMWorker(
        workspace_root=tmp_path / "ws", output_root=tmp_path / "out", sandbox=sandbox
    )
    result = worker.handle(job("syft", scan_id="s2", job_id="j2"))

    assert "image_digest" not in result["invocation"]


# ---------------------------------------------------------------------------
# Whether the reference was reproducible in advance
# ---------------------------------------------------------------------------


def test_a_tag_addressed_run_says_so_on_the_result(tmp_path: Path) -> None:
    """⚠ available() ALREADY REPORTS THIS AND IT IS NOT ENOUGH.

    Its detail reaches the engine list. A report's provenance is built from the
    RESULT, and the result said nothing — so a scan that ran a mutable tag was
    indistinguishable from one that ran a pinned digest.
    """
    result = classify(tmp_path, pinned=False, resolved=DIGEST)
    assert "ENGINE_IMAGE_NOT_PINNED" in codes(result)


def test_recording_the_digest_does_not_count_as_pinning(tmp_path: Path) -> None:
    """The two statements are independent, and conflating them would be worse
    than reporting neither: it would let an unpinned fleet look pinned because
    the digests happen to have been recorded after the fact."""
    result = classify(tmp_path, pinned=False, resolved=DIGEST)

    assert result.image_digest == DIGEST  # reproducible after the fact
    assert "ENGINE_IMAGE_NOT_PINNED" in codes(result)  # not in advance


def test_a_pinned_run_carries_no_pinning_diagnostic(tmp_path: Path) -> None:
    """A warning on every scan is a warning nobody reads."""
    result = classify(tmp_path, pinned=True, resolved=DIGEST)
    assert "ENGINE_IMAGE_NOT_PINNED" not in codes(result)


def test_an_image_with_no_registry_digest_is_reported_separately(tmp_path: Path) -> None:
    """A locally built image has no registry digest, and that is a different
    gap from an unpinned reference — a pinned reference can still resolve to an
    image the daemon cannot name."""
    result = classify(tmp_path, pinned=True, resolved="")
    assert "ENGINE_IMAGE_DIGEST_UNKNOWN" in codes(result)
    assert "ENGINE_IMAGE_NOT_PINNED" not in codes(result)


def test_the_pinning_hint_claims_a_recorded_digest_only_when_there_is_one(
    tmp_path: Path,
) -> None:
    """⚠ It said "the digest it resolved to is recorded on this result"
    unconditionally, and live CBOM runs carried that sentence with
    image_digest NULL — a provenance field stating something untrue."""

    def pin_hint(result: Any) -> str:
        return next(
            d["hint"] for d in result.diagnostics if d.get("code") == "ENGINE_IMAGE_NOT_PINNED"
        )

    assert "recorded on this result" in pin_hint(classify(tmp_path, pinned=False, resolved=DIGEST))
    assert "recorded on this result" not in pin_hint(classify(tmp_path, pinned=False, resolved=""))


# ---------------------------------------------------------------------------
# The manifest's current state, stated rather than assumed
# ---------------------------------------------------------------------------


def test_the_manifest_pinning_state_is_visible() -> None:
    """Not an assertion that engines ARE pinned — they are not, today.

    This records the count so that pinning some engines and not others cannot
    happen silently, and so `toolctl pin` has something that changes when it
    runs.
    """
    import yaml

    from .adapters.common import MANIFEST_PATH

    data = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8")) or {}
    containers = [
        (t["id"], (t.get("container") or {}).get("image_digest"))
        for t in data.get("tools", []) or []
        if (t.get("container") or {}).get("image")
    ]
    assert containers, "no container engines in the manifest"

    pinned = sorted(name for name, digest in containers if digest)

    # ⚠ THE PINNED SET IS NAMED, NOT COUNTED, AND THIS TEST FIRED THE MOMENT IT
    # CHANGED — which is what it was written for.
    #
    # Every engine was unpinned when this was written. `cdxgen` was pulled and
    # pinned by digest in the session that added it as an SBOM engine, and this
    # assertion failed rather than letting the roster drift quietly. Partial
    # pinning is the state that misleads: a reader who knows "some engines are
    # pinned" and not WHICH will assume the one they care about is.
    #
    # Adding a name here is a deliberate act. Removing one means an engine lost
    # its digest and started running tag-addressed again, which is the
    # regression this guards.
    # `cdxgen-ai` is the SAME image and the SAME digest as `cdxgen`, invoked with
    # `-t ai` — one image pinned once, two engine ids (the `syft-spdx` precedent).
    # It is named here rather than filtered out, because a reader of this list is
    # asking which ENGINES run against a pinned image, and both of them do.
    # `cbomkit-action` (2026-09-11) was pinned by digest from the registry the
    # day it was added — its `2.3.0` and `v2.3.0` tags are DIFFERENT images, so a
    # tag alone would not even say which one ran. `cdxgen-cbom` is the cdxgen
    # image and digest again, with the `cbom` entrypoint.
    assert pinned == ["cbomkit-action", "cdxgen", "cdxgen-ai", "cdxgen-cbom"], (
        f"the digest-pinned engine set changed to {pinned}: update this test "
        f"and docs/STATE.md — partial pinning is the state that quietly misleads"
    )

    unpinned = [name for name, digest in containers if not digest]
    assert unpinned, (
        "every engine is now digest-pinned — delete this test's unpinned branch "
        "and the ENGINE_IMAGE_NOT_PINNED diagnostic's 'expected' framing"
    )
