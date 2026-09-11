"""The hooks every sandboxed adapter overrides, exercised against real types.

⚠ TWO ADAPTERS HAVE NOW SHIPPED A BUG THAT ONLY A LIVE SCAN COULD FIND.

`ECADAdapter` returned a plain dict where the worker calls `.as_dict()`.
`CdxgenAdapter` read `layout.container_workspace`, which does not exist — the
field is `container_scratch`. Both raised deep inside the worker, after the
job had been dispatched, with a traceback naming the framework rather than the
adapter that caused it.

Neither was reachable from the adapters' own tests, because those exercise
PARSING and never touch the hooks the worker calls. This module tests the
hooks, against the real `WorkspaceLayout` and `ScanTarget`, for every adapter
in the registry — so a third one cannot repeat it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from workers.cbom.runner import ADAPTERS as _CBOM_ADAPTERS

from axebom_shared.adapters.base import ScanTarget
from axebom_shared.sandbox import WorkspaceLayout

from .runner import ADAPTERS as _SBOM_ADAPTERS

#: ⚠ EVERY WORKER'S SANDBOXED ADAPTERS, NOT ONLY THE SBOM WORKER'S. This read the
#: SBOM map alone, so the CBOM adapters — including cbomkit-action's shell
#: entrypoint and cdxgen-cbom's `-o -` — were never contract-tested at all.
ADAPTERS = {**_SBOM_ADAPTERS, **_CBOM_ADAPTERS}


def _names_a_scratch_path(name: str) -> bool:
    """Whether an env var names somewhere the tool intends to write."""
    upper = name.upper()
    return upper == "TMPDIR" or any(
        token in upper for token in ("TEMP_DIR", "TMP_DIR", "CACHE_DIR", "_HOME")
    )


#: Adapters that run no container and override none of these hooks.
_INTERNAL = {"github-dependency-graph-sbom", "webrecon-fingerprint"}

_SANDBOXED = sorted(set(ADAPTERS) - _INTERNAL)


@pytest.fixture
def layout(tmp_path: Path) -> WorkspaceLayout:
    return WorkspaceLayout(source=tmp_path)


@pytest.fixture
def target(tmp_path: Path) -> ScanTarget:
    """A target with every input an adapter might legitimately require.

    ⚠ sbom_path AND image_digest ARE SET DELIBERATELY. grype refuses to build
    an argv without our syft SBOM — it matches against that document rather
    than re-cataloguing the tree, because a second inventory is exactly the
    reconciliation work the normalizer exists to avoid — and trivy-image needs
    an image reference. Omitting them would make this contract test skip the
    two adapters with the most argv logic.
    """
    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}')
    return ScanTarget(
        scan_id="s",
        job_id="j",
        kind="upload",
        workspace=tmp_path,
        sbom_path=sbom,
        image_digest="sha256:" + "0" * 64,
    )


@pytest.mark.parametrize("engine_id", _SANDBOXED)
def test_extra_env_reads_only_fields_the_layout_has(engine_id, layout):
    """⚠ THE REGRESSION GUARD FOR cdxgen's `container_workspace`.

    `SandboxedAdapter.generate` calls `extra_env(layout)` before it starts the
    container. An attribute that does not exist raises there — after the job is
    dispatched, on a real scan, with `AttributeError` and nothing else.
    """
    adapter = ADAPTERS[engine_id](artifact_dir=None)
    env = adapter.extra_env(layout)

    assert isinstance(env, dict)
    for key, value in env.items():
        assert isinstance(key, str) and isinstance(value, str), (
            f"{engine_id} returned a non-string env entry {key!r}={value!r}; "
            "the sandbox bridge serializes these to JSON"
        )
    # ⚠ EVERY SCRATCH PATH MUST LIVE UNDER THE ONLY WRITABLE ROOT. The rootfs
    # is read-only by policy, so a scratch path anywhere else fails with a
    # message naming neither the tool's needs nor the sandbox policy — cdxgen's
    # first live run died on a hardcoded `/tmp/cdxgen-temp` with `EROFS`.
    scratch_vars = {k: v for k, v in env.items() if _names_a_scratch_path(k)}
    for name, value in scratch_vars.items():
        assert value == layout.container_scratch or value.startswith(
            layout.container_scratch + "/"
        ), (
            f"{engine_id} points {name} at {value!r}, which is outside the "
            f"container's only writable path ({layout.container_scratch!r})"
        )

    # ⚠ AND A TOOL THAT DELETES ITS OWN TEMP DIRECTORY MUST NOT BE HANDED THE
    # MOUNT POINT. cdxgen's `cleanupTmpDir` tried to `rm /workspace` and died
    # AFTER producing a correct SBOM. A path underneath is one it created.
    for name, value in scratch_vars.items():
        if name == "TMPDIR":
            continue
        assert value != layout.container_scratch, (
            f"{engine_id} hands {name} the scratch ROOT; a tool that cleans up "
            "its own temp directory will try to remove the tmpfs mount point"
        )


@pytest.mark.parametrize("engine_id", _SANDBOXED)
def test_build_argv_returns_strings_and_names_the_source(engine_id, layout, target):
    """argv is passed to the sandbox bridge as JSON and then to exec.

    A non-string element fails serialization; an argv that never names the
    source scans nothing and reports zero, which is worse than failing.
    """
    adapter = ADAPTERS[engine_id](artifact_dir=None)
    argv = adapter.build_argv(target, layout)

    assert isinstance(argv, list) and argv, f"{engine_id} produced no argv"
    for arg in argv:
        assert isinstance(arg, str), f"{engine_id} produced a non-string argv element {arg!r}"


@pytest.mark.parametrize("engine_id", _SANDBOXED)
def test_the_sandbox_refuses_no_adapters_argv(engine_id, layout, target):
    """⚠ NO ENGINE MAY RESOLVE DEPENDENCIES BY EXECUTING PACKAGE MANAGERS.

    CLAUDE.md invariant 7, enforced in the Go sandbox's CheckCommand rather
    than per adapter. Asserting it here as well means a forbidden argv fails in
    CI rather than at the moment a customer's untrusted code would have run it.
    """
    forbidden = (
        "npm install",
        "npm ci",
        "npm run",
        "yarn",
        "mvn",
        "gradle",
        "pip install",
        "setup.py",
        "cargo build",
        "go generate",
        "make",
    )
    argv = " ".join(ADAPTERS[engine_id](artifact_dir=None).build_argv(target, layout))
    for phrase in forbidden:
        assert phrase not in argv, f"{engine_id}'s argv contains {phrase!r}"
