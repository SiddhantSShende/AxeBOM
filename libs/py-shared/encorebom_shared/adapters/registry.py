"""Engine registry — engine_id to adapter.

The registry reads the SAME manifest `encorebom toolctl` reads
(OSINT/tools.manifest.yaml). One source of truth: if the Go side pins
syft 1.51.0 and the Python side hardcoded 1.19.1, a scan would run one version
and the report would claim another — and provenance IS the product here.

⚠ THE UNIT IS (tool, mode), NOT tool. `trivy-fs` and `trivy-image` are
different engines: different invocation, different capabilities, different
parser. Collapsing them would mean one adapter guessing which mode it is in.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

from encorebom_shared.adapters.base import (
    Availability,
    Capabilities,
    EngineMode,
    ToolAdapterBase,
)
from encorebom_shared.logging import get_logger

log = get_logger(__name__)

DEFAULT_MANIFEST = "OSINT/tools.manifest.yaml"


def _repo_root(start: Path | None = None) -> Path:
    """Walk up to the directory holding go.mod, so paths work from anywhere."""
    d = (start or Path.cwd()).resolve()
    for candidate in [d, *d.parents]:
        if (candidate / "go.mod").exists():
            return candidate
    return d


class ManifestAdapter(ToolAdapterBase):
    """A manifest-driven adapter.

    Phase 2 implements `available()`. Phase 7 replaces this with concrete
    per-engine subclasses that also implement generate() and parse().
    """

    def __init__(self, capabilities: Capabilities, entry: dict[str, Any]) -> None:
        super().__init__(capabilities)
        self._entry = entry

    def available(self) -> Availability:
        """Resolve container -> binary -> pip -> unavailable.

        Never raises. An engine that cannot run is `unavailable`, which is
        recorded in Engine Coverage — losing one engine costs that engine's
        coverage, visibly, not the whole scan.
        """
        e = self._entry
        engine_id = self.engine_id
        version = e.get("version")

        if e.get("enabled") is False:
            return Availability(
                False,
                EngineMode.UNAVAILABLE,
                version,
                _first_line(e.get("deferred_reason") or "disabled in the manifest"),
            )

        if e.get("upstream") == "internal":
            return Availability(True, EngineMode.INTERNAL, version, "internal engine")

        container = e.get("container") or {}
        if container.get("image"):
            ref = _container_ref(container)
            if not _docker_available():
                return Availability(
                    False,
                    EngineMode.UNAVAILABLE,
                    version,
                    f"container mode requires a running Docker daemon (image {ref})",
                )
            return Availability(True, EngineMode.CONTAINER, version, f"container {ref}")

        if e.get("container_only"):
            return Availability(
                False,
                EngineMode.UNAVAILABLE,
                version,
                _first_line(
                    e.get("container_only_reason") or "container-only but no image declared"
                ),
            )

        binary = e.get("binary") or {}
        if binary.get("url_template"):
            path = _installed_binary(engine_id, version)
            if path:
                return Availability(True, EngineMode.BINARY, version, f"binary {path}")
            return Availability(
                False,
                EngineMode.UNAVAILABLE,
                version,
                "binary not installed — run `task osint:sync`",
            )

        pip = e.get("pip") or {}
        if pip.get("package") or pip.get("git"):
            pkg = pip.get("package") or engine_id
            if _python_module_available(pkg):
                return Availability(True, EngineMode.PIP, version, f"pip {pkg}")
            return Availability(
                False,
                EngineMode.UNAVAILABLE,
                version,
                f"pip package {pkg!r} is not installed in this environment",
            )

        return Availability(
            False,
            EngineMode.UNAVAILABLE,
            version,
            "no container image, binary URL or pip package declared",
        )


def _container_ref(container: dict[str, Any]) -> str:
    """Prefer the digest: a tag is mutable and can be repointed after pinning."""
    image = container.get("image", "")
    if digest := container.get("image_digest"):
        return f"{image}@{digest}"
    if tag := container.get("image_tag"):
        return f"{image}:{tag}"
    return image


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        # `docker info` fails when the CLI is present but the daemon is not
        # running, which is the common state on a developer machine.
        subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],  # noqa: S607
            capture_output=True,
            timeout=10,
            check=True,
        )
        return True
    except (subprocess.SubprocessError, OSError):
        return False


def _installed_binary(engine_id: str, version: str | None) -> Path | None:
    tools_dir = Path(os.environ.get("OSINT_TOOLS_DIR", ".encorebom/tools"))
    if not tools_dir.is_absolute():
        tools_dir = _repo_root() / tools_dir
    d = tools_dir / engine_id / (version or "")
    if not d.is_dir():
        return None
    for p in sorted(d.iterdir()):
        if p.is_file() and not p.name.endswith((".partial", ".txt", ".sig", ".pem", ".json")):
            return p
    return None


def _python_module_available(package: str) -> bool:
    import importlib.util

    return importlib.util.find_spec(package.replace("-", "_")) is not None


def _first_line(s: str) -> str:
    return " ".join(str(s).split())[:200]


class Registry:
    """All engines, loaded from the manifest."""

    def __init__(self, adapters: dict[str, ToolAdapterBase]) -> None:
        self._adapters = adapters

    @classmethod
    def from_manifest(cls, path: str | Path | None = None) -> Registry:
        p = Path(path) if path else Path(os.environ.get("OSINT_MANIFEST", DEFAULT_MANIFEST))
        if not p.is_absolute():
            p = _repo_root() / p

        with p.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)

        adapters: dict[str, ToolAdapterBase] = {}
        for entry in data.get("tools", []):
            caps = Capabilities(
                engine_id=entry["id"],
                families=tuple(entry.get("families", ())),
                source_kinds=tuple(entry.get("source_kinds", ())),
                produces=tuple(entry.get("produces", ())),
                native_format=entry.get("native_format"),
                db_backed=bool(entry.get("db_backed", False)),
                default_weight=int(entry.get("default_weight", 1)),
            )
            adapters[caps.engine_id] = ManifestAdapter(caps, entry)

        log.debug("engine registry loaded", manifest=str(p), engines=len(adapters))
        return cls(adapters)

    def get(self, engine_id: str) -> ToolAdapterBase:
        try:
            return self._adapters[engine_id]
        except KeyError:
            raise KeyError(
                f"unknown engine {engine_id!r}; known: {sorted(self._adapters)}"
            ) from None

    def ids(self) -> list[str]:
        return sorted(self._adapters)

    def for_family(self, family: str) -> list[ToolAdapterBase]:
        return [a for a in self._adapters.values() if family in a.capabilities.families]

    def availability(self) -> dict[str, Availability]:
        """Probe every engine.

        This is what populates the report's Engine Coverage section, so it must
        report on EVERY engine — including the unavailable ones. An engine
        omitted from the report is the failure mode this whole design exists to
        prevent.
        """
        return {eid: a.available() for eid, a in sorted(self._adapters.items())}
