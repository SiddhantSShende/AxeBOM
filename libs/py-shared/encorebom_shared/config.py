"""Worker configuration.

Mirrors the Go `platform/config` loader: fail fast, report every problem at
once, and keep secrets out of every accidental rendering path.

WORKERS HOLD NO CREDENTIALS. There is deliberately no git token, no OAuth
secret, and no database password here. Engine containers receive a
content-addressed source archive and nothing else — see docs/ADR/0008. If a
future change appears to need a credential in a worker, the design has gone
wrong; route the work through the fetcher instead.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


class ConfigError(Exception):
    """Raised with every missing or invalid value at once."""


class _Loader:
    def __init__(self) -> None:
        self._missing: list[str] = []
        self._invalid: list[str] = []

    def string(self, name: str) -> str:
        value = os.environ.get(name, "")
        if not value:
            self._missing.append(name)
        return value

    def string_or(self, name: str, default: str) -> str:
        return os.environ.get(name) or default

    def integer(self, name: str, default: int) -> int:
        raw = os.environ.get(name)
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            self._invalid.append(f"{name} (not an integer: {raw!r})")
            return default

    def boolean(self, name: str, default: bool) -> bool:
        raw = os.environ.get(name)
        if raw is None or raw == "":
            return default
        return raw.strip().lower() in {"1", "true", "t", "yes", "y", "on"}

    def enum(self, name: str, allowed: tuple[str, ...], default: str) -> str:
        raw = os.environ.get(name)
        if not raw:
            return default
        if raw not in allowed:
            # An out-of-set value is an error, not a silent fallback. Silently
            # ignoring a typo'd SANDBOX_NETWORK would be a security problem.
            self._invalid.append(f"{name} ({raw!r} not in {allowed})")
            return default
        return raw

    def raise_if_problems(self) -> None:
        if not self._missing and not self._invalid:
            return
        parts = ["configuration error:"]
        if self._missing:
            parts.append(f"  missing required: {', '.join(self._missing)}")
        if self._invalid:
            parts.append(f"  invalid: {', '.join(self._invalid)}")
        parts.append("  see .env.example for the full template")
        raise ConfigError("\n".join(parts))


@dataclass(frozen=True)
class SandboxLimits:
    """Blast-radius limits for running third-party scanners over untrusted code.

    docs/05-SECURITY-MODEL.md §3. Loosening any of these is a security decision
    requiring an ADR, not a tuning exercise.
    """

    network: str = "none"
    cpu_millis: int = 2000
    memory_mb: int = 4096
    disk_mb: int = 20480
    pids_max: int = 512
    wall_clock_sec: int = 900


@dataclass(frozen=True)
class WorkerConfig:
    name: str
    env: str = "development"
    log_level: str = "info"
    log_format: str = "json"

    nats_url: str = "nats://localhost:54222"
    s3_endpoint: str = "http://localhost:59000"
    s3_bucket: str = "encorebom"
    s3_region: str = "us-east-1"

    tools_dir: str = ".encorebom/tools"
    manifest: str = "OSINT/tools.manifest.yaml"

    sandbox: SandboxLimits = field(default_factory=SandboxLimits)

    # Package-manager resolution executes arbitrary code from the scanned
    # repository (npm lifecycle scripts, Gradle build files). OFF by default,
    # and per-project rather than global when enabled.
    allow_package_manager_resolution: bool = False


def load_worker_config(name: str) -> WorkerConfig:
    """Load configuration for a named worker, failing fast on problems."""
    loader = _Loader()

    cfg = WorkerConfig(
        name=name,
        env=loader.enum("ENCOREBOM_ENV", ("development", "staging", "production"), "development"),
        log_level=loader.enum("LOG_LEVEL", ("debug", "info", "warn", "error"), "info"),
        log_format=loader.enum("LOG_FORMAT", ("json", "text"), "json"),
        nats_url=loader.string_or("NATS_URL", "nats://localhost:54222"),
        s3_endpoint=loader.string_or("S3_ENDPOINT", "http://localhost:59000"),
        s3_bucket=loader.string_or("S3_BUCKET", "encorebom"),
        s3_region=loader.string_or("S3_REGION", "us-east-1"),
        tools_dir=loader.string_or("OSINT_TOOLS_DIR", ".encorebom/tools"),
        manifest=loader.string_or("OSINT_MANIFEST", "OSINT/tools.manifest.yaml"),
        sandbox=SandboxLimits(
            network=loader.enum("SANDBOX_NETWORK", ("none", "allowlist"), "none"),
            cpu_millis=loader.integer("SANDBOX_CPU_MILLIS", 2000),
            memory_mb=loader.integer("SANDBOX_MEMORY_MB", 4096),
            disk_mb=loader.integer("SANDBOX_DISK_MB", 20480),
            pids_max=loader.integer("SANDBOX_PIDS_MAX", 512),
            wall_clock_sec=loader.integer("SANDBOX_WALL_CLOCK_SEC", 900),
        ),
        allow_package_manager_resolution=loader.boolean("ALLOW_PACKAGE_MANAGER_RESOLUTION", False),
    )

    loader.raise_if_problems()
    return cfg
