"""Scan engine adapters.

Every engine implements the same three-method contract
(docs/04-OSINT-INTEGRATION.md), so engines are swappable and a new one is an
adapter rather than a change to the orchestrator.
"""

from axebom_shared.adapters.base import (
    Availability,
    Capabilities,
    EngineMode,
    GenerateResult,
    RawArtifact,
    ResultStatus,
    ScanTarget,
    ToolAdapter,
    ToolAdapterBase,
)
from axebom_shared.adapters.registry import ManifestAdapter, Registry

__all__ = [
    "Availability",
    "Capabilities",
    "EngineMode",
    "GenerateResult",
    "ManifestAdapter",
    "RawArtifact",
    "Registry",
    "ResultStatus",
    "ScanTarget",
    "ToolAdapter",
    "ToolAdapterBase",
]
