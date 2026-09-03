"""SBOM engine adapters.

Six sandboxed engines, one per file, sharing the SandboxedAdapter machinery in
common.py — what differs per engine is the invocation, the output shape, and
the specific way each one can be wrong, which is what the per-file comments
record. github_dependency_graph.py and webrecon_fingerprint.py are the
exceptions: both subclass ToolAdapterBase directly, since there is no tool to
sandbox — see their own module docstrings.
"""

from .cdxgen import CdxgenAdapter
from .dependency_check import DependencyCheckAdapter
from .github_dependency_graph import GitHubDependencyGraphAdapter
from .grype import GrypeAdapter
from .osv_scanner import OSVScannerAdapter
from .syft import SyftAdapter, SyftSPDXAdapter
from .trivy_fs import TrivyFSAdapter
from .trivy_image import TrivyImageAdapter
from .webrecon_fingerprint import WebreconFingerprintAdapter

__all__ = [
    "CdxgenAdapter",
    "DependencyCheckAdapter",
    "GitHubDependencyGraphAdapter",
    "GrypeAdapter",
    "OSVScannerAdapter",
    "SyftAdapter",
    "SyftSPDXAdapter",
    "TrivyFSAdapter",
    "TrivyImageAdapter",
    "WebreconFingerprintAdapter",
]
