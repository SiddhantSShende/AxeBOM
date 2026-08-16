"""SBOM engine adapters.

Six engines, one per file. The shared machinery is in common.py; what differs
per engine is the invocation, the output shape, and the specific way each one
can be wrong — which is what the per-file comments record.
"""

from .dependency_check import DependencyCheckAdapter
from .grype import GrypeAdapter
from .osv_scanner import OSVScannerAdapter
from .syft import SyftAdapter, SyftSPDXAdapter
from .trivy_fs import TrivyFSAdapter
from .trivy_image import TrivyImageAdapter

__all__ = [
    "DependencyCheckAdapter",
    "GrypeAdapter",
    "OSVScannerAdapter",
    "SyftAdapter",
    "SyftSPDXAdapter",
    "TrivyFSAdapter",
    "TrivyImageAdapter",
]
