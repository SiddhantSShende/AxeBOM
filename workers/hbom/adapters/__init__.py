"""HBOM engine adapters.

⚠ NEITHER ADAPTER LOOKS AT HARDWARE, AND NEITHER RUNS A CONTAINER.

`hbom-ecad` parses design files the customer wrote and committed — KiCad
schematics and netlists, BOM exports from KiCad/Altium/OrCAD. `hbom-cdxgen-host`
reads a CycloneDX inventory the customer generated on their own device with
`cdxgen -t hbom`. Both are documents; neither is discovery. See CLAUDE.md's
honest-labels section.
"""

from .cdxgen_host import CAPABILITIES as CDXGEN_HOST_CAPABILITIES
from .cdxgen_host import CdxgenHostHBOMAdapter
from .ecad import CAPABILITIES as ECAD_CAPABILITIES
from .ecad import ECADAdapter

__all__ = [
    "CDXGEN_HOST_CAPABILITIES",
    "ECAD_CAPABILITIES",
    "CdxgenHostHBOMAdapter",
    "ECADAdapter",
]
