"""HBOM engine adapters.

⚠ NO ADAPTER HERE LOOKS AT HARDWARE, AND NONE RUNS A CONTAINER.

`hbom-ecad` parses design files the customer wrote and committed — KiCad
schematics and netlists, EAGLE schematics, BOM exports from KiCad/Altium/OrCAD. `hbom-cdxgen-host`
reads a CycloneDX inventory the customer generated on their own device with
`cdxgen -t hbom`. `hbom-host-report` reads the same kind of inventory from the
tools people actually have — lshw, dmidecode, fwupdmgr, PowerShell's CIM
cmdlets, Redfish. All three are documents somebody produced; none is discovery.
See CLAUDE.md's honest-labels section.
"""

from .cdxgen_host import CAPABILITIES as CDXGEN_HOST_CAPABILITIES
from .cdxgen_host import CdxgenHostHBOMAdapter
from .ecad import CAPABILITIES as ECAD_CAPABILITIES
from .ecad import ECADAdapter
from .hostreport import CAPABILITIES as HOST_REPORT_CAPABILITIES
from .hostreport import HostReportAdapter

__all__ = [
    "CDXGEN_HOST_CAPABILITIES",
    "ECAD_CAPABILITIES",
    "HOST_REPORT_CAPABILITIES",
    "CdxgenHostHBOMAdapter",
    "ECADAdapter",
    "HostReportAdapter",
]
