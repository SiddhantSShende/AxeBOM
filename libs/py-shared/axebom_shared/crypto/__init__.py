"""Cryptographic analysis: quantum vulnerability, PQC guidance, deprecation.

⚠ EVERYTHING IN THIS PACKAGE IS AXEBOM'S ANALYSIS, NOT A CERT-In FIELD.

The three values it produces — `quantum_vulnerable`, `pqc_recommendation` and
`deprecation_status` — carry `scored: false` in the compliance profile and are
EXCLUDED from both coverage numbers. That is not a technicality: letting our own
analysis move a compliance percentage would mean a customer's score changed
because we shipped a new rule, with no change to their software.

They are reported prominently and they never count.
"""

from .deprecation import DeprecationVerdict, assess_deprecation
from .pqc import PQCRecommendation, recommend_pqc
from .quantum_rules import PQC_FAMILIES, QuantumVerdict, assess_quantum, readiness_group

__all__ = [
    "PQC_FAMILIES",
    "DeprecationVerdict",
    "PQCRecommendation",
    "QuantumVerdict",
    "assess_deprecation",
    "assess_quantum",
    "readiness_group",
    "recommend_pqc",
]
