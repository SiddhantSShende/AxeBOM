"""Cryptographic analysis: quantum vulnerability, PQC guidance, deprecation.

⚠ EVERYTHING IN THIS PACKAGE IS ENCOREBOM'S ANALYSIS, NOT A CERT-In FIELD.

The three values it produces — `quantum_vulnerable`, `pqc_recommendation` and
`deprecation_status` — carry `scored: false` in the compliance profile and are
EXCLUDED from both coverage numbers. That is not a technicality: letting our own
analysis move a compliance percentage would mean a customer's score changed
because we shipped a new rule, with no change to their software.

They are reported prominently and they never count.
"""

from .deprecation import DeprecationVerdict, assess_deprecation
from .pqc import PQCRecommendation, recommend_pqc
from .quantum_rules import QuantumVerdict, assess_quantum

__all__ = [
    "DeprecationVerdict",
    "PQCRecommendation",
    "QuantumVerdict",
    "assess_deprecation",
    "assess_quantum",
    "recommend_pqc",
]
