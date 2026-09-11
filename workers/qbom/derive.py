"""QBOM derivation.

⚠ A QBOM IS NOT A SCAN, AND THE PRODUCT MUST NOT IMPLY OTHERWISE.

No open-source tool discovers quantum hardware. A QBOM is two things joined:

    crypto assets   REFERENCED from the CBOM, with quantum rules applied
    device metadata CAPTURED by form or import (CERT-In Table 8's elements)

Pretending it is a scan burns the phase and produces something undemoable — a
customer waits for results that are never coming, and the empty QBOM reads as a
broken product rather than as an honest one.

⚠ THE CRYPTO ASSETS ARE REFERENCED, NOT COPIED.

A QBOM that duplicated the CBOM's assets would drift from it the moment either
is re-normalized, and a reviewer comparing the two would find two different
answers to the same question with no way to tell which is current.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from axebom_shared.crypto.quantum_rules import PQC_FAMILIES, readiness_group

__all__ = ["PQC_FAMILIES", "QuantumReadiness", "crypto_asset_refs", "derive_readiness"]


@dataclass
class QuantumReadiness:
    """The quantum-readiness summary a report renders."""

    #: Assets Shor breaks. The migration list.
    vulnerable: list[dict[str, Any]] = field(default_factory=list)
    #: Symmetric assets carrying a Grover note. NOT a migration list.
    grover_notes: list[dict[str, Any]] = field(default_factory=list)
    #: Already post-quantum. Evidence of work already done.
    post_quantum: list[dict[str, Any]] = field(default_factory=list)
    #: Assets no rule matched. A stated gap, not a clean bill.
    unassessed: list[dict[str, Any]] = field(default_factory=list)

    diagnostics: list[dict[str, Any]] = field(default_factory=list)

    @property
    def total_assessed(self) -> int:
        return len(self.vulnerable) + len(self.grover_notes) + len(self.post_quantum)

    def readiness_note(self) -> str:
        """One paragraph a reader can act on.

        ⚠ IT NEVER PRODUCES A SCORE. A "quantum readiness: 72%" would be a
        number we invented, weighted by judgements we did not publish, about a
        threat with no agreed timeline. The counts are the honest form.
        """
        if self.total_assessed == 0 and not self.unassessed:
            return (
                "No cryptographic assets were discovered, so nothing could be "
                "assessed for quantum vulnerability. That is not the same as "
                "having no quantum-vulnerable cryptography — check Engine "
                "Coverage for whether a CBOM engine ran at all."
            )

        parts = [
            f"{len(self.vulnerable)} asset(s) use primitives broken by Shor's "
            f"algorithm and require migration."
        ]
        if self.post_quantum:
            parts.append(f"{len(self.post_quantum)} already use NIST post-quantum algorithms.")
        if self.grover_notes:
            parts.append(
                f"{len(self.grover_notes)} symmetric asset(s) carry a Grover note on "
                f"effective key strength. Those are sizing observations, NOT "
                f"vulnerabilities, and they are deliberately excluded from the "
                f"migration list."
            )
        if self.unassessed:
            parts.append(
                f"{len(self.unassessed)} asset(s) matched no rule and were not "
                f"assessed — recorded as a gap rather than reported as safe."
            )
        return " ".join(parts)


def derive_readiness(crypto_assets: list[dict[str, Any]]) -> QuantumReadiness:
    """Group already-analysed crypto assets into the readiness view.

    ⚠ IT RE-RUNS NOTHING. The analysis happened in the CBOM normalizer and the
    verdicts are on the assets. Recomputing here would be a second
    implementation of the rules, and the two would disagree the first time one
    changed — with the QBOM and the CBOM then reporting different answers about
    the same asset.
    """
    out = QuantumReadiness()

    for asset in crypto_assets:
        group = readiness_group(
            quantum_vulnerable=bool(asset.get("quantum_vulnerable")),
            grover_note=str(asset.get("grover_note") or ""),
            quantum_family=str(asset.get("quantum_family") or ""),
        )
        if group == "vulnerable":
            out.vulnerable.append(asset)
        elif group == "grover_note":
            out.grover_notes.append(asset)
        elif group == "post_quantum":
            out.post_quantum.append(asset)
        elif group == "unassessed":
            out.unassessed.append(asset)

    if out.unassessed:
        out.diagnostics.append(
            {
                "severity": "warn",
                "code": "NORMALIZE_CRYPTO_ASSET_TYPE_UNKNOWN",
                "message": (f"{len(out.unassessed)} crypto asset(s) matched no quantum rule"),
                "hint": (
                    "reported as unassessed rather than as not-vulnerable, so the "
                    "gap is visible instead of reading as a clean result"
                ),
            }
        )

    return out


def crypto_asset_refs(crypto_assets: list[dict[str, Any]]) -> list[str]:
    """The reference list a QBOM's `crypto_assets` field carries.

    ⚠ REFERENCES, NOT COPIES (CERT-In Table 8 element 5). A QBOM that embedded
    the assets would drift from the CBOM the moment either is re-normalized, and
    a reviewer comparing them would get two answers to one question.
    """
    refs: list[str] = []
    for asset in crypto_assets:
        # ⚠ `asset_key` FIRST (migrations/normalize/0020). A row id changes every
        # time a CBOM is re-normalized (invariant 10 writes a NEW document), so a
        # QBOM that referenced ids stopped resolving after every corrected pass;
        # the asset key is the same asset's name across versions.
        # services/project/internal/store/qbom.go resolves in the same order.
        ref = (
            asset.get("asset_key")
            or asset.get("id")
            or asset.get("component_key")
            or asset.get("name")
        )
        if ref:
            refs.append(str(ref))
    return refs
