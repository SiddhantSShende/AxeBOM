"""VEX — applied after dedup, joined to findings, never mutating them.

⚠ VEX NEVER MUTATES A FINDING. IT JOINS TO ONE.

A finding is what the scanners observed; a VEX statement is what a human
asserted about it. Writing the assertion over the observation destroys the
evidence a compliance artifact rests on — and makes the two impossible to
disagree, which is precisely the thing a reviewer needs to see.

So a suppressed finding is still a finding. It carries an effective status and
the statement that produced it, and the report shows both. "This CVE is not
exploitable in our configuration" is a defensible position; "this CVE does not
appear in our scan" is not the same claim and must not look like one.

⚠ APPEND-ONLY AND VERSIONED. CERT-In §6 (p.35) is explicit that VEX is an
iterative process updated with each change. A new statement SUPERSEDES rather
than overwrites, and the full history is preserved — a statement withdrawn in
September must not erase what was asserted in March.

Effective status = most specific scope, then latest timestamp.

See `docs/03-NORMALIZER-SPEC.md` §2.6 and `docs/01-DATA-MODEL.md`.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

#: The four CSAF 2.0 statuses. No others are valid.
STATUSES = frozenset({"not_affected", "affected", "fixed", "under_investigation"})

#: CSAF justification codes for `not_affected`.
#:
#: ⚠ REQUIRED for `not_affected`. "Not affected" without a reason is an
#: assertion with no argument behind it, and CSAF requires the justification for
#: exactly that reason.
JUSTIFICATIONS = frozenset(
    {
        "component_not_present",
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist",
    }
)

#: Scope specificity, most specific first. A statement about one component in
#: one project outranks a blanket statement about a cluster.
_SCOPE_RANK = {
    "component": 0,
    "project": 1,
    "tenant": 2,
    "global": 3,
}


@dataclass
class VexStatement:
    """One assertion about a (cluster, component) pair.

    `component_key` empty means the statement applies to the cluster across
    every component — a broader, less specific claim.
    """

    id: str
    cluster_id: str
    status: str
    #: RFC3339 with a literal Z, from the record. Never read from a clock here.
    created_at: str
    component_key: str = ""
    justification: str = ""
    remediation: str = ""
    scope: str = "component"
    version: int = 1
    #: Set when a later statement replaced this one. A superseded statement is
    #: kept — the history is the point.
    superseded_by: str = ""
    author_user_id: str = ""

    def applies_to(self, cluster_id: str, component_key: str) -> bool:
        if self.cluster_id != cluster_id:
            return False
        if not self.component_key:
            return True
        return self.component_key == component_key

    def specificity(self) -> int:
        # A statement naming a component is more specific than one that does
        # not, regardless of its declared scope.
        base = _SCOPE_RANK.get(self.scope, 9)
        return base if self.component_key else base + 10

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "cluster_id": self.cluster_id,
            "component_key": self.component_key,
            "status": self.status,
            "justification": self.justification,
            "remediation": self.remediation,
            "scope": self.scope,
            "version": self.version,
            "superseded_by": self.superseded_by,
            "author_user_id": self.author_user_id,
            "created_at": self.created_at,
        }


@dataclass
class EffectiveStatus:
    """The VEX status in force for one finding, and why."""

    status: str
    statement_id: str
    justification: str = ""
    #: Every statement that applied, newest first. Rendered so a reviewer can
    #: see the history rather than only the current answer.
    history: list[dict[str, Any]] = field(default_factory=list)

    @property
    def suppresses(self) -> bool:
        """Whether this status removes the finding from the ACTIONABLE list.

        ⚠ NOT from the report. A suppressed finding still appears, with its
        status and justification beside it. Removing it would make "we assessed
        this and it does not apply" indistinguishable from "we never saw it".
        """
        return self.status in ("not_affected", "fixed")

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "statement_id": self.statement_id,
            "justification": self.justification,
            "suppresses_from_actionable": self.suppresses,
            "history": self.history,
        }


def validate(statement: VexStatement) -> list[dict[str, Any]]:
    """Check a statement against CSAF. Returns diagnostics, never raises."""
    out: list[dict[str, Any]] = []

    if statement.status not in STATUSES:
        out.append(
            {
                "severity": "error",
                "code": "VEX_STATUS_INVALID",
                "message": f"{statement.status!r} is not a CSAF 2.0 status",
                "hint": f"one of: {', '.join(sorted(STATUSES))}",
            }
        )

    if statement.status == "not_affected" and not statement.justification:
        # ⚠ CSAF requires it, and for a good reason: "not affected" with no
        # argument behind it is an assertion a reviewer cannot evaluate.
        out.append(
            {
                "severity": "error",
                "code": "VEX_JUSTIFICATION_REQUIRED",
                "message": "not_affected requires a justification",
                "hint": (
                    "CSAF 2.0 requires it; an unjustified suppression is an "
                    "assertion a reviewer cannot evaluate"
                ),
            }
        )
    elif statement.justification and statement.justification not in JUSTIFICATIONS:
        out.append(
            {
                "severity": "warn",
                "code": "VEX_JUSTIFICATION_UNKNOWN",
                "message": f"{statement.justification!r} is not a CSAF justification code",
                "hint": f"one of: {', '.join(sorted(JUSTIFICATIONS))}",
            }
        )

    return out


def effective_for(
    statements: Iterable[VexStatement], *, cluster_id: str, component_key: str
) -> EffectiveStatus | None:
    """The status in force for one finding, or None if nothing applies.

    Most specific scope wins; ties break on the latest timestamp, then on the
    highest version. Superseded statements are excluded from the decision but
    KEPT in the history.
    """
    applicable = [s for s in statements if s.applies_to(cluster_id, component_key)]
    if not applicable:
        return None

    # Newest first for the history, regardless of which one wins.
    history = sorted(
        applicable,
        key=lambda s: (s.created_at, s.version),
        reverse=True,
    )

    live = [s for s in applicable if not s.superseded_by]
    if not live:
        # Every statement was superseded and the successors are not in this set.
        # Reporting nothing would silently drop an assertion that exists, so the
        # most recent superseded one stands, with its history visible.
        live = applicable

    winner = sorted(
        live,
        key=lambda s: (s.specificity(), _negate(s.created_at), -s.version),
    )[0]

    return EffectiveStatus(
        status=winner.status,
        statement_id=winner.id,
        justification=winner.justification,
        history=[s.as_dict() for s in history],
    )


def _negate(timestamp: str) -> tuple[int, ...]:
    """Sort key that puts the LATEST timestamp first.

    Strings do not negate, so the codepoints are inverted. Only correct for
    fixed-width RFC3339 with a literal Z — which is the only form this codebase
    ever stores (CLAUDE.md conventions).
    """
    return tuple(-ord(c) for c in timestamp)


def apply(
    findings: Iterable[Any], statements: Iterable[VexStatement]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Join VEX onto findings. Returns (rows, diagnostics).

    ⚠ RETURNS A SEPARATE JOIN TABLE rather than modifying the findings.

    The finding stays exactly what the scanners reported. A caller that wants
    the actionable list filters on `suppresses_from_actionable`; a report
    renders both. Nothing here writes to a finding, which is what keeps the
    observation and the assertion independently auditable.
    """
    statements = list(statements)
    diagnostics: list[dict[str, Any]] = []
    for statement in statements:
        diagnostics.extend(validate(statement))

    rows: list[dict[str, Any]] = []
    for finding in findings:
        effective = effective_for(
            statements,
            cluster_id=getattr(finding, "vuln_cluster_id", ""),
            component_key=getattr(finding, "component_key", ""),
        )
        if effective is None:
            continue
        rows.append(
            {
                "vuln_cluster_id": finding.vuln_cluster_id,
                "component_key": finding.component_key,
                **effective.as_dict(),
            }
        )

    if rows:
        suppressed = sum(1 for r in rows if r["suppresses_from_actionable"])
        if suppressed:
            diagnostics.append(
                {
                    "severity": "info",
                    "code": "VEX_SUPPRESSED_FINDINGS",
                    "message": f"{suppressed} finding(s) carry a not_affected or fixed status",
                    "hint": (
                        "they remain in the report with their justification; VEX joins to "
                        "a finding and never removes it"
                    ),
                }
            )

    return sorted(rows, key=lambda r: (r["vuln_cluster_id"], r["component_key"])), diagnostics
