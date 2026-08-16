# Phase 13 — VEX, CSAF and comments

**Estimated: 3 weeks** · Depends on Phase 10.

## Read first

1. `docs/STATE.md`
2. `docs/reference/certin-v2.0.yaml` → `vex`, `csaf` (PDF p.35–36)
3. `docs/01-DATA-MODEL.md` §7 (`vex_statements`, `csaf_advisories`), §8 (comments)
4. `docs/03-NORMALIZER-SPEC.md` §2.6

## Goal

Triage findings through the four VEX statuses, publish CSAF 2.0 advisories, and let teams discuss reports.

## Preconditions

Findings exist and are deduped by cluster. Report viewer works.

## Out of scope

Automated VEX generation, ingesting third-party VEX documents (roadmap), notification delivery (Phase 14).

## Deliverables

```
services/scan-orchestrator/vex/     create, update, history, effective status
services/report/csaf/               CSAF 2.0 generate + validate
services/comment/                   threaded CRUD

frontend/  findings triage panel, VEX history, CSAF viewer, comment rail
libs/go-shared/csaf/                CSAF 2.0 types + schema validation
```

## Contracts to honour

- **The four statuses, exactly**: `not_affected`, `affected`, `fixed`, `under_investigation` (PDF p.35, restated identically for CBOM/QBOM p.48, AIBOM p.56, HBOM p.62).
- **VEX is append-only and iterative.** The guideline is explicit that it updates with each change. A new statement **supersedes**; nothing mutates. Full history is preserved and visible.
- **VEX never mutates a finding.** It joins to it. Effective status = most specific scope, then latest timestamp.
- VEX attaches to `(component_key, cluster_id)` — **cluster, not raw vuln id** — so a triage decision survives alias-graph changes.
- CSAF follows VEX in sequence (PDF p.35 Figure 7): discovery → VEX → CSAF → mitigation → ongoing updates → SBOM integration.
- Comments are threaded to depth 5; edits and deletes are audited.

## Steps

1. VEX CRUD. Create writes a new version; `superseded_by` links the chain. Statements carry justification, remediation, workarounds and downtime — all four are named in the guideline text on p.35, not just status.
2. Effective-status resolution: scope specificity first, then timestamp. Test the ambiguous cases explicitly rather than letting resolution order be incidental.
3. History endpoint returning the full chain with authors and timestamps.
4. CSAF 2.0 generation: description, affected versions, severity, mitigation, tracking id. Validate against the official schema; store the full document in `csaf_advisories.document` for round-trip fidelity.
5. Wire VEX status into report rendering — the section stubbed in Phase 9 becomes real. Findings tables show effective VEX status alongside severity.
6. Cross-reference component data with VEX status for the "current vulnerability landscape" view the guideline asks for (p.49 §8.4.1.11).
7. Comments: threaded per report, mentions, edit and delete with audit. Optimistic UI with rollback.
8. Frontend: inline triage on a finding row without leaving the table; history timeline; CSAF viewer; comment rail on the report viewer.
9. Update `docs/STATE.md`.

## Test requirements

- All four statuses settable; every transition recorded.
- **A new statement supersedes rather than mutates**; history is complete and ordered.
- Effective status resolves correctly when two statements have different scopes, and when two share a scope but differ in timestamp.
- VEX survives an alias-cluster merge — because it attaches to the cluster, a triage decision is not silently orphaned when clusters change. **This is the test that justifies the cluster-not-vuln-id choice; do not skip it.**
- CSAF validates against the 2.0 schema; round-trips without loss.
- Report reflects VEX status; a `not_affected` finding is visibly de-emphasized rather than deleted.
- Comments thread to depth 5 and refuse deeper; edits and deletes are audited.
- **Cross-tenant**: VEX statements and comments of tenant B are invisible from tenant A.
- RBAC: a Viewer can comment but cannot edit VEX.

## Exit criteria

```
go test ./services/scan-orchestrator/vex/... ./services/report/csaf/... ./services/comment/... -v
go test ./libs/go-shared/csaf -run TestRoundTrip -v
task verify
```

Manual: triage a real finding through all four statuses → generate a CSAF advisory → confirm it appears in a regenerated report → thread a comment discussion on that report.

## Before you finish

Update `docs/STATE.md`: VEX and CSAF working, whether third-party VEX ingestion is still deferred, and any effective-status ambiguity you resolved by convention (document the convention).
