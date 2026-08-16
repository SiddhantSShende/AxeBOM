# ADR-0005 — Durable surrogate ids for vulnerability clusters

**Status:** Accepted · 2026-08-16

## Context

Four engines report the same vulnerability under four namespaces: grype emits GHSA, osv-scanner emits OSV-native (`GO-`, `PYSEC-`, `RUSTSEC-`), dependency-check emits CVE, trivy emits both. Deduping on the primary id inflates counts roughly 3× — a report claiming 240 vulnerabilities where there are 80 drives real remediation budgets.

The fix is union-find over an alias-edge graph: the connected component is the vulnerability identity. The question is **what identifies that component**.

## Decision

**`normalize.vuln_clusters.id` is a durable surrogate row, never derived from its members.**

Merging two clusters writes `normalize.vuln_cluster_merges(from_id, into_id, evidence_edge_id)`; a view resolves old ids forward. **Reports pin `display_id_at_render`.**

Three guards against over-merge, all required:

1. **Refuse CVE↔CVE merges unless an authoritative source asserts it** (OSV or GHSA, not a scanner).
2. **Cap cluster size.** Above 12 members, flag for review and stop auto-merging.
3. **Log every merge with its evidence edge.**

## Rationale

### The trap

The tempting implementation is a content-derived id — `uuidv5(sorted member list)`. It is deterministic, needs no extra table, and is wrong.

**It mutates the moment a new alias is discovered.** When OSV publishes an alias linking a previously-separate advisory, the member set changes, so the id changes. Every foreign key breaks. Every previously issued report references an id that no longer exists. The failure is silent and arrives weeks after the code shipped.

A durable surrogate plus a forwarding table costs one small table and makes cluster identity stable under exactly the conditions that will occur.

### Pinning the display id

A report issued in March says `CVE-2021-44228`. In September that cluster may have absorbed more aliases and its lowest-rank member may differ. **The report must still say what it said** — it is a compliance artifact, not a live view. `display_id_at_render` is stored on the finding.

### Over-merge

OSV aliases are not always equivalence-safe. Batched GHSAs alias several genuinely distinct CVEs; `MAL-` ids alias broadly. Unguarded union-find eventually collapses unrelated vulnerabilities into one cluster and **under-reports** — a worse failure than the 3× over-count it was fixing.

The size cap is heuristic and admitted as such: a cluster above 12 members is far more likely an over-merge than a real advisory family. Flagging for review rather than blocking makes the heuristic's error recoverable.

Logging every merge with its evidence edge exists because a compliance product must be able to answer "why did these two findings become one?" If it cannot answer that, the merge should not have happened.

## Consequences

An extra table and a resolution view. `alias_cluster_size` is a monitored histogram — a rising tail is the early signal of over-merge.

The alias graph is **global, not per-scan**, and grows monotonically. Recomputation is incremental union-find with a merge log, touching only affected clusters; never a full recompute.

Golden fixtures `log4shell-java` (closure across three partial edge sets) and `alias-overmerge` (guards hold) are the regression tests.
