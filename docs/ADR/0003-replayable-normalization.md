# ADR-0003 — Replayable normalization over immutable raw artifacts

**Status:** Accepted · 2026-08-16

## Context

Normalization — component identity, vulnerability alias closure, license resolution, graph merge, coverage — is the hardest correctness problem in the system and produces every number a customer sees. It **will** contain bugs, and some will be found months after reports have been issued.

Three questions follow:

- How do you fix a dedup bug without re-scanning every historical project?
- How do you defend a report issued six months ago?
- How do you absorb a CERT-In revision without re-running everything?

## Decision

**Normalization is a deterministic pure function of *(raw artifacts + ruleset version + alias snapshot)*.**

- Raw scanner output is written once to object storage and **never mutated or deleted**.
- Fixing a bug means **re-normalizing stored artifacts into `normalization_version + 1`** — not re-running scanners.
- Normalized data is never overwritten in place. It is versioned.
- Every `bom_document` records `ruleset_version`, `alias_snapshot_id` and `spdx_license_list_version`.

Implementation consequence: **no `time.Now()`, no randomness, no network calls inside the normalizer.** The alias graph is passed in as a pinned snapshot; `generated_at` comes from the scan record. A function needing the current time takes it as an argument.

## Consequences

Three things this buys, each of which would otherwise be very expensive:

1. **Reports are defensible.** The exact inputs and ruleset are recorded, so "where did this line come from?" has an answer.
2. **Fixes are retroactive.** A dedup bug fixed in month 9 applies to every scan ever run, without touching a customer's repository.
3. **Standards revisions are data changes.** CERT-In v2.1 becomes a profile update plus a re-normalization pass — not a re-scan of every project. Combined with ADR-0007, this is the difference between a week and a quarter.

Costs: object storage grows monotonically (raw artifacts are compliance evidence, so retention is a policy decision, not a storage one), and determinism must be actively maintained — sort every collection before serializing, or golden tests flap and their failures start being ignored, which is worse than not having them.

## Alternatives rejected

**Re-run scanners on bug fix.** Expensive, slow, and — worse — **not reproducible**: vulnerability databases have moved, upstream tools have changed, and the repository HEAD may differ. You would get a different answer and be unable to tell which part of the difference was your fix.

**Mutate normalized data in place.** Destroys the audit trail. A report referencing a finding that has since been silently rewritten is not evidence of anything.
