# ADR-0004 — One engine per job

**Status:** Accepted · 2026-08-16

## Context

A scan runs several engines per BOM family — SBOM alone uses syft, grype, trivy-fs, osv-scanner and dependency-check. The obvious model is one job per family, with the worker running all of that family's tools.

## Decision

**The orchestrator fans out one job per engine.** `ScanJobV1.engine` holds exactly one engine id, and `scan.engine_runs` has one row per (scan, engine).

Relatedly: **the unit is (tool, mode), not tool.** `trivy fs` and `trivy image` have different capabilities and different parsers, so `trivy-fs` and `trivy-image` are separate engines.

## Rationale

**Partial failure becomes expressible.** With one job per family, "grype timed out but syft succeeded" has no clean representation — the job either succeeded or it did not.

**Retry becomes proportionate.** All-or-nothing retry means re-running syft because dependency-check timed out. Since dependency-check's first NVD sync can take 30–60 minutes, that is not a hypothetical cost.

**Progress becomes honest.** Per-engine rows let the UI show one engine `partial` while others succeed — as it happens, rather than discovered in the report.

**Timeouts become tunable.** dependency-check and syft do not deserve the same wall-clock budget.

**Scheduling becomes flexible.** Engines run concurrently, and a slow one does not block the rest.

## Consequences

More jobs and more rows, which is cheap. Progress is a weighted mean over engines using `scan.engine_runs.weight`, computed by the orchestrator.

`partial` is a **first-class status, not an error**. Scan status derives mechanically: all succeeded → `completed`; ≥1 succeeded and ≥1 not → `completed_with_errors`; zero succeeded → `failed`. It is never hand-set.

This makes the **Engine Coverage** section of every report possible, and that section is the honest core of the product: an SBOM that silently omits an ecosystem converts an unknown into a false negative the customer trusts.

**Invalid engine/source combinations are rejected at scan-create time with a 422** enumerating every offending pair. Discovering at worker time that `cbomkit-theia` cannot process an `image` source, twenty minutes in, would be a design failure.

Requires ADR-0008: with N engine jobs per scan, source must be materialized once beforehand, or N clones race.
