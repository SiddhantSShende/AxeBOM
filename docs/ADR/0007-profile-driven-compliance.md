# ADR-0007 — Compliance standards are data, and counts are never hardcoded

**Status:** Accepted · 2026-08-16

## Context

CERT-In v2.0 defines 21 SBOM data fields, 11 QBOM elements, 4 crypto asset types with distinct field sets, 19 AIBOM elements and 24 HBOM elements. That list is needed by Go structs, Python models, report templates, exporters, the coverage checker, and UI copy.

Encoding it in each place means encoding it six times, and six copies drift.

## Decision

**One YAML file — `docs/reference/certin-v2.0.yaml` — is the source of truth.** Go structs and Python models are *generated* from it; report field tables and the coverage checker *read it at runtime*.

**Never hardcode a field count.** Not `21`, not "the 21 data fields", anywhere in code, tests, UI copy, or documentation. Render the count from the profile.

Every entry carries a `status` of `verified` (transcribed from a named page of a document read directly) or `assumed` (inferred from a secondary source, with a mandatory `note`). If any entry is `assumed`, every generated report says so:

> Validated against profile `certin-v2.0` revision 3 — 118 of 134 fields verified against the source document.

## Rationale

**A hardcoded count is how a product ships a false compliance claim.** The guideline revises to 23 fields; the profile is updated; the schema is updated; and the UI still reads "21 of 21 fields covered ✓" because nobody grepped for the literal. The claim is now false and nothing failed.

**Page citations make audits short.** `source_page: 23` against a committed PDF turns "where does this requirement come from?" into a lookup instead of an argument.

**The mechanism generalizes.** NTIA Minimum Elements, EU CRA, or an internal policy become sibling files with the same entry shape. A scan can be scored against several profiles at once, and nothing in the normalizer or exporters needs to know which standard it is scoring.

**Type-discrimination has to be expressible.** Table 9's four crypto asset types have different field sets. The profile models this with a discriminator and the coverage checker branches on it — because scoring a certificate against `key_size` would report every CBOM at roughly 30% coverage, falsely, in a document shown to a regulator.

## Consequences

A codegen step (`task profile:gen`) and a validator (`task profile:lint`, part of `task verify`).

`expected_counts` at the bottom of the profile are **transcription assertions, not application logic**. A mismatch means either the guideline was revised or the transcription is wrong — both need a human decision, never a silent fix.

Combined with ADR-0003, a standards revision is a **profile update plus a re-normalization pass** rather than a re-scan of every project. Historical reports keep their original profile revision recorded, so a report issued under v2.0 stays explainable after v2.1 ships.

Current state: 134 unique field ids, all 17 counts matching, **zero `assumed` entries** — the 66-page source PDF was read directly.
