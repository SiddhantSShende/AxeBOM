# Phase 9 — Reports

**Estimated: 3.5 weeks** · Depends on Phase 8.

## Read first

1. `docs/STATE.md`
2. `docs/01-DATA-MODEL.md` §8 (schema `report`)
3. `docs/reference/certin-v2.0.yaml` — the field tables render from this
4. **`docs/05-SECURITY-MODEL.md` §5 (output-side vulnerabilities)**
5. `docs/06-COMPLIANCE-PROFILES.md` §7

> **When implementing:** load the `pdf` skill before building the PDF renderer and the `xlsx` skill before the spreadsheet writer.

## Goal

Canonical BOM → SPDX and CycloneDX documents → PDF, XLSX and JSON, rendered asynchronously, signed, and shareable.

## Preconditions

Normalized data exists; `task test:golden` passes.

## Out of scope

Frontend viewer (Phase 10), VEX/CSAF sections (Phase 13 — leave the section stubbed with a clear "no VEX statements" state, not omitted).

## Deliverables

```
services/report/
  handler/    get, download, share, revoke, shared
  export/     spdx.go cyclonedx.go   (via protobom)
  render/     pdf.go xlsx.go json.go
  render/safe/cell.go    ← formula-injection escaping
  sign/       ed25519 detached signature
  share/      token issue + verify
  level/      top-level vs complete projection

cmd/axebom/verify.go     public signature verification
testdata/golden/*.spdx.json *.cdx.json
```

## Contracts to honour

- **`protobom` is the serialization layer** — do not hand-roll SPDX or CycloneDX writers.
- **Every report carries the Engine Coverage section.** Mandatory, not suppressible by a template. An SBOM that silently omits an ecosystem converts an unknown into a false negative.
- **Both coverage numbers**, with the formula printed and a footer noting the weights are AxeBOM's judgement, not CERT-In's.
- **Field tables render from the profile.** Never hardcode a count.
- **`not-provided` renders explicitly** — never blank, never omitted.
- **Escape every spreadsheet cell** beginning `= + - @` TAB CR, **in the writer**, unconditionally.
- Rendering is **async**: `status` moves `queued → rendering → ready`. Never block HTTP on a Complete BOM.
- **The word "compliant" does not appear in generated output.**

## Steps

1. Level projection: Top-Level = `depth <= 1` from the root set; Complete = everything including flagged orphans.
2. SPDX 2.3 and CycloneDX 1.6 exporters via protobom. Golden-file tests, byte-stable, validated against the official schemas.
3. JSON: the canonical document plus both standard documents.
4. **XLSX**: one sheet per entity, every profile field as a column. Streaming writer for memory. **`render/safe/cell.go` escaping applied unconditionally at the writer, not at call sites** — a call site will eventually be added without it.
5. **PDF** sections: executive summary · project, owner, validity · classifications and SDLC stage · **the six practices** · **coverage, both numbers, with formula and per-field breakdown** · **Engine Coverage incl. ecosystems with no engine** · component tables · license inventory · findings with CVSS and sources · VEX table (stubbed) · CSAF section (stubbed) · criticality breakdown · dependency graph summary · methodology footnotes (incl. the CERT-In `&subpath` vs `#subpath` discrepancy) · timestamp, author, signature.
6. **Page cap.** 50k components is 3000+ pages. Cap, set `truncated = true`, and write an explicit truncation note pointing to XLSX/JSON. Product rule: Top-Level → PDF, Complete → XLSX/JSON. `REPORT_TOO_LARGE_FOR_PDF` rather than an OOM.
7. PDF renderer runs with **remote resource loading disabled** — an `<img src="http://attacker/">` in a component description must not phone home.
8. Ed25519 detached signature via Vault Transit; publish the public key; `axebom verify` checks it.
9. Share links: 256-bit CSPRNG token, **hash stored**, optional expiry and download cap, every access audited, immediate revocation. `/shared/:token` is unauthenticated — rate-limit by IP, `Cache-Control: no-store`, `Content-Disposition: attachment`.
10. Async render worker with progress. Update `docs/STATE.md`.

## Test requirements

- SPDX and CycloneDX outputs validate against official schemas; golden-file, byte-stable.
- **Formula injection**: the `hostile-names` fixture component `=cmd|'/c calc'!A1` is escaped in XLSX **and** CSV.
- PDF of a 50k-component Complete BOM does not OOM — it truncates with a note.
- PDF render does not fetch remote resources.
- Signature verifies on a good report; **fails on a mutated one**.
- Share link: read-only, expires, respects the download cap, revocation is immediate, access is audited.
- **A Viewer cannot download a `private` report** (CERT-In §5.3.2 — private is the one with vulnerability detail).
- Every profile field appears in the XLSX; `not-provided` renders explicitly.
- Coverage numbers in the report match the database.
- Cross-tenant: report of tenant B is not downloadable from tenant A (404).

## Exit criteria

```
go test ./services/report/... -v
go test ./services/report/render/safe -run TestFormulaInjection -v
task verify
```

Manual: one scan → PDF + XLSX + CycloneDX + SPDX → `axebom verify` passes → share link renders read-only in a clean browser profile.

## Before you finish

Update `docs/STATE.md`: formats working, page cap value, signing key location, and which report sections are still stubbed.
