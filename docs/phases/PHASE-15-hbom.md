# Phase 15 — HBOM

**Estimated: 2.5 weeks** · Depends on Phase 10.

## Read first

1. `CLAUDE.md` — **invariant 9 (no GPL)**
2. `docs/STATE.md`
3. `docs/reference/certin-v2.0.yaml` → `hbom` (20 Table-11 elements + **4 from §10.4.1.4**)
4. `docs/01-DATA-MODEL.md` §6 (`hardware_components`)
5. `docs/04-OSINT-INTEGRATION.md` — HBOM section

## Goal

Hardware bills of materials via structured import and manual entry, with recursive subcomponents and optional part enrichment.

## The honest label

**There is no open-source HBOM scanner.** No tool discovers physical parts. This is import plus a data model, and **the UI must say so** — an "HBOM scan" button that only reads a CSV is a lie the customer will discover at exactly the wrong moment.

## The GPL constraint

`django-bom` is **GPL-3.0**. Importing it would make `hbom-worker` a GPL derivative work. It is also a Django *application*, not a library, so it cannot be embedded anyway.

**Use it as a schema reference only. Never `pip install` it, never import it.** Our model is ~24 fields in a recursive tree — roughly 300 lines. Write it.

## Preconditions

MVP works. Nothing else — this phase has no scanner dependency.

## Out of scope

Inventory management, purchasing, stock levels. EncoreBOM is a BOM platform, not an ERP.

## Deliverables

```
workers/hbom/
  csv_import.py     StockFlow-shaped and generic
  form.py           structured manual entry
  normalize.py      -> HardwareComponent
  providers/        base.py  manual.py  nexar.py  mouser.py

services/report/render/  HBOM sections
frontend/  CSV upload + column mapping, recursive tree editor, part lookup
fixtures/hbom-nested/
```

## Contracts to honour

- **All 24 elements**: Table 11's 20 **plus** the four from §10.4.1.4 (p.62) — `firmware_version`, `origin`, `criticality`, and vulnerabilities. Table 11 alone is incomplete, and a tool implementing only Table 11 is not compliant.
- **Two distinct supplier relationships.** Table 11 lists "Supplier Information" and "Supplier Location" twice with different descriptions: the product's supplier, and the component's supplier to the manufacturer. Four columns, not two.
- **`PartDataProvider` defaults to `manual`.** Nexar/Octopart is commercial and quota-limited; it must never be a hard dependency.
- Recursion is depth-capped (default 10) with a diagnostic, not unbounded.
- **Zero GPL code in the binary.** The license check from Phase 2 must still pass.

## Steps

1. `HardwareComponent` model with `parent_id` self-reference. All 24 fields, `not-provided` where absent.
2. CSV importer. Expected columns: `level, part_number, description, quantity, manufacturer, mpn, supplier, unit_cost`. **`level` drives the recursive tree.** Support a column-mapping step so a customer's own export shape works without editing their file.
3. Validate on import: level continuity (a level-3 row cannot follow a level-1 row), duplicate part numbers, and — as everywhere — **escape any cell beginning `= + - @` TAB CR on the way back out**.
4. Structured form for manual entry, recursive, with the same `not-provided` discipline.
5. `PartDataProvider` interface; `manual` returns nothing and is the default; `nexar` and `mouser` behind config, cached and batched.
6. Enrichment maps MPN → manufacturer, datasheet, lifecycle/EOL, compliance attributes (RoHS, CE) → the relevant Table 11 fields.
7. Report sections: recursive component tree, manufacturer origin (a supply-chain provenance signal, per §10.2.1), compliance, criticality.
8. Export via extended SBOM / CycloneDX per §10.4.1.6.
9. Frontend: upload with column mapping and a preview, tree editor, part lookup where a provider is configured.
10. Fixture `hbom-nested`: four levels, both supplier relationships populated. Update `docs/STATE.md`.

## Test requirements

- CSV import builds the correct tree from `level`.
- Malformed level sequence is rejected with a legible error naming the row.
- Recursion renders to depth 4; depth 11 hits the cap with a diagnostic rather than recursing.
- **All 24 elements** present or explicitly `not-provided`.
- **Both supplier relationships stored distinctly** — assert the product supplier and component supplier are separately queryable.
- `manual` provider works with no API key configured (the default path must be the tested path).
- Nexar provider is skipped cleanly when unconfigured — no error, no empty-credential call.
- **Formula injection escaped** on HBOM export.
- **License check passes: zero GPL in the dependency tree.** Run it explicitly as part of this phase's exit.
- Cross-tenant isolation on hardware components.

## Exit criteria

```
go test ./workers/hbom/... -v
task test:golden        # incl. hbom-nested
task osint:verify       # license check: no GPL
task verify
```

Manual: import a nested CSV → tree renders → add a component by form → optional part lookup → report shows manufacturer origin, compliance and the recursive tree.

## Before you finish

Update `docs/STATE.md`: HBOM working, which providers are configured, **confirm zero GPL in the binary**, and confirm the UI labels HBOM as import rather than discovery.
