# Phase 10 — Dashboard and dependencies

**Estimated: 3 weeks** · Depends on Phase 9. **← MVP boundary.**

## Read first

1. `docs/STATE.md`
2. **`docs/07-FRONTEND-SPEC.md` — in full**
3. `docs/02-CONTRACTS.md` §8 (REST), §10 (WebSocket)

> **When implementing:** load the `frontend-design` skill before writing components.

## Goal

The product becomes usable by someone who has not read the specs. The five-step generate flow, live progress, the dependencies explorer, findings, and the report viewer.

**Completing this phase means EncoreBOM is shippable as an SBOM platform.** Everything after adds BOM types and enterprise features.

## Preconditions

Reports generate and download; scans stream progress.

## Out of scope

CBOM/QBOM/AIBOM/HBOM UI (Phases 11–15 add their own views), VEX triage UI (Phase 13), campaigns UI (Phase 14).

## Deliverables

```
frontend/src/
  routes/  projects/{list,new,detail,practices}
           generate/  scans/[id]  dependencies/  findings/
           reports/[id]  shared/[token]  settings/
  components/  bom-type-chip  severity-badge  coverage-panel
               engine-coverage-table  scan-progress  dependency-table
               dependency-graph  component-drawer  finding-row
  lib/  api (generated types)  ws  query
  design/  tokens.css  theme.ts

services/gateway/handler/  dependencies, findings (keyset paginated)
e2e/  Playwright specs
```

## Contracts to honour

- Server state lives in TanStack Query **only**. Zustand holds theme, sidebar, and the wizard draft — nothing that round-trips.
- **BOM-type chips are glyph + label + colour.** Never colour alone (WCAG 1.4.1).
- **Keyset pagination**, never `OFFSET`.
- **Snapshot on WebSocket connect.** The stream is advisory; a reconnecting client must be immediately correct.
- Filters are URL state, so a view is shareable.
- Errors render `code`, `message`, copyable `request_id`, and a docs link. **Never "Something went wrong."**

## Steps

1. Design tokens: light and dark on `:root` with a `prefers-color-scheme` override and a `data-theme` override so the toggle wins both ways. Five BOM accents, five severity levels.
2. Projects list and the three-step connect wizard, including the practices step.
3. **The five-step generate flow.** Steps 2–5 genuinely multi-select. Wizard draft persists in Zustand and survives a refresh — losing four steps of configuration to a stray reload is the kind of small cruelty that makes people distrust a tool. The review step renders 422 combination errors **inline against the responsible step**, not as a toast.
4. Live progress: overall weighted bar plus per-engine rows with status pills. Reconnect with backoff showing a "reconnecting" state rather than a frozen percentage. Announce transitions to a polite live region.
5. **Dependencies explorer.** Virtualized table over 50k rows: name, version, ecosystem, license, direct/transitive, criticality, severity summary, **discovered-by provenance chips**. Filters for license, severity, direct/transitive, ecosystem, engine, full text.
6. Component drawer: every profile field with `not-provided` shown explicitly, all locations, candidate identities, provenance chain, and **both identifiers side by side, clearly labelled as different things**.
7. Dependency graph as a separate tab, defaulting to the subgraph around a selected component. At 50k nodes a force-directed graph is decoration. Render cycles rather than hanging the layout.
8. Findings grouped by cluster. **`severity_conflict` is an expandable badge showing who said what** — never hidden.
9. Report viewer: section nav, download menu with per-format render state, share dialog warning on `private` reports. **Coverage (both numbers) and Engine Coverage are prominent, not footer material.**
10. Empty, loading and error states everywhere; skeletons not spinners. Update `docs/STATE.md`.

## Test requirements

Playwright, the seven flows in `07-FRONTEND-SPEC.md §9`. The two that matter most:

- **Full E2E**: connect a repo → five-step flow → live progress → download a PDF.
- **A Viewer cannot download a `private` report.**

Plus: axe accessibility assertions on every route in CI; wizard state machine unit tests; WebSocket reconnect test (drop mid-scan, confirm correct state after snapshot); the dependencies table renders 50k rows without freezing.

## Exit criteria

```
npm --prefix frontend run build
npx playwright test
task verify
```

Manual, and this is the real test: **hand the app to someone who has not read these documents.** They should be able to connect a repo, run a scan, and download a report without guidance.

## Before you finish

Update `docs/STATE.md`: **mark M2 / MVP reached.** Record which screens are complete, which are stubbed for later BOM types, and any accessibility issue deferred.
