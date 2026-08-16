# 07 — Frontend Specification

Routes, state management, the design system, and the screens. Implementation lands in Phase 10; the BOM-type visual language and the progress model are decided here so earlier phases emit the right data.

> **When implementing:** load the `frontend-design` skill before writing components, for visual direction.

---

## 1. Stack

React 19 + TypeScript + Vite · **TanStack Query** for all server state · **Zustand** for the little client state that exists (theme, sidebar, the generate-flow wizard draft) · React Router · Tailwind + shadcn/ui (Radix primitives) · Recharts for charts, `@xyflow/react` for the dependency graph · native WebSocket with reconnect · Playwright for E2E.

**The rule that keeps this simple:** server data lives in TanStack Query and nowhere else. No Redux, no duplicating API responses into Zustand, no `useEffect` sync between the two. Zustand holds only state that never round-trips.

Generated API types come from the OpenAPI spec (`task api:types`), so a contract change breaks the build rather than the runtime.

---

## 2. Design language

### BOM-type accents

Five types appear together constantly — in project cards, scan configs, report headers, filter chips. They need to be distinguishable at a glance **and never by colour alone** (WCAG 1.4.1).

| Type | Accent | Glyph |
|---|---|---|
| SBOM | indigo | `▣` package |
| CBOM | amber | `⚿` key |
| QBOM | violet | `◈` atom |
| AIBOM | teal | `◐` model |
| HBOM | slate | `▤` chip |

Every chip carries **glyph + label + colour**. Colour is reinforcement, never the signal.

### Severity

Critical / High / Medium / Low / None, each with an icon and a text label. In tables the severity column shows the word, not just a dot — a colour-blind user reading a vulnerability report is a compliance risk, not an edge case.

### Theme and accessibility

Light and dark, both first-class, driven by CSS custom properties defined on `:root` with a `prefers-color-scheme` override and an explicit `data-theme` override so the toggle wins in both directions.

Target **WCAG 2.2 AA**: 4.5:1 body contrast, 3:1 for UI components, visible focus rings everywhere, full keyboard operation of every flow including the generate wizard and the graph, `prefers-reduced-motion` honoured, live regions for scan progress.

### Density

Enterprise-dense but legible. Tables carry a lot; give them 32 px rows, sticky headers, column visibility controls, and a per-row expand rather than shrinking type. Optimize for **scannability of status** — a user opens this to answer "what changed and what is broken," not to read prose.

---

## 3. Routes

```
/login  /signup  /invite/:token
/                                      → redirect to /projects
/projects                              list
/projects/new                          connect / register wizard
/projects/:id                          overview
/projects/:id/dependencies             filterable inventory + graph
/projects/:id/findings                 vulnerabilities + inline VEX triage
/projects/:id/scans                    history
/projects/:id/practices                CERT-In Table 5 category 3
/projects/:id/settings
/generate                              the 5-step flow
/scans/:id                             live progress
/reports/:id                           viewer + comments
/shared/:token                         unauthenticated read-only
/campaigns  /campaigns/new  /campaigns/:id
/settings/{org,members,integrations,api-keys,audit}
```

---

## 4. The generate flow

The product's signature interaction. A five-step stepper composing one `Scan`.

```
1  Project          single select
2  Classification   multi   SBOM CBOM QBOM AIBOM HBOM
3  Report type      multi   Top-Level · Complete
4  Standard         multi   SPDX · CycloneDX
5  Format           multi   PDF · XLSX · JSON · CycloneDX · SPDX
                    → Review → Run
```

Rules that matter:

- **Steps 2–5 are genuinely multi-select.** The guideline permits combinations and the user asked for them; do not quietly force single-select for implementation convenience.
- Only classifications the project carries are offered, with a link to add more.
- **Invalid engine/source combinations are surfaced at step 6, not after Run.** The API rejects them with a 422 enumerating offending pairs (`02-CONTRACTS.md §7`); the review step renders that inline against the responsible step rather than as a toast.
- The wizard draft persists in Zustand and survives a refresh. Losing four steps of configuration to a stray reload is the kind of small cruelty that makes people distrust a tool.
- Review shows exactly what will be produced: N reports, which engines will run, and an estimated duration.

---

## 5. Live progress

`WS /api/v1/scans/:id/progress`. The client receives a **snapshot on connect**, then `ScanEventV1` frames.

The snapshot is why this can be simple: **the stream is advisory and lossy-tolerant, and the database is the source of truth.** A dropped socket, a missed event, a background tab — reconnect, take the snapshot, and be correct. Never build progress logic that requires receiving every event.

Display: an overall weighted bar plus a per-engine row (name, status pill, percentage, duration). Engine rows are the honest view — one engine `partial` while others succeed is normal and must be visible as it happens, not discovered in the report.

Reconnect with exponential backoff, capped, showing a "reconnecting" state rather than freezing at the last percentage. Progress announced to screen readers via a polite live region, throttled to meaningful transitions.

---

## 6. Screens worth specifying

### Projects list
Cards or table. Each shows name, BOM-type chips, owner, validity window (with an expiry warning inside 30 days), last scan status, open critical count. Filter by classification, owner, status.

### Connect / register wizard
Three steps: **source** (GitHub repo picker with search, or upload archive/manifest/lockfile/image ref, or fully manual) → **owner & validity** (name, email, GitHub, phone; validity window) → **classification & practices** (BOM types, SDLC stage, and the six CERT-In practices fields).

The practices step is not optional and is not buried in settings. Its six fields are a minimum element (`06-COMPLIANCE-PROFILES.md §6`), and a project without them cannot produce a complete compliance report — the UI should say that plainly at the point of entry rather than surfacing it as a coverage gap weeks later.

### Dependencies
The densest screen. Virtualized table over potentially 50k rows: name, version, ecosystem, license, direct/transitive, criticality, severity summary, **discovered-by** (engine provenance chips).

Filters: license, severity, direct vs transitive, ecosystem, engine, full-text. Filters are URL state so a view is shareable.

A row expands to a drawer showing every CERT-In field with its `not-provided` status made explicit, all locations, candidate identities, the provenance chain, and both identifiers (`purl` and `certin_identifier`) side by side and clearly labelled as different things.

The graph view is a separate tab, not the default — at 50k nodes a force-directed graph is decoration. Default to the subgraph around a selected component, expandable outward, with cycles rendered rather than crashing the layout.

### Findings
Grouped by cluster. Each shows display id, severity with source, `severity_conflict` badge where engines disagreed (**expandable to show who said what** — never hidden), affected components, fix availability, VEX status.

Inline VEX triage: set status, justification, remediation without leaving the row. History is visible; statements are append-only.

### Report viewer
Left section nav mirroring the PDF, main pane rendering the report, right rail for comments.

Two things must be prominent, not buried in a footer:
- **Coverage: both numbers**, side by side, with the formula available on hover and a per-field breakdown table.
- **Engine Coverage**, including ecosystems detected with no available engine. This is the honest denominator; it belongs where a reader will see it.

Download menu offers each generated format; formats still rendering show a progress state (rendering is async — a Complete BOM is not a synchronous request). Share dialog creates a token with optional expiry and download cap, warns clearly when the report is `private` (contains vulnerability detail per CERT-In §5.3.2), and lists and revokes existing links.

### Campaigns
Schedule wizard: projects (multi) → cadence (friendly presets over raw cron, with the cron shown and editable) → timezone → the same BOM/level/standard/format dimensions → notifications. Run history with status, duration, generated reports, and next scheduled run.

---

## 7. Empty, loading, error

Every list has a designed empty state that tells the user what to do next, not just "no data."

Loading: skeletons matching final layout, never spinners on full pages. Optimistic updates for comments and VEX status; rollback on failure with an explanation.

Errors render the `code` from the taxonomy, the human `message`, the `request_id` (copyable — it is what support will ask for), and a docs link. **Never a bare "Something went wrong."**

`403` on a private report offers to request access. `404` on a cross-tenant id looks like an ordinary not-found, because that is exactly what it must look like.

---

## 8. Performance

Route-level code splitting; the graph library loads only on the graph tab. Virtualize any list over 100 rows. Keyset pagination throughout — `OFFSET` is a table scan at these volumes. TanStack Query `staleTime` of 30 s for lists, `Infinity` for completed scans and reports (they are immutable). Prefetch a report on hover over its download button.

Budget: LCP under 2.5 s on a mid-range laptop, interaction under 200 ms, initial JS under 250 KB gzipped excluding the lazily-loaded graph.

---

## 9. Testing

Playwright E2E covering the flows that matter end to end:

1. Sign up with GitHub → land in a tenant → see role-appropriate navigation.
2. Connect a repo → register with owner, validity, classifications and practices.
3. Run the five-step flow → watch live progress → download a PDF.
4. Filter dependencies by license and severity; open the drawer; verify `not-provided` fields render explicitly.
5. Triage a finding through all four VEX statuses; verify history.
6. Create a share link; open it in a clean context; verify read-only.
7. **Verify a Viewer cannot download a `private` report.**

Component tests for the wizard state machine, the WebSocket reconnect path, and the severity-conflict expansion. Axe accessibility assertions on every route in CI.
