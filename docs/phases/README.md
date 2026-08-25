# Phase prompts

One file per phase. Each is a **standalone prompt** — hand it to a fresh session and it contains everything that session needs to know, plus pointers to the specs it must read.

## How to use

Open a new session and say:

> Implement Phase 3 of AxeBOM. Read `docs/phases/PHASE-03-auth-tenancy-rbac.md`.

Or `task phase -- 03` to print it.

**Do one phase per session.** Phases are sized so that a session can finish one without exhausting context, which is why the larger ones (8, 9, 10) are still single phases rather than split — their internal coupling is tighter than the context cost of doing them whole.

## Structure

Every file has the same eight sections, so a session knows where to look without reading the whole thing:

| Section | Purpose |
|---|---|
| **Read first** | Exact file list, in order. Keeps context tight — do **not** read all of `docs/`. |
| **Goal** | One paragraph. |
| **Preconditions** | What must already work, with commands to check. |
| **Out of scope** | Explicit do-not-touch. Prevents scope creep into a later phase's territory. |
| **Deliverables** | File manifest with paths. |
| **Contracts to honour** | Invariants this phase must not violate. **References the SSOT docs, never restates them** — a restated spec drifts, and a future session believes the wrong copy. |
| **Steps** | Ordered, with the reasoning behind the non-obvious ones. |
| **Test requirements** | Including the tests most likely to be skipped and most costly to skip. |
| **Exit criteria** | Literal commands. Machine-checkable. |
| **Before you finish** | Update `docs/STATE.md`. Non-negotiable. |

## The sequence

| # | Phase | Wks | |
|---|---|---|---|
| 00 | Foundations | 1.0 | |
| 01 | Data model, migrations, RLS | 2.0 | |
| 02 | OSINT supply chain | 1.0 | |
| 03 | Auth, tenancy, RBAC | 1.5 | |
| 04 | Projects and sources | 1.5 | |
| 05 | Sandbox and fetcher | 2.0 | ⚠ highest risk |
| 06 | Scan orchestration | 2.0 | |
| 07 | SBOM engine adapters | 2.5 | |
| 08 | Normalizer and golden corpus | 4.0 | ⚠ most important |
| 09 | Reports | 3.5 | |
| 10 | Dashboard and dependencies | 3.0 | **← MVP** |
| 11 | CBOM and QBOM | 3.0 | |
| 12 | AIBOM | 2.5 | |
| 13 | VEX, CSAF and comments | 3.0 | |
| 14 | Campaigns and notifications | 2.0 | |
| 15 | HBOM | 2.5 | |
| 16 | Hardening and launch | 3.0 | **← GA** |

**≈24 weeks to MVP. ≈40 weeks to GA.**

## Ordering

Phases 0–10 are strictly sequential; each depends on the one before.

**11–15 are independent of each other** and all depend only on Phase 10. They can be reordered, run in parallel with more people, or dropped if a BOM type turns out not to matter to your customers. The order given prioritizes CBOM/QBOM because post-quantum readiness is the differentiator competitors most often lack.

Phase 16 depends on everything.

## Two phases worth extra care

**Phase 5 (sandbox)** is where the project's largest risk lives. From that point on, AxeBOM executes third-party binaries over untrusted user code. Do not compress it, and do not treat the escape suite as optional.

**Phase 8 (normalizer)** produces every number a customer sees. A bug there does not crash anything — it quietly reports the wrong count. Four weeks is the honest estimate; the golden corpus is what makes it verifiable.
