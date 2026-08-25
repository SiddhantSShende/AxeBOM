/**
 * The five-step generate flow's state machine.
 *
 * ⚠ STEPS 2–5 ARE GENUINELY MULTI-SELECT.
 *
 * The guideline permits combinations and the user asked for them. Quietly
 * forcing single-select would be an implementation convenience that changes
 * what the product does — a customer who needs SPDX *and* CycloneDX would have
 * to run two scans and reconcile two component counts by hand.
 *
 * ⚠ THE DRAFT SURVIVES A REFRESH.
 *
 * Losing four steps of configuration to a stray reload is the kind of small
 * cruelty that makes people distrust a tool. The draft is the ONE piece of
 * wizard state Zustand holds; everything the server knows stays in TanStack
 * Query (docs/07-FRONTEND-SPEC.md §1).
 *
 * The machine lives here, separate from the components, because it is the part
 * with rules worth testing — and a state machine tested through a rendered
 * stepper is tested through three layers of the wrong thing.
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { BomType } from '../design/theme';
import type { ApiError } from './api';

export type Level = 'top_level' | 'complete';
export type Standard = 'SPDX' | 'CycloneDX';
export type Format = 'pdf' | 'xlsx' | 'json' | 'spdx' | 'cyclonedx';

/** StepId numbers the five steps plus review. */
export type StepId = 1 | 2 | 3 | 4 | 5 | 6;

export const STEPS: readonly { id: StepId; title: string; hint: string }[] = [
  { id: 1, title: 'Project', hint: 'Which project to scan.' },
  { id: 2, title: 'Classification', hint: 'Which bills of materials to produce.' },
  { id: 3, title: 'Report type', hint: 'How deep each BOM goes.' },
  { id: 4, title: 'Standard', hint: 'Which document standards to emit.' },
  { id: 5, title: 'Format', hint: 'Which files to generate.' },
  { id: 6, title: 'Review', hint: 'What will be produced, and what will run.' },
] as const;

export interface WizardDraft {
  projectId: string | null;
  /** Step 2 — multi. */
  bomTypes: BomType[];
  /** Step 3 — multi. */
  levels: Level[];
  /** Step 4 — multi. */
  standards: Standard[];
  /** Step 5 — multi. */
  formats: Format[];
}

export const EMPTY_DRAFT: WizardDraft = {
  projectId: null,
  bomTypes: [],
  levels: [],
  standards: [],
  formats: [],
};

/**
 * CombinationError is one offending pair from the API's 422.
 *
 * ⚠ RENDERED INLINE AGAINST THE RESPONSIBLE STEP, NEVER AS A TOAST. A toast
 * saying "invalid combination" leaves the user to work out which of five
 * multi-selects to change; `step` is what lets the review screen point at it.
 */
export interface CombinationError {
  step: StepId;
  message: string;
}

// ---------------------------------------------------------------------------
// Pure rules
// ---------------------------------------------------------------------------

/**
 * stepComplete reports whether a step has enough to move on.
 *
 * Every multi-select step needs at least one choice. There is no "skip" —
 * a scan with no formats produces nothing, and letting it through would
 * surface as an empty reports list an hour later.
 */
export function stepComplete(draft: WizardDraft, step: StepId): boolean {
  switch (step) {
    case 1:
      return draft.projectId !== null && draft.projectId !== '';
    case 2:
      return draft.bomTypes.length > 0;
    case 3:
      return draft.levels.length > 0;
    case 4:
      return draft.standards.length > 0;
    case 5:
      return draft.formats.length > 0;
    case 6:
      return true;
  }
}

/**
 * reachable reports whether a user may jump to a step.
 *
 * ⚠ BACKWARD IS ALWAYS ALLOWED; FORWARD ONLY OVER COMPLETED STEPS. Locking
 * backward navigation is the classic wizard mistake: a user who mis-selected on
 * step 2 should not have to restart, and one who cannot go back will abandon.
 */
export function reachable(draft: WizardDraft, step: StepId, current: StepId): boolean {
  if (step <= current) return true;
  for (let s = 1; s < step; s++) {
    if (!stepComplete(draft, s as StepId)) return false;
  }
  return true;
}

/** firstIncompleteStep is where "Resume" lands. */
export function firstIncompleteStep(draft: WizardDraft): StepId {
  for (const { id } of STEPS) {
    if (id !== 6 && !stepComplete(draft, id)) return id;
  }
  return 6;
}

/**
 * plannedReports is what the review step promises.
 *
 * ⚠ THE CROSS PRODUCT, COMPUTED HONESTLY. Three BOM types × two levels × five
 * formats is thirty reports, and a user who selects that deserves to see the
 * number BEFORE running it rather than discovering thirty rows afterwards.
 *
 * `standards` does not multiply: it constrains which formats are meaningful.
 * `spdx` and `cyclonedx` are formats in their own right; `pdf`, `xlsx` and
 * `json` render whatever standard the document carries.
 */
export function plannedReports(draft: WizardDraft): number {
  const formats = effectiveFormats(draft);
  return draft.bomTypes.length * draft.levels.length * formats.length;
}

/**
 * effectiveFormats drops a standard-specific format the user did not ask for.
 *
 * Selecting format `spdx` while choosing only the CycloneDX standard is a
 * contradiction the review step surfaces (see validateDraft). This function is
 * what the count is based on, so the promised number matches what runs.
 */
export function effectiveFormats(draft: WizardDraft): Format[] {
  return draft.formats.filter((f) => {
    if (f === 'spdx') return draft.standards.includes('SPDX');
    if (f === 'cyclonedx') return draft.standards.includes('CycloneDX');
    return true;
  });
}

/**
 * scannableBomTypes drops the two types Generate cannot ask the scanner for.
 *
 * HBOM has no scanner — it is a CSV/form import — and QBOM is derived from
 * CBOM discovery rather than scanned directly (CLAUDE.md honest labels).
 * `Orchestrator.CreateScan` refuses either family outright
 * (`SCAN_FAMILY_NOT_DIRECTLY_SCANNABLE`); this is what the wizard sends to
 * `POST /v1/scans`, kept separate from `draft.bomTypes` (which still drives
 * `POST /v1/reports` — a report can honestly be requested for HBOM/QBOM
 * without this run scanning for it, since the API resolves bom_document_id
 * from whatever already exists at render time).
 */
export function scannableBomTypes(draft: WizardDraft): BomType[] {
  return draft.bomTypes.filter((t) => t !== 'HBOM' && t !== 'QBOM');
}

/**
 * validateDraft finds the contradictions we can see WITHOUT calling the API.
 *
 * ⚠ IT DOES NOT REPLACE THE SERVER'S 422. The API owns which engine/source
 * combinations are valid, and it enumerates every offending pair
 * (docs/02-CONTRACTS.md §7). This catches only what is checkable from the draft
 * alone, so a user is not sent to Review to be told something the form already
 * knew.
 *
 * Duplicating a server rule here would be worse than checking nothing: the two
 * would disagree, and the client's answer would be the wrong one.
 */
export function validateDraft(draft: WizardDraft): CombinationError[] {
  const errors: CombinationError[] = [];

  // ⚠ BLOCKING, NOT ADVISORY — same reasoning as the step-4 check below.
  // `Orchestrator.CreateScan` refuses a scan with zero scannable families
  // unconditionally; a Run built entirely from HBOM and/or QBOM would 422
  // every time, and the draft alone is enough to know that in advance.
  if (draft.bomTypes.length > 0 && scannableBomTypes(draft).length === 0) {
    errors.push({
      step: 2,
      message:
        'HBOM and QBOM are not produced by a scan — HBOM is imported from the ' +
        "project's Hardware tab, and QBOM becomes available once a CBOM scan " +
        'has run for this project. Select a scannable type as well (SBOM, ' +
        'CBOM or AIBOM), or use those tools directly instead of Generate.',
    });
  }

  if (draft.formats.includes('spdx') && !draft.standards.includes('SPDX')) {
    errors.push({
      step: 4,
      message:
        'The SPDX format was selected but the SPDX standard was not. Add SPDX ' +
        'at step 4, or remove the SPDX format at step 5.',
    });
  }
  if (draft.formats.includes('cyclonedx') && !draft.standards.includes('CycloneDX')) {
    errors.push({
      step: 4,
      message:
        'The CycloneDX format was selected but the CycloneDX standard was not. ' +
        'Add CycloneDX at step 4, or remove the CycloneDX format at step 5.',
    });
  }

  // ⚠ A WARNING THE USER CAN OVERRIDE, NOT A REFUSAL. A Complete BOM of a large
  // project is thousands of PDF pages; the renderer caps it and says so. But
  // "Complete + PDF" is legitimate for a small project, and refusing it outright
  // would be the client overruling a decision the server is happy to make.
  if (draft.levels.includes('complete') && draft.formats.includes('pdf')) {
    errors.push({
      step: 5,
      message:
        'A Complete BOM can exceed a PDF page cap on a large project, in which ' +
        'case the PDF is truncated with a note pointing at the XLSX. XLSX and ' +
        'JSON have no page limit.',
    });
  }

  if (plannedReports(draft) > 40) {
    errors.push({
      step: 6,
      message:
        `This would generate ${plannedReports(draft)} reports. That is ` +
        'allowed, but each renders separately — narrowing one dimension is ' +
        'usually what was meant.',
    });
  }

  return errors;
}

/** blocking separates hard contradictions from advisory notes. */
export function blocking(errors: CombinationError[]): CombinationError[] {
  return errors.filter((e) => e.step === 4 || e.step === 2);
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

interface WizardState {
  draft: WizardDraft;
  current: StepId;
  /** serverErrors are the API's 422, kept separate from local validation. */
  serverErrors: CombinationError[];

  setProject: (id: string) => void;
  toggle: <K extends 'bomTypes' | 'levels' | 'standards' | 'formats'>(
    key: K,
    value: WizardDraft[K][number],
  ) => void;
  goTo: (step: StepId) => void;
  next: () => void;
  back: () => void;
  setServerErrors: (errors: CombinationError[]) => void;
  reset: () => void;
}

export const useWizard = create<WizardState>()(
  persist(
    (set, get) => ({
      draft: { ...EMPTY_DRAFT },
      current: 1,
      serverErrors: [],

      setProject: (id) =>
        set((s) => ({
          draft: { ...s.draft, projectId: id },
          // ⚠ A NEW PROJECT INVALIDATES DOWNSTREAM CHOICES, because only the
          // classifications a project CARRIES may be offered. Keeping them
          // would let a user run a CBOM against a project that is not
          // classified for one, and the server would reject it at Run — after
          // five steps of work.
          serverErrors: [],
        })),

      toggle: (key, value) =>
        set((s) => {
          const list = s.draft[key] as unknown[];
          const has = list.includes(value);
          return {
            draft: {
              ...s.draft,
              [key]: has ? list.filter((v) => v !== value) : [...list, value],
            },
            // A change invalidates the server's verdict on the old draft.
            // Leaving stale 422s on screen would have a user "fix" an error
            // they already fixed.
            serverErrors: [],
          };
        }),

      goTo: (step) => {
        if (reachable(get().draft, step, get().current)) set({ current: step });
      },

      next: () =>
        set((s) => {
          if (!stepComplete(s.draft, s.current)) return s;
          return { current: Math.min(6, s.current + 1) as StepId };
        }),

      back: () => set((s) => ({ current: Math.max(1, s.current - 1) as StepId })),

      setServerErrors: (errors) => set({ serverErrors: errors }),

      reset: () => set({ draft: { ...EMPTY_DRAFT }, current: 1, serverErrors: [] }),
    }),
    {
      name: 'axebom.wizard',
      // ⚠ THE STEP IS PERSISTED WITH THE DRAFT. Restoring the values but not
      // the position drops the user back at step 1 in front of a form that is
      // already filled in, which reads as "it lost my work" even though it did
      // not.
      partialize: (s) => ({ draft: s.draft, current: s.current }),
    },
  ),
);

/**
 * toCombinationErrors maps the API's 422 details onto wizard steps.
 *
 * ⚠ THE FALLBACK MATTERS AS MUCH AS THE MAPPING. A detail we cannot attribute
 * to a step still has to reach the user — attached to Review, which is where
 * they are standing. Dropping it would leave a disabled Run button with no
 * explanation, which is the worst possible outcome for a validation error.
 */
export function toCombinationErrors(err: ApiError): CombinationError[] {
  const out: CombinationError[] = [];

  for (const detail of err.details) {
    const field = readString(detail.field) || readString(detail.dimension);
    const message = readString(detail.message) || readString(detail.reason) || err.message;
    out.push({ step: stepForField(field), message });
  }

  if (out.length === 0) out.push({ step: 6, message: err.message });
  return out;
}

function stepForField(field: string): StepId {
  if (field.includes('project')) return 1;
  if (field.includes('bom_type') || field.includes('classification')) return 2;
  if (field.includes('level')) return 3;
  if (field.includes('standard')) return 4;
  if (field.includes('format')) return 5;
  // Engine/source combination failures name neither; Review owns them, since
  // that is where the user is when the server answers.
  return 6;
}

/**
 * readString takes a value only when it IS a string.
 *
 * ⚠ String(x) ON AN OBJECT PRODUCES "[object Object]", and an error detail is
 * `Record<string, unknown>` — a nested object is entirely possible. Rendering
 * that at the user is worse than rendering nothing, because it looks like a bug
 * in our code rather than a validation failure in theirs.
 */
function readString(value: unknown): string {
  return typeof value === 'string' ? value : '';
}
