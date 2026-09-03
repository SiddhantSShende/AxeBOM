import { beforeEach, describe, expect, it } from 'vitest';
import {
  EMPTY_DRAFT,
  blocking,
  effectiveFormats,
  firstIncompleteStep,
  plannedReports,
  reachable,
  scannableBomTypes,
  stepComplete,
  useWizard,
  validateDraft,
  type StepId,
  type WizardDraft,
} from './wizard';

function draft(over: Partial<WizardDraft> = {}): WizardDraft {
  return { ...EMPTY_DRAFT, ...over };
}

/** A draft with one valid choice at every step. */
function complete(over: Partial<WizardDraft> = {}): WizardDraft {
  return draft({
    projectId: 'p1',
    bomTypes: ['SBOM'],
    levels: ['top_level'],
    standards: ['SPDX'],
    formats: ['pdf'],
    ...over,
  });
}

describe('step completion', () => {
  it('requires at least one choice at every multi-select step', () => {
    // ⚠ THERE IS NO SKIP. A scan with no formats produces nothing, and letting
    // it through surfaces as an empty reports list an hour later.
    const steps: StepId[] = [1, 2, 3, 4, 5];
    for (const step of steps) {
      expect(stepComplete(draft(), step)).toBe(false);
    }
    for (const step of steps) {
      expect(stepComplete(complete(), step)).toBe(true);
    }
  });

  it('treats an empty project id as incomplete', () => {
    expect(stepComplete(draft({ projectId: '' }), 1)).toBe(false);
  });
});

describe('navigation', () => {
  it('always allows going backward', () => {
    // A user who mis-selected at step 2 must not have to restart. A wizard
    // that locks backward navigation gets abandoned.
    expect(reachable(draft(), 1, 4)).toBe(true);
    expect(reachable(draft(), 3, 4)).toBe(true);
  });

  it('refuses to jump forward over an incomplete step', () => {
    expect(reachable(draft({ projectId: 'p1' }), 3, 1)).toBe(false);
  });

  it('allows jumping forward over completed steps', () => {
    expect(reachable(complete(), 6, 1)).toBe(true);
  });

  it('resumes at the first incomplete step', () => {
    expect(firstIncompleteStep(draft())).toBe(1);
    expect(firstIncompleteStep(draft({ projectId: 'p1' }))).toBe(2);
    expect(firstIncompleteStep(complete())).toBe(6);
  });
});

describe('multi-select', () => {
  beforeEach(() => useWizard.getState().reset());

  // ⚠ THE GUIDELINE PERMITS COMBINATIONS AND THE USER ASKED FOR THEM. Quietly
  // forcing single-select would be an implementation convenience that changes
  // what the product does.
  it('accumulates rather than replacing', () => {
    const { toggle } = useWizard.getState();
    toggle('bomTypes', 'SBOM');
    toggle('bomTypes', 'CBOM');
    toggle('formats', 'pdf');
    toggle('formats', 'xlsx');

    expect(useWizard.getState().draft.bomTypes).toEqual(['SBOM', 'CBOM']);
    expect(useWizard.getState().draft.formats).toEqual(['pdf', 'xlsx']);
  });

  it('toggles off', () => {
    const { toggle } = useWizard.getState();
    toggle('levels', 'complete');
    toggle('levels', 'complete');
    expect(useWizard.getState().draft.levels).toEqual([]);
  });
});

describe('the review count', () => {
  it('is the cross product of type, level and format', () => {
    // A user selecting three types, both levels and five formats deserves to
    // see the number BEFORE running it, not thirty rows afterwards.
    const d = complete({
      bomTypes: ['SBOM', 'CBOM', 'AIBOM'],
      levels: ['top_level', 'complete'],
      standards: ['SPDX', 'CycloneDX'],
      formats: ['pdf', 'xlsx', 'json', 'spdx', 'cyclonedx'],
    });
    expect(plannedReports(d)).toBe(3 * 2 * 5);
  });

  it('does not count a format whose standard was not selected', () => {
    // The promised number has to match what actually runs.
    const d = complete({ standards: ['SPDX'], formats: ['pdf', 'cyclonedx'] });
    expect(effectiveFormats(d)).toEqual(['pdf']);
    expect(plannedReports(d)).toBe(1);
  });
});

describe('scannableBomTypes', () => {
  // ⚠ HBOM MOVED OUT OF THIS FILTER, AND THAT IS THE ASSERTION.
  //
  // It had no scanner while a CSV and a form were the only ways in. `hbom-ecad`
  // parses the customer's own KiCad, Altium and OrCAD design files out of an
  // upload or a repository — a real scan, publishing real jobs. Filtering it
  // out now would stop a Generate run from producing the hardware BOM the
  // customer asked for, with no explanation they could act on.
  it('drops QBOM only — HBOM is scannable now', () => {
    expect(scannableBomTypes(complete({ bomTypes: ['SBOM', 'HBOM', 'CBOM', 'QBOM'] }))).toEqual([
      'SBOM',
      'HBOM',
      'CBOM',
    ]);
  });

  // QBOM is unchanged, and for the original reason: it is DERIVED from CBOM
  // discovery, not scanned. The server still refuses the family outright.
  it('still drops QBOM, which is derived rather than scanned', () => {
    expect(scannableBomTypes(complete({ bomTypes: ['QBOM'] }))).toEqual([]);
  });
});

describe('local validation', () => {
  it('blocks a draft made entirely of QBOM, against step 2', () => {
    const errors = validateDraft(complete({ bomTypes: ['QBOM'] }));
    const hard = blocking(errors);

    expect(hard).toHaveLength(1);
    expect(hard[0]!.step).toBe(2);
    expect(hard[0]!.message).toMatch(/not produced by a scan/);
    // ⚠ AND IT SAYS HOW TO GET ONE. A refusal that does not name the route to
    // the thing the user wanted leaves them with a disabled button and no idea
    // why — the worst outcome for a validation error.
    expect(hard[0]!.message).toMatch(/CBOM/);
  });

  // ⚠ HBOM ALONE IS NO LONGER A BLOCKED DRAFT. Before hbom-ecad this was a
  // guaranteed 422 from the server and the wizard was right to catch it early.
  it('does not block a draft made entirely of HBOM', () => {
    expect(blocking(validateDraft(complete({ bomTypes: ['HBOM'] })))).toHaveLength(0);
  });

  it('does not block QBOM alongside a scannable type', () => {
    const errors = validateDraft(complete({ bomTypes: ['SBOM', 'QBOM'] }));
    expect(blocking(errors)).toHaveLength(0);
  });

  it('catches a format whose standard was not selected, against step 4', () => {
    const errors = validateDraft(complete({ standards: ['SPDX'], formats: ['cyclonedx'] }));
    const hard = blocking(errors);

    expect(hard).toHaveLength(1);
    // ⚠ THE STEP IS WHAT MAKES THIS INLINE RATHER THAN A TOAST. "Invalid
    // combination" leaves the user to work out which of five multi-selects to
    // change.
    expect(hard[0]!.step).toBe(4);
    expect(hard[0]!.message).toMatch(/CycloneDX standard was not/);
  });

  it('warns about Complete + PDF without refusing it', () => {
    const errors = validateDraft(complete({ levels: ['complete'], formats: ['pdf'] }));
    // Legitimate for a small project. The client must not overrule a decision
    // the server is happy to make.
    expect(blocking(errors)).toHaveLength(0);
    expect(errors.some((e) => e.step === 5)).toBe(true);
  });

  it('warns about Complete + docx the same way, without refusing it', () => {
    const errors = validateDraft(complete({ levels: ['complete'], formats: ['docx'] }));
    expect(blocking(errors)).toHaveLength(0);
    expect(errors.some((e) => e.step === 5)).toBe(true);
  });

  it('warns about an unusually large cross product', () => {
    const errors = validateDraft(
      complete({
        bomTypes: ['SBOM', 'CBOM', 'QBOM', 'AIBOM', 'HBOM'],
        levels: ['top_level', 'complete'],
        standards: ['SPDX', 'CycloneDX'],
        formats: ['pdf', 'xlsx', 'json', 'spdx', 'cyclonedx'],
      }),
    );
    expect(errors.some((e) => e.step === 6 && /50 reports/.test(e.message))).toBe(true);
  });

  it('passes a clean draft', () => {
    expect(validateDraft(complete())).toHaveLength(0);
  });
});

describe('server errors', () => {
  beforeEach(() => useWizard.getState().reset());

  // ⚠ A STALE 422 IS WORSE THAN NONE. Leaving the server's verdict on screen
  // after the draft changed has a user "fix" an error they already fixed.
  it('are cleared when the draft changes', () => {
    useWizard.getState().setServerErrors([{ step: 2, message: 'nope' }]);
    expect(useWizard.getState().serverErrors).toHaveLength(1);

    useWizard.getState().toggle('formats', 'pdf');
    expect(useWizard.getState().serverErrors).toHaveLength(0);
  });

  it('are cleared when the project changes', () => {
    useWizard.getState().setServerErrors([{ step: 2, message: 'nope' }]);
    useWizard.getState().setProject('p2');
    expect(useWizard.getState().serverErrors).toHaveLength(0);
  });
});

describe('the store guards its own transitions', () => {
  beforeEach(() => useWizard.getState().reset());

  it('refuses next() from an incomplete step', () => {
    useWizard.getState().next();
    expect(useWizard.getState().current).toBe(1);
  });

  it('advances once the step is complete', () => {
    useWizard.getState().setProject('p1');
    useWizard.getState().next();
    expect(useWizard.getState().current).toBe(2);
  });

  it('refuses goTo() past an incomplete step', () => {
    useWizard.getState().goTo(5);
    expect(useWizard.getState().current).toBe(1);
  });

  it('never advances past review or back before step 1', () => {
    const w = useWizard.getState();
    w.setProject('p1');
    w.toggle('bomTypes', 'SBOM');
    w.toggle('levels', 'top_level');
    w.toggle('standards', 'SPDX');
    w.toggle('formats', 'pdf');

    for (let i = 0; i < 10; i++) useWizard.getState().next();
    expect(useWizard.getState().current).toBe(6);

    for (let i = 0; i < 10; i++) useWizard.getState().back();
    expect(useWizard.getState().current).toBe(1);
  });
});
