/**
 * Registration asks each BOM type for what that type actually needs.
 *
 * ⚠ THE DEFECT THIS GUARDS: every type was asked the same questions.
 *
 * Name, source, owner, validity, practices — identical for an SBOM and an
 * HBOM — and the inputs particular to a type lived on screens reachable only
 * once the project existed. A QBOM was therefore created with none of Table 8's
 * device metadata, which is the one part of a QBOM no scan can produce, and an
 * HBOM with no device, which on a `manual` project is the only thing that will
 * ever produce a document. Both then appeared as checklist items on a project
 * already made.
 *
 * The rule under test is NOT "QBOM and HBOM get a step". It is that the step is
 * driven by the server's `at_registration` flag, so the judgement lives in
 * services/project/internal/bommodule and this screen has no second copy of it.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router';
import { ProjectWizard } from './ProjectWizard';

function bomType(id: string, extra: Record<string, unknown> = {}) {
  return {
    id,
    requires_import: false,
    is_derived: false,
    sources: [],
    depends_on: [],
    requirements: [],
    ...extra,
  };
}

const OPTIONS = {
  source_types: ['github', 'upload', 'url', 'manual'],
  sdlc_stages: ['source'],
  bom_depths: ['top_level'],
  practices: [],
  bom_types: [
    bomType('SBOM'),
    bomType('CBOM'),
    bomType('QBOM', {
      is_derived: true,
      requirements: [
        {
          id: 'qbom.device_metadata',
          title: 'Record the quantum device metadata',
          detail: 'No scan can produce these.',
          at_registration: true,
          required: true,
        },
      ],
    }),
    bomType('AIBOM', {
      requirements: [
        {
          id: 'aibom.user_fields',
          title: 'Complete the Table 10 elements no tool reports',
          // Per MODEL, and no model exists until a scan has found one — so this
          // one must stay off the wizard however the others move.
          detail: 'Recorded per model, once a scan has found it.',
          at_registration: false,
          required: true,
        },
      ],
    }),
    bomType('HBOM', {
      requires_import: true,
      requirements: [
        {
          id: 'hbom.device',
          title: 'Register a device, or import its parts',
          detail: 'Nothing in AxeBOM examines hardware.',
          at_registration: true,
          required: true,
        },
      ],
    }),
  ],
};

const QBOM_FORM = {
  disclosure: 'Captured from this form, never scanned.',
  fields: [
    {
      field_id: 'q1',
      name: 'Model name',
      canonical_path: 'quantum_component.model_name',
      type: 'string',
      source_page: 41,
      derived: false,
    },
    {
      field_id: 'q2',
      name: 'Cryptographic assets',
      canonical_path: 'quantum_component.crypto_assets[]',
      type: 'ref_list',
      source_page: 41,
      derived: true,
    },
  ],
};

const DEVICE_FORM = {
  fields: [
    { attr: 'name', name: 'Device name', certin: true, required: true, source_page: 44 },
    { attr: 'asset_tag', name: 'Asset Tag', certin: false, required: false },
  ],
};

/** route answers each endpoint the wizard reaches, by path. */
function stubFetch() {
  const fetchMock = vi.fn((input: RequestInfo | URL) => {
    // Narrowed rather than String()'d: a Request stringifies to
    // "[object Object]", which would match no branch and silently answer {}.
    const url = input instanceof Request ? input.url : input.toString();
    const json = (body: unknown) =>
      Promise.resolve(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    if (url.includes('/v1/projects/options')) return json(OPTIONS);
    if (url.includes('/v1/qbom/form')) return json(QBOM_FORM);
    if (url.includes('/v1/hbom/device-form')) return json(DEVICE_FORM);
    if (url.includes('/v1/github/connection')) return json({ connected: false });
    return json({});
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

function renderWizard() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ProjectWizard />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Selects BOM types on step 1, leaving exactly `ids` chosen. */
async function chooseTypes(ids: string[]) {
  // SBOM is the default selection; clear it unless it was asked for.
  for (const id of ['SBOM', ...ids]) {
    const box = await screen.findByRole('checkbox', { name: new RegExp(`^${id}`) });
    const wanted = ids.includes(id);
    if ((box as HTMLInputElement).checked !== wanted) await userEvent.click(box);
  }
}

async function continueOnce() {
  await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
}

describe('ProjectWizard — per-type registration', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('does not add a per-type step for types that ask for nothing', async () => {
    stubFetch();
    renderWizard();
    await chooseTypes(['SBOM']);

    // The stepper is the contract: an SBOM-only registration must not show an
    // empty screen where another type's inputs would have been.
    const steps = await screen.findByRole('list', { name: 'Progress' });
    expect(steps.textContent).not.toContain('What it needs');
    expect(steps.textContent).toContain('Practices');
  });

  it('asks a QBOM project for the Table 8 elements no scan can produce', async () => {
    stubFetch();
    renderWizard();
    await chooseTypes(['QBOM']);

    expect((await screen.findByRole('list', { name: 'Progress' })).textContent).toContain(
      'What it needs',
    );

    await continueOnce(); // → source
    await userEvent.type(screen.getByRole('textbox', { name: /project name/i }), 'q');
    // A `github` source cannot advance without a picked repository, which is a
    // different gate and not what this test is about.
    await userEvent.click(screen.getByRole('radio', { name: /manual/i }));
    await continueOnce(); // → requirements

    expect(await screen.findByRole('heading', { name: /quantum device metadata/i })).toBeTruthy();
    expect(await screen.findByRole('textbox', { name: /model name/i })).toBeTruthy();
    // The disclosure is the server's sentence, not this screen's claim.
    expect(screen.getByText(QBOM_FORM.disclosure)).toBeTruthy();
  });

  // ⚠ A DERIVED ELEMENT MUST NOT GET AN INPUT. Table 8's crypto-asset list is
  // resolved from the project's CBOM discovery and overwritten on every
  // normalization pass; an input for it would invite somebody to type a value
  // the product then discards.
  it('offers no input for an element the product derives', async () => {
    stubFetch();
    renderWizard();
    await chooseTypes(['QBOM']);
    await continueOnce();
    await userEvent.type(screen.getByRole('textbox', { name: /project name/i }), 'q');
    await userEvent.click(screen.getByRole('radio', { name: /manual/i }));
    await continueOnce();

    await screen.findByRole('textbox', { name: /model name/i });
    expect(screen.queryByRole('textbox', { name: /cryptographic assets/i })).toBeNull();
  });

  it('asks an HBOM project which device it is about', async () => {
    stubFetch();
    renderWizard();
    await chooseTypes(['HBOM']);

    await continueOnce(); // → source
    await userEvent.type(screen.getByRole('textbox', { name: /project name/i }), 'h');
    await userEvent.click(screen.getByRole('radio', { name: /manual/i }));
    await continueOnce(); // → requirements

    expect(await screen.findByRole('textbox', { name: /device name/i })).toBeTruthy();
    // ⚠ THE COPY IS SOURCE-SPECIFIC, and that is the point of asking here: a
    // `manual` project has no scan at all, so this form IS the document.
    await waitFor(() =>
      expect(screen.getByText(/no source to read/i)).toBeTruthy(),
    );
  });

  // ⚠ AIBOM'S REQUIREMENT CANNOT MOVE INTO THE WIZARD, and the flag is what
  // says so: its elements are per-MODEL and no model exists until a scan has
  // found one. A change that made this step render from a list of type names
  // rather than from `at_registration` would break here.
  it('leaves a requirement the wizard cannot collect off the wizard', async () => {
    stubFetch();
    renderWizard();
    await chooseTypes(['AIBOM']);

    const steps = await screen.findByRole('list', { name: 'Progress' });
    expect(steps.textContent).not.toContain('What it needs');
    // It is still stated up front — as something the project will need later.
    expect(screen.getByText(/recorded per model/i)).toBeTruthy();
  });
});
