/**
 * The connect / register wizard.
 *
 * Three steps (docs/07-FRONTEND-SPEC.md §6):
 *
 *   1. source              GitHub repository, upload, or fully manual
 *   2. owner & validity    contact block and the validity window
 *   3. classification & practices
 *
 * THE PRACTICES STEP IS NOT OPTIONAL AND IS NOT BURIED IN SETTINGS.
 *
 * Its six fields are one of CERT-In's three minimum-element categories
 * (docs/06-COMPLIANCE-PROFILES.md §6). A project without them cannot produce a
 * complete compliance report, and the screen says so plainly at the point of
 * entry — the alternative is a user discovering it as a coverage gap weeks
 * later, in a document they were about to send to a regulator.
 */

import { useState } from 'react';
import { useNavigate } from 'react-router';
import { ApiError } from '../../lib/api';
import { BOM_TYPES } from '../../design/theme';
import {
  humanizeEnum,
  useCreateProject,
  useProjectOptions,
  useSetPractices,
  type CreateProjectInput,
  type Owner,
  type PracticesInput,
} from '../../lib/projects';

type Step = 1 | 2 | 3;

/**
 * recordedPractices counts substantively-filled sub-elements.
 *
 * Iterates the KNOWN keys rather than Object.values, which widens to `any` for
 * an interface of optional properties. A blank string does not count — the same
 * rule the server applies, so the wizard's running count cannot disagree with
 * the gap report it produces.
 */
const PRACTICE_KEYS = [
  'frequency',
  'depth',
  'known_unknowns',
  'distribution',
  'access_control',
  'errata_policy',
] as const satisfies ReadonlyArray<keyof PracticesInput>;

function recordedPractices(p: PracticesInput): number {
  return PRACTICE_KEYS.filter((k) => (p[k] ?? '').trim() !== '').length;
}

interface Draft {
  sourceType: string;
  name: string;
  description: string;
  repoFullName: string;
  repoExternalId: string;
  defaultBranch: string;
  owner: Owner;
  validityStart: string;
  validityEnd: string;
  classifications: string[];
  sdlcStage: string;
  practices: PracticesInput;
}

const emptyDraft: Draft = {
  sourceType: 'github',
  name: '',
  description: '',
  repoFullName: '',
  repoExternalId: '',
  defaultBranch: '',
  owner: {},
  validityStart: '',
  validityEnd: '',
  classifications: ['SBOM'],
  sdlcStage: 'source',
  practices: {},
};

export function ProjectWizard() {
  const navigate = useNavigate();
  const [step, setStep] = useState<Step>(1);
  const [draft, setDraft] = useState<Draft>(emptyDraft);
  const [error, setError] = useState<string | null>(null);

  const options = useProjectOptions();
  const createProject = useCreateProject();
  const [createdId, setCreatedId] = useState<string | null>(null);
  const setPractices = useSetPractices(createdId ?? '');

  const patch = (p: Partial<Draft>) => setDraft((d) => ({ ...d, ...p }));

  async function submit() {
    setError(null);
    try {
      const input: CreateProjectInput = {
        name: draft.name,
        ...(draft.description ? { description: draft.description } : {}),
        source_type: draft.sourceType,
        sdlc_stage: draft.sdlcStage,
        validity_start: draft.validityStart || null,
        validity_end: draft.validityEnd || null,
        owner: draft.owner,
        classifications: draft.classifications,
      };
      const project = await createProject.mutateAsync(input);
      setCreatedId(project.id);

      // Practices are written as a second call because they are a distinct
      // resource with its own permission — who may change a compliance
      // declaration is a different question from who may rename a project.
      const hasAny = recordedPractices(draft.practices) > 0;
      if (hasAny) {
        await setPractices.mutateAsync(draft.practices);
      }

      void navigate(`/projects/${project.id}`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Could not create the project');
    }
  }

  const canAdvance =
    step === 1
      ? draft.name.trim() !== '' &&
        (draft.sourceType !== 'github' || draft.repoExternalId.trim() !== '')
      : true;

  return (
    <div className="page">
      <header>
        <h1>Register a project</h1>
        <ol className="steps" aria-label="Progress">
          {(
            [
              [1, 'Source'],
              [2, 'Owner & validity'],
              [3, 'Classification & practices'],
            ] as const
          ).map(([n, label]) => (
            <li key={n} aria-current={step === n ? 'step' : undefined} data-done={step > n}>
              <span className="step-n">{n}</span>
              {label}
            </li>
          ))}
        </ol>
      </header>

      {error && (
        <p className="status status-down" role="alert">
          {error}
        </p>
      )}

      {step === 1 && <SourceStep draft={draft} patch={patch} options={options.data} />}
      {step === 2 && <OwnerStep draft={draft} patch={patch} />}
      {step === 3 && <ClassificationStep draft={draft} patch={patch} options={options.data} />}

      <nav className="wizard-nav">
        <button
          type="button"
          className="btn"
          onClick={() => setStep((s) => (s > 1 ? ((s - 1) as Step) : s))}
          disabled={step === 1}
        >
          Back
        </button>
        {step < 3 ? (
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => setStep((s) => (s + 1) as Step)}
            disabled={!canAdvance}
          >
            Continue
          </button>
        ) : (
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => void submit()}
            disabled={createProject.isPending || draft.classifications.length === 0}
          >
            {createProject.isPending ? 'Creating…' : 'Create project'}
          </button>
        )}
      </nav>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step 1 — source
// ---------------------------------------------------------------------------

function SourceStep({
  draft,
  patch,
  options,
}: {
  draft: Draft;
  patch: (p: Partial<Draft>) => void;
  options: { source_types: string[] } | undefined;
}) {
  const sources = options?.source_types ?? ['github', 'upload', 'manual'];

  return (
    <section aria-labelledby="source-heading">
      <h2 id="source-heading">Where does this project come from?</h2>

      <fieldset>
        <legend>Source</legend>
        {sources.map((s) => (
          <label key={s} className="radio">
            <input
              type="radio"
              name="source_type"
              value={s}
              checked={draft.sourceType === s}
              onChange={() => patch({ sourceType: s })}
            />
            {humanizeEnum(s)}
          </label>
        ))}
      </fieldset>

      <label className="field">
        <span>Project name</span>
        <input
          value={draft.name}
          onChange={(e) => patch({ name: e.target.value })}
          required
          maxLength={200}
        />
      </label>

      <label className="field">
        <span>Description</span>
        <textarea
          value={draft.description}
          onChange={(e) => patch({ description: e.target.value })}
          rows={2}
        />
      </label>

      {draft.sourceType === 'github' && (
        <>
          <label className="field">
            <span>Repository (owner/name)</span>
            <input
              value={draft.repoFullName}
              onChange={(e) => patch({ repoFullName: e.target.value })}
              placeholder="acme/payments-api"
            />
          </label>
          <label className="field">
            <span>Repository ID</span>
            <input
              value={draft.repoExternalId}
              onChange={(e) => patch({ repoExternalId: e.target.value })}
              placeholder="1296269"
              inputMode="numeric"
            />
            {/* Not a nicety: repository NAMES change, and a connection keyed on
                a name silently detaches when somebody renames the repo. */}
            <small>
              GitHub&apos;s numeric id. Repository names change; this does not, so it is what the
              connection is keyed on.
            </small>
          </label>
          <label className="field">
            <span>Default branch</span>
            <input
              value={draft.defaultBranch}
              onChange={(e) => patch({ defaultBranch: e.target.value })}
              placeholder="main"
            />
          </label>
        </>
      )}

      {draft.sourceType === 'manual' && (
        <p className="note">
          Manual registration records structured metadata with no repository. This is the normal
          path for hardware: <strong>there is no HBOM scanner</strong> — an HBOM is built from a CSV
          or form import, never discovered.
        </p>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Step 2 — owner and validity
// ---------------------------------------------------------------------------

function OwnerStep({ draft, patch }: { draft: Draft; patch: (p: Partial<Draft>) => void }) {
  const backwards =
    draft.validityStart !== '' &&
    draft.validityEnd !== '' &&
    draft.validityEnd < draft.validityStart;

  return (
    <section aria-labelledby="owner-heading">
      <h2 id="owner-heading">Who owns this, and for how long?</h2>
      <p className="note">
        The owner block is reproduced in every generated report as the point of contact.
      </p>

      {(
        [
          ['name', 'Owner name', 'text'],
          ['email', 'Owner email', 'email'],
          ['github', 'Owner GitHub', 'text'],
          ['phone', 'Owner phone', 'tel'],
        ] as const
      ).map(([key, label, type]) => (
        <label className="field" key={key}>
          <span>{label}</span>
          <input
            type={type}
            value={draft.owner[key] ?? ''}
            onChange={(e) => patch({ owner: { ...draft.owner, [key]: e.target.value } })}
          />
        </label>
      ))}

      <div className="field-pair">
        <label className="field">
          <span>Validity start</span>
          <input
            type="date"
            value={draft.validityStart}
            onChange={(e) => patch({ validityStart: e.target.value })}
          />
        </label>
        <label className="field">
          <span>Validity end</span>
          <input
            type="date"
            value={draft.validityEnd}
            onChange={(e) => patch({ validityEnd: e.target.value })}
            aria-invalid={backwards}
          />
        </label>
      </div>

      {backwards && (
        <p className="status status-down" role="alert">
          The validity window ends before it starts. The database refuses this too — a window that
          runs backwards renders as a nonsense compliance claim.
        </p>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Step 3 — classification and practices
// ---------------------------------------------------------------------------

function ClassificationStep({
  draft,
  patch,
  options,
}: {
  draft: Draft;
  patch: (p: Partial<Draft>) => void;
  options:
    | {
        bom_types: Array<{ id: string; requires_import: boolean; is_derived: boolean }>;
        sdlc_stages: string[];
        bom_depths: string[];
        practices: Array<{ id: string; name: string }>;
      }
    | undefined;
}) {
  const bomTypes =
    options?.bom_types ??
    BOM_TYPES.map((b) => ({
      id: b.type,
      requires_import: b.type === 'HBOM',
      is_derived: b.type === 'QBOM',
    }));
  const stages = options?.sdlc_stages ?? [];
  const depths = options?.bom_depths ?? [];

  const toggle = (id: string) =>
    patch({
      classifications: draft.classifications.includes(id)
        ? draft.classifications.filter((c) => c !== id)
        : [...draft.classifications, id],
    });

  const setPractice = (key: keyof PracticesInput, value: string) =>
    patch({ practices: { ...draft.practices, [key]: value } });

  // Rendered from the fetched list, never a literal. Writing the number here
  // would be the same mistake as hardcoding it in the backend.
  const practiceCount = options?.practices.length ?? 0;
  const recorded = recordedPractices(draft.practices);

  return (
    <section aria-labelledby="class-heading">
      <h2 id="class-heading">Classification</h2>

      <fieldset>
        <legend>BOM types</legend>
        <ul className="chips chips-selectable">
          {bomTypes.map((t) => {
            const selected = draft.classifications.includes(t.id);
            return (
              <li key={t.id}>
                <label className="chip" data-bom={t.id.toLowerCase()} data-selected={selected}>
                  <input type="checkbox" checked={selected} onChange={() => toggle(t.id)} />
                  <span>{t.id}</span>
                  {/* The honest labels travel with the data, so the UI cannot
                      imply discovery where there is none. */}
                  {t.requires_import && <span className="chip-note">import only</span>}
                  {t.is_derived && <span className="chip-note">derived from CBOM</span>}
                </label>
              </li>
            );
          })}
        </ul>
        {draft.classifications.length === 0 && (
          <p className="status status-down" role="alert">
            Select at least one. A project with no classification produces no BOM.
          </p>
        )}
      </fieldset>

      <label className="field">
        <span>SDLC stage</span>
        <select value={draft.sdlcStage} onChange={(e) => patch({ sdlcStage: e.target.value })}>
          {stages.map((s) => (
            <option key={s} value={s}>
              {humanizeEnum(s)}
            </option>
          ))}
        </select>
        <small>CERT-In §3.2. These values come from the compliance profile, not the UI.</small>
      </label>

      <h2 id="practices-heading">Practices and processes</h2>

      {/* THE POINT OF THIS SCREEN. Stated plainly, at the point of entry. */}
      <p className="note note-important">
        These are <strong>one of CERT-In&apos;s three minimum-element categories</strong> — not a
        settings page. A project with gaps here cannot produce a complete compliance report, however
        complete its component data is.
        {practiceCount > 0 && (
          <>
            {' '}
            <strong>
              {recorded} of {practiceCount} recorded.
            </strong>
          </>
        )}
      </p>

      <label className="field">
        <span>Frequency</span>
        <input
          value={draft.practices.frequency ?? ''}
          onChange={(e) => setPractice('frequency', e.target.value)}
          placeholder="weekly, every Monday 02:00 UTC"
        />
        <small>How often this BOM is regenerated. Campaigns automate it later.</small>
      </label>

      <label className="field">
        <span>Depth</span>
        <select
          value={draft.practices.depth ?? ''}
          onChange={(e) => setPractice('depth', e.target.value)}
        >
          <option value="">Not recorded</option>
          {depths.map((d) => (
            <option key={d} value={d}>
              {humanizeEnum(d)}
            </option>
          ))}
        </select>
        <small>CERT-In §3.1 levels, read from the profile.</small>
      </label>

      <label className="field">
        <span>Known unknowns</span>
        <textarea
          value={draft.practices.known_unknowns ?? ''}
          onChange={(e) => setPractice('known_unknowns', e.target.value)}
          rows={2}
          placeholder="What you know you cannot see"
        />
        <small>
          Left empty is fine: scanning fills this in from ecosystems detected with no available
          engine. Anything you add is kept alongside.
        </small>
      </label>

      <label className="field">
        <span>Distribution and delivery</span>
        <textarea
          value={draft.practices.distribution ?? ''}
          onChange={(e) => setPractice('distribution', e.target.value)}
          rows={2}
          placeholder="How this BOM reaches the people who need it"
        />
      </label>

      <label className="field">
        <span>Access control</span>
        <select
          value={draft.practices.access_control ?? ''}
          onChange={(e) => setPractice('access_control', e.target.value)}
        >
          <option value="">Not recorded</option>
          <option value="public">Public</option>
          <option value="private">Private</option>
        </select>
        <small>
          CERT-In §5.3.2 expects both a public and a private version to be maintainable. A private
          BOM carries vulnerability detail.
        </small>
      </label>

      <label className="field">
        <span>Accommodation of mistakes</span>
        <textarea
          value={draft.practices.errata_policy ?? ''}
          onChange={(e) => setPractice('errata_policy', e.target.value)}
          rows={2}
          placeholder="How corrections are issued"
        />
        <small>
          AxeBOM implements corrections as re-normalization into a new BOM version; describe your
          own process here.
        </small>
      </label>
    </section>
  );
}
