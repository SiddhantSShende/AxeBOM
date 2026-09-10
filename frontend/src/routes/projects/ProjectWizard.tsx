/**
 * The connect / register wizard.
 *
 * Four or five steps (docs/07-FRONTEND-SPEC.md §6):
 *
 *   1. BOM types           what this project should produce
 *   2. source              GitHub repository, upload, url, or fully manual
 *   3. what it needs       the inputs particular to the chosen types — SHOWN
 *                          ONLY when a chosen type asks for any
 *   4. owner & validity    contact block and the validity window
 *   5. practices           SDLC stage and the CERT-In practices fields
 *
 * ⚠ STEP 3 IS THE ANSWER TO "WHY DOES REGISTERING AN HBOM ASK THE SAME THINGS
 * AS REGISTERING AN SBOM?" — because it did.
 *
 * Every type got the same five questions, and the inputs that are particular to
 * a type lived on screens reachable only once the project existed. So a QBOM
 * was created with none of CERT-In Table 8's device metadata — the one part of
 * a QBOM that no scan can produce — and an HBOM with no device, which on a
 * `manual` project is the only thing that will ever produce a document. Both
 * then surfaced as checklist items on a project already made, which is the
 * wrong moment: the person who knows the answers is the one filling in the
 * form. The step is driven by the server's `at_registration` flag, so which
 * types ask for what stays in services/project/internal/bommodule and this file
 * holds no second copy of that judgement.
 *
 * THE PRACTICES STEP IS NOT OPTIONAL AND IS NOT BURIED IN SETTINGS.
 *
 * Its six fields are one of CERT-In's three minimum-element categories
 * (docs/06-COMPLIANCE-PROFILES.md §6). A project without them cannot produce a
 * complete compliance report, and the screen says so plainly at the point of
 * entry — the alternative is a user discovering it as a coverage gap weeks
 * later, in a document they were about to send to a regulator.
 */

import { useState, type ChangeEvent } from 'react';
import { useNavigate } from 'react-router';
import { AnimatePresence } from 'motion/react';
import { ApiError } from '../../lib/api';
import { BOM_TYPES } from '../../design/theme';
import {
  humanizeEnum,
  useConnectRepo,
  useCreateProject,
  useCreateWebSource,
  useGitHubConnect,
  useGitHubConnection,
  useSaveGitHubConnection,
  useProjectOptions,
  useSetPractices,
  useUploadFile,
  type CreateProjectInput,
  type Owner,
  type PracticesInput,
  type Repo,
} from '../../lib/projects';
import {
  EMPTY_QUANTUM_DEVICE,
  hasQuantumValues,
  useQBOMRegistrationForm,
  useRegisterQuantumDevice,
  type QuantumDeviceValues,
} from '../../lib/qbom';
import {
  EMPTY_DEVICE,
  hasDeviceValues,
  useDeviceForm,
  useRegisterDevice,
  type DeviceInput,
} from '../../lib/devices';
import { DeviceFieldGroups } from '../hbom/DeviceFields';
import { ErrorState, SkeletonRows } from '../../components/States';
import { GitHubRepoPicker } from './GitHubRepoPicker';

// UPLOAD_KINDS mirrors project.uploads' CHECK constraint minus the two kinds
// no wizard should ever offer here: `image_tarball` belongs to the `image`
// source type, not `upload`, and `hbom_csv` has its own dedicated import flow
// (routes/hbom/HardwareImport.tsx) — offering it here would produce an HBOM
// upload attached to a project that was never classified for one.
const UPLOAD_KINDS = ['source_archive', 'manifest', 'lockfile', 'sbom'] as const;

// SUPPORTED_SOURCE_TYPES is every source_type this wizard has a real
// attach-flow for. See SourceStep's own comment on `sources` for why this
// filters the server's full list rather than using it verbatim.
const SUPPORTED_SOURCE_TYPES = ['github', 'upload', 'url', 'manual'];

interface UploadDraftFile {
  file: File;
  kind: (typeof UPLOAD_KINDS)[number];
}

// StagedRepo is what a picked repository plus its connect token look like
// while they wait in Draft for submit() to attach them to the project the
// create call is about to produce.
interface StagedRepo {
  fullName: string;
  externalId: string;
  defaultBranch: string;
  cloneUrl: string;
  // The repo-scoped token useGitHubConnect resolved. Held only in this
  // in-memory Draft, never persisted client-side — useConnectRepo sends it
  // once, to Vault, and it is gone from here the moment the component
  // unmounts.
  token: string;
}

/**
 * StepId names the steps rather than numbering them, because the list is no
 * longer fixed.
 *
 * ⚠ `requirements` IS CONDITIONAL, AND THAT IS THE WHOLE CHANGE. Registration
 * asked all five BOM types the same questions and then handed back a checklist:
 * a QBOM project was created with none of Table 8's device metadata — the one
 * part of it no scan can produce — and an HBOM project with no device, which is
 * the only thing a `manual` one will ever have. Both were reachable only from a
 * screen that needs a created project, so the form each type cannot do without
 * came after the moment somebody was filling forms in.
 *
 * A numbered union could not express this: the step exists for some selections
 * and not others, and an SBOM-only project must not be shown an empty screen
 * where its per-type inputs would have been.
 */
type StepId = 'types' | 'source' | 'requirements' | 'owner' | 'practices';

const STEP_LABELS: Record<StepId, string> = {
  types: 'BOM types',
  source: 'Source',
  requirements: 'What it needs',
  owner: 'Owner & validity',
  practices: 'Practices',
};

/**
 * BomTypeOption is one entry of `/v1/projects/options`'s `bom_types`.
 *
 * Declared once rather than inline per step: three components read it, and
 * three structurally-typed copies drift the moment the server adds a field.
 */
interface BomTypeOption {
  id: string;
  requires_import: boolean;
  is_derived: boolean;
  sources: string[];
  depends_on: string[];
  requirements: Array<{
    id: string;
    title: string;
    detail: string;
    at_registration: boolean;
    required: boolean;
  }>;
}

/**
 * registrationRequirements is what the selected types ask for up front.
 *
 * ⚠ FILTERED ON THE SERVER'S OWN FLAG, NEVER ON A LIST OF TYPE NAMES HERE. The
 * modules decide what the wizard can collect (services/project/internal/
 * bommodule) — QBOM's and HBOM's are per-project and askable now, AIBOM's are
 * per-MODEL and cannot be, since no model exists until a scan finds one. A
 * hardcoded `['QBOM', 'HBOM']` in this file would be a second copy of that
 * judgement, and the copy that never learns about a sixth type.
 */
function registrationRequirements(
  bomTypes: BomTypeOption[],
  classifications: string[],
): BomTypeOption['requirements'] {
  const seen = new Set<string>();
  return bomTypes
    .filter((t) => classifications.includes(t.id))
    .flatMap((t) => t.requirements)
    .filter((r) => r.at_registration && !seen.has(r.id) && seen.add(r.id));
}

/** visibleSteps drops `requirements` when the selection asks for nothing. */
function visibleSteps(bomTypes: BomTypeOption[], classifications: string[]): StepId[] {
  const needs = registrationRequirements(bomTypes, classifications).length > 0;
  return needs
    ? ['types', 'source', 'requirements', 'owner', 'practices']
    : ['types', 'source', 'owner', 'practices'];
}

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
  githubRepo: StagedRepo | null;
  uploadFiles: UploadDraftFile[];
  webSourceUrl: string;
  owner: Owner;
  validityStart: string;
  validityEnd: string;
  classifications: string[];
  sdlcStage: string;
  practices: PracticesInput;
  // ⚠ THE TWO PER-TYPE INPUTS, STAGED LIKE EVERY OTHER ATTACHMENT. Both are
  // posted after the create call for the same reason uploads, practices and the
  // repo connection are: the project id they hang off does not exist until it
  // returns. They stay empty — and unsent — for the types that do not ask.
  quantumDevice: QuantumDeviceValues;
  hardwareDevice: DeviceInput;
}

const emptyDraft: Draft = {
  sourceType: 'github',
  name: '',
  description: '',
  githubRepo: null,
  uploadFiles: [],
  webSourceUrl: '',
  owner: {},
  validityStart: '',
  validityEnd: '',
  classifications: ['SBOM'],
  sdlcStage: 'source',
  practices: {},
  quantumDevice: EMPTY_QUANTUM_DEVICE,
  hardwareDevice: EMPTY_DEVICE,
};

export function ProjectWizard() {
  const navigate = useNavigate();
  const [step, setStep] = useState<StepId>('types');
  const [draft, setDraft] = useState<Draft>(emptyDraft);
  const [error, setError] = useState<string | null>(null);

  const options = useProjectOptions();
  const createProject = useCreateProject();
  const setPractices = useSetPractices();
  const uploadFile = useUploadFile();
  const connectRepo = useConnectRepo();
  const createWebSource = useCreateWebSource();
  const registerQuantumDevice = useRegisterQuantumDevice();
  const registerDevice = useRegisterDevice();

  const bomTypeOptions = options.data?.bom_types ?? [];
  const steps = visibleSteps(bomTypeOptions, draft.classifications);

  // ⚠ THE CURRENT STEP CAN STOP EXISTING. Going back to step 1 and deselecting
  // the last type that asked for something removes `requirements` from the list
  // while it is on screen. Falling back to the first step would throw away a
  // filled-in form; clamping to the last still-visible one keeps the user where
  // they were.
  const index = Math.min(Math.max(steps.indexOf(step), 0), steps.length - 1);
  const current = steps[index] ?? 'types';

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

      // ⚠ project.id, NOT A PIECE OF STATE, IN EVERY CALL BELOW. There is no
      // re-render between this line and the calls that follow, so a state
      // variable set from `project.id` would not be observable here even if
      // one existed — every mutate call below takes the project id as an
      // argument for exactly this reason. See useSetPractices's own doc
      // comment for the bug this replaced.

      // Practices are written as a second call because they are a distinct
      // resource with its own permission — who may change a compliance
      // declaration is a different question from who may rename a project.
      const hasAny = recordedPractices(draft.practices) > 0;
      if (hasAny) {
        await setPractices.mutateAsync({ projectId: project.id, ...draft.practices });
      }

      // Uploaded one at a time, not in parallel: a project with three staged
      // files that fails on the second should say which one, not leave the
      // caller guessing which of three concurrent requests it was.
      for (const { file, kind } of draft.uploadFiles) {
        await uploadFile.mutateAsync({ projectId: project.id, file, kind });
      }

      // Connecting the repository is a second call for the same reason
      // uploads and practices are: the project id it attaches to does not
      // exist until the create call above returns.
      if (draft.sourceType === 'github' && draft.githubRepo) {
        await connectRepo.mutateAsync({
          projectId: project.id,
          provider: 'github',
          repo_full_name: draft.githubRepo.fullName,
          repo_external_id: draft.githubRepo.externalId,
          default_branch: draft.githubRepo.defaultBranch,
          token: draft.githubRepo.token,
        });
      }

      // Same pattern as the repo connection above: the project id this
      // attaches to does not exist until the create call returns.
      if (draft.sourceType === 'url' && draft.webSourceUrl) {
        await createWebSource.mutateAsync({ projectId: project.id, root_url: draft.webSourceUrl });
      }

      // ⚠ ONLY WHEN SOMETHING WAS TYPED, AND ONLY FOR A SELECTED TYPE.
      //
      // Both guards matter. A QBOM device of nine empty strings is a document
      // whose every element is not-provided — `declaration_pct` 100,
      // `completeness_pct` 0 (invariant 3) — which every screen that counts
      // documents would then report as recorded. And posting either record for
      // a project not classified for it would attach data the project has no
      // BOM type to render, which the server is entitled to refuse.
      if (draft.classifications.includes('QBOM') && hasQuantumValues(draft.quantumDevice)) {
        await registerQuantumDevice.mutateAsync({
          projectId: project.id,
          values: draft.quantumDevice,
        });
      }

      if (draft.classifications.includes('HBOM') && hasDeviceValues(draft.hardwareDevice)) {
        await registerDevice.mutateAsync({ projectId: project.id, input: draft.hardwareDevice });
      }

      void navigate(`/projects/${project.id}`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Could not create the project');
    }
  }

  // The types step gates on having chosen something to produce: a project
  // classified for nothing is refused by the server anyway, and finding that
  // out on the last screen is the failure this reorder exists to remove.
  //
  // ⚠ THE REQUIREMENTS STEP GATES ON NOTHING, DELIBERATELY. Its inputs are
  // required for the BOM type to produce a document, not for the project to
  // exist — an HBOM project whose device is registered next week is a real and
  // supported state, and the same requirement is still listed on the project
  // afterwards. Blocking the wizard on them would turn "your HBOM will be empty
  // until you do this" into "you may not register this project", which is a
  // different and wrong claim. The step says what is missing instead.
  const canAdvance =
    current === 'types'
      ? draft.classifications.length > 0
      : current === 'source'
        ? draft.name.trim() !== '' &&
          (draft.sourceType !== 'github' || draft.githubRepo !== null) &&
          (draft.sourceType !== 'upload' || draft.uploadFiles.length > 0) &&
          (draft.sourceType !== 'url' || isHttpsURL(draft.webSourceUrl))
        : true;

  return (
    <div className="page">
      <header>
        <h1>Register a project</h1>
        {/* Numbered from the VISIBLE list, so an SBOM-only registration reads
            1–4 with no gap where the per-type step would have been. */}
        <ol className="steps" aria-label="Progress">
          {steps.map((id, n) => (
            <li key={id} aria-current={current === id ? 'step' : undefined} data-done={index > n}>
              <span className="step-n">{n + 1}</span>
              {STEP_LABELS[id]}
            </li>
          ))}
        </ol>
      </header>

      {error && (
        <p className="status status-down" role="alert">
          {error}
        </p>
      )}

      {/* ⚠ BOM TYPES FIRST. The wizard used to ask for the source on step 1 and
          the classifications on step 3, so an incompatible pairing — an AIBOM
          project on a url source, say — was only knowable on the last screen,
          after the whole form was filled. The order is the fix: choosing what
          to produce is what narrows every question after it. */}
      {current === 'types' && <BomTypeStep draft={draft} patch={patch} options={options.data} />}
      {current === 'source' && <SourceStep draft={draft} patch={patch} options={options.data} />}
      {current === 'requirements' && (
        <RequirementsStep
          draft={draft}
          patch={patch}
          requirements={registrationRequirements(bomTypeOptions, draft.classifications)}
        />
      )}
      {current === 'owner' && <OwnerStep draft={draft} patch={patch} />}
      {current === 'practices' && (
        <PracticesStep draft={draft} patch={patch} options={options.data} />
      )}

      <nav className="wizard-nav">
        <button
          type="button"
          className="btn"
          onClick={() => setStep(steps[index - 1] ?? 'types')}
          disabled={index === 0}
        >
          Back
        </button>
        {index < steps.length - 1 ? (
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => setStep(steps[index + 1] ?? current)}
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
  options:
    | {
        source_types: string[];
        bom_types: Array<{ id: string; sources: string[] }>;
      }
    | undefined;
}) {
  // ⚠ FILTERED, NOT THE RAW API LIST. `/v1/projects/options` reflects the
  // full project.source_type CHECK constraint — github, gitlab, bitbucket,
  // upload, image, manual, url — because that column also has to accept
  // whatever a project was created with by any other means. This wizard has
  // a real flow for exactly four of them; offering the rest as a radio
  // option that renders no fields and connects nothing on submit is a
  // control that looks like it does something and does not. Restricted here,
  // not on the server: another client is still free to create a project
  // with a source_type this wizard has no UI for.
  const wizardSources = (options?.source_types ?? SUPPORTED_SOURCE_TYPES).filter((s) =>
    SUPPORTED_SOURCE_TYPES.includes(s),
  );

  // ⚠ NARROWED BY WHAT WAS CHOSEN ON STEP 1, WHICH IS WHY STEP 1 MOVED.
  //
  // A source has to work for EVERY selected type, not just one: the source is a
  // property of the project while the classifications are a set, so a url
  // project classified {SBOM, AIBOM} produces a real SBOM and a permanently
  // empty AIBOM. The server refuses that; offering it here would turn a
  // preventable choice into a 422 after the form is filled.
  //
  // An empty `sources` on a type means "unknown" — the options fetch failed —
  // never "nothing", so it narrows nothing and the server stays authoritative.
  const perType = options?.bom_types ?? [];
  const chosen = perType.filter((t) => draft.classifications.includes(t.id));
  const sources = wizardSources.filter((src) =>
    chosen.every((t) => t.sources.length === 0 || t.sources.includes(src)),
  );

  // Reachable only by going back and adding a type after a source was picked.
  // Not silently reset: the source was a deliberate choice and the user is the
  // one who should decide which of the two to change.
  const sourceNowInvalid = sources.length > 0 && !sources.includes(draft.sourceType);

  return (
    <section aria-labelledby="source-heading">
      <h2 id="source-heading">Where does this project come from?</h2>

      {sourceNowInvalid && (
        <p className="status status-down" role="alert">
          {humanizeEnum(draft.sourceType)} cannot be read by every BOM type you selected
          {chosen.length > 0 && <> ({chosen.map((t) => t.id).join(', ')})</>}. Pick one of the
          sources below, or go back and change the BOM types.
        </p>
      )}

      {sources.length === 0 && (
        <p className="status status-down" role="alert">
          No source this wizard supports can be read by every BOM type you selected. Go back and
          reduce the selection — for example, register the hardware separately from the software.
        </p>
      )}

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

      {draft.sourceType === 'github' && <GitHubSource draft={draft} patch={patch} />}

      {draft.sourceType === 'upload' && <UploadFiles draft={draft} patch={patch} />}

      {draft.sourceType === 'url' && <UrlSource draft={draft} patch={patch} />}

      {/* ⚠ THIS NOTE USED TO READ "there is no HBOM scanner", AND IT WAS
          RENDERED TO USERS LONG AFTER IT STOPPED BEING TRUE.

          `hbom-ecad` parses committed KiCad, Altium and OrCAD design files out
          of an upload or a connected repository and publishes real jobs on
          scan.job.hbom. Telling someone at the point of registration that
          hardware can only be typed in by hand steers them away from a path
          that works.

          Neither honest-label guard could catch it: the Python guard walks
          workers/hbom/*.py and the TypeScript twin covers lib/hbom.ts and the
          BOM_TYPES summaries, and both look for OVER-claiming. This sentence
          under-claimed, which no test was watching for. hbom.test.ts now reads
          this file too. */}
      {draft.sourceType === 'manual' && (
        <p className="note">
          Manual registration records structured metadata with no repository — the path for a
          hardware BOM you enter by hand or import as a CSV. If your hardware design files are in a
          repository, connect it instead: AxeBOM parses committed KiCad, Altium and OrCAD files.
          Either way <strong>nothing here examines physical hardware</strong> — a schematic states
          what was designed, not what was built.
        </p>
      )}
    </section>
  );
}

// GitHubSource connects a repo-scoped GitHub token and stages a picked
// repository — nothing is sent to POST /v1/projects/{id}/connections until
// submit(), which needs the project id this wizard has not created yet.
function GitHubSource({ draft, patch }: { draft: Draft; patch: (p: Partial<Draft>) => void }) {
  const connection = useGitHubConnection();
  const connect = useGitHubConnect();
  const saveConnection = useSaveGitHubConnection();
  const [token, setToken] = useState<string | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);

  // ⚠ CONNECTED ONCE PER ORGANISATION, NOT ONCE PER PROJECT. Every registration
  // used to open its own OAuth popup and push a token through the browser. When
  // the organisation is already connected the token stays in Vault, this
  // component never sees one, and the picker opens immediately.
  const alreadyConnected = connection.data?.connected === true;

  async function handleConnect() {
    try {
      const t = await connect.mutateAsync();
      // Stored server-side before the picker opens, so this is the last time a
      // GitHub credential passes through the browser for this organisation.
      await saveConnection.mutateAsync({ token: t });
      setToken(t);
      setPickerOpen(true);
    } catch {
      // Surfaced below via connect.error; nothing further to do here.
    }
  }

  // ⚠ THE SAME ROUND TRIP, FROM INSIDE THE OPEN PICKER. Reconnecting is what a
  // rejected stored credential needs, and the PUT is an upsert keyed on the
  // tenant, so this replaces the dead token rather than adding a second one.
  // The picker stays open throughout: closing it to re-run the authorisation
  // would discard the search the user had already typed and land them back on
  // the step they started from, which is how "reconnect" came to feel like
  // starting the registration over.
  const reconnecting = connect.isPending || saveConnection.isPending;

  return (
    <div className="field">
      <span>Repository</span>

      {draft.githubRepo ? (
        <div className="row-actions">
          <strong>{draft.githubRepo.fullName}</strong>
          <button
            type="button"
            className="btn btn-sm btn-quiet"
            onClick={() => patch({ githubRepo: null })}
          >
            Change
          </button>
        </div>
      ) : alreadyConnected ? (
        <div className="row-actions">
          <button type="button" className="btn" onClick={() => setPickerOpen(true)}>
            Choose a repository
          </button>
          <small>
            Connected as <strong>{connection.data?.github_login || 'your GitHub account'}</strong>.
          </small>
        </div>
      ) : (
        <button
          type="button"
          className="btn"
          onClick={() => void handleConnect()}
          disabled={connect.isPending || saveConnection.isPending}
        >
          {connect.isPending || saveConnection.isPending ? 'Connecting…' : 'Connect GitHub'}
        </button>
      )}

      {connect.error && (
        <p className="status status-down" role="alert">
          {connect.error instanceof Error ? connect.error.message : 'Could not connect to GitHub.'}
        </p>
      )}

      <small>
        {alreadyConnected
          ? 'Your organisation is already connected, so no GitHub window opens. Disconnect from Settings to revoke it.'
          : 'Opens a GitHub window asking to read your repositories. The token is stored once for your organisation, server-side, so later projects can pick a repository without authorising again.'}
      </small>

      <AnimatePresence>
        {/* ⚠ `token` IS EMPTY WHEN THE ORGANISATION IS ALREADY CONNECTED, and
            the picker must still open. This condition was `pickerOpen && token`,
            which silently did nothing on the connect-once path: the button
            opened a picker that never rendered. The empty string means "use the
            organisation's stored credential", which the server resolves. */}
        {pickerOpen && (token !== null || alreadyConnected) && (
          <GitHubRepoPicker
            token={token ?? ''}
            onClose={() => setPickerOpen(false)}
            onReconnect={() => void handleConnect()}
            reconnecting={reconnecting}
            onSelect={(repo: Repo) =>
              patch({
                githubRepo: {
                  fullName: repo.full_name,
                  externalId: repo.external_id,
                  defaultBranch: repo.default_branch,
                  cloneUrl: repo.clone_url,
                  // Empty when the organisation is connected: the server pulls
                  // the stored credential rather than the browser carrying one.
                  token: token ?? '',
                },
              })
            }
          />
        )}
      </AnimatePresence>
    </div>
  );
}

// UploadFiles stages files for the project this wizard is about to create.
//
// The files themselves aren't sent until submit() — there is no project id to
// attach them to until the create call above returns. What lives here is only
// the client-side staging: a File plus the `kind` classification the upload
// endpoint requires, matching project.uploads' CHECK constraint.
function UploadFiles({ draft, patch }: { draft: Draft; patch: (p: Partial<Draft>) => void }) {
  function addFiles(event: ChangeEvent<HTMLInputElement>) {
    const chosen = Array.from(event.target.files ?? []);
    if (chosen.length === 0) return;
    patch({
      uploadFiles: [
        ...draft.uploadFiles,
        ...chosen.map((file) => ({ file, kind: guessKind(file.name) })),
      ],
    });
    // Clear the input so choosing the same file again (after removing it
    // below) still fires a change event.
    event.target.value = '';
  }

  function removeAt(index: number) {
    patch({ uploadFiles: draft.uploadFiles.filter((_, i) => i !== index) });
  }

  function setKindAt(index: number, kind: string) {
    patch({
      uploadFiles: draft.uploadFiles.map((f, i) =>
        i === index ? { ...f, kind: kind as UploadDraftFile['kind'] } : f,
      ),
    });
  }

  return (
    <div className="field">
      <label className="field">
        <span>Files</span>
        <input type="file" multiple onChange={addFiles} />
      </label>
      <small>
        A source archive (.zip, .tar, .tar.gz or .tar.zst) is scanned like a repository. A manifest,
        lockfile or native SBOM document is read as-is — nothing is extracted from it.
      </small>

      {draft.uploadFiles.length === 0 && draft.sourceType === 'upload' && (
        <p className="status status-down" role="alert">
          Add at least one file. A project registered for upload with nothing staged has no source
          to scan.
        </p>
      )}

      {draft.uploadFiles.length > 0 && (
        <ul className="chips">
          {draft.uploadFiles.map((f, i) => (
            <li key={`${f.file.name}-${i}`} className="row-actions">
              <span>{f.file.name}</span>
              <select value={f.kind} onChange={(e) => setKindAt(i, e.target.value)}>
                {UPLOAD_KINDS.map((k) => (
                  <option key={k} value={k}>
                    {k === 'sbom' ? 'SBOM (native document)' : humanizeEnum(k)}
                  </option>
                ))}
              </select>
              <button type="button" className="btn btn-sm btn-quiet" onClick={() => removeAt(i)}>
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// guessKind offers a sensible default kind from a filename's extension, so a
// user staging a single .zip doesn't have to touch the dropdown at all — it
// stays changeable for the cases the guess gets wrong.
function guessKind(filename: string): UploadDraftFile['kind'] {
  const lower = filename.toLowerCase();
  if (
    lower.endsWith('.zip') ||
    lower.endsWith('.tar') ||
    lower.endsWith('.tar.gz') ||
    lower.endsWith('.tgz') ||
    lower.endsWith('.tar.zst')
  ) {
    return 'source_archive';
  }
  if (/lock(file)?\.(json|yaml|yml)$|\.lock$/.test(lower)) {
    return 'lockfile';
  }
  if (
    lower.endsWith('spdx.json') ||
    lower.endsWith('cyclonedx.json') ||
    lower.endsWith('.bom.json')
  ) {
    return 'sbom';
  }
  return 'manifest';
}

// isHttpsURL mirrors the backend's own shape check (ValidateWebSourceURL) —
// https-only, a real host, no embedded credentials. NOT an SSRF defence:
// exactly like the backend's own version of this check, it exists only so a
// user sees an error immediately rather than after a round trip. The real
// defence is connection-time IP blocking, in the fetcher.
function isHttpsURL(raw: string): boolean {
  const value = raw.trim();
  if (!value) return false;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  return parsed.protocol === 'https:' && parsed.hostname !== '' && !parsed.username;
}

// UrlSource stages the single URL the project's fetch will start from. What
// Milestone 5 adds — subdomain discovery, JS-library fingerprinting — is not
// exposed here yet; the wizard only ever submits root_url, and the API
// defaults discovery_enabled/max_hosts sensibly (true / 25) until there is a
// reason to surface either as an advanced option.
function UrlSource({ draft, patch }: { draft: Draft; patch: (p: Partial<Draft>) => void }) {
  const touched = draft.webSourceUrl.trim() !== '';
  const invalid = touched && !isHttpsURL(draft.webSourceUrl);

  return (
    <label className="field">
      <span>URL</span>
      <input
        type="url"
        value={draft.webSourceUrl}
        onChange={(e) => patch({ webSourceUrl: e.target.value })}
        placeholder="https://example.com"
        aria-invalid={invalid}
      />
      {invalid && (
        <p className="status status-down" role="alert">
          Enter a full https:// URL with no embedded credentials.
        </p>
      )}
      <small>
        The page is fetched once to prove this source works. Discovering and scanning the rest of
        the site is not part of this pass yet — a scan against a URL-registered project has no
        engine that can read it until that lands.
      </small>
    </label>
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

function BomTypeStep({
  draft,
  patch,
  options,
}: {
  draft: Draft;
  patch: (p: Partial<Draft>) => void;
  options:
    | {
        bom_types: Array<{
          id: string;
          requires_import: boolean;
          is_derived: boolean;
          sources: string[];
          depends_on: string[];
          requirements: Array<{
            id: string;
            title: string;
            detail: string;
            at_registration: boolean;
            required: boolean;
          }>;
        }>;
      }
    | undefined;
}) {
  const bomTypes =
    options?.bom_types ??
    BOM_TYPES.map((b) => ({
      id: b.type,
      requires_import: b.type === 'HBOM',
      is_derived: b.type === 'QBOM',
      // ⚠ THE FALLBACK ALLOWS EVERYTHING, DELIBERATELY. This branch runs only
      // when /v1/projects/options could not be fetched. Guessing a narrower
      // list offline would disable a combination that is actually valid; the
      // server refuses the genuinely wrong ones either way, so the offline
      // form stays permissive and the server stays authoritative.
      sources: [] as string[],
      depends_on: [] as string[],
      requirements: [] as Array<{
        id: string;
        title: string;
        detail: string;
        at_registration: boolean;
        required: boolean;
      }>,
    }));

  const toggle = (id: string) =>
    patch({
      classifications: draft.classifications.includes(id)
        ? draft.classifications.filter((c) => c !== id)
        : [...draft.classifications, id],
    });

  const selected = new Set(draft.classifications);

  // ⚠ A DERIVATION WITH NOTHING TO DERIVE FROM. model.BOMType.IsDerived's own
  // comment has always said a QBOM without a CBOM "will produce device metadata
  // and no crypto assets — worth warning about at registration rather than at
  // report time". Nothing warned: the chip said "derived from CBOM", which
  // states the relationship and not the consequence of ignoring it. Named, not
  // refused — device metadata alone is a legitimate thing to want.
  const unmetDependencies = bomTypes
    .filter((t) => selected.has(t.id))
    .flatMap((t) => t.depends_on.filter((d) => !selected.has(d)).map((d) => [t.id, d] as const));

  const pendingRequirements = bomTypes
    .filter((t) => selected.has(t.id))
    .flatMap((t) => t.requirements)
    .filter((r) => !r.at_registration);

  return (
    <section aria-labelledby="class-heading">
      <h2 id="class-heading">What do you want to produce?</h2>

      {/* The first question, because the answer changes every question after
          it: which sources can be read, and what the project will still need. */}
      <p className="note">
        Pick the BOM types first. The sources you can register from, and the data
        this project will need, both follow from this choice.
      </p>

      <fieldset>
        <legend>BOM types</legend>
        <ul className="chips chips-selectable">
          {bomTypes.map((t) => {
            const isSelected = selected.has(t.id);
            return (
              <li key={t.id}>
                <label className="chip" data-bom={t.id.toLowerCase()} data-selected={isSelected}>
                  <input type="checkbox" checked={isSelected} onChange={() => toggle(t.id)} />
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
        {unmetDependencies.map(([type, dep]) => (
          <p key={`${type}-${dep}`} className="note note-important">
            {type} is derived from {dep}, and {dep} is not selected. The project will still record
            its {type} device metadata, but the readiness section will contain no cryptographic
            assets — there will be nothing to derive them from. Add {dep} unless that is what you
            intend.
          </p>
        ))}
      </fieldset>

      {/* What this selection will still need once the project exists. Rendered
          from the modules, so a BOM type that grows a new prerequisite says so
          here without a frontend change. */}
      {pendingRequirements.length > 0 && (
        <section className="note" aria-labelledby="needs-heading">
          <h3 id="needs-heading">What these BOM types will need</h3>
          <ul className="requirement-list">
            {pendingRequirements.map((r) => (
              <li key={r.id} data-required={r.required}>
                <strong>{r.title}</strong>
                {r.required && <span className="chip-note">required</span>}
                <p>{r.detail}</p>
              </li>
            ))}
          </ul>
          <small>
            These are set up after the project is created — the project page links to each one.
          </small>
        </section>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// What the selected BOM types actually need
// ---------------------------------------------------------------------------

/**
 * RequirementsStep asks the questions that are specific to a BOM type.
 *
 * ⚠ THIS STEP EXISTS BECAUSE REGISTRATION ASKED ALL FIVE TYPES THE SAME THINGS.
 *
 * Name, source, owner, validity, practices — identical whether the project was
 * an SBOM or an HBOM, and the inputs that are *particular* to a type lived on
 * screens reachable only after the project existed. So a QBOM was created with
 * none of Table 8's device metadata, which is the one part of a QBOM no scan
 * can produce; an HBOM was created with no device, which on a `manual` project
 * is the only thing that will ever produce a document. Both showed up later as
 * checklist items on a project already made, which is the wrong moment: the
 * person who knows the answers is the one filling in the form.
 *
 * ⚠ RENDERED FROM THE SERVER'S REQUIREMENT LIST, NOT FROM A LIST OF BOM TYPES.
 * `at_registration` is the modules' judgement about what can be asked for up
 * front (services/project/internal/bommodule). A requirement this file has no
 * form for still renders — as its own title and detail — rather than
 * disappearing, so a sixth type that grows a prerequisite is visible here on
 * the day it is added instead of silently absent until somebody writes the UI.
 */
function RequirementsStep({
  draft,
  patch,
  requirements,
}: {
  draft: Draft;
  patch: (p: Partial<Draft>) => void;
  requirements: BomTypeOption['requirements'];
}) {
  return (
    <section aria-labelledby="needs-heading">
      <h2 id="needs-heading">What these BOM types need</h2>

      <p className="note">
        These are particular to the types you picked, and nothing else on this form asks for them.
        You can leave them for later — the project keeps the same list — but the answers are
        easiest to give now.
      </p>

      {requirements.map((r) => (
        <section key={r.id} className="panel" aria-label={r.title}>
          <h3>
            {r.title}
            {r.required && <span className="chip-note">required</span>}
          </h3>
          <p className="field-hint">{r.detail}</p>

          {r.id === 'qbom.device_metadata' && (
            <QuantumDeviceFields
              values={draft.quantumDevice}
              onChange={(quantumDevice) => patch({ quantumDevice })}
            />
          )}

          {r.id === 'hbom.device' && (
            <HardwareDeviceFields
              draft={draft}
              values={draft.hardwareDevice}
              onChange={(hardwareDevice) => patch({ hardwareDevice })}
            />
          )}
        </section>
      ))}
    </section>
  );
}

/**
 * QuantumDeviceFields renders CERT-In Table 8's captured elements.
 *
 * ⚠ CAPTURED, NEVER SCANNED, AND THE DISCLOSURE COMES FROM THE SERVER. There is
 * no quantum-hardware scanner (CLAUDE.md honest labels); the sentence saying so
 * is served beside the fields rather than written here, so this screen cannot
 * come to claim something the backend does not.
 *
 * The derived elements are filtered out for the same reason QuantumDevice.tsx
 * filters them: crypto assets and findings are references resolved from the
 * project's CBOM discovery, and an input for one would invite a customer to
 * hand-type a value the product overwrites.
 */
function QuantumDeviceFields({
  values,
  onChange,
}: {
  values: QuantumDeviceValues;
  onChange: (v: QuantumDeviceValues) => void;
}) {
  const form = useQBOMRegistrationForm(true);

  if (form.isPending) return <SkeletonRows rows={5} columns={1} />;
  if (form.isError) return <ErrorState error={form.error} action="load the device metadata form" />;

  const fields = (form.data?.fields ?? []).filter((f) => !f.derived);

  return (
    <>
      <p className="field-hint">{form.data?.disclosure}</p>
      <div className="field-grid">
        {fields.map((f) => {
          const key = quantumFieldKey(f.canonical_path);
          // ⚠ THE ONLY LIST-TYPED ELEMENT, branched on by its known key — every
          // other Table 8 element is a plain string, and a dynamic lookup would
          // widen a fully statically-known shape to `any`. Mirrors the same
          // branch in routes/boms/QuantumDevice.tsx.
          if (key === 'software_dependencies') {
            return (
              <label key={f.field_id} className="field">
                <span>{f.name}</span>
                <input
                  value={values.software_dependencies.join(', ')}
                  placeholder="comma-separated"
                  onChange={(e) =>
                    onChange({
                      ...values,
                      software_dependencies: e.target.value
                        .split(',')
                        .map((v) => v.trim())
                        .filter(Boolean),
                    })
                  }
                />
                {f.source_page ? <small>CERT-In p.{f.source_page}</small> : null}
              </label>
            );
          }
          return (
            <label key={f.field_id} className="field">
              <span>{f.name}</span>
              <input
                value={readQuantumField(values, key)}
                onChange={(e) => onChange(writeQuantumField(values, key, e.target.value))}
              />
              {f.source_page ? <small>CERT-In p.{f.source_page}</small> : null}
            </label>
          );
        })}
      </div>
    </>
  );
}

/**
 * HardwareDeviceFields registers the device this project is about.
 *
 * ⚠ NOTHING HERE EXAMINES HARDWARE, AND THE COPY BELOW SAYS SO PER SOURCE.
 * What a device registration is worth depends on where the project comes from,
 * and the difference is not cosmetic: a repository of KiCad or Altium files has
 * its parts read by `hbom-ecad`, so the device is a label for what the scan
 * finds; a `manual` project has no scan at all, so this form is the entire
 * hardware document. Saying "register a device" identically in both cases is
 * what made registration feel like a form that ignored the answer to its own
 * first question.
 */
function HardwareDeviceFields({
  draft,
  values,
  onChange,
}: {
  draft: Draft;
  values: DeviceInput;
  onChange: (d: DeviceInput) => void;
}) {
  const form = useDeviceForm(true);
  const manual = draft.sourceType === 'manual';

  if (form.isPending) return <SkeletonRows rows={5} columns={1} />;
  if (form.isError) return <ErrorState error={form.error} action="load the device form" />;

  return (
    <>
      <p className="field-hint">
        {manual
          ? 'This project has no source to read, so what you enter here is the hardware document. ' +
            'A parts list can be imported against this device afterwards.'
          : 'Design files in the source are parsed for parts. Naming the device now gives those ' +
            'parts something to belong to; you can also import a parts list against it later.'}
      </p>

      <DeviceFieldGroups fields={form.data?.fields ?? []} draft={values} onChange={onChange} />

      {!hasDeviceValues(values) && (
        <p className="field-hint">
          {manual
            ? 'Without a name, no device is registered and this project has no hardware to report ' +
              'until one is added from its Hardware screen.'
            : 'Without a name, no device is registered now. You can add one from the project’s ' +
              'Hardware screen at any time.'}
        </p>
      )}
    </>
  );
}

/** quantumFieldKey turns a canonical path into the values key it maps to. */
function quantumFieldKey(canonicalPath: string): string {
  return canonicalPath.replace(/^quantum_component\./, '').replace(/\[\]$/, '');
}

/** The string-typed keys — every key except the one list field. */
type QuantumStringKey = Exclude<keyof QuantumDeviceValues, 'software_dependencies'>;

function isQuantumStringKey(key: string): key is QuantumStringKey {
  return key !== 'software_dependencies' && key in EMPTY_QUANTUM_DEVICE;
}

function readQuantumField(values: QuantumDeviceValues, key: string): string {
  return isQuantumStringKey(key) ? values[key] : '';
}

function writeQuantumField(
  values: QuantumDeviceValues,
  key: string,
  value: string,
): QuantumDeviceValues {
  return isQuantumStringKey(key) ? { ...values, [key]: value } : values;
}

/**
 * PracticesStep — CERT-In's third minimum-element category, plus SDLC stage.
 *
 * Split out of the old combined classification screen when BOM types moved to
 * step 1. They were together only because both happened to be "the rest";
 * choosing what to produce and describing how you govern it are different
 * decisions and the second is much longer.
 */
function PracticesStep({
  draft,
  patch,
  options,
}: {
  draft: Draft;
  patch: (p: Partial<Draft>) => void;
  options:
    | {
        sdlc_stages: string[];
        bom_depths: string[];
        practices: Array<{ id: string; name: string }>;
      }
    | undefined;
}) {
  const stages = options?.sdlc_stages ?? [];
  const depths = options?.bom_depths ?? [];

  const setPractice = (key: keyof PracticesInput, value: string) =>
    patch({ practices: { ...draft.practices, [key]: value } });

  // Rendered from the fetched list, never a literal. Writing the number here
  // would be the same mistake as hardcoding it in the backend.
  const practiceCount = options?.practices.length ?? 0;
  const recorded = recordedPractices(draft.practices);

  return (
    <section aria-labelledby="practices-heading">
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
