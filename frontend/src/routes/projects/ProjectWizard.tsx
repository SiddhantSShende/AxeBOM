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
  useProjectOptions,
  useSetPractices,
  useUploadFile,
  type CreateProjectInput,
  type Owner,
  type PracticesInput,
  type Repo,
} from '../../lib/projects';
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
  githubRepo: StagedRepo | null;
  uploadFiles: UploadDraftFile[];
  webSourceUrl: string;
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
  githubRepo: null,
  uploadFiles: [],
  webSourceUrl: '',
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
  const setPractices = useSetPractices();
  const uploadFile = useUploadFile();
  const connectRepo = useConnectRepo();
  const createWebSource = useCreateWebSource();

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

      void navigate(`/projects/${project.id}`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Could not create the project');
    }
  }

  const canAdvance =
    step === 1
      ? draft.name.trim() !== '' &&
        (draft.sourceType !== 'github' || draft.githubRepo !== null) &&
        (draft.sourceType !== 'upload' || draft.uploadFiles.length > 0) &&
        (draft.sourceType !== 'url' || isHttpsURL(draft.webSourceUrl))
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
  // ⚠ FILTERED, NOT THE RAW API LIST. `/v1/projects/options` reflects the
  // full project.source_type CHECK constraint — github, gitlab, bitbucket,
  // upload, image, manual, url — because that column also has to accept
  // whatever a project was created with by any other means. This wizard has
  // a real flow for exactly four of them; offering the rest as a radio
  // option that renders no fields and connects nothing on submit is a
  // control that looks like it does something and does not. Restricted here,
  // not on the server: another client is still free to create a project
  // with a source_type this wizard has no UI for.
  const sources = (options?.source_types ?? SUPPORTED_SOURCE_TYPES).filter((s) =>
    SUPPORTED_SOURCE_TYPES.includes(s),
  );

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
  const connect = useGitHubConnect();
  const [token, setToken] = useState<string | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);

  async function handleConnect() {
    try {
      const t = await connect.mutateAsync();
      setToken(t);
      setPickerOpen(true);
    } catch {
      // Surfaced below via connect.error; nothing further to do here.
    }
  }

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
      ) : (
        <button
          type="button"
          className="btn"
          onClick={() => void handleConnect()}
          disabled={connect.isPending}
        >
          {connect.isPending ? 'Connecting…' : 'Connect GitHub'}
        </button>
      )}

      {connect.error && (
        <p className="status status-down" role="alert">
          {connect.error instanceof Error ? connect.error.message : 'Could not connect to GitHub.'}
        </p>
      )}

      <small>
        Opens a GitHub window asking to read your repositories. The token this grants is used to
        list them and, once you pick one, to attach it to the project — it is never AxeBOM&apos;s
        password and nothing here is stored until you connect a repository.
      </small>

      <AnimatePresence>
        {pickerOpen && token && (
          <GitHubRepoPicker
            token={token}
            onClose={() => setPickerOpen(false)}
            onSelect={(repo: Repo) =>
              patch({
                githubRepo: {
                  fullName: repo.full_name,
                  externalId: repo.external_id,
                  defaultBranch: repo.default_branch,
                  cloneUrl: repo.clone_url,
                  token,
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

function ClassificationStep({
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
        }>;
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
      // ⚠ THE FALLBACK ALLOWS EVERYTHING, DELIBERATELY. This branch runs only
      // when /v1/projects/options could not be fetched. Guessing a narrower
      // list offline would disable a combination that is actually valid; the
      // server refuses the genuinely wrong ones either way, so the offline
      // form stays permissive and the server stays authoritative.
      sources: [] as string[],
    }));
  const stages = options?.sdlc_stages ?? [];
  const depths = options?.bom_depths ?? [];

  // ⚠ A BOM TYPE WHOSE ENGINES CANNOT READ THIS PROJECT'S SOURCE.
  //
  // The source is chosen on step 1 and the classifications here on step 3, so
  // this is the first screen where the combination is knowable. It matters
  // because the pairing is silently useless rather than obviously wrong: no
  // AIBOM engine reads a `url` source, so an AIBOM project registered from one
  // scans clean and reports nothing, forever. The dev database contains exactly
  // that row. The server refuses it now; offering the chip anyway would turn a
  // preventable choice into a 422 after the whole form is filled.
  //
  // An empty `sources` means "unknown" (the options fetch failed), never
  // "nothing" — see the fallback above.
  const incompatible = (t: { sources: string[] }) =>
    t.sources.length > 0 && !t.sources.includes(draft.sourceType);

  const blockedSelections = bomTypes
    .filter((t) => draft.classifications.includes(t.id) && incompatible(t))
    .map((t) => t.id);

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
            const blocked = incompatible(t);
            return (
              <li key={t.id}>
                <label
                  className="chip"
                  data-bom={t.id.toLowerCase()}
                  data-selected={selected}
                  data-blocked={blocked}
                >
                  <input
                    type="checkbox"
                    checked={selected}
                    disabled={blocked && !selected}
                    onChange={() => toggle(t.id)}
                  />
                  <span>{t.id}</span>
                  {/* The honest labels travel with the data, so the UI cannot
                      imply discovery where there is none. */}
                  {t.requires_import && <span className="chip-note">import only</span>}
                  {t.is_derived && <span className="chip-note">derived from CBOM</span>}
                  {/* Says WHY, and names the sources that would work — a
                      disabled control with no reason reads as a broken one. */}
                  {blocked && (
                    <span className="chip-note">
                      needs {t.sources.map(humanizeEnum).join(', ')}
                    </span>
                  )}
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
        {/* ⚠ SELECTED **AND** BLOCKED IS REACHABLE, AND ONLY BY GOING BACK.
            Disabling the checkbox stops a new incompatible choice, but a user
            who selects AIBOM here, returns to step 1 and switches the source to
            a url leaves a selection that was legal when it was made and is not
            any more. Silently dropping it would discard a choice they made on
            purpose, so it is named and left for them to remove — and the
            selected chips stay clickable precisely so they can. */}
        {blockedSelections.length > 0 && (
          <p className="status status-down" role="alert">
            {blockedSelections.join(', ')} cannot be produced from a{' '}
            {humanizeEnum(draft.sourceType)} source — no engine for{' '}
            {blockedSelections.length === 1 ? 'it' : 'them'} can read one, so the report would
            always be empty. Remove {blockedSelections.length === 1 ? 'it' : 'them'}, or go back and
            change the source.
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
