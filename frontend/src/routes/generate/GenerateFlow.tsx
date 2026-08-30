/**
 * The five-step generate flow — the product's signature interaction.
 *
 * The rules live in lib/wizard.ts; this file is the rendering. That split is
 * deliberate: the machine is the part worth testing, and a state machine tested
 * through a rendered stepper is tested through three layers of the wrong thing.
 *
 * docs/07-FRONTEND-SPEC.md §4.
 */

import { useMemo, type ReactNode } from 'react';
import { useNavigate } from 'react-router';
import { useMutation } from '@tanstack/react-query';
import { api, ApiError } from '../../lib/api';
import { useProjects } from '../../lib/projects';
import { BOM_TYPES } from '../../design/theme';
import { BomTypeChip } from '../../components/Chips';
import { EmptyState, ErrorState, SkeletonRows } from '../../components/States';
import {
  STEPS,
  blocking,
  effectiveFormats,
  plannedReports,
  reachable,
  scannableBomTypes,
  stepComplete,
  useWizard,
  validateDraft,
  type CombinationError,
  type Format,
  type Level,
  type Standard,
  toCombinationErrors,
  type StepId,
  type WizardDraft,
} from '../../lib/wizard';

/**
 * sourceKindFor maps a project's registered source onto what the scan API
 * accepts (events.SourceKind: git | upload | image | url).
 *
 * ⚠ `url` IS A REAL, SCANNABLE SOURCE KIND — NOT A GAP LIKE `manual`.
 * `events.SourceURL` (libs/go-shared/events/events.go) exists precisely so
 * `Orchestrator.CreateScan` can dispatch a url-registered project to
 * services/webrecon instead of the fetcher. Omitting it here left every
 * url-sourced project (created via the wizard's URL flow) unable to ever
 * reach Run — the mutation threw "has no scannable source" before a single
 * request left the browser, for a source kind the backend has always
 * accepted.
 *
 * ⚠ `manual` STILL HAS NO ANSWER, ON PURPOSE. A manually-registered project
 * has no engine that can reach it — HBOM is an import, not a scan (CLAUDE.md
 * honest labels) — and `orch.CreateScan` already refuses an unrecognised
 * source_kind with a clear message. Returning null here, rather than
 * guessing, is what lets the Review step say so before Run rather than after
 * a 422.
 */
function sourceKindFor(sourceType: string): 'git' | 'upload' | 'image' | 'url' | null {
  switch (sourceType) {
    case 'github':
    case 'gitlab':
    case 'bitbucket':
      return 'git';
    case 'upload':
      return 'upload';
    case 'image':
      return 'image';
    case 'url':
      return 'url';
    default:
      return null;
  }
}

const LEVELS: { value: Level; label: string; hint: string }[] = [
  {
    value: 'top_level',
    label: 'Top-Level',
    hint: 'Direct dependencies only. Transitive ones are counted and named as omitted.',
  },
  {
    value: 'complete',
    label: 'Complete',
    hint: 'Everything, including components no root reaches — flagged, not assumed direct.',
  },
];

const STANDARDS: { value: Standard; label: string; hint: string }[] = [
  {
    value: 'SPDX',
    label: 'SPDX 2.3',
    hint: 'The format most compliance reviewers ask for by name.',
  },
  {
    value: 'CycloneDX',
    label: 'CycloneDX 1.6',
    hint: "Named alongside SPDX by CERT-In's Automation Support element.",
  },
];

const FORMATS: { value: Format; label: string; hint: string }[] = [
  { value: 'pdf', label: 'PDF', hint: 'For reading. Page-capped — best paired with Top-Level.' },
  { value: 'xlsx', label: 'XLSX', hint: 'Every profile field as a column. No page limit.' },
  {
    value: 'json',
    label: 'JSON',
    hint: 'Canonical model plus both standard documents. No limits.',
  },
  { value: 'spdx', label: 'SPDX document', hint: 'The standalone SPDX file.' },
  { value: 'cyclonedx', label: 'CycloneDX document', hint: 'The standalone CycloneDX file.' },
];

export function GenerateFlow() {
  const navigate = useNavigate();
  const {
    draft,
    current,
    serverErrors,
    setProject,
    toggle,
    goTo,
    next,
    back,
    setServerErrors,
    reset,
  } = useWizard();

  const projects = useProjects();

  const localErrors = useMemo(() => validateDraft(draft), [draft]);
  const allErrors = [...localErrors, ...serverErrors];
  const hardErrors = blocking(allErrors);

  const project = projects.data?.projects.find((p) => p.id === draft.projectId) ?? null;

  const run = useMutation({
    // ⚠ TWO CALLS, NOT ONE. `POST /v1/scans` and `POST /v1/reports` are
    // different resources for a reason: a scan is ONE run of the engines; a
    // report is ONE rendered document. "Reports: 8" on the Review step was
    // always a cross product of bom_types × levels × formats — the SAME shape
    // report.reports has had since migrations/report/0001 — and this wizard
    // was posting all four dimensions to /v1/scans, which has never accepted
    // them (createScanRequest is project_id/source_kind/families/engines).
    // Every combination the review step promised 422'd as an unparseable
    // body before a single report could exist.
    mutationFn: async () => {
      const kind = project ? sourceKindFor(project.source_type) : null;
      if (!kind) {
        throw new Error(
          project
            ? `${project.name} has no scannable source (registered as ` +
                `"${project.source_type}"). HBOM is imported, not scanned, so this ` +
                'flow cannot produce a BOM for it.'
            : 'No project selected.',
        );
      }

      const scan = await api.post<{ id: string }>('/v1/scans', {
        project_id: draft.projectId,
        source_kind: kind,
        // events.Family is lowercase ("sbom"); the wizard's BomType is
        // uppercase ("SBOM") because CERT-In and the UI present it that way.
        //
        // ⚠ NOT draft.bomTypes. HBOM and QBOM are never scan families —
        // `Orchestrator.CreateScan` refuses both outright — so only the
        // scannable subset is sent here; validateDraft already blocks Run
        // before this fires if that subset is empty. The report loop below
        // still uses the full draft.bomTypes: a report can be requested for
        // HBOM/QBOM without this run scanning for it.
        families: scannableBomTypes(draft).map((t) => t.toLowerCase()),
      });

      // ⚠ FIRED WHILE THE SCAN IS STILL `queued`, AND THAT IS NOT A RACE.
      // /v1/reports resolves its bom_document_id at RENDER time, inside the
      // worker (services/report/internal/store/bomsource.go), not at create
      // time — a report can be queued before the scan that will feed it has
      // produced anything.
      //
      // `standard` is deliberately omitted: the API derives it from `format`
      // (spdx->SPDX, cyclonedx->CycloneDX, everything else->native) and
      // REFUSES a mismatch rather than silently correcting one
      // (parseStandard in services/report/internal/service/service.go) — so
      // sending our own guess here could only ever turn a valid request into
      // a rejected one.
      const combos: Array<{ bom_type: string; level: string; format: string }> = [];
      for (const bomType of draft.bomTypes) {
        for (const lvl of draft.levels) {
          for (const format of effectiveFormats(draft)) {
            combos.push({ bom_type: bomType, level: lvl, format });
          }
        }
      }

      // allSettled, not sequential awaits: these are independent resources,
      // and one rejection must not stop the rest from being queued. CBOM is a
      // real, LABELLED gap today ("CBOM reports are not yet renderable" —
      // CERT-In Table 9 is type-discriminated) — every other combination
      // still has to go through.
      const settled = await Promise.allSettled(
        combos.map((c) =>
          api.post('/v1/reports', {
            scan_id: scan.id,
            bom_type: c.bom_type,
            level: c.level,
            format: c.format,
          }),
        ),
      );
      const failed = settled.filter((r) => r.status === 'rejected').length;

      return { scan, planned: combos.length, failed };
    },
    onSuccess: ({ scan, planned, failed }) => {
      reset();
      void navigate(`/scans/${scan.id}`, {
        state:
          failed > 0
            ? {
                // Read by ScanProgress. A partial queue failure is not a
                // reason to hide the scan that DID start — it is a reason to
                // say plainly which of the promised reports did not queue.
                reportWarning: `${planned - failed} of ${planned} reports were queued. ${failed} could not be — CBOM is a known gap; anything else, retry from the reports list once the scan finishes.`,
              }
            : undefined,
      });
    },
    onError: (err) => {
      // ⚠ THE 422 IS MAPPED TO STEPS, NOT SHOWN AS A TOAST. The API enumerates
      // every offending pair (docs/02-CONTRACTS.md §7); rendering that against
      // the step that owns each one is the whole reason the wizard knows about
      // steps at all.
      if (err instanceof ApiError) setServerErrors(toCombinationErrors(err));
      else
        setServerErrors([{ step: 1, message: err instanceof Error ? err.message : String(err) }]);
    },
  });

  return (
    <div className="wizard">
      <header className="wizard-head">
        <h1>Generate</h1>
        <p className="tagline">One scan, however many bills of materials you need from it.</p>
      </header>

      <Stepper current={current} draft={draft} errors={allErrors} onGoTo={goTo} />

      <div className="wizard-body">
        {current === 1 && (
          <Step title="Project" hint="Which project to scan.">
            {projects.isPending && <SkeletonRows rows={4} columns={2} />}
            {projects.isError && (
              <ErrorState
                error={projects.error}
                action="load your projects"
                onRetry={() => void projects.refetch()}
              />
            )}
            {projects.data?.projects.length === 0 && (
              <EmptyState
                title="No projects yet"
                guidance="A scan runs against a project. Connect a repository or upload a manifest first."
                action={
                  <button
                    type="button"
                    className="btn"
                    onClick={() => void navigate('/projects/new')}
                  >
                    Connect a project
                  </button>
                }
              />
            )}
            <div className="option-grid">
              {projects.data?.projects.map((p) => (
                <button
                  type="button"
                  key={p.id}
                  className="option"
                  aria-pressed={draft.projectId === p.id}
                  onClick={() => setProject(p.id)}
                >
                  <span className="option-label">{p.name}</span>
                  <span className="option-chips">
                    {p.classifications.map((c) => (
                      <BomTypeChip key={c} type={c} />
                    ))}
                  </span>
                </button>
              ))}
            </div>
          </Step>
        )}

        {current === 2 && (
          <Step
            title="Classification"
            hint="Which bills of materials to produce. Choose as many as apply."
          >
            {/*
              ⚠ ONLY THE CLASSIFICATIONS THE PROJECT CARRIES ARE OFFERED, and
              the rest are shown DISABLED with a link rather than hidden. Hiding
              them leaves a user hunting for a BOM type they know exists; the
              disabled state answers "why can't I pick this" in place.
            */}
            <div className="option-grid">
              {BOM_TYPES.map((b) => {
                const available = project?.classifications.includes(b.type) ?? false;
                return (
                  <button
                    type="button"
                    key={b.type}
                    className="option"
                    disabled={!available}
                    aria-pressed={draft.bomTypes.includes(b.type)}
                    onClick={() => toggle('bomTypes', b.type)}
                  >
                    <span className="option-label">
                      <BomTypeChip type={b.type} />
                    </span>
                    <span className="option-hint">
                      {available
                        ? b.summary
                        : `${project?.name ?? 'This project'} is not classified for ${b.label}.`}
                    </span>
                  </button>
                );
              })}
            </div>
            {project && (
              <p className="step-note">
                Need another type?{' '}
                <a href={`/projects/${project.id}/settings`}>Add a classification</a> to{' '}
                {project.name}.
              </p>
            )}
          </Step>
        )}

        {current === 3 && (
          <Step title="Report type" hint="How deep each BOM goes. Both is a valid answer.">
            <OptionList
              options={LEVELS}
              selected={draft.levels}
              onToggle={(v) => toggle('levels', v)}
            />
          </Step>
        )}

        {current === 4 && (
          <Step title="Standard" hint="Which document standards to emit.">
            <OptionList
              options={STANDARDS}
              selected={draft.standards}
              onToggle={(v) => toggle('standards', v)}
            />
          </Step>
        )}

        {current === 5 && (
          <Step title="Format" hint="Which files to generate.">
            <OptionList
              options={FORMATS}
              selected={draft.formats}
              onToggle={(v) => toggle('formats', v)}
            />
          </Step>
        )}

        {current === 6 && (
          <Review
            projectName={project?.name ?? 'this project'}
            errors={allErrors}
            onFix={goTo}
            running={run.isPending}
            error={run.error}
            onRun={() => run.mutate()}
          />
        )}
      </div>

      <nav className="wizard-nav">
        <button type="button" className="btn btn-quiet" onClick={back} disabled={current === 1}>
          Back
        </button>
        {current < 6 ? (
          <button
            type="button"
            className="btn"
            onClick={next}
            disabled={!stepComplete(draft, current)}
          >
            Continue
          </button>
        ) : (
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => run.mutate()}
            // ⚠ ONLY HARD CONTRADICTIONS BLOCK. The Complete+PDF note and the
            // large-cross-product note are advisory: refusing them would be the
            // client overruling a decision the server is happy to make.
            disabled={hardErrors.length > 0 || run.isPending}
          >
            {run.isPending ? 'Starting…' : `Run and generate ${plannedReports(draft)} reports`}
          </button>
        )}
      </nav>
    </div>
  );
}

// ---------------------------------------------------------------------------

function Stepper({
  current,
  draft,
  errors,
  onGoTo,
}: {
  current: StepId;
  draft: WizardDraft;
  errors: CombinationError[];
  onGoTo: (s: StepId) => void;
}) {
  return (
    <ol className="stepper">
      {STEPS.map((s) => {
        const done = s.id < current && stepComplete(draft, s.id);
        const canReach = reachable(draft, s.id, current);
        const stepErrors = errors.filter((e) => e.step === s.id);
        return (
          <li key={s.id}>
            <button
              type="button"
              className="step-pip"
              data-state={s.id === current ? 'current' : done ? 'done' : 'todo'}
              data-invalid={stepErrors.length > 0 ? 'true' : undefined}
              disabled={!canReach}
              aria-current={s.id === current ? 'step' : undefined}
              onClick={() => onGoTo(s.id)}
            >
              <span className="step-number" aria-hidden="true">
                {s.id}
              </span>
              <span className="step-title">{s.title}</span>
              {stepErrors.length > 0 && <span className="step-flag">needs attention</span>}
            </button>
          </li>
        );
      })}
    </ol>
  );
}

function Step({ title, hint, children }: { title: string; hint: string; children: ReactNode }) {
  return (
    <section className="step" aria-labelledby={`step-${title}`}>
      <h2 id={`step-${title}`}>{title}</h2>
      <p className="step-hint">{hint}</p>
      {children}
    </section>
  );
}

function OptionList<T extends string>({
  options,
  selected,
  onToggle,
}: {
  options: readonly { value: T; label: string; hint: string }[];
  selected: readonly T[];
  onToggle: (value: T) => void;
}) {
  return (
    <div className="option-grid">
      {options.map((o) => (
        <button
          type="button"
          key={o.value}
          className="option"
          aria-pressed={selected.includes(o.value)}
          onClick={() => onToggle(o.value)}
        >
          <span className="option-label">{o.label}</span>
          <span className="option-hint">{o.hint}</span>
        </button>
      ))}
    </div>
  );
}

function Review({
  projectName,
  errors,
  onFix,
  running,
  error,
  onRun,
}: {
  projectName: string;
  errors: CombinationError[];
  onFix: (step: StepId) => void;
  running: boolean;
  error: unknown;
  onRun: () => void;
}) {
  const { draft } = useWizard();
  const formats = effectiveFormats(draft);

  return (
    <section className="step" aria-labelledby="step-review">
      <h2 id="step-review">Review</h2>
      <p className="step-hint">Exactly what will be produced, before anything runs.</p>

      <dl className="review">
        <dt>Project</dt>
        <dd>{projectName}</dd>
        <dt>Bills of materials</dt>
        <dd>
          {draft.bomTypes.map((t) => (
            <BomTypeChip key={t} type={t} />
          ))}
        </dd>
        <dt>Levels</dt>
        <dd>{draft.levels.map((l) => LEVELS.find((x) => x.value === l)?.label).join(', ')}</dd>
        <dt>Standards</dt>
        <dd>{draft.standards.join(', ')}</dd>
        <dt>Formats</dt>
        <dd>{formats.map((f) => FORMATS.find((x) => x.value === f)?.label).join(', ')}</dd>
        <dt>Reports</dt>
        <dd>
          <strong>{plannedReports(draft)}</strong> — one per BOM type × level × format
        </dd>
      </dl>

      {errors.length > 0 && (
        <div className="review-errors">
          {errors.map((e, i) => (
            <div
              key={i}
              className="review-error"
              data-hard={blocking([e]).length > 0 ? 'true' : undefined}
            >
              <p>{e.message}</p>
              {/*
                ⚠ THE FIX BUTTON IS THE POINT. An error message that names a
                problem without a way back to it makes the user re-navigate a
                six-step wizard by hand.
              */}
              <button type="button" className="btn btn-quiet" onClick={() => onFix(e.step)}>
                Go to step {e.step}
              </button>
            </div>
          ))}
        </div>
      )}

      {error != null && <ErrorState error={error} action="start the scan" onRetry={onRun} />}

      <p className="step-note">
        Rendering is asynchronous. The scan starts immediately; each report appears as it finishes,
        and a Complete BOM can take a while.
      </p>

      {running && <SkeletonRows rows={2} columns={3} />}
    </section>
  );
}
