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
import { useMutation, useQuery } from '@tanstack/react-query';
import { api, ApiError } from '../../lib/api';
import { BOM_TYPES } from '../../design/theme';
import { BomTypeChip } from '../../components/Chips';
import { EmptyState, ErrorState, SkeletonRows } from '../../components/States';
import {
  STEPS,
  blocking,
  effectiveFormats,
  plannedReports,
  reachable,
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

interface ProjectSummary {
  id: string;
  name: string;
  classifications: string[];
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

  const projects = useQuery({
    queryKey: ['projects', 'options'],
    queryFn: () => api.get<{ projects: ProjectSummary[] }>('/v1/projects?limit=200'),
    staleTime: 30_000,
  });

  const localErrors = useMemo(() => validateDraft(draft), [draft]);
  const allErrors = [...localErrors, ...serverErrors];
  const hardErrors = blocking(allErrors);

  const project = projects.data?.projects.find((p) => p.id === draft.projectId) ?? null;

  const run = useMutation({
    mutationFn: () =>
      api.post<{ id: string }>('/v1/scans', {
        project_id: draft.projectId,
        bom_types: draft.bomTypes,
        levels: draft.levels,
        standards: draft.standards,
        formats: effectiveFormats(draft),
      }),
    onSuccess: (scan) => {
      reset();
      void navigate(`/scans/${scan.id}`);
    },
    onError: (err) => {
      // ⚠ THE 422 IS MAPPED TO STEPS, NOT SHOWN AS A TOAST. The API enumerates
      // every offending pair (docs/02-CONTRACTS.md §7); rendering that against
      // the step that owns each one is the whole reason the wizard knows about
      // steps at all.
      if (err instanceof ApiError) setServerErrors(toCombinationErrors(err));
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
            <div key={i} className="review-error" data-hard={e.step === 4 ? 'true' : undefined}>
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
