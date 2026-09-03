/**
 * Project settings.
 *
 * The screen `GenerateFlow` step 2 and `ProjectWizard` have both linked to
 * since they were written, and which until now rendered Not Found — so "Add a
 * classification" was a dead end from inside the product's signature flow.
 *
 * ⚠ THE SOURCE IS NOT EDITABLE, AND ITS ABSENCE IS EXPLAINED RATHER THAN
 * SILENT. `services/project/internal/handler/handler.go` parses `source_type`
 * on a PUT and never passes it to `svc.Update`. A select that posts a value
 * the server discards is worse than no select: the user watches it save and
 * believes it.
 */

import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router';
import { BomTypeChip } from '../../components/Chips';
import { ErrorState, SkeletonRows } from '../../components/States';
import {
  humanizeEnum,
  useProject,
  useProjectOptions,
  useUpdateProject,
  type Owner,
  type UpdateProjectInput,
} from '../../lib/projects';

export function ProjectSettings() {
  const { id = '' } = useParams();
  const project = useProject(id);
  const options = useProjectOptions();
  const save = useUpdateProject(id);

  const [draft, setDraft] = useState<UpdateProjectInput | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    const p = project.data;
    if (!p) return;
    setDraft({
      name: p.name,
      description: p.description ?? '',
      sdlc_stage: p.sdlc_stage,
      validity_start: p.validity_start ?? '',
      validity_end: p.validity_end ?? '',
      owner: { ...p.owner },
      classifications: [...p.classifications],
    });
  }, [project.data]);

  if (project.isPending || options.isPending) return <SkeletonRows rows={8} columns={2} />;
  if (project.isError) return <ErrorState error={project.error} action="load this project" />;
  if (!draft) return <SkeletonRows rows={8} columns={2} />;

  const patch = (p: Partial<UpdateProjectInput>) => {
    setDraft((d) => (d ? { ...d, ...p } : d));
    setSaved(false);
  };
  const setOwner = (k: keyof Owner, v: string) => patch({ owner: { ...draft.owner, [k]: v } });

  const toggleClass = (c: string) =>
    patch({
      classifications: draft.classifications.includes(c)
        ? draft.classifications.filter((x) => x !== c)
        : [...draft.classifications, c],
    });

  const bomTypes = options.data?.bom_types ?? [];
  const stages = options.data?.sdlc_stages ?? [];

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Project settings</h1>
          {/* The project name is carried by the crumb above the tabs (App.tsx's
              ProjectCrumb); repeating it here printed it twice in one header. */}
        </div>
      </header>

      <form
        className="panel"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate(draft, { onSuccess: () => setSaved(true) });
        }}
      >
        <label className="field">
          <span>Name</span>
          <input value={draft.name} onChange={(e) => patch({ name: e.target.value })} required />
        </label>

        <label className="field">
          <span>Description</span>
          <textarea
            value={draft.description ?? ''}
            onChange={(e) => patch({ description: e.target.value })}
            rows={2}
          />
        </label>

        <label className="field">
          <span>SDLC stage</span>
          <select
            value={draft.sdlc_stage ?? ''}
            onChange={(e) => patch({ sdlc_stage: e.target.value })}
          >
            {stages.map((s) => (
              <option key={s} value={s}>
                {humanizeEnum(s)}
              </option>
            ))}
          </select>
          <small>CERT-In §3.2. These values come from the compliance profile, not the UI.</small>
        </label>

        <h2>Classification</h2>
        <p className="field-hint">
          Which BOM types this project carries. Removing one does not delete data already generated
          for it.
        </p>
        <ul className="chips option-chips">
          {bomTypes.map((b) => {
            const on = draft.classifications.includes(b.id);
            return (
              <li key={b.id}>
                <button
                  type="button"
                  className={`btn btn-sm${on ? ' btn-active' : ''}`}
                  aria-pressed={on}
                  onClick={() => toggleClass(b.id)}
                >
                  <BomTypeChip type={b.id} describe />
                </button>
              </li>
            );
          })}
        </ul>

        <h2>Owner and validity</h2>
        <div className="field-pair">
          <label className="field">
            <span>Owner name</span>
            <input
              value={draft.owner.name ?? ''}
              onChange={(e) => setOwner('name', e.target.value)}
            />
          </label>
          <label className="field">
            <span>Owner email</span>
            <input
              type="email"
              value={draft.owner.email ?? ''}
              onChange={(e) => setOwner('email', e.target.value)}
            />
          </label>
        </div>
        <div className="field-pair">
          <label className="field">
            <span>GitHub</span>
            <input
              value={draft.owner.github ?? ''}
              onChange={(e) => setOwner('github', e.target.value)}
            />
          </label>
          <label className="field">
            <span>Phone</span>
            <input
              value={draft.owner.phone ?? ''}
              onChange={(e) => setOwner('phone', e.target.value)}
            />
          </label>
        </div>

        <div className="field-pair">
          <label className="field">
            <span>Validity start</span>
            <input
              type="date"
              value={draft.validity_start ?? ''}
              onChange={(e) => patch({ validity_start: e.target.value })}
            />
          </label>
          <label className="field">
            <span>Validity end</span>
            <input
              type="date"
              value={draft.validity_end ?? ''}
              onChange={(e) => patch({ validity_end: e.target.value })}
            />
          </label>
        </div>

        {save.error != null && <ErrorState error={save.error} action="save this project" />}

        {/* A footer, not a loose button: the strip separates what you edit
            from the control that commits it. */}
        <div className="panel-actions">
          <button type="submit" className="btn btn-primary" disabled={save.isPending}>
            {save.isPending ? 'Saving…' : 'Save changes'}
          </button>
          {saved && !save.isPending && (
            <span className="status status-up" role="status">
              Saved
            </span>
          )}
        </div>
      </form>

      <section className="panel" aria-labelledby="source-heading">
        <h2 id="source-heading">Source</h2>
        <dl className="meta">
          <div>
            <dt>Source type</dt>
            <dd>{humanizeEnum(project.data?.source_type ?? '')}</dd>
          </div>
        </dl>
        {/* Not a disabled input. A control that cannot be used should not be
            drawn as one — say why instead. */}
        <p className="field-hint">
          The source is fixed when a project is registered. A BOM's provenance chain starts at the
          artefact it was built from, so repointing a project at a different source would silently
          change what every past report describes. Register a new project instead.
        </p>
      </section>

      <section className="panel" aria-labelledby="practices-link-heading">
        <h2 id="practices-link-heading">Practices and processes</h2>
        <p className="field-hint">
          The six CERT-In practice fields are a minimum element, not a setting, and live on their
          own screen.
        </p>
        <Link className="btn" to={`/projects/${id}/practices`}>
          Edit practices
        </Link>
      </section>
    </div>
  );
}
