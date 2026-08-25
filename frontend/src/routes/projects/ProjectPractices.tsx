/**
 * The practices editor.
 *
 * ⚠ THIS IS A MINIMUM ELEMENT, NOT A SETTINGS PAGE.
 *
 * CERT-In's three minimum-element categories are automation support, practices
 * and processes, and the data fields (docs/06-COMPLIANCE-PROFILES.md §6). A
 * project with gaps here cannot produce a complete compliance report however
 * complete its component data is, and the screen says so at the top rather
 * than letting the gap surface weeks later as a coverage number.
 *
 * Until now these six fields could only be set during registration — a project
 * created before the practices step existed had no way to fill them in, and
 * `useSetPractices` had no caller at all.
 */

import { useEffect, useState } from 'react';
import { useParams } from 'react-router';
import { ErrorState, SkeletonRows } from '../../components/States';
import {
  humanizeEnum,
  usePractices,
  useProject,
  useProjectOptions,
  useSetPractices,
  type PracticesInput,
} from '../../lib/projects';

const EMPTY: PracticesInput = {};

export function ProjectPractices() {
  const { id = '' } = useParams();
  const project = useProject(id);
  const practices = usePractices(id);
  const options = useProjectOptions();
  const save = useSetPractices(id);

  const [draft, setDraft] = useState<PracticesInput>(EMPTY);
  const [saved, setSaved] = useState(false);

  // Seed the form once the server value arrives. Keyed on the fetched object so
  // a refetch after save does not clobber a field the user is mid-edit in.
  useEffect(() => {
    const p = practices.data;
    if (!p) return;
    setDraft({
      frequency: p.frequency ?? '',
      depth: p.depth ?? '',
      known_unknowns: p.known_unknowns ?? '',
      distribution: p.distribution ?? '',
      access_control: p.access_control ?? '',
      errata_policy: p.errata_policy ?? '',
    });
  }, [practices.data]);

  const set = (k: keyof PracticesInput, v: string) => {
    setDraft((d) => ({ ...d, [k]: v }));
    setSaved(false);
  };

  if (practices.isPending || options.isPending) return <SkeletonRows rows={8} columns={2} />;
  if (practices.isError) return <ErrorState error={practices.error} action="load practices" />;

  const depths = options.data?.bom_depths ?? [];
  const compliance = practices.data?.compliance;

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Practices and processes</h1>
          <p className="tagline">{project.data?.name ?? 'Project'}</p>
        </div>
      </header>

      {/* THE POINT OF THIS SCREEN. Stated plainly, at the point of entry. */}
      <p className="note note-important">
        These are <strong>one of CERT-In&apos;s three minimum-element categories</strong> — not a
        settings page. A project with gaps here cannot produce a complete compliance report, however
        complete its component data is.
      </p>

      {compliance && (
        <p
          className={compliance.complete ? 'status status-up' : 'status status-warn'}
          role="status"
        >
          {/* Rendered from the response. The total comes from the compliance
              profile, so a CERT-In revision changes it without a release. */}
          <strong>
            {compliance.recorded} of {compliance.total} recorded.
          </strong>{' '}
          {compliance.note}
        </p>
      )}

      <form
        className="panel"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate(draft, { onSuccess: () => setSaved(true) });
        }}
      >
        <label className="field">
          <span>Frequency</span>
          <input
            value={draft.frequency ?? ''}
            onChange={(e) => set('frequency', e.target.value)}
            placeholder="weekly, every Monday 02:00 UTC"
          />
          <small>How often this BOM is regenerated. Campaigns automate it.</small>
        </label>

        <label className="field">
          <span>Depth</span>
          <select value={draft.depth ?? ''} onChange={(e) => set('depth', e.target.value)}>
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
            value={draft.known_unknowns ?? ''}
            onChange={(e) => set('known_unknowns', e.target.value)}
            rows={2}
            placeholder="What you know you cannot see"
          />
          <small>
            Ecosystems, vendored code or binaries no engine covers. Naming a gap is a substantive
            answer; leaving it blank is not.
          </small>
        </label>

        <label className="field">
          <span>Distribution and delivery</span>
          <textarea
            value={draft.distribution ?? ''}
            onChange={(e) => set('distribution', e.target.value)}
            rows={2}
            placeholder="How this BOM reaches the people who consume it"
          />
        </label>

        <label className="field">
          <span>Access control</span>
          <input
            value={draft.access_control ?? ''}
            onChange={(e) => set('access_control', e.target.value)}
            placeholder="who may read it, and how that is enforced"
          />
        </label>

        <label className="field">
          <span>Accommodation of mistakes</span>
          <textarea
            value={draft.errata_policy ?? ''}
            onChange={(e) => set('errata_policy', e.target.value)}
            rows={2}
            placeholder="How an error in a published BOM is corrected and re-issued"
          />
        </label>

        {save.error != null && <ErrorState error={save.error} action="save practices" />}

        <div className="wizard-actions">
          <button type="submit" className="btn btn-primary" disabled={save.isPending}>
            {save.isPending ? 'Saving…' : 'Save practices'}
          </button>
          {saved && !save.isPending && (
            <span className="status status-up" role="status">
              Saved
            </span>
          )}
        </div>
      </form>

      {compliance && compliance.gaps.length > 0 && (
        <section aria-labelledby="gaps-heading">
          <h2 id="gaps-heading">Gaps</h2>
          {/* Named, with the reason. "Something is missing" is not actionable;
              "Frequency is recorded as not-provided, which is a declaration
              rather than a substantive value" is. */}
          <ul className="gaps">
            {compliance.gaps.map((g) => (
              <li key={g.field_id}>
                <strong>{g.name}</strong> — {g.reason}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
