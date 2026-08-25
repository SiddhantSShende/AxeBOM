/**
 * Project detail.
 *
 * Shows classifications, owner, validity and all six practices — and, where a
 * practice is missing, says so as a NAMED GAP rather than an empty field.
 *
 * The compliance panel deliberately never renders a bare percentage. "4 of 6"
 * with the specific missing sub-elements is actionable; "67% compliant" is a
 * score somebody will screenshot, and this product does not assert compliance
 * (CLAUDE.md, honest labels).
 */

import { useParams, Link } from 'react-router';
import { ApiError } from '../../lib/api';
import { humanizeEnum, useProject, usePractices, validityWarning } from '../../lib/projects';

export function ProjectDetail() {
  const { id } = useParams<{ id: string }>();
  const project = useProject(id);
  const practices = usePractices(id);

  if (project.isPending) {
    return (
      <div className="page">
        <p className="status" aria-live="polite">
          Loading…
        </p>
      </div>
    );
  }

  if (project.isError) {
    const notFound = project.error instanceof ApiError && project.error.isNotFound;
    return (
      <div className="page">
        <p className="status status-down" role="alert">
          {notFound
            ? 'No such project.'
            : project.error instanceof Error
              ? project.error.message
              : 'Could not load the project'}
        </p>
        <Link to="/projects">Back to projects</Link>
      </div>
    );
  }

  const p = project.data;
  const warning = validityWarning(p.validity_end);

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>{p.name}</h1>
          {p.description && <p className="tagline">{p.description}</p>}
        </div>
        <Link className="btn" to="/projects">
          All projects
        </Link>
      </header>

      <section aria-labelledby="classification-heading">
        <h2 id="classification-heading">Classification</h2>
        <ul className="chips">
          {p.classifications.map((c) => (
            <li key={c} className="chip" data-bom={c.toLowerCase()}>
              {c}
            </li>
          ))}
        </ul>
        <dl className="meta">
          <div>
            <dt>SDLC stage</dt>
            <dd>{humanizeEnum(p.sdlc_stage)}</dd>
          </div>
          <div>
            <dt>Source</dt>
            <dd>{humanizeEnum(p.source_type)}</dd>
          </div>
        </dl>
      </section>

      <section aria-labelledby="owner-heading">
        <h2 id="owner-heading">Owner and validity</h2>
        <dl className="meta">
          <Field label="Name" value={p.owner.name} />
          <Field label="Email" value={p.owner.email} />
          <Field label="GitHub" value={p.owner.github} />
          <Field label="Phone" value={p.owner.phone} />
          <Field label="Valid from" value={p.validity_start} />
          <Field label="Valid until" value={p.validity_end} />
        </dl>
        {warning && (
          <p className="status status-warn" role="status">
            {warning}
          </p>
        )}
      </section>

      <section aria-labelledby="practices-heading">
        <h2 id="practices-heading">Practices and processes</h2>

        {practices.isPending && <p className="status">Loading…</p>}

        {practices.data && (
          <>
            <p
              className={
                practices.data.compliance.complete ? 'status status-up' : 'status status-warn'
              }
              role="status"
            >
              {/* Rendered from the response. The total comes from the compliance
                  profile, so a CERT-In revision changes it without a release. */}
              <strong>
                {practices.data.compliance.recorded} of {practices.data.compliance.total} recorded.
              </strong>{' '}
              {practices.data.compliance.note}
            </p>

            <dl className="meta meta-stacked">
              <Field label="Frequency" value={practices.data.frequency} />
              <Field
                label="Depth"
                value={practices.data.depth ? humanizeEnum(practices.data.depth) : null}
              />
              <Field label="Known unknowns" value={practices.data.known_unknowns} />
              <Field label="Distribution and delivery" value={practices.data.distribution} />
              <Field
                label="Access control"
                value={
                  practices.data.access_control ? humanizeEnum(practices.data.access_control) : null
                }
              />
              <Field label="Accommodation of mistakes" value={practices.data.errata_policy} />
            </dl>

            {practices.data.compliance.gaps.length > 0 && (
              <>
                <h3>Gaps</h3>
                {/* Named, with the reason. "Something is missing" is not
                    actionable; "Frequency is recorded as not-provided, which is
                    a declaration rather than a substantive value" is. */}
                <ul className="gaps">
                  {practices.data.compliance.gaps.map((g) => (
                    <li key={g.field_id}>
                      <strong>{g.name}</strong> — {g.reason}
                    </li>
                  ))}
                </ul>
              </>
            )}
          </>
        )}
      </section>
    </div>
  );
}

/**
 * Field renders one label/value pair.
 *
 * An absent value renders as an explicit "Not recorded", never as blank space:
 * a blank is indistinguishable from a rendering bug, and this product's whole
 * argument is that an unknown must be visible rather than omitted.
 */
function Field({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd className={value ? undefined : 'unset'}>{value || 'Not recorded'}</dd>
    </div>
  );
}
