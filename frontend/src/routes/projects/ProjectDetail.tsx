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

  /*
   * ⚠ NOT KEYED ON A HARDCODED CERT-In FIELD ID.
   *
   * The obvious implementation writes `certin.sbom.pp.frequency` into this
   * file, which copies the compliance profile into the frontend — the exact
   * duplication CLAUDE.md invariant 2 exists to prevent, and it fails
   * SILENTLY: a renamed element shows no reason rather than throwing. (Written
   * that way first, with the ids guessed wrong, and every reason vanished.)
   *
   * The gap's `name` is the profile's own `name` for the element, so both
   * sides are normalised to letters and matched on that. A miss degrades to
   * "no extra reason shown", which is the same thing a recorded field does.
   */
  const reasons = new Map(
    (practices.data?.compliance.gaps ?? []).map((g) => [normalize(g.name), g.reason] as const),
  );

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>{p.name}</h1>
          {p.description && <p className="tagline">{p.description}</p>}
        </div>
        <div className="page-actions">
          <ul className="chips">
            {p.classifications.map((c) => (
              <li key={c} className="chip" data-bom={c.toLowerCase()}>
                {c}
              </li>
            ))}
          </ul>
          <Link className="btn" to="/projects">
            All projects
          </Link>
        </div>
      </header>

      {/*
        ⚠ CLASSIFICATION MOVED INTO THE HEADER RATHER THAN GETTING A SECTION
        OF ITS OWN. It was a whole titled section containing one chip — a
        heading, a gap and a border to carry a single word that identifies the
        project and therefore belongs next to its name, the way a status badge
        does. What is left here is the pair of facts that genuinely describe
        the project's setup.
      */}
      <section className="surface" aria-labelledby="setup-heading">
        <div className="surface-head">
          <h2 id="setup-heading">Setup</h2>
        </div>
        <div className="surface-body">
          <dl className="meta meta-cols">
            <div>
              <dt>SDLC stage</dt>
              <dd>{humanizeEnum(p.sdlc_stage)}</dd>
            </div>
            <div>
              <dt>Source</dt>
              <dd>{humanizeEnum(p.source_type)}</dd>
            </div>
          </dl>
        </div>
      </section>

      <section className="surface" aria-labelledby="owner-heading">
        <div className="surface-head">
          <h2 id="owner-heading">Owner and validity</h2>
          {warning && (
            <span className="surface-head-aside">
              <span className="status status-warn" role="status">
                {warning}
              </span>
            </span>
          )}
        </div>
        <div className="surface-body">
          <dl className="meta meta-cols">
            <Field label="Name" value={p.owner.name} />
            <Field label="Email" value={p.owner.email} />
            <Field label="GitHub" value={p.owner.github} />
            <Field label="Phone" value={p.owner.phone} />
            <Field label="Valid from" value={p.validity_start} />
            <Field label="Valid until" value={p.validity_end} />
          </dl>
        </div>
      </section>

      <section className="surface" aria-labelledby="practices-heading">
        <div className="surface-head">
          <h2 id="practices-heading">Practices and processes</h2>
          {practices.data && (
            <span className="surface-head-aside">
              {/* Rendered from the response. The total comes from the
                  compliance profile, so a CERT-In revision changes it without
                  a release. */}
              <span
                className={
                  practices.data.compliance.complete ? 'status status-up' : 'status status-warn'
                }
                role="status"
              >
                {practices.data.compliance.recorded} of {practices.data.compliance.total} recorded
              </span>
            </span>
          )}
        </div>

        {practices.isPending && (
          <div className="surface-body">
            <p className="status">Loading…</p>
          </div>
        )}

        {practices.data && (
          <>
            <div className="surface-body">
              {/*
                ⚠ THE SIX FIELDS AND THE "GAPS" LIST WERE THE SAME SIX FACTS,
                RENDERED TWICE. Every unrecorded practice appeared once as a
                field reading "Not recorded" and again, verbatim, as a bullet
                below it — so the emptier a project was, the more of the page
                it filled. The gap REASON is what the second list actually
                added, so it is shown on the row it belongs to and the
                duplicate list is gone.
              */}
              <dl className="meta">
                {[
                  ['Frequency', practices.data.frequency],
                  ['Depth', practices.data.depth ? humanizeEnum(practices.data.depth) : null],
                  ['Known unknowns', practices.data.known_unknowns],
                  ['Distribution and delivery', practices.data.distribution],
                  [
                    'Access control',
                    practices.data.access_control
                      ? humanizeEnum(practices.data.access_control)
                      : null,
                  ],
                  ['Accommodation of mistakes', practices.data.errata_policy],
                ].map(([label, value]) => (
                  <Field
                    key={label as string}
                    label={label as string}
                    value={value as string | null}
                    reason={reasons.get(normalize(label as string))}
                  />
                ))}
              </dl>
            </div>

            <p className="surface-foot">{practices.data.compliance.note}</p>
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
function Field({
  label,
  value,
  reason,
}: {
  label: string;
  value: string | null | undefined;
  /** Present only for practice fields, which are the ones the API scores. */
  reason?: string | undefined;
}) {
  /*
   * ⚠ THE REASON IS SHOWN ONLY WHEN IT SAYS MORE THAN THE CELL ALREADY DOES.
   *
   * For an unset practice the API's reason is the string "not recorded",
   * which is what this row renders anyway — so printing it appended a second
   * copy of the same fact to every empty field. That is what the deleted
   * "Gaps" list was doing six times over. A reason that is genuinely more
   * specific (a value present but non-substantive, say) still surfaces.
   */
  const extra = reason && normalize(reason) !== 'notrecorded' ? reason : undefined;
  return (
    <div>
      <dt>{label}</dt>
      <dd className={value ? undefined : 'unset'}>
        {value || 'Not recorded'}
        {extra && <span className="field-gap">{extra}</span>}
      </dd>
    </div>
  );
}

/** Letters only, lower-cased — so "Known Unknowns" and "Known unknowns" match. */
function normalize(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]/g, '');
}
