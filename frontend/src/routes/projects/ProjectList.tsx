/**
 * The projects list (docs/07-FRONTEND-SPEC.md §6).
 *
 * Each card shows name, BOM-type chips, owner and validity — with an expiry
 * warning inside 30 days, because a BOM whose validity has lapsed is a
 * compliance document asserting a period that has passed.
 *
 * Scan status and open-critical counts arrive with Phase 6 and Phase 8; the
 * card is laid out to take them without a rewrite, and shows nothing rather
 * than a fabricated zero in the meantime.
 */

import { Link } from 'react-router';
import { ApiError } from '../../lib/api';
import { useProjects, validityWarning, type Project } from '../../lib/projects';

export function ProjectList() {
  const { data, isPending, isError, error } = useProjects();

  return (
    <div className="shell">
      <header className="page-header">
        <div>
          <h1>Projects</h1>
          <p className="tagline">Everything EncoreBOM tracks for your organisation</p>
        </div>
        <Link className="btn btn-primary" to="/projects/new">
          Register a project
        </Link>
      </header>

      {isPending && (
        <p className="status" aria-live="polite">
          Loading…
        </p>
      )}

      {isError && (
        <p className="status status-down" role="alert">
          {error instanceof ApiError
            ? error.message
            : 'Could not load projects — start the stack with `task dev`'}
        </p>
      )}

      {data && data.projects.length === 0 && (
        <section className="empty">
          <h2>No projects yet</h2>
          <p>
            Connect a GitHub repository, upload a manifest or lockfile, or register hardware
            manually.
          </p>
          <Link className="btn btn-primary" to="/projects/new">
            Register the first one
          </Link>
        </section>
      )}

      {data && data.projects.length > 0 && (
        <ul className="cards">
          {data.projects.map((p) => (
            <ProjectCard key={p.id} project={p} />
          ))}
        </ul>
      )}
    </div>
  );
}

function ProjectCard({ project }: { project: Project }) {
  const warning = validityWarning(project.validity_end);

  return (
    <li className="card">
      <h2>
        <Link to={`/projects/${project.id}`}>{project.name}</Link>
      </h2>

      <ul className="chips">
        {project.classifications.map((c) => (
          <li key={c} className="chip" data-bom={c.toLowerCase()}>
            {c}
          </li>
        ))}
      </ul>

      <dl className="meta">
        <div>
          <dt>Source</dt>
          <dd>{project.source_type}</dd>
        </div>
        <div>
          <dt>Stage</dt>
          <dd>{project.sdlc_stage}</dd>
        </div>
        {project.owner.name && (
          <div>
            <dt>Owner</dt>
            <dd>{project.owner.name}</dd>
          </div>
        )}
        {project.validity_end && (
          <div>
            <dt>Valid until</dt>
            <dd>{project.validity_end}</dd>
          </div>
        )}
      </dl>

      {warning && (
        // role="status", not an alert: it is important, not an interruption.
        <p className="status status-warn" role="status">
          {warning}
        </p>
      )}
    </li>
  );
}
