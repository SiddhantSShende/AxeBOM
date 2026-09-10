/**
 * One BOM type's home — the landing page for its sidebar section.
 *
 * ⚠ A LENS ON THE SAME PROJECTS, NOT A SEPARATE PRODUCT'S DATA. There is one
 * `project.project_classifications` table and one `bom_type` discriminator
 * threading through the schema (docs/01-DATA-MODEL.md) — this page is the
 * sidebar's navigational reorg around that shared model, not a second copy of
 * it. A project classified for two BOM types appears on both home pages.
 *
 * All five BOM types now have a dedicated detail screen — `detailRoute`
 * returns undefined only for a family this switch does not recognize.
 */

import { Link } from 'react-router';
import { bomMeta, type BomType } from '../../design/theme';
import { BomTypeChip } from '../../components/Chips';
import { EngineCoveragePanel } from '../../components/EngineCoveragePanel';
import { EmptyState, ErrorState, SkeletonRows } from '../../components/States';
import { useProjects, type Project } from '../../lib/projects';
import { useRole } from '../../lib/useAuth';

/** detailRoute is undefined where no dedicated screen exists yet. */
function detailRoute(family: BomType, projectId: string): string | undefined {
  switch (family) {
    case 'SBOM':
      return `/projects/${projectId}/dependencies`;
    case 'CBOM':
      return `/projects/${projectId}/crypto`;
    case 'QBOM':
      return `/projects/${projectId}/quantum`;
    case 'HBOM':
      return `/projects/${projectId}/hardware`;
    case 'AIBOM':
      return `/projects/${projectId}/ai-models`;
    default:
      return undefined;
  }
}

export function BomTypeHome({ family }: { family: BomType }) {
  const meta = bomMeta(family);
  const { data, isPending, isError, error } = useProjects();
  const { atLeast } = useRole();

  const projects = (data?.projects ?? []).filter((p) => p.classifications.includes(family));

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1 data-bom={meta.token}>
            <span aria-hidden="true">{meta.glyph}</span> {meta.label}
          </h1>
          <p className="tagline">{meta.summary}</p>
        </div>
        <Link className="btn btn-primary" to="/generate">
          Generate
        </Link>
      </header>

      <section className="panel" aria-labelledby={`${meta.token}-projects-heading`}>
        <h2 id={`${meta.token}-projects-heading`}>Projects classified for {meta.label}</h2>

        {isPending && <SkeletonRows rows={4} columns={3} />}
        {isError && <ErrorState error={error} action={`load ${meta.label} projects`} />}

        {!isPending && !isError && projects.length === 0 && (
          <EmptyState
            title={`No project is classified for ${meta.label} yet`}
            guidance={`Add the ${meta.label} classification from a project's Settings tab, then run Generate to produce its first report.`}
            action={
              <Link className="btn" to="/projects">
                Go to projects
              </Link>
            }
          />
        )}

        {!isPending && !isError && projects.length > 0 && (
          <ul className="cards">
            {projects.map((p) => (
              <ProjectRow key={p.id} project={p} family={family} />
            ))}
          </ul>
        )}
      </section>

      <EngineCoveragePanel family={family} />

      {atLeast('admin') ? (
        <p className="field-hint">
          <Link to="/settings/engines">Configure which engines run</Link> for {meta.label} across
          this organisation.
        </p>
      ) : (
        <p className="field-hint">
          Which engines run for {meta.label} is configured under Settings by an organisation admin.
        </p>
      )}
    </div>
  );
}

function ProjectRow({ project, family }: { project: Project; family: BomType }) {
  const href = detailRoute(family, project.id);
  return (
    <li className="card">
      <div className="option-label">
        <Link to={`/projects/${project.id}`}>{project.name}</Link>
        <span className="option-chips">
          {project.classifications.map((c) => (
            <BomTypeChip key={c} type={c} />
          ))}
        </span>
      </div>
      {href ? (
        <Link className="btn btn-quiet" to={href}>
          Open {bomMeta(family).label} view
        </Link>
      ) : (
        <span
          className="not-provided"
          title={`A dedicated ${bomMeta(family).label} view is not built yet. Generate can still produce a report once its data exists.`}
        >
          detail view not yet available
        </span>
      )}
    </li>
  );
}
