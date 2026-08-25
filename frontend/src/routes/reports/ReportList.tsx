/**
 * Every report this tenant has generated.
 *
 * ⚠ THE LIST STATES ITS OWN LIMITS RATHER THAN LOOKING COMPLETE.
 *
 * `GET /v1/reports` returns no `next_cursor`, so this cannot page; and
 * `reportResponse` carries no `project_id`, so the project column is recovered
 * by joining through the scan list. Both facts are surfaced — a report whose
 * scan is older than the joined page renders its project as `not-provided`
 * rather than blank, and a full page says so instead of implying it is
 * everything. See src/lib/reports.ts.
 */

import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { BomTypeChip, StatusPill } from '../../components/Chips';
import { EmptyState, ErrorState, SkeletonRows } from '../../components/States';
import { formatBytes, useReportsWithProject, type ReportWithProject } from '../../lib/reports';

export function ReportList() {
  const { rows, truncated, isPending, isError, error } = useReportsWithProject();
  const [bom, setBom] = useState('');
  const [status, setStatus] = useState('');

  const filtered = useMemo(
    () => rows.filter((r) => (!bom || r.bom_type === bom) && (!status || r.status === status)),
    [rows, bom, status],
  );

  const bomTypes = useMemo(() => [...new Set(rows.map((r) => r.bom_type))].sort(), [rows]);
  const statuses = useMemo(() => [...new Set(rows.map((r) => r.status))].sort(), [rows]);

  if (isPending) return <SkeletonRows rows={8} columns={6} />;
  if (isError) return <ErrorState error={error} action="load reports" />;

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Reports</h1>
          <p className="tagline">Every BOM document generated for your organisation</p>
        </div>
        <Link className="btn btn-primary" to="/generate">
          Generate
        </Link>
      </header>

      {rows.length === 0 ? (
        <EmptyState
          title="No reports yet"
          guidance="A report is rendered from a completed scan. Run the generate flow to produce one."
          action={
            <Link className="btn btn-primary" to="/generate">
              Generate the first report
            </Link>
          }
        />
      ) : (
        <>
          <div className="filters">
            <label className="filter">
              <span>BOM type</span>
              <select value={bom} onChange={(e) => setBom(e.target.value)}>
                <option value="">All</option>
                {bomTypes.map((b) => (
                  <option key={b} value={b}>
                    {b}
                  </option>
                ))}
              </select>
            </label>
            <label className="filter">
              <span>Status</span>
              <select value={status} onChange={(e) => setStatus(e.target.value)}>
                <option value="">All</option>
                {statuses.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </label>
            <p className="deps-count" role="status">
              {filtered.length} of {rows.length}
            </p>
          </div>

          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Created</th>
                  <th scope="col">Project</th>
                  <th scope="col">Type</th>
                  <th scope="col">Level</th>
                  <th scope="col">Standard</th>
                  <th scope="col">Format</th>
                  <th scope="col">Status</th>
                  <th scope="col">Size</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r) => (
                  <ReportRow key={r.id} report={r} />
                ))}
              </tbody>
            </table>
          </div>

          {truncated && (
            <p className="callout callout-warn" role="status">
              <strong>This list is not complete.</strong> The reports endpoint does not return a
              pagination cursor, so only the most recent {rows.length} can be shown. Open a
              project&apos;s scan history to reach older reports.
            </p>
          )}
        </>
      )}
    </div>
  );
}

function ReportRow({ report: r }: { report: ReportWithProject }) {
  const size = formatBytes(r.size_bytes);
  return (
    <tr className={r.truncated ? 'row-warn' : undefined}>
      <th scope="row">
        <Link to={`/reports/${r.id}`}>{formatWhen(r.created_at)}</Link>
      </th>
      <td>
        {r.project_id && r.project_name ? (
          <Link to={`/projects/${r.project_id}`}>{r.project_name}</Link>
        ) : (
          // The join could not reach this report's scan. Say so; a blank cell
          // is indistinguishable from a project with no name.
          <span className="not-provided">not-provided</span>
        )}
      </td>
      <td>
        <BomTypeChip type={r.bom_type} />
      </td>
      <td>{r.level}</td>
      <td>{r.standard}</td>
      <td>{r.format}</td>
      <td>
        <StatusPill status={r.status} />
        {r.truncated && <span className="tag tag-quiet">truncated</span>}
      </td>
      <td>{size ?? <span className="not-provided">not-provided</span>}</td>
    </tr>
  );
}

function formatWhen(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}
