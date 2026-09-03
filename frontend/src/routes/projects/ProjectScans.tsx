/**
 * Scan history for one project.
 *
 * ⚠ THE ENGINE BREAKDOWN IS ON EVERY ROW, NOT JUST THE FAILED ONES.
 *
 * A scan that reports `succeeded` while one engine went `partial` is the
 * normal case, and it is exactly the case a single overall status hides
 * (CLAUDE.md invariant 12). The per-engine chips are what stop a partial scan
 * from being read as a complete one three weeks later.
 *
 * ⚠ AND THERE IS NO FINDINGS COUNT HERE. The list endpoint does not compute
 * one, and rendering a zero it never sent would be a false negative in the
 * screen people use to decide whether a scan is worth opening.
 */

import { Link, useParams } from 'react-router';
import { StatusPill } from '../../components/Chips';
import { EmptyState, ErrorState, SkeletonRows } from '../../components/States';
import { isTerminal, useCancelScan, useScans, type ScanListItem } from '../../lib/scans';

export function ProjectScans() {
  const { id = '' } = useParams();
  const scans = useScans(id);
  const cancel = useCancelScan(id);

  if (scans.isPending) return <SkeletonRows rows={8} columns={5} />;
  if (scans.isError) return <ErrorState error={scans.error} action="load scan history" />;

  const rows = scans.data?.pages.flatMap((p) => p.scans) ?? [];

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Scans</h1>
          {/* The project name is carried by the crumb above the tabs (App.tsx's
              ProjectCrumb); repeating it here printed it twice in one header. */}
        </div>
        <Link className="btn btn-primary" to="/generate">
          Run a scan
        </Link>
      </header>

      {rows.length === 0 ? (
        <EmptyState
          title="No scans yet"
          guidance="A scan materializes the source once, runs the engines against that snapshot, and produces the reports. Nothing has run for this project."
          action={
            <Link className="btn btn-primary" to="/generate">
              Run the first scan
            </Link>
          }
        />
      ) : (
        <>
          <div className="table-wrap">
            <table className="table">
              <caption className="table-caption">
                Most recent first. Engine status is shown per engine because one engine going
                partial while the others succeed is normal, and is not visible in an overall status.
              </caption>
              <thead>
                <tr>
                  <th scope="col">Started</th>
                  <th scope="col">Status</th>
                  <th scope="col">Source</th>
                  <th scope="col">Types</th>
                  <th scope="col">Engines</th>
                  <th scope="col">Duration</th>
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((s) => (
                  <ScanRow
                    key={s.id}
                    scan={s}
                    onCancel={() => cancel.mutate(s.id)}
                    cancelling={cancel.isPending}
                  />
                ))}
              </tbody>
            </table>
          </div>

          {scans.hasNextPage && (
            <button
              type="button"
              className="btn"
              onClick={() => void scans.fetchNextPage()}
              disabled={scans.isFetchingNextPage}
            >
              {scans.isFetchingNextPage ? 'Loading…' : 'Load more'}
            </button>
          )}
        </>
      )}
    </div>
  );
}

function ScanRow({
  scan,
  onCancel,
  cancelling,
}: {
  scan: ScanListItem;
  onCancel: () => void;
  cancelling: boolean;
}) {
  const running = !isTerminal(scan.status);
  return (
    <tr>
      <th scope="row">
        <Link to={`/scans/${scan.id}`}>{formatWhen(scan.started_at ?? scan.created_at)}</Link>
        {scan.commit_sha && (
          <>
            {' '}
            <code className="text-faint">{scan.commit_sha.slice(0, 7)}</code>
          </>
        )}
      </th>
      <td>
        <StatusPill status={scan.status} />
        {running && <span className="deps-count">{scan.progress_pct}%</span>}
      </td>
      <td>{scan.source_kind}</td>
      <td>{scan.families.length > 0 ? scan.families.join(', ') : <NoValue />}</td>
      <td>
        {scan.engine_runs.length === 0 ? (
          <NoValue />
        ) : (
          <span className="provenance">
            {scan.engine_runs.map((r) => (
              <span key={r.engine} className="provenance-chip" data-status={r.status}>
                {r.engine} · {r.status}
              </span>
            ))}
          </span>
        )}
      </td>
      <td>{duration(scan.started_at, scan.finished_at)}</td>
      <td className="row-actions">
        <Link className="btn btn-sm" to={`/scans/${scan.id}`}>
          View
        </Link>
        {running && (
          <button
            type="button"
            className="btn btn-sm btn-danger"
            onClick={onCancel}
            disabled={cancelling}
          >
            Cancel
          </button>
        )}
      </td>
    </tr>
  );
}

/** An absent value is stated, never left blank (CLAUDE.md invariant 3). */
function NoValue() {
  return <span className="not-provided">not-provided</span>;
}

function formatWhen(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  // Local time for a human reading a history list; the exact UTC instant is on
  // the scan detail page, where it is evidence rather than a timestamp.
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

function duration(start: string | undefined, end: string | undefined) {
  if (!start || !end) return <NoValue />;
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (!Number.isFinite(ms) || ms < 0) return <NoValue />;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${s % 60}s`;
}
