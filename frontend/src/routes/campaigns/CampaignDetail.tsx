/**
 * One campaign: its schedule and its run history.
 *
 * ⚠ A SKIPPED RUN IS SHOWN, WITH ITS REASON, AND IS NOT STYLED AS A FAILURE.
 *
 * The scheduler records missed occurrences rather than firing all of them —
 * firing 48 catch-up scans after two days of downtime would be a thundering
 * herd. Recording them is what makes the gap visible instead of silent, and
 * that only works if this screen shows them. A compliance customer finding at
 * audit that two days have no scan, with nothing in the product saying why, is
 * the failure those rows exist to prevent.
 */

import { Link, useParams } from 'react-router';
import { EmptyState, ErrorState, SkeletonRows } from '../../components/States';
import { StatusPill } from '../../components/Chips';
import {
  describeCron,
  useCampaign,
  useCampaignRuns,
  useRunCampaignNow,
  type CampaignRun,
} from '../../lib/campaigns';
import { NextRun } from './CampaignList';

export function CampaignDetail() {
  const { id = '' } = useParams();
  const campaign = useCampaign(id);
  const runs = useCampaignRuns(id);
  const runNow = useRunCampaignNow();

  if (campaign.isPending) return <SkeletonRows rows={6} columns={4} />;
  if (campaign.error) {
    return (
      <ErrorState
        error={campaign.error}
        action="load this campaign"
        onRetry={() => void campaign.refetch()}
      />
    );
  }
  if (!campaign.data) return null;

  const c = campaign.data;

  return (
    <section>
      <header className="page-header">
        <div>
          <h1>{c.name}</h1>
          <p className="muted">
            Runs {describeCron(c.cron_expr)} · <code>{c.cron_expr}</code> · {c.timezone}
          </p>
        </div>
        <button
          type="button"
          className="btn"
          disabled={runNow.isPending}
          onClick={() => runNow.mutate(c.id)}
        >
          Run now
        </button>
      </header>

      <dl className="summary">
        <dt>Next run</dt>
        <dd>
          {c.enabled ? (
            <NextRun at={c.next_run_at} campaignZone={c.timezone} />
          ) : (
            <span className="muted">Paused</span>
          )}
        </dd>

        <dt>Last run</dt>
        <dd>
          {c.last_run_at ? (
            <NextRun at={c.last_run_at} campaignZone={c.timezone} />
          ) : (
            <span className="muted">Never</span>
          )}
        </dd>

        <dt>Projects</dt>
        <dd>{c.project_ids.length}</dd>

        <dt>Produces</dt>
        <dd>
          {c.bom_types.join(', ').toUpperCase()} · {c.report_levels.join(', ').replace(/_/g, ' ')} ·{' '}
          {c.standards.join(', ').toUpperCase()} · {c.formats.join(', ').toUpperCase()}
        </dd>
      </dl>

      <h2>Run history</h2>
      <RunHistory runs={runs.data} isPending={runs.isPending} error={runs.error} />
    </section>
  );
}

function RunHistory({
  runs,
  isPending,
  error,
}: {
  runs: CampaignRun[] | undefined;
  isPending: boolean;
  error: unknown;
}) {
  if (isPending) return <SkeletonRows rows={5} columns={4} />;
  if (error) return <ErrorState error={error} action="load the run history" />;

  if (!runs || runs.length === 0) {
    return (
      <EmptyState
        title="No runs yet"
        guidance="The first run will appear here once the schedule comes round, or you can run it now."
      />
    );
  }

  return (
    <table className="table">
      <caption className="sr-only">Campaign run history</caption>
      <thead>
        <tr>
          <th scope="col">Scheduled for</th>
          <th scope="col">Status</th>
          <th scope="col">Scans</th>
          <th scope="col">Detail</th>
        </tr>
      </thead>
      <tbody>
        {runs.map((run) => (
          <tr key={run.id}>
            <th scope="row">
              <time dateTime={run.scheduled_for}>
                {new Date(run.scheduled_for).toLocaleString(undefined, {
                  dateStyle: 'medium',
                  timeStyle: 'short',
                })}
              </time>
            </th>

            <td>
              <StatusPill status={run.status} />
            </td>

            <td>
              {run.scan_ids.length === 0 ? (
                <span className="muted">—</span>
              ) : (
                run.scan_ids.map((scanId) => (
                  <Link key={scanId} className="chip" to={`/scans/${scanId}`}>
                    {scanId.slice(0, 8)}
                  </Link>
                ))
              )}
            </td>

            <td>
              {/*
                ⚠ THE SKIP REASON IS RENDERED IN FULL. It explains that the run
                was superseded by a later catch-up rather than lost, which is
                the difference between a gap somebody has to investigate and one
                the product has already accounted for.
              */}
              {run.skip_reason && <p className="muted">{run.skip_reason}</p>}
              {run.error && (
                <p className="field-error" role="alert">
                  {run.error}
                </p>
              )}
              {!run.skip_reason && !run.error && <span className="muted">—</span>}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
