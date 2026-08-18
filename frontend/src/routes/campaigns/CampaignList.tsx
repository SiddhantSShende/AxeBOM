/**
 * The campaigns list.
 *
 * ⚠ EVERY ROW ANSWERS "WHEN DOES THIS NEXT RUN?" IN THE VIEWER'S OWN TIMEZONE,
 * AND NAMES THE CAMPAIGN'S.
 *
 * A campaign is stored against an IANA zone the customer chose — often not the
 * one the person reading the screen is in. Showing only the campaign's zone
 * makes people do arithmetic; showing only the viewer's hides the setting they
 * are responsible for. Both, side by side, is the only version that does not
 * mislead somebody.
 */

import { useState } from 'react';
import { Link } from 'react-router';
import { EmptyState, ErrorState, SkeletonRows } from '../../components/States';
import { StatusPill } from '../../components/Chips';
import {
  describeCron,
  useCampaigns,
  useDeleteCampaign,
  useRunCampaignNow,
  useSetCampaignEnabled,
  type Campaign,
} from '../../lib/campaigns';

export function CampaignList() {
  const { data: campaigns, isPending, error, refetch } = useCampaigns();

  if (isPending) return <SkeletonRows rows={5} columns={5} />;
  if (error) {
    return <ErrorState error={error} action="load your campaigns" onRetry={() => void refetch()} />;
  }

  if (!campaigns || campaigns.length === 0) {
    return (
      <EmptyState
        title="No scheduled scans yet"
        guidance={
          'A campaign runs scans on a schedule and generates the reports you choose. ' +
          'It is how the CERT-In "Frequency" practice a project declares actually happens ' +
          'rather than being an intention.'
        }
        action={
          <Link className="btn btn-primary" to="/campaigns/new">
            Schedule a scan
          </Link>
        }
      />
    );
  }

  return (
    <section>
      <header className="page-header">
        <h1>Scheduled scans</h1>
        <Link className="btn btn-primary" to="/campaigns/new">
          Schedule a scan
        </Link>
      </header>

      <table className="table">
        <caption className="sr-only">Scheduled scan campaigns</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Schedule</th>
            <th scope="col">Next run</th>
            <th scope="col">Projects</th>
            <th scope="col">Status</th>
            <th scope="col">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {campaigns.map((c) => (
            <CampaignRow key={c.id} campaign={c} />
          ))}
        </tbody>
      </table>
    </section>
  );
}

function CampaignRow({ campaign }: { campaign: Campaign }) {
  const setEnabled = useSetCampaignEnabled();
  const runNow = useRunCampaignNow();
  const remove = useDeleteCampaign();
  const [confirmingDelete, setConfirmingDelete] = useState(false);

  return (
    <tr>
      <th scope="row">
        <Link to={`/campaigns/${campaign.id}`}>{campaign.name}</Link>
      </th>

      <td>
        {describeCron(campaign.cron_expr)}
        <br />
        <small className="muted">
          <code>{campaign.cron_expr}</code> · {campaign.timezone}
        </small>
      </td>

      <td>
        {campaign.enabled ? (
          <NextRun at={campaign.next_run_at} campaignZone={campaign.timezone} />
        ) : (
          <span className="muted">Paused</span>
        )}
      </td>

      <td>{campaign.project_ids.length}</td>

      <td>
        <StatusPill status={campaign.enabled ? 'completed' : 'skipped'} />
      </td>

      <td className="row-actions">
        <button
          type="button"
          className="btn btn-sm"
          disabled={setEnabled.isPending}
          onClick={() =>
            setEnabled.mutate({ id: campaign.id, enabled: !campaign.enabled })
          }
        >
          {campaign.enabled ? 'Pause' : 'Resume'}
        </button>

        <button
          type="button"
          className="btn btn-sm"
          disabled={runNow.isPending}
          onClick={() => runNow.mutate(campaign.id)}
        >
          Run now
        </button>

        {/*
          ⚠ DELETE IS CONFIRMED IN PLACE, AND SAYS WHAT IS LOST. Deleting a
          campaign cascades its run history — the record of what was scanned and
          when, which is the thing a compliance customer is keeping.
        */}
        {confirmingDelete ? (
          <span className="confirm-inline" role="group" aria-label="Confirm delete">
            <span className="muted">Delete this campaign and its run history?</span>
            <button
              type="button"
              className="btn btn-sm btn-danger"
              disabled={remove.isPending}
              onClick={() => remove.mutate(campaign.id)}
            >
              Delete
            </button>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => setConfirmingDelete(false)}
            >
              Cancel
            </button>
          </span>
        ) : (
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => setConfirmingDelete(true)}
          >
            Delete
          </button>
        )}
      </td>
    </tr>
  );
}

/**
 * NextRun shows the instant in the viewer's zone and, when they differ, the
 * campaign's.
 */
export function NextRun({
  at,
  campaignZone,
}: {
  at: string | undefined;
  campaignZone: string;
}) {
  if (!at) {
    // A campaign that is enabled with no next run has nothing to show, and
    // saying "—" would look like a rendering bug rather than a state.
    return <span className="muted">Not scheduled</span>;
  }

  const instant = new Date(at);
  if (Number.isNaN(instant.getTime())) return <span className="muted">{at}</span>;

  const viewerZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const local = instant.toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  });

  if (viewerZone === campaignZone) {
    return <time dateTime={at}>{local}</time>;
  }

  const inCampaignZone = instant.toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: campaignZone,
  });

  return (
    <>
      <time dateTime={at}>{local}</time>
      <br />
      <small className="muted">
        {inCampaignZone} in {campaignZone}
      </small>
    </>
  );
}
