/**
 * Live scan progress.
 *
 * ⚠ THE PER-ENGINE ROWS ARE THE HONEST VIEW, NOT DECORATION.
 *
 * One engine going `partial` while others succeed is NORMAL, and it must be
 * visible as it happens rather than discovered in the report. A single overall
 * bar would show 100% for a scan that silently skipped an ecosystem — which is
 * precisely the false negative this product exists to avoid.
 *
 * docs/07-FRONTEND-SPEC.md §5.
 */

import { useEffect, useRef, useState } from 'react';
import { useLocation, useParams } from 'react-router';
import { StatusPill } from '../../components/Chips';
import { SkeletonRows } from '../../components/States';
import { getAccessToken } from '../../lib/api';
import {
  bearerProtocols,
  connectProgress,
  type ConnectionState,
  type ScanProgress as Progress,
} from '../../lib/ws';

export function ScanProgressRoute() {
  const { id = '' } = useParams();
  // ⚠ READ ONCE, ON THE ENTRY THAT SET IT. GenerateFlow passes this in
  // navigate() state when some (not all) of the reports it queued for this
  // scan were refused — CBOM today, a known, labelled gap
  // (services/report/internal/service/service.go). A reload or a direct visit
  // to this URL carries no state, which is correct: the warning describes one
  // specific queueing attempt, not a property of the scan itself.
  const reportWarning = (useLocation().state as { reportWarning?: string } | null)?.reportWarning;
  const [progress, setProgress] = useState<Progress | null>(null);
  const [connection, setConnection] = useState<ConnectionState>({ kind: 'connecting' });

  useEffect(() => {
    if (!id) return;
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    return connectProgress({
      url: `${proto}://${window.location.host}/api/v1/scans/${id}/progress`,
      handlers: { onProgress: setProgress, onConnection: setConnection },
      // ⚠ READ LAZILY. The token is renewed roughly every quarter hour and a
      // reconnect may happen long after this effect ran; capturing the value
      // here would present an expired credential and close the socket the
      // moment it recovered.
      protocols: () => bearerProtocols(getAccessToken()),
    });
  }, [id]);

  return (
    <div className="page">
      <header>
        <h1>Scan progress</h1>
        <ConnectionNotice state={connection} />
        {reportWarning && (
          <p className="conn conn-warn" role="status">
            {reportWarning}
          </p>
        )}
      </header>

      {progress === null ? (
        <SkeletonRows rows={4} columns={4} />
      ) : (
        <>
          <OverallBar progress={progress} />
          <EngineTable engines={progress.engines} />
          <Announcer progress={progress} />
        </>
      )}
    </div>
  );
}

/**
 * ConnectionNotice says what the socket is doing.
 *
 * ⚠ A RECONNECTING CLIENT IS WORKING, AND THE UI HAS TO SAY SO. Freezing at
 * the last percentage with no explanation is what makes a user reload the page
 * mid-scan — and a reload is the one action that loses nothing here but feels
 * like it might.
 */
function ConnectionNotice({ state }: { state: ConnectionState }) {
  switch (state.kind) {
    case 'live':
      return null;
    case 'connecting':
      return <p className="conn conn-info">Connecting to the live feed…</p>;
    case 'reconnecting':
      return (
        <p className="conn conn-warn" role="status">
          Reconnecting (attempt {state.attempt}). The scan is still running — this page will catch
          up automatically, because it re-reads the full state on reconnect rather than replaying
          missed events.
        </p>
      );
    case 'closed':
      return (
        <p className="conn conn-down" role="status">
          The live feed closed: {state.reason}. Refresh to reconnect; nothing is lost.
        </p>
      );
  }
}

function OverallBar({ progress }: { progress: Progress }) {
  return (
    <section className="progress-overall">
      <div className="progress-head">
        <StatusPill status={progress.status} />
        <span className="progress-percent">{Math.round(progress.percent)}%</span>
      </div>
      <div
        className="progress-track"
        role="progressbar"
        aria-valuenow={Math.round(progress.percent)}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Overall scan progress"
      >
        <div className="progress-fill" style={{ width: `${progress.percent}%` }} />
      </div>
      <p className="progress-note">
        Weighted by engine, not a simple average — a fast lockfile parser and a slow vulnerability
        match are not equal halves of a scan.
      </p>
    </section>
  );
}

function EngineTable({ engines }: { engines: Progress['engines'] }) {
  if (engines.length === 0) {
    return (
      <p className="conn conn-warn">
        No engines have reported yet. If this persists, the scan may have found no source it can
        read.
      </p>
    );
  }

  return (
    <table className="table">
      <caption className="table-caption">
        Every engine requested for this scan, including any that could not run. An engine that is{' '}
        <code>unavailable</code> is a stated gap, not a failure — and it is the reason a component
        count can be lower than you expect.
      </caption>
      <thead>
        <tr>
          <th scope="col">Engine</th>
          <th scope="col">Status</th>
          <th scope="col">Ecosystems</th>
          <th scope="col">Duration</th>
          <th scope="col">Note</th>
        </tr>
      </thead>
      <tbody>
        {engines.map((e) => (
          <tr key={e.engineId}>
            <th scope="row">{e.engineId}</th>
            <td>
              <StatusPill status={e.status} />
            </td>
            <td>
              {e.ecosystems.length > 0 ? (
                e.ecosystems.join(', ')
              ) : (
                <span className="not-provided">none yet</span>
              )}
            </td>
            <td>{e.durationMs === null ? '—' : `${(e.durationMs / 1000).toFixed(1)}s`}</td>
            <td>{e.message ?? ''}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/**
 * Announcer speaks meaningful transitions to a screen reader.
 *
 * ⚠ TRANSITIONS, NOT PERCENTAGES. A polite live region wired to the percentage
 * would announce "forty-one percent, forty-two percent" continuously and make
 * the page unusable with a screen reader — which is a worse outcome than
 * announcing nothing. Only a status change is worth interrupting for.
 */
function Announcer({ progress }: { progress: Progress }) {
  const previous = useRef<Map<string, string>>(new Map());
  const [message, setMessage] = useState('');

  useEffect(() => {
    const changes: string[] = [];
    for (const e of progress.engines) {
      const was = previous.current.get(e.engineId);
      if (was !== undefined && was !== e.status) {
        changes.push(`${e.engineId} ${e.status}`);
      }
      previous.current.set(e.engineId, e.status);
    }
    if (changes.length > 0) setMessage(changes.join('. '));
  }, [progress]);

  return (
    <div className="sr-only" role="status" aria-live="polite">
      {message}
    </div>
  );
}
