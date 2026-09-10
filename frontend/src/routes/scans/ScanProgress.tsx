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
import { Link, useLocation, useParams } from 'react-router';
import { AnimatePresence, m } from 'motion/react';
import { useMutation } from '@tanstack/react-query';
import { BomTypeChip, StatusPill } from '../../components/Chips';
import { ErrorState, SkeletonRows } from '../../components/States';
import { downloadFile, getAccessToken, triggerSave } from '../../lib/api';
import { formatBytes, levelLabel, useReports, type Report } from '../../lib/reports';
import { metricLabel, sortedCounts, tallyDiscoveries } from '../../lib/discoveries';
import { isTerminal } from '../../lib/scans';
import {
  bearerProtocols,
  connectProgress,
  type ActivityItem,
  type ConnectionState,
  type EngineProgress,
  type ScanProgress as Progress,
} from '../../lib/ws';

/** The rolling window's own width — see ActivityFeed's doc comment. */
const ACTIVITY_LIMIT = 3;

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
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  // ⚠ KEYED BY ENGINE, AND THAT IS WHAT MAKES IT SURVIVE A REDELIVERY. The
  // orchestrator's result consumer is at-least-once with MaxDeliver=4
  // (docs/02-CONTRACTS.md §2), so the same engine's counts can arrive twice.
  // Accumulating into a running total would double them and print "6 models"
  // for a repository holding three; last-value-wins per engine cannot.
  const [discoveries, setDiscoveries] = useState<Record<string, Record<string, number>>>({});
  const [connection, setConnection] = useState<ConnectionState>({ kind: 'connecting' });
  const seeded = useRef(false);
  // ⚠ QUERIED HERE, NOT INSIDE ReportsSection, so OverallBar can see it too —
  // see displayPercent's own doc comment for why "100%" has to wait on this,
  // not only on the scan's own engines.
  const reports = useReports(id);

  useEffect(() => {
    if (!id) return;
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    // ⚠ dispose IS CALLED FROM INSIDE onProgress, NOT ONLY FROM CLEANUP.
    //
    // The server sends the snapshot and, for an already-terminal scan,
    // closes immediately after with a normal (code 1000) closure — a
    // deliberate "nothing more will ever arrive," not a failure. But ws.ts's
    // reconnect loop treats EVERY close identically (by design: it is a
    // dumb, transport-only module that does not parse scan status — see its
    // own doc comment). Without this, a finished scan's progress page
    // reconnected forever: connect, get the same terminal snapshot, get
    // closed again, back off, repeat — each cycle logging a browser-level
    // "WebSocket connection failed" even though nothing was actually wrong.
    // Only the CALLER knows the scan is done, from the snapshot it just
    // received, so only the caller can correctly decide to stop.
    let dispose: (() => void) | null = null;
    dispose = connectProgress({
      url: `${proto}://${window.location.host}/api/v1/scans/${id}/progress`,
      handlers: {
        onProgress: (p) => {
          setProgress(p);
          // ⚠ SEEDED ONCE, FROM REAL HISTORY, NOT SYNTHESIZED. A scan that
          // is already terminal by the time this page connects (the common
          // case for a fast webrecon scan — see ActivityFeed's own doc
          // comment) will never produce a single live event: the server
          // sends the snapshot and closes immediately. Without this, the
          // feed would sit permanently empty for exactly the scans a user
          // is most likely to be looking at. Every entry here still traces
          // to a real, already-recorded engine_runs row — never invented.
          if (!seeded.current) {
            seeded.current = true;
            setActivity((prev) => (prev.length > 0 ? prev : deriveActivity(p.engines)));
          }
          if (isTerminal(p.status)) dispose?.();
        },
        onActivity: (a) => {
          setActivity((prev) => [a, ...prev].slice(0, ACTIVITY_LIMIT));
          // Only an engine RESULT carries counts; a phase transition carries
          // none, and an empty object here would blank an engine that had
          // already reported.
          if (a.engine && Object.keys(a.metrics).length > 0) {
            const { engine, metrics } = a;
            setDiscoveries((prev) => ({ ...prev, [engine]: metrics }));
          }
        },
        onConnection: setConnection,
      },
      // ⚠ READ LAZILY. The token is renewed roughly every quarter hour and a
      // reconnect may happen long after this effect ran; capturing the value
      // here would present an expired credential and close the socket the
      // moment it recovered.
      protocols: () => bearerProtocols(getAccessToken()),
    });
    return () => dispose?.();
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
          <OverallBar progress={progress} reports={reports.data?.reports} />
          <DiscoveryTally byEngine={discoveries} />
          <ActivityFeed items={activity} />
          <ReportsSection query={reports} />
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

/**
 * reportsPending reports whether any report requested for this scan has not
 * yet reached a terminal status. `undefined` (the query has not resolved
 * yet) counts as pending — the honest default while we do not yet know, not
 * an assumption that nothing was requested.
 */
function reportsPending(reports: Report[] | undefined): boolean {
  if (!reports) return true;
  return reports.some((r) => r.status === 'queued' || r.status === 'rendering');
}

/**
 * displayPercent is what the bar actually shows.
 *
 * ⚠ THE SCAN'S OWN WEIGHTED PERCENT HITS 100 THE MOMENT EVERY ENGINE IS
 * TERMINAL — but a report is rendered from that scan AFTER it finishes
 * (services/report/internal/worker/worker.go's loadNormalizedBOM resolves
 * the normalized BOM at RENDER time, not scan time), so "100%" on the scan
 * alone can be seconds ahead of the actual deliverable existing. Capped at
 * 99 until every report this scan has (if any) is also ready or failed —
 * never invented math blending scan and report progress into one number
 * (docs/02-CONTRACTS.md §5's own rule: the server computes weighted
 * progress, not the client), just an honest "not quite yet" while the part
 * this page cannot see into is still working.
 */
function displayPercent(progress: Progress, reports: Report[] | undefined): number {
  if (isTerminal(progress.status) && reportsPending(reports)) {
    return Math.min(progress.percent, 99);
  }
  return progress.percent;
}

/**
 * OverallBar is animated, not just CSS-transitioned on width — `m.div`
 * spring-eases toward each real percentage the server reports (never a
 * client-side guess: see ws.ts's own note on why an event's pct only ever
 * nudges this, and only when it is actually informative), and a subtle
 * shimmer plays while there is still real work outstanding — either the scan
 * itself, or a report rendering from it — purely decorative, gated on
 * `data-live` so a fully finished scan's bar sits still. Motion respects
 * prefers-reduced-motion globally (App.tsx's `<MotionConfig
 * reducedMotion="user">`; the CSS shimmer keyframe is capped the same way
 * every other animation in this app is, in app.css's global `@media
 * (prefers-reduced-motion: reduce)` rule).
 */
function OverallBar({ progress, reports }: { progress: Progress; reports: Report[] | undefined }) {
  const pending = reportsPending(reports);
  const live = !isTerminal(progress.status) || pending;
  const percent = displayPercent(progress, reports);
  return (
    <section className="progress-overall">
      <div className="progress-head">
        <StatusPill status={progress.status} />
        <m.span
          className="progress-percent"
          key={Math.round(percent)}
          initial={{ opacity: 0.4 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.2 }}
        >
          {Math.round(percent)}%
        </m.span>
      </div>
      <div
        className="progress-track"
        role="progressbar"
        aria-valuenow={Math.round(percent)}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Overall scan progress"
      >
        <m.div
          className="progress-fill"
          data-live={live ? 'true' : undefined}
          initial={false}
          animate={{ width: `${percent}%` }}
          transition={{ type: 'spring', stiffness: 120, damping: 20 }}
        />
      </div>
      <p className="progress-note">
        {isTerminal(progress.status) && pending
          ? 'The scan itself is done — this holds just under 100% until every report requested from it has also finished rendering.'
          : 'Weighted by engine, not a simple average — a fast lockfile parser and a slow vulnerability match are not equal halves of a scan.'}
      </p>
    </section>
  );
}

/**
 * ActivityFeed shows the most recent real activity — what an engine just
 * started, or just finished, in the engine's or the server's own words
 * (events.ScanEventV1.Message) — and nothing else.
 *
 * ⚠ ONLY THE LAST THREE. A scrolling transcript of every engine transition
 * competes with the structured table below it, which is the actual source of
 * truth for "what happened." This is a glance, not a log — capped so the
 * newest, most relevant items are what a user's eye lands on, with older ones
 * animating out rather than piling up.
 */
function ActivityFeed({ items }: { items: ActivityItem[] }) {
  if (items.length === 0) return null;

  return (
    <section className="activity-feed" aria-label="Recent scan activity">
      <h2 className="activity-feed-title">Right now</h2>
      <ul className="activity-list">
        <AnimatePresence initial={false}>
          {items.map((item) => (
            <m.li
              key={item.id}
              className="activity-item"
              data-phase={item.phase}
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 8 }}
              transition={{ duration: 0.24, ease: [0.16, 1, 0.3, 1] }}
            >
              <span className="activity-dot" aria-hidden="true" />
              <span className="activity-text">
                {item.engine && <strong>{item.engine}</strong>}
                {item.message ?? item.phase}
              </span>
              {sortedCounts(item.metrics).map(([key, count]) => (
                <span className="activity-count" key={key}>
                  <b>{count}</b> {metricLabel(key, count)}
                </span>
              ))}
              <span className="activity-time">{relativeTime(item.ts)}</span>
            </m.li>
          ))}
        </AnimatePresence>
      </ul>
    </section>
  );
}

/**
 * DiscoveryTally is what the scan has found so far, by kind.
 *
 * ⚠ THIS IS THE ANSWER TO "WHAT IS IT ACTUALLY FINDING", AND THE ENGINE TABLE
 * IS NOT. The table says which engines ran and how they ended; the overall bar
 * says how far along they are. Neither tells somebody watching an AI scan that
 * two vector stores and a RAG pipeline just turned up — and until the
 * orchestrator started filling events.ScanEventV1.Metrics, nothing did.
 *
 * ⚠ COUNTS AND KINDS, NEVER CONTENT. The server holds a metric KEY to the same
 * rule as a message — no path, no URL, nothing out of the scanned code
 * (events.SanitizeDiscoveries). BOM content is confidential under CERT-In §5.3;
 * the names of what was found live in Postgres and are read by the inventory
 * screens, which are authenticated per project. So this renders a number and a
 * kind, and a reader who wants the names follows the report.
 *
 * ⚠ ADVISORY, LIKE EVERY EVENT ON THIS PAGE. `docs/02-CONTRACTS.md` §10: no
 * progress logic may depend on receiving an event, and none here does — this
 * component renders nothing at all until an engine reports, and the normalized
 * document remains the only thing anyone counts from.
 */
function DiscoveryTally({ byEngine }: { byEngine: Record<string, Record<string, number>> }) {
  const rows = sortedCounts(tallyDiscoveries(byEngine));
  if (rows.length === 0) return null;

  return (
    <section className="discovery-tally" aria-label="What this scan has found so far">
      <h2 className="activity-feed-title">Found so far</h2>
      <ul className="discovery-list">
        <AnimatePresence initial={false}>
          {rows.map(([key, count]) => (
            <m.li
              className="discovery-chip"
              key={key}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              transition={{ duration: 0.24, ease: [0.16, 1, 0.3, 1] }}
            >
              <b className="discovery-count">{count}</b>
              <span className="discovery-kind">{metricLabel(key, count)}</span>
            </m.li>
          ))}
        </AnimatePresence>
      </ul>
      <p className="discovery-note">
        As each engine reports. The report is generated from the normalized document, which merges
        what every engine found — these are the raw per-engine claims.
      </p>
    </section>
  );
}

/**
 * deriveActivity turns a snapshot's own engine_runs into up to
 * ACTIVITY_LIMIT activity entries — see the seeding comment in
 * ScanProgressRoute for why this exists. Every field traces to a real,
 * already-recorded value (started_at/finished_at/status/message); nothing
 * here is invented, only re-presented in the feed's shape.
 *
 * ⚠ A "started" ENTRY IS ONLY SYNTHESIZED FOR AN ENGINE THAT HAS NOT ALSO
 * FINISHED. Adding both unconditionally meant an engine that finished
 * minutes (or, live, 36 minutes) ago still showed a `phase: 'running'` item
 * — present-tense wording plus the pulsing "live" dot (ActivityFeed's own
 * CSS) — right next to a bar already sitting at 100%, reading as "this is
 * happening right now" for something that is long over. A genuinely
 * still-in-progress engine (finishedAt not yet set) still gets it, correctly.
 */
function deriveActivity(engines: EngineProgress[]): ActivityItem[] {
  const items: ActivityItem[] = [];
  for (const e of engines) {
    if (e.startedAt && !e.finishedAt) {
      items.push({
        id: `${e.engineId}-started`,
        engine: e.engineId,
        phase: 'running',
        message: `running ${e.engineId}`,
        // ⚠ EMPTY, NOT RECONSTRUCTED. engine_runs records a status and a
        // duration, never a per-kind breakdown, and the breakdown reaches this
        // page only on the live event. Inventing one from the snapshot is the
        // exact fabrication this feed must not do — a scan already finished when
        // the page opens shows no counts here, and its inventory screens
        // (which read the normalized rows) show all of them.
        metrics: {},
        ts: e.startedAt,
      });
    }
    if (e.finishedAt) {
      items.push({
        id: `${e.engineId}-finished`,
        engine: e.engineId,
        phase: e.status === 'failed' || e.status === 'timeout' ? 'failed' : 'done',
        message: e.message ?? `${e.engineId} ${e.status}`,
        metrics: {},
        ts: e.finishedAt,
      });
    }
  }
  items.sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts));
  return items.slice(0, ACTIVITY_LIMIT);
}

/** relativeTime renders a coarse "how long ago", not a live-ticking clock —
 *  a re-render every second for a page whose real updates arrive over a
 *  WebSocket would be motion with no information in it. */
function relativeTime(iso: string): string {
  const ms = Date.now() - Date.parse(iso);
  if (!Number.isFinite(ms) || ms < 0) return 'just now';
  const s = Math.round(ms / 1000);
  if (s < 5) return 'just now';
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.round(m / 60)}h ago`;
}

/**
 * ReportsSection is where the actual deliverable lives — every report
 * `/generate` queued for this scan, with a real download link the moment
 * each one reaches `ready`.
 *
 * ⚠ query IS LIFTED TO ScanProgressRoute, NOT OWNED HERE. OverallBar needs
 * the same data (displayPercent's own doc comment: the bar holds under 100%
 * until reports finish too), and querying it twice would mean the two could
 * observe different moments of the same poll cycle and visibly disagree.
 * useReports polls on its own short interval while any report is still
 * queued/rendering (see its own doc comment) rather than waiting on a WS
 * event that was never guaranteed to arrive for report state in the first
 * place.
 */
function ReportsSection({ query }: { query: ReturnType<typeof useReports> }) {
  const { data, isPending, isError, error } = query;

  if (isPending) return <SkeletonRows rows={2} columns={3} />;
  if (isError) return <ErrorState error={error} action="load this scan's reports" />;

  // Nothing queued yet is not an error — a scan run from Generate always has
  // reports, but a scan triggered another way (the API, a campaign) may not.
  if (data.reports.length === 0) return null;

  return (
    <section className="reports-section" aria-label="Reports from this scan">
      <h2 className="activity-feed-title">Reports</h2>
      <ul className="report-list">
        {data.reports.map((r) => (
          <ReportRow key={r.id} report={r} />
        ))}
      </ul>
    </section>
  );
}

function ReportRow({ report: r }: { report: Report }) {
  const size = formatBytes(r.size_bytes);
  // ⚠ FETCHED AND SAVED THROUGH JS, NEVER A PLAIN <a href>. This report is
  // only reachable with a Bearer token, and that token lives in memory —
  // never a cookie (lib/api.ts's own note on accessToken) — so a bare
  // browser navigation carries no Authorization header at all and the
  // request 401s before a single byte comes back. downloadFile fetches it
  // through the same authenticated client every other call on this page
  // uses; triggerSave is what actually hands the browser the resulting
  // bytes to save, via a same-origin blob: URL.
  const download = useMutation({
    mutationFn: () => downloadFile(`/v1/reports/${r.id}/download`),
    onSuccess: triggerSave,
  });

  return (
    <li className="report-row">
      <BomTypeChip type={r.bom_type} />
      <span className="report-meta">
        {levelLabel(r.level)} · {r.standard} · {r.format.toUpperCase()}
      </span>
      <span className="report-action">
        {r.status === 'ready' ? (
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => download.mutate()}
            disabled={download.isPending}
          >
            {download.isPending ? 'Downloading…' : `Download${size ? ` (${size})` : ''}`}
          </button>
        ) : r.status === 'failed' ? (
          <span className="report-failed">
            <StatusPill status={r.status} />
            {r.error_code && <code>{r.error_code}</code>}
          </span>
        ) : (
          <StatusPill status={r.status} />
        )}
        {download.isError && (
          <span className="report-download-error" role="alert">
            Couldn&apos;t download: {download.error.message}
          </span>
        )}
      </span>
      <Link className="report-detail-link" to={`/reports/${r.id}`}>
        Details
      </Link>
    </li>
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
