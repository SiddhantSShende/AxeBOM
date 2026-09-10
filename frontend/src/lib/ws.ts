/**
 * The scan-progress WebSocket.
 *
 * ⚠ THE SNAPSHOT ON CONNECT IS WHY THIS CAN BE SIMPLE.
 *
 * The stream is ADVISORY and lossy-tolerant; the database is the source of
 * truth. A dropped socket, a missed frame, a backgrounded tab — reconnect, take
 * the snapshot, and be correct.
 *
 * The failure this design avoids is the tempting one: accumulating state from
 * events alone. That works in every test and breaks in exactly the situation a
 * user notices — a laptop lid closed for ten minutes — where the client either
 * shows a frozen percentage or, worse, a confident wrong one built from a
 * partial event stream.
 *
 * So: the structured state (percent, per-engine status/ecosystems/duration) is
 * ALWAYS a full replace from a snapshot, never accumulated from events — a
 * snapshot replaces all of it. Events are advisory in the other sense too:
 * they are human-readable ("what is running right now"), sourced from
 * services/scan-orchestrator's Orchestrator.PublishEvent and
 * services/webrecon's own per-host publishes
 * (libs/go-shared/events.PublishScanEvent, the shared construction path both
 * use) — and are surfaced separately, as an activity feed, not folded into the
 * structured engine table events.ScanEventV1.Message was never meant to be
 * machine-parsed into.
 *
 * docs/07-FRONTEND-SPEC.md §5, docs/02-CONTRACTS.md §10.
 */

export interface EngineProgress {
  engineId: string;
  status: string;
  percent: number;
  durationMs: number | null;
  ecosystems: string[];
  message: string | null;
  /** ISO timestamps, when the server has them — used to seed the activity
   *  feed with real history on connect, not to drive anything derived. */
  startedAt: string | null;
  finishedAt: string | null;
}

export interface ScanProgress {
  scanId: string;
  status: string;
  /** Weighted across engines by the server, not averaged here. */
  percent: number;
  engines: EngineProgress[];
}

/**
 * ActivityItem is one real, human-readable "what is happening" message —
 * either a live scan.event.* frame, or (see ScanProgress.tsx) derived from a
 * snapshot's own engine_runs history. Never fabricated: every field traces to
 * a real value the server actually sent.
 */
export interface ActivityItem {
  /** Stable across renders for AnimatePresence's exit animation. */
  id: string;
  engine: string | null;
  phase: string;
  message: string | null;
  /**
   * What this engine found, keyed by kind — `{ai_models: 3, 'ai_asset.prompt': 2}`.
   *
   * ⚠ COUNTS AND KINDS ONLY, AND THE SERVER GUARANTEES IT. BOM content is
   * confidential (CERT-In §5.3) and an advisory event stream is the wrong place
   * for it, so the keys go through the same gate as `message` server-side
   * (`events.SanitizeDiscoveries`) — no path, no URL, nothing out of the scanned
   * code. Renderers here must treat a key as an opaque label and never
   * reconstruct a filename from one.
   *
   * Empty for an engine that reported nothing finer than the four summary
   * dimensions, and for every event that is not an engine result.
   */
  metrics: Record<string, number>;
  /** ISO timestamp. */
  ts: string;
}

export type ConnectionState =
  | { kind: 'connecting' }
  /** live carries the last frame's arrival, so a stale stream is visible. */
  | { kind: 'live' }
  /** ⚠ NOT 'error'. A reconnecting client is working, and saying so keeps a
   *  user from reloading the page mid-scan. `attempt` drives the message. */
  | { kind: 'reconnecting'; attempt: number; nextRetryMs: number }
  | { kind: 'closed'; reason: string };

export interface ProgressHandlers {
  onProgress: (progress: ScanProgress) => void;
  /** Fires once per live scan.event.* frame. Never called for a snapshot —
   *  seeding a feed from snapshot history, if wanted, is the caller's own
   *  derivation (ScanProgress.tsx), not this module's. */
  onActivity: (activity: ActivityItem) => void;
  onConnection: (state: ConnectionState) => void;
}

/**
 * backoffMs is the reconnect schedule.
 *
 * ⚠ CAPPED, AND JITTERED. Uncapped exponential backoff means a client that
 * missed a blip waits four minutes to notice the server came back. No jitter
 * means every client in a fleet reconnects in the same millisecond after an
 * outage, which is how a recovering server gets knocked over a second time.
 */
export function backoffMs(attempt: number, random: () => number = Math.random): number {
  const base = Math.min(30_000, 500 * 2 ** Math.min(attempt, 6));
  // ±20%, so a thundering herd spreads out.
  const jitter = base * 0.2 * (random() * 2 - 1);
  return Math.max(250, Math.round(base + jitter));
}

/**
 * WS_SUBPROTOCOL and WS_BEARER_PREFIX carry authentication onto a handshake.
 *
 * ⚠ A BROWSER CANNOT PUT AN Authorization HEADER ON A WebSocket.
 *
 * `new WebSocket(url, protocols)` is the only place the platform lets a caller
 * add anything of their own, and what it adds lands in the
 * Sec-WebSocket-Protocol REQUEST HEADER — which is why this is not a way around
 * the rule that a token must never travel in a URL. URLs are written to access
 * logs, sent in Referer and kept in history; headers are not. The Kubernetes API
 * server solves the same problem the same way.
 *
 * ⚠ THESE TWO STRINGS ARE A CONTRACT WITH THE SERVER. They must stay identical
 * to oidcauth.WSSubprotocol and oidcauth.WSBearerPrefix in
 * libs/go-shared/oidcauth/middleware.go. RFC 6455 says a server that selects
 * none of the offered protocols makes a conforming browser FAIL the connection,
 * so a mismatch here is not a 401 — it is a socket that closes with no
 * explanation and a progress view that reconnects forever.
 */
export const WS_SUBPROTOCOL = 'axebom.v1';
export const WS_BEARER_PREFIX = 'axebom.bearer.';

/**
 * bearerProtocols is what the client offers on the handshake.
 *
 * The plain subprotocol is always offered so the server has something to
 * select; the credential is appended only when there is one, because an
 * unauthenticated socket should be refused by the server rather than fail to
 * negotiate.
 */
export function bearerProtocols(token: string | null | undefined): string[] {
  return token ? [WS_SUBPROTOCOL, WS_BEARER_PREFIX + token] : [WS_SUBPROTOCOL];
}

interface ConnectOptions {
  url: string;
  handlers: ProgressHandlers;
  /**
   * The subprotocols to offer, evaluated ON EVERY ATTEMPT.
   *
   * ⚠ A FUNCTION, NOT AN ARRAY, BECAUSE OF RECONNECTS. Access tokens live
   * fifteen minutes and the backoff runs up to thirty seconds between tries;
   * a laptop lid closed over lunch reopens to a socket whose captured token
   * expired long ago. Reading it at connect time means the reconnect presents
   * whatever the session currently holds.
   */
  protocols?: () => string[];
  /** Injectable for tests; defaults to the platform WebSocket. */
  factory?: (url: string, protocols?: string[]) => WebSocketLike;
  random?: () => number;
  setTimeoutFn?: (fn: () => void, ms: number) => number;
  clearTimeoutFn?: (id: number) => void;
}

/** WebSocketLike is the surface this module uses, so a fake is small. */
export interface WebSocketLike {
  close(): void;
  onopen: ((ev: unknown) => void) | null;
  onclose: ((ev: unknown) => void) | null;
  onerror: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: string }) => void) | null;
}

/**
 * connectProgress opens the socket and keeps it open.
 *
 * Returns a disposer. Calling it stops reconnecting — a component unmounting
 * mid-scan must not leave a socket retrying forever behind it.
 */
export function connectProgress(opts: ConnectOptions): () => void {
  const {
    url,
    handlers,
    protocols,
    factory = (u, p) => new WebSocket(u, p) as unknown as WebSocketLike,
    random = Math.random,
    setTimeoutFn = (fn, ms) => window.setTimeout(fn, ms),
    clearTimeoutFn = (id) => window.clearTimeout(id),
  } = opts;

  let socket: WebSocketLike | null = null;
  let attempt = 0;
  let timer: number | null = null;
  let disposed = false;
  // The last known structured state, so a live event's real pct (a genuine
  // server-computed number, unlike its Message) can nudge the bar between
  // snapshots without ever inventing the rest of the shape.
  let current: ScanProgress | null = null;

  const open = () => {
    if (disposed) return;

    handlers.onConnection(
      attempt === 0
        ? { kind: 'connecting' }
        : {
            kind: 'reconnecting',
            attempt,
            nextRetryMs: 0,
          },
    );

    const ws = factory(url, protocols?.());
    socket = ws;

    ws.onopen = () => {
      if (disposed) return;
      // ⚠ THE COUNTER RESETS ONLY ON A SUCCESSFUL OPEN. Resetting it when a
      // frame arrives would let a flapping connection restart the backoff on
      // every reconnect and hammer a struggling server.
      attempt = 0;
      handlers.onConnection({ kind: 'live' });
    };

    ws.onmessage = (ev) => {
      if (disposed) return;
      const frame = parseFrame(ev.data);
      if (!frame) return;

      if (frame.kind === 'snapshot') {
        current = frame.progress;
        handlers.onProgress(current);
        return;
      }

      // event: only a real, structured field (pct) ever touches `current`.
      // A 0 is indistinguishable on the wire from "not computed for this
      // event" (services/webrecon's own per-host events leave it at zero
      // deliberately), so it nudges the bar only when it is actually
      // informative.
      if (current && frame.pct > 0 && frame.pct !== current.percent) {
        current = { ...current, percent: frame.pct };
        handlers.onProgress(current);
      }
      handlers.onActivity(frame.activity);
    };

    ws.onerror = () => {
      // Deliberately silent: onerror is always followed by onclose, and
      // reporting both would show a user two failures for one event.
    };

    ws.onclose = () => {
      if (disposed) return;
      socket = null;
      attempt += 1;
      const wait = backoffMs(attempt, random);
      handlers.onConnection({ kind: 'reconnecting', attempt, nextRetryMs: wait });
      timer = setTimeoutFn(open, wait);
    };
  };

  open();

  return () => {
    // ⚠ TWO INDEPENDENT GUARDS, AND EITHER ONE ALONE IS SUFFICIENT.
    //
    // `close()` fires `onclose`, which would schedule a reconnect for a
    // component that is already gone. The `disposed` flag stops that, and
    // detaching the handlers stops it as well — verified by mutation: removing
    // either alone still passes, removing both fails.
    //
    // Kept deliberately, because they fail differently. The flag covers a
    // socket that closes on its own between the flag being set and the
    // handlers being cleared; detaching covers a socket implementation that
    // dispatches synchronously from inside close(). Neither is hypothetical
    // enough to drop.
    disposed = true;
    if (timer !== null) clearTimeoutFn(timer);
    if (socket) {
      socket.onopen = null;
      socket.onclose = null;
      socket.onerror = null;
      socket.onmessage = null;
      socket.close();
    }
  };
}

type ParsedFrame =
  | { kind: 'snapshot'; progress: ScanProgress }
  | { kind: 'event'; activity: ActivityItem; pct: number };

/**
 * parseFrame reads one wsMessage — {"type":"snapshot","snapshot":{...}} or
 * {"type":"event","event":{...}} — matching handler.go's wsMessage exactly
 * (services/scan-orchestrator/internal/handler/handler.go). The two carry
 * genuinely different shapes (a full scanDTO vs. one events.ScanEventV1), so
 * they are read by two different functions rather than one that pretends
 * they are the same — see readSnapshot/readEvent.
 *
 * An unparseable or unrecognized frame is DROPPED, not fatal. The next
 * snapshot corrects everything, and tearing down a working socket over one
 * malformed message would turn a server-side hiccup into a visibly broken
 * page.
 */
export function parseFrame(raw: string): ParsedFrame | null {
  let frame: unknown;
  try {
    frame = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof frame !== 'object' || frame === null) return null;
  const f = frame as Record<string, unknown>;

  if (f.type === 'snapshot') {
    const progress = isRecord(f.snapshot) ? readSnapshot(f.snapshot) : null;
    return progress ? { kind: 'snapshot', progress } : null;
  }
  if (f.type === 'event') {
    const parsed = isRecord(f.event) ? readEvent(f.event) : null;
    return parsed;
  }
  return null;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null;
}

/** readSnapshot maps handler.go's scanDTO. */
function readSnapshot(s: Record<string, unknown>): ScanProgress | null {
  const scanId = typeof s.id === 'string' ? s.id : null;
  if (!scanId) return null;

  const runs = Array.isArray(s.engine_runs) ? (s.engine_runs as Record<string, unknown>[]) : [];
  const engines = runs.map(readEngineRun).filter((e): e is EngineProgress => e !== null);

  return {
    scanId,
    status: typeof s.status === 'string' ? s.status : 'running',
    percent: clampPercent(s.progress_pct),
    engines,
  };
}

/** readEngineRun maps handler.go's engineRunDTO. */
function readEngineRun(raw: Record<string, unknown>): EngineProgress | null {
  const engineId = typeof raw.engine === 'string' ? raw.engine : null;
  if (!engineId) return null;

  const startedAt = typeof raw.started_at === 'string' ? raw.started_at : null;
  const finishedAt = typeof raw.finished_at === 'string' ? raw.finished_at : null;

  const diagnostics = Array.isArray(raw.diagnostics)
    ? (raw.diagnostics as Record<string, unknown>[])
    : [];
  const message =
    (typeof raw.error_message === 'string' && raw.error_message) ||
    (typeof diagnostics[0]?.message === 'string' ? diagnostics[0].message : null) ||
    null;

  return {
    engineId,
    status: typeof raw.status === 'string' ? raw.status : 'queued',
    // engineRunDTO carries no per-engine percentage — 100 once terminal, 0
    // while still running is the honest two-state answer this table already
    // conveys through `status` itself; see EngineTable, which reads status,
    // not this field, for the actual per-row picture.
    percent: raw.status && raw.status !== 'queued' && raw.status !== 'running' ? 100 : 0,
    durationMs: durationMs(startedAt, finishedAt),
    ecosystems: Array.isArray(raw.ecosystems_covered) ? (raw.ecosystems_covered as string[]) : [],
    message,
    startedAt,
    finishedAt,
  };
}

function durationMs(startedAt: string | null, finishedAt: string | null): number | null {
  if (!startedAt || !finishedAt) return null;
  const start = Date.parse(startedAt);
  const end = Date.parse(finishedAt);
  if (Number.isNaN(start) || Number.isNaN(end)) return null;
  return Math.max(0, end - start);
}

/** readEvent maps events.ScanEventV1 (libs/go-shared/events/events.go). */
function readEvent(raw: Record<string, unknown>): ParsedFrame | null {
  const phase = typeof raw.phase === 'string' ? raw.phase : null;
  if (!phase) return null;

  const id =
    (typeof raw.event_id === 'string' && raw.event_id) ||
    `${String(raw.ts)}-${String(raw.engine)}-${String(raw.seq)}`;

  return {
    kind: 'event',
    pct: clampPercent(raw.pct),
    activity: {
      id,
      engine: typeof raw.engine === 'string' ? raw.engine : null,
      phase,
      message: typeof raw.message === 'string' ? raw.message : null,
      metrics: readMetrics(raw.metrics),
      ts: typeof raw.ts === 'string' ? raw.ts : new Date().toISOString(),
    },
  };
}

/**
 * readMetrics reads events.ScanEventV1.Metrics.
 *
 * ⚠ THE SERVER ALREADY SANITISED THE KEYS AND THIS STILL CHECKS THE VALUES.
 * Not distrust of the orchestrator — a saved frame replayed from an older build,
 * or any future publisher, reaches this function too, and a NaN rendered into a
 * count reads as a broken page rather than a missing number. A non-integer or
 * negative value is dropped rather than coerced: `-1 → 0` would claim the engine
 * looked and found none.
 */
function readMetrics(raw: unknown): Record<string, number> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const out: Record<string, number> = {};
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) continue;
    out[key] = Math.floor(value);
  }
  return out;
}

/**
 * clampPercent bounds a server-supplied percentage.
 *
 * A NaN or a 103 renders as a progress bar past its own track, which reads as a
 * broken page rather than a broken number. Clamping is not hiding a bug: the
 * value is advisory, and the engine rows carry the real status.
 */
function clampPercent(value: unknown): number {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.min(100, Math.max(0, n));
}
