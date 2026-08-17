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
 * So: NOTHING here derives progress incrementally. Every frame replaces state
 * for the engine it names, and a snapshot replaces all of it.
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
}

export interface ScanProgress {
  scanId: string;
  status: string;
  /** Weighted across engines by the server, not averaged here. */
  percent: number;
  engines: EngineProgress[];
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

interface ConnectOptions {
  url: string;
  handlers: ProgressHandlers;
  /** Injectable for tests; defaults to the platform WebSocket. */
  factory?: (url: string) => WebSocketLike;
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
    factory = (u) => new WebSocket(u) as unknown as WebSocketLike,
    random = Math.random,
    setTimeoutFn = (fn, ms) => window.setTimeout(fn, ms),
    clearTimeoutFn = (id) => window.clearTimeout(id),
  } = opts;

  let socket: WebSocketLike | null = null;
  let attempt = 0;
  let timer: number | null = null;
  let disposed = false;

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

    const ws = factory(url);
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
      const progress = parseFrame(ev.data);
      if (progress) handlers.onProgress(progress);
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

/**
 * parseFrame reads a snapshot or an event frame.
 *
 * ⚠ BOTH SHAPES PRODUCE A COMPLETE ScanProgress. The snapshot is not a special
 * case handled elsewhere — it is the same type, which is what stops a
 * reconnect path from diverging from the steady-state one and only failing in
 * production.
 *
 * An unparseable frame is DROPPED, not fatal. The next snapshot corrects
 * everything, and tearing down a working socket over one malformed message
 * would turn a server-side hiccup into a visibly broken page.
 */
export function parseFrame(raw: string): ScanProgress | null {
  let frame: unknown;
  try {
    frame = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof frame !== 'object' || frame === null) return null;

  const f = frame as Record<string, unknown>;
  const scanId = typeof f.scan_id === 'string' ? f.scan_id : null;
  if (!scanId) return null;

  const engines = Array.isArray(f.engines)
    ? (f.engines as Record<string, unknown>[])
        .map(readEngine)
        .filter((e): e is EngineProgress => e !== null)
    : [];

  return {
    scanId,
    status: typeof f.status === 'string' ? f.status : 'running',
    percent: clampPercent(f.percent),
    engines,
  };
}

function readEngine(raw: Record<string, unknown>): EngineProgress | null {
  const engineId = typeof raw.engine_id === 'string' ? raw.engine_id : null;
  if (!engineId) return null;
  return {
    engineId,
    status: typeof raw.status === 'string' ? raw.status : 'queued',
    percent: clampPercent(raw.percent),
    durationMs: typeof raw.duration_ms === 'number' ? raw.duration_ms : null,
    ecosystems: Array.isArray(raw.ecosystems) ? (raw.ecosystems as string[]) : [],
    message: typeof raw.message === 'string' ? raw.message : null,
  };
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
