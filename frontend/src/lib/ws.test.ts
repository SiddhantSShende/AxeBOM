import { describe, expect, it, vi } from 'vitest';
import {
  type ActivityItem,
  type ConnectionState,
  type ScanProgress,
  WS_BEARER_PREFIX,
  WS_SUBPROTOCOL,
  type WebSocketLike,
  backoffMs,
  bearerProtocols,
  connectProgress,
  parseFrame,
} from './ws';

/** A socket a test can drive. */
class FakeSocket implements WebSocketLike {
  onopen: ((ev: unknown) => void) | null = null;
  onclose: ((ev: unknown) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  closed = false;

  /**
   * ⚠ A REAL WebSocket FIRES onclose AFTER close(), AND THIS FAKE MUST TOO.
   *
   * It did not, at first. Both disposal guards could then be deleted and every
   * test still passed — the fake never exercised the path, so the test was
   * vacuous in exactly the way that looks green. Modelling the callback is
   * what makes the mutation fail.
   */
  close() {
    this.closed = true;
    this.onclose?.({});
  }

  open() {
    this.onopen?.({});
  }
  send(data: string) {
    this.onmessage?.({ data });
  }
  drop() {
    this.onclose?.({});
  }
}

interface Harness {
  sockets: FakeSocket[];
  states: ConnectionState[];
  frames: ScanProgress[];
  activity: ActivityItem[];
  /** Runs the pending reconnect timer. */
  runTimer: () => void;
  dispose: () => void;
}

function harness(): Harness {
  const sockets: FakeSocket[] = [];
  const states: ConnectionState[] = [];
  const frames: ScanProgress[] = [];
  const activity: ActivityItem[] = [];
  let pending: (() => void) | null = null;

  const dispose = connectProgress({
    url: 'wss://example/scan',
    handlers: {
      onProgress: (p) => frames.push(p),
      onActivity: (a) => activity.push(a),
      onConnection: (s) => states.push(s),
    },
    factory: () => {
      const s = new FakeSocket();
      sockets.push(s);
      return s;
    },
    random: () => 0.5, // no jitter, so waits are predictable
    setTimeoutFn: (fn) => {
      pending = fn;
      return 1;
    },
    clearTimeoutFn: () => {
      pending = null;
    },
  });

  return {
    sockets,
    states,
    frames,
    activity,
    runTimer: () => {
      const fn = pending;
      pending = null;
      fn?.();
    },
    dispose,
  };
}

// The real wire shape — handler.go's wsMessage{type, snapshot: scanDTO} —
// not a flattened guess. scanDTO nests engine_runs (engineRunDTO), which
// names its engine field "engine", not "engine_id".
const snapshot = JSON.stringify({
  type: 'snapshot',
  snapshot: {
    id: 's1',
    status: 'running',
    progress_pct: 40,
    engine_runs: [
      { engine: 'syft', status: 'succeeded', ecosystems_covered: ['npm'] },
      { engine: 'grype', status: 'running', ecosystems_covered: [] },
    ],
  },
});

function eventFrame(over: Record<string, unknown> = {}): string {
  return JSON.stringify({
    type: 'event',
    event: {
      scan_id: 's1',
      job_id: 'j1',
      engine: 'grype',
      seq: 1,
      ts: '2026-08-30T19:00:00Z',
      phase: 'running',
      pct: 0,
      message: 'running grype',
      ...over,
    },
  });
}

describe('the snapshot is what makes reconnection correct', () => {
  // ⚠ THE TEST THE DESIGN EXISTS FOR. A client that accumulated state from
  // events would show a frozen or confidently-wrong percentage after a drop.
  // Here the reconnect takes a fresh snapshot and is immediately right.
  it('replaces state wholesale after a drop', () => {
    const h = harness();
    h.sockets[0]!.open();
    h.sockets[0]!.send(snapshot);

    expect(h.frames.at(-1)?.percent).toBe(40);
    expect(h.frames.at(-1)?.engines).toHaveLength(2);

    // The socket drops mid-scan and the scan progresses while we are away.
    h.sockets[0]!.drop();
    h.runTimer();
    h.sockets[1]!.open();
    h.sockets[1]!.send(
      JSON.stringify({
        type: 'snapshot',
        snapshot: {
          id: 's1',
          status: 'completed_with_errors',
          progress_pct: 100,
          engine_runs: [
            { engine: 'syft', status: 'succeeded', ecosystems_covered: ['npm'] },
            { engine: 'grype', status: 'partial', ecosystems_covered: ['npm'] },
            { engine: 'trivy-fs', status: 'unavailable', ecosystems_covered: [] },
          ],
        },
      }),
    );

    const latest = h.frames.at(-1)!;
    expect(latest.percent).toBe(100);
    expect(latest.status).toBe('completed_with_errors');
    // The engine that appeared while we were disconnected is present, and the
    // one that went partial reads partial — neither would be true if state
    // were accumulated from frames.
    expect(latest.engines.map((e) => e.engineId)).toEqual(['syft', 'grype', 'trivy-fs']);
    expect(latest.engines[1]!.status).toBe('partial');

    h.dispose();
  });

  it('reports reconnecting rather than freezing', () => {
    const h = harness();
    h.sockets[0]!.open();
    h.sockets[0]!.drop();

    const last = h.states.at(-1)!;
    // ⚠ NOT 'error'. A reconnecting client is working, and saying so keeps a
    // user from reloading the page mid-scan.
    expect(last.kind).toBe('reconnecting');
    if (last.kind === 'reconnecting') {
      expect(last.attempt).toBe(1);
      expect(last.nextRetryMs).toBeGreaterThan(0);
    }

    h.dispose();
  });

  it('resets the backoff only on a successful open', () => {
    const h = harness();
    h.sockets[0]!.open();
    h.sockets[0]!.drop();
    h.runTimer();
    h.sockets[1]!.drop(); // never opened

    const afterTwo = h.states.at(-1)!;
    expect(afterTwo.kind === 'reconnecting' && afterTwo.attempt).toBe(2);

    h.runTimer();
    h.sockets[2]!.open();
    h.sockets[2]!.drop();

    const afterOpen = h.states.at(-1)!;
    // A flapping connection must not restart the backoff on every reconnect
    // and hammer a struggling server.
    expect(afterOpen.kind === 'reconnecting' && afterOpen.attempt).toBe(1);

    h.dispose();
  });
});

describe('disposal', () => {
  // A component unmounting mid-scan must not leave a socket retrying forever.
  it('stops reconnecting and detaches handlers before closing', () => {
    const h = harness();
    h.sockets[0]!.open();
    const before = h.states.length;

    h.dispose();

    expect(h.sockets[0]!.closed).toBe(true);
    // close() would otherwise fire onclose and schedule a reconnect for a
    // component that is already gone.
    expect(h.states.length).toBe(before);
    h.runTimer();
    expect(h.sockets).toHaveLength(1);
  });
});

describe('backoff', () => {
  it('grows and is capped', () => {
    const noJitter = () => 0.5;
    expect(backoffMs(1, noJitter)).toBe(1000);
    expect(backoffMs(2, noJitter)).toBe(2000);
    // Uncapped growth means a client that missed a blip waits minutes to
    // notice the server came back.
    expect(backoffMs(20, noJitter)).toBe(30_000);
  });

  it('jitters, so a fleet does not reconnect in lockstep', () => {
    const low = backoffMs(4, () => 0);
    const high = backoffMs(4, () => 1);
    expect(low).toBeLessThan(high);
    // No jitter means every client reconnects in the same millisecond after an
    // outage, which knocks a recovering server over a second time.
    expect(high - low).toBeGreaterThan(1000);
  });

  it('never waits less than a quarter second', () => {
    expect(backoffMs(0, () => 0)).toBeGreaterThanOrEqual(250);
  });
});

describe('frame parsing', () => {
  // ⚠ THE REGRESSION THIS GUARDS. parseFrame previously read flat top-level
  // fields (scan_id, percent, engines[].engine_id) that handler.go's
  // wsMessage has never actually sent — the real shape nests everything
  // under "snapshot" (a scanDTO, keyed "id"/"progress_pct"/"engine_runs") or
  // "event" (an events.ScanEventV1). Every real frame the server ever sent
  // was silently dropped by the old parser; onProgress never fired once in
  // production. This fixture matches the real Go structs, not a convenient
  // guess.
  it('reads a real snapshot frame', () => {
    const parsed = parseFrame(snapshot);
    expect(parsed?.kind).toBe('snapshot');
    if (parsed?.kind !== 'snapshot') throw new Error('expected a snapshot');
    expect(parsed.progress.scanId).toBe('s1');
    expect(parsed.progress.engines[0]!.engineId).toBe('syft');
  });

  it('reads a real event frame', () => {
    const parsed = parseFrame(eventFrame({ message: 'running grype', pct: 42 }));
    expect(parsed?.kind).toBe('event');
    if (parsed?.kind !== 'event') throw new Error('expected an event');
    expect(parsed.activity.engine).toBe('grype');
    expect(parsed.activity.phase).toBe('running');
    expect(parsed.activity.message).toBe('running grype');
    expect(parsed.pct).toBe(42);
  });

  it('drops an unparseable or unrecognized frame instead of tearing down the socket', () => {
    expect(parseFrame('not json')).toBeNull();
    expect(parseFrame('{}')).toBeNull();
    expect(parseFrame('[]')).toBeNull();
    expect(parseFrame(JSON.stringify({ status: 'running' }))).toBeNull();
    expect(parseFrame(JSON.stringify({ type: 'snapshot' }))).toBeNull();
    expect(parseFrame(JSON.stringify({ type: 'unknown', snapshot: {} }))).toBeNull();
  });

  it('survives a malformed frame without losing the socket', () => {
    const h = harness();
    h.sockets[0]!.open();
    h.sockets[0]!.send('}{');
    h.sockets[0]!.send(snapshot);

    // One good frame after one bad one: the bad frame must not have closed
    // anything, or a server hiccup becomes a visibly broken page.
    expect(h.frames).toHaveLength(1);
    expect(h.sockets).toHaveLength(1);
    h.dispose();
  });

  it('clamps a nonsense percentage', () => {
    const parsed = parseFrame(
      JSON.stringify({ type: 'snapshot', snapshot: { id: 's1', progress_pct: 140 } }),
    );
    if (parsed?.kind !== 'snapshot') throw new Error('expected a snapshot');
    // A 140% bar renders past its own track, which reads as a broken page
    // rather than a broken number.
    expect(parsed.progress.percent).toBe(100);

    const nan = parseFrame(
      JSON.stringify({ type: 'snapshot', snapshot: { id: 's1', progress_pct: 'x' } }),
    );
    if (nan?.kind !== 'snapshot') throw new Error('expected a snapshot');
    expect(nan.progress.percent).toBe(0);
  });

  it('drops an engine_runs entry with no engine name rather than rendering a blank row', () => {
    const parsed = parseFrame(
      JSON.stringify({
        type: 'snapshot',
        snapshot: {
          id: 's1',
          engine_runs: [{ status: 'running' }, { engine: 'syft', status: 'running' }],
        },
      }),
    );
    if (parsed?.kind !== 'snapshot') throw new Error('expected a snapshot');
    expect(parsed.progress.engines).toHaveLength(1);
  });
});

describe('live events', () => {
  it('delivers each event to onActivity, not onProgress', () => {
    const h = harness();
    h.sockets[0]!.open();
    h.sockets[0]!.send(snapshot);
    h.sockets[0]!.send(eventFrame());

    expect(h.activity).toHaveLength(1);
    expect(h.activity[0]!.engine).toBe('grype');
    // The snapshot's own progress frame is the only one so far — an event's
    // Message is advisory text, not a structured state replace.
    expect(h.frames).toHaveLength(1);
    h.dispose();
  });

  it("nudges the bar from a real event pct, but never regresses it to a webrecon sub-event's unset zero", () => {
    const h = harness();
    h.sockets[0]!.open();
    h.sockets[0]!.send(snapshot);
    expect(h.frames.at(-1)?.percent).toBe(40);

    h.sockets[0]!.send(eventFrame({ pct: 75 }));
    expect(h.frames.at(-1)?.percent).toBe(75);

    // services/webrecon's per-host events leave pct at 0 deliberately
    // (events.PublishScanEvent's own doc comment) — that must not read as
    // "the scan just regressed to 0%".
    h.sockets[0]!.send(eventFrame({ pct: 0, message: 'fingerprinting host 2 of 3' }));
    expect(h.frames.at(-1)?.percent).toBe(75);
    expect(h.activity.at(-1)?.message).toBe('fingerprinting host 2 of 3');

    h.dispose();
  });
});

describe('the platform default', () => {
  it('is only used when no factory is supplied', () => {
    // Guards against the factory becoming required by accident, which would
    // make the production path untested.
    const spy = vi.fn();
    const dispose = connectProgress({
      url: 'wss://example/scan',
      handlers: { onProgress: () => {}, onActivity: () => {}, onConnection: spy },
      factory: () => new FakeSocket(),
      setTimeoutFn: () => 1,
      clearTimeoutFn: () => {},
    });
    expect(spy).toHaveBeenCalledWith({ kind: 'connecting' });
    dispose();
  });
});

describe('the handshake credential', () => {
  it('offers the plain subprotocol and the bearer one', () => {
    expect(bearerProtocols('abc.def.ghi')).toEqual([
      WS_SUBPROTOCOL,
      `${WS_BEARER_PREFIX}abc.def.ghi`,
    ]);
  });

  it('still offers a subprotocol when there is no token', () => {
    // RFC 6455: a server that selects none of the offered protocols makes the
    // browser fail the connection. Offering nothing at all would turn a 401
    // into an unexplained close, so the plain protocol is always present and
    // the server refuses the request on its own terms.
    expect(bearerProtocols(null)).toEqual([WS_SUBPROTOCOL]);
    expect(bearerProtocols(undefined)).toEqual([WS_SUBPROTOCOL]);
  });

  it('is read again on every reconnect, not captured once', () => {
    // A socket that reconnects after a long backoff must present the token the
    // session holds NOW. Capturing it at connect time is how a laptop woken
    // from sleep reconnects forever with a credential that expired at lunch.
    const offered: (string[] | undefined)[] = [];
    const sockets: FakeSocket[] = [];
    let token = 'first';
    const timers: (() => void)[] = [];

    const dispose = connectProgress({
      url: 'wss://example/scan',
      handlers: { onProgress: () => {}, onActivity: () => {}, onConnection: () => {} },
      protocols: () => bearerProtocols(token),
      factory: (_url, p) => {
        offered.push(p);
        const s = new FakeSocket();
        sockets.push(s);
        return s;
      },
      random: () => 0.5,
      setTimeoutFn: (fn) => timers.push(fn),
      clearTimeoutFn: () => timers.splice(0),
    });

    token = 'renewed';
    sockets[0]!.onclose?.({});
    timers.shift()?.();

    expect(offered[0]).toEqual([WS_SUBPROTOCOL, `${WS_BEARER_PREFIX}first`]);
    expect(offered[1]).toEqual([WS_SUBPROTOCOL, `${WS_BEARER_PREFIX}renewed`]);
    dispose();
  });
});

describe('discovery counts on a live event', () => {
  it('carries what the engine reported', () => {
    const frame = parseFrame(
      JSON.stringify({
        type: 'event',
        event: {
          phase: 'engine_done',
          engine: 'airom',
          ts: '2026-01-01T00:00:00Z',
          metrics: { ai_models: 3, 'ai_asset.vector_store': 1 },
        },
      }),
    );
    expect(frame?.kind).toBe('event');
    if (frame?.kind !== 'event') return;
    expect(frame.activity.metrics).toEqual({ ai_models: 3, 'ai_asset.vector_store': 1 });
  });

  it('is an empty object, never undefined, when the event carries none', () => {
    // Every phase transition reaches this path. A renderer reading
    // `Object.keys(item.metrics)` must not have to null-check per call site —
    // one missed check is a blank progress page for a running scan.
    const frame = parseFrame(
      JSON.stringify({ type: 'event', event: { phase: 'queued', ts: '2026-01-01T00:00:00Z' } }),
    );
    if (frame?.kind !== 'event') throw new Error('expected an event frame');
    expect(frame.activity.metrics).toEqual({});
  });

  it('drops a value that is not a usable count', () => {
    // ⚠ DROPPED, NOT COERCED. `-1 → 0` would say the engine looked for prompts
    // and found none; a NaN rendered into a chip reads as a broken page. A
    // replayed frame from an older build reaches this function too.
    const frame = parseFrame(
      JSON.stringify({
        type: 'event',
        event: {
          phase: 'engine_done',
          ts: '2026-01-01T00:00:00Z',
          metrics: { good: 2, negative: -1, text: '4', nothing: null },
        },
      }),
    );
    if (frame?.kind !== 'event') throw new Error('expected an event frame');
    expect(frame.activity.metrics).toEqual({ good: 2 });
  });

  it('survives metrics arriving as something other than an object', () => {
    for (const metrics of [null, 'ai_models=3', ['ai_models', 3], 7]) {
      const frame = parseFrame(
        JSON.stringify({
          type: 'event',
          event: { phase: 'engine_done', ts: '2026-01-01T00:00:00Z', metrics },
        }),
      );
      if (frame?.kind !== 'event') throw new Error('expected an event frame');
      expect(frame.activity.metrics).toEqual({});
    }
  });
});
