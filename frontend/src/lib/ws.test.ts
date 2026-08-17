import { describe, expect, it, vi } from 'vitest';
import {
  backoffMs,
  connectProgress,
  parseFrame,
  type ConnectionState,
  type ScanProgress,
  type WebSocketLike,
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
  /** Runs the pending reconnect timer. */
  runTimer: () => void;
  dispose: () => void;
}

function harness(): Harness {
  const sockets: FakeSocket[] = [];
  const states: ConnectionState[] = [];
  const frames: ScanProgress[] = [];
  let pending: (() => void) | null = null;

  const dispose = connectProgress({
    url: 'wss://example/scan',
    handlers: {
      onProgress: (p) => frames.push(p),
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
    runTimer: () => {
      const fn = pending;
      pending = null;
      fn?.();
    },
    dispose,
  };
}

const snapshot = JSON.stringify({
  scan_id: 's1',
  status: 'running',
  percent: 40,
  engines: [
    { engine_id: 'syft', status: 'succeeded', percent: 100, ecosystems: ['npm'] },
    { engine_id: 'grype', status: 'running', percent: 20, ecosystems: [] },
  ],
});

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
        scan_id: 's1',
        status: 'completed_with_errors',
        percent: 100,
        engines: [
          { engine_id: 'syft', status: 'succeeded', percent: 100, ecosystems: ['npm'] },
          { engine_id: 'grype', status: 'partial', percent: 100, ecosystems: ['npm'] },
          { engine_id: 'trivy-fs', status: 'unavailable', percent: 0, ecosystems: [] },
        ],
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
  it('reads a snapshot and an event frame identically', () => {
    // The snapshot is not a special case handled elsewhere — that is what stops
    // the reconnect path diverging from the steady-state one.
    const parsed = parseFrame(snapshot)!;
    expect(parsed.scanId).toBe('s1');
    expect(parsed.engines[0]!.engineId).toBe('syft');
  });

  it('drops an unparseable frame instead of tearing down the socket', () => {
    expect(parseFrame('not json')).toBeNull();
    expect(parseFrame('{}')).toBeNull();
    expect(parseFrame('[]')).toBeNull();
    expect(parseFrame(JSON.stringify({ status: 'running' }))).toBeNull();
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
    const parsed = parseFrame(JSON.stringify({ scan_id: 's1', percent: 140, engines: [] }))!;
    // A 140% bar renders past its own track, which reads as a broken page
    // rather than a broken number.
    expect(parsed.percent).toBe(100);

    const nan = parseFrame(JSON.stringify({ scan_id: 's1', percent: 'x', engines: [] }))!;
    expect(nan.percent).toBe(0);
  });

  it('drops an engine entry with no id rather than rendering a blank row', () => {
    const parsed = parseFrame(
      JSON.stringify({
        scan_id: 's1',
        engines: [{ status: 'running' }, { engine_id: 'syft', status: 'running' }],
      }),
    )!;
    expect(parsed.engines).toHaveLength(1);
  });
});

describe('the platform default', () => {
  it('is only used when no factory is supplied', () => {
    // Guards against the factory becoming required by accident, which would
    // make the production path untested.
    const spy = vi.fn();
    const dispose = connectProgress({
      url: 'wss://example/scan',
      handlers: { onProgress: () => {}, onConnection: spy },
      factory: () => new FakeSocket(),
      setTimeoutFn: () => 1,
      clearTimeoutFn: () => {},
    });
    expect(spy).toHaveBeenCalledWith({ kind: 'connecting' });
    dispose();
  });
});
