import { describe, expect, it } from 'vitest';
import { isTerminal } from './scans';

describe('isTerminal', () => {
  // ⚠ THE REGRESSION THIS GUARDS: it previously checked 'succeeded'/'partial',
  // neither of which scan.scans' status CHECK constraint (migrations) or
  // events.ScanStatus (Go) ever produces. The real terminal values are
  // 'completed' and 'completed_with_errors', and both silently read as "still
  // running" under the old list — exactly the two most common outcomes.
  it.each(['completed', 'completed_with_errors', 'failed', 'cancelled'])(
    'treats %s as terminal',
    (status) => {
      expect(isTerminal(status)).toBe(true);
    },
  );

  it.each(['queued', 'fetching', 'running', 'normalizing'])(
    'treats %s as not terminal',
    (status) => {
      expect(isTerminal(status)).toBe(false);
    },
  );

  it('does not recognize the old, wrong vocabulary as terminal', () => {
    expect(isTerminal('succeeded')).toBe(false);
    expect(isTerminal('partial')).toBe(false);
  });
});
