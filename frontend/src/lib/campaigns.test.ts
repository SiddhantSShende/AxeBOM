import { describe, expect, it } from 'vitest';
import {
  SCHEDULE_PRESETS,
  browserTimezone,
  describeCron,
  matchPreset,
  validateCron,
} from './campaigns';

describe('schedule presets', () => {
  it('never schedules on the hour or at midnight', () => {
    // ⚠ `0 0 * * *` IS WHAT EVERYONE REACHES FOR, and it is why every scheduler
    // has a thundering herd at midnight — ours included, since a campaign fires
    // scans against shared infrastructure. Offsetting into the small hours
    // spreads the load and costs the customer nothing.
    for (const preset of SCHEDULE_PRESETS) {
      const [minute, hour] = preset.cron.split(' ');
      expect(minute, `${preset.id} fires on the hour`).not.toBe('0');
      expect(hour, `${preset.id} fires at midnight`).not.toBe('0');
    }
  });

  it('produces expressions the shape check accepts', () => {
    for (const preset of SCHEDULE_PRESETS) {
      expect(validateCron(preset.cron), preset.id).toBeNull();
    }
  });

  it('round-trips through matchPreset', () => {
    for (const preset of SCHEDULE_PRESETS) {
      expect(matchPreset(preset.cron)?.id).toBe(preset.id);
    }
  });

  it('tolerates extra whitespace when matching', () => {
    expect(matchPreset('  30   2 * * *  ')?.id).toBe('daily');
  });

  it('has a distinct cron per preset', () => {
    // Two presets producing the same expression would make the highlighted
    // button depend on array order rather than on what the user picked.
    const crons = SCHEDULE_PRESETS.map((p) => p.cron);
    expect(new Set(crons).size).toBe(crons.length);
  });
});

describe('describeCron', () => {
  it('renders a known preset in words', () => {
    expect(describeCron('30 2 * * *')).toBe('at 02:30 every day');
  });

  it('never invents a description for an expression it does not know', () => {
    // ⚠ A WRONG PLAIN-ENGLISH RENDERING IS WORSE THAN NONE. Somebody reads
    // "every day at 2:30am", believes it, and never checks the expression that
    // actually says something else.
    const described = describeCron('*/7 3 * * 2');
    expect(described).toContain('*/7 3 * * 2');
    expect(described).not.toContain('every day');
  });
});

describe('validateCron', () => {
  it('accepts a five-field expression', () => {
    expect(validateCron('30 2 * * 1-5')).toBeNull();
  });

  it('rejects the wrong field count and says how many it found', () => {
    const err = validateCron('30 2 * *');
    expect(err).toContain('5 fields');
    expect(err).toContain('4');
  });

  it('rejects an empty schedule', () => {
    expect(validateCron('   ')).toBeTruthy();
  });

  it('does not reject expressions the server accepts', () => {
    // ⚠ THE SERVER IS THE AUTHORITY. A client validator that disagrees produces
    // either a form rejecting valid input or one accepting what the server
    // refuses; this check is deliberately shape-only.
    for (const expr of [
      '*/15 * * * *',
      '0 9 1,15 * *',
      '30 6 * * MON-FRI',
      '0 0 29 2 *',
      '@nonsense but five fields here',
    ]) {
      expect(validateCron(expr), expr).toBeNull();
    }
  });
});

describe('browserTimezone', () => {
  it('returns an IANA name, never an offset', () => {
    // An offset is correct for half the year, and which half depends on the
    // zone. A campaign stored as "+05:30" is simply wrong wherever DST applies.
    const tz = browserTimezone();
    expect(tz).not.toMatch(/^[+-]\d{2}:\d{2}$/);
    expect(tz.length).toBeGreaterThan(0);
  });
});
