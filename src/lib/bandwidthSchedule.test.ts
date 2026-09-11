import { describe, expect, it } from 'vitest';
import type { BandwidthScheduleRule } from '$lib/types';
import {
  ALL_DAYS,
  MAX_RULE_LABEL_CHARS,
  MINUTES_PER_DAY,
  WEEKDAYS_MASK,
  WEEKEND_MASK,
  endTimeValueToMinutes,
  firstScheduleProblem,
  hasDay,
  isOvernight,
  localNow,
  minutesToTimeValue,
  newRuleId,
  newScheduleRule,
  ruleMatches,
  ruleProblem,
  timeValueToMinutes,
  toggleDay,
} from './bandwidthSchedule';

const MON = 0;
const TUE = 1;
const SAT = 5;
const SUN = 6;

function rule(patch: Partial<BandwidthScheduleRule> = {}): BandwidthScheduleRule {
  return {
    id: 'r1',
    enabled: true,
    label: '',
    days: ALL_DAYS,
    start_minute: 9 * 60,
    end_minute: 17 * 60,
    max_upload_speed: 50_000,
    max_download_speed: 500_000,
    ...patch,
  };
}

describe('day bitmask', () => {
  it('is Monday-first, matching the Rust bit order', () => {
    expect(hasDay(WEEKDAYS_MASK, MON)).toBe(true);
    expect(hasDay(WEEKDAYS_MASK, SAT)).toBe(false);
    expect(hasDay(WEEKEND_MASK, SAT)).toBe(true);
    expect(hasDay(WEEKEND_MASK, SUN)).toBe(true);
    expect(hasDay(WEEKEND_MASK, MON)).toBe(false);
  });

  it('toggles a day without disturbing the others or setting unknown bits', () => {
    expect(toggleDay(0, MON)).toBe(0b0000_0001);
    expect(toggleDay(ALL_DAYS, SUN)).toBe(0b0011_1111);
    expect(toggleDay(0b1000_0000, MON) & ~ALL_DAYS).toBe(0);
    // Out of range is a no-op rather than a silently mangled mask.
    expect(toggleDay(ALL_DAYS, 7)).toBe(ALL_DAYS);
    expect(toggleDay(ALL_DAYS, -1)).toBe(ALL_DAYS);
  });
});

describe('time inputs', () => {
  it('round-trips a minute through the HH:MM an <input type="time"> uses', () => {
    expect(minutesToTimeValue(0)).toBe('00:00');
    expect(minutesToTimeValue(9 * 60)).toBe('09:00');
    expect(minutesToTimeValue(23 * 60 + 59)).toBe('23:59');
    expect(timeValueToMinutes('09:00')).toBe(9 * 60);
    expect(timeValueToMinutes('23:59')).toBe(23 * 60 + 59);
    expect(timeValueToMinutes('9:05')).toBe(9 * 60 + 5);
    // Some browsers add seconds when `step` is set.
    expect(timeValueToMinutes('09:00:00')).toBe(9 * 60);
  });

  it('renders the exclusive end of a day as midnight rather than out of range', () => {
    // `<input type="time">` has no way to say 24:00; both ends are the same
    // instant, so showing 00:00 is the honest rendering.
    expect(minutesToTimeValue(MINUTES_PER_DAY)).toBe('00:00');
  });

  it('maps a midnight end back to the exclusive end of the day', () => {
    // Straight `timeValueToMinutes` would give 0, which reads as an empty
    // window and would be rejected — so "until midnight" needs the lift.
    expect(endTimeValueToMinutes('00:00')).toBe(MINUTES_PER_DAY);
    expect(endTimeValueToMinutes('06:00')).toBe(6 * 60);
  });

  it('rejects anything that is not a time', () => {
    for (const bad of ['', 'nope', '25:00', '12:60', '1200', '--:--']) {
      expect(timeValueToMinutes(bad)).toBeNull();
      expect(endTimeValueToMinutes(bad)).toBeNull();
    }
  });
});

describe('ruleProblem mirrors the backend validator', () => {
  it('accepts a plain window', () => {
    expect(ruleProblem(rule())).toBeNull();
    expect(ruleProblem(rule({ start_minute: 0, end_minute: MINUTES_PER_DAY }))).toBeNull();
    expect(ruleProblem(rule({ start_minute: 22 * 60, end_minute: 6 * 60 }))).toBeNull();
  });

  it('names each rejection the backend would make', () => {
    expect(ruleProblem(rule({ days: 0 }))).toBe('no_days');
    expect(ruleProblem(rule({ days: 0b1000_0001 }))).toBe('no_days');
    expect(ruleProblem(rule({ start_minute: 600, end_minute: 600 }))).toBe('empty_window');
    expect(ruleProblem(rule({ end_minute: 0 }))).toBe('invalid_window');
    expect(ruleProblem(rule({ end_minute: MINUTES_PER_DAY + 1 }))).toBe('invalid_window');
    expect(ruleProblem(rule({ start_minute: MINUTES_PER_DAY }))).toBe('invalid_window');
    expect(ruleProblem(rule({ label: 'x'.repeat(MAX_RULE_LABEL_CHARS + 1) }))).toBe(
      'label_too_long',
    );
  });

  it('checks a disabled rule too, so enabling it later cannot fail the save', () => {
    expect(ruleProblem(rule({ enabled: false, days: 0 }))).toBe('no_days');
  });

  it('reports the first offending rule for the save guard', () => {
    const good = rule({ id: 'good' });
    const bad = rule({ id: 'bad', days: 0 });
    expect(firstScheduleProblem([good, good])).toBeNull();
    expect(firstScheduleProblem([good, bad])).toEqual({ rule: bad, problem: 'no_days' });
  });
});

describe('ruleMatches mirrors schedule::matches', () => {
  it('treats the window as half-open so adjacent rules do not both claim a minute', () => {
    const morning = rule({ start_minute: 9 * 60, end_minute: 17 * 60 });
    expect(ruleMatches(morning, TUE, 9 * 60 - 1)).toBe(false);
    expect(ruleMatches(morning, TUE, 9 * 60)).toBe(true);
    expect(ruleMatches(morning, TUE, 17 * 60 - 1)).toBe(true);
    expect(ruleMatches(morning, TUE, 17 * 60)).toBe(false);
  });

  it('carries an overnight window into the next day under the opening day', () => {
    const overnight = rule({ days: 1 << MON, start_minute: 22 * 60, end_minute: 6 * 60 });
    expect(ruleMatches(overnight, MON, 22 * 60)).toBe(true);
    expect(ruleMatches(overnight, TUE, 0)).toBe(true);
    expect(ruleMatches(overnight, TUE, 5 * 60 + 59)).toBe(true);
    expect(ruleMatches(overnight, TUE, 6 * 60)).toBe(false);
    expect(ruleMatches(overnight, MON, 6 * 60)).toBe(false);
  });

  it('wraps from Sunday into Monday', () => {
    const overnight = rule({ days: 1 << SUN, start_minute: 23 * 60, end_minute: 2 * 60 });
    expect(ruleMatches(overnight, SUN, 23 * 60 + 30)).toBe(true);
    expect(ruleMatches(overnight, MON, 60)).toBe(true);
    expect(ruleMatches(overnight, SAT, 60)).toBe(false);
  });

  it('never matches a disabled or malformed rule', () => {
    expect(ruleMatches(rule({ enabled: false }), MON, 10 * 60)).toBe(false);
    expect(ruleMatches(rule({ days: 0 }), MON, 10 * 60)).toBe(false);
    expect(ruleMatches(rule({ start_minute: 600, end_minute: 600 }), MON, 600)).toBe(false);
  });

  it('flags a window that crosses midnight', () => {
    expect(isOvernight(rule({ start_minute: 22 * 60, end_minute: 6 * 60 }))).toBe(true);
    expect(isOvernight(rule({ start_minute: 9 * 60, end_minute: 17 * 60 }))).toBe(false);
    // A full day is not overnight: it starts and ends inside the same day.
    expect(isOvernight(rule({ start_minute: 0, end_minute: MINUTES_PER_DAY }))).toBe(false);
  });
});

describe('localNow', () => {
  it('is Monday-first, unlike Date#getDay', () => {
    // 2026-09-07 is a Monday, 2026-09-13 the Sunday that follows.
    expect(localNow(new Date(2026, 8, 7, 0, 0)).weekday).toBe(MON);
    expect(localNow(new Date(2026, 8, 13, 0, 0)).weekday).toBe(SUN);
  });

  it('reports minutes from local midnight', () => {
    expect(localNow(new Date(2026, 8, 7, 0, 0)).minute).toBe(0);
    expect(localNow(new Date(2026, 8, 7, 13, 37)).minute).toBe(13 * 60 + 37);
    expect(localNow(new Date(2026, 8, 7, 23, 59)).minute).toBe(MINUTES_PER_DAY - 1);
  });
});

describe('new rules', () => {
  it('starts from a window the backend accepts', () => {
    const created = newScheduleRule();
    expect(ruleProblem(created)).toBeNull();
    expect(created.enabled).toBe(true);
  });

  it('generates ids the backend id check allows', () => {
    // `[A-Za-z0-9_-]`, non-empty, at most 64 bytes — see `schedule::validate`.
    for (let i = 0; i < 50; i++) {
      const id = newRuleId();
      expect(id).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(id.length).toBeGreaterThan(0);
      expect(id.length).toBeLessThanOrEqual(64);
    }
  });

  it('does not hand two rules the same id', () => {
    const ids = new Set(Array.from({ length: 200 }, () => newRuleId()));
    expect(ids.size).toBe(200);
  });
});
