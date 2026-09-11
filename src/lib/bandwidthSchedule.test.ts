import { describe, expect, it } from 'vitest';
import type { BandwidthScheduleRule } from '$lib/types';
import {
  ALL_DAYS,
  MAX_CONFIGURED_SPEED_BPS,
  MAX_RULE_LABEL_CHARS,
  MAX_SCHEDULE_RULES,
  MINUTES_PER_DAY,
  WEEKDAYS_MASK,
  endTimeValueToMinutes,
  hasDay,
  isOvernight,
  minutesToTimeValue,
  newRuleId,
  newScheduleRule,
  ruleProblem,
  scheduleProblem,
  timeValueToMinutes,
  toggleDay,
} from './bandwidthSchedule';

const MON = 0;
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
    expect(hasDay(WEEKDAYS_MASK, SUN)).toBe(false);
    expect(hasDay(0b0110_0000, SAT)).toBe(true);
    expect(hasDay(0b0110_0000, SUN)).toBe(true);
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
    expect(ruleProblem(rule({ id: '' }))).toBe('invalid_id');
    expect(ruleProblem(rule({ id: 'has space' }))).toBe('invalid_id');
    expect(ruleProblem(rule({ id: 'a'.repeat(65) }))).toBe('invalid_id');
  });

  it('counts a label the way Rust does, not the way UTF-16 does', () => {
    // Rust counts scalar values; `String#length` counts code units, so an
    // astral character is 1 there and 2 here. Reporting a problem for a label
    // the backend accepted disabled Save for the whole page.
    const emoji = '\u{1f600}'.repeat(MAX_RULE_LABEL_CHARS);
    expect([...emoji].length).toBe(MAX_RULE_LABEL_CHARS);
    expect(emoji.length).toBe(MAX_RULE_LABEL_CHARS * 2);
    expect(ruleProblem(rule({ label: emoji }))).toBeNull();
    expect(ruleProblem(rule({ label: emoji + '\u{1f600}' }))).toBe('label_too_long');
  });

  it('refuses a speed the limiter cannot hold', () => {
    // Unbounded rule speeds reach the token refill and overflow it, which
    // panics the refill task under the release profile and aborts every
    // rate-limited transfer for the session.
    expect(ruleProblem(rule({ max_upload_speed: MAX_CONFIGURED_SPEED_BPS }))).toBeNull();
    expect(ruleProblem(rule({ max_upload_speed: MAX_CONFIGURED_SPEED_BPS + 1 }))).toBe(
      'speed_too_high',
    );
    expect(ruleProblem(rule({ max_download_speed: Number.MAX_SAFE_INTEGER }))).toBe(
      'speed_too_high',
    );
  });

  it('checks a disabled rule too, so enabling it later cannot fail the save', () => {
    expect(ruleProblem(rule({ enabled: false, days: 0 }))).toBe('no_days');
  });

  it('mirrors the checks that belong to the list rather than a rule', () => {
    // Both are refused by `schedule::validate` exactly as a malformed rule is.
    // Without them Save stayed enabled and the rejection named no rule.
    expect(scheduleProblem([rule({ id: 'a' }), rule({ id: 'b' })])).toBeNull();
    expect(scheduleProblem([rule({ id: 'dup' }), rule({ id: 'dup' })])).toBe('duplicate_id');
    const tooMany = Array.from({ length: MAX_SCHEDULE_RULES + 1 }, (_, i) =>
      rule({ id: `r${i}` }),
    );
    expect(scheduleProblem(tooMany)).toBe('too_many');
    expect(scheduleProblem(tooMany.slice(0, MAX_SCHEDULE_RULES))).toBeNull();
  });
});

describe('overnight windows', () => {
  it('flags a window that crosses midnight', () => {
    expect(isOvernight(rule({ start_minute: 22 * 60, end_minute: 6 * 60 }))).toBe(true);
    expect(isOvernight(rule({ start_minute: 9 * 60, end_minute: 17 * 60 }))).toBe(false);
    // A full day is not overnight: it starts and ends inside the same day.
    expect(isOvernight(rule({ start_minute: 0, end_minute: MINUTES_PER_DAY }))).toBe(false);
  });
});

describe('new rules', () => {
  it('starts from a window the backend accepts', () => {
    const created = newScheduleRule();
    expect(ruleProblem(created)).toBeNull();
    expect(created.enabled).toBe(true);
  });

  it('carries the manual limits forward instead of defaulting to unlimited', () => {
    // `0` means unlimited, so a rule added with zeroes and then switched on
    // *removed* the user's limit for its window — the opposite of what anyone
    // adds a bandwidth timetable for. Seeded from the manual pair, a new rule
    // is a no-op until it is deliberately changed.
    const created = newScheduleRule(50_000, 500_000);
    expect(created.max_upload_speed).toBe(50_000);
    expect(created.max_download_speed).toBe(500_000);
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
