/**
 * Shape and presentation helpers for the bandwidth timetable.
 *
 * The authority on what a rule *means* is `src-tauri/src/bandwidth/schedule.rs`
 * — it is what the running app evaluates once a second, and what rejects a bad
 * rule at the IPC boundary. Everything here exists so the editor can show the
 * same answer before a save round-trip: which day bits are set, what a window
 * reads as, and whether the rule about to be sent is one the backend will take.
 *
 * A frontend copy of a backend rule drifts silently, so the constants below are
 * pinned to their Rust counterparts by name in the comments and the matching
 * shapes are covered by tests on both sides.
 */

import type { BandwidthScheduleRule } from '$lib/types';

/** `MINUTES_PER_DAY` in `schedule.rs`. */
export const MINUTES_PER_DAY = 1440;
/** `MAX_SCHEDULE_RULES` in `schedule.rs`. */
export const MAX_SCHEDULE_RULES = 32;
/** `MAX_RULE_LABEL_CHARS` in `schedule.rs`. */
export const MAX_RULE_LABEL_CHARS = 48;
/** `ALL_DAYS` in `schedule.rs`: Monday (bit 0) through Sunday (bit 6). */
export const ALL_DAYS = 0b0111_1111;
/** Monday-first, matching the bit order. */
export const WEEKDAY_COUNT = 7;
/** Bits 0–4. */
export const WEEKDAYS_MASK = 0b0001_1111;
/** Bits 5–6. */
export const WEEKEND_MASK = 0b0110_0000;

/** Whether `weekday` (0 = Monday) is selected in `days`. */
export function hasDay(days: number, weekday: number): boolean {
  return weekday >= 0 && weekday < WEEKDAY_COUNT && (days & (1 << weekday)) !== 0;
}

/** `days` with `weekday` flipped. */
export function toggleDay(days: number, weekday: number): number {
  if (weekday < 0 || weekday >= WEEKDAY_COUNT) return days;
  return (days ^ (1 << weekday)) & ALL_DAYS;
}

/**
 * `HH:MM` for a minute-of-day, in 24-hour form.
 *
 * Deliberately not locale-formatted: this is the value of an `<input
 * type="time">`, which is always `HH:MM` regardless of what the browser
 * *displays*. Using a localized string here would produce a control that
 * silently refuses the user's typing.
 */
export function minutesToTimeValue(minute: number): string {
  const clamped = Math.max(0, Math.min(MINUTES_PER_DAY, Math.round(minute)));
  // 1440 is the exclusive end of a day, which `<input type="time">` cannot
  // represent — it wraps to 00:00, which is the same instant.
  const wrapped = clamped % MINUTES_PER_DAY;
  const hours = Math.floor(wrapped / 60);
  const minutes = wrapped % 60;
  return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}`;
}

/**
 * Minute-of-day from an `<input type="time">` value, or `null` if it is not one.
 *
 * A time input can hand back an empty string (cleared) or, with `step`, a
 * `HH:MM:SS` value; seconds are dropped rather than rejected.
 */
export function timeValueToMinutes(value: string): number | null {
  const match = /^(\d{1,2}):(\d{2})(?::\d{2})?$/.exec(value.trim());
  if (!match) return null;
  const hours = Number(match[1]);
  const minutes = Number(match[2]);
  if (!Number.isInteger(hours) || !Number.isInteger(minutes)) return null;
  if (hours > 23 || minutes > 59) return null;
  return hours * 60 + minutes;
}

/**
 * The end minute as the backend stores it.
 *
 * `<input type="time">` cannot express "midnight at the end of the day": it
 * gives back `00:00`, which is minute 0 and would read as an empty window. The
 * backend's exclusive end runs to 1440 for exactly this case, so 0 is mapped up
 * on the way in.
 */
export function endTimeValueToMinutes(value: string): number | null {
  const minutes = timeValueToMinutes(value);
  if (minutes === null) return null;
  return minutes === 0 ? MINUTES_PER_DAY : minutes;
}

/** Whether a window crosses midnight (and so runs into the following day). */
export function isOvernight(rule: Pick<BandwidthScheduleRule, 'start_minute' | 'end_minute'>): boolean {
  return rule.end_minute <= rule.start_minute;
}

/**
 * Why the backend would refuse this rule, or `null` if it would take it.
 *
 * Mirrors `schedule::validate`. Returned as a stable key rather than a sentence
 * so the caller localizes it, and named after the same conditions so the two
 * lists can be read side by side.
 */
export type RuleProblem = 'no_days' | 'empty_window' | 'invalid_window' | 'label_too_long';

export function ruleProblem(rule: BandwidthScheduleRule): RuleProblem | null {
  if ((rule.days & ALL_DAYS) === 0 || (rule.days & ~ALL_DAYS) !== 0) return 'no_days';
  if (rule.label.length > MAX_RULE_LABEL_CHARS) return 'label_too_long';
  if (
    !Number.isInteger(rule.start_minute)
    || !Number.isInteger(rule.end_minute)
    || rule.start_minute < 0
    || rule.start_minute >= MINUTES_PER_DAY
    || rule.end_minute < 1
    || rule.end_minute > MINUTES_PER_DAY
  ) {
    return 'invalid_window';
  }
  if (rule.start_minute === rule.end_minute) return 'empty_window';
  return null;
}

/** Whether every rule would be accepted, so Save can say so before trying. */
export function firstScheduleProblem(
  rules: BandwidthScheduleRule[],
): { rule: BandwidthScheduleRule; problem: RuleProblem } | null {
  for (const rule of rules) {
    const problem = ruleProblem(rule);
    if (problem) return { rule, problem };
  }
  return null;
}

/**
 * Whether `rule`'s window is open at `(weekday, minute)`.
 *
 * A local mirror of `schedule::matches`, used only to preview a rule the user
 * is still editing. What is actually *in force* comes from the backend's
 * `RuntimeStatus`, so the two can never disagree on screen about a saved rule.
 */
export function ruleMatches(rule: BandwidthScheduleRule, weekday: number, minute: number): boolean {
  if (!rule.enabled) return false;
  if (ruleProblem(rule)) return false;
  const { start_minute: start, end_minute: end } = rule;
  if (start < end) {
    return hasDay(rule.days, weekday) && minute >= start && minute < end;
  }
  // Crosses midnight: the tail belongs to the day the window opened.
  const yesterday = (weekday + WEEKDAY_COUNT - 1) % WEEKDAY_COUNT;
  return (
    (hasDay(rule.days, weekday) && minute >= start)
    || (hasDay(rule.days, yesterday) && minute < end)
  );
}

/** Local weekday (0 = Monday) and minute-of-day, matching `schedule::local_now`. */
export function localNow(now: Date = new Date()): { weekday: number; minute: number } {
  // `getDay()` is Sunday-first; the bitmask is Monday-first.
  const weekday = (now.getDay() + 6) % 7;
  return { weekday, minute: now.getHours() * 60 + now.getMinutes() };
}

/** A fresh rule for the "Add" button: weekdays, 09:00–17:00, limits unset. */
export function newScheduleRule(): BandwidthScheduleRule {
  return {
    id: newRuleId(),
    enabled: true,
    label: '',
    days: WEEKDAYS_MASK,
    start_minute: 9 * 60,
    end_minute: 17 * 60,
    max_upload_speed: 0,
    max_download_speed: 0,
  };
}

/**
 * An id the backend accepts (`[A-Za-z0-9_-]`, non-empty, ≤64 bytes).
 *
 * `crypto.randomUUID` is not guaranteed outside a secure context, and this only
 * has to be unique within one user's list — a timestamp plus randomness is
 * ample, and stays short enough to read in a log line.
 */
export function newRuleId(): string {
  const random = Math.random().toString(36).slice(2, 10);
  return `r-${Date.now().toString(36)}-${random}`;
}
