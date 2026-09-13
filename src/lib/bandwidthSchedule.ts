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

/** `MAX_CONFIGURED_SPEED_BPS` in `bandwidth/mod.rs`: 100 GiB/s. */
export const MAX_CONFIGURED_SPEED_BPS = 100 * 1024 * 1024 * 1024;
/** Monday-first, matching the bit order. */
export const WEEKDAY_COUNT = 7;
/** Bits 0–4. Seeds a new rule; there is no weekend equivalent because nothing
 *  needs one — `toggleDay` covers Saturday and Sunday like any other day. */
export const WEEKDAYS_MASK = 0b0001_1111;

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
export type RuleProblem =
  | 'no_days'
  | 'empty_window'
  | 'invalid_window'
  | 'label_too_long'
  | 'speed_too_high'
  | 'invalid_id';

/** `MAX_RULE_ID_BYTES` in `schedule.rs`, and the charset it accepts. */
const MAX_RULE_ID_BYTES = 64;
const RULE_ID_RE = /^[A-Za-z0-9_-]+$/;

export function ruleProblem(rule: BandwidthScheduleRule): RuleProblem | null {
  // Ids come from `newRuleId`, so this should be unreachable — but the union
  // above advertises parity with `schedule::validate`, and without it a rule
  // from a hand-edited config leaves Save enabled and the save failing with a
  // page-level error that names no rule. Byte length, matching Rust's
  // `id.len()`, because an id is ASCII by that charset anyway.
  if (
    !rule.id
    || new TextEncoder().encode(rule.id).length > MAX_RULE_ID_BYTES
    || !RULE_ID_RE.test(rule.id)
  ) {
    return 'invalid_id';
  }
  if ((rule.days & ALL_DAYS) === 0 || (rule.days & ~ALL_DAYS) !== 0) return 'no_days';
  // Spread rather than `.length`: Rust counts scalar values and JavaScript
  // counts UTF-16 code units, so a label of 30 emoji is 30 to the backend and
  // 60 here. The backend would accept and persist it, and this would then
  // report a problem for a saved rule — which disables Save for the whole
  // page until the user works out which rule is at fault.
  if ([...rule.label].length > MAX_RULE_LABEL_CHARS) return 'label_too_long';
  if (
    rule.max_upload_speed > MAX_CONFIGURED_SPEED_BPS
    || rule.max_download_speed > MAX_CONFIGURED_SPEED_BPS
  ) {
    return 'speed_too_high';
  }
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

/** A fault that belongs to the list rather than to any one rule. */
export type ScheduleProblem = 'too_many' | 'duplicate_id';

/**
 * Why the backend would refuse the list as a whole, or `null` if it would take
 * it. Mirrors the two checks in `schedule::validate` that are not per-rule.
 */
export function scheduleProblem(rules: BandwidthScheduleRule[]): ScheduleProblem | null {
  if (rules.length > MAX_SCHEDULE_RULES) return 'too_many';
  const seen = new Set<string>();
  for (const rule of rules) {
    if (seen.has(rule.id)) return 'duplicate_id';
    seen.add(rule.id);
  }
  return null;
}

// There is deliberately no local mirror of `schedule::matches` or
// `schedule::local_now` here. One existed, with tests that read as though they
// established Rust/TypeScript parity for the evaluation logic — but nothing
// called either, so they proved parity for code the app never ran. Which rule
// is in force comes from the backend's `RuntimeStatus`, which is the only
// answer that can be right, since the backend is what the limiter obeys. A
// preview of an *unsaved* edit is the one thing that would need a local
// evaluator; build it here if that is ever wanted.

/**
 * A fresh rule for the "Add" button: weekdays, 09:00–17:00, carrying the
 * manual limits forward.
 *
 * Seeded from the manual pair rather than left at `0`, because `0` means
 * *unlimited* here — so a rule added with the defaults and then switched on
 * removed the user's limit between 09:00 and 17:00, which is the opposite of
 * what anyone reaches for a bandwidth timetable to do. Copying the current
 * numbers makes the new rule a no-op until it is deliberately changed, which is
 * the safe starting point.
 */
export function newScheduleRule(
  manualUpload = 0,
  manualDownload = 0,
): BandwidthScheduleRule {
  return {
    id: newRuleId(),
    enabled: true,
    label: '',
    days: WEEKDAYS_MASK,
    start_minute: 9 * 60,
    end_minute: 17 * 60,
    max_upload_speed: manualUpload,
    max_download_speed: manualDownload,
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
