import { getLocale } from '$lib/i18n';
import { noteOwnClipboardText } from '$lib/clipboardOwn';

/**
 * Format a byte count as a human-readable string (e.g. "1.5 MB", "1,5 Mo").
 * Uses iterative division to avoid floating-point edge cases.
 */
export function formatBytes(bytes: number): string {
  const units = SIZE_UNITS.units;
  if (!Number.isFinite(bytes) || bytes <= 0) return `${SIZE_FORMATTER.format(0)} ${units[0]}`;
  let i = 0;
  let val = bytes;
  while (val >= 1024 && i < units.length - 1) {
    val /= 1024;
    i++;
  }
  // toFixed(1) rounds anything >= 1023.95 up to "1024.0", so carry into the
  // next unit rather than printing "1024 KB" just below the 1 MB boundary.
  if (val >= 1023.95 && i < units.length - 1) {
    val /= 1024;
    i++;
  }
  return `${SIZE_FORMATTER.format(Number(val.toFixed(1)))} ${units[i]}`;
}

/**
 * True when the app window is actually on screen. Used to decide whether the
 * user can be considered to have *seen* something (e.g. an incoming chat
 * message) rather than merely having the relevant view mounted.
 */
export function isAppVisible(): boolean {
  return typeof document === 'undefined' || document.visibilityState === 'visible';
}

/** Alias for formatBytes -- used in file-size contexts. */
export const formatSize = formatBytes;

/** Format bytes/sec as a speed string (e.g. "1.5 MB/s", "1,5 МБ/с"). */
export function formatSpeed(bytesPerSec: number): string {
  return `${formatBytes(bytesPerSec)}${SIZE_UNITS.perSecond}`;
}

/** The app language's label for 1024^`power` bytes: "KB", "Ko", "КБ". */
export function sizeUnitLabel(power: number): string {
  return SIZE_UNITS.units[power] ?? '';
}

/** The app language's label for 1024^`power` bytes per second: "KB/s", "КБ/с". */
export function speedUnitLabel(power: number): string {
  return `${sizeUnitLabel(power)}${SIZE_UNITS.perSecond}`;
}

/*
 * `Intl.DateTimeFormat` construction is surprisingly expensive — each call
 * to `toLocaleDateString(undefined, options)` allocates a fresh formatter
 * internally, which shows up in the flame graph for tables rendering
 * hundreds of rows (transfers, library, known clients). Module-scope these
 * once per page load. Locale changes reload the webview, so construction with
 * Paraglide's active locale keeps these aligned with the in-app language.
 */
const APP_LOCALE = getLocale();
const SHORT_DT_FORMATTER = new Intl.DateTimeFormat(APP_LOCALE, {
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
});
const LEDGER_DATE_FORMATTER = new Intl.DateTimeFormat(APP_LOCALE, {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
});
const RELATIVE_TIME_FORMATTER = new Intl.RelativeTimeFormat(APP_LOCALE, {
  numeric: 'auto',
  style: 'short',
});
const COMPACT_COUNT_FORMATTER = new Intl.NumberFormat(APP_LOCALE, {
  notation: 'compact',
  maximumFractionDigits: 1,
});
const NUMBER_FORMATTER = new Intl.NumberFormat(APP_LOCALE);
const DATE_FORMATTERS = new Map<string, Intl.DateTimeFormat>();
// Sizes stay binary (1 KB = 1024 B), so these are hand-written rather than
// Intl's `kilobyte` units, which are decimal and would print "kB" everywhere.
// The per-second suffix follows the units' script: "Mo/s", but "МБ/с".
const SIZE_UNITS: { units: readonly string[]; perSecond: string } = ({
  fr: { units: ['o', 'Ko', 'Mo', 'Go', 'To'], perSecond: '/s' },
  ru: { units: ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'], perSecond: '/с' },
} as Record<string, { units: readonly string[]; perSecond: string }>)[APP_LOCALE]
  ?? { units: ['B', 'KB', 'MB', 'GB', 'TB'], perSecond: '/s' };
const SIZE_FORMATTER = new Intl.NumberFormat(APP_LOCALE, {
  maximumFractionDigits: 1,
  useGrouping: false,
});
const DURATION_UNIT_FORMATTERS = new Map<string, Intl.NumberFormat>();
let durationJoiner: string | undefined;

function dateFormatter(options: Intl.DateTimeFormatOptions): Intl.DateTimeFormat {
  const key = JSON.stringify(options);
  let formatter = DATE_FORMATTERS.get(key);
  if (!formatter) {
    formatter = new Intl.DateTimeFormat(APP_LOCALE, options);
    DATE_FORMATTERS.set(key, formatter);
  }
  return formatter;
}

function formatUnixWith(ts: number, options: Intl.DateTimeFormatOptions): string {
  if (!Number.isFinite(ts) || ts <= 0) return '\u2014';
  return dateFormatter(options).format(new Date(ts * 1000));
}

/**
 * A count with the app language's digit grouping ("12,345", "12.345",
 * "12 345"). `n.toLocaleString()` groups by the OS locale instead, which
 * disagrees with the surrounding sentence whenever the two differ.
 */
export function formatNumber(n: number): string {
  if (!Number.isFinite(n)) return '\u2014';
  return NUMBER_FORMATTER.format(n);
}

/** A unix timestamp as date and time in the app language — the in-app
 *  replacement for `new Date(ts * 1000).toLocaleString()`. */
export function formatDateTime(
  ts: number,
  options: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    second: '2-digit',
  },
): string {
  return formatUnixWith(ts, options);
}

/** A unix timestamp's calendar date in the app language. Named apart from
 *  {@link formatDate}, which is the short table-cell date *and* time. */
export function formatCalendarDate(
  ts: number,
  options: Intl.DateTimeFormatOptions = { year: 'numeric', month: 'numeric', day: 'numeric' },
): string {
  return formatUnixWith(ts, options);
}

/** A unix timestamp's time of day in the app language. */
export function formatClockTime(
  ts: number,
  options: Intl.DateTimeFormatOptions = { hour: 'numeric', minute: '2-digit', second: '2-digit' },
): string {
  return formatUnixWith(ts, options);
}

/**
 * Abbreviate a large count for a narrow column ("12.3K").
 *
 * Goes through `Intl` rather than appending `K`/`M` by hand: those suffixes are
 * English, and a German or Russian reader expects "Tsd." and "тыс." for the same
 * magnitude. Small numbers come back in full, so this is only ever a shortening.
 */
export function formatCompactCount(n: number): string {
  if (!Number.isFinite(n)) return '\u2014';
  return COMPACT_COUNT_FORMATTER.format(n);
}

/** Format a unix timestamp as a short date string. */
export function formatDate(ts: number): string {
  if (!ts || ts <= 0) return '\u2014';
  return SHORT_DT_FORMATTER.format(new Date(ts * 1000));
}

/** Format a unix timestamp for long-lived ledger views (e.g. the Known
 *  Clients tab) where rows can persist for months. Always includes the
 *  year so users can immediately tell a stale row from a fresh one —
 *  the year-less variant above hides exactly the information you need
 *  when triaging a months-old row. Drops the time portion entirely:
 *  for ledger rows the date alone is what matters, and the time would
 *  just push the column wider for no real signal. */
export function formatDateWithYear(ts: number): string {
  if (!ts || ts <= 0) return '\u2014';
  return LEDGER_DATE_FORMATTER.format(new Date(ts * 1000));
}

/**
 * Format a unix timestamp as a localized short relative duration vs `now`.
 *
 * Intended for ledger views where what matters is "how stale is this
 * row" rather than the exact wall-clock date. Pair with a tooltip
 * showing the absolute date for users who need precision. Returns
 * the em-dash sentinel for missing or future timestamps so callers
 * can treat it as a drop-in replacement for `formatDate*`.
 */
export function formatRelativeTime(ts: number, nowSecs: number = Math.floor(Date.now() / 1000)): string {
  if (!ts || ts <= 0) return '\u2014';
  const diff = nowSecs - ts;
  if (!Number.isFinite(diff)) return '\u2014';
  if (diff < 45) return RELATIVE_TIME_FORMATTER.format(0, 'second');
  if (diff < 3600) {
    const m = Math.round(diff / 60);
    return RELATIVE_TIME_FORMATTER.format(-m, 'minute');
  }
  if (diff < 86400) {
    const h = Math.round(diff / 3600);
    return RELATIVE_TIME_FORMATTER.format(-h, 'hour');
  }
  if (diff < 7 * 86400) {
    const d = Math.round(diff / 86400);
    return RELATIVE_TIME_FORMATTER.format(-d, 'day');
  }
  if (diff < 30 * 86400) {
    const w = Math.round(diff / (7 * 86400));
    return RELATIVE_TIME_FORMATTER.format(-w, 'week');
  }
  if (diff < 365 * 86400) {
    const mo = Math.round(diff / (30 * 86400));
    return RELATIVE_TIME_FORMATTER.format(-mo, 'month');
  }
  const y = Math.round(diff / (365 * 86400));
  return RELATIVE_TIME_FORMATTER.format(-y, 'year');
}

type DurationUnit = 'day' | 'hour' | 'minute' | 'second';

function formatDurationUnit(value: number, unit: DurationUnit, digits: number): string {
  const key = `${unit}:${digits}`;
  let formatter = DURATION_UNIT_FORMATTERS.get(key);
  if (!formatter) {
    formatter = new Intl.NumberFormat(APP_LOCALE, {
      style: 'unit',
      unit,
      unitDisplay: 'narrow',
      minimumIntegerDigits: digits,
    });
    DURATION_UNIT_FORMATTERS.set(key, formatter);
  }
  return formatter.format(value);
}

/**
 * Join duration parts compactly in the app language's narrow units: "2h 15m",
 * "2h 15 Min.", "2 ч 15 мин", "2小时15分钟".
 *
 * Deliberately not `Intl.ListFormat` / `Intl.DurationFormat`: their narrow
 * style joins as a list ("2h, 15 Min.", "1h, 05 Min. und 09 Sek."), which reads
 * as prose in a table column. Parts are spaced, except where the units are
 * Chinese or Japanese set solid; zh-TW's narrow units carry their own space
 * ("2 小時"), so that locale is spaced like the rest.
 * `pad` zero-pads every part after the first, for counters that tick in place.
 */
function formatDurationParts(parts: [number, DurationUnit][], pad = false): string {
  if (durationJoiner === undefined) {
    const sample = formatDurationUnit(1, 'hour', 1);
    durationJoiner =
      /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}]/u.test(sample) && !/\s/u.test(sample)
        ? ''
        : ' ';
  }
  return parts
    .map(([value, unit], i) => formatDurationUnit(value, unit, pad && i > 0 ? 2 : 1))
    .join(durationJoiner);
}

/** The two most significant units of a non-negative duration, for table columns. */
function compactDuration(secs: number): string {
  const days = Math.floor(secs / 86400);
  const hrs = Math.floor((secs % 86400) / 3600);
  const mins = Math.floor((secs % 3600) / 60);
  if (days > 0) return formatDurationParts([[days, 'day'], [hrs, 'hour']]);
  if (hrs > 0) return formatDurationParts([[hrs, 'hour'], [mins, 'minute']]);
  if (mins > 0) return formatDurationParts([[mins, 'minute']]);
  return formatDurationParts([[Math.floor(secs), 'second']]);
}

/** Format seconds as a human-readable duration (e.g. "2h 15m"). */
export function formatDurationSecs(secs: number): string {
  if (!Number.isFinite(secs) || secs < 0) return '\u2014';
  return compactDuration(secs);
}

/**
 * Format elapsed seconds down to the second, zero-padding minutes and seconds
 * so a live counter keeps its width (e.g. "1h 05m 09s").
 */
export function formatElapsed(secs: number): string {
  const total = Number.isFinite(secs) && secs > 0 ? Math.floor(secs) : 0;
  const h = Math.floor(total / 3600);
  const min = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return formatDurationParts([[h, 'hour'], [min, 'minute'], [s, 'second']], true);
  if (min > 0) return formatDurationParts([[min, 'minute'], [s, 'second']], true);
  return formatDurationParts([[s, 'second']]);
}

/** Format remaining size + ETA combined (eMule Remaining column style). */
export function formatRemaining(totalSize: number, transferred: number, speed: number): string {
  if (transferred >= totalSize) return '\u2014';
  const remaining = totalSize - transferred;
  const remainStr = formatBytes(remaining);
  // Guard against a non-finite speed (NaN/Infinity) — `NaN <= 0` is false, so
  // without `Number.isFinite` the ETA math below would render "NaNd NaNh".
  if (!Number.isFinite(speed) || speed <= 0) return remainStr;
  return `${compactDuration(Math.round(remaining / speed))} (${remainStr})`;
}

/** Truncate a hex hash with ellipsis. */
export function truncateHash(hash: string, len = 16): string {
  if (hash.length <= len) return hash;
  return `${hash.slice(0, len)}\u2026`;
}

const utf8 = new TextEncoder();

/** The backend's nickname cap (`commands/settings.rs`), in UTF-8 bytes. */
export const NICKNAME_MAX_BYTES = 128;

let graphemeSegmenter: Intl.Segmenter | undefined;
/** An input's value when its IME composition began. */
const beforeComposition = new WeakMap<EventTarget, string>();

/** What a user sees as single characters: an emoji ZWJ sequence or a letter
 *  with its combining accents is one. Whole code points where the webview has
 *  no `Intl.Segmenter`. */
function graphemes(text: string): Iterable<string> {
  if (typeof Intl === 'undefined' || typeof Intl.Segmenter !== 'function') return text;
  graphemeSegmenter ??= new Intl.Segmenter(undefined, { granularity: 'grapheme' });
  return Array.from(graphemeSegmenter.segment(text), (s) => s.segment);
}

/** Cut `text` to at most `maxBytes` UTF-8 bytes, for fields the backend caps in
 *  bytes where `maxlength` counts UTF-16 units. Cuts between characters as
 *  {@link graphemes} sees them. */
export function clampUtf8Bytes(text: string, maxBytes: number): string {
  if (utf8.encode(text).length <= maxBytes) return text;
  let bytes = 0;
  let out = '';
  for (const ch of graphemes(text)) {
    bytes += utf8.encode(ch).length;
    if (bytes > maxBytes) break;
    out += ch;
  }
  return out;
}

const isHighSurrogate = (unit: number) => unit >= 0xd800 && unit <= 0xdbff;
const isLowSurrogate = (unit: number) => unit >= 0xdc00 && unit <= 0xdfff;

/** Where `next` differs from `previous`, as `[start, end)` in `next`, with the
 *  caret (when known) marking the end of what was typed so a repeated letter
 *  is placed where the user put it. Never splits a surrogate pair. */
function editedRange(previous: string, next: string, caret: number | null): [number, number] {
  let end = next.length;
  let previousEnd = previous.length;
  const floor = caret === null ? 0 : Math.min(caret, next.length);
  while (end > floor && previousEnd > 0 && next[end - 1] === previous[previousEnd - 1]) {
    end--;
    previousEnd--;
  }
  let start = 0;
  while (start < end && start < previousEnd && next[start] === previous[start]) start++;
  if (start > 0 && isHighSurrogate(next.charCodeAt(start - 1))) start--;
  if (end < next.length && isLowSurrogate(next.charCodeAt(end))) end++;
  return [start, end];
}

/** `oninput`/`oncompositionend` handler that keeps an input within `maxBytes`
 *  UTF-8 bytes as the user types. `previous` is the value before this edit.
 *  What does not fit is cut from the text just typed or pasted, not from the
 *  end of the value, and the caret stays after what was kept. Waits out IME
 *  composition, as `maxlength` does, so a half-composed CJK character is not
 *  cut. Returns the value to store. */
export function clampInputUtf8Bytes(event: Event, maxBytes: number, previous: string): string {
  const input = event.currentTarget as HTMLInputElement;
  if ((event as InputEvent).isComposing) {
    if (!beforeComposition.has(input)) beforeComposition.set(input, previous);
    return input.value;
  }
  const before = beforeComposition.get(input) ?? previous;
  beforeComposition.delete(input);
  const next = input.value;
  if (utf8.encode(next).length <= maxBytes) return next;

  const caret = input.selectionStart === input.selectionEnd ? input.selectionStart : null;
  const [start, end] = editedRange(before, next, caret);
  const head = next.slice(0, start);
  const tail = next.slice(end);
  const room = maxBytes - utf8.encode(head + tail).length;
  let value: string;
  let caretAt: number;
  if (room < 0) {
    // Over the cap before this edit too, e.g. a prefill: only a cut at the end
    // can bring it back.
    value = clampUtf8Bytes(head + tail, maxBytes);
    caretAt = Math.min(head.length, value.length);
  } else {
    const kept = clampUtf8Bytes(next.slice(start, end), room);
    value = head + kept + tail;
    caretAt = head.length + kept.length;
  }
  input.value = value;
  input.setSelectionRange?.(caretAt, caretAt);
  return value;
}

// Lives in its own module so `$lib/i18n` can recognise `TimeoutError` without
// importing this file, which imports `$lib/i18n` itself.
export { TimeoutError, withTimeout } from './timeout';

/**
 * Copy text to the clipboard.
 *
 * Tries the OS clipboard through the backend first, then the webview's own
 * APIs. The order matters: `navigator.clipboard.writeText()` requires a secure
 * context and a live user activation, so a copy fired from a context menu or
 * after an `await` can be refused even on platforms where it usually works.
 * The DOM `execCommand` path is kept last as a fallback for a build running
 * without the backend command.
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  noteOwnClipboardText(text);
  try {
    const { writeClipboardText } = await import('$lib/api/system');
    await writeClipboardText(text);
    return true;
  } catch {
    // Fall through to the webview paths.
  }
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fall through to legacy path.
  }
  const ta = document.createElement('textarea');
  try {
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    return document.execCommand('copy');
  } catch {
    return false;
  } finally {
    // `select()` and `execCommand` can both throw after the node is attached,
    // and the catch used to return without detaching it — one orphaned
    // off-screen textarea per failed attempt, for as long as the window lives.
    ta.remove();
  }
}

/** First eight hex chars of a member or channel id, for UI labels. */
export function shortPubkey(id: string): string {
  if (!id) return '';
  return id.slice(0, 8) + '\u2026';
}

/**
 * Single characters that render like a Latin letter, folded to that letter.
 * Cyrillic and Greek homoglyphs plus a few Latin variants; case is kept on the
 * left because an uppercase Greek eta is an "H" while its lowercase is not.
 */
const CONFUSABLE_CHARS: Record<string, string> = {
  // Cyrillic
  'а': 'a', 'А': 'a', 'В': 'b', 'в': 'b', 'с': 'c', 'С': 'c', 'ԁ': 'd', 'е': 'e', 'Е': 'e',
  'һ': 'h', 'Н': 'h', 'н': 'h', 'і': 'i', 'І': 'i', 'ј': 'j', 'Ј': 'j', 'К': 'k', 'к': 'k',
  'М': 'm', 'м': 'm', 'о': 'o', 'О': 'o', 'р': 'p', 'Р': 'p', 'ԛ': 'q', 'Ԛ': 'q', 'ѕ': 's',
  'Ѕ': 's', 'Т': 't', 'т': 't', 'у': 'y', 'У': 'y', 'Ү': 'y', 'ү': 'y', 'ԝ': 'w', 'Ԝ': 'w',
  'х': 'x', 'Х': 'x', 'ӏ': 'l', 'Ӏ': 'l',
  // Greek
  'α': 'a', 'Α': 'a', 'Β': 'b', 'Ε': 'e', 'Ζ': 'z', 'Η': 'h', 'ι': 'i', 'Ι': 'i', 'κ': 'k',
  'Κ': 'k', 'Μ': 'm', 'Ν': 'n', 'ν': 'v', 'ο': 'o', 'Ο': 'o', 'ρ': 'p', 'Ρ': 'p', 'τ': 't',
  'Τ': 't', 'υ': 'u', 'Υ': 'y', 'χ': 'x', 'Χ': 'x', 'γ': 'y',
  // Latin variants
  'ı': 'i', 'ɩ': 'i', 'ǀ': 'l', 'ʟ': 'l',
};

// eslint-disable-next-line no-misleading-character-class
const COMBINING_DIACRITIC_RE = /[\u0300-\u036F\u1AB0-\u1AFF\u1DC0-\u1DFF\u20D0-\u20FF]/u;
const LOOKALIKE_SCRIPT_RE = /[\p{Script=Latin}\p{Script=Greek}\p{Script=Cyrillic}]/u;

const skeletonCache = new Map<string, string>();
const SKELETON_CACHE_MAX = 4096;

/**
 * What a name looks like rather than what it spells, for spotting two names a
 * reader cannot tell apart: `AIice` and `Alice`, `rnallory` and `mallory`, a
 * Cyrillic `а` standing in for a Latin one.
 *
 * Deliberately over-eager: it is only ever used to decide that a label needs a
 * key fragment next to it, and a false collision costs eight hex digits.
 */
export function confusableSkeleton(name: string): string {
  const cached = skeletonCache.get(name);
  if (cached !== undefined) return cached;
  let folded = '';
  let onLookalikeBase = false;
  for (const ch of name.normalize('NFKD').replace(/\p{Cf}/gu, '')) {
    // Only accents on Latin/Greek/Cyrillic letters are decoration. Elsewhere a
    // mark is the letter — a Devanagari vowel sign, a Thai vowel, kana dakuten —
    // and dropping it would call "राम" and "रमा" the same name.
    if (COMBINING_DIACRITIC_RE.test(ch)) {
      if (!onLookalikeBase) folded += ch;
      continue;
    }
    onLookalikeBase = LOOKALIKE_SCRIPT_RE.test(ch);
    folded += CONFUSABLE_CHARS[ch] ?? ch;
  }
  const skeleton = folded
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/[il1|!]/g, 'l')
    .replace(/0/g, 'o')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w');
  if (skeletonCache.size >= SKELETON_CACHE_MAX) skeletonCache.clear();
  skeletonCache.set(name, skeleton);
  return skeleton;
}

/** True when a name mixes Latin, Cyrillic and Greek letters — the usual shape
 *  of a homoglyph spoof, and nearly never of a real name. */
export function mixesLookalikeScripts(name: string): boolean {
  let scripts = 0;
  if (/\p{Script=Latin}/u.test(name)) scripts += 1;
  if (/\p{Script=Cyrillic}/u.test(name)) scripts += 1;
  if (/\p{Script=Greek}/u.test(name)) scripts += 1;
  return scripts > 1;
}

/** Roster / chat label: append a short id when the nickname is shared in-room,
 *  or only looks the same as another member's. */
export function disambiguatedMemberName(
  nickname: string | undefined | null,
  pubkey: string,
  roomNicknames: readonly (string | undefined | null)[],
): string {
  const nick = (nickname ?? '').trim();
  if (!nick) return shortPubkey(pubkey);
  const key = confusableSkeleton(nick);
  let hits = 0;
  for (const other of roomNicknames) {
    const name = (other ?? '').trim();
    if (name && confusableSkeleton(name) === key) {
      hits += 1;
      if (hits > 1) {
        return `${nick} (${shortPubkey(pubkey)})`;
      }
    }
  }
  return nick;
}

/** One run of message text, or one link found inside it. */
export interface MessageSegment {
  text: string;
  /** Present when this run is a link. Always equal to `text`. */
  href?: string;
}

/**
 * Longest link offered as clickable. Matches `EXTERNAL_URL_MAX` in
 * `commands/settings.rs`, so the UI never presents something the backend is
 * certain to refuse.
 */
const LINK_MAX_LEN = 2048;
const LINK_SCAN_MAX = LINK_MAX_LEN + 64;

/** Explicit scheme only. `www.` and bare hostnames are deliberately not
 *  matched: guessing a scheme for a string somebody typed in a room means
 *  guessing where they meant to send you. */
const LINK_RE = /https?:\/\/[^\s<>"'`]+/gi;

/** Bidi controls reorder how a host *reads* without changing where it points,
 *  so a link carrying one is left as plain text rather than made clickable.
 *  The backend refuses them too; this is what stops the UI offering it. */
// eslint-disable-next-line no-misleading-character-class
const BIDI_CONTROL_RE = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/;

/**
 * Trailing punctuation that belongs to the sentence rather than to the link.
 *
 * "see https://example.com." should not open a URL ending in a full stop.
 * Brackets are only given back when they are unbalanced, so a Wikipedia link
 * like `/wiki/Ember_(disambiguation)` keeps its closing parenthesis.
 */
function trimTrailingPunctuation(url: string): string {
  let end = url.length;
  const closers: Record<string, string> = { ')': '(', ']': '[', '}': '{' };
  // Closers minus openers per bracket pair, counted once on the first trailing
  // bracket and then kept current as closers are trimmed. Recounting per
  // character made a link ending in thousands of `)` quadratic.
  let excess: Record<string, number> | null = null;
  while (end > 0) {
    const ch = url[end - 1];
    if ('.,;:!?"\u2019\u201d'.includes(ch)) {
      end -= 1;
      continue;
    }
    const opener = closers[ch];
    if (opener) {
      if (excess === null) {
        excess = { ')': 0, ']': 0, '}': 0 };
        for (let i = 0; i < end; i++) {
          const c = url[i];
          if (c === '(') excess[')'] -= 1;
          else if (c === ')') excess[')'] += 1;
          else if (c === '[') excess[']'] -= 1;
          else if (c === ']') excess[']'] += 1;
          else if (c === '{') excess['}'] -= 1;
          else if (c === '}') excess['}'] += 1;
        }
      }
      if (excess[ch] > 0) {
        excess[ch] -= 1;
        end -= 1;
        continue;
      }
    }
    break;
  }
  return url.slice(0, end);
}

/**
 * Split message text into plain runs and links.
 *
 * Returns segments rather than markup on purpose: the caller renders each run
 * as a text node, so nothing a member types can become HTML. A message with no
 * links yields a single segment, which is the common case and costs one
 * regex scan.
 */
export function linkifyMessage(text: string): MessageSegment[] {
  if (!text) return [];
  const segments: MessageSegment[] = [];
  let cursor = 0;
  LINK_RE.lastIndex = 0;
  for (let match = LINK_RE.exec(text); match !== null; match = LINK_RE.exec(text)) {
    // Refused before trimming, so an oversized run costs one regex match and
    // nothing more. The bound is looser than `LINK_MAX_LEN` because the raw
    // match still carries the sentence punctuation trimming gives back; the
    // `usable` test below is the one that decides.
    if (match[0].length > LINK_SCAN_MAX) continue;
    const raw = trimTrailingPunctuation(match[0]);
    // Everything trimmed off goes back to the following text run, so no
    // character is ever dropped from what the sender wrote.
    LINK_RE.lastIndex = match.index + raw.length;
    const usable = raw.length <= LINK_MAX_LEN && !BIDI_CONTROL_RE.test(raw);
    if (!usable) continue;
    if (match.index > cursor) {
      segments.push({ text: text.slice(cursor, match.index) });
    }
    segments.push({ text: raw, href: raw });
    cursor = match.index + raw.length;
  }
  if (cursor < text.length) {
    segments.push({ text: text.slice(cursor) });
  }
  return segments;
}

/** An `@` the caret is currently sitting inside, in composer text. */
export interface MentionToken {
  /** Index of the `@` itself. */
  start: number;
  /** What has been typed after it, possibly empty. */
  query: string;
}

/**
 * A channel handle is 2–12 ASCII alphanumerics — no spaces, no punctuation
 * (`sanitize_channel_username` in `commands/channels.rs`) — so the token under
 * the caret is unambiguous and an inserted name never needs quoting.
 *
 * The `@` has to sit at a word boundary, or an email address would open the
 * suggestion list on every keystroke.
 */
const MENTION_TOKEN_RE = /(^|[^\p{L}\p{N}_])@([A-Za-z0-9]{0,12})$/u;

/** The `@` token the caret is inside, or null when it is not inside one. */
export function mentionTokenAt(text: string, caret: number): MentionToken | null {
  const before = text.slice(0, Math.max(0, Math.min(caret, text.length)));
  const match = MENTION_TOKEN_RE.exec(before);
  if (!match) return null;
  return { start: before.length - match[2].length - 1, query: match[2] };
}

/**
 * Replace the `@` token spanning `[start, caret)` with `@name`, and say where
 * the caret should land.
 *
 * A trailing space unless the next character already is one, so the caret ends
 * up ready for the rest of the sentence either way rather than glued to the
 * name or leaving a double space behind.
 */
export function insertMention(
  text: string,
  start: number,
  caret: number,
  name: string,
): { text: string; caret: number } {
  const head = text.slice(0, start);
  const tail = text.slice(caret);
  const spacer = tail.startsWith(' ') ? '' : ' ';
  return {
    text: `${head}@${name}${spacer}${tail}`,
    caret: head.length + name.length + 1 + spacer.length,
  };
}

/**
 * Read text from the clipboard, or `null` when there is none to read.
 *
 * The backend is tried first and is the only path that works everywhere.
 * `navigator.clipboard.readText()` is gated on a permission model WebKitGTK —
 * Tauri's Linux webview — does not grant to programmatic reads at all, and
 * `execCommand('paste')` is refused there too, so on Linux both webview paths
 * fail and "Paste eD2K link" reported the clipboard as unavailable however
 * much text was actually on it. They stay as fallbacks for a build whose
 * backend lacks the command.
 *
 * `null` is returned for "nothing readable" as well as for an empty clipboard;
 * callers treat both as nothing to paste.
 */
export async function readFromClipboard(): Promise<string | null> {
  try {
    const { readClipboardText } = await import('$lib/api/system');
    const text = await readClipboardText();
    if (text) return text;
    // An empty (or image-only) clipboard is an answer, not a failure — don't
    // retry the webview paths, which cannot do better and on Linux report a
    // permission error that would be shown as if the read had broken.
    return null;
  } catch {
    // Fall through to the webview paths.
  }
  try {
    return await navigator.clipboard.readText();
  } catch {
    // Fall through to legacy path.
  }
  const ta = document.createElement('textarea');
  try {
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.focus();
    const ok = document.execCommand('paste');
    return ok ? ta.value : null;
  } catch {
    return null;
  } finally {
    // See `copyToClipboard`: detach on every path, thrown or not.
    ta.remove();
  }
}
