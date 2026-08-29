import { getLocale } from '$lib/i18n';

/**
 * Format a byte count as a human-readable string (e.g. "1.5 MB").
 * Uses iterative division to avoid floating-point edge cases.
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
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
  const formatted = val.toFixed(1);
  return `${formatted.endsWith('.0') ? formatted.slice(0, -2) : formatted} ${units[i]}`;
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

/** Format bytes/sec as a speed string (e.g. "1.5 MB/s"). */
export function formatSpeed(bytesPerSec: number): string {
  return `${formatBytes(bytesPerSec)}/s`;
}

/** Format remaining time given total size, transferred bytes, and current speed. */
export function formatEta(totalSize: number, transferred: number, speed: number): string {
  if (!Number.isFinite(speed) || !Number.isFinite(totalSize) || !Number.isFinite(transferred)) return '\u2014';
  if (speed <= 0 || transferred >= totalSize) return '\u2014';
  const remaining = totalSize - transferred;
  const secs = Math.round(remaining / speed);
  if (secs < 60) return `${secs}s`;
  const days = Math.floor(secs / 86400);
  const hrs = Math.floor((secs % 86400) / 3600);
  const mins = Math.floor((secs % 3600) / 60);
  if (days > 0) return `${days}d ${hrs}h`;
  if (hrs > 0) return `${hrs}h ${mins}m`;
  return `${mins}m`;
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

/**
 * Format milliseconds as HH:MM (eMule CastSecondsToHM style).
 * Returns "\u2014" for zero or invalid values.
 *
 * @param ms - Duration in **milliseconds** (not seconds).
 *   Callers passing seconds should use {@link formatDurationSecs} instead.
 */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return '\u2014';
  const totalSecs = Math.floor(ms / 1000);
  const hrs = Math.floor(totalSecs / 3600);
  const mins = Math.floor((totalSecs % 3600) / 60);
  if (hrs > 0) return `${hrs}:${String(mins).padStart(2, '0')}`;
  if (mins > 0) return `${mins} min`;
  return `${totalSecs}s`;
}

/** Format seconds as a human-readable duration (e.g. "2h 15m"). */
export function formatDurationSecs(secs: number): string {
  if (!Number.isFinite(secs) || secs < 0) return '\u2014';
  if (secs === 0) return '0s';
  const days = Math.floor(secs / 86400);
  const hrs = Math.floor((secs % 86400) / 3600);
  const mins = Math.floor((secs % 3600) / 60);
  if (days > 0) return `${days}d ${hrs}h`;
  if (hrs > 0) return `${hrs}h ${mins}m`;
  if (mins > 0) return `${mins}m`;
  return `${Math.floor(secs)}s`;
}

/** Format remaining size + ETA combined (eMule Remaining column style). */
export function formatRemaining(totalSize: number, transferred: number, speed: number): string {
  if (transferred >= totalSize) return '\u2014';
  const remaining = totalSize - transferred;
  const remainStr = formatBytes(remaining);
  // Guard against a non-finite speed (NaN/Infinity) — `NaN <= 0` is false, so
  // without `Number.isFinite` the ETA math below would render "NaNd NaNh".
  if (!Number.isFinite(speed) || speed <= 0) return remainStr;
  const secs = Math.round(remaining / speed);
  const days = Math.floor(secs / 86400);
  const hrs = Math.floor((secs % 86400) / 3600);
  const mins = Math.floor((secs % 3600) / 60);
  let timeStr: string;
  if (days > 0) timeStr = `${days}d ${hrs}h`;
  else if (hrs > 0) timeStr = `${hrs}h ${mins}m`;
  else if (mins > 0) timeStr = `${mins}m`;
  else timeStr = `${secs}s`;
  return `${timeStr} (${remainStr})`;
}

/** Format a percentage with smart decimal handling. */
export function formatPercent(value: number, decimals = 1): string {
  if (!Number.isFinite(value) || value <= 0) return '0%';
  if (value >= 100) return '100%';
  return `${value.toFixed(decimals)}%`;
}

/** Truncate a hex hash with ellipsis. */
export function truncateHash(hash: string, len = 16): string {
  if (hash.length <= len) return hash;
  return `${hash.slice(0, len)}\u2026`;
}

/** Pluralize a noun based on count. */
export function pluralize(count: number, singular: string, plural?: string): string {
  return count === 1 ? `${count} ${singular}` : `${count} ${plural || singular + 's'}`;
}

/**
 * Race a promise (in practice a Tauri `invoke()`) against a deadline.
 *
 * K24: without this the UI hangs indefinitely when the backend is wedged —
 * blocked on a slow DNS resolution, a stuck oneshot receiver — and a poll's
 * in-flight guard stays latched for the rest of the session. Rejects with a
 * normal `Error` carrying a recognisable message so callers can show a
 * "timed out, please try again" toast instead of a spinner that never
 * resolves.
 *
 * Only for calls whose expected duration is short and bounded. Anything
 * legitimately long-running — library scans, file hashing, native file
 * dialogs waiting on the user — must not be wrapped: a deadline there
 * reports failure for an operation that is still succeeding.
 */
export function withTimeout<T>(promise: Promise<T>, label: string, ms = 20_000): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`${label} timed out after ${Math.round(ms / 1000)}s`));
    }, ms);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

/** Copy text to clipboard with a DOM fallback for WebView2 / denied permissions. */
export async function copyToClipboard(text: string): Promise<boolean> {
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

/** Roster / chat label: append a short id when the nickname is shared in-room. */
export function disambiguatedMemberName(
  nickname: string | undefined | null,
  pubkey: string,
  roomNicknames: readonly (string | undefined | null)[],
): string {
  const nick = (nickname ?? '').trim();
  if (!nick) return shortPubkey(pubkey);
  const lower = nick.toLowerCase();
  let hits = 0;
  for (const other of roomNicknames) {
    if ((other ?? '').trim().toLowerCase() === lower) {
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
  while (end > 0) {
    const ch = url[end - 1];
    if ('.,;:!?"\u2019\u201d'.includes(ch)) {
      end -= 1;
      continue;
    }
    const opener = closers[ch];
    if (opener) {
      const slice = url.slice(0, end);
      let opens = 0;
      let closes = 0;
      for (const c of slice) {
        if (c === opener) opens += 1;
        else if (c === ch) closes += 1;
      }
      if (closes > opens) {
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

/** Read text from the clipboard with a DOM fallback for WebView2 / denied permissions. */
export async function readFromClipboard(): Promise<string | null> {
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
