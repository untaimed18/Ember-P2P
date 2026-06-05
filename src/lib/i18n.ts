/**
 * Project-wide i18n facade over Paraglide JS.
 *
 * Components import message functions directly from
 * `$lib/paraglide/messages.js` (`import * as m from ...`) and use
 * `m.foo()` at call sites — that's the path that gets type-checked
 * and tree-shaken. This module exists for things that don't fit
 * cleanly into a single `m.*` call:
 *
 *  - Reading / changing the active locale at runtime.
 *  - Mapping a backend error code (string identifier) to a
 *    translated message via `translateErrorCode`.
 *  - Listing the available locales so the Settings picker can
 *    render the right options.
 *
 * Locale changes go through `setLocale()` (Paraglide), which writes
 * to localStorage under the `PARAGLIDE_LOCALE` key and triggers a
 * full page reload by default. A reload is the simplest correct
 * option for a desktop app: it guarantees that every cached
 * `m.*()` call site picks up the new strings without us having to
 * thread a Svelte store through every component.
 */
import {
  baseLocale,
  locales,
  getLocale,
  setLocale,
  localStorageKey,
  type Locale,
} from '$lib/paraglide/runtime';
import * as m from '$lib/paraglide/messages';

export { baseLocale, locales, getLocale, setLocale };
export type { Locale };

/**
 * Whether the active locale was explicitly chosen by the user
 * (i.e. there is a value in `localStorage[PARAGLIDE_LOCALE]`)
 * versus inferred from `navigator.language` / `baseLocale`. The
 * Settings picker uses this to decide whether the "System"
 * radio is the currently-selected one.
 */
export function hasExplicitLocale(): boolean {
  if (typeof localStorage === 'undefined') return false;
  try {
    return localStorage.getItem(localStorageKey) !== null;
  } catch {
    return false;
  }
}

/**
 * Clear the user's explicit locale choice and reload, letting
 * Paraglide's strategy chain fall through to `preferredLanguage`
 * (the OS / browser locale) and then `baseLocale`. The reload
 * mirrors what `setLocale()` does for explicit choices — every
 * cached `m.*()` call site picks up the new locale uniformly.
 */
export function useSystemLocale(): void {
  if (typeof localStorage !== 'undefined') {
    try {
      localStorage.removeItem(localStorageKey);
    } catch {
      // ignore — quota / private mode; reload still does the right
      // thing if a stale value lingers (it just stays selected).
    }
  }
  if (typeof location !== 'undefined') {
    location.reload();
  }
}

/**
 * The locale that `preferredLanguage` would resolve to right
 * now — i.e. the first compiled locale whose language tag is a
 * prefix match for `navigator.language`, otherwise the base.
 * Used by the Settings picker to show e.g. "System (Spanish)"
 * so the user knows what they'd be following.
 */
export function systemLocale(): Locale {
  if (typeof navigator === 'undefined') return baseLocale;
  const nav = (navigator.languages?.[0] ?? navigator.language ?? '').toLowerCase();
  if (!nav) return baseLocale;
  const lang = nav.split('-')[0];
  const compiled = locales as readonly Locale[];
  // exact match first, then language-only prefix match.
  const exact = compiled.find((l) => l.toLowerCase() === nav);
  if (exact) return exact;
  const prefix = compiled.find((l) => l.toLowerCase() === lang);
  return prefix ?? baseLocale;
}

/**
 * Apply the current locale to the `<html lang>` attribute. Run on
 * app boot (and on locale change via the page-reload that
 * `setLocale` triggers). Screen readers, browser spellcheck, and
 * `:lang()` CSS selectors all key off this attribute.
 */
export function applyDocumentLang(): void {
  if (typeof document === 'undefined') return;
  const locale = getLocale();
  document.documentElement.setAttribute('lang', locale);
}

/**
 * Human-readable name for each locale, in that locale's own
 * language. Pulled from the message catalog so the Settings picker
 * shows e.g. "Español" while the rest of the UI is in English —
 * the standard convention for language switchers (users recognize
 * their own language faster than a translation of it).
 */
export function languageLabel(locale: Locale): string {
  switch (locale) {
    case 'en':
      return m.language_name_en({}, { locale });
    case 'es':
      return m.language_name_es({}, { locale });
    default:
      return locale;
  }
}

/**
 * Coded-error envelope emitted by the Rust command layer
 * (`src-tauri/src/commands/errors.rs`). The `__coded` sentinel
 * disambiguates our envelopes from arbitrary error strings that
 * merely happen to be valid JSON.
 */
type CodedError = {
  __coded: true;
  code: string;
  /** English fallback, used when the UI has no key for `code`. */
  message: string;
  /** Optional dynamic detail (e.g. an underlying error's text). */
  context?: string;
};

function parseCodedError(raw: string): CodedError | null {
  // Cheap guard before attempting a JSON parse — the vast majority
  // of error strings are plain text and shouldn't pay parse cost.
  if (raw.length < 2 || raw[0] !== '{' || !raw.includes('"__coded"')) {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(raw);
    if (
      parsed &&
      typeof parsed === 'object' &&
      (parsed as { __coded?: unknown }).__coded === true &&
      typeof (parsed as { code?: unknown }).code === 'string' &&
      typeof (parsed as { message?: unknown }).message === 'string'
    ) {
      return parsed as CodedError;
    }
  } catch {
    // Not JSON after all — fall through to plain-string handling.
  }
  return null;
}

/**
 * Resolve a backend error `code` to its translated message by
 * looking up the `error_<code>` Paraglide message at runtime.
 *
 * The command layer emits ~250 distinct codes (see
 * `src-tauri/src/commands/errors.rs`); a hand-maintained switch
 * would be pure boilerplate that drifts out of sync. Paraglide
 * compiles each message to a named export, so the namespace object
 * doubles as a `Record<string, MessageFn>` we can index dynamically.
 *
 * Codes that carry dynamic detail interpolate it via the message's
 * `{detail}` placeholder; codes without detail ignore the argument.
 * Returns `undefined` when no `error_<code>` key exists, letting the
 * caller fall back to the envelope's embedded English `message` —
 * so a newer backend never yields a blank error on an older UI.
 */
type MessageFn = (inputs?: Record<string, unknown>, options?: unknown) => string;
const messageFns = m as unknown as Record<string, MessageFn | undefined>;

function translateCode(code: string, context: string | undefined): string | undefined {
  const fn = messageFns[`error_${code}`];
  if (typeof fn !== 'function') return undefined;
  return context !== undefined ? fn({ detail: context }) : fn();
}

/**
 * Map a Tauri command error onto a translated message.
 *
 * Three tiers, in priority order:
 *  1. A coded envelope from `commands::errors` — decode `code`,
 *     interpolate `context`, fall back to the envelope's English
 *     `message` for an unregistered code.
 *  2. A legacy bare code string (`"FriendNotFound"`, etc.) emitted
 *     by older friend/KAD command paths.
 *  3. Any other string — shown verbatim (foreign/underlying errors).
 *
 * Adding new error codes is always non-breaking: an unmapped code
 * degrades to its embedded English message rather than disappearing.
 */
export function translateErrorCode(input: unknown): string {
  return translateError(input);
}

/**
 * Localize a network `degraded_reason` code (see `NetworkStats`). The store
 * keeps a stable code rather than an English string so the reason re-renders
 * in the active locale. Unknown values fall back to the raw string (or empty)
 * so a newer backend/store code can't blank the UI.
 */
export function degradedReasonText(reason: string | undefined): string {
  switch (reason) {
    case 'stale':
      return m.network_degraded_stale();
    case 'limited':
      return m.network_degraded_limited();
    case 'establishing':
      return m.network_degraded_establishing();
    default:
      return reason ?? '';
  }
}

/**
 * Localize a backend firewall-status string (eMule `FirewallStatus` debug
 * form: "Open" / "Firewalled" / "Unknown"). Reuses the existing firewall
 * labels. Any unrecognized value is shown verbatim rather than dropped.
 */
export function firewallStatusText(status: string | undefined): string {
  switch (status) {
    case 'Open':
      return m.kad_firewall_open();
    case 'Firewalled':
      return m.kad_firewall_firewalled();
    case 'Unknown':
    case undefined:
    case '':
      return m.common_unknown();
    default:
      return status;
  }
}

/**
 * Like {@link translateErrorCode}, but lets the caller supply the
 * message shown when the error carries no usable string (e.g. a
 * thrown non-Error value). Call sites that previously had their own
 * `e instanceof Error ? e.message : … : m.something()` ternary pass
 * their domain-specific fallback here so coded backend errors are
 * still decoded while the bespoke fallback is preserved.
 */
export function translateError(input: unknown, fallback?: string): string {
  const raw = input instanceof Error
    ? input.message
    : typeof input === 'string'
    ? input
    : '';
  if (!raw) return fallback ?? m.error_unknown();

  // Tier 1: structured coded envelope.
  const coded = parseCodedError(raw);
  if (coded) {
    const translated = translateCode(coded.code, coded.context);
    if (translated !== undefined) return translated;
    // Unregistered code (e.g. newer backend, older UI): show the
    // embedded English framing and append any dynamic detail so we
    // never drop information the user might need.
    const base = coded.message || m.error_unknown();
    return coded.context ? `${base}: ${coded.context}` : base;
  }

  // Tier 2: legacy bare codes. The Rust side emits these as the
  // exact error message (no surrounding text) to match. Any
  // additional context (e.g. an offending hash) belongs in a
  // separate field, not concatenated into the code.
  switch (raw) {
    case 'FriendNotFound':
      return m.error_friend_not_found();
    case 'FriendOffline':
      return m.error_friend_offline();
    case 'InvalidHash':
      return m.error_invalid_hash();
    case 'InvalidNickname':
      return m.error_invalid_nickname();
    case 'NetworkUnavailable':
      return m.error_network_unavailable();
    case 'AlreadyFriend':
      return m.error_already_friend();
    case 'SelfAdd':
      return m.error_self_add();
    default:
      // Tier 3: unknown plain string — surface as-is.
      return raw;
  }
}
