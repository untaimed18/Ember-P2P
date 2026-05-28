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
 * Map a Tauri command error string (or any backend error) onto a
 * translated message. The Rust side increasingly returns stable
 * error CODES rather than free-form English (`"FriendNotFound"`,
 * `"InvalidHash"`, etc.) so we can localize them client-side
 * without round-tripping through every `format!` site in the
 * backend.
 *
 * Falls back to the original message when no mapping exists, so
 * adding new error codes is a non-breaking change — old callers
 * keep showing the raw string until a key is registered here.
 */
export function translateErrorCode(input: unknown): string {
  const raw = input instanceof Error
    ? input.message
    : typeof input === 'string'
    ? input
    : '';
  if (!raw) return m.error_unknown();

  // Stable backend codes. The Rust side should emit these as the
  // exact error message (no surrounding text) to match. Any
  // additional context (e.g. an offending hash) belongs in a
  // separate field on the command's error type, not concatenated
  // into the code.
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
      return raw;
  }
}
