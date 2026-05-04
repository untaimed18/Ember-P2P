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
  type Locale,
} from '$lib/paraglide/runtime';
import * as m from '$lib/paraglide/messages';

export { baseLocale, locales, getLocale, setLocale };
export type { Locale };

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
