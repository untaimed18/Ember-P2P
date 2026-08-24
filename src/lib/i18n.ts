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
import type { SpamReason } from '$lib/types';

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
  // exact match first (e.g. zh-CN), then language-only (e.g. es),
  // then script/region-aware Chinese, then primary-subtag match.
  const exact = compiled.find((l) => l.toLowerCase() === nav);
  if (exact) return exact;
  const prefix = compiled.find((l) => l.toLowerCase() === lang);
  if (prefix) return prefix;
  if (lang === 'zh') {
    // Match whole subtags, not substrings. An explicit script wins over the
    // region, so `zh-Hans-HK` is Simplified even though its region normally
    // implies Traditional — a substring test read the `hk` and got it
    // backwards.
    const parts = nav.split(/[-_]/);
    const hant = parts.includes('hant')
      ? true
      : parts.includes('hans')
        ? false
        : parts.some((part) => part === 'tw' || part === 'hk' || part === 'mo');
    const want = hant ? 'zh-tw' : 'zh-cn';
    const preferred = compiled.find((l) => l.toLowerCase() === want);
    if (preferred) return preferred;
  }
  const regional = compiled.find((l) => {
    const lower = l.toLowerCase();
    return lower.startsWith(`${lang}-`) || lower.startsWith(`${lang}_`);
  });
  return regional ?? baseLocale;
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
    case 'fr':
      return m.language_name_fr({}, { locale });
    case 'pt-BR':
      return m.language_name_pt_BR({}, { locale });
    case 'de':
      return m.language_name_de({}, { locale });
    case 'zh-CN':
      return m.language_name_zh_CN({}, { locale });
    case 'it':
      return m.language_name_it({}, { locale });
    case 'ru':
      return m.language_name_ru({}, { locale });
    case 'zh-TW':
      return m.language_name_zh_TW({}, { locale });
    default:
      return locale;
  }
}

/**
 * Representative country flag for a UI locale, using the same
 * `/flags/*.svg` circle-flags assets as Transfers. Languages aren't
 * countries — this is a recognition aid for the Settings picker only.
 * Returns null when no sensible mapping exists.
 */
export function localeFlagSrc(locale: Locale): string | null {
  const code = (() => {
    switch (locale) {
      case 'en':
        return 'us';
      case 'es':
        return 'es';
      case 'fr':
        return 'fr';
      case 'pt-BR':
        return 'br';
      case 'de':
        return 'de';
      case 'zh-CN':
        return 'cn';
      case 'it':
        return 'it';
      case 'ru':
        return 'ru';
      case 'zh-TW':
        return 'tw';
      default:
        return null;
    }
  })();
  return code ? `/flags/${code}.svg` : null;
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
  // Always pass the argument object. Paraglide compiles a `{detail}` message to
  // `${i?.detail}` with no default for its inputs parameter, so calling it bare
  // renders the literal string "undefined" — and a handful of backend sites
  // emit these codes through the context-free `coded()`.
  return fn({ detail: context ?? '' });
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
 * Every `TransferFailureCode` the backend can put on a transfer row.
 *
 * The codes come from the `transfer_failure_codes!` table in
 * `src-tauri/src/network/ed2k/transfer.rs`, which is the only place a failure
 * sentence is minted: `classify_failure` reduces every download and upload
 * failure to one of these before it leaves Rust — deliberately, so peer IPs and
 * local paths from anyhow chains cannot leak into the UI — and the sites that
 * assign the field directly (`commands/transfers.rs`,
 * `commands/collections.rs`, `storage/database.rs`) pick from the same table.
 *
 * `scripts/backend-codes.test.mjs` requires this map to name exactly the codes
 * that table declares, so a variant added in Rust without a row here fails
 * `npm test` rather than quietly rendering English in the other eight locales.
 */
const TRANSFER_FAILURE_CODES = new Map<string, () => string>([
  ['cancelled', m.transfers_failure_reason_cancelled],
  ['remote_missing_file', m.transfers_failure_reason_remote_missing],
  // Same wording as the row badge, which the Ember page and docs also use.
  ['ember_content_hash_mismatch', m.transfers_ember_mismatch_label],
  ['aich_hash_mismatch', m.transfers_failure_reason_aich_mismatch],
  ['hash_mismatch', m.transfers_failure_reason_hash_mismatch],
  ['download_timed_out', m.transfers_failure_reason_download_timeout],
  ['insufficient_disk_space', m.transfers_failure_reason_insufficient_disk],
  ['connection_failed', m.transfers_failure_reason_connection_failed],
  ['peer_handshake_failed', m.transfers_failure_reason_handshake_failed],
  ['queue_wait_interrupted', m.transfers_failure_reason_queue_wait],
  ['hashset_request_failed', m.transfers_failure_reason_hashset_failed],
  ['connection_lost', m.transfers_failure_reason_connection_lost],
  ['permanent_failure', m.transfers_failure_reason_permanent],
  ['transient_failure', m.transfers_failure_reason_transient],
  ['network_channel_unavailable', m.transfers_failure_reason_no_channel],
  ['ember_pin_corrupt', m.transfers_failure_reason_ember_pin_corrupt],
  ['aich_pin_corrupt', m.transfers_failure_reason_aich_pin_corrupt],
]);

/**
 * Every `TransferHealthCode`, from the `transfer_health_codes!` table in
 * `src-tauri/src/sharing/manager.rs`. Pinned to that table by
 * `scripts/backend-codes.test.mjs` the same way the failure codes are.
 *
 * `retrying_after` is absent: its sentence names the failure being retried, so
 * it is composed in {@link transferHealthReasonText} from the row's
 * `failure_code` rather than rendered from a single message.
 */
const TRANSFER_HEALTH_CODES = new Map<string, () => string>([
  ['queued_sources', m.transfers_health_reason_queued_sources],
  ['waiting_sources', m.transfers_health_reason_waiting_sources],
  ['no_data', m.transfers_health_reason_no_data],
  ['idle', m.transfers_health_reason_idle],
  ['retrying_sources', m.transfers_health_reason_retrying_sources],
  ['still_searching', m.transfers_health_reason_still_searching],
  ['no_sources', m.transfers_health_reason_no_sources],
  ['waiting_slot', m.transfers_health_reason_waiting_slot],
]);

/**
 * Every `SpamReasonCode`, from the `spam_reason_codes!` table in
 * `src-tauri/src/search/spam.rs`.
 *
 * Unlike the transfer tables these take arguments: most reasons interpolate the
 * weight they contributed, and some a percentage or a vote count. The numbers
 * ride the wire as fields on the reason so each locale can put them where its
 * own sentence needs them. `scripts/backend-codes.test.mjs` checks both that
 * every code has a row and that the `{placeholders}` on the two sides agree.
 */
const SPAM_REASON_CODES = new Map<string, (reason: SpamReason) => string>([
  // The whitelist verdict is the same sentence the Mark Not Spam action shows
  // optimistically, so the two share a key rather than drifting apart.
  ['not_spam_marked', () => m.search_spam_reason_manual_not_spam()],
  ['known_hash', (r) => m.search_spam_reason_known_hash({ weight: r.weight ?? 0 })],
  ['exact_filename', (r) => m.search_spam_reason_exact_filename({ weight: r.weight ?? 0 })],
  [
    'very_similar_name',
    (r) => m.search_spam_reason_very_similar_name({ percent: r.percent ?? 0, weight: r.weight ?? 0 }),
  ],
  [
    'similar_name',
    (r) => m.search_spam_reason_similar_name({ percent: r.percent ?? 0, weight: r.weight ?? 0 }),
  ],
  [
    'reordered_name',
    (r) => m.search_spam_reason_reordered_name({ percent: r.percent ?? 0, weight: r.weight ?? 0 }),
  ],
  [
    'loosely_similar_name',
    (r) =>
      m.search_spam_reason_loosely_similar_name({ percent: r.percent ?? 0, weight: r.weight ?? 0 }),
  ],
  ['size_signature', (r) => m.search_spam_reason_size_signature({ weight: r.weight ?? 0 })],
  ['fake_pattern', (r) => m.search_spam_reason_fake_pattern({ weight: r.weight ?? 0 })],
  [
    'community_fake_majority',
    (r) =>
      m.search_spam_reason_community_fake_majority({
        votes: r.votes ?? 0,
        total: r.total ?? 0,
        weight: r.weight ?? 0,
      }),
  ],
  [
    'community_fake_some',
    (r) =>
      m.search_spam_reason_community_fake_some({
        votes: r.votes ?? 0,
        total: r.total ?? 0,
        weight: r.weight ?? 0,
      }),
  ],
  ['result_rated_fake', (r) => m.search_spam_reason_result_rated_fake({ weight: r.weight ?? 0 })],
  [
    'batch_name_many_hashes',
    (r) =>
      m.search_spam_reason_batch_name_many_hashes({ count: r.count ?? 0, weight: r.weight ?? 0 }),
  ],
  [
    'batch_hash_many_names',
    (r) =>
      m.search_spam_reason_batch_hash_many_names({ count: r.count ?? 0, weight: r.weight ?? 0 }),
  ],
  [
    'batch_source_concentration',
    (r) => m.search_spam_reason_batch_source_concentration({ weight: r.weight ?? 0 }),
  ],
  ['spam_source_ip', (r) => m.search_spam_reason_spam_source_ip({ weight: r.weight ?? 0 })],
  [
    'spam_server_all_sources',
    (r) => m.search_spam_reason_spam_server_all_sources({ weight: r.weight ?? 0 }),
  ],
  [
    'spam_server_influence',
    (r) => m.search_spam_reason_spam_server_influence({ weight: r.weight ?? 0 }),
  ],
  [
    'server_ratio_high',
    (r) => m.search_spam_reason_server_ratio_high({ percent: r.percent ?? 0, weight: r.weight ?? 0 }),
  ],
  [
    'server_ratio_elevated',
    (r) =>
      m.search_spam_reason_server_ratio_elevated({ percent: r.percent ?? 0, weight: r.weight ?? 0 }),
  ],
  ['aggressive_boost', (r) => m.search_spam_reason_aggressive_boost({ weight: r.weight ?? 0 })],
  ['no_signals', () => m.search_spam_reason_no_signals()],
]);

/**
 * Localize the coded spam reasons on a search hit, falling back to the English
 * list when the row carries none.
 *
 * Two things can leave `details` empty: a backend older than the codes, and the
 * optimistic patch behind Mark spam / Mark not spam, which writes an
 * already-translated sentence straight into `spam_reasons`. Neither should be
 * dropped, so the fallback list is rendered verbatim.
 */
export function spamReasonTexts(
  details: SpamReason[] | undefined | null,
  english: string[] | undefined | null,
): string[] {
  if (details?.length) {
    return details.map((reason) => SPAM_REASON_CODES.get(reason.code)?.(reason) ?? reason.text);
  }
  return english ?? [];
}

/** Stages, from `infer_stage_from_error` plus the two literal call sites. */
const TRANSFER_FAILURE_STAGES = new Map<string, () => string>([
  ['tcp_connect', m.transfers_failure_stage_tcp_connect],
  ['hello_wait', m.transfers_failure_stage_hello_wait],
  ['emule_info_wait', m.transfers_failure_stage_emule_info_wait],
  ['file_status_wait', m.transfers_failure_stage_file_status_wait],
  ['queue_wait', m.transfers_failure_stage_queue_wait],
  ['hashset_wait', m.transfers_failure_stage_hashset_wait],
  ['data_wait', m.transfers_failure_stage_data_wait],
  ['cancelled', m.transfers_failure_stage_cancelled],
  ['disk_space', m.transfers_failure_stage_disk_space],
  ['unknown', m.common_unknown],
]);

/** Kinds, from `failure_kind_name` in `src-tauri/src/network/ed2k/transfer.rs`. */
const TRANSFER_FAILURE_KINDS = new Map<string, () => string>([
  ['transient', m.transfers_failure_kind_transient],
  ['permanent', m.transfers_failure_kind_permanent],
  ['download_timeout', m.transfers_failure_kind_download_timeout],
  ['insufficient_disk', m.transfers_failure_kind_insufficient_disk],
]);

/**
 * Localize a transfer's failure from its `failure_code`.
 *
 * `reason` is the backend's own English, shown only when the row carries no
 * code this UI knows — which no live producer does any more, so in practice
 * this is the "a newer backend added a variant" path. Showing it beats
 * blanking the row.
 */
export function transferFailureReasonText(
  reason: string | undefined | null,
  code?: string | undefined | null,
): string {
  if (code) {
    const coded = TRANSFER_FAILURE_CODES.get(code);
    if (coded) return coded();
  }
  return reason ?? '';
}

/**
 * Localize a transfer's health state from its `health_code`.
 *
 * One health reason is composed rather than canned: `retrying_after` names the
 * failure being retried, which the row carries alongside as `failure_code`.
 * Recomposing it from two translated halves keeps that path localized without a
 * key per failure, and the message carries a colon so languages that capitalize
 * differently from English still read correctly.
 */
export function transferHealthReasonText(
  reason: string | undefined | null,
  code?: string | undefined | null,
  failureCode?: string | undefined | null,
): string {
  if (code === 'retrying_after') {
    const failure = failureCode ? TRANSFER_FAILURE_CODES.get(failureCode) : undefined;
    if (failure) return m.transfers_health_reason_retrying_after({ reason: failure() });
  } else if (code) {
    const coded = TRANSFER_HEALTH_CODES.get(code);
    if (coded) return coded();
  }
  return reason ?? '';
}

/** Localize a transfer's `failure_stage` (shown in the status tooltip). */
export function transferFailureStageText(stage: string | undefined | null): string {
  if (!stage) return '';
  return TRANSFER_FAILURE_STAGES.get(stage)?.() ?? stage;
}

/** Localize a transfer's `failure_kind` (shown in the status tooltip). */
export function transferFailureKindText(kind: string | undefined | null): string {
  if (!kind) return '';
  return TRANSFER_FAILURE_KINDS.get(kind)?.() ?? kind;
}

/**
 * The active spam-filter profile, as a bare noun for the score tooltip.
 *
 * Deliberately not the `settings_spam_profile_*` strings: those carry a
 * parenthetical ("Balanced (recommended)") that would nest a second set of
 * brackets inside "Score 5/10 (…)". The backend value is a stable code from
 * `SpamFilterProfile`, so an unrecognized one is shown verbatim rather than
 * dropped.
 */
const SPAM_PROFILES = new Map<string, () => string>([
  ['relaxed', () => m.search_spam_profile_relaxed()],
  ['balanced', () => m.search_spam_profile_balanced()],
  ['aggressive', () => m.search_spam_profile_aggressive()],
]);

export function spamProfileText(profile: string | undefined | null): string {
  if (!profile) return '';
  return SPAM_PROFILES.get(profile)?.() ?? profile;
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
  if (raw.includes('SecureFriendV2Required')) {
    return m.error_secure_friend_v2_required();
  }
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
    case 'ChatEncryptFailed':
    case 'Failed to encrypt chat message':
      return m.error_chat_encrypt_failed();
    default:
      // Tier 3: unknown plain string — surface as-is.
      return raw;
  }
}
