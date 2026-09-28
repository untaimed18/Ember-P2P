import { getLocale } from '$lib/paraglide/runtime';

/**
 * Languages a room owner can mark as the room's default.
 *
 * Must stay in step with `CHANNEL_LANGUAGES` in
 * `src-tauri/src/network/ember/dht/publish.rs`, which gives each code its
 * one-byte wire id. The backend refuses a code it does not list.
 */
export const CHANNEL_LANGUAGES = [
  'en', 'es', 'fr', 'de', 'pt', 'it', 'ru', 'zh', 'ja', 'ko',
  'ar', 'hi', 'tr', 'pl', 'nl', 'sv', 'uk', 'vi', 'id', 'th',
  'fa', 'he', 'el', 'cs', 'ro', 'hu', 'da', 'fi', 'no', 'bn',
  'ms', 'fil', 'bg', 'hr', 'sr', 'sk', 'ca',
] as const;

export type ChannelLanguage = (typeof CHANNEL_LANGUAGES)[number];

const KNOWN = new Set<string>(CHANNEL_LANGUAGES);

export function isChannelLanguage(code: string | null | undefined): code is ChannelLanguage {
  return !!code && KNOWN.has(code);
}

/** circle-flags' language flag, copied into `static/flags/language/` on install. */
export function channelLanguageFlagSrc(code: ChannelLanguage): string {
  return `/flags/language/${code}.svg`;
}

const namesCache = new Map<string, Intl.DisplayNames | null>();

function displayNames(locale: string): Intl.DisplayNames | null {
  if (!namesCache.has(locale)) {
    let names: Intl.DisplayNames | null = null;
    try {
      names = new Intl.DisplayNames([locale], { type: 'language', fallback: 'none' });
    } catch {
      names = null;
    }
    namesCache.set(locale, names);
  }
  return namesCache.get(locale) ?? null;
}

function capitalize(name: string, locale: string): string {
  return name.charAt(0).toLocaleUpperCase(locale) + name.slice(1);
}

/** The language's name in the app language, e.g. "German" in English. */
export function channelLanguageName(code: ChannelLanguage, locale: string = getLocale()): string {
  const name = displayNames(locale)?.of(code);
  return name ? capitalize(name, locale) : code.toUpperCase();
}

/** The language's name in itself, e.g. "Deutsch". */
export function channelLanguageNativeName(code: ChannelLanguage): string {
  const name = displayNames(code)?.of(code);
  return name ? capitalize(name, code) : channelLanguageName(code);
}

/** Other names people type for a language that CLDR does not give it. */
const SEARCH_ALIASES: Partial<Record<ChannelLanguage, string>> = {
  bn: 'bengali',
  fa: 'farsi',
  fil: 'tagalog',
};

/**
 * Lowercase text a picker search matches against: the name in the app
 * language, the name in itself, the English name and any alias, so "German"
 * still finds Deutsch with the app in French.
 */
export function channelLanguageSearchText(code: ChannelLanguage, locale: string = getLocale()): string {
  return [
    code,
    channelLanguageName(code, locale),
    channelLanguageNativeName(code),
    channelLanguageName(code, 'en'),
    SEARCH_ALIASES[code] ?? '',
  ]
    .join(' ')
    .toLocaleLowerCase();
}

/** Every language, sorted by its name in the app language. */
export function sortedChannelLanguages(locale: string = getLocale()): ChannelLanguage[] {
  const collator = new Intl.Collator(locale);
  return [...CHANNEL_LANGUAGES].sort((a, b) =>
    collator.compare(channelLanguageName(a, locale), channelLanguageName(b, locale)),
  );
}
