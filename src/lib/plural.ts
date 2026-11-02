import { getLocale } from '$lib/paraglide/runtime';

/**
 * The variants of one plural message group, keyed by CLDR category.
 *
 * `one` is used for exactly 1, and for the other counts a locale files under
 * `one` — Russian 21, 31, 101, … — only when the group sets `oneShowsCount`.
 * Most `_one` strings write the number into the message as `{count}` (or
 * whatever the group calls it), which is what lets them stand in for 21: the
 * noun after it takes the same form in Russian. A `_one` string that names a
 * single thing instead ("this server", "{name} is typing") must not, so those
 * groups leave the flag off and such counts get `other`.
 *
 * French and Portuguese file 0 under `one` too. It never takes `one` here:
 * "0 fichiers" is the form people expect from a count, and those strings say
 * the plural.
 *
 * `few` and `many` are optional and fall back to `other`. A group only carries
 * `_few` where a locale needs a distinct form for it: Russian and Polish 2–4,
 * 22–24, … Their `_other` strings are written in the form that `many`
 * (0, 5–20, …) takes, so no group needs a separate `_many` yet.
 */
export interface PluralForms {
  one: () => string;
  /** `one` shows the count it is given — or is the noun after a count shown
   *  beside it — so it also serves the counts besides 1 that the locale files
   *  under `one`. */
  oneShowsCount?: boolean;
  few?: () => string;
  many?: () => string;
  other: () => string;
}

const RULES = new Map<string, Intl.PluralRules>();

/** The CLDR plural category `count` falls in for `locale`. */
export function pluralCategory(count: number, locale: string = getLocale()): Intl.LDMLPluralRule {
  let rules = RULES.get(locale);
  if (!rules) {
    rules = new Intl.PluralRules(locale);
    RULES.set(locale, rules);
  }
  return rules.select(count);
}

/**
 * Pick the variant of a plural message that fits `count` in the app language.
 *
 * ```ts
 * plural(n, {
 *   one: () => m.library_deleted_one({ count: formatNumber(n) }),
 *   oneShowsCount: true,
 *   few: () => m.library_deleted_few({ count: formatNumber(n) }),
 *   other: () => m.library_deleted_other({ count: formatNumber(n) }),
 * });
 * ```
 */
export function plural(count: number, forms: PluralForms, locale: string = getLocale()): string {
  if (count === 1) return forms.one();
  switch (pluralCategory(count, locale)) {
    case 'one':
      return count !== 0 && forms.oneShowsCount ? forms.one() : forms.other();
    case 'few':
      return (forms.few ?? forms.other)();
    case 'many':
      return (forms.many ?? forms.other)();
    default:
      return forms.other();
  }
}
