import { getLocale } from '$lib/paraglide/runtime';

/**
 * The variants of one plural message group, keyed by CLDR category.
 *
 * `one` is only ever used for exactly 1. The catalog's `_one` strings spell the
 * number out ("1 file", "this server"), so they cannot stand in for the other
 * counts some locales also file under `one` — French and Portuguese 0, Russian
 * 21, 31, … — and those get `other` instead.
 *
 * `few` and `many` are optional and fall back to `other`. A group only carries
 * `_few` where a locale needs a distinct form for it: Russian 2–4, 22–24, …
 * Russian `_other` strings are written in the form that `many` (0, 5–20, …)
 * takes, so no group needs a separate `_many` yet.
 */
export interface PluralForms {
  one: () => string;
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
 *   one: m.library_deleted_one,
 *   few: () => m.library_deleted_few({ count: n }),
 *   other: () => m.library_deleted_other({ count: n }),
 * });
 * ```
 */
export function plural(count: number, forms: PluralForms, locale: string = getLocale()): string {
  if (count === 1) return forms.one();
  switch (pluralCategory(count, locale)) {
    case 'few':
      return (forms.few ?? forms.other)();
    case 'many':
      return (forms.many ?? forms.other)();
    default:
      return forms.other();
  }
}
