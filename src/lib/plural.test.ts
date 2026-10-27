import { describe, expect, it } from 'vitest';
import { plural, pluralCategory, type PluralForms } from './plural';

/** Forms that name themselves, so a test reads which variant was chosen. */
const all: PluralForms = {
  one: () => 'one',
  few: () => 'few',
  many: () => 'many',
  other: () => 'other',
};

const twoForm: PluralForms = { one: () => 'one', other: () => 'other' };

describe('pluralCategory', () => {
  it('follows CLDR for the shipped locales', () => {
    expect(pluralCategory(1, 'en')).toBe('one');
    expect(pluralCategory(0, 'en')).toBe('other');
    expect(pluralCategory(0, 'fr')).toBe('one');
    expect(pluralCategory(3, 'ru')).toBe('few');
    expect(pluralCategory(5, 'ru')).toBe('many');
    expect(pluralCategory(21, 'ru')).toBe('one');
    expect(pluralCategory(1, 'zh-CN')).toBe('other');
  });
});

describe('plural', () => {
  it('uses the singular for exactly one in every locale', () => {
    for (const locale of ['en', 'es', 'fr', 'pt-BR', 'de', 'zh-CN', 'it', 'ru', 'zh-TW']) {
      expect(plural(1, all, locale)).toBe('one');
    }
  });

  it('picks the Russian few and many forms', () => {
    for (const n of [2, 3, 4, 22, 34, 102]) expect(plural(n, all, 'ru')).toBe('few');
    for (const n of [0, 5, 11, 12, 14, 20, 25, 111]) expect(plural(n, all, 'ru')).toBe('many');
  });

  it('falls back to other when a group has no few or many form', () => {
    expect(plural(3, twoForm, 'ru')).toBe('other');
    expect(plural(5, twoForm, 'ru')).toBe('other');
    // Spanish, French, Italian and Portuguese file round millions under `many`.
    expect(plural(1_000_000, twoForm, 'es')).toBe('other');
  });

  it('never shows a spelled-out "1" string for another count', () => {
    // French and Portuguese put 0 in `one`, Russian puts 21 there; the `_one`
    // strings say "1", so those counts must render through `other`.
    expect(plural(0, all, 'fr')).toBe('other');
    expect(plural(0, all, 'pt-BR')).toBe('other');
    expect(plural(21, all, 'ru')).toBe('other');
  });

  it('lets a one that shows its count serve Russian 21, 31, …', () => {
    const counted: PluralForms = { ...all, oneShowsCount: true };
    for (const n of [21, 31, 101, 1001]) expect(plural(n, counted, 'ru')).toBe('one');
    // Russian 11 and 111 are `many`, not `one`, whatever their last digit.
    for (const n of [11, 111]) expect(plural(n, counted, 'ru')).toBe('many');
    for (const n of [22, 34]) expect(plural(n, counted, 'ru')).toBe('few');
    // French and Portuguese 0 stays plural, and other languages are unchanged.
    expect(plural(0, counted, 'fr')).toBe('other');
    expect(plural(0, counted, 'pt-BR')).toBe('other');
    expect(plural(0, counted, 'ru')).toBe('many');
    expect(plural(21, counted, 'en')).toBe('other');
    expect(plural(21, counted, 'de')).toBe('other');
  });

  it('keeps English and German to one and other', () => {
    for (const n of [0, 2, 3, 5, 21, 1000]) {
      expect(plural(n, all, 'en')).toBe('other');
      expect(plural(n, all, 'de')).toBe('other');
    }
  });

  it('only renders the variant it returns', () => {
    let calls = 0;
    const counted: PluralForms = {
      one: () => { calls += 1; return 'one'; },
      other: () => { calls += 1; return 'other'; },
    };
    plural(7, counted, 'en');
    expect(calls).toBe(1);
  });
});
