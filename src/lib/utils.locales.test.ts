import { describe, expect, it, vi } from 'vitest';

/**
 * `utils.ts` builds its formatters once, from the locale active at import, so
 * each case re-imports it under a forced locale.
 */
const state = vi.hoisted(() => ({ locale: 'en' }));

// Only `getLocale` is needed; the real module would reload the whole compiled
// message catalog on every re-import.
vi.mock('$lib/i18n', () => ({ getLocale: () => state.locale }));

async function utilsIn(locale: string) {
  state.locale = locale;
  vi.resetModules();
  return import('./utils');
}

describe('durations in the app language', () => {
  it('keeps the compact English column format', async () => {
    const { formatDurationSecs, formatElapsed, formatRemaining } = await utilsIn('en');
    expect(formatDurationSecs(0)).toBe('0s');
    expect(formatDurationSecs(45)).toBe('45s');
    expect(formatDurationSecs(15 * 60 + 30)).toBe('15m');
    expect(formatDurationSecs(2 * 3600 + 15 * 60)).toBe('2h 15m');
    expect(formatDurationSecs(3 * 86400 + 4 * 3600)).toBe('3d 4h');
    expect(formatElapsed(3600 + 5 * 60 + 9)).toBe('1h 05m 09s');
    expect(formatElapsed(65)).toBe('1m 05s');
    expect(formatElapsed(0)).toBe('0s');
    expect(formatRemaining(2048, 1024, 1024)).toBe('1s (1 KB)');
  });

  it('uses the locale’s own unit abbreviations', async () => {
    const fr = await utilsIn('fr');
    expect(fr.formatDurationSecs(3 * 86400 + 4 * 3600)).toBe('3j 4h');
    const ru = await utilsIn('ru');
    expect(ru.formatDurationSecs(2 * 3600 + 15 * 60)).toBe('2 ч 15 мин');
    const zh = await utilsIn('zh-CN');
    expect(zh.formatDurationSecs(2 * 3600 + 15 * 60)).toBe('2小时15分钟');
  });

  it('never falls back to English letters for a non-English locale', async () => {
    const de = await utilsIn('de');
    const text = de.formatDurationSecs(2 * 3600 + 15 * 60);
    expect(text).not.toBe('2h 15m');
    expect(text).toContain('Min');
  });

  it('joins parts compactly rather than as a list', async () => {
    // `Intl.ListFormat` gave "2h, 15 Min." and, on the ticking timer,
    // "1h, 05 Min. und 09 Sek.".
    const de = await utilsIn('de');
    for (const text of [de.formatDurationSecs(2 * 3600 + 15 * 60), de.formatElapsed(3600 + 5 * 60 + 9)]) {
      expect(text).not.toMatch(/,|\bund\b/);
    }
    expect(de.formatElapsed(3600 + 5 * 60 + 9)).toMatch(/^1\s?h 05 Min\. 09 Sek\.$/);
  });

  it('sets Chinese units solid unless the locale spaces them itself', async () => {
    const zhCN = await utilsIn('zh-CN');
    expect(zhCN.formatElapsed(3600 + 5 * 60 + 9)).toBe('1小时05分钟09秒');
    // zh-TW's narrow units are "2 小時", so gluing parts together gave "2 小時15 分鐘".
    const zhTW = await utilsIn('zh-TW');
    expect(zhTW.formatDurationSecs(2 * 3600 + 15 * 60)).toBe('2 小時 15 分鐘');
  });

  it('still reports nonsense as unknown', async () => {
    const { formatDurationSecs, formatRemaining } = await utilsIn('ru');
    expect(formatDurationSecs(-1)).toBe('\u2014');
    expect(formatDurationSecs(Number.NaN)).toBe('\u2014');
    expect(formatRemaining(10, 10, 5)).toBe('\u2014');
  });
});

describe('sizes in the app language', () => {
  it('keeps KB/MB and a full stop in English', async () => {
    const { formatBytes, formatSpeed } = await utilsIn('en');
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(1023)).toBe('1023 B');
    expect(formatSpeed(1024 * 1024)).toBe('1 MB/s');
  });

  it('writes French octets and a decimal comma', async () => {
    const { formatBytes, formatSpeed } = await utilsIn('fr');
    expect(formatBytes(1536)).toBe('1,5 Ko');
    expect(formatBytes(0)).toBe('0 o');
    expect(formatSpeed(3 * 1024 * 1024)).toBe('3 Mo/s');
  });

  it('writes Cyrillic units in Russian', async () => {
    const { formatBytes } = await utilsIn('ru');
    expect(formatBytes(1.5 * 1024 ** 3)).toBe('1,5 ГБ');
  });

  it('keeps a speed in one script', async () => {
    const ru = await utilsIn('ru');
    expect(ru.formatSpeed(1.5 * 1024 * 1024)).toBe('1,5 МБ/\u0441');
    expect(ru.formatSpeed(1.5 * 1024 * 1024)).not.toMatch(/[a-z]/i);
    expect(ru.speedUnitLabel(1)).toBe('КБ/\u0441');
    const fr = await utilsIn('fr');
    expect(fr.speedUnitLabel(2)).toBe('Mo/s');
  });

  it('labels unit pickers with the same units the tables print', async () => {
    const en = await utilsIn('en');
    expect([0, 1, 2].map(en.speedUnitLabel)).toEqual(['B/s', 'KB/s', 'MB/s']);
    expect(en.sizeUnitLabel(3)).toBe('GB');
    const fr = await utilsIn('fr');
    expect([0, 1, 2, 3].map(fr.sizeUnitLabel)).toEqual(['o', 'Ko', 'Mo', 'Go']);
  });

  it('does not group the digits of a sub-kilobyte count', async () => {
    const { formatBytes } = await utilsIn('de');
    expect(formatBytes(1023)).toBe('1023 B');
  });
});
