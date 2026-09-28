import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  CHANNEL_LANGUAGES,
  channelLanguageName,
  channelLanguageNativeName,
  channelLanguageSearchText,
  isChannelLanguage,
  sortedChannelLanguages,
} from './channelLanguages';

describe('channel languages', () => {
  it('lists exactly what the backend can put on the wire, in the same order', () => {
    // Order is the wire id, so a reordered copy here would be harmless in the
    // UI and still wrong the moment someone reads this list to add a language.
    const rust = readFileSync(
      fileURLToPath(new URL('../../src-tauri/src/network/ember/dht/publish.rs', import.meta.url)),
      'utf8',
    );
    const block = rust.match(/pub const CHANNEL_LANGUAGES: &\[&str\] = &\[([\s\S]*?)\];/);
    expect(block, 'CHANNEL_LANGUAGES in publish.rs').not.toBeNull();
    const codes = [...block![1].matchAll(/"([a-z]+)"/g)].map((m) => m[1]);
    expect(codes).toEqual([...CHANNEL_LANGUAGES]);
  });

  it('has a flag for every language', () => {
    for (const code of CHANNEL_LANGUAGES) {
      const flag = fileURLToPath(
        new URL(`../../node_modules/circle-flags/flags/language/${code}.svg`, import.meta.url),
      );
      expect(existsSync(flag), `${code}.svg`).toBe(true);
    }
  });

  it('accepts only listed codes', () => {
    expect(isChannelLanguage('de')).toBe(true);
    expect(isChannelLanguage('xx')).toBe(false);
    expect(isChannelLanguage('')).toBe(false);
    expect(isChannelLanguage(undefined)).toBe(false);
  });

  it('names languages in the app language and in themselves', () => {
    expect(channelLanguageName('de', 'en')).toBe('German');
    expect(channelLanguageName('de', 'fr')).toBe('Allemand');
    expect(channelLanguageNativeName('de')).toBe('Deutsch');
  });

  it('is found by its English name and common aliases whatever the app language', () => {
    expect(channelLanguageSearchText('de', 'fr')).toContain('german');
    expect(channelLanguageSearchText('de', 'fr')).toContain('allemand');
    expect(channelLanguageSearchText('bn', 'en')).toContain('bengali');
  });

  it('sorts by the name the reader sees', () => {
    const sorted = sortedChannelLanguages('en');
    expect(sorted).toHaveLength(CHANNEL_LANGUAGES.length);
    expect(sorted.indexOf('ar')).toBeLessThan(sorted.indexOf('bg'));
    expect(sorted.indexOf('de')).toBeLessThan(sorted.indexOf('el'));
  });
});
