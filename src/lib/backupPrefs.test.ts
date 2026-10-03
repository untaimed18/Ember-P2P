import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { localStorageKey } from '$lib/paraglide/runtime';
import {
  BACKED_UP_STORAGE_KEYS,
  SEARCH_HISTORY_STORAGE_KEY,
  applyRestoredPrefs,
  collectBackupPrefs,
} from './backupPrefs';

function memoryStorage(initial: Record<string, string> = {}) {
  const map = new Map(Object.entries(initial));
  return {
    map,
    getItem: (key: string) => map.get(key) ?? null,
    setItem: (key: string, value: string) => void map.set(key, value),
    removeItem: (key: string) => void map.delete(key),
  };
}

const srcDir = fileURLToPath(new URL('..', import.meta.url));

describe('backed-up storage keys', () => {
  it('match the list the backend accepts, in the same order', () => {
    const rust = readFileSync(
      fileURLToPath(new URL('../../src-tauri/src/commands/backup.rs', import.meta.url)),
      'utf8',
    );
    const block = rust.match(/const WEBVIEW_PREF_KEYS: &\[&str\] = &\[([\s\S]*?)\];/);
    expect(block, 'WEBVIEW_PREF_KEYS in backup.rs').not.toBeNull();
    const keys = [...block![1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
    expect(keys).toEqual([...BACKED_UP_STORAGE_KEYS]);
  });

  it('name keys the app still uses', () => {
    // A storage key that is bumped (`...V3` to `...V4`) without this list
    // following would quietly drop out of every backup.
    const sources = (readdirSync(srcDir, { recursive: true }) as string[])
      .filter((file) => /\.(ts|svelte)$/.test(file))
      .filter((file) => !/backupPrefs(\.test)?\.ts$/.test(file) && !file.includes('paraglide'))
      .map((file) => readFileSync(join(srcDir, file), 'utf8'))
      .join('\n');
    for (const key of BACKED_UP_STORAGE_KEYS) {
      if (key === 'PARAGLIDE_LOCALE') continue;
      expect(
        sources.includes(`'${key}'`) || sources.includes(`"${key}"`),
        `${key} is not used anywhere in src`,
      ).toBe(true);
    }
    expect(BACKED_UP_STORAGE_KEYS).toContain(localStorageKey);
    expect(BACKED_UP_STORAGE_KEYS).toContain(SEARCH_HISTORY_STORAGE_KEY);
  });

  it('leave out geometry, transient state and the update record', () => {
    for (const key of [
      'ember.updater.dismissedUpdate',
      'ember.chatTabs.v1',
      'ember.chatWindow.bounds.v1',
      'ember.searchTabs.v1',
      'transfers-split',
      'library-col-widths',
    ]) {
      expect(BACKED_UP_STORAGE_KEYS as readonly string[]).not.toContain(key);
    }
  });
});

describe('collectBackupPrefs', () => {
  it('takes only the backed-up keys that are set', () => {
    const storage = memoryStorage({
      'ember-theme': 'dark',
      PARAGLIDE_LOCALE: 'de',
      'transfers-split': '40',
      'ember.updater.dismissedUpdate': '{"version":"9.9.9"}',
    });
    expect(collectBackupPrefs(storage, { searchHistory: true })).toEqual({
      'ember-theme': 'dark',
      PARAGLIDE_LOCALE: 'de',
    });
  });

  it('leaves search history out when saving it is off', () => {
    const storage = memoryStorage({ [SEARCH_HISTORY_STORAGE_KEY]: '["linux"]' });
    expect(collectBackupPrefs(storage, { searchHistory: true })).toEqual({
      [SEARCH_HISTORY_STORAGE_KEY]: '["linux"]',
    });
    expect(collectBackupPrefs(storage, { searchHistory: false })).toEqual({});
  });

  it('leaves search history out while the setting is not known', () => {
    const storage = memoryStorage({
      [SEARCH_HISTORY_STORAGE_KEY]: '["linux"]',
      'ember-theme': 'dark',
    });
    expect(collectBackupPrefs(storage, { searchHistory: undefined })).toEqual({
      'ember-theme': 'dark',
    });
  });

  it('survives storage that throws or is missing', () => {
    const broken = {
      getItem: () => {
        throw new Error('SecurityError');
      },
      setItem: () => {},
      removeItem: () => {},
    };
    expect(collectBackupPrefs(broken, { searchHistory: true })).toEqual({});
    expect(collectBackupPrefs(null, { searchHistory: true })).toBeNull();
  });
});

describe('applyRestoredPrefs', () => {
  it('writes the snapshot and clears backed-up keys it does not carry', () => {
    const storage = memoryStorage({
      'ember-theme': 'light',
      'ember.channels.hidden.v1': '["0123456789abcdef0123456789abcdef"]',
      'transfers-split': '40',
    });
    expect(applyRestoredPrefs({ 'ember-theme': 'dark', PARAGLIDE_LOCALE: 'fr' }, storage)).toBe(true);
    expect(Object.fromEntries(storage.map)).toEqual({
      'ember-theme': 'dark',
      PARAGLIDE_LOCALE: 'fr',
      'transfers-split': '40',
    });
  });

  it('never writes a key outside the list', () => {
    const storage = memoryStorage();
    applyRestoredPrefs(
      JSON.parse('{"ember.updater.dismissedUpdate":"9.9.9","__proto__":"x","ember-theme":"dark"}'),
      storage,
    );
    expect([...storage.map.keys()]).toEqual(['ember-theme']);
  });

  it('treats a non-string value as absent', () => {
    const storage = memoryStorage({ 'ember-theme': 'light' });
    applyRestoredPrefs({ 'ember-theme': 1 }, storage);
    expect(storage.getItem('ember-theme')).toBeNull();
  });

  it('reports no change when there is nothing to do, so the window does not reload', () => {
    const storage = memoryStorage({ 'ember-theme': 'dark' });
    expect(applyRestoredPrefs({ 'ember-theme': 'dark' }, storage)).toBe(false);
    for (const snapshot of [null, undefined, 'dark', ['ember-theme', 'dark'], 42]) {
      expect(applyRestoredPrefs(snapshot, storage)).toBe(false);
    }
    expect(Object.fromEntries(storage.map)).toEqual({ 'ember-theme': 'dark' });
  });

  it('keeps going past a key the storage refuses', () => {
    const storage = memoryStorage();
    const refusing = {
      ...storage,
      setItem: (key: string, value: string) => {
        if (key === 'ember-theme') throw new Error('QuotaExceededError');
        storage.setItem(key, value);
      },
    };
    expect(applyRestoredPrefs({ 'ember-theme': 'dark', PARAGLIDE_LOCALE: 'it' }, refusing)).toBe(true);
    expect(Object.fromEntries(storage.map)).toEqual({ PARAGLIDE_LOCALE: 'it' });
  });
});
