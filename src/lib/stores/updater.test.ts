import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@tauri-apps/api/core', () => ({
  Channel: class {},
  invoke: vi.fn(),
}));
vi.mock('@tauri-apps/plugin-process', () => ({ relaunch: vi.fn() }));

import { isUpdateCheckDue } from './updater';

const KEY = 'ember.updater.lastCheckedAt';
const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.UTC(2026, 8, 25, 12, 0, 0);

const storage = new Map<string, string>();

beforeEach(() => {
  storage.clear();
  vi.stubGlobal('localStorage', {
    getItem: (k: string) => storage.get(k) ?? null,
    setItem: (k: string, v: string) => void storage.set(k, v),
    removeItem: (k: string) => void storage.delete(k),
  });
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('isUpdateCheckDue', () => {
  it('is due when nothing has been recorded', () => {
    expect(isUpdateCheckDue('weekly')).toBe(true);
  });

  it('follows the configured interval for a past stamp', () => {
    storage.set(KEY, String(NOW - 2 * DAY));
    expect(isUpdateCheckDue('daily')).toBe(true);
    expect(isUpdateCheckDue('weekly')).toBe(false);
  });

  it('tolerates a stamp slightly ahead of the clock', () => {
    storage.set(KEY, String(NOW + 60 * 60 * 1000));
    expect(isUpdateCheckDue('daily')).toBe(false);
    expect(storage.has(KEY)).toBe(true);
  });

  it('treats a stamp saved under a clock running far ahead as due, and drops it', () => {
    // Saved while the clock read a year ahead; the clock has since been fixed.
    storage.set(KEY, String(NOW + 365 * DAY));
    expect(isUpdateCheckDue('monthly')).toBe(true);
    expect(storage.has(KEY)).toBe(false);
  });

  it('treats an unparseable stamp as never checked', () => {
    storage.set(KEY, 'not-a-number');
    expect(isUpdateCheckDue('monthly')).toBe(true);
  });
});
