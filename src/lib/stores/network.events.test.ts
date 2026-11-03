import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { NetworkStats } from '$lib/types';

const events = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
const statsCalls = vi.hoisted(() => ({ next: null as null | (() => Promise<unknown>) }));

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async (name: string, handler: (event: { payload: unknown }) => void) => {
    events.set(name, handler);
    return () => events.delete(name);
  }),
}));
vi.mock('$lib/api/kad', () => ({
  getNetworkStats: vi.fn(() => statsCalls.next?.() ?? Promise.reject(new Error('not ready'))),
}));
vi.mock('$lib/api/server', () => ({ getServerLog: vi.fn(async () => []) }));
vi.mock('$lib/api/search', () => ({ relatedSearchSupported: vi.fn(async () => true) }));
vi.mock('$lib/stores/friends', () => ({ friendDisplayName: vi.fn(() => '') }));
vi.mock('$lib/notifications', () => ({ notify: vi.fn(async () => {}) }));
vi.mock('$lib/stores/toast', () => {
  let next = 1;
  const scoped = {
    addToast: vi.fn(() => next++),
    toast: vi.fn(),
    toastError: vi.fn(),
    toastSuccess: vi.fn(),
    toastWarning: vi.fn(),
  };
  return { ...scoped, removeToast: vi.fn(), toastsFor: () => scoped };
});

import { get } from 'svelte/store';
import { addToast, toastError } from '$lib/stores/toast';
import {
  cleanupNetworkStore,
  initNetworkStore,
  networkError,
  networkStats,
  serverStatus,
  startStatsPoll,
} from './network';

function emit(name: string, payload: unknown) {
  const handler = events.get(name);
  if (!handler) throw new Error(`nothing listens for ${name}`);
  handler({ payload });
}

function deferredStats() {
  let resolve!: (stats: NetworkStats) => void;
  const promise = new Promise<NetworkStats>((r) => { resolve = r; });
  statsCalls.next = () => promise;
  return resolve;
}

const withServer = (server_status: string): NetworkStats => ({
  ...get(networkStats),
  server_status,
  ed2k_low_id: false,
});

let stopPoll: (() => void) | null = null;

beforeEach(async () => {
  vi.useFakeTimers();
  vi.mocked(addToast).mockClear();
  vi.mocked(toastError).mockClear();
  statsCalls.next = null;
  await initNetworkStore();
});

afterEach(() => {
  stopPoll?.();
  stopPoll = null;
  cleanupNetworkStore();
  vi.useRealTimers();
});

describe('a stats poll racing a server status event', () => {
  it('does not put back the status from before the event', async () => {
    emit('server-status-changed', { status: 'connected' });
    networkStats.update((s) => ({ ...s, ed2k_low_id: true }));
    const land = deferredStats();
    stopPoll = startStatsPoll();
    await vi.advanceTimersByTimeAsync(3000);

    emit('server-status-changed', { status: 'disconnected' });
    land(withServer('connected'));
    await vi.advanceTimersByTimeAsync(0);

    expect(get(serverStatus)).toBe('disconnected');
    expect(get(networkStats).ed2k_low_id).toBeNull();
  });

  it('still takes the status from a poll that started after it', async () => {
    emit('server-status-changed', { status: 'disconnected' });
    const land = deferredStats();
    stopPoll = startStatsPoll();
    await vi.advanceTimersByTimeAsync(3000);

    land(withServer('connected'));
    await vi.advanceTimersByTimeAsync(0);

    expect(get(serverStatus)).toBe('connected');
    expect(get(networkStats).ed2k_low_id).toBe(false);
  });
});

describe('network errors', () => {
  it('keep a persistent error over a later transient one, and past a connect', () => {
    emit('network-error', { message: 'TCP port 4662 is already in use.' });
    emit('network-error', { message: 'Unable to reach KAD.', transient: true });
    expect(get(networkError)).toBe('TCP port 4662 is already in use.');

    emit('network-status', 'connected');
    expect(get(networkError)).toBe('TCP port 4662 is already in use.');
  });

  it('clear a transient error on connect', () => {
    emit('network-error', { message: 'Unable to reach KAD.', transient: true });
    emit('network-status', 'connected');
    expect(get(networkError)).toBeNull();
  });

  it('let a persistent error replace a transient one', () => {
    emit('network-error', { message: 'Unable to reach KAD.', transient: true });
    emit('network-error', { message: 'UDP bind failed.' });
    emit('network-status', 'connected');
    expect(get(networkError)).toBe('UDP bind failed.');
  });

  it('decode a coded envelope with no translation to its English message', () => {
    emit('network-error', {
      message: JSON.stringify({ __coded: true, code: 'not_a_real_code', message: 'English fallback' }),
    });
    expect(get(networkError)).toBe('English fallback');
  });
});

describe('a fatal network error', () => {
  it('raises a sticky toast and a persistent banner', () => {
    emit('network-error', { message: 'Unable to reach KAD.', transient: true });
    emit('network-fatal-error', 'Listener died');
    expect(addToast).toHaveBeenCalledWith('error', expect.stringContaining('Listener died'), 0);
    expect(toastError).not.toHaveBeenCalled();

    emit('network-status', 'connected');
    expect(get(networkError)).toBe('Listener died');
  });
});
