import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const events = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async (name: string, handler: (event: { payload: unknown }) => void) => {
    events.set(name, handler);
    return () => events.delete(name);
  }),
}));
vi.mock('$lib/api/kad', () => ({ getNetworkStats: vi.fn(async () => { throw new Error('not ready'); }) }));
vi.mock('$lib/api/server', () => ({ getServerLog: vi.fn(async () => []) }));
vi.mock('$lib/api/search', () => ({ relatedSearchSupported: vi.fn(async () => true) }));
vi.mock('$lib/stores/friends', () => ({ friendDisplayName: vi.fn(() => '') }));
vi.mock('$lib/notifications', () => ({ notify: vi.fn(async () => {}) }));
vi.mock('$lib/stores/toast', () => {
  let next = 1;
  return {
    addToast: vi.fn(() => next++),
    removeToast: vi.fn(),
    toast: vi.fn(),
    toastError: vi.fn(),
    toastSuccess: vi.fn(),
    toastWarning: vi.fn(),
  };
});

import * as m from '$lib/paraglide/messages';
import { addToast, removeToast, toastSuccess } from '$lib/stores/toast';
import {
  cleanupNetworkStore,
  initNetworkStore,
  networkStats,
  reachableWithoutUpnp,
  UPNP_WARNING_GRACE_MS,
} from './network';
import { get } from 'svelte/store';

function emit(name: string, payload: unknown) {
  const handler = events.get(name);
  if (!handler) throw new Error(`nothing listens for ${name}`);
  handler({ payload });
}

const upnp = (mapped: boolean, extra: Record<string, unknown> = {}) =>
  emit('upnp-status', { mapped, gateway_found: true, stood_down: false, tcp_port: 4662, udp_port: 4672, ...extra });

const failed = () => m.upnp_alert_failed_rejected({ tcp: 4662, udp: 4672 });

beforeEach(async () => {
  vi.useFakeTimers();
  vi.mocked(addToast).mockClear();
  vi.mocked(removeToast).mockClear();
  vi.mocked(toastSuccess).mockClear();
  await initNetworkStore();
});

afterEach(() => {
  cleanupNetworkStore();
  vi.useRealTimers();
});

describe('reachableWithoutUpnp', () => {
  it('takes a connect-back or a HighID, nothing weaker', () => {
    expect(reachableWithoutUpnp({ tcp_status: 'Open', ed2k_low_id: null })).toBe(true);
    expect(reachableWithoutUpnp({ tcp_status: 'Unknown', ed2k_low_id: false })).toBe(true);
    expect(reachableWithoutUpnp({ tcp_status: 'Firewalled', ed2k_low_id: true })).toBe(false);
    expect(reachableWithoutUpnp({ tcp_status: 'Unknown', ed2k_low_id: undefined })).toBe(false);
  });
});

describe('the start-up UPnP failure warning', () => {
  it('waits out the grace period, then warns a node nothing shows is reachable', () => {
    upnp(false);
    expect(addToast).not.toHaveBeenCalled();
    vi.advanceTimersByTime(UPNP_WARNING_GRACE_MS);
    expect(addToast).toHaveBeenCalledWith('warning', failed(), 0);
  });

  it('never warns a node that is already reachable', () => {
    networkStats.update((s) => ({ ...s, tcp_status: 'Open' }));
    upnp(false);
    vi.advanceTimersByTime(UPNP_WARNING_GRACE_MS * 2);
    expect(addToast).not.toHaveBeenCalled();
  });

  it('is cancelled by proof that arrives during the grace period', () => {
    upnp(false);
    networkStats.update((s) => ({ ...s, ed2k_low_id: false }));
    vi.advanceTimersByTime(UPNP_WARNING_GRACE_MS);
    expect(addToast).not.toHaveBeenCalled();
  });

  it('is taken down by proof that arrives after it went up', () => {
    upnp(false);
    vi.advanceTimersByTime(UPNP_WARNING_GRACE_MS);
    expect(addToast).toHaveBeenCalledTimes(1);
    networkStats.update((s) => ({ ...s, tcp_status: 'Open' }));
    expect(removeToast).toHaveBeenCalled();
  });

  it('says "restored" only to someone who was warned', () => {
    upnp(false);
    upnp(true);
    expect(toastSuccess).not.toHaveBeenCalled();

    cleanupNetworkStore();
    return initNetworkStore().then(() => {
      upnp(false);
      vi.advanceTimersByTime(UPNP_WARNING_GRACE_MS);
      upnp(true);
      expect(toastSuccess).toHaveBeenCalledWith(m.upnp_alert_restored());
    });
  });
});

describe('a mapping that stood down', () => {
  it('is quiet, both going down and coming back', () => {
    upnp(true);
    upnp(false, { stood_down: true });
    expect(get(networkStats).upnp_stood_down).toBe(true);
    expect(addToast).not.toHaveBeenCalled();
    upnp(true);
    expect(get(networkStats).upnp_stood_down).toBe(false);
    expect(toastSuccess).not.toHaveBeenCalled();
  });

  it('warns, like a start-up failure, if mapping again does not work', () => {
    upnp(true);
    upnp(false, { stood_down: true });
    upnp(false);
    expect(addToast).not.toHaveBeenCalled();
    vi.advanceTimersByTime(UPNP_WARNING_GRACE_MS);
    expect(addToast).toHaveBeenCalledWith('warning', failed(), 0);
  });

  it('while a real loss still warns at once', () => {
    upnp(true);
    upnp(false);
    expect(addToast).toHaveBeenCalledWith('warning', m.upnp_alert_lost({ tcp: 4662, udp: 4672 }), 0);
  });
});
