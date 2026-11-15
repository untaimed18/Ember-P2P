import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/plugin-process', () => ({ relaunch: vi.fn(async () => {}) }));
vi.mock('$app/navigation', () => ({ goto: vi.fn(async () => {}) }));

import { invoke } from '@tauri-apps/api/core';
import { relaunch } from '@tauri-apps/plugin-process';
import { goto } from '$app/navigation';
import * as m from '$lib/paraglide/messages';
import type { NetworkBinding } from '$lib/api/networkInterface';
import { clearAllToasts, removeToast, toasts } from '$lib/stores/toast';
import { startNetworkBindWatch } from './networkBindWatch';

let binding: NetworkBinding;

beforeEach(() => {
  vi.useFakeTimers();
  clearAllToasts();
  vi.mocked(relaunch).mockClear();
  vi.mocked(goto).mockClear();
  binding = { state: 'bound', name: 'NordLynx', address: '10.5.0.2' };
  vi.mocked(invoke).mockReset();
  vi.mocked(invoke).mockImplementation(async (command) => {
    if (command === 'get_network_binding') return binding;
    throw new Error(`unexpected ${command}`);
  });
});

afterEach(() => {
  vi.useRealTimers();
});

const shown = () => get(toasts);
const nextLook = () => vi.advanceTimersByTimeAsync(5_000);

describe('the chosen network interface notice', () => {
  it('waits a look before warning, and goes once the interface is there', async () => {
    binding = { state: 'waiting', name: 'NordLynx', address: null };
    const stop = startNetworkBindWatch();
    await vi.advanceTimersByTimeAsync(0);
    expect(shown()).toHaveLength(0);

    await nextLook();
    expect(shown()).toHaveLength(1);
    expect(shown()[0].type).toBe('warning');
    expect(shown()[0].message).toBe(m.network_bind_waiting({ name: 'NordLynx' }));

    binding = { state: 'bound', name: 'NordLynx', address: '10.5.0.2' };
    await nextLook();
    expect(shown()).toHaveLength(0);
    stop();
  });

  it('says nothing while no interface is chosen or the chosen one is there', async () => {
    binding = { state: 'any', name: '', address: null };
    const stop = startNetworkBindWatch();
    await nextLook();
    await nextLook();
    expect(shown()).toHaveLength(0);
    binding = { state: 'bound', name: 'NordLynx', address: '10.5.0.2' };
    await nextLook();
    await nextLook();
    expect(shown()).toHaveLength(0);
    stop();
  });

  it('stays dismissed for that trouble only, and offers a restart for a new address', async () => {
    binding = { state: 'lost', name: 'NordLynx', address: null };
    const stop = startNetworkBindWatch();
    await nextLook();
    const [lost] = shown();
    expect(lost.message).toBe(m.network_bind_lost({ name: 'NordLynx' }));
    removeToast(lost.id);

    await nextLook();
    await nextLook();
    expect(shown()).toHaveLength(0);

    binding = { state: 'changed', name: 'NordLynx', address: '10.5.0.9' };
    await nextLook();
    const [changed] = shown();
    expect(changed.message).toBe(m.network_bind_changed({ name: 'NordLynx', address: '10.5.0.9' }));
    expect(changed.action?.label).toBe(m.settings_restart_now());
    changed.action?.run();
    await vi.advanceTimersByTimeAsync(0);
    expect(relaunch).toHaveBeenCalledTimes(1);
    stop();
  });

  it('opens the network settings, and does not come back while the trouble lasts', async () => {
    binding = { state: 'waiting', name: 'NordLynx', address: null };
    const stop = startNetworkBindWatch();
    await nextLook();
    expect(shown()[0].action?.label).toBe(m.network_bind_open_settings());
    shown()[0].action?.run();
    expect(goto).toHaveBeenCalledWith('/settings?section=network');

    await nextLook();
    await nextLook();
    expect(shown()).toHaveLength(0);

    binding = { state: 'bound', name: 'NordLynx', address: '10.5.0.2' };
    await nextLook();
    binding = { state: 'lost', name: 'NordLynx', address: null };
    await nextLook();
    await nextLook();
    expect(shown()).toHaveLength(1);
    stop();
  });

  it('takes its notice down when stopped', async () => {
    binding = { state: 'waiting', name: 'NordLynx', address: null };
    const stop = startNetworkBindWatch();
    await nextLook();
    expect(shown()).toHaveLength(1);
    stop();
    expect(shown()).toHaveLength(0);
    await nextLook();
    expect(shown()).toHaveLength(0);
  });
});
