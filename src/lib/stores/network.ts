import { writable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import type { UnlistenFn } from '@tauri-apps/api/event';
import type { NetworkStats } from '$lib/types';
import { getNetworkStats } from '$lib/api/peers';

export const networkStats = writable<NetworkStats>({
  connected_peers: 0,
  upload_speed: 0,
  download_speed: 0,
  total_uploaded: 0,
  total_downloaded: 0,
  status: 'disconnected',
  external_ip: '',
  firewalled: true,
  buddy_status: 'none',
  upnp_mapped: false,
  stores_acknowledged: 0,
});

export const networkError = writable<string | null>(null);

let initialized = false;
let unlisteners: UnlistenFn[] = [];
let lastEventUpdate = 0;

export async function initNetworkStore() {
  if (initialized) return;
  initialized = true;

  unlisteners.push(
    await listen<NetworkStats>('network-stats', (event) => {
      lastEventUpdate = Date.now();
      networkStats.set(event.payload);
    })
  );

  unlisteners.push(
    await listen<string>('network-status', (event) => {
      lastEventUpdate = Date.now();
      networkStats.update((s) => ({ ...s, status: event.payload as NetworkStats['status'] }));
    })
  );

  unlisteners.push(
    await listen<{ firewalled: boolean; external_ip: string }>('firewall-status', (event) => {
      lastEventUpdate = Date.now();
      networkStats.update((s) => ({
        ...s,
        firewalled: event.payload.firewalled,
        external_ip: event.payload.external_ip,
      }));
    })
  );

  unlisteners.push(
    await listen<{ message: string }>('network-error', (event) => {
      networkError.set(event.payload.message);
    })
  );

  try {
    const stats = await getNetworkStats();
    networkStats.set(stats);
  } catch {
    // Backend not ready yet
  }
}

export function cleanupNetworkStore() {
  for (const unlisten of unlisteners) unlisten();
  unlisteners = [];
  initialized = false;
}

export function startStatsPoll() {
  const interval = setInterval(async () => {
    if (Date.now() - lastEventUpdate < 2000) return;
    try {
      const stats = await getNetworkStats();
      networkStats.set(stats);
    } catch {
      // Ignore polling errors
    }
  }, 3000);

  return () => clearInterval(interval);
}
