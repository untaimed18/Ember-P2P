import { writable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
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
});

let initialized = false;

export async function initNetworkStore() {
  if (initialized) return;
  initialized = true;

  listen<NetworkStats>('network-stats', (event) => {
    networkStats.set(event.payload);
  });

  listen<string>('network-status', (event) => {
    networkStats.update((s) => ({ ...s, status: event.payload as NetworkStats['status'] }));
  });

  try {
    const stats = await getNetworkStats();
    networkStats.set(stats);
  } catch {
    // Backend not ready yet
  }
}

export function startStatsPoll() {
  const interval = setInterval(async () => {
    try {
      const stats = await getNetworkStats();
      networkStats.set(stats);
    } catch {
      // Ignore polling errors
    }
  }, 3000);

  return () => clearInterval(interval);
}
