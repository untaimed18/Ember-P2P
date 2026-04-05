import { writable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import type { UnlistenFn } from '@tauri-apps/api/event';
import type { NetworkStats } from '$lib/types';
import { getNetworkStats } from '$lib/api/kad';

const STALE_NETWORK_MS = 12_000;

export const networkStats = writable<NetworkStats>({
  connected_peers: 0,
  upload_speed: 0,
  download_speed: 0,
  total_uploaded: 0,
  total_downloaded: 0,
  status: 'disconnected',
  external_ip: '',
  firewalled: false,
  buddy_status: 'none',
  upnp_mapped: false,
  stores_acknowledged: 0,
  kad_users_estimate: 0,
  tcp_status: 'Unknown',
  udp_status: 'Unknown',
  ember_peers: 0,
  epx_sources_received: 0,
  stale: false,
  degraded: false,
  degraded_reason: undefined,
  last_update_at: 0,
  last_poll_ok_at: 0,
});

export const networkError = writable<string | null>(null);
export type ServerStatus = 'connected' | 'connecting' | 'disconnected';
export const serverStatus = writable<ServerStatus>('disconnected');

let initialized = false;
let unlisteners: UnlistenFn[] = [];
let lastEventUpdate = 0;
let lastPollOkAt = 0;

function syncServerStatus(stats: NetworkStats) {
  const s = stats.server_status;
  if (s === 'connected' || s === 'connecting' || s === 'disconnected') {
    serverStatus.set(s);
  }
}
let lastNetworkUpdate = 0;

function withDerivedNetworkState(stats: NetworkStats, now = Date.now()): NetworkStats {
  const newestUpdate = Math.max(lastEventUpdate, lastPollOkAt, lastNetworkUpdate);
  const stale = newestUpdate > 0 && now - newestUpdate > STALE_NETWORK_MS;
  const tcpStatus = stats.tcp_status || 'Unknown';
  const udpStatus = stats.udp_status || 'Unknown';

  let degraded = false;
  let degradedReason: string | undefined;

  if (stale) {
    degraded = true;
    degradedReason = 'Network status is stale';
  } else if (
    stats.status === 'connected' &&
    (stats.firewalled || tcpStatus === 'Firewalled' || udpStatus === 'Firewalled')
  ) {
    degraded = true;
    degradedReason = 'Limited reachability';
  } else if (stats.status === 'connecting' && !stats.external_ip) {
    degraded = true;
    degradedReason = 'Still establishing reachability';
  }

  return {
    ...stats,
    tcp_status: tcpStatus,
    udp_status: udpStatus,
    stale,
    degraded,
    degraded_reason: degradedReason,
    last_update_at: newestUpdate,
    last_poll_ok_at: lastPollOkAt,
  };
}

export async function initNetworkStore() {
  if (initialized) return;

  const [u1, u2, u3, u4] = await Promise.all([
    listen<string>('network-status', (event) => {
      lastEventUpdate = Date.now();
      lastNetworkUpdate = lastEventUpdate;
      networkStats.update((s) =>
        withDerivedNetworkState({ ...s, status: event.payload as NetworkStats['status'] })
      );
    }),
    listen<{ firewalled: boolean; external_ip: string; tcp_status?: string; udp_status?: string }>('firewall-status', (event) => {
      lastEventUpdate = Date.now();
      lastNetworkUpdate = lastEventUpdate;
      networkStats.update((s) => ({
        ...withDerivedNetworkState({
          ...s,
          firewalled: event.payload.firewalled,
          external_ip: event.payload.external_ip,
          tcp_status: event.payload.tcp_status ?? s.tcp_status,
          udp_status: event.payload.udp_status ?? s.udp_status,
        }),
      }));
    }),
    listen<{ message: string }>('network-error', (event) => {
      lastEventUpdate = Date.now();
      networkError.set(event.payload.message);
    }),
    listen<{ status: ServerStatus }>('server-status-changed', (event) => {
      serverStatus.set(event.payload.status);
    }),
  ]);
  initialized = true;
  unlisteners.push(u1, u2, u3, u4);

  try {
    const stats = await getNetworkStats();
    lastPollOkAt = Date.now();
    lastNetworkUpdate = lastPollOkAt;
    syncServerStatus(stats);
    networkStats.update((current) => {
      const merged = { ...stats };
      if (!merged.external_ip && current.external_ip) {
        merged.external_ip = current.external_ip;
      }
      if (!merged.tcp_status && current.tcp_status) {
        merged.tcp_status = current.tcp_status;
      }
      if (!merged.udp_status && current.udp_status) {
        merged.udp_status = current.udp_status;
      }
      return withDerivedNetworkState(merged);
    });
  } catch {
    // Backend not ready yet
  }
}

export function cleanupNetworkStore() {
  for (const unlisten of unlisteners) unlisten();
  unlisteners = [];
  initialized = false;
  lastEventUpdate = 0;
  lastPollOkAt = 0;
  lastNetworkUpdate = 0;
  serverStatus.set('disconnected');
  networkError.set(null);
  networkStats.set({
    connected_peers: 0, upload_speed: 0, download_speed: 0,
    total_uploaded: 0, total_downloaded: 0, status: 'disconnected',
    external_ip: '', firewalled: false, buddy_status: 'none',
    upnp_mapped: false, stores_acknowledged: 0, kad_users_estimate: 0,
    tcp_status: 'Unknown', udp_status: 'Unknown', ember_peers: 0,
    epx_sources_received: 0, stale: false, degraded: false,
    degraded_reason: undefined, last_update_at: 0, last_poll_ok_at: 0,
  } as NetworkStats);
}

export function startStatsPoll() {
  const interval = setInterval(async () => {
    if (Date.now() - lastEventUpdate < 5500) return;
    try {
      const stats = await Promise.race([
        getNetworkStats(),
        new Promise<never>((_, reject) => setTimeout(() => reject('timeout'), 4000)),
      ]);
      lastPollOkAt = Date.now();
      lastNetworkUpdate = lastPollOkAt;
      syncServerStatus(stats);
      networkStats.update((current) => {
        const merged = { ...stats };
        // Don't let a stale poll snapshot regress values already delivered
        // by real-time events (the backend cache refreshes every 5s, but
        // events like firewall-status arrive instantly).
        if (!merged.external_ip && current.external_ip) {
          merged.external_ip = current.external_ip;
        }
        if (current.firewalled && !merged.firewalled && merged.external_ip === '') {
          merged.firewalled = current.firewalled;
        }
        if (current.buddy_status !== 'none' && merged.buddy_status === 'none') {
          merged.buddy_status = current.buddy_status;
        }
        if (!merged.tcp_status && current.tcp_status) {
          merged.tcp_status = current.tcp_status;
        }
        if (!merged.udp_status && current.udp_status) {
          merged.udp_status = current.udp_status;
        }
        return withDerivedNetworkState(merged);
      });
    } catch {
      networkStats.update((current) => withDerivedNetworkState(current));
    }
  }, 3000);

  return () => clearInterval(interval);
}
