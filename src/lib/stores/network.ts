import { writable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import type { UnlistenFn } from '@tauri-apps/api/event';
import type { NetworkStats } from '$lib/types';
import { getNetworkStats } from '$lib/api/kad';
import { toastError, toastWarning } from '$lib/stores/toast';

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
  initialized = true;

  const registered: UnlistenFn[] = [];
  try {
    registered.push(await listen<string>('network-status', (event) => {
      lastEventUpdate = Date.now();
      lastNetworkUpdate = lastEventUpdate;
      networkStats.update((s) =>
        withDerivedNetworkState({ ...s, status: event.payload as NetworkStats['status'] })
      );
    }));
    registered.push(await listen<{ firewalled: boolean; external_ip: string; tcp_status?: string; udp_status?: string }>('firewall-status', (event) => {
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
    }));
    registered.push(await listen<{ message: string }>('network-error', (event) => {
      lastEventUpdate = Date.now();
      networkError.set(event.payload.message);
    }));
    // Fatal network errors come directly from the network-task supervisor
    // in `lib.rs` — the payload is a bare redacted string (not an object).
    // Surface them with maximum prominence: populate the persistent
    // `networkError` store so the KAD-page banner renders, AND push a
    // sticky toast so users on other pages notice. The previous version
    // of this store had no listener at all, so catastrophic start-up or
    // runtime failures (e.g. "port already in use", "permission denied")
    // reached the user as a silently-dead network layer.
    registered.push(await listen<string>('network-fatal-error', (event) => {
      lastEventUpdate = Date.now();
      const message = typeof event.payload === 'string'
        ? event.payload
        : 'Network error: network task stopped.';
      networkError.set(message);
      // Long duration (15 s) — fatal failures deserve more than the
      // default 8 s of a regular error toast.
      toastError(`Network stopped: ${message}`);
    }));
    // Non-fatal warnings from network start-up / ongoing operation (e.g.
    // UDP port already in use → auto-rebound to a different port). These
    // changes are user-visible (forwarding rules, advertised port) so
    // popping a toast lets users correct their router / settings
    // instead of wondering why peer reachability is lower than expected.
    registered.push(await listen<{ message: string }>('network-warning', (event) => {
      const msg = event.payload?.message;
      if (msg) {
        toastWarning(msg);
      }
    }));
    registered.push(await listen<{ status: ServerStatus }>('server-status-changed', (event) => {
      serverStatus.set(event.payload.status);
    }));
  } catch (e) {
    for (const u of registered) u();
    initialized = false;
    throw e;
  }
  unlisteners.push(...registered);

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
  if (statsPollInterval !== null) {
    clearInterval(statsPollInterval);
    statsPollInterval = null;
    detachStatsVisibilityListener();
  }
  statsPollConsumers = 0;
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

let statsPollInterval: ReturnType<typeof setInterval> | null = null;
let statsPollConsumers = 0;

// Module-scope so both the consumer-ref teardown and `cleanupNetworkStore`
// can reliably detach it without keeping a dangling DOM listener. Set
// true by `visibilitychange` when the tab becomes visible; the next poll
// tick consumes it to pump one reconcile even if the event-freshness
// gate below would normally skip.
let statsPumpOnNextVisible = false;
let statsVisibilityListenerAttached = false;
function onStatsVisibilityChange() {
  if (typeof document !== 'undefined' && document.visibilityState === 'visible') {
    statsPumpOnNextVisible = true;
  }
}
function attachStatsVisibilityListener() {
  if (statsVisibilityListenerAttached || typeof document === 'undefined') return;
  document.addEventListener('visibilitychange', onStatsVisibilityChange);
  statsVisibilityListenerAttached = true;
}
function detachStatsVisibilityListener() {
  if (!statsVisibilityListenerAttached || typeof document === 'undefined') return;
  document.removeEventListener('visibilitychange', onStatsVisibilityChange);
  statsVisibilityListenerAttached = false;
  statsPumpOnNextVisible = false;
}

export function startStatsPoll() {
  statsPollConsumers += 1;
  if (statsPollInterval !== null) {
    return () => {
      statsPollConsumers = Math.max(0, statsPollConsumers - 1);
      if (statsPollConsumers === 0 && statsPollInterval !== null) {
        clearInterval(statsPollInterval);
        statsPollInterval = null;
        detachStatsVisibilityListener();
      }
    };
  }

  attachStatsVisibilityListener();

  statsPollInterval = setInterval(async () => {
    // Skip the IPC entirely when the window is hidden. The backend keeps
    // firing `network-status` / `firewall-status` events and those land in
    // the store regardless; the poll is only a reconciliation fallback for
    // when events are silent, and a hidden tab has no one watching the
    // sidebar dot or the status bar. Without this gate we did a full
    // `getNetworkStats()` round-trip + reactive re-broadcast every 3 s
    // while backgrounded, for no observable benefit.
    if (typeof document !== 'undefined' && document.visibilityState !== 'visible') {
      return;
    }
    if (!statsPumpOnNextVisible && Date.now() - lastEventUpdate < 5500) return;
    statsPumpOnNextVisible = false;
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

  return () => {
    statsPollConsumers = Math.max(0, statsPollConsumers - 1);
    if (statsPollConsumers === 0 && statsPollInterval !== null) {
      clearInterval(statsPollInterval);
      statsPollInterval = null;
      detachStatsVisibilityListener();
    }
  };
}
