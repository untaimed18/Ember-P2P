import { writable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import type { UnlistenFn } from '@tauri-apps/api/event';
import type { DegradedReason, NetworkStats } from '$lib/types';
import { getNetworkStats } from '$lib/api/kad';
import { getSettings, updateSettings } from '$lib/api/settings';
import { addToast, removeToast, toastError, toastSuccess, toastWarning } from '$lib/stores/toast';
import * as m from '$lib/paraglide/messages';

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

// True once UPnP has been auto-disabled this session after a failed start-up
// mapping. Lets UI (e.g. the KAD-page UPnP tile) show "Disabled" immediately,
// without waiting for the persisted setting to round-trip back through
// `getSettings`. Reset on store teardown.
export const upnpAutoDisabled = writable<boolean>(false);

let initialized = false;
let unlisteners: UnlistenFn[] = [];
let lastEventUpdate = 0;
let lastPollOkAt = 0;
// Last UPnP mapped state we surfaced, so we only toast on transitions.
// `null` until the backend's startup `upnp-status` event arrives: that first
// event sets the baseline (warning if it failed, silence if it succeeded —
// working UPnP is the expected case and shouldn't pop a toast). Subsequent
// events are real changes (recovery / loss) and are always toasted.
let lastUpnpMapped: boolean | null = null;
// Id of the current sticky UPnP failure toast (if any). UPnP-failure toasts
// don't auto-dismiss — port forwarding is broken until the user acts, so the
// warning must persist until they close it. We track the id so we can retract
// the stale warning ourselves once the mapping recovers, instead of leaving a
// permanent "UPnP failed" toast next to a "restored" one.
let upnpToastId: number | null = null;

function clearUpnpToast() {
  if (upnpToastId !== null) {
    removeToast(upnpToastId);
    upnpToastId = null;
  }
}

// Guard so we persist the auto-disable at most once per session even if the
// backend somehow re-reports the failure. Reset on store teardown.
let upnpAutoDisablePersisted = false;

// Persist `upnp_enabled = false` after the backend auto-disabled UPnP for a
// failed mapping. The network task has already stopped using UPnP for this
// session; this just makes the choice stick (and reflects it in the Settings
// UI) so the next launch doesn't retry a setup the router can't satisfy. The
// user can re-enable it in Settings once they've fixed forwarding.
async function persistUpnpDisabled() {
  if (upnpAutoDisablePersisted) return;
  upnpAutoDisablePersisted = true;
  try {
    const current = await getSettings();
    if (current.upnp_enabled) {
      await updateSettings({ ...current, upnp_enabled: false });
    }
  } catch {
    // Let a later event retry — the on-disk setting wasn't changed.
    upnpAutoDisablePersisted = false;
  }
}

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
  // Stable reason code, localized at render time (see `degradedReasonText` in
  // `$lib/i18n`). The store must not embed a display string here, otherwise it
  // would be frozen in whatever locale was active when the status last changed.
  let degradedReason: DegradedReason | undefined;

  if (stale) {
    degraded = true;
    degradedReason = 'stale';
  } else if (
    stats.status === 'connected' &&
    (stats.firewalled || tcpStatus === 'Firewalled' || udpStatus === 'Firewalled')
  ) {
    degraded = true;
    degradedReason = 'limited';
  } else if (stats.status === 'connecting' && !stats.external_ip) {
    degraded = true;
    degradedReason = 'establishing';
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
    // UPnP port-mapping outcome. Emitted once at network start-up and again
    // whenever the mapped state flips during the periodic maintenance tick
    // (recovery after a retry, or loss after a router reboot). We keep
    // `upnp_mapped` in the store fresh from here so the KAD-page tile updates
    // immediately, and toast the user when automatic forwarding isn't working
    // so they can set up manual port forwarding if peers can't reach them.
    // `auto_disabled` is set when the backend turned UPnP off after a failed
    // start-up mapping; we then persist the setting so it stays off.
    registered.push(await listen<{
      mapped: boolean;
      gateway_found: boolean;
      auto_disabled: boolean;
      tcp_port: number;
      udp_port: number;
    }>('upnp-status', (event) => {
      lastEventUpdate = Date.now();
      lastNetworkUpdate = lastEventUpdate;
      const { mapped, gateway_found, auto_disabled, tcp_port, udp_port } = event.payload;
      networkStats.update((s) => withDerivedNetworkState({ ...s, upnp_mapped: mapped }));

      if (auto_disabled) {
        upnpAutoDisabled.set(true);
        void persistUpnpDisabled();
      }

      // Failure toasts are sticky (duration 0): they stay until the user
      // dismisses them with the X. Only one is ever live at a time — replace
      // any previous one so the message always reflects the latest state.
      const showStickyWarning = (message: string) => {
        clearUpnpToast();
        upnpToastId = addToast('warning', message, 0);
      };

      if (lastUpnpMapped === null) {
        // First report this session establishes the baseline. A failure here
        // is also where the backend auto-disables UPnP, so the message tells
        // the user it's been turned off and how to re-enable it.
        if (!mapped) {
          showStickyWarning(
            gateway_found
              ? m.upnp_alert_failed_rejected({ tcp: tcp_port, udp: udp_port })
              : m.upnp_alert_failed_no_gateway({ tcp: tcp_port, udp: udp_port })
          );
        }
      } else if (mapped !== lastUpnpMapped) {
        if (mapped) {
          // Recovered: retract the lingering failure warning and confirm.
          clearUpnpToast();
          toastSuccess(m.upnp_alert_restored());
        } else {
          showStickyWarning(m.upnp_alert_lost({ tcp: tcp_port, udp: udp_port }));
        }
      }
      lastUpnpMapped = mapped;
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
  clearUpnpToast();
  lastUpnpMapped = null;
  upnpAutoDisablePersisted = false;
  upnpAutoDisabled.set(false);
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
// Guard against overlapping polls: a slow `getNetworkStats()` (up to the 4 s
// race timeout) can still be running when the next 3 s tick fires. Without
// this, two requests run concurrently and the slower/older one can resolve
// last and clobber fresher stats.
let statsPollInFlight = false;

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
    if (statsPollInFlight) return;
    statsPumpOnNextVisible = false;
    statsPollInFlight = true;
    let pollTimeout: ReturnType<typeof setTimeout> | undefined;
    try {
      const stats = await Promise.race([
        getNetworkStats(),
        new Promise<never>((_, reject) => {
          pollTimeout = setTimeout(() => reject('timeout'), 4000);
        }),
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
    } finally {
      // Clear the race watchdog so the loser timer doesn't linger.
      if (pollTimeout) clearTimeout(pollTimeout);
      statsPollInFlight = false;
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
