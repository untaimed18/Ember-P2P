import { invoke } from '@tauri-apps/api/core';
import type { NetworkStats, KadContact, KadSearchEntry } from '$lib/types';

/**
 * K24: wrap a Tauri invoke in a race against a deadline so the KAD UI
 * doesn't hang indefinitely when the backend is wedged (e.g. blocked on
 * a slow DNS resolution or a stuck oneshot receiver). Throws a normal
 * `Error` with a recognisable message so the caller can show the user a
 * "timed out, please try again" toast instead of a spinner that never
 * resolves. 20 seconds is enough for legitimate slow ops (pinned HTTP
 * download of a fresh nodes.dat, firewall recheck) but short enough
 * that a hung IPC doesn't feel permanent.
 */
function withTimeout<T>(promise: Promise<T>, label: string, ms = 20_000): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`${label} timed out after ${Math.round(ms / 1000)}s`));
    }, ms);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

export async function getNetworkStats(): Promise<NetworkStats> {
  return invoke('get_network_stats');
}

export async function banPeer(peerId: string): Promise<void> {
  return invoke('ban_peer', { peerId });
}

export async function kadConnect(): Promise<void> {
  return withTimeout(invoke('kad_connect'), 'KAD connect');
}

export async function kadDisconnect(): Promise<void> {
  return withTimeout(invoke('kad_disconnect'), 'KAD disconnect');
}

export async function kadRecheckFirewall(): Promise<void> {
  return withTimeout(invoke('kad_recheck_firewall'), 'KAD firewall recheck');
}

export async function getKadContacts(): Promise<KadContact[]> {
  return withTimeout(invoke<KadContact[]>('get_kad_contacts'), 'get_kad_contacts', 10_000);
}

export async function getKadSearches(): Promise<KadSearchEntry[]> {
  return withTimeout(invoke<KadSearchEntry[]>('get_kad_searches'), 'get_kad_searches', 10_000);
}

/** K30: cancel an active KAD search. The backend accepts the id as a
 *  string to dodge the JS BigInt/Number precision boundary for u64. */
export async function kadCancelSearch(id: number | string): Promise<void> {
  return withTimeout(
    invoke('kad_cancel_search', { id: String(id) }),
    'KAD cancel search',
    5_000,
  );
}
