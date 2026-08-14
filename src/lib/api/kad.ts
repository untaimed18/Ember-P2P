import { invoke } from '@tauri-apps/api/core';
import { withTimeout } from '$lib/utils';
import type { NetworkStats, PeerInfo, KadContact, KadSearchEntry } from '$lib/types';

// The KAD commands below take `withTimeout`'s 20 s default unless noted: long
// enough for the legitimately slow ones (pinned HTTP download of a fresh
// nodes.dat, firewall recheck) but short enough that a hung IPC doesn't feel
// permanent.

export async function getPeers(): Promise<PeerInfo[]> {
  return invoke('get_peers');
}

export async function getNetworkStats(): Promise<NetworkStats> {
  return invoke('get_network_stats');
}

export async function banPeer(peerId: string): Promise<void> {
  return invoke('ban_peer', { peerId });
}

export async function unbanPeer(peerId: string): Promise<void> {
  return invoke('unban_peer', { peerId });
}

export async function kadConnect(): Promise<void> {
  return withTimeout(invoke('kad_connect'), 'KAD connect');
}

export async function kadDisconnect(): Promise<void> {
  return withTimeout(invoke('kad_disconnect'), 'KAD disconnect');
}

/** Returns a human-readable success message when the bootstrap packet
 *  actually went out, or throws with a concrete failure reason. */
export async function kadBootstrapIp(ip: string, port: number): Promise<string> {
  return withTimeout(
    invoke<string>('kad_bootstrap_ip', { ip, port }),
    'KAD IP bootstrap',
  );
}

/** Returns a human-readable success message (e.g. "Loaded 123 contacts
 *  from nodes.dat") when the download + parse + insert all succeeded, or
 *  throws with a concrete failure reason. */
export async function kadBootstrapUrl(url: string): Promise<string> {
  // URL bootstrap includes an HTTP download; give it a longer ceiling.
  // Must be >= the backend's own 90s deadline (`kad_bootstrap_url` in
  // peers.rs awaits the worker with a 90s timeout); a shorter client
  // ceiling would surface a false "timed out" toast while the backend is
  // still legitimately downloading and may yet succeed.
  return withTimeout(
    invoke<string>('kad_bootstrap_url', { url }),
    'KAD URL bootstrap',
    90_000,
  );
}

export async function kadBootstrapClients(): Promise<void> {
  return withTimeout(invoke('kad_bootstrap_clients'), 'KAD client bootstrap');
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
