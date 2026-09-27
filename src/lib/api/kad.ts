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

/** Resolves once the bootstrap packet actually went out, or throws with a
 *  concrete failure reason. The resolved string is backend English. */
export async function kadBootstrapIp(ip: string, port: number): Promise<string> {
  return withTimeout(
    invoke<string>('kad_bootstrap_ip', { ip, port }),
    'KAD IP bootstrap',
  );
}

/** Resolves with backend English ("Loaded 123 contacts from nodes.dat") when
 *  the download + parse + insert all succeeded, or throws with a concrete
 *  failure reason. Render it through `kadNodesLoadedText`. */
export async function kadBootstrapUrl(url: string): Promise<string> {
  // Must cover the backend's worst case, or a slow host gets a false "timed
  // out" toast while the command is still running and may yet succeed.
  // `kad_bootstrap_url` (peers.rs) runs, in sequence: an up-front DNS check
  // (5 s), `fetch_pinned_get` following up to 5 redirects — six hops of a 5 s
  // DNS check plus a 60 s request each (`build_pinned_client`) — and then a
  // 90 s wait for the network task. That is 485 s; the rest is margin.
  return withTimeout(
    invoke<string>('kad_bootstrap_url', { url }),
    'KAD URL bootstrap',
    (5 + 6 * (5 + 60) + 90 + 25) * 1000,
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
