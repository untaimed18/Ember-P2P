import { invoke } from '@tauri-apps/api/core';
import type { NetworkStats, PeerInfo, KadContact, KadSearchEntry } from '$lib/types';

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
  return invoke('kad_connect');
}

export async function kadDisconnect(): Promise<void> {
  return invoke('kad_disconnect');
}

export async function kadBootstrapIp(ip: string, port: number): Promise<void> {
  return invoke('kad_bootstrap_ip', { ip, port });
}

export async function kadBootstrapUrl(url: string): Promise<void> {
  return invoke('kad_bootstrap_url', { url });
}

export async function kadBootstrapClients(): Promise<void> {
  return invoke('kad_bootstrap_clients');
}

export async function kadRecheckFirewall(): Promise<void> {
  return invoke('kad_recheck_firewall');
}

export async function getKadContacts(): Promise<KadContact[]> {
  return invoke('get_kad_contacts');
}

export async function getKadSearches(): Promise<KadSearchEntry[]> {
  return invoke('get_kad_searches');
}
