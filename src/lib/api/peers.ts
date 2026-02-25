import { invoke } from '@tauri-apps/api/core';
import type { NetworkStats, PeerInfo } from '$lib/types';

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
