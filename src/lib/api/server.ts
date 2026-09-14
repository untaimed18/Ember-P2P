import { invoke } from '@tauri-apps/api/core';
import type { ServerInfo, ServerPriority } from '$lib/types';

export async function connectToServer(ip: string, port: number): Promise<string> {
  return invoke('connect_to_server', { ip, port });
}

export async function disconnectServer(): Promise<string> {
  return invoke('disconnect_server');
}

export async function addServer(ip: string, port: number, name: string): Promise<string> {
  return invoke('add_server', { ip, port, name });
}

export async function removeServer(ip: string, port: number): Promise<string> {
  return invoke('remove_server', { ip, port });
}

/** eMule's "add to / remove from static server list". */
export async function setServerStatic(ip: string, port: number, isStatic: boolean): Promise<string> {
  return invoke('set_server_static', { ip, port, isStatic });
}

export async function setServerPriority(
  ip: string,
  port: number,
  priority: ServerPriority,
): Promise<string> {
  return invoke('set_server_priority', { ip, port, priority });
}

export async function getServerList(): Promise<ServerInfo[]> {
  return invoke('get_server_list');
}

export async function getConnectedServer(): Promise<ServerInfo | null> {
  return invoke('get_connected_server');
}

export async function downloadServerMet(url: string): Promise<string> {
  return invoke('download_server_met', { url });
}
