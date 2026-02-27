import { invoke } from '@tauri-apps/api/core';
import type { ServerInfo } from '$lib/types';

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

export async function getServerList(): Promise<ServerInfo[]> {
  return invoke('get_server_list');
}

export async function getConnectedServer(): Promise<ServerInfo | null> {
  return invoke('get_connected_server');
}
