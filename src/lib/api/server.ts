import { invoke } from '@tauri-apps/api/core';
import type { ServerInfo, ServerLogLine, ServerPriority } from '$lib/types';

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

/** The backend's retained server log, oldest line first. Used to restore the
 *  history after a reload of the webview, which the frontend store cannot
 *  survive on its own. */
export async function getServerLog(): Promise<ServerLogLine[]> {
  return invoke('get_server_log');
}

/** Discard the backend's retained log, so clearing the view is permanent
 *  rather than undone by the next reload. */
export async function clearServerLogHistory(): Promise<void> {
  return invoke('clear_server_log');
}

export async function downloadServerMet(url: string): Promise<string> {
  return invoke('download_server_met', { url });
}
