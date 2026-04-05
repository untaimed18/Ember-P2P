import { invoke } from '@tauri-apps/api/core';

export interface IpFilterEntry {
  start_ip: string;
  end_ip: string;
  description: string;
  hits: number;
}

export interface IpFilterStats {
  enabled: boolean;
  block_private: boolean;
  range_count: number;
  total_hits: number;
  entries: IpFilterEntry[];
}

export async function getIpFilterStats(): Promise<IpFilterStats> {
  return invoke('get_ip_filter_stats');
}

export async function addIpFilterRange(
  startIp: string,
  endIp: string,
  description: string
): Promise<void> {
  return invoke('add_ip_filter_range', { startIp, endIp, description });
}

export async function removeIpFilterRange(startIp: string, endIp: string): Promise<void> {
  return invoke('remove_ip_filter_range', { startIp, endIp });
}

export async function setIpFilterEnabled(enabled: boolean): Promise<void> {
  return invoke('set_ip_filter_enabled', { enabled });
}

export async function setBlockPrivateIps(blockPrivate: boolean): Promise<void> {
  return invoke('set_block_private_ips', { blockPrivate });
}

export async function downloadAndLoadIpfilter(): Promise<string> {
  return invoke('download_and_load_ipfilter');
}

export async function importIpfilterFile(filePath: string): Promise<string> {
  return invoke('import_ipfilter_file', { filePath });
}
