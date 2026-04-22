import { invoke } from '@tauri-apps/api/core';
import type { AntiLeechSnapshot, AntiLeechReplaceResult } from '$lib/types';

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

/**
 * Download and load an ipfilter from a user-supplied URL.
 *
 * Complements `downloadAndLoadIpfilter` (fixed default URL) and
 * `importIpfilterFile` (local path). Used for corporate / alternate
 * ipfilter distributions that aren't covered by the bundled default.
 * The backend validates the URL (DNS resolved, public-IP only, host
 * pinned), caps the response at 50 MiB, auto-extracts zip archives,
 * atomically writes to `ipfilter.dat`, and re-enables the filter.
 *
 * Returns a human-readable success summary; throws with a concrete
 * error message on failure so the UI can surface it verbatim.
 */
export async function updateIpfilterFromUrl(url: string): Promise<string> {
  return invoke('update_ipfilter_from_url', { url });
}

export async function importIpfilterFile(filePath: string): Promise<string> {
  return invoke('import_ipfilter_file', { filePath });
}

// ----- Anti-leech client filter ------------------------------------

export async function getAntileechPatterns(): Promise<AntiLeechSnapshot> {
  return invoke('get_antileech_patterns');
}

export async function setAntileechPatterns(patterns: string[]): Promise<AntiLeechReplaceResult> {
  return invoke('set_antileech_patterns', { patterns });
}

export async function setAntileechEnabled(enabled: boolean): Promise<void> {
  return invoke('set_antileech_enabled', { enabled });
}

export async function resetAntileechToDefaults(): Promise<AntiLeechSnapshot> {
  return invoke('reset_antileech_to_defaults');
}
