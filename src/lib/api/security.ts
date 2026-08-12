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
  /** False while an enabled filter has not finished (or failed) loading ranges. */
  ranges_ready: boolean;
  range_count: number;
  total_hits: number;
  entries: IpFilterEntry[];
}

export type IpFilterApplyOutcome = 'applied' | 'deferred' | 'failed';

export interface IpFilterApplyResult {
  outcome: IpFilterApplyOutcome;
  entryCount: number;
}

export interface SecurityPolicyState {
  loaded: boolean;
  resetRequired: boolean;
  reason?: string;
}

export async function getSecurityPolicyState(): Promise<SecurityPolicyState> {
  return invoke('get_security_policy_state');
}

export async function acknowledgeSecurityPolicyReset(): Promise<void> {
  return invoke('acknowledge_security_policy_reset');
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

export async function downloadAndLoadIpfilter(): Promise<IpFilterApplyResult> {
  return invoke('download_and_load_ipfilter');
}

/**
 * Download and load an ipfilter from a user-supplied URL.
 *
 * Complements `downloadAndLoadIpfilter` (fixed default URL) and
 * `pickAndImportIpfilterFile` (local file). Used for corporate / alternate
 * ipfilter distributions that aren't covered by the bundled default.
 * The backend validates the URL (DNS resolved, public-IP only, host
 * pinned), caps the response at 50 MiB, auto-extracts zip archives,
 * atomically writes to `ipfilter.dat`, and re-enables the filter.
 *
 * Returns a structured live-apply outcome; errors are reserved for download,
 * validation, and persistence failures.
 */
export async function updateIpfilterFromUrl(url: string): Promise<IpFilterApplyResult> {
  return invoke('update_ipfilter_from_url', { url });
}

/**
 * Opens a native picker in the Rust core and imports the chosen IP filter.
 *
 * The dialog deliberately lives in the backend: choosing a file there is the
 * user's authorization, whereas a path sent over IPC is not. Resolves to `null`
 * when the user dismisses the picker.
 */
export async function pickAndImportIpfilterFile(): Promise<IpFilterApplyResult | null> {
  return invoke('pick_and_import_ipfilter_file');
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
