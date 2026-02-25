import { invoke } from '@tauri-apps/api/core';
import type { AppSettings } from '$lib/types';

export async function getSettings(): Promise<AppSettings> {
  return invoke('get_settings');
}

export async function updateSettings(settings: AppSettings): Promise<string> {
  return invoke('update_settings', { settings });
}

export async function downloadNodesDat(): Promise<string> {
  return invoke('download_nodes_dat');
}
