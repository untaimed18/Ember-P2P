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

export async function downloadIpfilter(): Promise<string> {
  return invoke('download_ipfilter');
}

/** Hide the main window to the system tray. The Tauri-side handler keeps
 *  the process alive; the user can reopen via the tray icon's Show menu
 *  entry or a left-click on the tray icon. */
export async function hideToTray(): Promise<void> {
  return invoke('hide_to_tray');
}

/** Fully exit Ember. Routes through `app.exit(0)` on the Rust side so the
 *  existing network/save shutdown sequence (the same one triggered by
 *  File → Exit) runs before the process dies. */
export async function quitApp(): Promise<void> {
  return invoke('quit_app');
}

/** Persist the close-button behavior without serialising the whole
 *  `AppSettings` payload. Use this from the close-confirmation dialog
 *  when the user ticks "Remember my choice"; full settings saves still
 *  go through `updateSettings`. */
export async function setCloseBehavior(behavior: 'ask' | 'tray' | 'exit'): Promise<void> {
  return invoke('set_close_behavior', { behavior });
}
