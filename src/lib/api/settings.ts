import { invoke } from '@tauri-apps/api/core';
import type { AppSettings } from '$lib/types';

export type SettingsUpdateOutcome = 'applied' | 'restart_required' | 'deferred';
export type LiveApplyOutcome = 'applied' | 'deferred' | 'failed';

export async function getSettings(): Promise<AppSettings> {
  return invoke('get_settings');
}

export interface UpdateSettingsResult {
  outcome: SettingsUpdateOutcome;
  settings: AppSettings;
}

export interface NodesDatDownloadResult {
  outcome: LiveApplyOutcome;
  parsedCount: number;
  appliedCount?: number;
  byteCount: number;
}

export interface IpFilterDownloadResult {
  outcome: LiveApplyOutcome;
  entryCount: number;
  byteCount: number;
}

export interface UpdateSettingsOptions {
  /** Treat this save as consent to re-approve a download folder whose approval
   *  was revoked, which is otherwise unrecoverable in-app because re-picking the
   *  same path is not a change. Only the Settings page's own save button sets
   *  it: background callers (the UPnP auto-disable handler) reach this with no
   *  user present, and re-approval grants sandbox access to whatever object now
   *  sits at that path. */
  reapproveDownloadRoot?: boolean;
}

export async function updateSettings(
  settings: AppSettings,
  options: UpdateSettingsOptions = {},
): Promise<UpdateSettingsResult> {
  const result = await invoke<UpdateSettingsResult>('update_settings', {
    settings,
    reapproveDownloadRoot: options.reapproveDownloadRoot ?? false,
  });
  // Always use the canonical persisted revision, including the partial-success
  // path where runtime application was deferred because the command queue was
  // full. A retry must never submit a stale revision.
  Object.assign(settings, result.settings);
  return result;
}

/** Open the native picker for the download folder, returning the chosen path
 *  or `null` if the user cancelled.
 *
 *  The dialog runs in the backend so the chosen path is authorized there.
 *  `update_settings` rejects a *changed* `download_folder` that did not come
 *  from here, the same way shared folders can only be added through
 *  `pick_shared_folder`. */
export async function pickDownloadFolder(): Promise<string | null> {
  return invoke<string | null>('pick_download_folder');
}

export async function downloadNodesDat(): Promise<NodesDatDownloadResult> {
  return invoke('download_nodes_dat');
}

export async function downloadIpfilter(): Promise<IpFilterDownloadResult> {
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

/** Consume a native close request that preceded listener registration. */
export async function takePendingCloseRequest(): Promise<boolean> {
  return invoke('take_pending_close_request');
}

/**
 * Consume the one-shot notice that startup turned the Ember overlay on for a
 * profile that had it off. A latch rather than an event because the migration
 * behind it is already persisted and never repeats, so a notice dropped
 * because the webview was still starting would never be shown at all.
 */
export async function takePendingEmberDefaultOnNotice(): Promise<boolean> {
  return invoke('take_pending_ember_default_on_notice');
}

/**
 * Consume the one-shot notice that a staged profile restore failed or is
 * still waiting. Sticky, because the user needs to open Settings → Backup
 * to retry or discard.
 */
export async function takePendingRestoreFailedNotice(): Promise<boolean> {
  return invoke('take_pending_restore_failed_notice');
}

/** Open the official Ember website in the default browser. */
export async function openEmberWebsite(): Promise<void> {
  return invoke('open_ember_website');
}

export async function getEmberWebsiteUrl(): Promise<string> {
  return invoke('get_ember_website_url');
}

/** Absolute path to the folder holding `ember.log`, for a bug report. */
export async function getLogFolderPath(): Promise<string> {
  return invoke('get_log_folder_path');
}

export async function openLogFolder(): Promise<void> {
  return invoke('open_log_folder');
}

export type EmberShareTarget =
  | 'x'
  | 'facebook'
  | 'reddit'
  | 'bluesky'
  | 'linkedin'
  | 'telegram'
  | 'whatsapp'
  | 'email';

export async function openEmberShare(target: EmberShareTarget, text: string): Promise<void> {
  return invoke('open_ember_share', { target, text });
}

/**
 * Open a link found in a message, in the default browser.
 *
 * Unlike every other opener here this one takes a URL, because the URL is
 * whatever somebody typed into a room. The backend allows only `http` and
 * `https` and refuses embedded credentials, control characters and bidi
 * overrides; callers are still expected to confirm the destination with the
 * user first, because a link and where it goes are different things.
 */
export async function openExternalUrl(url: string): Promise<void> {
  return invoke('open_external_url', { url });
}
