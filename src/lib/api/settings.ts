import { invoke } from '@tauri-apps/api/core';
import * as m from '$lib/paraglide/messages';
import type { AppSettings, WebService } from '$lib/types';
import { flushToastActionsBeforeExit } from '$lib/stores/toast';

export type SettingsUpdateOutcome = 'applied' | 'restart_required' | 'deferred';
export type LiveApplyOutcome = 'applied' | 'deferred' | 'failed';

export async function getSettings(): Promise<AppSettings> {
  return invoke('get_settings');
}

/** The settings the network stack reads once, as this run of Ember started
 *  with them. A saved value that differs takes effect after a restart. */
export interface LaunchSettings {
  tcp_port: number;
  udp_port: number;
  upnp_enabled: boolean;
}

export async function getLaunchSettings(): Promise<LaunchSettings> {
  return invoke('get_launch_settings');
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
   *  same path is not a change. Only picking the folder in Settings sets it:
   *  background callers (the UPnP auto-disable handler) reach this with no
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
  return invoke<string | null>('pick_download_folder', { title: m.picker_download_folder() });
}

/** Open the native picker for the external Preview player, returning the
 *  chosen path or `null` if the user cancelled.
 *
 *  Same provenance rule as `pickDownloadFolder`, and it matters more here:
 *  this names a program Ember will execute, so `update_settings` refuses a
 *  *changed* `preview_player` that did not come from this dialog. Clearing it
 *  back to empty needs no picker. */
export async function pickPreviewPlayer(): Promise<string | null> {
  return invoke<string | null>('pick_preview_player', { title: m.picker_preview_player() });
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
 *  File → Exit) runs before the process dies. A cancel or removal still
 *  behind an Undo toast is sent first. */
export async function quitApp(): Promise<void> {
  await flushToastActionsBeforeExit();
  return invoke('quit_app');
}

/** Exits decided outside the window (the tray, "exit" on close, "when
 *  downloads finish") ask through this to have pending Undo actions sent. */
export const QUIT_REQUESTED_EVENT = 'ember:quit-requested';

/** Whether a cancel or removal is waiting behind an Undo toast. */
export async function setPendingUndo(pending: boolean): Promise<void> {
  return invoke('set_pending_undo', { pending });
}

/** Persist the close-button behavior without serialising the whole
 *  `AppSettings` payload. Use this from the close-confirmation dialog
 *  when the user ticks "Remember my choice"; full settings saves still
 *  go through `updateSettings`. */
export async function setCloseBehavior(behavior: 'ask' | 'tray' | 'exit'): Promise<void> {
  return invoke('set_close_behavior', { behavior });
}

/** The limits the tray and the status bar change directly. Fields left out
 *  keep their saved values. */
export interface QuickLimitsPatch {
  alt_speed_enabled?: boolean;
  max_upload_speed?: number;
  max_download_speed?: number;
  alt_max_upload_speed?: number;
  alt_max_download_speed?: number;
}

/** Emitted with the full persisted settings after a save made outside the
 *  Settings page (the tray's alternative-speed toggle, the status bar). */
export const SETTINGS_CHANGED_EVENT = 'ember:settings-changed';

/** Persist and apply speed limits without a full settings save. Resolves with
 *  the settings as saved; {@link SETTINGS_CHANGED_EVENT} follows. */
export async function setQuickLimits(patch: QuickLimitsPatch): Promise<AppSettings> {
  return invoke('set_quick_limits', { patch });
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

/**
 * Consume the one-shot notice that startup discarded a staged restore because
 * it had waited too long to be applied. Nothing on disk records it afterwards.
 */
export async function takePendingRestoreExpiredNotice(): Promise<boolean> {
  return invoke('take_pending_restore_expired_notice');
}

/**
 * Consume the folder an applied restore put in place of a download folder on
 * a network share, or null. Nothing else records that it happened.
 */
export async function takePendingRestoreDownloadFolderNotice(): Promise<string | null> {
  return invoke('take_pending_restore_download_folder_notice');
}

/**
 * Consume the notice that known.met could not be read this session (`reset`:
 * the catalog was lost and sharing reset to fail-closed), or null.
 */
export async function takePendingKnownMetNotice(): Promise<{ reset: boolean } | null> {
  return invoke('take_pending_known_met_notice');
}

/** Open the official Ember website in the default browser. */
export async function openEmberWebsite(): Promise<void> {
  return invoke('open_ember_website');
}

/** Open the project's Buy Me a Coffee page. The address is fixed in the backend. */
export async function openSupportPage(): Promise<void> {
  return invoke('open_support_page');
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
 * `https`, refuses embedded credentials, control characters and bidi
 * overrides, rejects hosts that are — or resolve to — loopback, private or
 * link-local space, and then asks the user to confirm with a native dialog
 * naming the host.
 *
 * Callers must not add a confirmation of their own. The native one cannot be
 * skipped by a compromised renderer, which is the whole point of it, and a
 * second prompt for the same decision only teaches people to dismiss both.
 * A declined dialog resolves successfully: nothing was opened, which is not
 * an error.
 */
export async function openExternalUrl(url: string): Promise<void> {
  return invoke('open_external_url', { url });
}

/**
 * Open a configured web service for one file — eMule's right-click → Web
 * services.
 *
 * The service is named by its index in `AppSettings.web_services` rather than
 * by URL: the backend reads the template from settings, so what opens is a URL
 * the user stored rather than one this renderer composed. It also has to be
 * that way round, because a template's `#hashid` parses as a URL fragment and
 * only becomes a destination once the placeholders are filled.
 *
 * Goes through the same native confirmation as {@link openExternalUrl}, which
 * is also where the user is told which third party is about to learn what they
 * are looking for. Do not add a confirmation of your own. A declined dialog
 * resolves successfully.
 */
export async function openWebService(
  serviceIndex: number,
  fileHash: string,
  fileName: string,
  fileSize: number,
): Promise<void> {
  return invoke('open_web_service', {
    serviceIndex,
    fileHash,
    fileName,
    fileSize,
  });
}

/**
 * Let the user pick an eMule `webservices.dat` and return what it holds.
 *
 * Returns `null` if the picker was dismissed. Nothing is persisted: merge the
 * result into the settings list and save it like any other change, so there is
 * one persistence path. The file is chosen by a native dialog in the backend,
 * because picking a file is the authorization and a path from this renderer
 * would not be.
 */
export async function importWebServicesFile(): Promise<WebService[] | null> {
  return invoke('pick_and_import_webservices_file', { title: m.picker_webservices() });
}

/**
 * The example service Settings offers as a one-click add.
 *
 * Read from the backend rather than hardcoded here so the string that gets
 * stored is the reviewed one, and so the offer cannot drift from what the
 * validator accepts.
 */
export async function getExampleWebService(): Promise<WebService> {
  return invoke('get_example_web_service');
}
