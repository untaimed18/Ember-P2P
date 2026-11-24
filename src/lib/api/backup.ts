import { invoke } from '@tauri-apps/api/core';
import * as m from '$lib/paraglide/messages';
import { isServer } from '$lib/runtime';
import { saveFrom, uploadFile } from '$lib/runtime/web/files';

export interface BackupSummary {
  path: string;
  bytes: number;
  files: number;
  /** Unix seconds. */
  created_at: number;
  /** Files left out because they could not be read: only `chat-history.key`,
   *  when chat is locked. */
  skipped: string[];
}

export interface BackupPreview {
  app_version: string;
  created_at: number;
  schema_version: number;
  files: string[];
  total_bytes: number;
  includes_identity: boolean;
  /** The backup's database is newer than this build can open, so a restore
   *  would be refused. */
  schema_too_new: boolean;
  /** Profile files the backup does not carry, which keep this device's copy. */
  missing: string[];
  /** The backup brings a database but no chat-history key, so this device's
   *  key is set aside and chat history stays locked after the restore. */
  chat_key_set_aside: boolean;
}

export interface RestoreSummary {
  /** Files written to the staging directory, applied on the next launch. */
  staged: string[];
  /** Profile files the backup does not carry, which keep this device's copy. */
  missing: string[];
  /** See `BackupPreview.chat_key_set_aside`. */
  chat_key_set_aside: boolean;
  app_version: string;
  created_at: number;
}

export interface PendingRestoreStatus {
  pending: boolean;
  /** Unix seconds; 0 when nothing is staged. */
  staged_at: number;
  /** Unix seconds after which a launch discards the restore instead of
   *  applying it; 0 when nothing is staged or the restore never expires. */
  expires_at: number;
  app_version: string;
  files: number;
}

/** Write an encrypted profile backup. The save location is chosen in a native
 *  dialog; on emberd the browser saves it, and `path` is the name it saves
 *  it as. `webviewPrefs` is the window's own preferences, from `collectBackupPrefs`. */
export async function exportBackup(
  passphrase: string,
  webviewPrefs: Record<string, string> | null,
): Promise<BackupSummary | null> {
  if (isServer) {
    const summary = await invoke<BackupSummary>('export_backup_for_download', { passphrase, webviewPrefs });
    saveFrom('/api/backup');
    return summary;
  }
  return invoke('export_backup', {
    passphrase,
    webviewPrefs,
    title: m.picker_backup_save(),
    filter: m.picker_filter_backup(),
  });
}

/** emberd: send a backup from the browser's computer, chosen for restore as
 *  {@link pickBackupFile} chooses one. */
export async function uploadBackupFile(file: File): Promise<void> {
  await uploadFile('/api/backup', file);
}

/** The window preferences a restore applied at this launch brought back, once. */
export async function takePendingRestoredPrefs(): Promise<Record<string, string> | null> {
  return invoke('take_pending_restored_prefs');
}

/** Native open-dialog for restore. Returns the display path, or null if cancelled. */
export async function pickBackupFile(): Promise<string | null> {
  return invoke('pick_backup_file', { title: m.picker_backup_open(), filter: m.picker_filter_backup() });
}

/** Forget a previously picked restore file. */
export async function clearPickedBackup(): Promise<void> {
  return invoke('clear_picked_backup');
}

/** Decrypt and inspect the backup picked via `pickBackupFile`. */
export async function previewBackup(passphrase: string): Promise<BackupPreview> {
  return invoke('preview_backup', { passphrase });
}

/** Stage the picked backup; contents are swapped in during the next launch. */
export async function importBackup(passphrase: string): Promise<RestoreSummary> {
  return invoke('import_backup', { passphrase });
}

/** What the next launch will apply, if anything. */
export async function pendingRestoreStatus(): Promise<PendingRestoreStatus> {
  return invoke('pending_restore_status');
}

/** Throw away a staged restore so the next launch changes nothing. */
export async function discardPendingRestore(): Promise<void> {
  return invoke('discard_pending_restore');
}
