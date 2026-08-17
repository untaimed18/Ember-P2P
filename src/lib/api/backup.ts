import { invoke } from '@tauri-apps/api/core';

export interface BackupSummary {
  path: string;
  bytes: number;
  files: number;
  /** Unix seconds. */
  created_at: number;
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
}

export interface RestoreSummary {
  /** Files written to the staging directory, applied on the next launch. */
  staged: string[];
  /** Files this build knows about that the backup did not carry. */
  missing: string[];
  app_version: string;
  created_at: number;
}

export interface PendingRestoreStatus {
  pending: boolean;
  /** Unix seconds; 0 when nothing is staged. */
  staged_at: number;
  app_version: string;
  files: number;
}

/** Write an encrypted profile backup. The save location is chosen in a native dialog. */
export async function exportBackup(passphrase: string): Promise<BackupSummary | null> {
  return invoke('export_backup', { passphrase });
}

/** Native open-dialog for restore. Returns the display path, or null if cancelled. */
export async function pickBackupFile(): Promise<string | null> {
  return invoke('pick_backup_file');
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
