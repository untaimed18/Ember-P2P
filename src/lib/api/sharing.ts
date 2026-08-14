import { invoke } from '@tauri-apps/api/core';
import { withTimeout } from '$lib/utils';
import type { FileInfo, MediaMetadata } from '$lib/types';

/** Open the backend-owned native picker and add every selected folder.
 *  Returns the folders actually added, which is empty when the user cancels. */
export async function addSharedFolder(): Promise<string[]> {
  return invoke('pick_shared_folder');
}

/** Approve the folders a dropped file asked about.
 *
 *  Takes only the token the backend issued with the prompt — the paths never
 *  leave the backend, because a dropped path is authorization by virtue of the
 *  OS handing it to the native window, and routing it through the renderer
 *  would throw that away. Returns how many folders were shared. */
export async function confirmDroppedFolders(token: number): Promise<number> {
  return invoke('confirm_dropped_folders', { token });
}

/** Discard a dropped-file prompt the user declined. */
export async function dismissDroppedFolders(token: number): Promise<void> {
  return invoke('dismiss_dropped_folders', { token });
}

export async function removeSharedFolder(path: string): Promise<void> {
  return invoke('remove_shared_folder', { path });
}

export async function getSharedFiles(): Promise<FileInfo[]> {
  return invoke('get_shared_files');
}

/**
 * Count and total size of files the user is actively sharing (the `shared`
 * flag is set), not the total number of files in the library. Lightweight
 * alternative to summing `getSharedFiles()` for the status bar.
 */
export async function getSharedFileCount(): Promise<{ count: number; total_bytes: number }> {
  return invoke('get_shared_file_count');
}

export async function getSharedFolders(): Promise<string[]> {
  return invoke('get_shared_folders');
}

export async function getFolderPriorities(): Promise<Record<string, string>> {
  return invoke('get_folder_priorities');
}

/** On-demand media metadata for a shared file (null for non-media files). */
export async function getFileMediaMetadata(filePath: string): Promise<MediaMetadata | null> {
  return invoke('get_file_media_metadata', { filePath });
}

/**
 * Set (or, with an empty/`none` priority, clear) the default upload priority
 * for a shared folder. Applies immediately to files under the folder and
 * persists so newly indexed files inherit it. Returns the count updated.
 */
export async function setFolderPriority(folderPath: string, priority: string): Promise<number> {
  return invoke('set_folder_priority', { folderPath, priority });
}

export async function setFilePriority(filePath: string, priority: 'verylow' | 'low' | 'normal' | 'high' | 'release' | 'auto'): Promise<void> {
  return invoke('set_file_priority', { filePath, priority });
}

export async function reloadSharedFiles(): Promise<void> {
  return invoke('reload_shared_files');
}

export async function getScanStatus(): Promise<boolean> {
  // Reads a flag, but the library page polls it every 3 s: without a deadline
  // a wedged backend latches that poll's in-flight guard for good and the
  // "hashing" banner never clears. Deliberately NOT applied to `startScan` /
  // `reloadSharedFiles` — those are legitimately long-running.
  return withTimeout(invoke<boolean>('get_scan_status'), 'get_scan_status', 8_000);
}

export async function getLibraryScanTruncated(): Promise<boolean> {
  return invoke('get_library_scan_truncated');
}

export async function stopHashing(): Promise<string[]> {
  return invoke('stop_hashing');
}

export async function resumeHashing(): Promise<void> {
  return invoke('resume_hashing');
}

export async function unshareFile(filePath: string, fileHash?: string): Promise<void> {
  return invoke('unshare_file', { filePath, fileHash });
}

export async function shareFile(filePath: string): Promise<void> {
  return invoke('share_file', { filePath });
}

export async function batchSetPriority(filePaths: string[], priority: string): Promise<number> {
  return invoke('batch_set_priority', { filePaths, priority });
}

export async function batchShare(filePaths: string[]): Promise<number> {
  return invoke('batch_share', { filePaths });
}

export async function batchUnshare(filePaths: string[]): Promise<number> {
  return invoke('batch_unshare', { filePaths });
}

/**
 * Restrict files to mutual friends, or return them to the open network.
 * Resolves with the number of files whose scope actually changed.
 */
export async function setFilesFriendsOnly(
  filePaths: string[],
  friendsOnly: boolean,
): Promise<number> {
  return invoke('set_files_friends_only', { filePaths, friendsOnly });
}

export async function unshareFolder(path: string): Promise<void> {
  return invoke('unshare_folder', { path });
}

export async function openSharedFile(filePath: string): Promise<void> {
  return invoke('open_shared_file', { filePath });
}

export async function openSharedFolder(filePath: string): Promise<void> {
  return invoke('open_shared_folder', { filePath });
}

/** Canonical path safe for convertFileSrc / in-app media playback. */
export async function resolveMediaAssetPath(filePath: string): Promise<string> {
  return invoke('resolve_media_asset_path', { filePath });
}

export async function deleteSharedFile(filePath: string, fileHash?: string): Promise<void> {
  return invoke('delete_shared_file', { filePath, fileHash });
}

export async function republishFile(fileHash: string): Promise<void> {
  return invoke('republish_file', { fileHash });
}

export async function scanMissingFiles(): Promise<{
  paths: string[];
  truncated: boolean;
  totalMissing: number;
}> {
  return invoke('scan_missing_files');
}

export async function removeMissingFiles(paths: string[]): Promise<number> {
  return invoke('remove_missing_files', { paths });
}
