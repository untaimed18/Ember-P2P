import { invoke } from '@tauri-apps/api/core';
import type { FileInfo, MediaMetadata } from '$lib/types';

export async function addSharedFolder(path: string): Promise<void> {
  return invoke('add_shared_folder', { path });
}

export async function removeSharedFolder(path: string): Promise<void> {
  return invoke('remove_shared_folder', { path });
}

export async function getSharedFiles(): Promise<FileInfo[]> {
  return invoke('get_shared_files');
}

/**
 * Count of files the user is actively sharing (the `shared` flag is set),
 * not the total number of files in the library. Lightweight alternative to
 * `getSharedFiles().length` for the status bar.
 */
export async function getSharedFileCount(): Promise<number> {
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
  return invoke('get_scan_status');
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

export async function unshareFolder(path: string): Promise<void> {
  return invoke('unshare_folder', { path });
}

export async function openSharedFile(filePath: string): Promise<void> {
  return invoke('open_shared_file', { filePath });
}

export async function openSharedFolder(filePath: string): Promise<void> {
  return invoke('open_shared_folder', { filePath });
}

export async function deleteSharedFile(filePath: string, fileHash?: string): Promise<void> {
  return invoke('delete_shared_file', { filePath, fileHash });
}

export async function republishFile(fileHash: string): Promise<void> {
  return invoke('republish_file', { fileHash });
}

export async function scanMissingFiles(): Promise<string[]> {
  return invoke('scan_missing_files');
}

export async function removeMissingFiles(paths: string[]): Promise<number> {
  return invoke('remove_missing_files', { paths });
}
