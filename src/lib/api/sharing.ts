import { invoke } from '@tauri-apps/api/core';
import type { FileInfo } from '$lib/types';

export async function addSharedFolder(path: string): Promise<void> {
  return invoke('add_shared_folder', { path });
}

export async function removeSharedFolder(path: string): Promise<void> {
  return invoke('remove_shared_folder', { path });
}

export async function getSharedFiles(): Promise<FileInfo[]> {
  return invoke('get_shared_files');
}

export async function getSharedFolders(): Promise<string[]> {
  return invoke('get_shared_folders');
}

export async function setFilePriority(fileHash: string, priority: string): Promise<void> {
  return invoke('set_file_priority', { fileHash, priority });
}

export async function reloadSharedFiles(): Promise<void> {
  return invoke('reload_shared_files');
}

export async function getScanStatus(): Promise<boolean> {
  return invoke('get_scan_status');
}

export async function unshareFile(fileHash: string): Promise<void> {
  return invoke('unshare_file', { fileHash });
}

export async function openSharedFile(filePath: string): Promise<void> {
  return invoke('open_shared_file', { filePath });
}

export async function openSharedFolder(filePath: string): Promise<void> {
  return invoke('open_shared_folder', { filePath });
}
