import { invoke } from '@tauri-apps/api/core';
import type { FileInfo } from '$lib/types';

export async function addSharedFolder(path: string): Promise<FileInfo[]> {
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
