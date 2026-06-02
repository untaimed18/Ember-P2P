import { invoke } from '@tauri-apps/api/core';
import type { Collection } from './collections';

/**
 * Drain and return every deep-link payload (ed2k:// URI or .emulecollection
 * path) the backend has buffered. Called on mount and on each
 * `deep-link-received` event. The backend clears the buffer atomically, so
 * concurrent callers never see the same payload twice.
 */
export async function takePendingDeepLinks(): Promise<string[]> {
  return invoke('take_pending_deep_links');
}

/**
 * Load a .emulecollection that was opened via the OS file association. Unlike
 * {@link loadCollection}, the path may live anywhere on disk (Downloads,
 * Desktop, etc.) because the user explicitly opened it.
 */
export async function openCollectionFile(path: string): Promise<Collection> {
  return invoke('open_collection_file', { path });
}
