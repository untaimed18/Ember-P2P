import { invoke } from '@tauri-apps/api/core';
import type { Collection } from './collections';

export interface PendingDeepLink {
  id: string;
  payload: string;
}

/** Lists durable pending links. A link remains queued until it is acknowledged. */
export async function listPendingDeepLinks(): Promise<PendingDeepLink[]> {
  return invoke('list_pending_deep_links');
}

/** Acknowledge a successfully handled durable deep link. */
export async function ackPendingDeepLink(id: string): Promise<void> {
  return invoke('ack_pending_deep_link', { id });
}

/**
 * Load a .emulecollection that was opened via the OS file association. Unlike
 * {@link loadCollection}, the path may live anywhere on disk (Downloads,
 * Desktop, etc.) because the user explicitly opened it.
 */
export async function openCollectionFile(path: string): Promise<Collection> {
  return invoke('open_collection_file', { path });
}
