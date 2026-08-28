import { invoke } from '@tauri-apps/api/core';
import type { Collection } from './collections';

export interface PendingDeepLink {
  id: string;
  payload: string;
}

export interface DeepLinkPreview {
  kind: 'file' | 'server' | 'serverList' | 'collection' | 'channel';
  name?: string;
  size?: number;
  hash?: string;
  /** Untrusted `eh=` digest. Shown on confirm; never passed to startDownload. */
  ember?: string;
  endpoint?: string;
  host?: string;
}

export async function previewDeepLink(payload: string): Promise<DeepLinkPreview> {
  return invoke('preview_deep_link', { payload });
}

/** Lists durable pending links. A link remains queued until it is acknowledged. */
export async function listPendingDeepLinks(): Promise<PendingDeepLink[]> {
  return invoke('list_pending_deep_links');
}

/** Acknowledge a successfully handled durable deep link. */
export async function ackPendingDeepLink(id: string): Promise<void> {
  return invoke('ack_pending_deep_link', { id });
}

/** Load an OS-delivered collection through its durable pending-link id. */
export async function openPendingCollection(id: string): Promise<Collection> {
  return invoke('open_pending_collection', { id });
}
