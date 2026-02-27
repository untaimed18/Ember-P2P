import { writable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import type { UnlistenFn } from '@tauri-apps/api/event';
import type { Transfer } from '$lib/types';
import { getTransfers } from '$lib/api/transfers';

interface ProgressPayload {
  id: string;
  downloaded: number;
  total: number;
  progress: number;
  speed: number;
}

interface TransferEventPayload {
  id: string;
  error?: string;
}

export const transfers = writable<Transfer[]>([]);

let initialized = false;
let unlisteners: UnlistenFn[] = [];

export async function initTransferStore() {
  if (initialized) return;
  initialized = true;

  unlisteners.push(await listen<ProgressPayload>('transfer-progress', (event) => {
    markEventUpdate();
    const p = event.payload;
    transfers.update((list) => {
      const idx = list.findIndex((t) => t.id === p.id);
      if (idx >= 0) {
        list[idx] = {
          ...list[idx],
          transferred: p.downloaded,
          progress: p.progress,
          speed: p.speed,
          status: 'active',
        };
      }
      return [...list];
    });
  }));

  unlisteners.push(await listen<TransferEventPayload>('transfer-complete', (event) => {
    markEventUpdate();
    const id = event.payload.id;
    transfers.update((list) =>
      list.map((t) =>
        t.id === id ? { ...t, status: 'completed' as const, progress: 100, speed: 0 } : t
      )
    );
  }));

  unlisteners.push(await listen<TransferEventPayload>('transfer-failed', (event) => {
    markEventUpdate();
    const { id, error } = event.payload;
    transfers.update((list) =>
      list.map((t) =>
        t.id === id ? { ...t, status: 'failed' as const, speed: 0, failure_reason: error } : t
      )
    );
  }));

  unlisteners.push(await listen<TransferEventPayload & { status?: string; peer_id?: string }>(
    'transfer-status',
    (event) => {
      markEventUpdate();
      const { id, status, peer_id } = event.payload;
      transfers.update((list) =>
        list.map((t) => {
          if (t.id !== id) return t;
          const updated = { ...t };
          if (status) updated.status = status as Transfer['status'];
          if (peer_id) {
            updated.peer_id = peer_id;
            updated.peer_name = peer_id;
          }
          return updated;
        })
      );
    }
  ));

  try {
    const all = await getTransfers();
    transfers.set(all);
  } catch {
    // Backend not ready yet
  }
}

export function cleanupTransferStore() {
  for (const unlisten of unlisteners) unlisten();
  unlisteners = [];
  initialized = false;
}

let lastEventUpdate = 0;

function markEventUpdate() {
  lastEventUpdate = Date.now();
}

export function startTransferPoll() {
  const interval = setInterval(async () => {
    if (Date.now() - lastEventUpdate < 3000) return;
    try {
      const all = await getTransfers();
      transfers.set(all);
    } catch {
      // Ignore
    }
  }, 2000);

  return () => clearInterval(interval);
}
