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

  unlisteners.push(await listen<Transfer>('transfer-started', (event) => {
    markEventUpdate();
    const t = event.payload;
    transfers.update((list) => {
      if (list.some((x) => x.id === t.id)) return list;
      return [...list, t];
    });
  }));

  unlisteners.push(await listen<ProgressPayload>('transfer-progress', (event) => {
    markEventUpdate();
    const p = event.payload;
    transfers.update((list) => {
      const idx = list.findIndex((t) => t.id === p.id);
      if (idx >= 0) {
        const existing = list[idx];
        if (existing.status === 'paused' || existing.status === 'stopped' || existing.status === 'completed' || existing.status === 'failed' || existing.status === 'verifying' || existing.status === 'completing') {
          return list;
        }
        list[idx] = {
          ...existing,
          transferred: p.downloaded,
          progress: p.progress,
          speed: p.speed,
          status: 'active',
        };
        return [...list];
      }
      return list;
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

  unlisteners.push(await listen<TransferEventPayload & { status?: string; peer_id?: string; sources?: number }>(
    'transfer-status',
    (event) => {
      markEventUpdate();
      const { id, status, peer_id, sources } = event.payload;
      transfers.update((list) =>
        list.map((t) => {
          if (t.id !== id) return t;
          const updated = { ...t };
          if (status) updated.status = status as Transfer['status'];
          if (peer_id) {
            updated.peer_id = peer_id;
            updated.peer_name = peer_id;
          }
          if (sources !== undefined) updated.sources = sources;
          return updated;
        })
      );
    }
  ));

  unlisteners.push(await listen<{ id: string; sources: number; active_sources: number; queued_sources: number }>(
    'transfer-sources',
    (event) => {
      markEventUpdate();
      const { id, sources, active_sources, queued_sources } = event.payload;
      transfers.update((list) =>
        list.map((t) => {
          if (t.id !== id) return t;
          return { ...t, sources, active_sources, queued_sources };
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
  let busy = false;
  const interval = setInterval(async () => {
    if (busy) return;
    // Skip poll if events recently updated the store (avoid redundant fetches)
    if (Date.now() - lastEventUpdate < 2000) return;
    busy = true;
    try {
      const all = await Promise.race([
        getTransfers(),
        new Promise<never>((_, reject) => setTimeout(() => reject('timeout'), 4000)),
      ]);
      transfers.set(all);
    } catch {
      // Ignore timeouts and errors
    } finally {
      busy = false;
    }
  }, 3000);

  return () => clearInterval(interval);
}
