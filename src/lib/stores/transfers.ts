import { writable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import type { UnlistenFn } from '@tauri-apps/api/event';
import type { Transfer } from '$lib/types';
import { getTransfers } from '$lib/api/transfers';

interface ProgressPayload {
  id: string;
  downloaded: number;
  uploaded?: number;
  total: number;
  progress: number;
  speed: number;
  upload_time?: number;
}

interface TransferEventPayload {
  id: string;
  error?: string;
  failure_reason?: string;
  failure_kind?: Transfer['failure_kind'];
  failure_stage?: string;
  health?: Transfer['health'];
  health_reason?: string;
  stalled_since?: number;
  sources?: number;
  peer_id?: string;
}

export const transfers = writable<Transfer[]>([]);

let initialized = false;
let unlisteners: UnlistenFn[] = [];
let pollInterval: ReturnType<typeof setInterval> | null = null;
let pollConsumers = 0;

const pendingProgress = new Map<string, ProgressPayload>();
let progressFlushScheduled = false;

function scheduleProgressFlush() {
  if (progressFlushScheduled) return;
  progressFlushScheduled = true;
  if (typeof requestAnimationFrame === 'function' && document.visibilityState === 'visible') {
    requestAnimationFrame(flushProgress);
  } else {
    setTimeout(flushProgress, 32);
  }
}

function flushProgress() {
  progressFlushScheduled = false;
  if (pendingProgress.size === 0) return;
  const batch = new Map(pendingProgress);
  pendingProgress.clear();
  transfers.update((list) => {
    let changed = false;
    const skipStatuses: Transfer['status'][] = ['paused', 'stopped', 'completed', 'failed', 'verifying', 'completing', 'hashing', 'insufficient'];
    for (const [id, p] of batch) {
      const idx = list.findIndex((t) => t.id === id);
      if (idx < 0) continue;
      const existing = list[idx];
      if (skipStatuses.includes(existing.status)) continue;
      const transferred = p.uploaded ?? p.downloaded ?? 0;
      list[idx] = {
        ...existing,
        transferred,
        completed_size: transferred,
        progress: p.progress,
        speed: p.speed,
        status: existing.status === 'searching' || existing.status === 'queued' ? existing.status : 'active',
        health: 'healthy',
        health_reason: undefined,
        stalled_since: undefined,
        ...(p.upload_time != null ? { upload_time: p.upload_time } : {}),
      };
      changed = true;
    }
    return changed ? [...list] : list;
  });
}

export async function initTransferStore() {
  if (initialized) return;

  const unsubs = await Promise.all([
    listen<Transfer>('transfer-started', (event) => {
      markEventUpdate();
      const t = event.payload;
      transfers.update((list) => {
        if (list.some((x) => x.id === t.id)) return list;
        return [...list, t];
      });
    }),
    listen<ProgressPayload>('transfer-progress', (event) => {
      markEventUpdate();
      const p = event.payload;
      pendingProgress.set(p.id, p);
      scheduleProgressFlush();
    }),
    listen<TransferEventPayload>('transfer-complete', (event) => {
      markEventUpdate();
      const id = event.payload.id;
      transfers.update((list) =>
        list.map((t) =>
          t.id === id ? { ...t, status: 'completed' as const, progress: 100, speed: 0, transferred: t.total_size, completed_size: t.total_size } : t
        )
      );
    }),
    listen<TransferEventPayload>('transfer-failed', (event) => {
      markEventUpdate();
      const { id, error, failure_kind, failure_stage } = event.payload;
      transfers.update((list) =>
        list.map((t) =>
          t.id === id
            ? {
                ...t,
                status: 'failed' as const,
                speed: 0,
                failure_reason: error,
                failure_kind,
                failure_stage,
              }
            : t
        )
      );
    }),
    listen<TransferEventPayload & { status?: string }>(
      'transfer-status',
      (event) => {
        markEventUpdate();
        const {
          id,
          status,
          peer_id,
          sources,
          error,
          failure_reason,
          failure_kind,
          failure_stage,
          health,
          health_reason,
          stalled_since,
        } = event.payload;
        transfers.update((list) =>
          list.map((t) => {
            if (t.id !== id) return t;
            const updated = { ...t };
            if (status) updated.status = status as Transfer['status'];
            if (peer_id) {
              updated.peer_id = peer_id;
            }
            if (sources !== undefined) updated.sources = sources;
            if (failure_reason !== undefined) updated.failure_reason = failure_reason;
            else if (error !== undefined) updated.failure_reason = error;
            if (failure_kind !== undefined) updated.failure_kind = failure_kind;
            if (failure_stage !== undefined) updated.failure_stage = failure_stage;
            if (health !== undefined) updated.health = health;
            if (health_reason !== undefined) updated.health_reason = health_reason;
            if (stalled_since !== undefined) updated.stalled_since = stalled_since;
            return updated;
          })
        );
      }
    ),
    listen<TransferEventPayload>('transfer-health', (event) => {
      markEventUpdate();
      const { id, error, failure_reason, failure_kind, failure_stage, health, health_reason, stalled_since } = event.payload;
      transfers.update((list) =>
        list.map((t) =>
          t.id === id
            ? {
                ...t,
                failure_reason: failure_reason ?? error ?? t.failure_reason,
                failure_kind: failure_kind ?? t.failure_kind,
                failure_stage: failure_stage ?? t.failure_stage,
                health: health ?? t.health,
                health_reason: health_reason,
                stalled_since,
              }
            : t
        )
      );
    }),
    listen<{ id: string; speed: number }>('transfer-speed-decay', (event) => {
      markEventUpdate();
      const { id, speed } = event.payload;
      transfers.update((list) =>
        list.map((t) => (t.id === id ? { ...t, speed } : t))
      );
    }),
    listen<{ id: string; sources: number; active_sources: number; queued_sources: number }>(
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
    ),
    listen<{ transfer_id: string; queue_rank?: number }>(
      'transfer-source-detail',
      (event) => {
        markEventUpdate();
        const { transfer_id, queue_rank } = event.payload;
        if (queue_rank === undefined || queue_rank === null) return;
        transfers.update((list) =>
          list.map((t) => (t.id === transfer_id ? { ...t, queue_rank } : t))
        );
      }
    ),
  ]);
  initialized = true;
  unlisteners.push(...unsubs);

  try {
    const all = await getTransfers();
    transfers.update((current) => {
      const currentById = new Map(current.map((t) => [t.id, t]));
      const merged = all.map((apiItem) => {
        const eventItem = currentById.get(apiItem.id);
        if (eventItem) {
          return {
            ...apiItem,
            speed: eventItem.speed,
            progress: Math.max(apiItem.progress, eventItem.progress),
            transferred: Math.max(apiItem.transferred, eventItem.transferred),
            completed_size: Math.max(apiItem.completed_size || 0, eventItem.completed_size || 0),
            health: eventItem.health ?? apiItem.health,
            health_reason: eventItem.health_reason ?? apiItem.health_reason,
            stalled_since: eventItem.stalled_since ?? apiItem.stalled_since,
            failure_reason: eventItem.failure_reason ?? apiItem.failure_reason,
            failure_kind: eventItem.failure_kind ?? apiItem.failure_kind,
            failure_stage: eventItem.failure_stage ?? apiItem.failure_stage,
          };
        }
        return apiItem;
      });
      for (const t of current) {
        if (!merged.some((m) => m.id === t.id)) {
          merged.push(t);
        }
      }
      return merged;
    });
  } catch {
    // Backend not ready yet
  }
}

export function cleanupTransferStore() {
  for (const unlisten of unlisteners) unlisten();
  unlisteners = [];
  if (pollInterval !== null) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
  pollConsumers = 0;
  pendingProgress.clear();
  progressFlushScheduled = false;
  initialized = false;
  transfers.set([]);
}

let lastEventUpdate = 0;

function markEventUpdate() {
  lastEventUpdate = Date.now();
}

export function startTransferPoll() {
  pollConsumers += 1;
  if (pollInterval !== null) {
    return () => {
      pollConsumers = Math.max(0, pollConsumers - 1);
      if (pollConsumers === 0 && pollInterval !== null) {
        clearInterval(pollInterval);
        pollInterval = null;
      }
    };
  }

  let busy = false;

  const poll = async () => {
    if (busy) return;
    if (Date.now() - lastEventUpdate < 2000) return;
    busy = true;
    try {
      const all = await Promise.race([
        getTransfers(),
        new Promise<never>((_, reject) => setTimeout(() => reject('timeout'), 4000)),
      ]);
      transfers.update((current) => {
        const currentById = new Map(current.map((t) => [t.id, t]));
        const apiIds = new Set(all.map((t) => t.id));
        const merged = all.map((apiItem) => {
          const eventItem = currentById.get(apiItem.id);
          if (eventItem && eventItem.status === 'active' && apiItem.status === 'active') {
            return {
              ...apiItem,
              progress: Math.max(apiItem.progress, eventItem.progress),
              speed: eventItem.speed,
              transferred: Math.max(apiItem.transferred, eventItem.transferred),
              completed_size: Math.max(apiItem.completed_size || 0, eventItem.completed_size || 0),
              health: eventItem.health ?? apiItem.health,
              health_reason: eventItem.health_reason ?? apiItem.health_reason,
              stalled_since: eventItem.stalled_since ?? apiItem.stalled_since,
              failure_reason: eventItem.failure_reason ?? apiItem.failure_reason,
              failure_kind: eventItem.failure_kind ?? apiItem.failure_kind,
              failure_stage: eventItem.failure_stage ?? apiItem.failure_stage,
            };
          }
          return apiItem;
        });
        const terminalStatuses: Transfer['status'][] = ['completed', 'failed', 'stopped'];
        for (const t of current) {
          if (!apiIds.has(t.id) && !terminalStatuses.includes(t.status)) {
            merged.push(t);
          }
        }
        return merged;
      });
    } catch {
      // Ignore timeouts and errors
    } finally {
      busy = false;
    }
  };

  poll();
  pollInterval = setInterval(poll, 3000);

  return () => {
    pollConsumers = Math.max(0, pollConsumers - 1);
    if (pollConsumers === 0 && pollInterval !== null) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
  };
}
