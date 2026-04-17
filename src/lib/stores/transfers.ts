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

const STATUS_PRIORITY: Record<string, number> = {
  searching: 0,
  queued: 1,
  active: 2,
  paused: 3,
  stopped: 3,
  hashing: 4,
  insufficient: 4,
  noneneeded: 4,
  failed: 5,
  verifying: 6,
  completing: 7,
  completed: 8,
};

function isMoreAdvancedStatus(eventStatus: string, apiStatus: string): boolean {
  return (STATUS_PRIORITY[eventStatus] ?? 0) > (STATUS_PRIORITY[apiStatus] ?? 0);
}

/** Known backend Transfer statuses. Used to runtime-narrow event payloads
 *  before casting to `Transfer['status']`, so an unexpected backend string
 *  can never silently widen TypeScript's view of truth (D31). */
const KNOWN_STATUSES = new Set<Transfer['status']>([
  'searching',
  'queued',
  'active',
  'paused',
  'stopped',
  'hashing',
  'insufficient',
  'noneneeded',
  'failed',
  'verifying',
  'completing',
  'completed',
]);

function narrowStatus(raw: string | undefined): Transfer['status'] | undefined {
  if (!raw) return undefined;
  return (KNOWN_STATUSES as Set<string>).has(raw) ? (raw as Transfer['status']) : undefined;
}

/** Terminal statuses that must not be downgraded by later events. D30:
 *  once a transfer is `completed`, a late `transfer-failed` must not flip
 *  it back to `failed`, and vice versa. */
const TERMINAL_STATUSES = new Set<Transfer['status']>(['completed', 'failed']);

function isTerminal(s: Transfer['status']): boolean {
  return TERMINAL_STATUSES.has(s);
}

/** Statuses for which `transfer-speed-decay` should actually update `speed`.
 *  Paused / stopped / completed / failed rows are intentionally frozen so
 *  the UI can show the last-known speed (or zero) without the decay ticker
 *  stomping it. D5. */
const SPEED_DECAY_APPLIES: ReadonlySet<Transfer['status']> = new Set<Transfer['status']>([
  'active',
  'searching',
  'queued',
  'verifying',
  'completing',
  'hashing',
]);

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
  active_sources?: number;
  queued_sources?: number;
  peer_id?: string;
}

export const transfers = writable<Transfer[]>([]);

let initialized = false;
let unlisteners: UnlistenFn[] = [];
let pollInterval: ReturnType<typeof setInterval> | null = null;
let pollConsumers = 0;

// Pending progress payloads per transfer id. We keep the newest payload
// and the first-seen timestamp so that a `transfer-progress` that arrives
// ahead of its `transfer-started` (or for a row the API poll hasn't
// caught up on yet) is not silently dropped — it's retried on the next
// flush up to ORPHAN_PROGRESS_TTL_MS, then discarded.
interface PendingProgress {
  payload: ProgressPayload;
  firstSeen: number;
}
const pendingProgress = new Map<string, PendingProgress>();
const ORPHAN_PROGRESS_TTL_MS = 5000;
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
  const now = Date.now();
  const batch = Array.from(pendingProgress.entries());
  const retained = new Map<string, PendingProgress>();
  transfers.update((list) => {
    let changed = false;
    const skipStatuses: Transfer['status'][] = ['paused', 'stopped', 'completed', 'failed', 'verifying', 'completing', 'hashing', 'insufficient', 'noneneeded'];
    for (const [id, entry] of batch) {
      const p = entry.payload;
      const idx = list.findIndex((t) => t.id === id);
      if (idx < 0) {
        // No matching row yet. Keep the latest payload and re-try on the
        // next frame unless the race window has clearly expired.
        if (now - entry.firstSeen < ORPHAN_PROGRESS_TTL_MS) {
          retained.set(id, entry);
        }
        continue;
      }
      const existing = list[idx];
      if (skipStatuses.includes(existing.status)) continue;
      const rawTransferred = existing.direction === 'upload' ? (p.uploaded ?? p.downloaded ?? 0) : (p.downloaded ?? 0);
      const transferred = Math.max(rawTransferred, existing.transferred || 0);
      const completedSize = Math.max(transferred, existing.completed_size || 0);
      list[idx] = {
        ...existing,
        transferred,
        completed_size: completedSize,
        progress: Math.max(p.progress, existing.progress || 0),
        speed: p.speed,
        status: existing.status === 'searching' || existing.status === 'queued' ? existing.status : 'active',
        health: existing.health === 'stalled' ? 'healthy' : existing.health,
        health_reason: existing.health === 'stalled' ? undefined : existing.health_reason,
        stalled_since: existing.health === 'stalled' ? undefined : existing.stalled_since,
        ...(p.upload_time != null ? { upload_time: p.upload_time } : {}),
      };
      changed = true;
    }
    return changed ? [...list] : list;
  });
  pendingProgress.clear();
  if (retained.size > 0) {
    for (const [id, entry] of retained) pendingProgress.set(id, entry);
    scheduleProgressFlush();
  }
}

export async function initTransferStore() {
  if (initialized) return;
  initialized = true;

  let unsubs: UnlistenFn[];
  try {
    unsubs = await Promise.all([
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
      const existing = pendingProgress.get(p.id);
      pendingProgress.set(p.id, {
        payload: p,
        firstSeen: existing?.firstSeen ?? Date.now(),
      });
      scheduleProgressFlush();
    }),
    listen<TransferEventPayload>('transfer-complete', (event) => {
      markEventUpdate();
      const id = event.payload.id;
      transfers.update((list) =>
        list.map((t) => {
          if (t.id !== id) return t;
          // D30: never flip a row already in a terminal state (e.g. late
          // `transfer-complete` after a `transfer-failed`).
          if (isTerminal(t.status) && t.status !== 'completed') return t;
          return { ...t, status: 'completed' as const, progress: 100, speed: 0, transferred: t.total_size, completed_size: t.total_size };
        })
      );
    }),
    listen<TransferEventPayload>('transfer-failed', (event) => {
      markEventUpdate();
      const { id, error, failure_kind, failure_stage } = event.payload;
      transfers.update((list) =>
        list.map((t) => {
          if (t.id !== id) return t;
          // D30: don't downgrade a completed row to failed if a stray
          // late-arriving failure event shows up. Treat `failed` -> `failed`
          // as idempotent so kind/stage metadata can still refresh.
          if (isTerminal(t.status) && t.status !== 'failed') return t;
          return {
            ...t,
            status: 'failed' as const,
            speed: 0,
            failure_reason: error,
            failure_kind,
            failure_stage,
          };
        })
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
          active_sources,
          queued_sources,
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
            // D31: runtime-narrow the status string so an unexpected
            // backend value can't widen the UI's type view.
            const narrowed = narrowStatus(status);
            if (narrowed) {
              // D30: reject downgrades from a terminal state via a
              // transfer-status event too. Completed/failed are sticky
              // until an explicit reset (remove / cancel).
              if (!(isTerminal(t.status) && t.status !== narrowed)) {
                updated.status = narrowed;
              }
            }
            if (peer_id) {
              updated.peer_id = peer_id;
            }
            if (sources !== undefined) updated.sources = sources;
            if (active_sources !== undefined) updated.active_sources = active_sources;
            if (queued_sources !== undefined) updated.queued_sources = queued_sources;
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
        list.map((t) => {
          if (t.id !== id) return t;
          // D5: only apply decay-driven speed updates to rows that are
          // actually transferring. Paused / stopped / completed / failed
          // rows keep their last-known speed (or zero) so the row doesn't
          // flicker as the decay ticker fires.
          if (!SPEED_DECAY_APPLIES.has(t.status)) return t;
          return { ...t, speed };
        })
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
        const { transfer_id, queue_rank } = event.payload;
        if (queue_rank === undefined || queue_rank === null) return;
        markEventUpdate();
        transfers.update((list) =>
          list.map((t) => (t.id === transfer_id ? { ...t, queue_rank } : t))
        );
      }
    ),
    ]);
  } catch (e) {
    initialized = false;
    throw e;
  }
  unlisteners.push(...unsubs);

  try {
    const all = await getTransfers();
    transfers.update((current) => {
      const currentById = new Map(current.map((t) => [t.id, t]));
      const merged = all.map((apiItem) => {
        const eventItem = currentById.get(apiItem.id);
        if (eventItem) {
          const preferEvent = isMoreAdvancedStatus(eventItem.status, apiItem.status);
          return {
            ...apiItem,
            status: preferEvent ? eventItem.status : apiItem.status,
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
          if (!eventItem) return apiItem;
          const preferEvent = isMoreAdvancedStatus(eventItem.status, apiItem.status);
          return {
            ...apiItem,
            status: preferEvent ? eventItem.status : apiItem.status,
            progress: Math.max(apiItem.progress, eventItem.progress),
            speed: preferEvent ? eventItem.speed : apiItem.speed,
            transferred: Math.max(apiItem.transferred, eventItem.transferred),
            completed_size: Math.max(apiItem.completed_size || 0, eventItem.completed_size || 0),
            health: eventItem.health ?? apiItem.health,
            health_reason: eventItem.health_reason ?? apiItem.health_reason,
            stalled_since: eventItem.stalled_since ?? apiItem.stalled_since,
            failure_reason: eventItem.failure_reason ?? apiItem.failure_reason,
            failure_kind: eventItem.failure_kind ?? apiItem.failure_kind,
            failure_stage: eventItem.failure_stage ?? apiItem.failure_stage,
          };
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
