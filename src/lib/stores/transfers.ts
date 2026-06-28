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
  // `paused` / `stopped` / `insufficient` are reversible, backend-authoritative
  // side states — not points on the monotonic searching→…→completed pipeline
  // this priority table models. The API snapshot is read straight from the
  // transfer manager, so it always reflects the live pause/stop/resume state; a
  // *stored* row in one of these states must therefore never out-rank a fresh
  // API status. Without this guard a resumed download stayed visually stuck on
  // "Paused"/"Stopped"/"Insufficient" forever: all three sit ABOVE
  // active/searching/queued in STATUS_PRIORITY, so the poll merge kept
  // preferring the stale stored value over the live status the backend now
  // reports after the user resumed.
  if (eventStatus === 'paused' || eventStatus === 'stopped' || eventStatus === 'insufficient') {
    return false;
  }
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

/** Statuses that should NOT accept `transfer-progress` payloads. Hoisted to
 *  module scope (was rebuilt inside `flushProgress` on every frame) and
 *  stored as a Set so the per-row membership check in the flush loop is
 *  O(1) instead of a linear scan. */
const PROGRESS_SKIP_STATUSES: ReadonlySet<Transfer['status']> = new Set<Transfer['status']>([
  'paused',
  'stopped',
  'completed',
  'failed',
  'verifying',
  'completing',
  'hashing',
  'insufficient',
  'noneneeded',
]);

/** Mirror `TransferManager::update_status`: entering these states clears
 *  runtime health on the backend, but `transfer-status` events often omit
 *  `health`, leaving the UI stuck on a stale `degraded` bar colour. */
const HEALTH_RESET_STATUSES: ReadonlySet<Transfer['status']> = new Set<Transfer['status']>([
  'active',
  'verifying',
  'completing',
  'completed',
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
  /** Backend tags upload-direction terminal events so the store can
   *  vanish the row on completion (matches eMule UX where finished
   *  upload sessions disappear from the active list). Falls back to
   *  the in-store row's `direction` when the payload doesn't carry it. */
  direction?: string;
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
// Handles for the pending flush so `cleanupTransferStore` can cancel a frame
// that would otherwise fire after teardown.
let flushRaf: number | null = null;
let flushTimeout: ReturnType<typeof setTimeout> | null = null;

/** Upload IDs we've explicitly removed via terminal events (complete/fail).
 *  Tracked with an expiry timestamp so the polling refresh below can
 *  ignore stale `getTransfers()` snapshots that captured the row a few
 *  ms before the backend dropped it from `mgr.completed`. Without this,
 *  a poll started just before a `transfer-complete` could resurrect the
 *  just-vanished upload row in the UI for a single poll cycle. The
 *  TTL is ~3× the poll interval (3 s) so even a slow pollback can't
 *  win the race. */
const recentlyRemovedUploads = new Map<string, number>();
const REMOVED_UPLOAD_TTL_MS = 10_000;
function markUploadRemoved(id: string) {
  recentlyRemovedUploads.set(id, Date.now() + REMOVED_UPLOAD_TTL_MS);
}
function pruneRemovedUploads(now: number) {
  for (const [id, expiry] of recentlyRemovedUploads) {
    if (expiry <= now) recentlyRemovedUploads.delete(id);
  }
}
function wasRecentlyRemoved(id: string, now: number): boolean {
  const expiry = recentlyRemovedUploads.get(id);
  if (expiry === undefined) return false;
  if (expiry <= now) {
    recentlyRemovedUploads.delete(id);
    return false;
  }
  return true;
}

function scheduleProgressFlush() {
  if (progressFlushScheduled) return;
  progressFlushScheduled = true;
  if (typeof requestAnimationFrame === 'function' && document.visibilityState === 'visible') {
    flushRaf = requestAnimationFrame(() => {
      flushRaf = null;
      flushProgress();
    });
  } else {
    flushTimeout = setTimeout(() => {
      flushTimeout = null;
      flushProgress();
    }, 32);
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
    // Build a one-shot id -> index lookup. The old code did
    // `list.findIndex(...)` per pending payload, making the flush
    // O(P * N) where P = payloads queued this frame and N = total
    // transfers. With ~100 transfers and a burst of ~100 payloads coalesced
    // into one frame that's ~10k scans per 16 ms frame. O(P + N) via a Map
    // is roughly an order of magnitude cheaper.
    const indexById = new Map<string, number>();
    for (let i = 0; i < list.length; i++) {
      indexById.set(list[i].id, i);
    }
    for (const [id, entry] of batch) {
      const p = entry.payload;
      const idx = indexById.get(id);
      if (idx === undefined) {
        // No matching row yet. Keep the latest payload and re-try on the
        // next frame unless the race window has clearly expired.
        if (now - entry.firstSeen < ORPHAN_PROGRESS_TTL_MS) {
          retained.set(id, entry);
        }
        continue;
      }
      const existing = list[idx];
      if (PROGRESS_SKIP_STATUSES.has(existing.status)) continue;
      const rawTransferred = existing.direction === 'upload' ? (p.uploaded ?? p.downloaded ?? 0) : (p.downloaded ?? 0);
      const transferred = Math.max(rawTransferred, existing.transferred || 0);
      const completedSize = Math.max(transferred, existing.completed_size || 0);
      const bytesMoved = transferred > (existing.transferred || 0);
      const clearStaleHealth = bytesMoved || existing.health === 'stalled';
      list[idx] = {
        ...existing,
        transferred,
        completed_size: completedSize,
        progress: Math.max(p.progress, existing.progress || 0),
        speed: p.speed,
        status: existing.status === 'searching' || existing.status === 'queued' ? existing.status : 'active',
        health: clearStaleHealth ? 'healthy' : existing.health,
        health_reason: clearStaleHealth ? undefined : existing.health_reason,
        stalled_since: clearStaleHealth ? undefined : existing.stalled_since,
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

  // Sequential `await listen(...)` with explicit rollback instead of
  // `Promise.all`. With Promise.all, a single rejected `listen` after
  // earlier ones resolved leaves those resolved subscriptions registered
  // in Tauri's WebView (their UnlistenFn is unreachable inside the
  // rejected aggregate promise). On retry — or just for the rest of the
  // session — events would fire on orphaned handlers we can never
  // unlisten. The per-step rollback below guarantees that on any failure
  // we drop every listener we already registered and surface the error.
  const registered: UnlistenFn[] = [];
  const safeListen = async <T>(
    event: string,
    handler: Parameters<typeof listen<T>>[1],
  ): Promise<void> => {
    try {
      const unlisten = await listen<T>(event, handler);
      registered.push(unlisten);
    } catch (e) {
      for (const u of registered) {
        try { u(); } catch { /* ignore */ }
      }
      registered.length = 0;
      throw e;
    }
  };
  try {
    await safeListen<Transfer>('transfer-started', (event) => {
      markEventUpdate();
      const t = event.payload;
      transfers.update((list) => {
        if (list.some((x) => x.id === t.id)) return list;
        return [...list, t];
      });
    });
    await safeListen<ProgressPayload>('transfer-progress', (event) => {
      markEventUpdate();
      const p = event.payload;
      const existing = pendingProgress.get(p.id);
      pendingProgress.set(p.id, {
        payload: p,
        firstSeen: existing?.firstSeen ?? Date.now(),
      });
      scheduleProgressFlush();
    });
    await safeListen<TransferEventPayload>('transfer-complete', (event) => {
      markEventUpdate();
      const { id, direction } = event.payload;
      transfers.update((list) => {
        // Find the row (if any) so we can decide whether to drop it
        // outright (uploads) or simply mark it completed (downloads).
        const existing = list.find((t) => t.id === id);
        const isUpload = direction === 'upload' || existing?.direction === 'upload';
        if (isUpload) {
          // Match eMule: an upload session ending — successfully or not —
          // immediately removes the row from the active uploads pane.
          // Cumulative upload totals live in the statistics view.
          markUploadRemoved(id);
          pendingProgress.delete(id);
          return list.filter((t) => t.id !== id);
        }
        return list.map((t) => {
          if (t.id !== id) return t;
          // D30: never flip a row already in a terminal state (e.g. late
          // `transfer-complete` after a `transfer-failed`).
          if (isTerminal(t.status) && t.status !== 'completed') return t;
          // This branch is downloads only — uploads returned above. A
          // download emits `transfer-complete` only once the whole file is
          // present and hash-verified, so the row is by definition 100%.
          // Snap the bar/counters to full: the rate-limited `transfer-progress`
          // ticks can leave the last reported value a few percent short, which
          // showed up as e.g. "98% Complete" rows. (Uploads are deliberately
          // NOT snapped — an upload session routinely ends well short of
          // `total_size`, but that path never reaches here.)
          return {
            ...t,
            status: 'completed' as const,
            speed: 0,
            progress: 100,
            transferred: t.total_size,
            completed_size: t.total_size,
          };
        });
      });
    });
    await safeListen<TransferEventPayload>('transfer-failed', (event) => {
      markEventUpdate();
      const { id, error, failure_kind, failure_stage, direction } = event.payload;
      transfers.update((list) => {
        const existing = list.find((t) => t.id === id);
        const isUpload = direction === 'upload' || existing?.direction === 'upload';
        if (isUpload) {
          // Mirror the `transfer-complete` upload path: failed upload
          // sessions also disappear from the active list. The failure
          // reason is preserved in statistics and event logs, just not
          // as a sticky row in the upload pane.
          markUploadRemoved(id);
          pendingProgress.delete(id);
          return list.filter((t) => t.id !== id);
        }
        return list.map((t) => {
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
        });
      });
    });
    await safeListen<TransferEventPayload & { status?: string }>(
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
            // Paused / stopped rows are not transferring — zero the speed in the
            // same tick the status flips so an instantly-applied pause/stop
            // event doesn't leave a stale rate on screen until the next poll
            // (the speed-decay ticker deliberately skips these states, so
            // nothing else would clear it).
            if ((narrowed === 'paused' || narrowed === 'stopped') && updated.status === narrowed) {
              updated.speed = 0;
            }
            if (peer_id) {
              updated.peer_id = peer_id;
            }
            if (sources !== undefined) updated.sources = Math.max(sources, t.sources);
            if (active_sources !== undefined || queued_sources !== undefined) {
              const nextActive = active_sources ?? t.active_sources ?? 0;
              const nextQueued = queued_sources ?? t.queued_sources ?? 0;
              const liveIncoming = nextActive + nextQueued;
              const liveCurrent = (t.active_sources || 0) + (t.queued_sources || 0);
              const statusChanged = narrowed != null && t.status !== narrowed;
              if (liveIncoming > 0 || liveCurrent === 0 || statusChanged) {
                if (active_sources !== undefined) updated.active_sources = active_sources;
                if (queued_sources !== undefined) updated.queued_sources = queued_sources;
              }
            }
            if (failure_reason !== undefined) updated.failure_reason = failure_reason;
            else if (error !== undefined) updated.failure_reason = error;
            if (failure_kind !== undefined) updated.failure_kind = failure_kind;
            if (failure_stage !== undefined) updated.failure_stage = failure_stage;
            if (health !== undefined) updated.health = health;
            if (health_reason !== undefined) updated.health_reason = health_reason;
            if (stalled_since !== undefined) updated.stalled_since = stalled_since;
            // Backend clears runtime health on these transitions but usually
            // omits `health` from the event — drop stale `degraded` so the
            // progress bar returns to accent blue when downloading resumes.
            if (
              narrowed &&
              HEALTH_RESET_STATUSES.has(narrowed) &&
              health === undefined &&
              t.status !== narrowed
            ) {
              updated.health = 'healthy';
              updated.health_reason = undefined;
              updated.stalled_since = undefined;
            }
            return updated;
          })
        );
      },
    );
    await safeListen<TransferEventPayload>('transfer-health', (event) => {
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
                // Only let the event's reason/stalled fields take effect when it
                // actually carries a new `health` value (in which case they are
                // authoritative for that state, including clearing them for a
                // 'healthy' transition). When `health` is omitted, preserve the
                // existing values instead of clobbering them to undefined.
                health_reason: health !== undefined ? health_reason : t.health_reason,
                stalled_since: health !== undefined ? stalled_since : t.stalled_since,
              }
            : t
        )
      );
    });
    await safeListen<{ id: string; speed: number }>('transfer-speed-decay', (event) => {
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
    });
    await safeListen<{ id: string; sources: number; active_sources: number; queued_sources: number }>(
      'transfer-sources',
      (event) => {
        markEventUpdate();
        const { id, sources, active_sources, queued_sources } = event.payload;
        transfers.update((list) =>
          list.map((t) => {
            if (t.id !== id) return t;
            const prevLive = (t.active_sources || 0) + (t.queued_sources || 0);
            const newLive = active_sources + queued_sources;
            // Discovery refreshes often send an updated total with 0/0
            // live counts; don't stomp live counters the multi-source
            // worker is still reporting.
            const preserveLive = newLive === 0 && prevLive > 0;
            return {
              ...t,
              sources: Math.max(sources, t.sources),
              active_sources: preserveLive ? t.active_sources : active_sources,
              queued_sources: preserveLive ? t.queued_sources : queued_sources,
            };
          })
        );
      },
    );
    await safeListen<{ transfer_id: string; queue_rank?: number }>(
      'transfer-source-detail',
      (event) => {
        const { transfer_id, queue_rank } = event.payload;
        if (queue_rank === undefined || queue_rank === null) return;
        markEventUpdate();
        transfers.update((list) =>
          list.map((t) => (t.id === transfer_id ? { ...t, queue_rank } : t))
        );
      },
    );
  } catch (e) {
    initialized = false;
    throw e;
  }
  unlisteners.push(...registered);

  try {
    const all = await getTransfers();
    transfers.update((current) => {
      const currentById = new Map(current.map((t) => [t.id, t]));
      const merged = all.map((apiItem) => {
        const eventItem = currentById.get(apiItem.id);
        if (eventItem) {
          const preferEvent = isMoreAdvancedStatus(eventItem.status, apiItem.status);
          return snapCompletedDownload({
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
            sources: Math.max(apiItem.sources ?? 0, eventItem.sources ?? 0),
            active_sources: Math.max(apiItem.active_sources ?? 0, eventItem.active_sources ?? 0),
            queued_sources: Math.max(apiItem.queued_sources ?? 0, eventItem.queued_sources ?? 0),
          });
        }
        return snapCompletedDownload(apiItem);
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

/**
 * Defense-in-depth for the "completed but <100%" bar: a completed download is
 * by definition the whole file, so snap its progress/byte counters to full.
 * The `transfer-complete` event path already does this, but the poll/initial
 * merges take `Math.max(api, event)` of the raw values, so a backend row that
 * predates the server-side fix (or any rounding gap) could still surface a
 * completed row at e.g. 98%. Uploads are never snapped (a session legitimately
 * ends short of total_size).
 */
function snapCompletedDownload(t: Transfer): Transfer {
  if (
    t.status === 'completed' &&
    t.direction !== 'upload' &&
    t.total_size > 0 &&
    ((t.progress ?? 0) < 100 || (t.transferred ?? 0) < t.total_size)
  ) {
    return {
      ...t,
      progress: 100,
      transferred: t.total_size,
      completed_size: t.total_size,
      speed: 0,
    };
  }
  return t;
}

/**
 * Per-row timestamp of when an event-only transfer first went missing from the
 * backend's `list_transfers()` snapshot. Used by the poll merge to drop
 * non-terminal "zombie" rows the backend has consistently stopped reporting,
 * while still riding out a single poll/event race.
 */
const missingFromApiSince = new Map<string, number>();
const ZOMBIE_GRACE_MS = 12_000;

export function cleanupTransferStore() {
  for (const unlisten of unlisteners) unlisten();
  unlisteners = [];
  if (pollInterval !== null) {
    clearInterval(pollInterval);
    pollInterval = null;
    detachPollVisibilityListener();
  }
  pollConsumers = 0;
  pendingProgress.clear();
  recentlyRemovedUploads.clear();
  missingFromApiSince.clear();
  // Cancel any flush queued for the next frame/tick so it can't run against a
  // store we've just reset (or a subsequently re-initialised one).
  if (flushRaf !== null) {
    cancelAnimationFrame(flushRaf);
    flushRaf = null;
  }
  if (flushTimeout !== null) {
    clearTimeout(flushTimeout);
    flushTimeout = null;
  }
  progressFlushScheduled = false;
  initialized = false;
  transfers.set([]);
}

let pollPumpOnNextVisible = false;
let pollVisibilityListenerAttached = false;
function onPollVisibilityChange() {
  if (typeof document !== 'undefined' && document.visibilityState === 'visible') {
    pollPumpOnNextVisible = true;
  }
}
function attachPollVisibilityListener() {
  if (pollVisibilityListenerAttached || typeof document === 'undefined') return;
  document.addEventListener('visibilitychange', onPollVisibilityChange);
  pollVisibilityListenerAttached = true;
}
function detachPollVisibilityListener() {
  if (!pollVisibilityListenerAttached || typeof document === 'undefined') return;
  document.removeEventListener('visibilitychange', onPollVisibilityChange);
  pollVisibilityListenerAttached = false;
  pollPumpOnNextVisible = false;
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
        detachPollVisibilityListener();
      }
    };
  }

  attachPollVisibilityListener();

  let busy = false;

  const poll = async () => {
    if (busy) return;
    // Skip the IPC entirely when the window is hidden. Every tick here
    // costs a Rust-side `list_transfers()` + the full merge-and-broadcast
    // below; while the tab is in the background there's no subscriber
    // worth the wake-up, and the event-driven path keeps the store warm
    // enough that the first poll after we regain visibility catches up.
    // `pollPumpOnNextVisible` is flipped by the visibilitychange handler
    // so the first tick after we regain focus always reconciles, even if
    // the event-freshness gate below would normally skip.
    if (typeof document !== 'undefined' && document.visibilityState !== 'visible') {
      return;
    }
    if (!pollPumpOnNextVisible && Date.now() - lastEventUpdate < 2000) return;
    pollPumpOnNextVisible = false;
    busy = true;
    let pollTimeout: ReturnType<typeof setTimeout> | undefined;
    try {
      const all = await Promise.race([
        getTransfers(),
        new Promise<never>((_, reject) => {
          pollTimeout = setTimeout(() => reject('timeout'), 4000);
        }),
      ]);
      transfers.update((current) => {
        const now = Date.now();
        pruneRemovedUploads(now);
        const currentById = new Map(current.map((t) => [t.id, t]));
        const apiIds = new Set(all.map((t) => t.id));
        const merged = all
          // Skip API items for upload rows we removed within the last
          // ~10 s. Without this, a poll that fetched its snapshot just
          // before a `transfer-complete` event would resurrect the
          // just-vanished row for a single poll cycle, defeating the
          // eMule-style auto-remove UX.
          .filter((apiItem) => !wasRecentlyRemoved(apiItem.id, now))
          .map((apiItem) => {
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
              sources: Math.max(apiItem.sources ?? 0, eventItem.sources ?? 0),
              active_sources: Math.max(apiItem.active_sources ?? 0, eventItem.active_sources ?? 0),
              queued_sources: Math.max(apiItem.queued_sources ?? 0, eventItem.queued_sources ?? 0),
            };
          })
          .map(snapCompletedDownload);
        const terminalStatuses: Transfer['status'][] = ['completed', 'failed', 'stopped'];
        const mergedIds = new Set(merged.map((t) => t.id));
        for (const t of current) {
          if (mergedIds.has(t.id) || apiIds.has(t.id)) {
            // Still known to the backend (or intentionally dropped by the
            // recently-removed filter) — clear any "missing" timer.
            missingFromApiSince.delete(t.id);
            continue;
          }
          if (terminalStatuses.includes(t.status)) {
            missingFromApiSince.delete(t.id);
            continue;
          }
          // Non-terminal row the backend snapshot doesn't include. Keep it
          // briefly to absorb a poll/event race, but drop it once the backend
          // has consistently omitted it for the grace window — otherwise an
          // event-only row whose transfer the backend dropped would linger
          // forever as a stuck "active" zombie.
          const firstMissing = missingFromApiSince.get(t.id) ?? now;
          missingFromApiSince.set(t.id, firstMissing);
          if (now - firstMissing <= ZOMBIE_GRACE_MS) {
            merged.push(t);
          }
        }
        return merged;
      });
    } catch {
      // Ignore timeouts and errors
    } finally {
      // Clear the race watchdog so the loser timer doesn't linger.
      if (pollTimeout) clearTimeout(pollTimeout);
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
      detachPollVisibilityListener();
    }
  };
}
