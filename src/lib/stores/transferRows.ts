import type { Transfer } from '$lib/types';

/**
 * Row-level reducers for the transfers store, kept free of Tauri and Svelte so
 * they can be tested.
 *
 * Every function here returns its input *unchanged by identity* when nothing
 * it would write differs. The store only publishes a new array when one of
 * them hands back a different one, and the Transfers page keys its derived
 * partitions, sorts and row components on that identity — a new array or row
 * object where nothing changed is a re-sort and a re-render for nothing.
 */

/** Statuses that are definitionally not moving bytes, so their displayed rate
 *  must read zero rather than whatever the last progress event left behind.
 *
 *  `insufficient` and `noneneeded` belong here and were missing from all three
 *  of the lists that model this. The backend does its part — `refresh_health`
 *  zeroes `transfer.speed` and emits `transfer-speed-decay` — but the row was
 *  absent from `SPEED_DECAY_APPLIES` so the decay was dropped, and `mergeSpeed`
 *  then re-maxed the stale value against the poll's 0 forever. A download that
 *  filled the disk went on showing its last rate indefinitely, counted itself
 *  into the "Active" chip via `displaySpeed(t) > 0`, and rendered a
 *  counting-down ETA for a transfer that had stopped.
 *
 *  Deliberately excludes `searching` / `verifying` / `hashing` / `completing`:
 *  those are in `SPEED_DECAY_APPLIES` so the backend fades their rate towards
 *  zero, and the row is meant to show that fade. */
export const IDLE_STATUSES: ReadonlySet<Transfer['status']> = new Set<Transfer['status']>([
  'completed',
  'failed',
  'stopped',
  'paused',
  'insufficient',
  'noneneeded',
]);

/** Statuses for which `transfer-speed-decay` should actually update `speed`.
 *  Paused / stopped / completed / failed rows are intentionally frozen so
 *  the UI can show the last-known speed (or zero) without the decay ticker
 *  stomping it. D5. */
export const SPEED_DECAY_APPLIES: ReadonlySet<Transfer['status']> = new Set<Transfer['status']>([
  'active',
  'searching',
  'queued',
  'verifying',
  'completing',
  'hashing',
  // Accept the decay for these two as well. The backend zeroes their speed and
  // emits the event; dropping it left the stored row carrying a stale rate.
  // `IDLE_STATUSES` makes the *displayed* value 0 regardless, but the stored
  // field feeds other readers, so let the authoritative 0 land.
  'insufficient',
  'noneneeded',
]);

/** Mirror `TransferManager::update_status`: entering these clears runtime
 *  health on the backend, but the event usually omits `health`. */
const HEALTH_RESET_STATUSES: ReadonlySet<Transfer['status']> = new Set<Transfer['status']>([
  'active',
  'verifying',
  'completing',
  'completed',
]);

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

/** Runtime-narrow a backend status string before casting, so an unexpected
 *  value can never silently widen TypeScript's view of truth (D31). */
export function narrowStatus(raw: string | undefined): Transfer['status'] | undefined {
  if (!raw) return undefined;
  return (KNOWN_STATUSES as Set<string>).has(raw) ? (raw as Transfer['status']) : undefined;
}

/** Completed/failed are sticky until an explicit reset (D30). */
export function isTerminal(s: Transfer['status']): boolean {
  return s === 'completed' || s === 'failed';
}

function isReversible(s: Transfer['status'] | undefined): boolean {
  return s === 'paused' || s === 'stopped' || s === 'insufficient';
}

/** Every field `===`, counting a key set to `undefined` the same as an absent
 *  one — the merges write optional fields either way. Transfer fields are all
 *  primitives. */
export function shallowEqualRow(a: object, b: object): boolean {
  if (a === b) return true;
  const ar = a as Record<string, unknown>;
  const br = b as Record<string, unknown>;
  for (const k in ar) {
    if (ar[k] !== br[k]) return false;
  }
  for (const k in br) {
    if (!(k in ar) && br[k] !== undefined) return false;
  }
  return true;
}

/** `prev` when `next` carries the same values, so unchanged rows keep their
 *  identity through a merge. */
export function keepIdentity<T extends object>(prev: T | undefined, next: T): T {
  return prev !== undefined && shallowEqualRow(prev, next) ? prev : next;
}

/** Rewrites one row; `null` removes it. */
export type RowPatch<T> = (row: T) => T | null;

/**
 * Apply patches in order, each to the row with its id. A patch for an id not
 * in the list is dropped. Returns `list` itself when no patch changed a value.
 */
export function applyRowPatches<T extends { id: string }>(
  list: T[],
  patches: ReadonlyArray<readonly [string, RowPatch<T>]>,
): T[] {
  if (patches.length === 0) return list;
  let out: T[] | null = null;
  let index: Map<string, number> | null = null;
  for (const [id, patch] of patches) {
    const rows: T[] = out ?? list;
    if (index === null) index = rowIndex(rows);
    let idx = index.get(id);
    if (idx !== undefined && rows[idx]?.id !== id) {
      index = rowIndex(rows, true);
      idx = index.get(id);
    }
    if (idx === undefined) continue;
    const row = rows[idx];
    const next = patch(row);
    if (next === null) {
      out = rows.filter((r) => r.id !== id);
      index = null;
      continue;
    }
    if (next === row || shallowEqualRow(row, next)) continue;
    if (out === null) {
      out = list.slice();
      // Same ids at the same positions until a removal.
      indexCache.set(out, index);
    }
    out[idx] = next;
  }
  return out ?? list;
}

/** id -> position, cached per array so a burst of flushes over a list whose
 *  shape did not change builds it once. Arrays are never mutated in place
 *  once published, which is what makes the cache sound. */
const indexCache = new WeakMap<object, Map<string, number>>();

function rowIndex<T extends { id: string }>(rows: T[], rebuild = false): Map<string, number> {
  const cached = rebuild ? undefined : indexCache.get(rows);
  if (cached && cached.size === rows.length) return cached;
  const index = new Map<string, number>();
  for (let i = 0; i < rows.length; i++) {
    if (!index.has(rows[i].id)) index.set(rows[i].id, i);
  }
  indexCache.set(rows, index);
  return index;
}

/** Bookkeeping the status and sources reducers share with the poll merge. */
export interface RowEventContext {
  /** When the event arrived, not when the batch was applied. */
  now: number;
  reversibleStateEnteredAt: Map<string, number>;
  reversibleStateLeftAt: Map<string, number>;
  sourceCountsUpdatedAt: Map<string, number>;
}

export interface StatusEventPayload {
  id: string;
  status?: string;
  error?: string;
  failure_reason?: string;
  failure_code?: string;
  failure_kind?: Transfer['failure_kind'];
  failure_stage?: string;
  health?: Transfer['health'];
  health_reason?: string;
  health_code?: string;
  stalled_since?: number;
  sources?: number;
  active_sources?: number;
  queued_sources?: number;
  peer_id?: string;
}

/** `transfer-status` applied to one row. */
export function applyStatusEvent(
  t: Transfer,
  p: StatusEventPayload,
  ctx: RowEventContext,
): Transfer {
  const id = t.id;
  const updated: Transfer = { ...t };
  const narrowed = narrowStatus(p.status);
  if (narrowed) {
    if (!(isTerminal(t.status) && t.status !== narrowed)) {
      updated.status = narrowed;
      if (isReversible(narrowed)) {
        ctx.reversibleStateEnteredAt.set(id, ctx.now);
        ctx.reversibleStateLeftAt.delete(id);
      } else {
        if (isReversible(t.status)) ctx.reversibleStateLeftAt.set(id, ctx.now);
        ctx.reversibleStateEnteredAt.delete(id);
      }
    }
  }
  // Paused / stopped rows are not transferring — zero the speed in the same
  // tick the status flips, since the speed-decay ticker skips these states.
  if ((narrowed === 'paused' || narrowed === 'stopped') && updated.status === narrowed) {
    updated.speed = 0;
    updated.active_sources = 0;
    updated.queued_sources = 0;
  }
  // Clear stale failure_* once the transfer leaves Failed without new ones.
  if (
    narrowed &&
    (narrowed === 'searching' ||
      narrowed === 'queued' ||
      narrowed === 'active' ||
      narrowed === 'paused' ||
      narrowed === 'stopped' ||
      narrowed === 'hashing' ||
      narrowed === 'verifying' ||
      narrowed === 'completing') &&
    p.failure_reason === undefined &&
    p.failure_code === undefined &&
    p.failure_kind === undefined &&
    p.failure_stage === undefined &&
    p.error === undefined
  ) {
    delete updated.failure_reason;
    delete updated.failure_code;
    delete updated.failure_kind;
    delete updated.failure_stage;
  }
  if (p.peer_id) updated.peer_id = p.peer_id;
  if (p.sources !== undefined) updated.sources = p.sources;
  if (p.active_sources !== undefined || p.queued_sources !== undefined) {
    const nextActive = p.active_sources ?? t.active_sources ?? 0;
    const nextQueued = p.queued_sources ?? t.queued_sources ?? 0;
    const liveIncoming = nextActive + nextQueued;
    const liveCurrent = (t.active_sources || 0) + (t.queued_sources || 0);
    const statusChanged = narrowed != null && t.status !== narrowed;
    if (liveIncoming > 0 || liveCurrent === 0 || statusChanged) {
      if (p.active_sources !== undefined) updated.active_sources = p.active_sources;
      if (p.queued_sources !== undefined) updated.queued_sources = p.queued_sources;
      if (liveIncoming > 0) ctx.sourceCountsUpdatedAt.set(id, ctx.now);
      else ctx.sourceCountsUpdatedAt.delete(id);
    }
  }
  if (p.failure_reason !== undefined) updated.failure_reason = p.failure_reason;
  else if (p.error !== undefined) updated.failure_reason = p.error;
  if (p.failure_code !== undefined) updated.failure_code = p.failure_code;
  if (p.failure_kind !== undefined) updated.failure_kind = p.failure_kind;
  if (p.failure_stage !== undefined) updated.failure_stage = p.failure_stage;
  if (p.health !== undefined) updated.health = p.health;
  if (p.health_reason !== undefined) updated.health_reason = p.health_reason;
  if (p.health_code !== undefined) updated.health_code = p.health_code;
  if (p.stalled_since !== undefined) updated.stalled_since = p.stalled_since;
  // The backend clears runtime health on these transitions but usually omits
  // `health` — drop a stale `degraded` so the bar returns to accent blue.
  if (narrowed && HEALTH_RESET_STATUSES.has(narrowed) && p.health === undefined && t.status !== narrowed) {
    updated.health = 'healthy';
    updated.health_reason = undefined;
    updated.health_code = undefined;
    updated.stalled_since = undefined;
  }
  return updated;
}

/** `transfer-health` applied to one row. */
export function applyHealthEvent(t: Transfer, p: StatusEventPayload): Transfer {
  return {
    ...t,
    failure_reason: p.failure_reason ?? p.error ?? t.failure_reason,
    failure_code: p.failure_code ?? t.failure_code,
    failure_kind: p.failure_kind ?? t.failure_kind,
    failure_stage: p.failure_stage ?? t.failure_stage,
    health: p.health ?? t.health,
    // The reason/stalled fields are authoritative only alongside a new
    // `health`; without one, keep what the row has.
    health_reason: p.health !== undefined ? p.health_reason : t.health_reason,
    health_code: p.health !== undefined ? p.health_code : t.health_code,
    stalled_since: p.health !== undefined ? p.stalled_since : t.stalled_since,
  };
}

/** `transfer-speed-decay` applied to one row. */
export function applySpeedDecay(t: Transfer, speed: number): Transfer {
  if (!SPEED_DECAY_APPLIES.has(t.status) || t.speed === speed) return t;
  return { ...t, speed };
}

export interface SourcesEventPayload {
  id: string;
  sources: number;
  active_sources: number;
  queued_sources: number;
}

/** A live-count event is trusted over a later 0/0 discovery refresh for this
 *  long. */
export const LIVE_SOURCE_EVENT_GRACE_MS = 6_000;

/** `transfer-sources` applied to one row. */
export function applySourcesEvent(
  t: Transfer,
  p: SourcesEventPayload,
  ctx: RowEventContext,
): Transfer {
  const prevLive = (t.active_sources || 0) + (t.queued_sources || 0);
  const newLive = p.active_sources + p.queued_sources;
  // Discovery refreshes often send an updated total with 0/0 live counts;
  // don't stomp live counters the multi-source worker is still reporting.
  const lastLiveUpdate = ctx.sourceCountsUpdatedAt.get(t.id) ?? 0;
  const preserveLive =
    newLive === 0 && prevLive > 0 && ctx.now - lastLiveUpdate < LIVE_SOURCE_EVENT_GRACE_MS;
  if (newLive > 0) ctx.sourceCountsUpdatedAt.set(t.id, ctx.now);
  else if (!preserveLive) ctx.sourceCountsUpdatedAt.delete(t.id);
  return {
    ...t,
    sources: p.sources,
    active_sources: preserveLive ? t.active_sources : p.active_sources,
    queued_sources: preserveLive ? t.queued_sources : p.queued_sources,
  };
}

/** The poller's copy of the backend's rows at `revision`. */
export interface SnapshotState<T extends { id: string }> {
  epoch: number | null;
  revision: number;
  rows: Map<string, T>;
}

export interface SnapshotDelta<T> {
  epoch: number;
  revision: number;
  full: boolean;
  transfers: T[];
  removed: string[];
}

/**
 * Fold a `get_transfers_since` answer into `state`, in place. Returns the ids
 * it changed (`null` = everything, a full snapshot), or `undefined` when the
 * answer is older than what `state` already holds and was ignored — two polls
 * can be in flight at once and resolve out of order.
 */
export function applySnapshotDelta<T extends { id: string }>(
  state: SnapshotState<T>,
  delta: SnapshotDelta<T>,
): Set<string> | null | undefined {
  const sameEpoch = state.epoch === delta.epoch;
  if (sameEpoch && delta.revision < state.revision) return undefined;
  if (delta.full) {
    state.epoch = delta.epoch;
    state.revision = delta.revision;
    state.rows = new Map(delta.transfers.map((t) => [t.id, t]));
    return null;
  }
  // A delta is relative to a revision of its own epoch; against anything
  // else there is nothing to apply it to.
  if (!sameEpoch) return undefined;
  const changed = new Set<string>();
  // Removals first: a row removed and then re-added is in both lists.
  for (const id of delta.removed) {
    if (state.rows.delete(id)) changed.add(id);
  }
  for (const t of delta.transfers) {
    state.rows.set(t.id, t);
    changed.add(t.id);
  }
  state.revision = delta.revision;
  return changed;
}

export interface ReconcileOptions<T extends { id: string }> {
  /** Ids the backend changed since the last reconcile; `null` = all. */
  changed: ReadonlySet<string> | null;
  /** A row the backend did not change but that must be merged anyway —
   *  typically because something other than the poll rewrote it. */
  needsMerge(row: T): boolean;
  merge(api: T, current: T): T;
  /** A new backend row entering the list. */
  fresh(api: T): T;
  /** Backend rows the UI already removed and must not resurrect. */
  suppressed(id: string): boolean;
  /** A listed row the backend does not have: keep it or drop it. */
  keepMissing(row: T): boolean;
  /**
   * Ids a reconcile skipped as suppressed while the backend had them, kept
   * across calls by the caller. Whatever the backend reported for them was
   * consumed without being merged, so a listed row with one of these ids —
   * put back after a failed cancel, as the same object it was — is merged
   * the next time it is not suppressed. Updated in place.
   */
  resurfaced?: Set<string>;
}

/**
 * Merge the backend's rows into the list. Rows keep their position and, when
 * the merge changes no value, their identity; new rows are appended in
 * backend order. Returns `current` itself when nothing changed.
 */
export function reconcileRows<T extends { id: string }>(
  current: T[],
  api: ReadonlyMap<string, T>,
  opts: ReconcileOptions<T>,
): T[] {
  const out: T[] = [];
  const listed = new Set<string>();
  const resurfaced = opts.resurfaced;
  let changed = false;
  for (const row of current) {
    const apiRow = api.get(row.id);
    if (apiRow === undefined) {
      if (opts.keepMissing(row)) out.push(row);
      else changed = true;
      continue;
    }
    if (opts.suppressed(row.id)) {
      resurfaced?.add(row.id);
      changed = true;
      continue;
    }
    listed.add(row.id);
    if (
      opts.changed === null ||
      opts.changed.has(row.id) ||
      resurfaced?.has(row.id) ||
      opts.needsMerge(row)
    ) {
      const merged = keepIdentity(row, opts.merge(apiRow, row));
      if (merged !== row) changed = true;
      out.push(merged);
    } else {
      out.push(row);
    }
    resurfaced?.delete(row.id);
  }
  for (const [id, apiRow] of api) {
    if (listed.has(id)) continue;
    if (opts.suppressed(id)) {
      resurfaced?.add(id);
      continue;
    }
    out.push(opts.fresh(apiRow));
    resurfaced?.delete(id);
    changed = true;
  }
  if (resurfaced) {
    // Gone from the backend: nothing is left to merge it against.
    for (const id of resurfaced) {
      if (!api.has(id)) resurfaced.delete(id);
    }
  }
  return changed ? out : current;
}

/** Fold two queued `transfer-health` payloads for one row into one with the
 *  same effect as applying them in order. */
export function mergeHealthPayloads(
  first: StatusEventPayload,
  second: StatusEventPayload,
): StatusEventPayload {
  const healthFrom = second.health !== undefined ? second : first;
  return {
    id: second.id,
    failure_reason: second.failure_reason ?? second.error ?? first.failure_reason ?? first.error,
    failure_code: second.failure_code ?? first.failure_code,
    failure_kind: second.failure_kind ?? first.failure_kind,
    failure_stage: second.failure_stage ?? first.failure_stage,
    health: healthFrom.health,
    health_reason: healthFrom.health_reason,
    health_code: healthFrom.health_code,
    stalled_since: healthFrom.stalled_since,
  };
}

type Coalesced =
  | { kind: 'health'; payload: StatusEventPayload }
  | { kind: 'speed'; speed: number }
  | {
      kind: 'sources';
      /** Newest event reporting live counts, when an idle one followed it:
       *  whether that idle one keeps the counts depends on how long after it
       *  arrived, so both are replayed. */
      live?: readonly [SourcesEventPayload, number];
      last: readonly [SourcesEventPayload, number];
    };

type PendingEntry =
  | { id: string; kind: 'status'; patch: RowPatch<Transfer> }
  | ({ id: string } & Coalesced);

/**
 * Row events waiting to be applied, in arrival order, with repeats folded.
 *
 * Health, speed-decay and source events for a row only ever touch their own
 * fields, so they commute with each other; of the four kinds only a status
 * event reads or writes what the others do. A repeat of one of those three
 * kinds is therefore folded into the queued one of the same kind — in its
 * original position — unless a status event for that row was queued in
 * between, in which case it starts a new entry. Without status churn that
 * bounds the queue at three entries per row however long it waits.
 */
export class PendingRowOps {
  private entries = new Map<string, PendingEntry>();
  /** Status events queued per row since the last drain; part of the key, so
   *  a status event seals the row's earlier entries. */
  private statusCount = new Map<string, number>();
  private serial = 0;

  get size(): number {
    return this.entries.size;
  }

  private key(kind: string, id: string): string {
    return `${kind}\u0000${this.statusCount.get(id) ?? 0}\u0000${id}`;
  }

  status(id: string, patch: RowPatch<Transfer>): void {
    this.entries.set(`status\u0000${++this.serial}`, { id, kind: 'status', patch });
    this.statusCount.set(id, (this.statusCount.get(id) ?? 0) + 1);
  }

  health(payload: StatusEventPayload): void {
    const key = this.key('health', payload.id);
    const prev = this.entries.get(key);
    this.entries.set(key, {
      id: payload.id,
      kind: 'health',
      payload: prev?.kind === 'health' ? mergeHealthPayloads(prev.payload, payload) : payload,
    });
  }

  speed(id: string, speed: number): void {
    this.entries.set(this.key('speed', id), { id, kind: 'speed', speed });
  }

  sources(payload: SourcesEventPayload, receivedAt: number): void {
    const key = this.key('sources', payload.id);
    const prev = this.entries.get(key);
    const event = [payload, receivedAt] as const;
    let live: readonly [SourcesEventPayload, number] | undefined;
    if (payload.active_sources + payload.queued_sources === 0 && prev?.kind === 'sources') {
      const [last] = prev.last;
      live = last.active_sources + last.queued_sources > 0 ? prev.last : prev.live;
    }
    this.entries.set(key, { id: payload.id, kind: 'sources', live, last: event });
  }

  /** Every queued event as a patch, oldest first, leaving the queue empty. */
  drain(context: (receivedAt: number) => RowEventContext): Array<readonly [string, RowPatch<Transfer>]> {
    const out: Array<readonly [string, RowPatch<Transfer>]> = [];
    for (const entry of this.entries.values()) {
      switch (entry.kind) {
        case 'status':
          out.push([entry.id, entry.patch]);
          break;
        case 'health': {
          const payload = entry.payload;
          out.push([entry.id, (t) => applyHealthEvent(t, payload)]);
          break;
        }
        case 'speed': {
          const speed = entry.speed;
          out.push([entry.id, (t) => applySpeedDecay(t, speed)]);
          break;
        }
        case 'sources': {
          const { live, last } = entry;
          out.push([
            entry.id,
            (t) => {
              const afterLive = live ? applySourcesEvent(t, live[0], context(live[1])) : t;
              return applySourcesEvent(afterLive, last[0], context(last[1]));
            },
          ]);
          break;
        }
      }
    }
    this.clear();
    return out;
  }

  clear(): void {
    this.entries.clear();
    this.statusCount.clear();
    this.serial = 0;
  }
}
