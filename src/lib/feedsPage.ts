/**
 * Small pieces of the Feeds page's state, kept here so they can be tested
 * without mounting the page.
 */
import type { FeedItemStatus, FeedsChangedEvent } from '$lib/api/feeds';

/** The largest auto-download cap the backend keeps, in MiB (`commands/feeds.rs`). */
export const AUTO_MIB_MAX = 2 ** 30;

/** What a cap field holds, as saved: an emptied or negative one is 0, and a
 *  huge one is the most the backend keeps. */
export function capMib(value: number | null | undefined): number {
  const whole = Math.floor(Number(value) || 0);
  return Math.min(AUTO_MIB_MAX, Math.max(0, whole));
}

/** What saving a feed's editor keeps. */
export interface FeedDraft {
  title: string;
  description: string;
  items: readonly { ed2k: string; note: string }[];
}

/** `feed` as the editor compares it. */
export function draftOf(feed: FeedDraft): FeedDraft {
  return {
    title: feed.title,
    description: feed.description,
    items: feed.items.map((i) => ({ ed2k: i.ed2k, note: i.note })),
  };
}

/** Whether saving `a` would store the same as `b`: the same details, and the
 *  same files in the same order with the same notes. */
export function sameDraft(a: FeedDraft, b: FeedDraft): boolean {
  return (
    a.title === b.title &&
    a.description === b.description &&
    a.items.length === b.items.length &&
    a.items.every((item, i) => item.ed2k.toLowerCase() === b.items[i].ed2k.toLowerCase() && item.note === b.items[i].note)
  );
}

/** Whether an `ember:feeds-changed` event may concern the followed feed
 *  `feed`: one that names it, or one that names no feed at all. An event
 *  naming only a salt is about one of the user's own feeds. */
export function concernsFollowed(
  event: FeedsChangedEvent | null | undefined,
  feed: { publisher: string; salt: string },
): boolean {
  if (!event?.publisher && !event?.salt) return true;
  return event.publisher === feed.publisher && event.salt === feed.salt;
}

/** A download's latest figures from its progress events: bytes on disk and
 *  bytes per second. */
export interface LiveProgress {
  done: number;
  speed: number;
}

interface ProgressRow {
  size: number;
  progress: number;
  transfer: { id: string; done: number; speed: number } | null;
}

/** `items` with the figures in `live`, by transfer id, taken in; `items`
 *  itself when none of them change, so nothing redraws for nothing. */
export function withLiveProgress<T extends ProgressRow>(items: T[], live: ReadonlyMap<string, LiveProgress>): T[] {
  let changed = false;
  const next = items.map((item) => {
    const t = item.transfer;
    const p = t ? live.get(t.id) : undefined;
    if (!t || !p) return item;
    const done = Math.min(item.size, Math.max(0, p.done));
    if (done === t.done && p.speed === t.speed) return item;
    changed = true;
    const progress = item.size > 0 ? (done / item.size) * 100 : item.progress;
    return { ...item, progress, transfer: { ...t, done, speed: p.speed } };
  });
  return changed ? next : items;
}

/** Whether two values read from the backend hold the same: compared field by
 *  field, nested objects and arrays too. */
function sameValue(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const x = a as Record<string, unknown>;
  const y = b as Record<string, unknown>;
  const keys = Object.keys(x);
  return keys.length === Object.keys(y).length && keys.every((k) => k in y && sameValue(x[k], y[k]));
}

/** `next`, a list read again, with each row that has not changed since
 *  `prev` kept as the row `prev` holds, by eD2K hash; `prev` itself when no
 *  row changed, moved, came or went. A feed's list can hold 2,000 files, and
 *  a row given anew is drawn anew. */
export function keepUnchanged<T extends { ed2k: string }>(prev: readonly T[], next: T[]): T[] {
  const held = new Map(prev.map((row) => [row.ed2k, row]));
  let same = prev.length === next.length;
  const merged = next.map((row, i) => {
    const old = held.get(row.ed2k);
    const kept = old !== undefined && sameValue(old, row) ? old : row;
    if (kept !== prev[i]) same = false;
    return kept;
  });
  return same ? (prev as T[]) : merged;
}

/** The followed feed to open when none the user chose is: the one last
 *  opened, else the first with something new, else the first. */
export function pickFollowed<T extends { publisher: string; salt: string; unread: number }>(
  feeds: readonly T[],
  remembered: string | null,
): T | undefined {
  return (
    feeds.find((f) => `${f.publisher}/${f.salt}` === remembered) ?? feeds.find((f) => f.unread > 0) ?? feeds[0]
  );
}

/** Whether a followed feed's file is here to open or show in its folder. */
export const onDisk = (status: FeedItemStatus): boolean => status === 'done' || status === 'in_library';

/** Run `task` on each of `items`, at most `limit` at once, on to the end
 *  whatever fails; resolves to what the failed ones threw, in their order. */
export async function runEach<T>(
  items: readonly T[],
  limit: number,
  task: (item: T) => Promise<unknown>,
): Promise<unknown[]> {
  const failed: { at: number; error: unknown }[] = [];
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const at = next++;
      try {
        await task(items[at]);
      } catch (error) {
        failed.push({ at, error });
      }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  return failed.sort((a, b) => a.at - b.at).map((f) => f.error);
}
