/**
 * Small pieces of the Feeds page's state, kept here so they can be tested
 * without mounting the page.
 */
import type { FeedsChangedEvent } from '$lib/api/feeds';

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
