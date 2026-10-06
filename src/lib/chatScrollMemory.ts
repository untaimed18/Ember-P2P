/**
 * Where the reader left each conversation, so coming back to one with nothing
 * new in it lands where they were reading instead of at the bottom. With
 * unread lines the conversation opens on those instead.
 *
 * Kept for this session only and in this window only. The spot is a message
 * and how far its top sat below the top of the transcript, rather than a pixel
 * offset, because the transcript is rebuilt from scratch on every visit and
 * lines that arrived in between change its height.
 */

export interface ScrollSpot {
  /** Database row id of the first message showing at the top. */
  id: number;
  /** Its top edge relative to the top of the transcript, in pixels. Negative
   *  when the message is partly scrolled off. */
  offset: number;
}

/** Enough for every conversation a reader moves between in one sitting. */
export const SCROLL_MEMORY_LIMIT = 64;

const spots = new Map<string, ScrollSpot>();

/** Remember where a conversation was left, or forget it when `spot` is null
 *  (the reader was at the newest line, which is where it opens anyway). */
export function rememberScroll(key: string, spot: ScrollSpot | null): void {
  spots.delete(key);
  if (!spot) return;
  spots.set(key, spot);
  // Oldest first in insertion order, and every write re-inserts.
  while (spots.size > SCROLL_MEMORY_LIMIT) {
    const oldest = spots.keys().next().value;
    if (oldest === undefined) break;
    spots.delete(oldest);
  }
}

export function recalledScroll(key: string): ScrollSpot | undefined {
  return spots.get(key);
}

export function forgetAllScroll(): void {
  spots.clear();
}

/**
 * Index of the first row whose bottom edge is below `top`, given the bottom
 * edges in document order (which is also top-to-bottom order). `count` when
 * every row is above it.
 */
export function firstRowBelow(bottoms: (index: number) => number, count: number, top: number): number {
  let lo = 0;
  let hi = count;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (bottoms(mid) > top) hi = mid;
    else lo = mid + 1;
  }
  return lo;
}
