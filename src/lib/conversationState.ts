/**
 * Small pieces of `ChatConversation`'s state, kept here so they can be tested
 * without mounting the component.
 */

/** A room line's delivery as `ember:channel-delivery` reports it. */
export type RoomDelivery = 'delivered' | 'queued' | 'failed';

/**
 * Delivery reports for room lines that arrived before the send's response
 * added the line: a room line can be flooded, or reported failed, before
 * `send_channel_message` returns its row. Each report is used once, by the
 * row it names, and only kept while a send or resend is still waiting on its
 * response; anything else would sit here unused.
 */
export class EarlyRoomDeliveries {
  private held = new Map<number, RoomDelivery>();

  /** Keep `delivery` for row `id` if a send is waiting to add it. Returns
   *  whether it was kept. */
  hold(id: number, delivery: RoomDelivery, sendWaiting: boolean): boolean {
    if (!sendWaiting) return false;
    this.held.set(id, delivery);
    return true;
  }

  /** `row` with any report kept for it applied, which is then spent. */
  apply<T extends { id: number; delivery?: string }>(row: T): T {
    const early = this.held.get(row.id);
    if (early === undefined) return row;
    this.held.delete(row.id);
    return { ...row, delivery: early };
  }

  /** Forget every report: another conversation is open. */
  clear(): void {
    this.held.clear();
  }

  get size(): number {
    return this.held.size;
  }
}

/** What the slow-mode live region last dealt with. */
export interface SlowModeAnnouncer {
  key: string;
  waiting: boolean;
}

/**
 * What the slow-mode live region says when the wait or the conversation
 * changes. The count changes every second, and even a polite region reads out
 * each change, so only the start and end of a wait are spoken.
 *
 * `say` is `'started'` or `'ready'` for a change to speak, `'clear'` when the
 * conversation changed (a switch drops the wait without it having run out,
 * so it is not announced as over), and `null` when nothing changed.
 */
export function stepSlowModeAnnouncer(
  prev: SlowModeAnnouncer,
  key: string,
  waiting: boolean,
): { next: SlowModeAnnouncer; say: 'started' | 'ready' | 'clear' | null } {
  if (key !== prev.key) return { next: { key, waiting: false }, say: 'clear' };
  if (waiting === prev.waiting) return { next: prev, say: null };
  return { next: { key, waiting }, say: waiting ? 'started' : 'ready' };
}
