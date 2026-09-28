/**
 * Pinned messages in rooms: which pins the bar shows, in what order, and what
 * the owner's Pin control offers for a given line.
 *
 * The pins themselves are the owner's, carried on their signed moderation
 * snapshot (`ModerationTail::pinned_msg_ids` in
 * `src-tauri/src/network/ember/dht/publish.rs`) and handed to the UI as wire
 * ids on `ChannelInfo.pinned_msg_ids`, oldest pin first.
 */
import type { ChannelPinInfo } from '$lib/api/channels';
import type { QuotableMessage } from '$lib/channelReply';

export type PinEntry =
  | { kind: 'message'; msgId: string; id: number; senderPubkey: string; text: string }
  /** Pinned, but the line has not reached this device — or has aged out of
   *  its history. Shown as such rather than hidden, so the count is honest. */
  | { kind: 'missing'; msgId: string };

/**
 * What the pin bar shows, newest pin first.
 *
 * `pinnedIds` is the order and the membership; `lookups` is the backend's read
 * of each line, which may lag a snapshot that has just changed. A loaded copy
 * wins over the lookup, because it is the one live edits patch. A pin removed
 * from this device is dropped altogether: it was deleted, not delayed, and the
 * owner's next commit takes it off the wire.
 */
export function resolvePins(
  pinnedIds: readonly string[],
  lookups: readonly ChannelPinInfo[],
  loaded: ReadonlyMap<string, QuotableMessage>,
  removed: ReadonlySet<string>,
): PinEntry[] {
  const byId = new Map(lookups.map((pin) => [pin.msg_id, pin]));
  const out: PinEntry[] = [];
  for (let i = pinnedIds.length - 1; i >= 0; i--) {
    const msgId = pinnedIds[i];
    if (removed.has(msgId)) continue;
    const here = loaded.get(msgId);
    if (here && here.id > 0) {
      out.push({
        kind: 'message',
        msgId,
        id: here.id,
        senderPubkey: here.sender_pubkey ?? '',
        text: here.message,
      });
      continue;
    }
    const lookup = byId.get(msgId);
    if (lookup?.deleted) continue;
    if (lookup?.message) {
      out.push({
        kind: 'message',
        msgId,
        id: lookup.message.id,
        senderPubkey: lookup.message.sender_pubkey,
        text: lookup.message.excerpt,
      });
    } else {
      out.push({ kind: 'missing', msgId });
    }
  }
  return out;
}

/** The pin after `index` among `count`, wrapping, for the bar's "1 of 3". */
export function nextPinIndex(index: number, count: number): number {
  if (count <= 0) return 0;
  return (Math.max(0, index) + 1) % count;
}

/** `index` kept inside a list that may have shrunk under it. */
export function clampPinIndex(index: number, count: number): number {
  if (count <= 0) return 0;
  return Math.min(Math.max(0, index), count - 1);
}

/**
 * Which pin the bar shows once the room's pin list has changed from `prevIds`
 * to `nextIds`. A new pin is the one worth seeing first; otherwise the reader
 * stays where they were, pulled back inside the list if it shrank under them.
 * Pass an empty `prevIds` for a room just opened.
 */
export function pinIndexAfterChange(
  prevIds: readonly string[],
  nextIds: readonly string[],
  index: number,
): number {
  const before = new Set(prevIds);
  if (nextIds.some((id) => !before.has(id))) return 0;
  return clampPinIndex(index, nextIds.length);
}

/**
 * What the owner's Pin control offers for one line: unpin a pinned one, pin
 * another, or — at the cap — nothing, with a tooltip saying why. Refusing is
 * clearer than quietly replacing the oldest: the owner chose those pins.
 */
export function pinAction(
  msgId: string,
  pinnedIds: readonly string[],
  max: number,
): 'pin' | 'unpin' | 'full' {
  if (pinnedIds.includes(msgId)) return 'unpin';
  return pinnedIds.length >= max ? 'full' : 'pin';
}
