/**
 * Room typing indicators: when to send one, who is typing, and how to say it.
 *
 * A signal is live only. The backend sends it one hop, never stores it, and
 * drops one older than ten seconds (`CHANNEL_TYPING_MAX_AGE_SECS` in
 * `src-tauri/src/network/ember/channel.rs`), so everything here is about the
 * next few seconds and nothing survives leaving the room.
 */

/** How often a composing member refreshes their signal. Mirrors the backend's
 *  `CHANNEL_TYPING_REFRESH_SECS`, which meters both ends over this window. */
export const ROOM_TYPING_REFRESH_MS = 4000;

/** How long an indicator stays up after the last signal that raised it. Longer
 *  than the refresh so one late datagram does not make the line flicker, short
 *  enough that someone who stopped mid-sentence stops being "typing" soon. */
export const ROOM_TYPING_EXPIRE_MS = 6000;

/** Member pubkey (lowercase hex) to the time their indicator lapses. Insertion
 *  order is the order people started typing, which is the order they are named. */
export type Typists = ReadonlyMap<string, number>;

/** Raise or refresh `member`'s indicator. Refreshing keeps their place. */
export function noteTypist(typists: Typists, member: string, now: number): Typists {
  const next = new Map(typists);
  next.set(member.toLowerCase(), now + ROOM_TYPING_EXPIRE_MS);
  return next;
}

/** Take `member`'s indicator down. The same map back when they had none, so a
 *  caller assigning the result to state does not wake anything for nothing. */
export function dropTypist(typists: Typists, member: string): Typists {
  const key = member.toLowerCase();
  if (!typists.has(key)) return typists;
  const next = new Map(typists);
  next.delete(key);
  return next;
}

/** Only the indicators still up at `now`; the same map when none lapsed. */
export function pruneTypists(typists: Typists, now: number): Typists {
  let lapsed = false;
  for (const until of typists.values()) {
    if (until <= now) {
      lapsed = true;
      break;
    }
  }
  if (!lapsed) return typists;
  return new Map([...typists].filter(([, until]) => until > now));
}

/** When the next indicator lapses, or null when there are none to wait for. */
export function nextTypistExpiry(typists: Typists): number | null {
  let soonest: number | null = null;
  for (const until of typists.values()) {
    if (soonest === null || until < soonest) soonest = until;
  }
  return soonest;
}

/** Who to name, in the order they started: up at `now`, and not someone this
 *  device has chosen to ignore. */
export function visibleTypists(
  typists: Typists,
  now: number,
  ignored: Iterable<string> = [],
): string[] {
  const hidden = new Set([...ignored].map((key) => key.toLowerCase()));
  return [...typists]
    .filter(([member, until]) => until > now && !hidden.has(member))
    .map(([member]) => member);
}

/**
 * What, if anything, to send after a keystroke or a change in what the user
 * may do.
 *
 * A start goes out on the first keystroke and then at most once per refresh,
 * so a steady typist costs one signal every four seconds and an idle composer
 * costs nothing. A stop is sent only to take down an indicator this device
 * raised — when the text is cleared, or when typing stops being allowed.
 */
export function outgoingTypingAction(opts: {
  hasText: boolean;
  allowed: boolean;
  lastSentOn: boolean;
  lastSentAt: number;
  now: number;
}): 'start' | 'stop' | null {
  if (!opts.allowed || !opts.hasText) return opts.lastSentOn ? 'stop' : null;
  if (!opts.lastSentOn || opts.now - opts.lastSentAt >= ROOM_TYPING_REFRESH_MS) return 'start';
  return null;
}

/** Least time between two spoken "is typing" announcements. */
export const ROOM_TYPING_ANNOUNCE_GAP_MS = 10_000;

/**
 * Whether a screen reader should hear that someone is typing. Only when the
 * room goes from nobody to somebody, and not again within the gap: the visible
 * line changes with every typist and every lapse, and speaking each of those
 * would talk over the conversation it is a hint about.
 */
export function shouldAnnounceTyping(opts: {
  active: boolean;
  wasActive: boolean;
  lastAnnouncedAt: number;
  now: number;
}): boolean {
  return opts.active && !opts.wasActive && opts.now - opts.lastAnnouncedAt >= ROOM_TYPING_ANNOUNCE_GAP_MS;
}

export type TypingSegment = { kind: 'text' | 'name'; text: string };

/** Private-use stand-ins for the names while the translated sentence is built,
 *  so each name can be drawn in its own `<bdi>` wherever the translation put it. */
const FIRST = '\uE000';
const SECOND = '\uE001';

/**
 * "Ada is typing…", "Ada and Bo are typing…", "Several people are typing…",
 * as segments: a name is never spliced into the sentence as text, so a
 * right-to-left name cannot reorder the words around it.
 *
 * Three or more collapse to "several" rather than a list: the line is a hint,
 * and a count would change every few seconds in a busy room.
 */
export function typingLineSegments(
  names: readonly string[],
  messages: {
    one: (name: string) => string;
    two: (first: string, second: string) => string;
    several: () => string;
  },
): TypingSegment[] {
  if (names.length === 0) return [];
  if (names.length > 2) return [{ kind: 'text', text: messages.several() }];
  const sentence = names.length === 1 ? messages.one(FIRST) : messages.two(FIRST, SECOND);
  const segments: TypingSegment[] = [];
  let text = '';
  for (const ch of sentence) {
    if (ch === FIRST || ch === SECOND) {
      if (text) segments.push({ kind: 'text', text });
      text = '';
      segments.push({ kind: 'name', text: ch === FIRST ? names[0] : names[1] });
    } else {
      text += ch;
    }
  }
  if (text) segments.push({ kind: 'text', text });
  return segments;
}
