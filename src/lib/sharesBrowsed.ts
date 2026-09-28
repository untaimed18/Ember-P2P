/**
 * Someone viewed the user's shared files: an ed2k client's "View Files", or a
 * friend browsing over Ember. This module turns the backend's
 * `shares-browsed` event into something safe to show; `stores/network.ts`
 * decides where it goes.
 *
 * The backend already reports each peer at most once per ten minutes (see
 * `network/shares_browsed.rs`), so every event here is worth a log line.
 */

export interface SharesBrowsedNotice {
  via: 'ed2k' | 'friend';
  /** Whether the peer was shown the list, or refused. */
  allowed: boolean;
  /** The peer's nickname (cleaned), or its address when it announced none. */
  name: string;
  /** Address and client for the log, e.g. `203.0.113.7, eMule v0.50a`.
   *  Empty for friends, whose name says who they are. */
  details: string;
  /** Lower-case Ember hash, for friends only. */
  friendHash?: string;
}

/** Longest nickname shown before it is cut with an ellipsis. */
const MAX_NAME_CHARS = 48;
const FRIEND_HASH_RE = /^[0-9a-f]{32}$/i;
/** An IPv4 or IPv6 address as the backend formats it; nothing else. */
const IP_RE = /^[0-9a-f:.]{2,45}$/i;

/**
 * A remote peer chose this string, so it is kept to one short line: control
 * characters and runs of whitespace would otherwise let it break the log
 * layout or push the rest of the message off a toast.
 */
export function cleanPeerName(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  // eslint-disable-next-line no-control-regex
  const flat = raw.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, ' ').replace(/\s+/g, ' ').trim();
  const chars = Array.from(flat);
  return chars.length > MAX_NAME_CHARS ? `${chars.slice(0, MAX_NAME_CHARS - 1).join('')}\u2026` : flat;
}

/**
 * Validate the event payload. Anything malformed is dropped rather than shown
 * half-filled; the backend only ever sends the two shapes below.
 */
export function parseSharesBrowsed(
  payload: unknown,
  friendName: (hash: string) => string,
): SharesBrowsedNotice | null {
  if (!payload || typeof payload !== 'object') return null;
  const p = payload as Record<string, unknown>;
  if (typeof p.allowed !== 'boolean') return null;

  if (p.via === 'friend') {
    if (typeof p.friend_hash !== 'string' || !FRIEND_HASH_RE.test(p.friend_hash)) return null;
    const friendHash = p.friend_hash.toLowerCase();
    return {
      via: 'friend',
      allowed: p.allowed,
      name: cleanPeerName(friendName(friendHash)) || `${friendHash.slice(0, 8)}\u2026`,
      details: '',
      friendHash,
    };
  }

  if (p.via === 'ed2k') {
    if (typeof p.peer_ip !== 'string' || !IP_RE.test(p.peer_ip)) return null;
    const nickname = cleanPeerName(p.peer_name);
    const client = cleanPeerName(p.client_software);
    return {
      via: 'ed2k',
      allowed: p.allowed,
      name: nickname || p.peer_ip,
      // Without a nickname the address is already the name.
      details: [nickname ? p.peer_ip : '', client].filter(Boolean).join(', '),
    };
  }

  return null;
}

/** `Name (details)`, or just the name when there are no details. */
export function describePeer(notice: SharesBrowsedNotice): string {
  return notice.details ? `${notice.name} (${notice.details})` : notice.name;
}

/** Toasts for browses closer together than this are left to the log. */
export const SHARES_BROWSED_TOAST_GAP_MS = 30_000;

/**
 * Whether a toast may be shown now, given when the last one was. Several
 * different peers browsing within seconds is one thing to know about, and the
 * log still lists each of them.
 */
export function sharesBrowsedToastDue(lastToastAt: number, now: number): boolean {
  return now - lastToastAt >= SHARES_BROWSED_TOAST_GAP_MS;
}
