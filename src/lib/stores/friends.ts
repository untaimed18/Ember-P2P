import { writable, get } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import type { UnlistenFn } from '@tauri-apps/api/event';
import {
  getFriendRequests,
  getOnlineFriends,
  getUnreadMessageCounts,
  isFriendDiscoverable,
  type FriendRequestInfo,
} from '$lib/api/friends';

export const onlineFriends = writable<Set<string>>(new Set());
export const unreadCounts = writable<Map<string, number>>(new Map());
export const friendRequests = writable<FriendRequestInfo[]>([]);
export const searchingFriends = writable<Set<string>>(new Set());
export const isDiscoverable = writable(false);

// L19: per-friend timers that automatically clear stale "searching"
// state. The backend emits `friend-searching` and is supposed to
// follow up with either `friend-confirmed`, `friend-search-failed`,
// or `friend-online` — but if the worker crashes mid-search or the
// terminal event is lost on the IPC bridge, the friend-row spinner
// would otherwise spin forever. After SEARCH_TTL_MS we forcibly
// drop the entry; the user can re-trigger the search if they
// actually want one.
const SEARCH_TTL_MS = 60_000;
const searchTimers = new Map<string, ReturnType<typeof setTimeout>>();
const FRIEND_HASH_RE = /^[0-9a-f]{32}$/i;

function validFriendHash(raw: unknown): string | null {
  return typeof raw === 'string' && FRIEND_HASH_RE.test(raw) ? raw.toLowerCase() : null;
}

function safeEventText(raw: unknown, max = 4096): string {
  return typeof raw === 'string' ? raw.slice(0, max) : '';
}

function clearSearchTimer(hash: string) {
  const t = searchTimers.get(hash);
  if (t !== undefined) {
    clearTimeout(t);
    searchTimers.delete(hash);
  }
}
function armSearchTimer(hash: string) {
  clearSearchTimer(hash);
  searchTimers.set(
    hash,
    setTimeout(() => {
      searchTimers.delete(hash);
      searchingFriends.update((s) => {
        const next = new Set(s);
        next.delete(hash);
        return next;
      });
    }, SEARCH_TTL_MS),
  );
}

// The friend hash of the chat that's currently open and focused in
// the UI. Set by `ChatConversation` when it mounts/unmounts (which
// in turn is driven by the active tab in the multi-conversation
// `ChatDock`). Used to skip `unreadCounts` increments for messages
// the user is actively looking at — without this, a chat-message
// event arriving while the conversation is open would still bump
// the unread badge, leaving phantom counts when the user switches
// tabs or closes the dock. The store mirrors this outside
// `unreadCounts` because the chat-message listener fires regardless
// of which UI surface is mounted.
export const activeChatHash = writable<string | null>(null);

// Dedup window for inbound `ember:chat-message` events. The backend can deliver
// the same logical message twice in quick succession (the download- and
// upload-side session loops both surface it), which would otherwise double-bump
// the unread badge. The signature includes the message timestamp, so two
// genuinely-distinct messages (different timestamps) are never collapsed — only
// true re-emits of the same `(hash, timestamp, body)` tuple are suppressed.
// `ChatConversation` applies an equivalent dedup to the rendered bubble list.
const recentChatSigs = new Map<string, number>();
const CHAT_SIG_TTL_MS = 10_000;

let initialized = false;
let unlisteners: UnlistenFn[] = [];
// Bumped by `cleanupFriendsStore`; see the matching comment in
// `stores/network.ts` for why `initFriendsStore` re-checks this after each
// await in its (long) async setup chain before writing to any store.
let storeEpoch = 0;

// Coalesces bursts of `ember:friend-request` events into a single
// `getFriendRequests` IPC call. The optimistic merge in the event
// listener handles the common case (one peer, one request); the
// debounced refetch is a safety net for edge cases like
// "request arrived before this window finished its initial load"
// or "a sibling window mutated the table". 250 ms is short enough
// that the user perceives the panel as responsive but long enough
// that a duplicate event from the upload + download side of a
// single peer connection collapses into one fetch.
let friendRequestRefetchTimer: ReturnType<typeof setTimeout> | null = null;
/** Bumped on optimistic accept/reject so in-flight debounced refetches
 *  can't resurrect a row the user just dismissed. */
let friendRequestsGen = 0;
/** >0 while an accept/reject IPC is in flight — refetch must not
 *  blind-set the store over the optimistic removal. */
let friendRequestMutationInFlight = 0;

/** Call around optimistic accept/reject so stale refetches are ignored. */
export function beginFriendRequestMutation() {
  friendRequestMutationInFlight++;
  friendRequestsGen++;
}

export function endFriendRequestMutation() {
  friendRequestMutationInFlight = Math.max(0, friendRequestMutationInFlight - 1);
  friendRequestsGen++;
}

function scheduleFriendRequestRefetch() {
  if (friendRequestRefetchTimer !== null) return;
  friendRequestRefetchTimer = setTimeout(() => {
    friendRequestRefetchTimer = null;
    const gen = friendRequestsGen;
    getFriendRequests()
      .then((reqs) => {
        if (friendRequestMutationInFlight > 0 || gen !== friendRequestsGen) return;
        friendRequests.set(reqs);
      })
      .catch((err) => {
        // L16: previously a bare comment swallowed every failure
        // including transient IPC errors that we'd want to know
        // about during development. The optimistic merge already
        // wrote a row from the event payload, so the UI isn't
        // wrong — but a persistent refetch failure means later
        // mutations from sibling windows won't be picked up. Log
        // at warn level so a recurring failure shows up in
        // devtools without spamming the user.
        console.warn('friendRequestRefetch failed:', err);
      });
  }, 250);
}

export async function initFriendsStore() {
  if (initialized) return;
  initialized = true;
  const myEpoch = storeEpoch;

  const registered: UnlistenFn[] = [];
  try {
    registered.push(
      await listen<{ user_hash: string }>('ember:friend-online', (event) => {
        const hash = validFriendHash(event.payload?.user_hash);
        if (!hash) return;
        onlineFriends.update((s) => (s.has(hash) ? s : new Set([...s, hash])));
        searchingFriends.update((s) => { const next = new Set(s); next.delete(hash); return next; });
        clearSearchTimer(hash);
      }),
    );
    registered.push(
      await listen<{ user_hash: string }>('ember:friend-offline', (event) => {
        const hash = validFriendHash(event.payload?.user_hash);
        if (!hash) return;
        onlineFriends.update((s) => { const next = new Set(s); next.delete(hash); return next; });
      }),
    );
    registered.push(
      await listen<{ user_hash: string; direction: string; message?: string; timestamp?: number }>('ember:chat-message', (event) => {
        const p = event.payload;
        const hash = validFriendHash(p?.user_hash);
        if (!hash) return;
        if (p.direction !== 'received') return;
        // Suppress backend double-emits so the unread badge counts each
        // inbound message once (see `recentChatSigs` above).
        const now = Date.now();
        for (const [k, exp] of recentChatSigs) {
          if (exp <= now) recentChatSigs.delete(k);
        }
        const sig = `${hash}|${p.timestamp ?? ''}|${safeEventText(p.message)}`;
        if (recentChatSigs.has(sig)) return;
        recentChatSigs.set(sig, now + CHAT_SIG_TTL_MS);
        // If the chat with this friend is open and focused, the
        // user is reading the message in real time — incrementing
        // `unreadCounts` would leave a phantom badge until the
        // tab loses focus and is reactivated. `ChatConversation`
        // separately marks the message read on the backend.
        if (get(activeChatHash) === hash) return;
        unreadCounts.update((m) => {
          const next = new Map(m);
          next.set(hash, (next.get(hash) || 0) + 1);
          return next;
        });
      }),
    );
    registered.push(
      await listen<{ sender_hash: string; nickname: string; verified?: boolean }>(
        'ember:friend-request',
        (event) => {
          const sender_hash = validFriendHash(event.payload?.sender_hash);
          if (!sender_hash) return;
          const nickname = safeEventText(event.payload?.nickname, 128);
          const verified = event.payload?.verified;
          // Optimistic merge from the event payload so we don't pay
          // for a full DB round-trip on every inbound request. The
          // backend may emit the same logical request twice in quick
          // succession (the upload-side handler in `upload.rs` and
          // the friend-session loop in `friend_connect.rs` can both
          // fire from a single peer connection). Without a local
          // dedupe each event triggered a fresh `getFriendRequests`
          // IPC call.
          friendRequests.update((cur) => {
            const idx = cur.findIndex((r) => r.sender_hash === sender_hash);
            const newRow: FriendRequestInfo = {
              sender_hash,
              sender_nickname: nickname || '',
              received_at: Math.floor(Date.now() / 1000),
              // "verified once, always verified" mirrors the backend
              // `MAX(verified, excluded.verified)` upsert in
              // `db.add_friend_request`. A spoofer can't down-rate
              // an existing verified row by flooding unverified
              // duplicates from another channel.
              verified:
                (idx >= 0 && cur[idx].verified) || verified === true,
            };
            if (idx === -1) return [...cur, newRow];
            const next = cur.slice();
            // Preserve the original received_at on update so the
            // sort order (most-recent-first) stays stable across
            // duplicate events.
            next[idx] = { ...newRow, received_at: cur[idx].received_at };
            return next;
          });

          // Trailing-edge debounced reconciliation against the
          // backend, in case the optimistic merge missed something
          // (older request rows from a previous session, or fields
          // we don't carry on the event). Coalesces bursts into a
          // single fetch.
          scheduleFriendRequestRefetch();
        },
      ),
    );
    registered.push(
      await listen<{ user_hash: string }>('ember:friend-confirmed', (event) => {
        const hash = validFriendHash(event.payload?.user_hash);
        if (!hash) return;
        searchingFriends.update((s) => { const next = new Set(s); next.delete(hash); return next; });
        clearSearchTimer(hash);
      }),
    );
    registered.push(
      await listen<{ discoverable: boolean; nodes: number }>('ember:friend-discoverable', (event) => {
        if (typeof event.payload?.discoverable === 'boolean') {
          isDiscoverable.set(event.payload.discoverable);
        }
      }),
    );
    registered.push(
      await listen<{ user_hash: string }>('ember:friend-searching', (event) => {
        const hash = validFriendHash(event.payload?.user_hash);
        if (!hash) return;
        searchingFriends.update((s) => new Set([...s, hash]));
        // Arm/refresh the auto-clear so a missing terminal event
        // (e.g. backend crash mid-search) doesn't strand the
        // spinner.
        armSearchTimer(hash);
      }),
    );
    registered.push(
      await listen<{ user_hash: string; reason?: string }>('ember:friend-search-failed', (event) => {
        const hash = validFriendHash(event.payload?.user_hash);
        if (!hash) return;
        searchingFriends.update((s) => { const next = new Set(s); next.delete(hash); return next; });
        clearSearchTimer(hash);
      }),
    );
  } catch (e) {
    for (const u of registered) u();
    initialized = false;
    console.error('Failed to initialize friends store listeners:', e);
    throw e;
  }
  if (myEpoch !== storeEpoch) {
    // `cleanupFriendsStore` ran while we were still registering (dev HMR
    // remount / rapid re-init). Unlisten what we just added rather than
    // adopting orphaned listeners into an already-torn-down store.
    for (const u of registered) u();
    return;
  }
  unlisteners.push(...registered);

  // Every await below re-checks `myEpoch` before touching a store: a
  // cleanup that lands between two of these calls must not let the later
  // one's response repopulate a store that was just reset for the next
  // init cycle.
  try {
    const reqs = await getFriendRequests();
    if (myEpoch !== storeEpoch) return;
    friendRequests.set(reqs);
  } catch { /* backend not ready yet */ }

  try {
    const counts = await getUnreadMessageCounts();
    if (myEpoch !== storeEpoch) return;
    // Merge rather than replace: the `ember:chat-message` listener is
    // registered above, so an inbound message that lands during init has
    // already bumped `unreadCounts`. A blind `set` would drop that live
    // increment. Take the max per friend so we neither lose a bump that the
    // DB snapshot hasn't captured yet nor double-count one it already has.
    unreadCounts.update((cur) => {
      const next = new Map<string, number>(counts);
      for (const [hash, n] of cur) {
        next.set(hash, Math.max(next.get(hash) ?? 0, n));
      }
      return next;
    });
  } catch { /* backend not ready yet */ }

  // M6: previously `isDiscoverable` only flipped when the backend
  // emitted `ember:friend-discoverable`, which doesn't fire until
  // the rendezvous reachability check completes. On startup the
  // Friends page therefore showed "Not Discoverable" for several
  // seconds even when the user already had discovery enabled in a
  // prior session. Seed the store from the same backend status the
  // event would carry, so the UI is correct on first paint.
  try {
    const discoverable = await isFriendDiscoverable();
    if (myEpoch !== storeEpoch) return;
    isDiscoverable.set(discoverable);
  } catch { /* backend not ready yet */ }

  // Seed the online set from the backend's current view so friends don't all
  // show offline (chat/browse disabled) until the next `ember:friend-online`
  // transition. Merge rather than replace so any online event that landed
  // during init isn't dropped.
  try {
    const online = await getOnlineFriends();
    if (myEpoch !== storeEpoch) return;
    onlineFriends.update((s) => new Set([...s, ...online]));
  } catch { /* backend not ready yet */ }
}

export function clearUnread(friendHash: string) {
  unreadCounts.update((m) => { const next = new Map(m); next.delete(friendHash); return next; });
}

/**
 * Clear any in-progress search state (spinner) and its auto-clear timer for a
 * friend. Called when a friend is removed from the list so a search that was
 * mid-flight doesn't leave a spinner spinning against a now-gone row (and so
 * the TTL timer doesn't fire later against stale state).
 */
export function clearFriendSearch(friendHash: string) {
  clearSearchTimer(friendHash);
  searchingFriends.update((s) => {
    if (!s.has(friendHash)) return s;
    const next = new Set(s);
    next.delete(friendHash);
    return next;
  });
}

export function cleanupFriendsStore() {
  storeEpoch++;
  for (const unlisten of unlisteners) {
    try {
      unlisten();
    } catch (e) {
      console.warn('Failed to unlisten friends store listener:', e);
    }
  }
  unlisteners = [];
  initialized = false;
  if (friendRequestRefetchTimer !== null) {
    clearTimeout(friendRequestRefetchTimer);
    friendRequestRefetchTimer = null;
  }
  friendRequestsGen++;
  friendRequestMutationInFlight = 0;
  // L19: tear down any outstanding search-TTL timers; otherwise
  // a re-init would re-arm them on top of stale state.
  for (const t of searchTimers.values()) clearTimeout(t);
  searchTimers.clear();
  recentChatSigs.clear();
  onlineFriends.set(new Set());
  unreadCounts.set(new Map());
  friendRequests.set([]);
  searchingFriends.set(new Set());
  isDiscoverable.set(false);
  activeChatHash.set(null);
}
