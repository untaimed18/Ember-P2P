import { writable, get } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import type { UnlistenFn } from '@tauri-apps/api/event';
import {
  getFriendRequests,
  getFriends,
  getOnlineFriends,
  getUnreadMessageCounts,
  isFriendDiscoverable,
  type FriendRequestInfo,
} from '$lib/api/friends';
import { appSettings } from '$lib/stores/settings';
import { toast } from '$lib/stores/toast';
import * as m from '$lib/paraglide/messages';

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

let activeChatHashSnapshot: string | null = null;
activeChatHash.subscribe((v) => { activeChatHashSnapshot = v; });

// Best-effort hash → nickname map, used only to name a friend in the
// "came online" toast. Populated from `get_friends` on init and refreshed when
// a friendship is confirmed. A rename made elsewhere may briefly show a stale
// name until the next confirm/init — acceptable for a transient toast.
let friendNames = new Map<string, string>();
async function refreshFriendNames(): Promise<void> {
  try {
    const list = await getFriends();
    friendNames = new Map(list.map((f) => [f.user_hash, f.nickname]));
  } catch {
    // Keep whatever we had; the toast falls back to a short hash.
  }
}

function shortHash(hash: string): string {
  return hash.length > 8 ? hash.slice(0, 8) + '\u2026' : hash;
}

// Toast a friend coming online, gated on the user preference. Called only on a
// genuine offline→online transition (see the listener) so re-emitted online
// signals for an already-online friend don't spam, and never for the initial
// startup snapshot (seeded with `.update`, bypassing this).
function notifyFriendOnline(hash: string): void {
  if (!get(appSettings)?.friend_online_notifications) return;
  toast(m.friend_online_toast({ name: friendNames.get(hash) || shortHash(hash) }));
}

let initialized = false;
let unlisteners: UnlistenFn[] = [];

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
function scheduleFriendRequestRefetch() {
  if (friendRequestRefetchTimer !== null) return;
  friendRequestRefetchTimer = setTimeout(() => {
    friendRequestRefetchTimer = null;
    getFriendRequests()
      .then((reqs) => friendRequests.set(reqs))
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

  const registered: UnlistenFn[] = [];
  try {
    registered.push(
      await listen<{ user_hash: string }>('ember:friend-online', (event) => {
        const hash = event.payload.user_hash;
        let wasOffline = false;
        onlineFriends.update((s) => {
          if (s.has(hash)) return s;
          wasOffline = true;
          return new Set([...s, hash]);
        });
        searchingFriends.update((s) => { const next = new Set(s); next.delete(hash); return next; });
        clearSearchTimer(hash);
        // Only notify on a real transition — repeated online signals for an
        // already-online friend (the backend can emit several) must not toast.
        if (wasOffline) notifyFriendOnline(hash);
      }),
    );
    registered.push(
      await listen<{ user_hash: string }>('ember:friend-offline', (event) => {
        onlineFriends.update((s) => { const next = new Set(s); next.delete(event.payload.user_hash); return next; });
      }),
    );
    registered.push(
      await listen<{ user_hash: string; direction: string }>('ember:chat-message', (event) => {
        if (event.payload.direction !== 'received') return;
        // If the chat with this friend is open and focused, the
        // user is reading the message in real time — incrementing
        // `unreadCounts` would leave a phantom badge until the
        // tab loses focus and is reactivated. `ChatConversation`
        // separately marks the message read on the backend.
        if (activeChatHashSnapshot === event.payload.user_hash) return;
        unreadCounts.update((m) => {
          const next = new Map(m);
          next.set(event.payload.user_hash, (next.get(event.payload.user_hash) || 0) + 1);
          return next;
        });
      }),
    );
    registered.push(
      await listen<{ sender_hash: string; nickname: string; verified?: boolean }>(
        'ember:friend-request',
        (event) => {
          const { sender_hash, nickname, verified } = event.payload;
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
        searchingFriends.update((s) => { const next = new Set(s); next.delete(event.payload.user_hash); return next; });
        clearSearchTimer(event.payload.user_hash);
        // A confirm (manual accept or auto-confirm) can introduce a brand-new
        // mutual friend; refresh the name map so a later online toast can name
        // them.
        void refreshFriendNames();
      }),
    );
    registered.push(
      await listen<{ discoverable: boolean; nodes: number }>('ember:friend-discoverable', (event) => {
        isDiscoverable.set(event.payload.discoverable);
      }),
    );
    registered.push(
      await listen<{ user_hash: string }>('ember:friend-searching', (event) => {
        searchingFriends.update((s) => new Set([...s, event.payload.user_hash]));
        // Arm/refresh the auto-clear so a missing terminal event
        // (e.g. backend crash mid-search) doesn't strand the
        // spinner.
        armSearchTimer(event.payload.user_hash);
      }),
    );
    registered.push(
      await listen<{ user_hash: string; reason?: string }>('ember:friend-search-failed', (event) => {
        searchingFriends.update((s) => { const next = new Set(s); next.delete(event.payload.user_hash); return next; });
        clearSearchTimer(event.payload.user_hash);
      }),
    );
  } catch (e) {
    for (const u of registered) u();
    initialized = false;
    console.error('Failed to initialize friends store listeners:', e);
    throw e;
  }
  unlisteners.push(...registered);

  try {
    const reqs = await getFriendRequests();
    friendRequests.set(reqs);
  } catch { /* backend not ready yet */ }

  try {
    const counts = await getUnreadMessageCounts();
    unreadCounts.set(new Map(counts));
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
    isDiscoverable.set(discoverable);
  } catch { /* backend not ready yet */ }

  // Seed the name map used by online toasts.
  await refreshFriendNames();

  // Seed the online set from the backend's current view so friends don't all
  // show offline (chat/browse disabled) until the next `ember:friend-online`
  // transition. Merge rather than replace so any online event that landed
  // during init isn't dropped. Seeding via the store (not the listener) means
  // these pre-online friends don't trigger "came online" toasts.
  try {
    const online = await getOnlineFriends();
    onlineFriends.update((s) => new Set([...s, ...online]));
  } catch { /* backend not ready yet */ }
}

export function clearUnread(friendHash: string) {
  unreadCounts.update((m) => { const next = new Map(m); next.delete(friendHash); return next; });
}

export function cleanupFriendsStore() {
  for (const unlisten of unlisteners) unlisten();
  unlisteners = [];
  initialized = false;
  if (friendRequestRefetchTimer !== null) {
    clearTimeout(friendRequestRefetchTimer);
    friendRequestRefetchTimer = null;
  }
  // L19: tear down any outstanding search-TTL timers; otherwise
  // a re-init would re-arm them on top of stale state.
  for (const t of searchTimers.values()) clearTimeout(t);
  searchTimers.clear();
  onlineFriends.set(new Set());
  unreadCounts.set(new Map());
  friendRequests.set([]);
  searchingFriends.set(new Set());
  isDiscoverable.set(false);
  activeChatHash.set(null);
  friendNames = new Map();
}
