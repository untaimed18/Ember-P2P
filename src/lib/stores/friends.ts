import { writable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import type { UnlistenFn } from '@tauri-apps/api/event';
import { getFriendRequests, getUnreadMessageCounts, type FriendRequestInfo } from '$lib/api/friends';

export const onlineFriends = writable<Set<string>>(new Set());
export const unreadCounts = writable<Map<string, number>>(new Map());
export const friendRequests = writable<FriendRequestInfo[]>([]);
export const searchingFriends = writable<Set<string>>(new Set());
export const isDiscoverable = writable(false);

let initialized = false;
let unlisteners: UnlistenFn[] = [];

export async function initFriendsStore() {
  if (initialized) return;
  initialized = true;

  const registered: UnlistenFn[] = [];
  try {
    registered.push(
      await listen<{ user_hash: string }>('ember:friend-online', (event) => {
        const hash = event.payload.user_hash;
        onlineFriends.update((s) => new Set([...s, hash]));
        searchingFriends.update((s) => { const next = new Set(s); next.delete(hash); return next; });
      }),
    );
    registered.push(
      await listen<{ user_hash: string }>('ember:friend-offline', (event) => {
        onlineFriends.update((s) => { const next = new Set(s); next.delete(event.payload.user_hash); return next; });
      }),
    );
    registered.push(
      await listen<{ user_hash: string; direction: string }>('ember:chat-message', (event) => {
        if (event.payload.direction === 'received') {
          unreadCounts.update((m) => {
            const next = new Map(m);
            next.set(event.payload.user_hash, (next.get(event.payload.user_hash) || 0) + 1);
            return next;
          });
        }
      }),
    );
    registered.push(
      await listen<{ sender_hash: string; nickname: string }>('ember:friend-request', () => {
        getFriendRequests()
          .then((reqs) => friendRequests.set(reqs))
          .catch(() => {});
      }),
    );
    registered.push(
      await listen<{ user_hash: string }>('ember:friend-confirmed', (event) => {
        searchingFriends.update((s) => { const next = new Set(s); next.delete(event.payload.user_hash); return next; });
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
      }),
    );
    registered.push(
      await listen<{ user_hash: string; reason?: string }>('ember:friend-search-failed', (event) => {
        searchingFriends.update((s) => { const next = new Set(s); next.delete(event.payload.user_hash); return next; });
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
}

export function clearUnread(friendHash: string) {
  unreadCounts.update((m) => { const next = new Map(m); next.delete(friendHash); return next; });
}

export function cleanupFriendsStore() {
  for (const unlisten of unlisteners) unlisten();
  unlisteners = [];
  initialized = false;
  onlineFriends.set(new Set());
  unreadCounts.set(new Map());
  friendRequests.set([]);
  searchingFriends.set(new Set());
  isDiscoverable.set(false);
}
