import { beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';

const handlers = new Map<string, (event: { payload: unknown }) => void>();
const emitted: { name: string; payload: unknown }[] = [];
let leftUnread: [string, number, number][] = [];

vi.mock('@tauri-apps/api/event', () => ({
  listen: async (name: string, handler: (event: { payload: unknown }) => void) => {
    handlers.set(name, handler);
    return () => handlers.delete(name);
  },
  emit: async (name: string, payload: unknown) => {
    emitted.push({ name, payload });
  },
}));

vi.mock('$lib/api/friends', () => ({
  getFriendRequests: async () => [],
  getFriends: async () => [],
  getOnlineFriends: async () => [],
  getUnreadMessageCounts: async () => new Map(),
  isFriendDiscoverable: async () => false,
  markAllChatsRead: async () => leftUnread,
  parseChatAttachment: () => null,
}));

vi.mock('$lib/notifications', () => ({
  notify: async () => {},
  shouldNotify: () => false,
}));

vi.mock('$lib/stores/toast', () => ({
  toastsFor: () => ({ toast: () => {}, toastError: () => {}, toastSuccess: () => {} }),
}));

const { cleanupFriendsStore, initFriendsStore, markAllFriendChatsRead, unreadCounts } = await import(
  './friends'
);

const FRIEND = 'ab'.repeat(16);
const OTHER = 'cd'.repeat(16);

function chat(payload: Record<string, unknown>, from = FRIEND) {
  handlers.get('ember:chat-message')?.({
    payload: { user_hash: from, direction: 'received', ...payload },
  });
}

beforeEach(async () => {
  cleanupFriendsStore();
  handlers.clear();
  emitted.length = 0;
  leftUnread = [];
  await initFriendsStore();
});

describe('friend unread badge', () => {
  it('counts the same word sent twice in one second when the rows differ', () => {
    chat({ id: 7, message: 'hi', timestamp: 1000 });
    chat({ id: 8, message: 'hi', timestamp: 1000 });

    expect(get(unreadCounts).get(FRIEND)).toBe(2);
  });

  it('counts a re-emit of one row once', () => {
    chat({ id: 7, message: 'hi', timestamp: 1000 });
    chat({ id: 7, message: 'hi', timestamp: 1000 });

    expect(get(unreadCounts).get(FRIEND)).toBe(1);
  });

  it('falls back to the content tuple for an emit without an id', () => {
    chat({ message: 'hi', timestamp: 1000 });
    chat({ message: 'hi', timestamp: 1000 });
    chat({ message: 'hi', timestamp: 1001 });

    expect(get(unreadCounts).get(FRIEND)).toBe(2);
  });
});

describe('mark all as read', () => {
  it('clears what was read and keeps what is left, in both windows', async () => {
    chat({ id: 7, message: 'hi', timestamp: 1000 });
    chat({ id: 8, message: 'fleeting', timestamp: 1001 });
    chat({ id: 9, message: 'yo', timestamp: 1002 }, OTHER);
    leftUnread = [[FRIEND, 1, 8]];

    expect(await markAllFriendChatsRead()).toBe(1);

    expect(get(unreadCounts).get(FRIEND)).toBe(1);
    expect(get(unreadCounts).has(OTHER)).toBe(false);
    expect(emitted).toContainEqual({ name: 'ember-ui:unread-set', payload: { user_hash: FRIEND, count: 1 } });
    expect(emitted).toContainEqual({ name: 'ember-ui:unread-cleared', payload: { user_hash: OTHER } });
  });

  it('takes the count the other window set, and nothing malformed', () => {
    chat({ id: 7, message: 'hi', timestamp: 1000 });
    chat({ id: 8, message: 'fleeting', timestamp: 1001 });
    const set = (payload: unknown) => handlers.get('ember-ui:unread-set')?.({ payload });

    set({ user_hash: FRIEND, count: 1 });
    expect(get(unreadCounts).get(FRIEND)).toBe(1);

    set({ user_hash: FRIEND, count: -1 });
    set({ user_hash: FRIEND, count: 2.5 });
    set({ user_hash: 'not-a-hash', count: 4 });
    expect(get(unreadCounts).get(FRIEND)).toBe(1);
    expect(get(unreadCounts).size).toBe(1);
  });
});
