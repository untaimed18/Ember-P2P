import { beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';

const handlers = new Map<string, (event: { payload: unknown }) => void>();

vi.mock('@tauri-apps/api/event', () => ({
  listen: async (name: string, handler: (event: { payload: unknown }) => void) => {
    handlers.set(name, handler);
    return () => handlers.delete(name);
  },
  emit: async () => {},
}));

vi.mock('$lib/api/friends', () => ({
  getFriendRequests: async () => [],
  getFriends: async () => [],
  getOnlineFriends: async () => [],
  getUnreadMessageCounts: async () => new Map(),
  isFriendDiscoverable: async () => false,
  parseChatAttachment: () => null,
}));

vi.mock('$lib/notifications', () => ({
  notify: async () => {},
  shouldNotify: () => false,
}));

vi.mock('$lib/stores/toast', () => ({
  toast: () => {},
  toastError: () => {},
  toastSuccess: () => {},
}));

const { cleanupFriendsStore, initFriendsStore, unreadCounts } = await import('./friends');

const FRIEND = 'ab'.repeat(16);

function chat(payload: Record<string, unknown>) {
  handlers.get('ember:chat-message')?.({
    payload: { user_hash: FRIEND, direction: 'received', ...payload },
  });
}

beforeEach(async () => {
  cleanupFriendsStore();
  handlers.clear();
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
