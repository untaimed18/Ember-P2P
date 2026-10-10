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

const api = vi.hoisted(() => ({
  getFriendRequests: vi.fn(),
  getFriends: vi.fn(),
  getOnlineFriends: vi.fn(),
  getUnreadMessageCounts: vi.fn(),
  isFriendDiscoverable: vi.fn(),
}));
vi.mock('$lib/api/friends', () => ({ ...api, parseChatAttachment: () => null }));

const startDownload = vi.hoisted(() => vi.fn());
vi.mock('$lib/api/transfers', () => ({ startDownload }));

vi.mock('$lib/notifications', () => ({
  notify: async () => {},
  shouldNotify: () => false,
}));

vi.mock('$lib/stores/toast', () => ({
  toast: () => {},
  toastError: () => {},
  toastSuccess: () => {},
}));

const {
  acceptIncomingFileOffer,
  acceptingOffer,
  cleanupFriendsStore,
  fileOffers,
  friendRequests,
  initFriendsStore,
  isDiscoverable,
  legacyStrandedFriends,
  onlineFriends,
  unreadCounts,
} = await import('./friends');

const A = 'aa'.repeat(16);
const B = 'bb'.repeat(16);
const C = 'cc'.repeat(16);
const FILE = 'f0'.repeat(16);

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

function fire(name: string, payload: unknown) {
  const handler = handlers.get(name);
  if (!handler) throw new Error(`no listener for ${name}`);
  handler({ payload });
}

function request(sender_hash: string, received_at: number) {
  return { sender_hash, sender_nickname: '', received_at, verified: false };
}

beforeEach(() => {
  cleanupFriendsStore();
  handlers.clear();
  api.getFriendRequests.mockReset().mockResolvedValue([]);
  api.getFriends.mockReset().mockResolvedValue([]);
  api.getOnlineFriends.mockReset().mockResolvedValue([]);
  api.getUnreadMessageCounts.mockReset().mockResolvedValue([]);
  api.isFriendDiscoverable.mockReset().mockResolvedValue(false);
  startDownload.mockReset();
});

// The listeners are live while the startup snapshots are in flight, so an
// event can land between the moment a snapshot was read and the moment it
// arrives. For anything that event touched, the event is the newer answer.
describe('startup seed against live events', () => {
  it('runs the seeds side by side', async () => {
    const online = deferred<string[]>();
    api.getOnlineFriends.mockReturnValue(online.promise);
    const init = initFriendsStore();
    await vi.waitFor(() => expect(api.getOnlineFriends).toHaveBeenCalled());
    expect(api.getFriendRequests).toHaveBeenCalled();
    expect(api.getUnreadMessageCounts).toHaveBeenCalled();
    expect(api.isFriendDiscoverable).toHaveBeenCalled();
    expect(api.getFriends).toHaveBeenCalled();
    online.resolve([]);
    await init;
  });

  it('keeps an offline event over an online snapshot taken before it', async () => {
    const online = deferred<string[]>();
    api.getOnlineFriends.mockReturnValue(online.promise);
    const init = initFriendsStore();
    await vi.waitFor(() => expect(api.getOnlineFriends).toHaveBeenCalled());

    fire('ember:friend-online', { user_hash: A });
    fire('ember:friend-offline', { user_hash: A });
    online.resolve([A, B]);
    await init;

    expect([...get(onlineFriends)]).toEqual([B]);
  });

  it('keeps request rows that events added or withdrew during the fetch', async () => {
    const reqs = deferred<ReturnType<typeof request>[]>();
    api.getFriendRequests.mockReturnValue(reqs.promise);
    const init = initFriendsStore();
    await vi.waitFor(() => expect(api.getFriendRequests).toHaveBeenCalled());

    fire('ember:friend-request', { sender_hash: A, nickname: 'Ana' });
    fire('ember:friend-request-withdrawn', { sender_hash: B });
    reqs.resolve([request(B, 20), request(C, 10)]);
    await init;

    expect(get(friendRequests).map((r) => r.sender_hash)).toEqual([A, C]);
  });

  it('keeps a discoverability event over the snapshot', async () => {
    const snapshot = deferred<boolean>();
    api.isFriendDiscoverable.mockReturnValue(snapshot.promise);
    const init = initFriendsStore();
    await vi.waitFor(() => expect(api.isFriendDiscoverable).toHaveBeenCalled());

    fire('ember:friend-discoverable', { discoverable: true, intro_ok: true, legacy_stranded_friends: [C] });
    snapshot.resolve(false);
    await init;

    expect(get(isDiscoverable)).toBe(true);
    expect([...get(legacyStrandedFriends)]).toEqual([C]);
  });

  it('asks again for unread counts when a message lands during the fetch', async () => {
    const first = deferred<[string, number][]>();
    const second = deferred<[string, number][]>();
    api.getUnreadMessageCounts
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);
    const init = initFriendsStore();
    await vi.waitFor(() => expect(api.getUnreadMessageCounts).toHaveBeenCalledTimes(1));

    fire('ember:chat-message', { user_hash: A, id: 9, direction: 'received', message: 'hi' });
    first.resolve([[A, 2], [B, 1]]);
    await vi.waitFor(() => expect(api.getUnreadMessageCounts).toHaveBeenCalledTimes(2));
    second.resolve([[A, 3], [B, 1]]);
    await init;

    expect(get(unreadCounts)).toEqual(new Map([[A, 3], [B, 1]]));
  });

  it('lets a clear stand over a snapshot that still counts the messages', async () => {
    const first = deferred<[string, number][]>();
    const second = deferred<[string, number][]>();
    api.getUnreadMessageCounts
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);
    const init = initFriendsStore();
    await vi.waitFor(() => expect(api.getUnreadMessageCounts).toHaveBeenCalledTimes(1));

    fire('ember-ui:unread-cleared', { user_hash: A });
    first.resolve([[A, 4]]);
    await vi.waitFor(() => expect(api.getUnreadMessageCounts).toHaveBeenCalledTimes(2));
    fire('ember-ui:unread-cleared', { user_hash: A });
    second.resolve([[A, 4]]);
    await init;

    expect(get(unreadCounts).has(A)).toBe(false);
  });

  it('never counts fewer than the snapshot for a friend only bumped meanwhile', async () => {
    const first = deferred<[string, number][]>();
    const second = deferred<[string, number][]>();
    api.getUnreadMessageCounts
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);
    const init = initFriendsStore();
    await vi.waitFor(() => expect(api.getUnreadMessageCounts).toHaveBeenCalledTimes(1));

    fire('ember:chat-message', { user_hash: A, id: 1, direction: 'received' });
    first.resolve([[A, 4]]);
    await vi.waitFor(() => expect(api.getUnreadMessageCounts).toHaveBeenCalledTimes(2));
    fire('ember:chat-message', { user_hash: A, id: 2, direction: 'received' });
    second.resolve([[A, 5]]);
    await init;

    expect(get(unreadCounts).get(A)).toBe(5);
  });
});

describe('file offers', () => {
  it('keeps whether the sender restricts the file to friends', async () => {
    await initFriendsStore();
    fire('ember:file-offer', { user_hash: A, file_hash: FILE, file_name: 'a.mkv', file_size: 1, friends_only: true });
    fire('ember:file-offer', { user_hash: B, file_hash: FILE, file_name: 'b.mkv', file_size: 1 });

    expect(get(fileOffers).map((o) => o.friends_only)).toEqual([true, false]);
  });

  it('starts one download however many surfaces ask at once', async () => {
    const download = deferred<{ already_queued: boolean }>();
    startDownload.mockReturnValue(download.promise);
    const offer = { user_hash: A, file_hash: FILE, file_name: 'a.mkv', file_size: 1 };

    const first = acceptIncomingFileOffer(offer);
    expect(get(acceptingOffer)).toBe(`${A}:${FILE}`);
    expect(await acceptIncomingFileOffer(offer)).toBeNull();

    download.resolve({ already_queued: false });
    expect(await first).toEqual({ already_queued: false });
    expect(startDownload).toHaveBeenCalledTimes(1);
    expect(get(acceptingOffer)).toBeNull();
  });

  it('lets the next accept through after one fails', async () => {
    startDownload.mockRejectedValueOnce(new Error('nope'));
    const offer = { user_hash: A, file_hash: FILE, file_name: 'a.mkv', file_size: 1 };

    await expect(acceptIncomingFileOffer(offer)).rejects.toThrow('nope');
    expect(get(acceptingOffer)).toBeNull();
  });
});
