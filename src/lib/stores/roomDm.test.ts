import { describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(async () => () => {}) }));

const { dmMemberOf, dmPreview, dmRequests, dmTabKey, dmThreads, dmThreadsWithoutTab, dmUnread, refreshDmThreads } =
  await import('./roomDm');
const { chatTabs } = await import('./chatTabs');
const { invoke } = await import('@tauri-apps/api/core');
import type { RoomDmThread } from '$lib/api/roomDm';

const MEMBER = 'AB'.repeat(32);

function thread(overrides: Partial<RoomDmThread>): RoomDmThread {
  return {
    member_pubkey: MEMBER.toLowerCase(),
    name: 'Lin',
    state: 'open',
    peer_state: '',
    channel_id: 'c0'.repeat(16),
    updated_at: 1,
    unread: 0,
    last_text: '',
    last_at: 0,
    can_send: true,
    is_friend: false,
    ...overrides,
  };
}

describe('room private conversations', () => {
  it('keys a dock tab by member and reads the member back', () => {
    const key = dmTabKey(MEMBER);
    expect(key).toBe(`dm:${MEMBER.toLowerCase()}`);
    expect(dmMemberOf(key)).toBe(MEMBER.toLowerCase());
    expect(dmMemberOf('aa'.repeat(16)), 'a friend tab is not one').toBeNull();
    expect(dmMemberOf(null)).toBeNull();
  });

  // Someone's first messages wait on an answer; they show as a request, and
  // nothing about them counts as unread until it is accepted.
  it('counts unread only in accepted conversations and lists requests apart', () => {
    const other = 'cd'.repeat(32);
    dmThreads.set([
      thread({ unread: 3 }),
      thread({ member_pubkey: other, state: 'request', unread: 2 }),
    ]);
    expect([...get(dmUnread)]).toEqual([[dmTabKey(MEMBER), 3]]);
    expect(get(dmRequests).map((t) => t.member_pubkey)).toEqual([other]);
  });

  // A tab closed, or never added past the tab cap, must not leave a count
  // that nothing on screen leads to. Requests have their banners instead.
  it('lists accepted conversations with something in them that have no tab', () => {
    const [b, c, d, e, f] = ['b', 'c', 'd', 'e', 'f'].map((x) => x.repeat(64));
    const threads = [
      thread({ unread: 2, last_at: 10 }),
      thread({ member_pubkey: b, last_at: 9 }),
      thread({ member_pubkey: c, state: 'declined', last_at: 8 }),
      thread({ member_pubkey: d }),
      thread({ member_pubkey: e, state: 'request', last_at: 7 }),
      thread({ member_pubkey: f, last_at: 6 }),
    ];
    const listed = dmThreadsWithoutTab(threads, [dmTabKey(b), 'aa'.repeat(16)]);
    expect(listed.map((t) => t.member_pubkey)).toEqual([MEMBER.toLowerCase(), f]);
  });

  // A request dropped silently, or a conversation deleted in the other
  // window, must not leave a tab pointing at nothing. A tab on a
  // conversation not started yet has never been listed and stays.
  it('closes the tab of a conversation that is no longer listed', async () => {
    const [gone, fresh] = ['e', 'f'].map((x) => x.repeat(64));
    chatTabs.set([
      { hash: dmTabKey(MEMBER), name: 'Lin' },
      { hash: dmTabKey(gone), name: 'Gone' },
      { hash: dmTabKey(fresh), name: 'New' },
    ]);
    dmThreads.set([thread({}), thread({ member_pubkey: gone, state: 'request' })]);
    vi.mocked(invoke).mockResolvedValueOnce([thread({})]);
    await refreshDmThreads();
    expect(get(chatTabs).map((t) => t.hash)).toEqual([dmTabKey(MEMBER), dmTabKey(fresh)]);
  });

  it('cuts a preview between graphemes', () => {
    const family = '👨‍👩‍👧';
    const flag = '🇫🇷';
    const wave = '👋🏽';
    expect(dmPreview('a'.repeat(139) + family + 'b')).toBe('a'.repeat(139) + family);
    expect(dmPreview('a'.repeat(139) + flag + flag)).toBe('a'.repeat(139) + flag);
    expect(dmPreview(wave.repeat(3), 2)).toBe(wave.repeat(2));
    expect(dmPreview('short')).toBe('short');
  });
});
