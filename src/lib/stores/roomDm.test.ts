import { describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(async () => () => {}) }));

const { dmMemberOf, dmRequests, dmTabKey, dmThreads, dmUnread } = await import('./roomDm');
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
});
