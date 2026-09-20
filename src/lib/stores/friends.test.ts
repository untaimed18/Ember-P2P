import { beforeEach, describe, expect, it } from 'vitest';
import { get } from 'svelte/store';
import {
  beginFriendsListFetch,
  cleanupFriendsStore,
  commitFriendsList,
  friendsList,
  setFriendsList,
} from './friends';
import type { FriendInfo } from '$lib/api/friends';

function friend(userHash: string): FriendInfo {
  return {
    user_hash: userHash,
    nickname: '',
    added_at: 0,
    last_ip: '',
    last_port: 0,
    last_seen: 0,
    mutual: true,
  };
}

const A = 'aa'.repeat(16);
const B = 'bb'.repeat(16);

beforeEach(() => {
  cleanupFriendsStore();
});

// Three surfaces fetch this list — the Friends page, the Transfers table, and
// the confirm-event refresh — so "last write wins" would let whichever call
// was slowest decide, putting back a row the user had just removed.
describe('shared friends list ordering', () => {
  it('drops a fetch that a newer one already superseded', () => {
    const slow = beginFriendsListFetch();
    const fast = beginFriendsListFetch();

    expect(commitFriendsList(fast, [friend(B)])).toBe(true);
    expect(commitFriendsList(slow, [friend(A)])).toBe(false);
    expect(get(friendsList).map((f) => f.user_hash)).toEqual([B]);
  });

  it('takes a fetch that finishes in order', () => {
    const first = beginFriendsListFetch();
    expect(commitFriendsList(first, [friend(A)])).toBe(true);

    const second = beginFriendsListFetch();
    expect(commitFriendsList(second, [friend(B)])).toBe(true);
    expect(get(friendsList).map((f) => f.user_hash)).toEqual([B]);
  });

  it('lets an authoritative write supersede a fetch still in flight', () => {
    const inFlight = beginFriendsListFetch();
    setFriendsList([friend(A)]);

    expect(commitFriendsList(inFlight, [friend(B)])).toBe(false);
    expect(get(friendsList).map((f) => f.user_hash)).toEqual([A]);
  });

  it('starts clean after a teardown so a stale ticket cannot win', () => {
    const stale = beginFriendsListFetch();
    cleanupFriendsStore();

    const fresh = beginFriendsListFetch();
    expect(commitFriendsList(fresh, [friend(A)])).toBe(true);
    expect(commitFriendsList(stale, [friend(B)])).toBe(false);
    expect(get(friendsList).map((f) => f.user_hash)).toEqual([A]);
  });
});
