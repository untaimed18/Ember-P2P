import { beforeEach, describe, expect, it } from 'vitest';
import { get } from 'svelte/store';
import {
  beginFriendsListFetch,
  cleanupFriendsStore,
  commitFriendsList,
  forgetFriendName,
  friendLabel,
  friendNames,
  friendsList,
  patchFriendsList,
} from './friends';
import type { FriendInfo } from '$lib/api/friends';

function friend(userHash: string, nickname = ''): FriendInfo {
  return {
    user_hash: userHash,
    nickname,
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

  it('starts clean after a teardown so a stale ticket cannot win', () => {
    const stale = beginFriendsListFetch();
    cleanupFriendsStore();

    const fresh = beginFriendsListFetch();
    expect(commitFriendsList(fresh, [friend(A)])).toBe(true);
    expect(commitFriendsList(stale, [friend(B)])).toBe(false);
    expect(get(friendsList).map((f) => f.user_hash)).toEqual([A]);
  });

  it('refuses a fetch from before a teardown even when it lands first', () => {
    const stale = beginFriendsListFetch();
    cleanupFriendsStore();

    expect(commitFriendsList(stale, [friend(B)])).toBe(false);
    expect(get(friendsList)).toEqual([]);
    expect(commitFriendsList(beginFriendsListFetch(), [friend(A)])).toBe(true);
  });

  it('keeps a local edit over a fetch that was already in flight', () => {
    commitFriendsList(beginFriendsListFetch(), [friend(A, 'Old')]);
    const inFlight = beginFriendsListFetch();

    patchFriendsList((list) => list.map((f) => ({ ...f, nickname: 'New' })));
    expect(commitFriendsList(inFlight, [friend(A, 'Old')])).toBe(false);
    expect(get(friendsList)[0].nickname).toBe('New');
    expect(get(friendNames).get(A)).toBe('New');

    expect(commitFriendsList(beginFriendsListFetch(), [friend(A, 'Saved')])).toBe(true);
    expect(get(friendNames).get(A)).toBe('Saved');
  });
});

describe('friend name cache', () => {
  it('follows the list, so a removed friend stops making a namesake ambiguous', () => {
    commitFriendsList(beginFriendsListFetch(), [friend(A, 'Bob'), friend(B, 'Bob')]);
    expect(friendLabel(A, null, get(friendNames))).toBe(`Bob (${A.slice(0, 8)}\u2026)`);

    commitFriendsList(beginFriendsListFetch(), [friend(A, 'Bob')]);
    expect([...get(friendNames).keys()]).toEqual([A]);
    expect(friendLabel(A, null, get(friendNames))).toBe('Bob');
  });

  it('drops a name that was cleared in the list', () => {
    commitFriendsList(beginFriendsListFetch(), [friend(A, 'Ana')]);
    commitFriendsList(beginFriendsListFetch(), [friend(A, '')]);
    expect(get(friendNames).has(A)).toBe(false);
  });

  it('forgets one friend on request', () => {
    commitFriendsList(beginFriendsListFetch(), [friend(A, 'Ana'), friend(B, 'Bea')]);
    forgetFriendName(A.toUpperCase());
    expect([...get(friendNames).keys()]).toEqual([B]);
  });
});
