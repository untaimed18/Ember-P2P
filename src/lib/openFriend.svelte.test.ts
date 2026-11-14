import { afterEach, describe, expect, it } from 'vitest';
import { flushSync } from 'svelte';
import type { FriendInfo } from '$lib/api/friends';
import { OpenFriend } from './openFriend.svelte';

const friend = (user_hash: string, nickname: string) => ({ user_hash, nickname }) as FriendInfo;

let cleanups: (() => void)[] = [];
afterEach(() => {
  for (const cleanup of cleanups) cleanup();
  cleanups = [];
});

/** An `OpenFriend` over a list the test can replace, as the store does. */
function mount(initial: FriendInfo[]) {
  let list = $state.raw(initial);
  let open: OpenFriend | undefined;
  cleanups.push($effect.root(() => {
    open = new OpenFriend(() => list);
  }));
  flushSync();
  if (!open) throw new Error('the effect root did not run');
  return {
    open,
    setList(next: FriendInfo[]) {
      list = next;
      flushSync();
    },
  };
}

describe('OpenFriend', () => {
  it('opens on a friend from the list and stays there', () => {
    const ann = friend('a'.repeat(32), 'Ann');
    const { open } = mount([ann]);
    open.current = ann;
    flushSync();
    expect(open.current).toBe(ann);
  });

  it("takes the list's newer copy of the friend", () => {
    const ann = friend('a'.repeat(32), 'Ann');
    const { open, setList } = mount([ann]);
    open.current = ann;
    flushSync();

    const renamed = friend(ann.user_hash, 'Annie');
    setList([renamed]);
    expect(open.current).toBe(renamed);
  });

  it('gives a copy of its own back to the one the list holds', () => {
    const ann = friend('a'.repeat(32), 'Ann');
    const { open } = mount([ann]);
    open.current = { ...ann, nickname: 'Annie' };
    flushSync();
    expect(open.current).toBe(ann);
  });

  it('closes when the friend leaves the list', () => {
    const ann = friend('a'.repeat(32), 'Ann');
    const bob = friend('b'.repeat(32), 'Bob');
    const { open, setList } = mount([ann, bob]);
    open.current = ann;
    flushSync();

    setList([bob]);
    expect(open.current).toBeNull();
  });
});
