import { beforeEach, describe, expect, it } from 'vitest';
import { get } from 'svelte/store';
import {
  forgetChannelIgnores,
  ignoreScopeFor,
  ignoredKeysForChannel,
  ignoredMemberKeys,
  ignoredMembers,
  isMemberIgnored,
  toggleMemberIgnore,
  toggleMemberIgnoreInChannel,
  type IgnoredMember,
} from './channels';

const ALICE = 'aa'.repeat(32);
const BOB = 'bb'.repeat(32);
const ROOM_A = '11'.repeat(16);
const ROOM_B = '22'.repeat(16);

beforeEach(() => {
  ignoredMembers.set([]);
});

describe('ignore scope', () => {
  it('treats an entry with no rooms as ignored everywhere', () => {
    ignoredMembers.set([{ pubkey: ALICE, name: 'Ada' }]);

    expect(isMemberIgnored(get(ignoredMembers), ALICE, ROOM_A)).toBe(true);
    expect(isMemberIgnored(get(ignoredMembers), ALICE, ROOM_B)).toBe(true);
    // No room in hand at all — the notification paths ask this way.
    expect(isMemberIgnored(get(ignoredMembers), ALICE)).toBe(true);
  });

  it('confines a scoped entry to the rooms it names', () => {
    ignoredMembers.set([{ pubkey: ALICE, name: 'Ada', rooms: [ROOM_A] }]);

    expect(isMemberIgnored(get(ignoredMembers), ALICE, ROOM_A)).toBe(true);
    expect(isMemberIgnored(get(ignoredMembers), ALICE, ROOM_B)).toBe(false);
    // The global list drives surfaces that have no room context, so a
    // room-scoped ignore must not silence someone app-wide.
    expect(get(ignoredMemberKeys)).toEqual([]);
  });

  it('hides global and this-room entries together, nothing else', () => {
    const list: IgnoredMember[] = [
      { pubkey: ALICE, name: '' },
      { pubkey: BOB, name: '', rooms: [ROOM_B] },
    ];
    expect(ignoredKeysForChannel(list, ROOM_A)).toEqual([ALICE]);
    expect(ignoredKeysForChannel(list, ROOM_B).sort()).toEqual([ALICE, BOB].sort());
  });
});

describe('toggling', () => {
  it('scopes a fresh ignore to one room', () => {
    toggleMemberIgnoreInChannel(ALICE, ROOM_A, 'Ada');
    expect(get(ignoredMembers)).toEqual([{ pubkey: ALICE, name: 'Ada', rooms: [ROOM_A] }]);
  });

  it('adds a second room rather than replacing the first', () => {
    toggleMemberIgnoreInChannel(ALICE, ROOM_A);
    toggleMemberIgnoreInChannel(ALICE, ROOM_B);
    expect(get(ignoredMembers)[0].rooms).toEqual([ROOM_A, ROOM_B]);
  });

  it('drops the entry when the last room is un-ignored', () => {
    toggleMemberIgnoreInChannel(ALICE, ROOM_A);
    toggleMemberIgnoreInChannel(ALICE, ROOM_A);
    expect(get(ignoredMembers)).toEqual([]);
  });

  it('will not quietly narrow a global ignore to one room', () => {
    toggleMemberIgnore(ALICE, 'Ada');
    toggleMemberIgnoreInChannel(ALICE, ROOM_A);

    // Asking to ignore someone in a room while they are already ignored
    // everywhere is not a request to start reading them elsewhere.
    expect(get(ignoredMembers)).toEqual([{ pubkey: ALICE, name: 'Ada' }]);
    expect(isMemberIgnored(get(ignoredMembers), ALICE, ROOM_B)).toBe(true);
  });

  it('clears a room-scoped entry from the Settings undo', () => {
    toggleMemberIgnoreInChannel(ALICE, ROOM_A);
    // The global toggle is what Settings offers, and it is the only way to
    // reach a scope set in a room the user has since left.
    toggleMemberIgnore(ALICE);
    expect(get(ignoredMembers)).toEqual([]);
  });

  it('reports the scope a member menu has to label', () => {
    toggleMemberIgnoreInChannel(ALICE, ROOM_A);
    toggleMemberIgnore(BOB);
    const list = get(ignoredMembers);

    expect(ignoreScopeFor(list, ALICE, ROOM_A)).toBe('room');
    expect(ignoreScopeFor(list, ALICE, ROOM_B)).toBe('none');
    expect(ignoreScopeFor(list, BOB, ROOM_A)).toBe('global');
    expect(ignoreScopeFor(list, BOB, null)).toBe('global');
  });
});

describe('forgetting a room', () => {
  it('drops that room from scoped entries and leaves global ones alone', () => {
    ignoredMembers.set([
      { pubkey: ALICE, name: '', rooms: [ROOM_A, ROOM_B] },
      { pubkey: BOB, name: '' },
    ]);
    forgetChannelIgnores(ROOM_A);

    expect(get(ignoredMembers)).toEqual([
      { pubkey: ALICE, name: '', rooms: [ROOM_B] },
      { pubkey: BOB, name: '' },
    ]);
  });

  it('removes an entry that named only the forgotten room', () => {
    ignoredMembers.set([{ pubkey: ALICE, name: '', rooms: [ROOM_A] }]);
    forgetChannelIgnores(ROOM_A);
    expect(get(ignoredMembers)).toEqual([]);
  });

  it('hands back the same list when no entry names the room', () => {
    ignoredMembers.set([{ pubkey: BOB, name: '' }]);
    const before = get(ignoredMembers);
    forgetChannelIgnores(ROOM_A);
    expect(get(ignoredMembers)).toBe(before);
  });
});
