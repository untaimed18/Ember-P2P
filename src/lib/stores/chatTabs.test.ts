import { beforeEach, describe, expect, it } from 'vitest';
import { get } from 'svelte/store';
import {
  activeChatTab,
  chatDockOpen,
  chatTabs,
  closeTab,
  getDraft,
  isRoomTab,
  openChat,
  retainChatTabs,
  retainRoomTabs,
  roomTabChannelId,
  roomTabKey,
  setDraft,
} from './chatTabs';

const FRIEND = 'aa'.repeat(16);
const ROOM_ID = '11'.repeat(16);
const ROOM = `ch:${ROOM_ID}`;
const OTHER_ROOM_ID = '22'.repeat(16);

beforeEach(() => {
  chatTabs.set([]);
  activeChatTab.set(null);
  chatDockOpen.set(false);
  setDraft(FRIEND, '');
  setDraft(ROOM, '');
  setDraft(roomTabKey(ROOM_ID), '');
});

describe('setDraft', () => {
  it('keeps a channel draft even when no friend tab is open', () => {
    setDraft(ROOM, 'hello room');
    expect(getDraft(ROOM)).toBe('hello room');
  });

  it('drops a friend draft when that tab is not open', () => {
    setDraft(FRIEND, 'hello');
    expect(getDraft(FRIEND)).toBe('');
  });

  it('keeps a friend draft only while its tab is open', () => {
    openChat(FRIEND, 'Ada');
    setDraft(FRIEND, 'hello');
    expect(getDraft(FRIEND)).toBe('hello');
    closeTab(FRIEND);
    expect(getDraft(FRIEND)).toBe('');
  });

  it('does not resurrect a friend draft after closeTab', () => {
    openChat(FRIEND, 'Ada');
    setDraft(FRIEND, 'hello');
    closeTab(FRIEND);
    setDraft(FRIEND, 'hello');
    expect(getDraft(FRIEND)).toBe('');
  });
});

// A room tab's hash is its conversation key, so the two cannot drift — but
// that also means every helper keyed on "is this a friend" has to say so.
describe('room tabs', () => {
  it('round-trips a channel id through its tab key', () => {
    const key = roomTabKey(ROOM_ID.toUpperCase());
    expect(isRoomTab(key)).toBe(true);
    expect(roomTabChannelId(key)).toBe(ROOM_ID);
    expect(isRoomTab(FRIEND)).toBe(false);
    expect(roomTabChannelId(FRIEND)).toBeNull();
  });

  it('survives the friend-list reconcile', () => {
    openChat(roomTabKey(ROOM_ID), 'Lobby');
    openChat(FRIEND, 'Ada');

    // `retainChatTabs` is handed the friend list, which says nothing about
    // rooms — filtering room tabs on it would close them all at startup.
    retainChatTabs([FRIEND]);
    expect(get(chatTabs).map((t) => t.hash)).toEqual([roomTabKey(ROOM_ID), FRIEND]);

    retainChatTabs([]);
    expect(get(chatTabs).map((t) => t.hash)).toEqual([roomTabKey(ROOM_ID)]);
  });

  it('closes a tab for a room this device has left', () => {
    openChat(roomTabKey(ROOM_ID), 'Lobby');
    openChat(FRIEND, 'Ada');
    setDraft(roomTabKey(ROOM_ID), 'half a sentence');

    retainRoomTabs([OTHER_ROOM_ID]);

    expect(get(chatTabs).map((t) => t.hash)).toEqual([FRIEND]);
    // The draft goes with it, or it would haunt the room on a later rejoin.
    expect(getDraft(roomTabKey(ROOM_ID))).toBe('');
  });

  it('leaves friend tabs alone when sweeping rooms', () => {
    openChat(FRIEND, 'Ada');
    const before = get(chatTabs);
    retainRoomTabs([]);
    expect(get(chatTabs)).toBe(before);
  });

  it('moves the selection off a room tab it closes', () => {
    openChat(FRIEND, 'Ada');
    openChat(roomTabKey(ROOM_ID), 'Lobby');
    expect(get(activeChatTab)).toBe(roomTabKey(ROOM_ID));

    retainRoomTabs([]);
    expect(get(activeChatTab)).toBe(FRIEND);
  });
});
