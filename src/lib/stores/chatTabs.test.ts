import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import { unreadCounts } from './friends';
import {
  activeChatTab,
  chatDockOpen,
  chatTabs,
  closeTab,
  focusNextUnread,
  getDraft,
  openChat,
  registerDraftFlusher,
  renameTab,
  restoreFriendDrafts,
  retainChatTabs,
  setChatPopout,
  setDraft,
  takeFriendDrafts,
  toggleDock,
  type ChatTabOp,
} from './chatTabs';

const FRIEND = 'aa'.repeat(16);
const OTHER = 'bb'.repeat(16);
const THIRD = 'cc'.repeat(16);
const ROOM_ID = '11'.repeat(16);
/** A room draft key. Rooms are not dock conversations; this prefix exists here
 *  only because `ChatConversation` parks a half-typed room line in the same
 *  draft map. */
const ROOM = `ch:${ROOM_ID}`;

beforeEach(() => {
  chatTabs.set([]);
  activeChatTab.set(null);
  chatDockOpen.set(false);
  unreadCounts.set(new Map());
  setDraft(FRIEND, '');
  setDraft(OTHER, '');
  setDraft(THIRD, '');
  setDraft(ROOM, '');
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

describe('retainChatTabs', () => {
  it('drops tabs for identities that are no longer friends', () => {
    openChat(FRIEND, 'Ada');
    openChat(OTHER, 'Grace');

    retainChatTabs([FRIEND]);

    expect(get(chatTabs).map((t) => t.hash)).toEqual([FRIEND]);
  });

  // The dock is for friends. A previous version let the Channels page pin a
  // room here, so a `ch:` tab can still be sitting in localStorage on the first
  // launch after the change — the friend-list sweep is what clears it, since a
  // room hash can never appear in the friend list.
  it('sweeps a room tab left over from an older version', () => {
    openChat(ROOM, 'Lobby');
    openChat(FRIEND, 'Ada');

    retainChatTabs([FRIEND]);

    expect(get(chatTabs).map((t) => t.hash)).toEqual([FRIEND]);
  });

  it('collapses the dock when nothing is left to show', () => {
    openChat(FRIEND, 'Ada');
    expect(get(chatDockOpen)).toBe(true);

    retainChatTabs([]);

    expect(get(chatTabs)).toEqual([]);
    expect(get(activeChatTab)).toBeNull();
    expect(get(chatDockOpen)).toBe(false);
  });

  it('moves the selection off a tab it closes', () => {
    openChat(FRIEND, 'Ada');
    openChat(OTHER, 'Grace');
    expect(get(activeChatTab)).toBe(OTHER);

    retainChatTabs([FRIEND]);

    expect(get(activeChatTab)).toBe(FRIEND);
  });

  it('leaves an untouched list alone', () => {
    openChat(FRIEND, 'Ada');
    const before = get(chatTabs);

    retainChatTabs([FRIEND, OTHER]);

    expect(get(chatTabs)).toBe(before);
  });
});

// The dock shows one conversation at a time, so the header's "unread elsewhere"
// count has to be able to take you to the conversation it is counting.
describe('focusNextUnread', () => {
  it('goes to the one conversation with unread messages', () => {
    openChat(FRIEND, 'Ada');
    openChat(OTHER, 'Grace');
    activeChatTab.set(FRIEND);
    unreadCounts.set(new Map([[OTHER, 2]]));

    expect(focusNextUnread()).toBe(true);
    expect(get(activeChatTab)).toBe(OTHER);
  });

  it('walks every unread conversation instead of sticking on the first', () => {
    openChat(FRIEND, 'Ada');
    openChat(OTHER, 'Grace');
    openChat(THIRD, 'Alan');
    activeChatTab.set(FRIEND);
    unreadCounts.set(
      new Map([
        [OTHER, 1],
        [THIRD, 1],
      ]),
    );

    expect(focusNextUnread()).toBe(true);
    expect(get(activeChatTab)).toBe(OTHER);
    expect(focusNextUnread()).toBe(true);
    expect(get(activeChatTab)).toBe(THIRD);
    // And wraps, rather than reporting nothing left.
    expect(focusNextUnread()).toBe(true);
    expect(get(activeChatTab)).toBe(OTHER);
  });

  it('considers the first tab when nothing is active yet', () => {
    openChat(FRIEND, 'Ada');
    openChat(OTHER, 'Grace');
    activeChatTab.set(null);
    unreadCounts.set(new Map([[FRIEND, 3]]));

    expect(focusNextUnread()).toBe(true);
    expect(get(activeChatTab)).toBe(FRIEND);
  });

  it('reports nothing to go to when everything is read', () => {
    openChat(FRIEND, 'Ada');
    activeChatTab.set(FRIEND);

    expect(focusNextUnread()).toBe(false);
    expect(get(activeChatTab)).toBe(FRIEND);
  });

  it('reveals the dock when it was closed', () => {
    openChat(FRIEND, 'Ada');
    openChat(OTHER, 'Grace');
    activeChatTab.set(FRIEND);
    unreadCounts.set(new Map([[OTHER, 1]]));
    chatDockOpen.set(false);

    expect(focusNextUnread()).toBe(true);
    expect(get(chatDockOpen)).toBe(true);
  });
});

describe('while the chat is popped out', () => {
  let forwarded: ChatTabOp[];
  let reveals: number;
  const store = new Map<string, string>();

  beforeEach(() => {
    store.clear();
    vi.stubGlobal('localStorage', {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
      removeItem: (k: string) => void store.delete(k),
    });
    forwarded = [];
    reveals = 0;
    setChatPopout({
      forward: (op) => forwarded.push(op),
      reveal: () => {
        reveals += 1;
      },
    });
  });

  afterEach(() => {
    setChatPopout(null);
    vi.unstubAllGlobals();
  });

  it('forwards an opened chat to the chat window instead of opening the dock', () => {
    openChat(FRIEND, 'Ada');
    expect(forwarded).toEqual([{ kind: 'open', hash: FRIEND, name: 'Ada' }]);
    expect(reveals).toBe(1);
    expect(get(chatDockOpen)).toBe(false);
  });

  it('builds on the tabs the chat window saved, not on its own stale copy', () => {
    chatTabs.set([{ hash: OTHER, name: 'Grace' }]);
    // The chat window closed Grace and opened a third friend meanwhile.
    store.set('ember.chatTabs.v1', JSON.stringify({ tabs: [{ hash: THIRD, name: 'Lin' }], activeHash: THIRD }));

    openChat(FRIEND, 'Ada');

    expect(get(chatTabs).map((t) => t.hash)).toEqual([THIRD, FRIEND]);
    expect(get(activeChatTab)).toBe(FRIEND);
  });

  it('shows the chat window when the chats toggle is used', () => {
    toggleDock();
    expect(reveals).toBe(1);
    expect(get(chatDockOpen)).toBe(false);
  });

  it('forwards renames and closes', () => {
    openChat(FRIEND, 'Ada');
    renameTab(FRIEND, 'Ada L.');
    closeTab(FRIEND);
    expect(forwarded.slice(1)).toEqual([
      { kind: 'rename', hash: FRIEND, name: 'Ada L.' },
      { kind: 'close', hash: FRIEND },
    ]);
  });
});

describe('draft handoff between windows', () => {
  it('flushes the open conversation before handing drafts over', () => {
    openChat(FRIEND, 'Ada');
    let typed = 'half a thought';
    const unregister = registerDraftFlusher(() => setDraft(FRIEND, typed));

    expect(takeFriendDrafts()).toEqual({ [FRIEND]: 'half a thought' });
    typed = 'the whole thought';
    expect(takeFriendDrafts()).toEqual({ [FRIEND]: 'the whole thought' });
    unregister();
  });

  it('leaves room drafts out of the handoff', () => {
    setDraft(ROOM, 'room line');
    expect(takeFriendDrafts()).toEqual({});
  });

  it('restores drafts only for tabs that are open', () => {
    openChat(FRIEND, 'Ada');
    restoreFriendDrafts({ [FRIEND]: 'kept', [OTHER]: 'no tab' });
    expect(getDraft(FRIEND)).toBe('kept');
    expect(getDraft(OTHER)).toBe('');
  });
});
