import { derived, get, writable } from 'svelte/store';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import {
  listRoomDmThreads,
  ROOM_DM_MESSAGE_EVENT,
  ROOM_DM_STATUS_EVENT,
  ROOM_DM_THREAD_EVENT,
  type RoomDmMessageEvent,
  type RoomDmThread,
} from '$lib/api/roomDm';
import { activeChatTab, addChatTab, chatDockOpen, openChat } from '$lib/stores/chatTabs';
import { notify } from '$lib/notifications';
import { isAppVisible } from '$lib/utils';
import { chatWindowShows, isChatWindow } from '$lib/windowRole';
import * as m from '$lib/paraglide/messages';

/**
 * Private conversations with room members.
 *
 * Each one is a tab in the chat dock, keyed `dm:<member key>` so it can never
 * be taken for a friend's (a friend is keyed by their 32-character hash, a
 * member by a 64-character key, and the prefix says so outright).
 */
export const DM_TAB_PREFIX = 'dm:';

export function dmTabKey(member: string): string {
  return `${DM_TAB_PREFIX}${member.toLowerCase()}`;
}

/** The member a dock tab is with, or null for a friend's tab. */
export function dmMemberOf(tabKey: string | null | undefined): string | null {
  return tabKey?.startsWith(DM_TAB_PREFIX) ? tabKey.slice(DM_TAB_PREFIX.length) : null;
}

export const dmThreads = writable<RoomDmThread[]>([]);

/** Unread per dock tab, for conversations the user has taken up: a request
 *  shows as a request, not as unread. */
export const dmUnread = derived(dmThreads, (threads) => {
  const out = new Map<string, number>();
  for (const thread of threads) {
    if (thread.state === 'open' && thread.unread > 0) out.set(dmTabKey(thread.member_pubkey), thread.unread);
  }
  return out;
});

/** Conversations someone started that wait on the user's answer. */
export const dmRequests = derived(dmThreads, (threads) => threads.filter((t) => t.state === 'request'));

let refreshSeq = 0;

export async function refreshDmThreads(): Promise<void> {
  const seq = ++refreshSeq;
  try {
    const threads = await listRoomDmThreads();
    if (seq === refreshSeq) dmThreads.set(threads);
  } catch (e) {
    console.warn('roomDm: could not read private conversations', e);
  }
}

/** Open a private conversation with a member in the dock. */
export function openPrivateChat(member: string, name: string): void {
  openChat(dmTabKey(member), name);
}

/** Whether the user is looking at this conversation now: in the dock, in
 *  the chat window when this is it, or, from the main window, in a chat
 *  window that says it shows it. */
export function viewingDm(member: string): boolean {
  const key = dmTabKey(member);
  if (isChatWindow()) return get(activeChatTab) === key && isAppVisible();
  if (chatWindowShows(key)) return true;
  return get(chatDockOpen) && get(activeChatTab) === key && isAppVisible();
}

/** A tab for a conversation that has something to read, so its unread count
 *  can be found from the dock. From the main window only: it forwards the
 *  tab to a chat window that is popped out. */
export function keepDmTab(member: string, name: string): void {
  if (isChatWindow()) return;
  addChatTab(dmTabKey(member), name);
}

let unlisteners: UnlistenFn[] = [];
let initialized = false;
let epoch = 0;

export async function initRoomDmStore(): Promise<void> {
  if (initialized) return;
  initialized = true;
  const mine = ++epoch;
  const registered: UnlistenFn[] = [];
  try {
    registered.push(
      await listen<RoomDmMessageEvent>(ROOM_DM_MESSAGE_EVENT, (event) => {
        const msg = event.payload;
        void refreshDmThreads();
        const name = msg.name?.trim() || m.channels_dm_someone();
        if (!msg.request) keepDmTab(msg.member_pubkey, msg.name?.trim() ?? '');
        if (viewingDm(msg.member_pubkey)) return;
        if (msg.request) {
          if (msg.new_thread) void notify('friend_message', m.channels_dm_request_notify({ name }), msg.text.slice(0, 140));
          return;
        }
        void notify('friend_message', m.channels_dm_notify_title({ name }), msg.text.slice(0, 140));
      }),
    );
    registered.push(await listen(ROOM_DM_STATUS_EVENT, () => void refreshDmThreads()));
    registered.push(await listen(ROOM_DM_THREAD_EVENT, () => void refreshDmThreads()));
  } catch (e) {
    for (const fn of registered) fn();
    initialized = false;
    throw e;
  }
  if (mine !== epoch) {
    for (const fn of registered) fn();
    return;
  }
  unlisteners = registered;
  await refreshDmThreads();
}

export function cleanupRoomDmStore(): void {
  epoch++;
  for (const fn of unlisteners) fn();
  unlisteners = [];
  initialized = false;
  refreshSeq++;
  dmThreads.set([]);
}
