import { derived, get, writable, type Readable } from 'svelte/store';
import { emit, listen, type UnlistenFn } from '@tauri-apps/api/event';
import {
  answerRoomDmRequest,
  dropRoomDmRequest,
  listRoomDmThreads,
  ROOM_DM_MESSAGE_EVENT,
  ROOM_DM_STATUS_EVENT,
  ROOM_DM_THREAD_EVENT,
  type RoomDmMessageEvent,
  type RoomDmThread,
} from '$lib/api/roomDm';
import { activeChatTab, addChatTab, chatDockOpen, closeTab, openChat } from '$lib/stores/chatTabs';
import { ignoreMemberEverywhere, pushIgnoredNow } from '$lib/stores/channels';
import { addActionToast, removeToast, toastError } from '$lib/stores/toast';
import { notify } from '$lib/notifications';
import { translateError } from '$lib/i18n';
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

export type HeldDmAnswer = 'decline' | 'ignore';

/** Answers given in this window and still behind their Undo, by member. */
const heldHere = writable<ReadonlyMap<string, HeldDmAnswer>>(new Map());
/** Chat window only: what the main window says it is holding. */
const heldByMain = writable<ReadonlyMap<string, HeldDmAnswer>>(new Map());

/** Requests declined or ignored while the Undo is still on offer, by member:
 *  answered as far as anything on screen goes, though nothing is sent yet. */
export const dmAnswersHeld: Readable<ReadonlyMap<string, HeldDmAnswer>> = derived(
  [heldHere, heldByMain],
  ([here, main]) => (main.size === 0 ? here : here.size === 0 ? main : new Map([...main, ...here])),
);

/** Conversations someone started that wait on the user's answer. One whose
 *  answer is held behind an Undo is answered already. */
export const dmRequests = derived([dmThreads, dmAnswersHeld], ([threads, held]) =>
  threads.filter((t) => t.state === 'request' && !held.has(t.member_pubkey.toLowerCase())),
);

/** Accepted conversations with something in them and no dock tab, newest
 *  first: the dock lists them so one whose tab was closed, or never fitted,
 *  can be reached again with its unread count. A request is answered from
 *  its banner on the Channels page, and a declined one holds nothing. */
export function dmThreadsWithoutTab(threads: RoomDmThread[], tabKeys: Iterable<string>): RoomDmThread[] {
  const open = new Set(tabKeys);
  return threads.filter(
    (t) => t.state === 'open' && (t.last_at > 0 || t.unread > 0) && !open.has(dmTabKey(t.member_pubkey)),
  );
}

const graphemes: Intl.Segmenter | null =
  typeof Intl !== 'undefined' && 'Segmenter' in Intl ? new Intl.Segmenter(undefined, { granularity: 'grapheme' }) : null;

/** The start of a message for a notification or a preview, at most `max`
 *  characters as a reader counts them, so a family, flag or skin-toned emoji
 *  is kept whole or left out. Without `Intl.Segmenter`, cut by code point. */
export function dmPreview(text: string, max = 140): string {
  if (!graphemes) return Array.from(text).slice(0, max).join('');
  let out = '';
  let count = 0;
  for (const { segment } of graphemes.segment(text)) {
    if (count === max) break;
    out += segment;
    count++;
  }
  return out;
}

/** Close the dock tab of a conversation that is gone. */
export function closeDmTab(member: string): void {
  closeTab(dmTabKey(member));
}

let refreshSeq = 0;

export async function refreshDmThreads(): Promise<void> {
  const seq = ++refreshSeq;
  try {
    const threads = await listRoomDmThreads();
    if (seq !== refreshSeq) return;
    // A tab can be open on a conversation not started yet, so only one that
    // was listed and no longer is counts as gone: dropped, or deleted from
    // the other window.
    const listed = new Set(threads.map((t) => t.member_pubkey.toLowerCase()));
    const gone = get(dmThreads).filter((t) => !listed.has(t.member_pubkey.toLowerCase()));
    dmThreads.set(threads);
    for (const thread of gone) closeDmTab(thread.member_pubkey);
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

/** Ignore everywhere, and remove any request of theirs without a word to
 *  them: a decline would tell them they were refused, where silence looks
 *  like being offline. The request goes only once the backend holds the
 *  ignore, so nothing they send meanwhile opens a new one; if the ignore
 *  could not be saved, the request stays. */
export async function ignoreDmMemberSilently(member: string, name: string): Promise<void> {
  const key = member.toLowerCase();
  const hadRequest = get(dmThreads).some((t) => t.member_pubkey === key && t.state === 'request');
  ignoreMemberEverywhere(key, name);
  try {
    await pushIgnoredNow();
    await dropRoomDmRequest(key);
    if (hadRequest) closeDmTab(key);
  } catch (e) {
    toastError(translateError(e, m.error_operation_failed()));
  } finally {
    void refreshDmThreads();
  }
}

// ── Answers held behind an Undo ──────────────────────────────────────────
//
// A Decline drops what they wrote and an Ignore stops everything they send,
// so neither goes out until its Undo toast does. The main window holds every
// answer: it is the window that commits Undo toasts before Ember exits, and
// the one a reload or the backend's quit path is wired to. A Decline in the
// chat window is handed over to it; the chat window's own toast only drives
// the main window's (`ember-ui:*` events, as in `chatPopout.ts`).

const HOLD_MS = 8000;
/** The main window's copy of an answer given in the chat window. That
 *  window's toast settles it, and stops counting while it is hovered, so
 *  this only covers that window never saying. */
const HOLD_FOR_CHAT_MS = 60_000;
/** Answers held in the main window, so one a reload interrupts is still
 *  sent: a reload runs no toast's expiry. Per session, like the toasts. */
const HELD_KEY = 'ember.roomDm.held.v1';

/** Chat window → main window: hold this Decline. */
const HOLD_EVENT = 'ember-ui:dm-hold';
/** Chat window → main window: undo the answer held (`commit: false`), or
 *  send it now (`commit: true`). */
const UNHOLD_EVENT = 'ember-ui:dm-unhold';
/** Main window → chat window: every answer it holds. */
const HELD_EVENT = 'ember-ui:dm-held';
/** Chat window → main window: say what you hold. */
const HELD_ASK_EVENT = 'ember-ui:dm-held-ask';
/** Emitted by the backend when the chat window is destroyed. */
const CHAT_CLOSED_EVENT = 'ember:chat-window-closed';

const MEMBER_RE = /^[0-9a-f]{64}$/;

interface HeldEntry {
  kind: HeldDmAnswer;
  /** As given, for the ignore list; the toast falls back for an empty one. */
  name: string;
  toastId: number | null;
  /** Taken back without a word: accepted meanwhile, or settled elsewhere. */
  dropped: boolean;
  /** Main window: held for the chat window, whose toast settles it. */
  forChat: boolean;
  /** Chat window: the main window has said it holds this one. */
  taken: boolean;
}

const held = new Map<string, HeldEntry>();

function memberKey(raw: unknown): string | null {
  return typeof raw === 'string' && MEMBER_RE.test(raw.toLowerCase()) ? raw.toLowerCase() : null;
}

function heldKind(raw: unknown): HeldDmAnswer | null {
  return raw === 'decline' || raw === 'ignore' ? raw : null;
}

function heldMessage(kind: HeldDmAnswer, name: string): string {
  const shown = name.trim() || m.channels_dm_someone();
  return kind === 'decline' ? m.channels_dm_declined_toast({ name: shown }) : m.channels_dm_ignoring_toast({ name: shown });
}

function heldRows(): Array<{ member: string; kind: HeldDmAnswer; name: string }> {
  return [...held].map(([member, entry]) => ({ member, kind: entry.kind, name: entry.name }));
}

function broadcastHeld() {
  void emit(HELD_EVENT, { held: heldRows().map(({ member, kind }) => ({ member, kind })) }).catch(() => {});
}

function publishHeld() {
  heldHere.set(new Map([...held].map(([member, entry]) => [member, entry.kind])));
  if (isChatWindow()) return;
  broadcastHeld();
  try {
    const rows = heldRows();
    if (rows.length > 0) sessionStorage.setItem(HELD_KEY, JSON.stringify(rows));
    else sessionStorage.removeItem(HELD_KEY);
  } catch {
    // Without storage a reload in the Undo window loses the answer, which
    // leaves the request standing.
  }
}

function letGo(key: string, entry: HeldEntry) {
  if (held.get(key) !== entry) return;
  held.delete(key);
  publishHeld();
}

/** Whether a held answer still has something to answer. A Decline needs
 *  the request still waiting; an Ignore is about the person, so only an
 *  Accept since then stops it. Unreadable, the answer goes: the backend
 *  declines only a request that is still waiting. */
async function stillToAnswer(key: string, kind: HeldDmAnswer): Promise<boolean> {
  let threads: RoomDmThread[];
  try {
    threads = await listRoomDmThreads();
  } catch {
    return true;
  }
  const state = threads.find((t) => t.member_pubkey.toLowerCase() === key)?.state;
  return kind === 'decline' ? state === 'request' : state !== 'open';
}

async function sendHeld(key: string, entry: HeldEntry) {
  if (entry.kind === 'ignore') {
    await ignoreDmMemberSilently(key, entry.name);
    return;
  }
  try {
    await answerRoomDmRequest(key, false);
  } catch (e) {
    toastError(translateError(e, m.error_operation_failed()));
  }
}

/** The toast went without its Undo: send the answer, unless it was taken
 *  back or answered otherwise meanwhile. Hidden until the threads say how
 *  it ended, so the request does not flash back first. */
async function settleHeld(key: string, entry: HeldEntry) {
  try {
    if (entry.dropped || !(await stillToAnswer(key, entry.kind)) || entry.dropped) return;
    await sendHeld(key, entry);
  } finally {
    await refreshDmThreads();
    letGo(key, entry);
  }
}

/** Main window: hold an answer behind an Undo toast. */
function holdHere(key: string, kind: HeldDmAnswer, name: string, forChat: boolean) {
  if (held.has(key)) {
    // The chat window asking for one held here already: tell it so.
    if (forChat) broadcastHeld();
    return;
  }
  const entry: HeldEntry = { kind, name, toastId: null, dropped: false, forChat, taken: true };
  held.set(key, entry);
  publishHeld();
  entry.toastId = addActionToast(
    'info',
    heldMessage(kind, name),
    { label: m.common_undo(), undo: true, run: () => letGo(key, entry) },
    () => settleHeld(key, entry),
    forChat ? HOLD_FOR_CHAT_MS : HOLD_MS,
  );
}

/** Chat window: hand a Decline to the main window, with the Undo here. */
function holdInMain(key: string, name: string) {
  if (held.has(key) || get(heldByMain).has(key)) return;
  const entry: HeldEntry = { kind: 'decline', name, toastId: null, dropped: false, forChat: false, taken: false };
  held.set(key, entry);
  publishHeld();
  void emit(HOLD_EVENT, { member: key, name }).catch(() => {});
  entry.toastId = addActionToast(
    'info',
    heldMessage('decline', name),
    {
      label: m.common_undo(),
      undo: true,
      run: () => {
        letGo(key, entry);
        void emit(UNHOLD_EVENT, { member: key, commit: false }).catch(() => {});
      },
    },
    async () => {
      if (entry.dropped) {
        letGo(key, entry);
      } else if (entry.taken) {
        // Still hidden through `heldByMain` until the main window is done.
        void emit(UNHOLD_EVENT, { member: key, commit: true }).catch(() => {});
        letGo(key, entry);
      } else {
        // The main window never took it up: answer from here.
        await settleHeld(key, entry);
      }
    },
  );
}

/** Close a held answer's toast with nothing sent. */
function closeHeld(key: string, entry: HeldEntry) {
  entry.dropped = true;
  letGo(key, entry);
  if (entry.toastId !== null) removeToast(entry.toastId);
}

/** Take a held answer back without a word, here or in the main window. */
function dropHeld(key: string) {
  const entry = held.get(key);
  if (entry) closeHeld(key, entry);
  if (isChatWindow() && (entry || get(heldByMain).has(key))) {
    void emit(UNHOLD_EVENT, { member: key, commit: false }).catch(() => {});
  }
}

/** Decline a request behind an Undo: it is hidden at once and answered when
 *  the toast goes. `name` is only for the toast. */
export function declineDmRequest(member: string, name: string): void {
  const key = member.toLowerCase();
  if (isChatWindow()) holdInMain(key, name);
  else holdHere(key, 'decline', name, false);
}

/** Ignore a requester everywhere behind an Undo, as {@link declineDmRequest}
 *  declines. `name` goes on the ignore list as given. */
export function ignoreDmRequester(member: string, name: string): void {
  holdHere(member.toLowerCase(), 'ignore', name, false);
}

/** The request is being accepted: a Decline or Ignore held for it is taken
 *  back without a word, wherever it was given. */
export function cancelHeldDmAnswer(member: string): void {
  dropHeld(member.toLowerCase());
}

/** Main window: what the chat window asks of the answers held. */
async function listenAsMain(registered: UnlistenFn[]): Promise<void> {
  registered.push(
    await listen<{ member?: unknown; name?: unknown }>(HOLD_EVENT, async (event) => {
      const key = memberKey(event.payload?.member);
      const name = typeof event.payload?.name === 'string' ? event.payload.name.slice(0, 256) : '';
      if (!key) return;
      // A hand-over that arrives late, after the chat window answered from
      // there itself, must not raise a second Undo for a settled request.
      if (!held.has(key) && !(await stillToAnswer(key, 'decline'))) return;
      holdHere(key, 'decline', name, true);
    }),
  );
  registered.push(
    await listen<{ member?: unknown; commit?: unknown }>(UNHOLD_EVENT, (event) => {
      const key = memberKey(event.payload?.member);
      const entry = key ? held.get(key) : undefined;
      if (!key || !entry) return;
      if (event.payload?.commit !== true) dropHeld(key);
      else if (entry.forChat && entry.toastId !== null) removeToast(entry.toastId);
    }),
  );
  registered.push(await listen(HELD_ASK_EVENT, () => broadcastHeld()));
  registered.push(
    // Its toast is gone with it, which is the toast going without its Undo.
    await listen(CHAT_CLOSED_EVENT, () => {
      for (const entry of [...held.values()]) {
        if (entry.forChat && entry.toastId !== null) removeToast(entry.toastId);
      }
    }),
  );
}

let heldSeq = 0;

/** Chat window: follow what the main window holds. */
async function listenAsChat(registered: UnlistenFn[]): Promise<void> {
  const fn = await listen<{ held?: unknown }>(HELD_EVENT, async (event) => {
    const seq = ++heldSeq;
    const next = new Map<string, HeldDmAnswer>();
    const rows = Array.isArray(event.payload?.held) ? event.payload.held : [];
    for (const row of rows as Array<{ member?: unknown; kind?: unknown }>) {
      const key = memberKey(row?.member);
      const kind = heldKind(row?.kind);
      if (key && kind) next.set(key, kind);
    }
    let settled = false;
    for (const key of get(heldByMain).keys()) {
      if (next.has(key)) continue;
      settled = true;
      // Undone or sent over there: this toast has nothing left to offer.
      const entry = held.get(key);
      if (entry?.taken) closeHeld(key, entry);
    }
    for (const key of next.keys()) {
      const entry = held.get(key);
      if (entry) entry.taken = true;
    }
    // Hidden until the threads here say how it ended.
    if (settled) await refreshDmThreads();
    if (seq === heldSeq) heldByMain.set(next);
  });
  registered.push(fn);
  void emit(HELD_ASK_EVENT).catch(() => {});
}

/** Main window: send the answers a reload cut off mid-Undo. The toast went
 *  without its Undo being taken, so the answer stands, checked like any. */
function settleLeftOver() {
  let raw: string | null = null;
  try {
    raw = sessionStorage.getItem(HELD_KEY);
  } catch {
    return;
  }
  if (!raw) return;
  let rows: unknown;
  try {
    rows = JSON.parse(raw);
  } catch {
    rows = [];
  }
  let added = false;
  for (const row of Array.isArray(rows) ? (rows as Array<Record<string, unknown>>) : []) {
    const key = memberKey(row?.member);
    const kind = heldKind(row?.kind);
    if (!key || !kind || held.has(key)) continue;
    const name = typeof row.name === 'string' ? row.name.slice(0, 256) : '';
    const entry: HeldEntry = { kind, name, toastId: null, dropped: false, forChat: false, taken: true };
    held.set(key, entry);
    added = true;
    void settleHeld(key, entry);
  }
  if (added || held.size === 0) publishHeld();
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
          if (msg.new_thread) void notify('friend_message', m.channels_dm_request_notify({ name }), dmPreview(msg.text));
          return;
        }
        void notify('friend_message', m.channels_dm_notify_title({ name }), dmPreview(msg.text));
      }),
    );
    registered.push(await listen(ROOM_DM_STATUS_EVENT, () => void refreshDmThreads()));
    registered.push(await listen(ROOM_DM_THREAD_EVENT, () => void refreshDmThreads()));
    if (isChatWindow()) await listenAsChat(registered);
    else await listenAsMain(registered);
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
  if (!isChatWindow()) settleLeftOver();
}

export function cleanupRoomDmStore(): void {
  epoch++;
  for (const fn of unlisteners) fn();
  unlisteners = [];
  initialized = false;
  refreshSeq++;
  heldSeq++;
  dmThreads.set([]);
  heldByMain.set(new Map());
  // Their toasts still settle them; a store started again here must not
  // treat them as its own.
  held.clear();
  heldHere.set(new Map());
}
