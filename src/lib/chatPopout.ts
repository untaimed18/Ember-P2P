import { get, writable } from 'svelte/store';
import { emit, listen, type UnlistenFn } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { goto } from '$app/navigation';
import * as m from '$lib/paraglide/messages';
import { getLocale, translateError } from '$lib/i18n';
import {
  activeChatTab,
  chatDockOpen,
  chatTabs,
  closeTab,
  addChatTab,
  openChat,
  reloadChatTabs,
  renameTab,
  restoreFriendDrafts,
  setChatPopout,
  takeFriendDrafts,
  type ChatPopoutHook,
  type ChatTabOp,
} from '$lib/stores/chatTabs';
import { activeChatHash } from '$lib/stores/friends';
import { isAcceptedFriendInput } from '$lib/friendCode';
import { loadAppSettings } from '$lib/stores/settings';
import { initTheme } from '$lib/stores/theme';
import { toastError } from '$lib/stores/toast';
import { chatWindowPresence, isChatWindow, type ChatWindowPresence } from '$lib/windowRole';
import { feedLinksIn } from '$lib/feedLinks';
import {
  closeChatWindow,
  focusMainWindow,
  openChatWindow,
  type ChatWindowBounds,
} from '$lib/api/chatWindow';

/**
 * The chat popped out of the dock into a window of its own.
 *
 * Two documents, two sets of stores: nothing here is shared memory. The chat
 * window runs its own friends store (with notifications left to the main
 * window) and owns the tab list while it is out; the main window forwards
 * whatever would have opened or changed a tab, and learns from the chat
 * window what it is showing so unread counts and notifications stay right.
 * Messages between the two are frontend-only events, named `ember-ui:*` to
 * keep them apart from the backend's `ember:*`.
 */

const MODE_KEY = 'ember.chatDock.mode.v1';
const BOUNDS_KEY = 'ember.chatWindow.bounds.v1';
const REOPEN_KEY = 'ember.chatWindow.reopenAtLaunch.v1';
/** In session storage, so a reload of the main window (a language change)
 *  is not taken for a launch. */
const LAUNCH_CHECKED_KEY = 'ember.chatWindow.launchChecked';

const TAB_OP_EVENT = 'ember-ui:chat-tab-op';
const PRESENCE_EVENT = 'ember-ui:chat-presence';
const READY_EVENT = 'ember-ui:chat-ready';
const DRAFTS_EVENT = 'ember-ui:chat-drafts';
const STASH_EVENT = 'ember-ui:chat-drafts-stash';
const NAVIGATE_EVENT = 'ember-ui:chat-navigate';
/** Emitted by the backend when the chat window is destroyed. */
const CLOSED_EVENT = 'ember:chat-window-closed';
/** Sent by the backend to the chat window when its X is pressed. */
const REDOCK_REQUEST_EVENT = 'ember:chat-window-redock';

/** How long the chat window waits for the drafts before drawing without
 *  them. The main window answers in a frame or two; this is for when it
 *  cannot answer at all. */
const DRAFT_HANDSHAKE_MS = 800;
const MAX_DRAFT_CHARS = 20_000;
/** A dock tab key: a friend's hash, or `dm:` and a room member's key for a
 *  private conversation (`stores/roomDm.ts`). */
const HASH_RE = /^(?:[0-9a-f]{32}|dm:[0-9a-f]{64})$/;

function readStorage(key: string): string | null {
  try {
    return typeof localStorage === 'undefined' ? null : localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStorage(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Remembered for this session only.
  }
}

function validHash(raw: unknown): string | null {
  return typeof raw === 'string' && HASH_RE.test(raw.toLowerCase()) ? raw.toLowerCase() : null;
}

/** Drafts as another window sent them, kept to what a draft can be. */
function parseDrafts(raw: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!raw || typeof raw !== 'object') return out;
  for (const [key, text] of Object.entries(raw as Record<string, unknown>)) {
    const hash = validHash(key);
    if (hash && typeof text === 'string' && text) out[hash] = text.slice(0, MAX_DRAFT_CHARS);
  }
  return out;
}

function loadBounds(): ChatWindowBounds | null {
  const raw = readStorage(BOUNDS_KEY);
  if (!raw) return null;
  try {
    const b = JSON.parse(raw) as Partial<ChatWindowBounds>;
    const fields = [b.x, b.y, b.width, b.height];
    if (!fields.every((v) => typeof v === 'number' && Number.isFinite(v))) return null;
    return b as ChatWindowBounds;
  } catch {
    return null;
  }
}

// ── Main window ────────────────────────────────────────────────────────────

/** The chat is in its own window rather than the dock. */
export const chatPoppedOut = writable<boolean>(readStorage(MODE_KEY) === 'window');

/** Open the chat window when Ember starts if the chat was in it when Ember
 *  closed. Kept on this device, as the mode is; off unless chosen, since
 *  until then the window opened only once a conversation was. */
export const chatReopenAtLaunch = writable<boolean>(readStorage(REOPEN_KEY) === '1');
chatReopenAtLaunch.subscribe((on) => writeStorage(REOPEN_KEY, on ? '1' : '0'));

/** The launch's one look at whether to reopen the chat window. Not when the
 *  main window starts hidden (in the tray at login): the chat would be the
 *  only window on screen. An update restart reopens it on its own when it
 *  was open, and a second ask only brings it forward. */
async function reopenAtLaunch() {
  try {
    if (sessionStorage.getItem(LAUNCH_CHECKED_KEY)) return;
    sessionStorage.setItem(LAUNCH_CHECKED_KEY, '1');
  } catch {
    return;
  }
  if (!get(chatPoppedOut) || !get(chatReopenAtLaunch)) return;
  try {
    if (!(await getCurrentWindow().isVisible())) return;
  } catch {
    return;
  }
  await showChatWindow();
}

/** Drafts waiting for the chat window to ask for them. Held in memory only,
 *  for the reason the dock keeps its drafts off disk. */
let pendingDrafts: Record<string, string> = {};
/** The conversation the chat window last said was active, stashed with its
 *  drafts, to open when the chat docks back. */
let pendingActiveHash: string | null = null;

const hook: ChatPopoutHook = {
  forward(op) {
    void emit(TAB_OP_EVENT, op).catch(() => {});
  },
  reveal() {
    void showChatWindow();
  },
};

/** An open already on its way: a second ask while the window is being made
 *  waits for it rather than racing it. */
let showing: Promise<void> | null = null;

/** Open the chat window, or bring it to the front. Falls back to the dock if
 *  the window cannot be made, so asking for the chat always shows it. */
export function showChatWindow(): Promise<void> {
  showing ??= openOrFallBack().finally(() => {
    showing = null;
  });
  return showing;
}

async function openOrFallBack(): Promise<void> {
  try {
    await openChatWindow(m.chat_window_title(), loadBounds());
    // Opening it puts it in front of the user, with the conversation that was
    // active. Until its first presence report arrives, which can take a
    // second, say so, or a message the user is reading there would notify
    // and count as unread. The report replaces this; a close clears it.
    if (get(chatWindowPresence) === null) {
      chatWindowPresence.set({
        activeHash: validHash(get(activeChatTab)),
        visible: true,
        focused: true,
      });
    }
  } catch (e) {
    toastError(translateError(e, m.error_chat_window_open_failed()));
    chatPoppedOut.set(false);
    reloadChatTabs();
    restoreFriendDrafts(pendingDrafts);
    pendingDrafts = {};
    chatDockOpen.set(true);
  }
}

/** Move the chat out of the dock into its own window. */
export function popOutChat() {
  pendingDrafts = takeFriendDrafts();
  chatPoppedOut.set(true);
  chatDockOpen.set(false);
  void showChatWindow();
}

/** Take the chat back into the dock, from the main window's side. */
function redockHere(payload: { activeHash?: unknown; drafts?: unknown } | undefined) {
  chatPoppedOut.set(false);
  chatWindowPresence.set(null);
  reloadChatTabs();
  const active = validHash(payload?.activeHash);
  if (active && get(chatTabs).some((t) => t.hash === active)) activeChatTab.set(active);
  restoreFriendDrafts(parseDrafts(payload?.drafts));
  pendingDrafts = {};
  pendingActiveHash = null;
  chatDockOpen.set(true);
  void focusMainWindow().catch(() => {});
}

function parsePresence(raw: unknown): ChatWindowPresence | null {
  if (!raw || typeof raw !== 'object') return null;
  const p = raw as Record<string, unknown>;
  return {
    activeHash: validHash(p.activeHash),
    visible: p.visible === true,
    focused: p.focused === true,
  };
}

/** Pages the chat window may send the main window to. */
const NAVIGABLE = new Set(['/friends', '/feeds']);

export async function initChatPopoutMain(): Promise<() => void> {
  const unsubscribe = chatPoppedOut.subscribe((out) => {
    writeStorage(MODE_KEY, out ? 'window' : 'dock');
    setChatPopout(out ? hook : null);
  });
  const unlisteners: UnlistenFn[] = [];
  try {
    unlisteners.push(
      await listen(PRESENCE_EVENT, (e) => chatWindowPresence.set(parsePresence(e.payload))),
      await listen(CLOSED_EVENT, () => {
        chatWindowPresence.set(null);
        // The window is gone, by its own Dock back, hung, or closed before it
        // could answer: dock the chat back here with what it last stashed.
        // Only now, so a window that failed to close is never left open
        // beside a dock that took the chat back.
        if (get(chatPoppedOut)) redockHere({ activeHash: pendingActiveHash, drafts: pendingDrafts });
      }),
      await listen(READY_EVENT, () => {
        const drafts = pendingDrafts;
        pendingDrafts = {};
        void emit(DRAFTS_EVENT, { drafts }).catch(() => {});
      }),
      await listen<{ activeHash?: unknown; drafts?: unknown }>(STASH_EVENT, (e) => {
        pendingDrafts = parseDrafts(e.payload?.drafts);
        pendingActiveHash = validHash(e.payload?.activeHash) ?? pendingActiveHash;
      }),
      await listen<{ path?: unknown; add?: unknown; name?: unknown; follow?: unknown }>(NAVIGATE_EVENT, (e) => {
        const path = e.payload?.path;
        if (typeof path !== 'string' || !NAVIGABLE.has(path)) return;
        // Only fills the Add form: adding stays a click in this window.
        const add = e.payload?.add;
        const name = typeof e.payload?.name === 'string' ? e.payload.name : '';
        const follow = typeof e.payload?.follow === 'string' ? feedLinksIn(e.payload.follow) : [];
        const target =
          path === '/friends' && typeof add === 'string' && isAcceptedFriendInput(add)
            ? friendsAddPath(add, name)
            : path === '/feeds' && follow.length === 1
              ? feedsFollowPath(follow[0])
              : path;
        void goto(target).catch((err) => console.warn('chat window: navigation failed', err));
      }),
    );
  } catch (e) {
    console.warn('chat popout: listener registration failed', e);
  }
  // After the listeners, so the window's ready handshake is heard.
  void reopenAtLaunch();
  return () => {
    unsubscribe();
    setChatPopout(null);
    for (const unlisten of unlisteners) unlisten();
  };
}

// ── Chat window ────────────────────────────────────────────────────────────

function applyTabOp(raw: unknown) {
  if (!raw || typeof raw !== 'object') return;
  const op = raw as Partial<ChatTabOp> & { name?: unknown };
  const hash = validHash(op.hash);
  if (!hash) return;
  const name = typeof op.name === 'string' ? op.name.slice(0, 256) : '';
  if (op.kind === 'open') openChat(hash, name);
  else if (op.kind === 'add') addChatTab(hash, name);
  else if (op.kind === 'rename') renameTab(hash, name);
  else if (op.kind === 'close') closeTab(hash);
}

let dockingBack = false;

/** Put the chat back into the main window's dock, drafts and all, and close
 *  this window. What its X does.
 *
 *  The main window docks the chat when it hears the window is gone, from what
 *  is stashed here first. Telling it to dock before the close, as this used
 *  to, left the chat docked there and still open here whenever the close
 *  failed. */
export async function dockBack(): Promise<void> {
  if (dockingBack) return;
  dockingBack = true;
  const drafts = takeFriendDrafts();
  await emit(STASH_EVENT, { activeHash: get(activeChatTab), drafts }).catch(() => {});
  try {
    await closeChatWindow();
  } catch (e) {
    dockingBack = false;
    // Still open, so the drafts stay with it.
    restoreFriendDrafts(drafts);
    toastError(translateError(e, m.error_operation_failed()));
  }
}

/** Show a page of the main window, from a link in the chat window. */
export function showInMainWindow(path: string) {
  void emit(NAVIGATE_EVENT, { path }).catch(() => {});
  void focusMainWindow().catch(() => {});
}

/** Show the main window's Friends page with `code` and the name they go by
 *  in its Add form, from the chat window, which cannot add friends itself. */
export function addFriendInMainWindow(code: string, name: string) {
  void emit(NAVIGATE_EVENT, { path: '/friends', add: code, name }).catch(() => {});
  void focusMainWindow().catch(() => {});
}

/** The Feeds page following the feed `link` names, or opening it when it is
 *  followed already or one of ours. */
export function feedsFollowPath(link: string): string {
  return `/feeds?follow=${encodeURIComponent(link)}`;
}

/** Follow or open the feed a link in a message names, in the main window:
 *  the chat window cannot follow a feed itself. */
export function openFeedLink(link: string) {
  if (isChatWindow()) {
    void emit(NAVIGATE_EVENT, { path: '/feeds', follow: link }).catch(() => {});
    void focusMainWindow().catch(() => {});
  } else {
    void goto(feedsFollowPath(link)).catch((err) => console.warn('feed link: navigation failed', err));
  }
}

/** The Friends page with its Add form filled: `code`, and `name` when there
 *  is one. */
export function friendsAddPath(code: string, name: string): string {
  const shown = name.trim().slice(0, 256);
  return `/friends?add=${encodeURIComponent(code.trim())}${shown ? `&name=${encodeURIComponent(shown)}` : ''}`;
}

/**
 * Wire the chat window up to the main one. Resolves once the drafts have
 * arrived (or the wait for them has run out), which is when the chat is ready
 * to draw: a conversation mounted before them would open with an empty box.
 */
export async function initChatWindowSide(): Promise<() => void> {
  const unlisteners: UnlistenFn[] = [];
  const cleanups: Array<() => void> = [];
  const win = getCurrentWindow();
  let minimized = false;

  let resolveDrafts: () => void = () => {};
  const draftsArrived = new Promise<void>((resolve) => {
    resolveDrafts = resolve;
  });

  const report = () => {
    const presence: ChatWindowPresence = {
      activeHash: get(activeChatHash),
      visible: document.visibilityState === 'visible' && !minimized,
      focused: document.hasFocus(),
    };
    void emit(PRESENCE_EVENT, presence).catch(() => {});
  };
  const stash = () =>
    emit(STASH_EVENT, { activeHash: get(activeChatTab), drafts: takeFriendDrafts() }).catch(() => {});

  // A language change reloads only the main window; this one keeps the
  // locale it loaded in until it reloads too. Checked on focus rather than
  // when the stored choice changes, which is while the main window is itself
  // reloading and could not take the drafts. They go to it first, and it
  // hands them back once the reloaded window asks.
  const loadedLocale = getLocale();
  let reloading = false;
  const followLocale = (): boolean => {
    if (reloading) return true;
    if (getLocale() === loadedLocale) return false;
    reloading = true;
    void stash().finally(() => location.reload());
    return true;
  };

  let boundsTimer: ReturnType<typeof setTimeout> | undefined;
  const saveBounds = () => {
    clearTimeout(boundsTimer);
    boundsTimer = setTimeout(async () => {
      try {
        minimized = await win.isMinimized();
        report();
        if (minimized || (await win.isMaximized())) return;
        const scale = await win.scaleFactor();
        const position = await win.outerPosition();
        const size = await win.innerSize();
        writeStorage(
          BOUNDS_KEY,
          JSON.stringify({
            x: Math.round(position.x / scale),
            y: Math.round(position.y / scale),
            width: Math.round(size.width / scale),
            height: Math.round(size.height / scale),
          }),
        );
      } catch {
        // Not remembered this time; the window still works.
      }
    }, 400);
  };

  const onFocus = () => {
    // Changed in the main window while this one was in the background.
    if (followLocale()) return;
    report();
    initTheme();
    void loadAppSettings().catch(() => {});
  };
  const onBlur = () => {
    report();
    void stash();
  };
  window.addEventListener('focus', onFocus);
  window.addEventListener('blur', onBlur);
  document.addEventListener('visibilitychange', report);
  window.addEventListener('pagehide', stash);
  cleanups.push(() => {
    window.removeEventListener('focus', onFocus);
    window.removeEventListener('blur', onBlur);
    document.removeEventListener('visibilitychange', report);
    window.removeEventListener('pagehide', stash);
    clearTimeout(boundsTimer);
  });
  cleanups.push(activeChatHash.subscribe(() => report()));

  try {
    unlisteners.push(
      await listen<{ drafts?: unknown }>(DRAFTS_EVENT, (e) => {
        restoreFriendDrafts(parseDrafts(e.payload?.drafts));
        resolveDrafts();
      }),
      await listen(TAB_OP_EVENT, (e) => applyTabOp(e.payload)),
      await listen(REDOCK_REQUEST_EVENT, () => void dockBack()),
      await win.onMoved(saveBounds),
      await win.onResized(saveBounds),
    );
    await emit(READY_EVENT);
  } catch (e) {
    console.warn('chat window: wiring to the main window failed', e);
    resolveDrafts();
  }

  await Promise.race([
    draftsArrived,
    new Promise<void>((resolve) => setTimeout(resolve, DRAFT_HANDSHAKE_MS)),
  ]);
  report();

  return () => {
    for (const cleanup of cleanups) cleanup();
    for (const unlisten of unlisteners) unlisten();
  };
}
