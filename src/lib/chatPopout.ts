import { get, writable } from 'svelte/store';
import { emit, listen, type UnlistenFn } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { goto } from '$app/navigation';
import * as m from '$lib/paraglide/messages';
import { translateError } from '$lib/i18n';
import {
  activeChatTab,
  chatDockOpen,
  chatTabs,
  closeTab,
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
import { loadAppSettings } from '$lib/stores/settings';
import { initTheme } from '$lib/stores/theme';
import { toastError } from '$lib/stores/toast';
import { chatWindowPresence, type ChatWindowPresence } from '$lib/windowRole';
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

const TAB_OP_EVENT = 'ember-ui:chat-tab-op';
const PRESENCE_EVENT = 'ember-ui:chat-presence';
const READY_EVENT = 'ember-ui:chat-ready';
const DRAFTS_EVENT = 'ember-ui:chat-drafts';
const STASH_EVENT = 'ember-ui:chat-drafts-stash';
const REDOCK_EVENT = 'ember-ui:chat-redock';
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
const HASH_RE = /^[0-9a-f]{32}$/;

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

/** Drafts waiting for the chat window to ask for them. Held in memory only,
 *  for the reason the dock keeps its drafts off disk. */
let pendingDrafts: Record<string, string> = {};

const hook: ChatPopoutHook = {
  forward(op) {
    void emit(TAB_OP_EVENT, op).catch(() => {});
  },
  reveal() {
    void showChatWindow();
  },
};

/** Open the chat window, or bring it to the front. Falls back to the dock if
 *  the window cannot be made, so asking for the chat always shows it. */
export async function showChatWindow(): Promise<void> {
  try {
    await openChatWindow(m.chat_window_title(), loadBounds());
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
const NAVIGABLE = new Set(['/friends']);

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
        // Gone without docking back first: hung, or closed before it could
        // answer. Dock it back here with the drafts it last stashed.
        if (get(chatPoppedOut)) redockHere({ drafts: pendingDrafts });
      }),
      await listen(READY_EVENT, () => {
        const drafts = pendingDrafts;
        pendingDrafts = {};
        void emit(DRAFTS_EVENT, { drafts }).catch(() => {});
      }),
      await listen<{ drafts?: unknown }>(STASH_EVENT, (e) => {
        pendingDrafts = parseDrafts(e.payload?.drafts);
      }),
      await listen<{ activeHash?: unknown; drafts?: unknown }>(REDOCK_EVENT, (e) => redockHere(e.payload)),
      await listen<{ path?: unknown }>(NAVIGATE_EVENT, (e) => {
        const path = e.payload?.path;
        if (typeof path === 'string' && NAVIGABLE.has(path)) {
          void goto(path).catch((err) => console.warn('chat window: navigation failed', err));
        }
      }),
    );
  } catch (e) {
    console.warn('chat popout: listener registration failed', e);
  }
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
  else if (op.kind === 'rename') renameTab(hash, name);
  else if (op.kind === 'close') closeTab(hash);
}

let dockingBack = false;

/** Put the chat back into the main window's dock, drafts and all, and close
 *  this window. What its X does. */
export async function dockBack(): Promise<void> {
  if (dockingBack) return;
  dockingBack = true;
  const drafts = takeFriendDrafts();
  // Closed even if the main window did not hear this: it docks the chat back
  // itself when the window goes, from the drafts last stashed with it.
  await emit(STASH_EVENT, { drafts }).catch(() => {});
  await emit(REDOCK_EVENT, { activeHash: get(activeChatTab), drafts }).catch(() => {});
  try {
    await closeChatWindow();
  } catch (e) {
    dockingBack = false;
    toastError(translateError(e, m.error_operation_failed()));
  }
}

/** Show a page of the main window, from a link in the chat window. */
export function showInMainWindow(path: string) {
  void emit(NAVIGATE_EVENT, { path }).catch(() => {});
  void focusMainWindow().catch(() => {});
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
  const stash = () => {
    void emit(STASH_EVENT, { drafts: takeFriendDrafts() }).catch(() => {});
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
    report();
    // Changed in the main window while this one was in the background.
    initTheme();
    void loadAppSettings().catch(() => {});
  };
  const onBlur = () => {
    report();
    stash();
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
