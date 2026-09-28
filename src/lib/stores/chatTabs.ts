import { writable, derived, get } from 'svelte/store';
import { unreadCounts } from '$lib/stores/friends';

/**
 * Multi-conversation chat dock state.
 *
 * The dock lives at the app-shell level (mounted in `+layout.svelte`)
 * and holds an ordered list of "open" conversations as tabs. One tab
 * is active at a time and renders a `ChatConversation`. The previous
 * single-conversation chat sidebar was scoped to the Friends page;
 * this store lifts the lifecycle into the layout so:
 *
 *  - opening a chat from `/friends` keeps it open while the user
 *    clicks around `/transfers`, `/library`, etc.
 *  - users can chat with several friends without closing-and-
 *    reopening between each one.
 *  - the in-flight conversation isn't destroyed on every navigation.
 *
 * Tabs and the last-active hash persist to `localStorage` so
 * relaunching the app restores recent conversations (messages are
 * re-fetched lazily when a tab becomes active, identical to the
 * old open-on-click flow).
 *
 * The dock-open boolean is intentionally NOT persisted — the user
 * always starts a session with the dock collapsed so the app surface
 * looks the same as a clean launch.
 */
export interface ChatTab {
  /** Friend hash. The dock holds friend conversations and nothing else. */
  hash: string;
  name: string;
}

/**
 * Draft-key namespace for a room, which is *not* a tab namespace.
 *
 * Rooms live on `/channels` and only there. The draft map below is still shared
 * with them, because `ChatConversation` keeps a half-typed line across a
 * navigation whether it is drawing a friend or a room, and it derives its own
 * `ch:<channel id>` key for that. So this prefix marks the one thing about a
 * room this store knows: a draft under it has no tab and never will, which is
 * what {@link setDraft} needs to tell it apart from a friend draft whose tab
 * has just closed.
 */
const CHANNEL_DRAFT_PREFIX = 'ch:';

const STORAGE_KEY = 'ember.chatTabs.v1';
const MAX_CHAT_TABS = 50;

interface PersistedState {
  tabs: ChatTab[];
  activeHash: string | null;
}

// The `typeof` checks sit inside the `try`: with storage disabled, merely
// reading the `localStorage` global throws a SecurityError, and this runs at
// module load, where a throw takes the whole layout down with it.
function loadPersisted(): PersistedState {
  try {
    if (typeof localStorage === 'undefined') return { tabs: [], activeHash: null };
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { tabs: [], activeHash: null };
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return { tabs: [], activeHash: null };
    const obj = parsed as { tabs?: unknown; activeHash?: unknown };
    const tabsRaw = Array.isArray(obj.tabs) ? obj.tabs : [];
    // Defensive parsing: a future schema change or hand-edited
    // localStorage shouldn't be able to crash store hydration. Drop
    // any entries that don't match the expected shape.
    const tabs: ChatTab[] = tabsRaw
      .filter(
        (t): t is ChatTab =>
          !!t &&
          typeof t === 'object' &&
          typeof (t as ChatTab).hash === 'string' &&
          typeof (t as ChatTab).name === 'string',
      )
      .map((t) => ({ hash: t.hash.toLowerCase(), name: t.name }))
      .slice(-MAX_CHAT_TABS);
    const activeRaw =
      typeof obj.activeHash === 'string' ? obj.activeHash.toLowerCase() : null;
    const activeHash =
      activeRaw && tabs.some((t) => t.hash === activeRaw)
        ? activeRaw
        : tabs[0]?.hash ?? null;
    return { tabs, activeHash };
  } catch {
    return { tabs: [], activeHash: null };
  }
}

function persist(state: PersistedState) {
  try {
    if (typeof localStorage === 'undefined') return;
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {
    // Quota exceeded / private mode / disabled — non-fatal. The dock
    // works for the duration of the session; only restore-on-relaunch
    // is lost.
  }
}

const initial = loadPersisted();

export const chatTabs = writable<ChatTab[]>(initial.tabs);
export const activeChatTab = writable<string | null>(initial.activeHash);
export const chatDockOpen = writable<boolean>(false);

// Persist whenever either piece of durable state changes. We can't
// derive() into a side-effect cleanly, so we subscribe twice and use
// `get()` to read the other half each time. Two writes per change is
// fine — the payload is tiny and localStorage is synchronous.
chatTabs.subscribe((tabs) => persist({ tabs, activeHash: get(activeChatTab) }));
activeChatTab.subscribe((activeHash) => persist({ tabs: get(chatTabs), activeHash }));

/** A change to the tab list made in one window, to be replayed in the other. */
export type ChatTabOp =
  | { kind: 'open'; hash: string; name: string }
  | { kind: 'close'; hash: string }
  | { kind: 'rename'; hash: string; name: string };

/**
 * Installed in the main window while the chat is popped out into its own
 * window (see `chatPopout.ts`). The tabs are then the chat window's, and it
 * saves every change it makes, so the main window re-reads them before
 * changing anything — its own copy is stale and saving it would undo what
 * was done over there — and forwards the change instead of opening the dock.
 */
export interface ChatPopoutHook {
  forward(op: ChatTabOp): void;
  /** Show the chat: open the chat window, or bring it forward. */
  reveal(): void;
}

let popout: ChatPopoutHook | null = null;

export function setChatPopout(hook: ChatPopoutHook | null) {
  popout = hook;
}

/** Re-read the tab list from storage, where the other window saved it. */
export function reloadChatTabs() {
  const state = loadPersisted();
  chatTabs.set(state.tabs);
  activeChatTab.set(state.activeHash);
}

/**
 * Sum of unread counts across all friends. Used by the Chats toggle
 * button in the sidebar to show a total-pending badge regardless of
 * which (if any) tabs the user has currently open. Driven by the
 * same `unreadCounts` map that powers per-friend badges on the
 * Friends page, so the two stay perfectly in sync.
 */
export const totalUnread = derived(unreadCounts, (counts) => {
  let total = 0;
  for (const n of counts.values()) total += n;
  return total;
});

/**
 * In-memory per-conversation draft buffer.
 *
 * Switching tabs in a multi-conversation UI must NOT lose what the
 * user was typing in the previous conversation; that's the default
 * Slack/Discord/Telegram behaviour and Ember should match it.
 * Stored in a plain `Map` (not a Svelte store) because there's no
 * rendered UI that needs to react to "some other tab's draft
 * changed" — only the active `ChatConversation` reads/writes its
 * own slot, on mount/unmount.
 *
 * Drafts live for the lifetime of the page session only. They are
 * deliberately NOT persisted to localStorage — half-typed messages
 * shouldn't survive an app restart, and persisting message content
 * on disk has obvious privacy implications on shared devices.
 * Cleared explicitly when a tab is closed (see `closeTab`) so a
 * stale draft can't haunt a freshly-reopened conversation.
 *
 * Declared up here (above the action functions) so static analysis
 * doesn't flag a use-before-define on `chatDrafts.delete` inside
 * `closeTab`.
 */
const chatDrafts = new Map<string, string>();

export function getDraft(hash: string): string {
  return chatDrafts.get(hash) ?? '';
}

export function setDraft(hash: string, text: string) {
  // Guard against a resurrection race with `closeTab`: closing the
  // ACTIVE tab changes which hash `ChatConversation` is displaying,
  // which fires that component's cleanup effect — the same effect
  // that normally stashes a draft on an ordinary tab switch. That
  // cleanup runs against `chatTabs`/`activeChatTab` reactivity, which
  // is scheduled *after* `closeTab` has already removed the tab and
  // wiped its draft, so without this check the cleanup's `setDraft`
  // call would silently re-create a draft entry for a hash that no
  // longer has an open tab — exactly the "stale draft haunts a
  // reopened conversation" bug this module's doc comment says can't
  // happen. Friend drafts therefore persist only while a tab is open.
  //
  // Channel drafts use a `ch:` key and never appear in `chatTabs` —
  // rooms live on `/channels`, not in the dock. Gating those the same
  // way discarded every in-progress room line on leave. `closeTab`
  // cannot reopen a `ch:` key, so the resurrection race does not apply.
  const isChannelDraft = hash.startsWith(CHANNEL_DRAFT_PREFIX);
  const tabOpen = get(chatTabs).some((t) => t.hash === hash);
  if (text && (isChannelDraft || tabOpen)) {
    chatDrafts.set(hash, text);
  } else {
    chatDrafts.delete(hash);
  }
}

export function clearDraft(hash: string) {
  chatDrafts.delete(hash);
}

/**
 * The open conversation keeps its draft in its own input and only writes it
 * here when it is left. Handing the drafts to another window cannot wait for
 * that — the dock's exit animation holds the conversation mounted — so the
 * conversation registers a flush that {@link takeFriendDrafts} runs first.
 */
const draftFlushers = new Set<() => void>();

export function registerDraftFlusher(flush: () => void): () => void {
  draftFlushers.add(flush);
  return () => {
    draftFlushers.delete(flush);
  };
}

/** Every friend draft, current to the keystroke, for another window to take
 *  over. Passed over IPC rather than through storage: drafts stay off disk. */
export function takeFriendDrafts(): Record<string, string> {
  for (const flush of draftFlushers) flush();
  const out: Record<string, string> = {};
  for (const [key, text] of chatDrafts) {
    if (!key.startsWith(CHANNEL_DRAFT_PREFIX) && text) out[key] = text;
  }
  return out;
}

/** Replace the friend drafts with ones handed over by the other window. Only
 *  open tabs keep one, the same rule {@link setDraft} applies. */
export function restoreFriendDrafts(drafts: Record<string, string>) {
  for (const key of [...chatDrafts.keys()]) {
    if (!key.startsWith(CHANNEL_DRAFT_PREFIX)) chatDrafts.delete(key);
  }
  const open = new Set(get(chatTabs).map((t) => t.hash));
  for (const [key, text] of Object.entries(drafts)) {
    if (typeof text === 'string' && text && open.has(key)) chatDrafts.set(key, text);
  }
}

/**
 * Open (or focus) a conversation tab and ensure the dock is visible.
 *
 * If a tab already exists for `hash`, its display name is refreshed
 * (a friend rename should be picked up immediately) and the tab is
 * activated. A new tab is appended to the end of the strip;
 * subsequent reorders are an explicit user action only.
 */
export function openChat(hash: string, name: string) {
  const key = hash.toLowerCase();
  if (popout) reloadChatTabs();
  chatTabs.update((tabs) => {
    const idx = tabs.findIndex((t) => t.hash.toLowerCase() === key);
    if (idx === -1) {
      const next = [...tabs, { hash: key, name }];
      if (next.length <= MAX_CHAT_TABS) return next;
      const evicted = next.shift();
      if (evicted) chatDrafts.delete(evicted.hash);
      return next;
    }
    if (tabs[idx].name !== name || tabs[idx].hash !== key) {
      const next = tabs.slice();
      next[idx] = { hash: key, name };
      return next;
    }
    return tabs;
  });
  activeChatTab.set(key);
  if (popout) {
    popout.forward({ kind: 'open', hash: key, name });
    popout.reveal();
    return;
  }
  chatDockOpen.set(true);
}

/**
 * Close a single tab. If it was the active one, the neighbouring tab
 * (preferring the previous) becomes active. Closing the last tab
 * collapses the dock — there's nothing left to show.
 */
export function closeTab(hash: string) {
  const key = hash.toLowerCase();
  if (popout) reloadChatTabs();
  const tabs = get(chatTabs);
  const idx = tabs.findIndex((t) => t.hash.toLowerCase() === key);
  if (idx === -1) return;
  const next = tabs.slice();
  next.splice(idx, 1);
  chatTabs.set(next);
  // Wipe any draft. We do this AFTER mutating the tab list so the
  // map can't briefly hold a draft for a hash whose tab is gone —
  // the next `getDraft` for the same hash always sees an empty
  // string until the user types something new.
  chatDrafts.delete(key);
  chatDrafts.delete(hash);

  if (get(activeChatTab)?.toLowerCase() === key) {
    const neighbor = next[idx - 1]?.hash ?? next[idx]?.hash ?? null;
    activeChatTab.set(neighbor);
    if (neighbor === null) chatDockOpen.set(false);
  }
  popout?.forward({ kind: 'close', hash: key });
}

/** Activate an existing tab (no-op if it isn't open) and reveal the dock. */
export function setActiveTab(hash: string) {
  const key = hash.toLowerCase();
  if (popout) reloadChatTabs();
  const tab = get(chatTabs).find((t) => t.hash.toLowerCase() === key);
  if (tab) {
    activeChatTab.set(tab.hash);
    if (popout) {
      popout.forward({ kind: 'open', hash: tab.hash, name: tab.name });
      popout.reveal();
      return;
    }
    chatDockOpen.set(true);
  }
}

/**
 * Toggle the dock visibility without affecting tab membership.
 *
 * If the user opens the dock with zero tabs, we still flip the
 * boolean so the empty-state UI renders — they'll be steered toward
 * `/friends` to start a chat from there.
 */
export function toggleDock() {
  if (popout) {
    popout.reveal();
    return;
  }
  chatDockOpen.update((v) => !v);
}

export function closeDock() {
  chatDockOpen.set(false);
}

/**
 * Cycle to the previous (-1) or next (+1) tab, wrapping at the ends.
 * Used by the Ctrl+Tab / Ctrl+Shift+Tab hotkeys inside the dock.
 */
export function cycleTab(direction: 1 | -1) {
  const tabs = get(chatTabs);
  if (tabs.length === 0) return;
  const active = get(activeChatTab);
  const idx = tabs.findIndex((t) => t.hash === active);
  if (idx === -1) {
    activeChatTab.set(tabs[0].hash);
    return;
  }
  const nextIdx = (idx + direction + tabs.length) % tabs.length;
  activeChatTab.set(tabs[nextIdx].hash);
}

/**
 * Activate the next open conversation that has unread messages.
 *
 * The dock shows one conversation at a time, so "you have 3 unread elsewhere"
 * needs somewhere to go or it is only a reproach. Returns whether it found one.
 *
 * Starts *after* the active tab and wraps, so pressing it repeatedly walks
 * every unread conversation rather than returning to the same one — and when
 * nothing is active it starts at the first tab instead of skipping it.
 */
export function focusNextUnread(): boolean {
  const tabs = get(chatTabs);
  if (tabs.length === 0) return false;
  const counts = get(unreadCounts);
  const active = get(activeChatTab);
  const activeIdx = tabs.findIndex((t) => t.hash === active);
  for (let step = 1; step <= tabs.length; step++) {
    const tab = tabs[(activeIdx + step + tabs.length) % tabs.length];
    if ((counts.get(tab.hash) ?? 0) > 0) {
      activeChatTab.set(tab.hash);
      chatDockOpen.set(true);
      return true;
    }
  }
  return false;
}

/**
 * Drop a tab when its underlying friend was removed from the friend
 * list (the conversation's identity is gone, leaving the tab open
 * would be misleading). Called from the friend-removal flow.
 */
export function removeChatForFriend(hash: string) {
  closeTab(hash.toLowerCase());
}

/**
 * Drop persisted tabs whose identities are no longer friends.
 *
 * The allow-list is the friend list, and a tab is a friend conversation, so
 * anything outside it goes. That includes the `ch:` room tabs a previous
 * version let the Channels page pin here: rooms are not dock conversations, and
 * this is the sweep that clears one left in `localStorage` on the first launch
 * after the change rather than leaving it to sit there opening nothing.
 */
export function retainChatTabs(friendHashes: Iterable<string>) {
  if (popout) reloadChatTabs();
  const allow = new Set([...friendHashes].map((h) => h.toLowerCase()));
  const tabs = get(chatTabs);
  const next = tabs.filter((t) => allow.has(t.hash.toLowerCase()));
  if (next.length === tabs.length) return;
  for (const gone of tabs) {
    if (!next.includes(gone)) chatDrafts.delete(gone.hash);
  }
  chatTabs.set(next);
  const active = get(activeChatTab);
  if (active && !next.some((t) => t.hash.toLowerCase() === active.toLowerCase())) {
    activeChatTab.set(next[0]?.hash ?? null);
    if (next.length === 0) chatDockOpen.set(false);
  }
  // The chat window holds its own copy of the list; tell it, as closeTab does.
  for (const gone of tabs) {
    if (!next.includes(gone)) popout?.forward({ kind: 'close', hash: gone.hash.toLowerCase() });
  }
}

/**
 * Update the display name on an existing tab (no-op if the friend
 * isn't currently open). Called from the rename flow on the
 * Friends page so the tab strip and the conversation header don't
 * stay stuck on the old nickname after a rename.
 */
export function renameTab(hash: string, newName: string) {
  const key = hash.toLowerCase();
  if (popout) reloadChatTabs();
  chatTabs.update((tabs) => {
    const idx = tabs.findIndex((t) => t.hash.toLowerCase() === key);
    if (idx === -1 || tabs[idx].name === newName) return tabs;
    const next = tabs.slice();
    next[idx] = { hash: tabs[idx].hash, name: newName };
    return next;
  });
  popout?.forward({ kind: 'rename', hash: key, name: newName });
}

