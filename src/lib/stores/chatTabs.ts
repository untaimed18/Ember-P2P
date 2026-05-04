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
  hash: string;
  name: string;
}

const STORAGE_KEY = 'ember.chatTabs.v1';

interface PersistedState {
  tabs: ChatTab[];
  activeHash: string | null;
}

function loadPersisted(): PersistedState {
  if (typeof localStorage === 'undefined') return { tabs: [], activeHash: null };
  try {
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
      .map((t) => ({ hash: t.hash, name: t.name }));
    const activeRaw = typeof obj.activeHash === 'string' ? obj.activeHash : null;
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
  if (typeof localStorage === 'undefined') return;
  try {
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
  if (text) chatDrafts.set(hash, text);
  else chatDrafts.delete(hash);
}

export function clearDraft(hash: string) {
  chatDrafts.delete(hash);
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
  chatTabs.update((tabs) => {
    const idx = tabs.findIndex((t) => t.hash === hash);
    if (idx === -1) return [...tabs, { hash, name }];
    if (tabs[idx].name !== name) {
      const next = tabs.slice();
      next[idx] = { hash, name };
      return next;
    }
    return tabs;
  });
  activeChatTab.set(hash);
  chatDockOpen.set(true);
}

/**
 * Close a single tab. If it was the active one, the neighbouring tab
 * (preferring the previous) becomes active. Closing the last tab
 * collapses the dock — there's nothing left to show.
 */
export function closeTab(hash: string) {
  const tabs = get(chatTabs);
  const idx = tabs.findIndex((t) => t.hash === hash);
  if (idx === -1) return;
  const next = tabs.slice();
  next.splice(idx, 1);
  chatTabs.set(next);
  // Wipe any draft. We do this AFTER mutating the tab list so the
  // map can't briefly hold a draft for a hash whose tab is gone —
  // the next `getDraft` for the same hash always sees an empty
  // string until the user types something new.
  chatDrafts.delete(hash);

  if (get(activeChatTab) === hash) {
    const neighbor = next[idx - 1]?.hash ?? next[idx]?.hash ?? null;
    activeChatTab.set(neighbor);
    if (neighbor === null) chatDockOpen.set(false);
  }
}

/** Activate an existing tab (no-op if it isn't open) and reveal the dock. */
export function setActiveTab(hash: string) {
  if (get(chatTabs).some((t) => t.hash === hash)) {
    activeChatTab.set(hash);
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
 * Drop a tab when its underlying friend was removed from the friend
 * list (the conversation's identity is gone, leaving the tab open
 * would be misleading). Called from the friend-removal flow.
 */
export function removeChatForFriend(hash: string) {
  closeTab(hash);
}

/**
 * Update the display name on an existing tab (no-op if the friend
 * isn't currently open). Called from the rename flow on the
 * Friends page so the tab strip and the conversation header don't
 * stay stuck on the old nickname after a rename.
 */
export function renameTab(hash: string, newName: string) {
  chatTabs.update((tabs) => {
    const idx = tabs.findIndex((t) => t.hash === hash);
    if (idx === -1 || tabs[idx].name === newName) return tabs;
    const next = tabs.slice();
    next[idx] = { hash, name: newName };
    return next;
  });
}

