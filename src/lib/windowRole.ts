import { get, writable } from 'svelte/store';
import { getCurrentWindow } from '@tauri-apps/api/window';

/**
 * Which window this document is, and — in the main window — what the
 * popped-out chat window says it is showing.
 *
 * A leaf module on purpose: `notifications` and the friends store read it, and
 * both sit underneath `chatTabs`, so anything heavier here would close an
 * import cycle.
 */

/** Keep in step with `CHAT_WINDOW_LABEL` in `commands/chat_window.rs`. */
export const CHAT_WINDOW_LABEL = 'chat';

let label: string | null | undefined;

function windowLabel(): string | null {
  if (label !== undefined) return label;
  try {
    label =
      typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window
        ? getCurrentWindow().label
        : null;
  } catch {
    label = null;
  }
  return label;
}

/** This document is the popped-out chat window rather than the main one. */
export function isChatWindow(): boolean {
  return windowLabel() === CHAT_WINDOW_LABEL;
}

/** What the chat window reports about itself, so the main window can tell a
 *  conversation being read over there from one nobody is looking at. */
export interface ChatWindowPresence {
  /** The friend conversation on screen, or null for none. */
  activeHash: string | null;
  /** Not minimized or hidden. */
  visible: boolean;
  /** Has keyboard focus. */
  focused: boolean;
}

/** Main window only. Null while the chat window is closed. */
export const chatWindowPresence = writable<ChatWindowPresence | null>(null);

/** The chat window is showing this conversation where the user can see it. */
export function chatWindowShows(hash: string): boolean {
  const presence = get(chatWindowPresence);
  return !!presence && presence.visible && presence.activeHash === hash.toLowerCase();
}

/** The user is working in the chat window, which is working in Ember. */
export function chatWindowFocused(): boolean {
  const presence = get(chatWindowPresence);
  return !!presence && presence.visible && presence.focused;
}
