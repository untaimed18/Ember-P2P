import { invoke } from '@tauri-apps/api/core';

/** Where the chat window was last left, in logical pixels. */
export interface ChatWindowBounds {
  x: number;
  y: number;
  width: number;
  height: number;
}

/** Open the chat window, or bring it forward if it is open. Main window only.
 *  `bounds` is ignored when it would put the window off every monitor. */
export async function openChatWindow(title: string, bounds: ChatWindowBounds | null): Promise<void> {
  return invoke('open_chat_window', { title, bounds });
}

export async function closeChatWindow(): Promise<void> {
  return invoke('close_chat_window');
}

export async function focusMainWindow(): Promise<void> {
  return invoke('focus_main_window');
}
