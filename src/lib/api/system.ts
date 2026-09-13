import { invoke } from '@tauri-apps/api/core';
import type { RuntimeStatus } from '$lib/types';

/**
 * Ask the OS to show a desktop notification.
 *
 * The text is composed here rather than in Rust because every notification
 * names something only the renderer can say — a friend's nickname, a room's
 * name, a localized sentence. The backend sanitizes and rate-limits whatever it
 * is handed; see `src-tauri/src/commands/system.rs`.
 *
 * Prefer {@link notify} in `$lib/notifications` over calling this directly: it
 * applies the per-category switches and the "only while unfocused" rule.
 */
export async function showNotification(
  title: string,
  body: string,
): Promise<void> {
  return invoke('show_notification', { title, body });
}

/**
 * Snapshot of the state the clock-driven features publish: which bandwidth
 * schedule window is open, and whether sleep is being deferred.
 *
 * Used for first paint. Afterwards the backend emits `ember:runtime-status`
 * with the same shape whenever it changes, so nothing needs to poll.
 */
export async function getRuntimeStatus(): Promise<RuntimeStatus> {
  return invoke('get_runtime_status');
}

/**
 * Read the system clipboard as text, or `null` when it holds none.
 *
 * Goes through the backend because the webview cannot do this reliably:
 * WebKitGTK (Tauri's Linux webview) refuses programmatic
 * `navigator.clipboard.readText()` outright. Callers should prefer
 * {@link readFromClipboard} in `$lib/utils`, which falls back to the webview
 * APIs if this command is unavailable.
 */
export async function readClipboardText(): Promise<string | null> {
  return invoke('read_clipboard_text');
}

/** Write text to the system clipboard. See {@link readClipboardText}. */
export async function writeClipboardText(text: string): Promise<void> {
  return invoke('write_clipboard_text', { text });
}
