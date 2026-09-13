import { writable } from 'svelte/store';

/** One line of eD2K server activity, as emitted by the backend's
 *  `emit_server_log`. `at` is captured on arrival rather than baked into
 *  `message` so the view can render it in the user's current locale and
 *  re-render it if that changes. */
export interface ServerLogEntry {
  /** Monotonic within a session; only used as an `{#each}` key. Two messages
   *  can share a millisecond, so the timestamp cannot serve as one. */
  id: number;
  /** Epoch milliseconds the message reached the frontend. */
  at: number;
  message: string;
}

/**
 * Session-long history of eD2K server messages (connect progress, the
 * server's MOTD, disconnect reasons).
 *
 * Lives here rather than in `routes/servers/+page.svelte` because the shell
 * navigates with `goto()` under `{#key $page.url.pathname}`, which destroys
 * the page component on every tab switch. Page-local state meant a server's
 * greeting was gone the moment the user looked at anything else, and the
 * `server-log` listener went with it, so messages that arrived while away were
 * never recorded at all. The backend keeps no history to replay, so the
 * frontend has to be the one to remember.
 */
export const serverLog = writable<ServerLogEntry[]>([]);

/** Lines kept before the oldest are dropped. Matches the cap the Servers page
 *  applied when it owned this list. */
const MAX_ENTRIES = 200;

let nextId = 1;

export function appendServerLog(message: string): void {
  if (!message) return;
  const entry: ServerLogEntry = { id: nextId++, at: Date.now(), message };
  serverLog.update((entries) =>
    entries.length >= MAX_ENTRIES
      ? [...entries.slice(entries.length - MAX_ENTRIES + 1), entry]
      : [...entries, entry],
  );
}

export function clearServerLog(): void {
  serverLog.set([]);
}
