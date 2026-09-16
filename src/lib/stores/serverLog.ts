import { writable } from 'svelte/store';
import type { ServerLogLine } from '$lib/types';

/** One line of eD2K server activity, as emitted by the backend's
 *  `emit_server_log`. `at` is kept separate from `message` so the view can
 *  render it in the user's current locale and re-render it if that changes. */
export interface ServerLogEntry {
  /** Monotonic within a session; only used as an `{#each}` key. Two messages
   *  can share a millisecond, so the timestamp cannot serve as one. */
  id: number;
  /** Epoch milliseconds. The backend's own timestamp for lines that came from
   *  it, so a replayed line keeps the time it happened rather than the time it
   *  was read back; arrival time for lines the UI writes itself. */
  at: number;
  message: string;
  /** Backend sequence number, absent on lines the UI wrote itself. Used to
   *  recognise a replayed line as one already held. */
  seq?: number;
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
 * never recorded at all.
 *
 * This survives navigation but not a reload of the webview, which takes the
 * whole module graph with it. So the backend now retains the last lines too,
 * and `hydrateServerLog` asks for them on startup.
 */
export const serverLog = writable<ServerLogEntry[]>([]);

/** Lines kept before the oldest are dropped. Matches `SERVER_LOG_HISTORY` in
 *  `src-tauri/src/network/mod.rs`; there is no point retaining more there than
 *  is shown here. */
const MAX_ENTRIES = 200;

let nextId = 1;

/** Drop the oldest entries once over cap. */
function capped(entries: ServerLogEntry[]): ServerLogEntry[] {
  return entries.length > MAX_ENTRIES ? entries.slice(entries.length - MAX_ENTRIES) : entries;
}

/**
 * Record a line.
 *
 * `line` carries the backend's sequence number and timestamp when the line came
 * from the backend. Called without one — as the Servers page does for its own
 * progress messages — the line is stamped on arrival and has no sequence.
 */
export function appendServerLog(message: string, line?: ServerLogLine): void {
  if (!message) return;
  const entry: ServerLogEntry = {
    id: nextId++,
    at: line?.at ?? Date.now(),
    message,
    seq: line?.seq,
  };
  serverLog.update((entries) => capped([...entries, entry]));
}

/**
 * Merge the backend's retained log into the store.
 *
 * Runs after the `server-log` listener is registered, so that nothing emitted
 * in between is missed; the overlap that creates is what `seq` is for. Ordering
 * is by timestamp, which interleaves the replayed lines with any the UI wrote
 * itself correctly, with `seq` breaking ties within a millisecond.
 */
export function hydrateServerLog(history: ServerLogLine[]): void {
  if (history.length === 0) return;
  serverLog.update((entries) => {
    const held = new Set(entries.map((e) => e.seq).filter((seq) => seq !== undefined));
    const merged = [...entries];
    for (const line of history) {
      if (held.has(line.seq)) continue;
      merged.push({ id: nextId++, at: line.at, message: line.message, seq: line.seq });
    }
    merged.sort((a, b) => a.at - b.at || (a.seq ?? 0) - (b.seq ?? 0));
    return capped(merged);
  });
}

export function clearServerLog(): void {
  serverLog.set([]);
}
