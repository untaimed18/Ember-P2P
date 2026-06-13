import { writable } from 'svelte/store';
import { check, type Update } from '@tauri-apps/plugin-updater';
import { relaunch } from '@tauri-apps/plugin-process';

// Shared auto-update state. Both the corner `UpdateNotice` banner and the
// Settings → About card read and drive this single store, so a check started
// from one place is reflected in the other and there's exactly one in-flight
// `Update` resource at a time.

export type UpdaterPhase =
  | 'idle' // no check run yet, or last check found nothing
  | 'checking'
  | 'available' // an update exists, not yet downloading
  | 'downloading'
  | 'installing'
  | 'ready' // installed on disk, waiting for the user to relaunch
  | 'uptodate' // last manual check confirmed we're current
  | 'error';

export interface UpdaterState {
  phase: UpdaterPhase;
  /** Version string of the available/installed update (null when none). */
  version: string | null;
  /** Release notes (manifest `body`), if provided. */
  notes: string | null;
  /** Release date (manifest `date`), if provided. */
  date: string | null;
  /** Bytes downloaded so far in the current download. */
  downloaded: number;
  /** Total bytes to download, when the server reported a content length. */
  total: number | null;
  /** Human-readable error from the last failed check/download. */
  error: string | null;
  /** Set when the user dismisses the banner for the current version. */
  dismissed: boolean;
}

const INITIAL: UpdaterState = {
  phase: 'idle',
  version: null,
  notes: null,
  date: null,
  downloaded: 0,
  total: null,
  error: null,
  dismissed: false,
};

export const updater = writable<UpdaterState>({ ...INITIAL });

// Module-private handle to the pending update. Kept out of the store because
// it's a non-serializable Tauri `Resource` (and we only ever need the latest).
let pending: Update | null = null;

async function disposePending(): Promise<void> {
  if (!pending) return;
  const stale = pending;
  pending = null;
  try {
    await stale.close();
  } catch {
    // The resource may already be consumed by install; ignore.
  }
}

function toMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === 'string') return e;
  return String(e);
}

/**
 * Check the configured endpoint for a newer version.
 *
 * `silent` (used by the startup check) swallows failures back to `idle` so a
 * missing network / unreachable manifest never surfaces UI noise. A manual
 * check leaves the error in the store for the Settings card to display.
 *
 * Returns true when an update is available.
 */
export async function checkForUpdates(opts: { silent?: boolean } = {}): Promise<boolean> {
  await disposePending();
  updater.update((s) => ({ ...s, phase: 'checking', error: null }));
  try {
    const found = await check();
    if (found) {
      pending = found;
      updater.set({
        phase: 'available',
        version: found.version,
        notes: found.body ?? null,
        date: found.date ?? null,
        downloaded: 0,
        total: null,
        error: null,
        dismissed: false,
      });
      return true;
    }
    updater.set({ ...INITIAL, phase: opts.silent ? 'idle' : 'uptodate' });
    return false;
  } catch (e) {
    if (opts.silent) {
      updater.set({ ...INITIAL, phase: 'idle' });
    } else {
      updater.update((s) => ({ ...s, phase: 'error', error: toMessage(e) }));
    }
    return false;
  }
}

/**
 * Download and install the pending update, streaming progress into the store.
 * On success the phase becomes `ready`; the caller (or the user, via the
 * banner) then triggers {@link restartToUpdate}.
 */
export async function installUpdate(): Promise<void> {
  if (!pending) return;
  updater.update((s) => ({ ...s, phase: 'downloading', downloaded: 0, total: null, error: null }));
  let downloaded = 0;
  let total: number | null = null;
  try {
    await pending.downloadAndInstall((event) => {
      switch (event.event) {
        case 'Started':
          total = event.data.contentLength ?? null;
          updater.update((s) => ({ ...s, phase: 'downloading', total, downloaded: 0 }));
          break;
        case 'Progress':
          downloaded += event.data.chunkLength;
          updater.update((s) => ({ ...s, downloaded }));
          break;
        case 'Finished':
          updater.update((s) => ({ ...s, phase: 'installing' }));
          break;
      }
    });
    updater.update((s) => ({ ...s, phase: 'ready' }));
  } catch (e) {
    updater.update((s) => ({ ...s, phase: 'error', error: toMessage(e) }));
  }
}

/** Restart the app to apply an installed update. */
export async function restartToUpdate(): Promise<void> {
  await relaunch();
}

/** Hide the banner for the current version without cancelling anything. */
export function dismissNotice(): void {
  updater.update((s) => ({ ...s, dismissed: true }));
}
