import { writable } from 'svelte/store';
import { check, type Update } from '@tauri-apps/plugin-updater';
import { relaunch } from '@tauri-apps/plugin-process';
import * as m from '$lib/paraglide/messages';

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

export type UpdateCheckFrequency = 'daily' | 'weekly' | 'monthly';

const FREQUENCY_MS: Record<UpdateCheckFrequency, number> = {
  daily: 24 * 60 * 60 * 1000,
  weekly: 7 * 24 * 60 * 60 * 1000,
  monthly: 30 * 24 * 60 * 60 * 1000,
};

// When the automatic startup check last ran, kept in the webview's
// localStorage rather than in `AppSettings`/config.json: it's a bookkeeping
// cache ("did we already check recently?"), not a user preference, and the
// entire update-check flow already lives on the frontend with no backend
// awareness of checks at all (see the module doc above). A manual check
// from Settings → About also updates it, since that makes an automatic
// check redundant until the configured interval elapses again.
const LAST_CHECK_STORAGE_KEY = 'ember.updater.lastCheckedAt';
const DISMISSED_VERSION_STORAGE_KEY = 'ember.updater.dismissedVersion';

function readLastCheckedAt(): number {
  try {
    const raw = localStorage.getItem(LAST_CHECK_STORAGE_KEY);
    const parsed = raw === null ? NaN : Number(raw);
    return Number.isFinite(parsed) ? parsed : 0;
  } catch {
    // Storage unavailable (private mode / disabled) — treat as "never
    // checked" so callers fall back to a safe (if more frequent) default.
    return 0;
  }
}

function recordCheckedNow(): void {
  try {
    localStorage.setItem(LAST_CHECK_STORAGE_KEY, String(Date.now()));
  } catch {
    // Quota or storage failure — worst case we check more often than the
    // configured frequency on this device; not worth surfacing to the user.
  }
}

function readDismissedVersion(): string | null {
  try {
    return localStorage.getItem(DISMISSED_VERSION_STORAGE_KEY);
  } catch {
    return null;
  }
}

function recordDismissedVersion(version: string): void {
  try {
    localStorage.setItem(DISMISSED_VERSION_STORAGE_KEY, version);
  } catch {
    // In-memory dismissal still works for this session.
  }
}

/**
 * True when no check has ever been recorded, or enough time has passed
 * since the last one (manual or silent) for the given `frequency`. The
 * startup flow in `+layout.svelte` uses this to decide whether the silent
 * background check should run at all this launch.
 */
export function isUpdateCheckDue(frequency: UpdateCheckFrequency): boolean {
  const last = readLastCheckedAt();
  if (last <= 0) return true;
  return Date.now() - last >= FREQUENCY_MS[frequency];
}

// Module-private handle to the pending update. Kept out of the store because
// it's a non-serializable Tauri `Resource` (and we only ever need the latest).
let pending: Update | null = null;

// Guards against a second `installUpdate()` entering before the first has
// flipped the phase to `downloading`. A Tauri `Update` resource is not safe to
// `downloadAndInstall` concurrently, so a double-click on "Install" could
// otherwise corrupt the download / surface a spurious error.
let installInFlight = false;
let retryAction: 'check' | 'install' | 'relaunch' = 'check';

/** True while `checkForUpdates` is awaiting the plugin `check()` call. */
let checkInFlight = false;

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
 * Every call (silent or manual) records "checked now" for
 * {@link isUpdateCheckDue}, regardless of outcome — an attempt counts even
 * if it fails, matching how "check weekly" is normally understood (retry
 * roughly on that cadence, not on every launch just because the last
 * attempt happened to fail).
 *
 * Returns true when an update is available.
 */
export async function checkForUpdates(opts: { silent?: boolean } = {}): Promise<boolean> {
  // Never run while a download/install is in progress: `disposePending()`
  // below would `close()` the very `Update` resource `installUpdate()` is
  // mid-way through streaming, aborting it. A check during install is a no-op.
  // Also skip when another check is already in flight — a second entry would
  // dispose the first check's result (or the currently-available pending).
  if (installInFlight || checkInFlight) return false;
  checkInFlight = true;
  // Keep an existing `available` pending until the new check succeeds, so a
  // failed/empty re-check doesn't wipe the Install button's resource.
  const keepPendingUntilSuccess = pending != null;
  recordCheckedNow();
  updater.update((s) => ({ ...s, phase: 'checking', error: null }));
  try {
    const found = await check();
    if (found) {
      await disposePending();
      pending = found;
      updater.set({
        phase: 'available',
        version: found.version,
        notes: found.body ?? null,
        date: found.date ?? null,
        downloaded: 0,
        total: null,
        error: null,
        dismissed: readDismissedVersion() === found.version,
      });
      return true;
    }
    if (keepPendingUntilSuccess && pending) {
      // Empty re-check: keep the Install resource rather than wiping a
      // previously-available update (manifest flap / transient empty).
      updater.update((s) => ({
        ...s,
        phase: 'available',
        error: null,
      }));
      return true;
    }
    await disposePending();
    updater.set({ ...INITIAL, phase: opts.silent ? 'idle' : 'uptodate' });
    return false;
  } catch (e) {
    retryAction = 'check';
    if (keepPendingUntilSuccess && pending) {
      // Re-check failed but we still have a usable Update resource — restore
      // the available phase instead of disposing it.
      updater.update((s) => ({
        ...s,
        phase: 'available',
        error: opts.silent ? s.error : toMessage(e),
      }));
    } else if (opts.silent) {
      updater.set({ ...INITIAL, phase: 'idle' });
    } else {
      updater.update((s) => ({ ...s, phase: 'error', error: toMessage(e) }));
    }
    return false;
  } finally {
    checkInFlight = false;
  }
}

/**
 * Download and install the pending update, streaming progress into the store.
 * On success the phase becomes `ready`; the caller (or the user, via the
 * banner) then triggers {@link restartToUpdate}.
 */
export async function installUpdate(): Promise<void> {
  if (installInFlight) return;
  if (!pending) {
    retryAction = 'check';
    updater.update((s) => ({
      ...s,
      phase: 'error',
      error: m.updater_no_staged_update(),
    }));
    return;
  }
  installInFlight = true;
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
    // The update is staged on disk now; the relaunch is driven by
    // `relaunch()`, not this handle. Release the `Update` resource here
    // instead of leaking it until the next `checkForUpdates()`. (Only on
    // success — the error path keeps `pending` so the Retry button can reuse
    // it.)
    await disposePending();
  } catch (e) {
    retryAction = 'install';
    updater.update((s) => ({ ...s, phase: 'error', error: toMessage(e) }));
  } finally {
    installInFlight = false;
  }
}

/** Restart the app to apply an installed update. */
export async function restartToUpdate(): Promise<void> {
  try {
    await relaunch();
  } catch (e) {
    retryAction = 'relaunch';
    updater.update((s) => ({ ...s, phase: 'error', error: toMessage(e) }));
  }
}

/** Retry the action that produced the current update error. */
export async function retryUpdate(): Promise<void> {
  if (retryAction === 'relaunch') {
    await restartToUpdate();
  } else if (retryAction === 'install' && pending) {
    await installUpdate();
  } else {
    await checkForUpdates();
  }
}

/** Hide the banner for the current version without cancelling anything. */
export function dismissNotice(): void {
  updater.update((s) => {
    if (s.version) recordDismissedVersion(s.version);
    return { ...s, dismissed: true };
  });
}
