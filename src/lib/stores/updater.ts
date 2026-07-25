import { writable } from 'svelte/store';
import { Channel, invoke } from '@tauri-apps/api/core';
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
  /** Signed updater security epoch for this update (null when none/unknown). */
  securityEpoch: number | null;
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
  /** Set when the user dismisses the banner for this epoch/version identity. */
  dismissed: boolean;
}

interface SecureUpdateInfo {
  version: string;
  securityEpoch: number;
  notes: string | null;
  date: string | null;
}

interface SecureUpdateCheckResult {
  update: SecureUpdateInfo | null;
  pendingRetained: boolean;
  error?: string | null;
}

type SecureUpdateProgress =
  | { event: 'Started'; data: { contentLength: number } }
  | { event: 'Progress'; data: { chunkLength: number } }
  | { event: 'Finished' };

const INITIAL: UpdaterState = {
  phase: 'idle',
  version: null,
  securityEpoch: null,
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
const DISMISSED_UPDATE_STORAGE_KEY = 'ember.updater.dismissedUpdate';
const LEGACY_DISMISSED_VERSION_STORAGE_KEY = 'ember.updater.dismissedVersion';

interface DismissedUpdateIdentity {
  securityEpoch: number;
  version: string;
}

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

function normalizeSecurityEpoch(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
    ? value
    : null;
}

function readDismissedUpdate(): DismissedUpdateIdentity | null {
  try {
    const raw = localStorage.getItem(DISMISSED_UPDATE_STORAGE_KEY);
    if (raw !== null) {
      try {
        const parsed = JSON.parse(raw) as Partial<DismissedUpdateIdentity>;
        const securityEpoch = normalizeSecurityEpoch(parsed.securityEpoch);
        if (securityEpoch !== null && typeof parsed.version === 'string' && parsed.version) {
          return { securityEpoch, version: parsed.version };
        }
      } catch {
        // Ignore a corrupt new-format value and try the legacy key below.
      }
    }

    // Version-only dismissals predate epoch-aware updates. Model them as
    // epoch 0 so they can still hide a legacy epoch-0 result, but can never
    // suppress a newer security epoch that reuses an equal/lower version.
    const legacyVersion = localStorage.getItem(LEGACY_DISMISSED_VERSION_STORAGE_KEY);
    return legacyVersion ? { securityEpoch: 0, version: legacyVersion } : null;
  } catch {
    return null;
  }
}

function isUpdateDismissed(securityEpoch: number | null, version: string): boolean {
  if (securityEpoch === null) return false;
  const dismissed = readDismissedUpdate();
  return dismissed?.securityEpoch === securityEpoch && dismissed.version === version;
}

function recordDismissedUpdate(securityEpoch: number, version: string): void {
  try {
    localStorage.setItem(
      DISMISSED_UPDATE_STORAGE_KEY,
      JSON.stringify({ securityEpoch, version } satisfies DismissedUpdateIdentity),
    );
    // The tuple is now authoritative. Removing the old key prevents a future
    // storage fallback from reviving a stale version-only dismissal.
    localStorage.removeItem(LEGACY_DISMISSED_VERSION_STORAGE_KEY);
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

// The native updater service owns the non-serializable, signed Update handle.
// The renderer only tracks whether that service has a verified pending update;
// it cannot supply URLs, targets, proxies, or downgrade options.
let pending = false;

// Guards against a second `installUpdate()` entering before the first has
// flipped the phase to `downloading`. A Tauri `Update` resource is not safe to
// `downloadAndInstall` concurrently, so a double-click on "Install" could
// otherwise corrupt the download / surface a spurious error.
let installInFlight = false;
let retryAction: 'check' | 'install' | 'relaunch' = 'check';

/** True while `checkForUpdates` is awaiting the plugin `check()` call. */
let checkInFlight = false;

async function disposePending(): Promise<void> {
  pending = false;
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
  recordCheckedNow();
  updater.update((s) => ({ ...s, phase: 'checking', error: null }));
  try {
    const result = await invoke<SecureUpdateCheckResult>('secure_updater_check');
    const found = result.update;
    if (found) {
      // Native retention is authoritative: empty re-checks and check errors that
      // still keep a verified artifact re-offer UpdateInfo so Install survives
      // even after a prior IPC failure cleared the local pending flag.
      pending = true;
      const securityEpoch = normalizeSecurityEpoch(found.securityEpoch);
      updater.set({
        phase: 'available',
        version: found.version,
        securityEpoch,
        notes: found.notes,
        date: found.date,
        downloaded: 0,
        total: null,
        error: opts.silent ? null : (result.error ?? null),
        // Unknown/malformed epoch metadata must fail visible, never reuse a
        // potentially stale dismissal identity.
        dismissed: isUpdateDismissed(securityEpoch, found.version),
      });
      return true;
    }
    await disposePending();
    if (result.error && !opts.silent) {
      retryAction = 'check';
      updater.update((s) => ({
        ...s,
        phase: 'error',
        error: result.error ?? null,
      }));
      return false;
    }
    updater.set({ ...INITIAL, phase: opts.silent ? 'idle' : 'uptodate' });
    return false;
  } catch (e) {
    retryAction = 'check';
    // Hard invoke failures (IPC) leave native state unknown — fail closed on
    // the Install affordance rather than offering a possibly-cleared artifact.
    // A later successful check rehydrates from pendingRetained + update metadata.
    await disposePending();
    if (opts.silent) {
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
    const onEvent = new Channel<SecureUpdateProgress>();
    onEvent.onmessage = (event) => {
      switch (event.event) {
        case 'Started':
          total = event.data.contentLength;
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
    };
    await invoke('secure_updater_install', { onEvent });
    updater.update((s) => ({ ...s, phase: 'ready' }));
    // The native service consumed its verified Update only after successful
    // artifact hash/signature checks and installation. Keep retry state only
    // on the error path.
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

/** Hide the banner for the current epoch/version without cancelling anything. */
export function dismissNotice(): void {
  updater.update((s) => {
    if (s.version && s.securityEpoch !== null) {
      recordDismissedUpdate(s.securityEpoch, s.version);
    }
    return { ...s, dismissed: true };
  });
}
