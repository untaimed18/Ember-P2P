import { get, writable } from 'svelte/store';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import * as m from '$lib/paraglide/messages';
import { notify } from '$lib/notifications';
import { addToast, toast } from '$lib/stores/toast';

/**
 * Silent updates, as the backend runs them (`auto_update::silent`).
 *
 * The backend decides everything — when an update is ready, when Ember is
 * idle, when the countdown ends — because a webview hidden in the tray is
 * throttled and cannot keep time. This store mirrors what it publishes and
 * carries the user's answers back.
 */

export type SilentUpdatePhase =
  | 'off'
  | 'idle'
  | 'preparing'
  | 'waiting'
  | 'postponed'
  | 'held'
  | 'countdown'
  | 'installing';

export type SilentUpdateUnsupported = 'deb' | 'msi' | 'other';

export interface SilentUpdateStatus {
  supported: boolean;
  unsupportedReason: SilentUpdateUnsupported | null;
  enabled: boolean;
  phase: SilentUpdatePhase;
  version: string | null;
  /** Unix milliseconds. */
  countdownEndsAt: number | null;
  /** Unix milliseconds. */
  postponedUntil: number | null;
  lastSuccess: { from: string; to: string; at: number } | null;
  /** Ready for a week without a quiet moment. */
  waitingLong: boolean;
  /** The last attempt to download the update failed; retried hourly. */
  prepareFailed: boolean;
}

interface UpdateOutcome {
  reason: 'silent' | 'manual';
  fromVersion: string;
  targetVersion: string;
  installed: boolean;
}

const STATUS_EVENT = 'ember:silent-update';
/** A countdown gave way to a transfer or local work. Leaving it for any other
 *  reason, such as the machine sleeping, says nothing. */
const BUSY_EVENT = 'ember:silent-update-busy';

export const silentUpdate = writable<SilentUpdateStatus | null>(null);

/**
 * Whether silent updates will take care of the update on offer, so the
 * ordinary "update available" notice can stay out of the way. True only while
 * it is actually going to happen: switched on, possible here, not held or
 * postponed, and not stuck failing to download.
 */
export function silentUpdateHandlesIt(status: SilentUpdateStatus | null): boolean {
  if (!status || !status.enabled || !status.supported || status.prepareFailed) return false;
  return (
    status.phase === 'preparing'
    || status.phase === 'waiting'
    || status.phase === 'countdown'
    || status.phase === 'installing'
  );
}

function apply(next: SilentUpdateStatus) {
  const previous = get(silentUpdate);
  silentUpdate.set(next);
  if (next.phase === 'countdown' && previous?.phase !== 'countdown') {
    // The dialog covers a window someone is looking at; this reaches one in
    // the tray or behind other windows. `notify` skips it when Ember is the
    // focused window and the user asked for that.
    void notify('silent_update', m.silent_update_notify_title(), m.silent_update_notify_body());
  }
  if (previous?.phase === 'installing' && next.phase === 'held') {
    // The install failed before Ember closed, so nothing else will say so.
    const version = next.version ?? '';
    whenVisible(() => addToast('warning', m.silent_update_failed({ version }), 0));
  }
}

/** Load the current state and follow the backend's changes to it. */
export async function initSilentUpdate(): Promise<UnlistenFn> {
  const [unlistenStatus, unlistenBusy] = await Promise.all([
    listen<SilentUpdateStatus>(STATUS_EVENT, (event) => apply(event.payload)),
    listen(BUSY_EVENT, () => toast(m.silent_update_aborted())),
  ]);
  try {
    apply(await invoke<SilentUpdateStatus>('get_silent_update_status'));
  } catch (e) {
    console.warn('silent update: could not load the status', e);
  }
  return () => {
    unlistenStatus();
    unlistenBusy();
  };
}

export function silentUpdateNow(): Promise<void> {
  return invoke('silent_update_now');
}

export function silentUpdatePostpone(): Promise<void> {
  return invoke('silent_update_postpone');
}

export function silentUpdateSkip(version: string): Promise<void> {
  return invoke('silent_update_skip', { version });
}

export function silentUpdateResume(): Promise<void> {
  return invoke('silent_update_resume');
}

/** Run `show` once the window is on screen, so a notice raised while Ember sat
 *  in the tray is not dismissed on a timer before anyone could read it. */
function whenVisible(show: () => void) {
  if (document.visibilityState === 'visible') {
    show();
    return;
  }
  const onVisible = () => {
    if (document.visibilityState !== 'visible') return;
    document.removeEventListener('visibilitychange', onVisible);
    show();
  };
  document.addEventListener('visibilitychange', onVisible);
}

/**
 * Say how the silent update this launch came back from turned out: installed
 * while the user was away, or not, in which case it will not be retried
 * silently. Nothing on an ordinary launch or after a manual install.
 */
export async function reportUpdateOutcome(): Promise<void> {
  let outcome: UpdateOutcome | null;
  try {
    outcome = await invoke<UpdateOutcome | null>('take_update_outcome');
  } catch {
    return;
  }
  if (!outcome) return;
  const version = outcome.targetVersion;
  whenVisible(() => {
    if (outcome.installed) addToast('success', m.silent_update_done({ version }), 12_000);
    // Stays until dismissed: it is the only sign the update did not happen.
    else addToast('warning', m.silent_update_failed({ version }), 0);
  });
}
