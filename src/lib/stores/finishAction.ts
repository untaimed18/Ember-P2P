import { get, writable } from 'svelte/store';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import * as m from '$lib/paraglide/messages';
import { notify } from '$lib/notifications';
import { toastWarning } from '$lib/stores/toast';

/**
 * "When downloads finish", as the backend runs it (`finish_action.rs`). The
 * backend watches the list and keeps the countdown, because a webview hidden
 * in the tray is throttled and cannot keep time; this mirrors what it
 * publishes and carries the user's answers back. Nothing is saved: every
 * launch starts at doing nothing.
 */

export type FinishAction = 'none' | 'exit' | 'sleep';

export interface FinishActionStatus {
  action: FinishAction;
  sleepSupported: boolean;
  /** Armed, but no download has run since, so nothing is being waited on. */
  waitingForDownloads: boolean;
  /** Unix milliseconds. */
  countdownEndsAt: number | null;
}

const STATUS_EVENT = 'ember:finish-action';
const SLEEP_FAILED_EVENT = 'ember:finish-action-sleep-failed';

export const finishAction = writable<FinishActionStatus | null>(null);

/** The countdown the notification was sent for, kept across a reload of the
 *  page so the same countdown is not announced twice. */
const NOTIFIED_KEY = 'ember-finish-action-notified';

function alreadyNotified(endsAt: number): boolean {
  try {
    return sessionStorage.getItem(NOTIFIED_KEY) === String(endsAt);
  } catch {
    return false;
  }
}

function markNotified(endsAt: number) {
  try {
    sessionStorage.setItem(NOTIFIED_KEY, String(endsAt));
  } catch {
    // Announced again after a reload at worst.
  }
}

function apply(next: FinishActionStatus) {
  const previous = get(finishAction);
  finishAction.set(next);
  const endsAt = next.countdownEndsAt;
  if (endsAt !== null && previous?.countdownEndsAt !== endsAt && !alreadyNotified(endsAt)) {
    markNotified(endsAt);
    // The dialog covers a window someone is looking at; this reaches one in
    // the tray or behind other windows.
    void notify(
      'finish_action',
      m.finish_action_notify_title(),
      next.action === 'sleep' ? m.finish_action_notify_sleep() : m.finish_action_notify_exit(),
    );
  }
}

export async function initFinishAction(): Promise<UnlistenFn> {
  // An event that lands while the first read is in flight is newer than
  // whatever that read returns.
  let heard = false;
  const unlistenStatus = await listen<FinishActionStatus>(STATUS_EVENT, (event) => {
    heard = true;
    apply(event.payload);
  });
  const unlistenFailed = await listen(SLEEP_FAILED_EVENT, () => {
    toastWarning(m.finish_action_sleep_failed());
    void notify('finish_action', m.finish_action_notify_title(), m.finish_action_sleep_failed());
  });
  try {
    const status = await invoke<FinishActionStatus>('get_finish_action');
    if (!heard) apply(status);
  } catch (e) {
    console.warn('finish action: could not load the status', e);
  }
  return () => {
    unlistenStatus();
    unlistenFailed();
  };
}

export async function setFinishAction(action: FinishAction): Promise<void> {
  apply(await invoke<FinishActionStatus>('set_finish_action', { action }));
}

export async function cancelFinishAction(): Promise<void> {
  apply(await invoke<FinishActionStatus>('cancel_finish_action'));
}

export async function runFinishActionNow(): Promise<void> {
  apply(await invoke<FinishActionStatus>('run_finish_action_now'));
}
