import { get, writable } from 'svelte/store';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import * as m from '$lib/paraglide/messages';
import { notify } from '$lib/notifications';

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

export const finishAction = writable<FinishActionStatus | null>(null);

function apply(next: FinishActionStatus) {
  const previous = get(finishAction);
  finishAction.set(next);
  if (next.countdownEndsAt !== null && previous?.countdownEndsAt == null) {
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
  const unlisten = await listen<FinishActionStatus>(STATUS_EVENT, (event) => apply(event.payload));
  try {
    apply(await invoke<FinishActionStatus>('get_finish_action'));
  } catch (e) {
    console.warn('finish action: could not load the status', e);
  }
  return unlisten;
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
