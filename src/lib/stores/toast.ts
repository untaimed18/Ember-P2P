import { get, writable } from 'svelte/store';

export interface ToastAction {
  label: string;
  run: () => void;
  /** Takes back something already done, so Ctrl+Z can reach it. */
  undo?: boolean;
}

export interface ToastItem {
  id: number;
  type: 'success' | 'error' | 'warning' | 'info';
  message: string;
  action?: ToastAction;
}

let nextId = 0;
/** Called once when a toast with an action leaves without the action being
 *  taken — on its timer, on ×, or by `flushToastActions`. */
const toastExpiry = new Map<number, () => void | Promise<unknown>>();
/** Ids whose action is an Undo, while it can still be taken. */
const undoToasts = new Set<number>();
/** What expiring toasts started (the cancels and removals they held back),
 *  until it settles. An exit has to wait for these too. */
const inFlight = new Set<Promise<unknown>>();

let pendingUndoListener: ((pending: boolean) => void) | null = null;
let reportedPending = false;

function undoPending(): boolean {
  return undoToasts.size > 0 || inFlight.size > 0;
}

function reportPending() {
  const pending = undoPending();
  if (pending === reportedPending) return;
  reportedPending = pending;
  pendingUndoListener?.(pending);
}

/** Told whenever something an Undo held back starts waiting or has finished
 *  being sent, so an exit decided outside the window knows to let it finish. */
export function onPendingUndoChange(listener: ((pending: boolean) => void) | null) {
  pendingUndoListener = listener;
  reportedPending = undoPending();
  listener?.(reportedPending);
}

function setUndoPending(id: number, pending: boolean) {
  if (pending) undoToasts.add(id);
  else undoToasts.delete(id);
  reportPending();
}
const toastTimers = new Map<number, ReturnType<typeof setTimeout>>();
/** Ids added with `durationMs = 0`. These are notices the user is meant to
 *  acknowledge (consent prompts, fatal failures), so they are never dismissed
 *  on a timer and the queue cap evicts them last. */
const stickyToasts = new Set<number>();

export const toasts = writable<ToastItem[]>([]);

/** Most toasts on screen at once. Event-driven callers burst: one misbehaving
 *  backend emits `network-warning` repeatedly and the network store toasts on
 *  every one. Past a handful the stack stops being readable well before it
 *  stops being rendered. */
const MAX_TOASTS = 5;

/** Remaining auto-dismiss budget per toast, so a paused timer can be resumed
 *  with the time it had left rather than restarting from full. */
const toastRemaining = new Map<number, { durationMs: number; startedAt: number }>();
/** Set while the pointer or keyboard focus is inside the stack. */
let dismissPaused = false;

function clearToastTimer(id: number) {
  const timer = toastTimers.get(id);
  if (timer) { clearTimeout(timer); toastTimers.delete(id); }
  stickyToasts.delete(id);
  toastRemaining.delete(id);
}

function armToastTimer(id: number, durationMs: number) {
  toastRemaining.set(id, { durationMs, startedAt: Date.now() });
  if (dismissPaused) return;
  toastTimers.set(id, setTimeout(() => removeToast(id), durationMs));
}

/**
 * Hold every auto-dismiss while the user is reading the stack.
 *
 * An error toast lives 8 seconds, which is not long for a backend message the
 * reader has to parse — and it used to vanish mid-sentence with no way to get it
 * back, since nothing keeps a history. Hovering or tabbing into the stack now
 * freezes the countdown and leaving resumes it with whatever was left, so
 * reading never costs the message.
 */
export function pauseToastDismiss() {
  if (dismissPaused) return;
  dismissPaused = true;
  const now = Date.now();
  for (const [id, timer] of toastTimers) {
    clearTimeout(timer);
    const budget = toastRemaining.get(id);
    if (!budget) continue;
    const left = budget.durationMs - (now - budget.startedAt);
    // Floor rather than zero: a toast whose time ran out while the pointer was
    // over it should still be readable for a moment after the pointer leaves.
    toastRemaining.set(id, { durationMs: Math.max(left, 1200), startedAt: now });
  }
  toastTimers.clear();
}

export function resumeToastDismiss() {
  if (!dismissPaused) return;
  dismissPaused = false;
  const now = Date.now();
  for (const [id, budget] of toastRemaining) {
    if (stickyToasts.has(id)) continue;
    toastRemaining.set(id, { durationMs: budget.durationMs, startedAt: now });
    toastTimers.set(id, setTimeout(() => removeToast(id), budget.durationMs));
  }
}

function expire(id: number): void | Promise<unknown> {
  const onExpire = toastExpiry.get(id);
  toastExpiry.delete(id);
  const result = onExpire?.();
  if (result instanceof Promise) {
    const settled: Promise<unknown> = result.catch(() => {}).finally(() => {
      inFlight.delete(settled);
      reportPending();
    });
    inFlight.add(settled);
  }
  // After the in-flight entry, so the pending state never dips to false
  // between the toast going and its commit starting.
  setUndoPending(id, false);
  return result;
}

/**
 * A toast offering one action, such as Undo. Exactly one of `action.run` and
 * `onExpire` is called: the action if the user takes it, otherwise `onExpire`
 * once the toast is gone for any reason. The countdown pauses with the others
 * while the stack is hovered, so reading the toast never costs the chance to
 * take the action.
 */
export function addActionToast(
  type: ToastItem['type'],
  message: string,
  action: ToastAction,
  onExpire: () => void | Promise<unknown>,
  durationMs = 8000,
) {
  const id = nextId++;
  const wrapped: ToastAction = {
    label: action.label,
    undo: action.undo,
    run: () => {
      if (!toastExpiry.delete(id)) return;
      setUndoPending(id, false);
      removeToast(id);
      action.run();
    },
  };
  toastExpiry.set(id, onExpire);
  if (action.undo) setUndoPending(id, true);
  return pushToast(id, { id, type, message, action: wrapped }, durationMs);
}

/** Reword a toast still on screen, when what it is about has changed. */
export function setToastMessage(id: number, message: string) {
  toasts.update((t) => t.map((x) => (x.id === id ? { ...x, message } : x)));
}

/** Take the newest Undo still on offer. Returns whether there was one. */
export function runLatestUndo(): boolean {
  const latest = [...undoToasts].pop();
  if (latest === undefined) return false;
  const item = get(toasts).find((t) => t.id === latest);
  if (!item?.action) return false;
  item.action.run();
  return true;
}

/**
 * Let every toast still offering an action expire now, and wait for what
 * expiring does — the cancels and removals behind Undo toasts — to finish.
 * For exit: nothing behind an Undo reaches the backend until then.
 */
export async function flushToastActions(): Promise<void> {
  for (const id of [...toastExpiry.keys()]) {
    clearToastTimer(id);
    toasts.update((t) => t.filter((x) => x.id !== id));
    expire(id);
  }
  // Including commits that started on their own timer before this was asked.
  await Promise.allSettled([...inFlight]);
}

/** `flushToastActions` for an exit or restart, which waits for it only so
 *  long: a backend that stopped answering must not keep Ember from closing. */
export async function flushToastActionsBeforeExit(timeoutMs = 3500): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  await Promise.race([
    flushToastActions(),
    new Promise<void>((resolve) => { timer = setTimeout(resolve, timeoutMs); }),
  ]);
  clearTimeout(timer);
}

export function addToast(type: ToastItem['type'], message: string, durationMs = 5000) {
  const id = nextId++;
  return pushToast(id, { id, type, message }, durationMs);
}

function pushToast(id: number, item: ToastItem, durationMs: number) {
  if (durationMs <= 0) stickyToasts.add(id);
  const evicted: number[] = [];
  toasts.update((t) => {
    const next = [...t, item];
    while (next.length > MAX_TOASTS) {
      // Drop the oldest dismissable toast, so a burst of warnings can't
      // quietly swallow a consent notice. A sticky notice goes only to make
      // room for another one: it may be the only time it is ever shown. A
      // toast still offering an action is never dropped: expiring it runs what
      // it offered to hold back, early. Failing all that, the stack runs over.
      const evictable = (x: ToastItem) => !toastExpiry.has(x.id) && x.id !== id;
      let idx = next.findIndex((x) => evictable(x) && !stickyToasts.has(x.id));
      if (idx === -1 && durationMs <= 0) idx = next.findIndex(evictable);
      if (idx === -1) break;
      const [removed] = next.splice(idx, 1);
      evicted.push(removed.id);
    }
    return next;
  });
  for (const evictedId of evicted) {
    clearToastTimer(evictedId);
    expire(evictedId);
  }
  // No timer for a sticky toast. Both callers that pass 0 depend on it: the
  // Ember-default-on notice comes from a one-shot backend latch that is spent
  // as soon as it resolves, so auto-dismissing it loses the only consent
  // notice the user will ever get, and the UPnP failure warning only re-fires
  // when `mapped` changes, so it would not come back either.
  if (durationMs > 0) {
    armToastTimer(id, durationMs);
  }
  return id;
}

export function removeToast(id: number) {
  clearToastTimer(id);
  let remaining = 0;
  toasts.update((t) => {
    const next = t.filter((x) => x.id !== id);
    remaining = next.length;
    return next;
  });
  // Dismissing the last toast unmounts the container, and `mouseleave` does not
  // fire for an element removed from under the pointer — so closing the final
  // toast by clicking its × while hovering would latch the pause on and leave
  // the *next* toast with no timer at all. Nothing is left to hover, so drop it.
  if (remaining === 0) dismissPaused = false;
  expire(id);
}

export function clearAllToasts() {
  for (const timer of toastTimers.values()) clearTimeout(timer);
  toastTimers.clear();
  stickyToasts.clear();
  toastRemaining.clear();
  // The stack is gone, so a pointer that was over it is not over anything any
  // more; leaving this latched would suppress the next toast's timer entirely.
  dismissPaused = false;
  toasts.set([]);
  const pending = [...toastExpiry.keys()];
  for (const id of pending) expire(id);
}

export function toast(message: string) { addToast('info', message); }
export function toastSuccess(message: string) { addToast('success', message); }
export function toastError(message: string) { addToast('error', message, 8000); }
export function toastWarning(message: string) { addToast('warning', message, 6000); }
