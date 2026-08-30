import { writable } from 'svelte/store';

export interface ToastItem {
  id: number;
  type: 'success' | 'error' | 'warning' | 'info';
  message: string;
}

let nextId = 0;
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

export function addToast(type: ToastItem['type'], message: string, durationMs = 5000) {
  const id = nextId++;
  if (durationMs <= 0) stickyToasts.add(id);
  const evicted: number[] = [];
  toasts.update((t) => {
    const next = [...t, { id, type, message }];
    while (next.length > MAX_TOASTS) {
      // Drop the oldest dismissable toast. Only when every entry is sticky
      // does the oldest sticky one go, so a burst of warnings can't quietly
      // swallow a consent notice.
      let idx = next.findIndex((x) => !stickyToasts.has(x.id));
      if (idx === -1 || next[idx].id === id) idx = 0;
      const [removed] = next.splice(idx, 1);
      evicted.push(removed.id);
    }
    return next;
  });
  for (const evictedId of evicted) clearToastTimer(evictedId);
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
}

export function toast(message: string) { addToast('info', message); }
export function toastSuccess(message: string) { addToast('success', message); }
export function toastError(message: string) { addToast('error', message, 8000); }
export function toastWarning(message: string) { addToast('warning', message, 6000); }
