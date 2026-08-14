import { writable } from 'svelte/store';

export interface ToastItem {
  id: number;
  type: 'success' | 'error' | 'warning' | 'info';
  message: string;
}

let nextId = 0;
const toastTimers = new Map<number, ReturnType<typeof setTimeout>>();
/** Ids added with `durationMs = 0`. These are notices the user is meant to
 *  acknowledge (consent prompts, fatal failures), so the queue cap evicts
 *  them last — but they still get the ceiling timer below, so one nobody
 *  closes can't hold a slot for the rest of the session. */
const stickyToasts = new Set<number>();

export const toasts = writable<ToastItem[]>([]);

/** Most toasts on screen at once. Event-driven callers burst: one misbehaving
 *  backend emits `network-warning` repeatedly and the network store toasts on
 *  every one. Past a handful the stack stops being readable well before it
 *  stops being rendered. */
const MAX_TOASTS = 5;
/** Ceiling applied to `durationMs = 0`. Sticky means "outlives a normal
 *  toast", not "forever" — an unnoticed one would otherwise occupy a slot
 *  and keep evicting the messages that follow it. */
const STICKY_TOAST_MAX_MS = 120_000;

function clearToastTimer(id: number) {
  const timer = toastTimers.get(id);
  if (timer) { clearTimeout(timer); toastTimers.delete(id); }
  stickyToasts.delete(id);
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
  toastTimers.set(
    id,
    setTimeout(() => removeToast(id), durationMs > 0 ? durationMs : STICKY_TOAST_MAX_MS),
  );
  return id;
}

export function removeToast(id: number) {
  clearToastTimer(id);
  toasts.update((t) => t.filter((x) => x.id !== id));
}

export function clearAllToasts() {
  for (const timer of toastTimers.values()) clearTimeout(timer);
  toastTimers.clear();
  stickyToasts.clear();
  toasts.set([]);
}

export function toast(message: string) { addToast('info', message); }
export function toastSuccess(message: string) { addToast('success', message); }
export function toastError(message: string) { addToast('error', message, 8000); }
export function toastWarning(message: string) { addToast('warning', message, 6000); }
