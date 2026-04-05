import { writable } from 'svelte/store';

export interface ToastItem {
  id: number;
  type: 'success' | 'error' | 'warning' | 'info';
  message: string;
}

let nextId = 0;
const toastTimers = new Map<number, ReturnType<typeof setTimeout>>();

export const toasts = writable<ToastItem[]>([]);

export function addToast(type: ToastItem['type'], message: string, durationMs = 5000) {
  const id = nextId++;
  toasts.update((t) => [...t, { id, type, message }]);
  if (durationMs > 0) {
    toastTimers.set(id, setTimeout(() => removeToast(id), durationMs));
  }
  return id;
}

export function removeToast(id: number) {
  const timer = toastTimers.get(id);
  if (timer) { clearTimeout(timer); toastTimers.delete(id); }
  toasts.update((t) => t.filter((x) => x.id !== id));
}

export function toast(message: string) { addToast('info', message); }
export function toastSuccess(message: string) { addToast('success', message); }
export function toastError(message: string) { addToast('error', message, 8000); }
export function toastWarning(message: string) { addToast('warning', message, 6000); }
