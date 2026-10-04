import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import { addActionToast, addToast, clearAllToasts, pauseToastDismiss, removeToast, resumeToastDismiss, toasts } from './toast';

describe('action toasts', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    clearAllToasts();
    vi.useRealTimers();
  });

  it('runs the action and never the expiry when the action is taken', () => {
    const run = vi.fn();
    const onExpire = vi.fn();
    addActionToast('info', 'Cancelled', { label: 'Undo', run }, onExpire, 1000);
    get(toasts)[0].action!.run();
    get(toasts)[0]?.action?.run();
    vi.advanceTimersByTime(5000);
    expect(run).toHaveBeenCalledTimes(1);
    expect(onExpire).not.toHaveBeenCalled();
    expect(get(toasts)).toHaveLength(0);
  });

  it('expires once on its timer, and the action is then inert', () => {
    const run = vi.fn();
    const onExpire = vi.fn();
    addActionToast('info', 'Cancelled', { label: 'Undo', run }, onExpire, 1000);
    const action = get(toasts)[0].action!;
    vi.advanceTimersByTime(1000);
    expect(onExpire).toHaveBeenCalledTimes(1);
    action.run();
    expect(run).not.toHaveBeenCalled();
  });

  it('expires when dismissed, evicted or cleared', () => {
    const dismissed = vi.fn();
    const id = addActionToast('info', 'a', { label: 'Undo', run: vi.fn() }, dismissed);
    removeToast(id);
    expect(dismissed).toHaveBeenCalledTimes(1);

    const evicted = vi.fn();
    addActionToast('info', 'b', { label: 'Undo', run: vi.fn() }, evicted);
    for (let i = 0; i < 5; i++) addToast('info', `filler ${i}`);
    expect(evicted).toHaveBeenCalledTimes(1);

    const cleared = vi.fn();
    addActionToast('info', 'c', { label: 'Undo', run: vi.fn() }, cleared);
    clearAllToasts();
    expect(cleared).toHaveBeenCalledTimes(1);
  });

  it('holds the expiry while the stack is hovered', () => {
    const onExpire = vi.fn();
    addActionToast('info', 'Cancelled', { label: 'Undo', run: vi.fn() }, onExpire, 1000);
    pauseToastDismiss();
    vi.advanceTimersByTime(10_000);
    expect(onExpire).not.toHaveBeenCalled();
    resumeToastDismiss();
    // A toast whose time ran out while hovered keeps a short floor to be read.
    vi.advanceTimersByTime(1200);
    expect(onExpire).toHaveBeenCalledTimes(1);
  });
});
