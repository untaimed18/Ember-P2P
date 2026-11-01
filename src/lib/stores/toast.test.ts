import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import {
  addActionToast, addToast, clearAllToasts, flushToastActions, onPendingUndoChange, pauseToastDismiss,
  removeToast, resumeToastDismiss, runLatestUndo, toasts,
} from './toast';

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

  it('expires when dismissed or cleared', () => {
    const dismissed = vi.fn();
    const id = addActionToast('info', 'a', { label: 'Undo', run: vi.fn() }, dismissed);
    removeToast(id);
    expect(dismissed).toHaveBeenCalledTimes(1);

    const cleared = vi.fn();
    addActionToast('info', 'c', { label: 'Undo', run: vi.fn() }, cleared);
    clearAllToasts();
    expect(cleared).toHaveBeenCalledTimes(1);
  });

  it('is never pushed out by the cap, which drops plain toasts instead', () => {
    const onExpire = vi.fn();
    addActionToast('info', 'b', { label: 'Undo', run: vi.fn() }, onExpire);
    for (let i = 0; i < 8; i++) addToast('info', `filler ${i}`);
    expect(onExpire).not.toHaveBeenCalled();
    expect(get(toasts)).toHaveLength(5);
    expect(get(toasts)[0].message).toBe('b');

    for (let i = 0; i < 6; i++) addActionToast('info', `undo ${i}`, { label: 'Undo', run: vi.fn() }, onExpire);
    expect(onExpire).not.toHaveBeenCalled();
  });

  it('takes the newest Undo on request, and flushes the rest for exit', async () => {
    const older = vi.fn();
    const newer = vi.fn();
    const olderExpired = vi.fn(() => Promise.resolve());
    addActionToast('info', 'a', { label: 'Undo', run: older, undo: true }, olderExpired);
    addActionToast('info', 'b', { label: 'Undo', run: newer, undo: true }, vi.fn());
    addActionToast('info', 'offer', { label: 'Add', run: vi.fn() }, vi.fn());
    expect(runLatestUndo()).toBe(true);
    expect(newer).toHaveBeenCalledTimes(1);
    expect(older).not.toHaveBeenCalled();

    const pending: boolean[] = [];
    onPendingUndoChange((p) => pending.push(p));
    await flushToastActions();
    onPendingUndoChange(null);
    expect(olderExpired).toHaveBeenCalledTimes(1);
    expect(pending).toEqual([true, false]);
    expect(get(toasts)).toHaveLength(0);
    expect(runLatestUndo()).toBe(false);
  });

  it('waits for a commit already sent on its timer, and stays pending until it lands', async () => {
    let land!: () => void;
    const commit = new Promise<void>((resolve) => { land = resolve; });
    const pending: boolean[] = [];
    onPendingUndoChange((p) => pending.push(p));
    addActionToast('info', 'a', { label: 'Undo', run: vi.fn(), undo: true }, () => commit, 1000);
    vi.advanceTimersByTime(1000);
    expect(pending).toEqual([false, true]);

    let flushed = false;
    const flush = flushToastActions().then(() => { flushed = true; });
    await Promise.resolve();
    expect(flushed).toBe(false);
    land();
    await flush;
    onPendingUndoChange(null);
    expect(pending).toEqual([false, true, false]);
  });

  it('never lets a plain toast push out a sticky notice', () => {
    addToast('warning', 'consent', 0);
    for (let i = 0; i < 4; i++) addActionToast('info', `undo ${i}`, { label: 'Undo', run: vi.fn() }, vi.fn());
    addToast('info', 'copied');
    expect(get(toasts).some((t) => t.message === 'consent')).toBe(true);
  });

  it('restarts an identical toast instead of stacking a copy', () => {
    const first = addToast('warning', 'Disk full', 1000);
    vi.advanceTimersByTime(800);
    expect(addToast('warning', 'Disk full', 1000)).toBe(first);
    expect(get(toasts)).toHaveLength(1);
    vi.advanceTimersByTime(800);
    expect(get(toasts)).toHaveLength(1);
    vi.advanceTimersByTime(200);
    expect(get(toasts)).toHaveLength(0);
  });

  it('keeps toasts that differ in type or message apart', () => {
    addToast('warning', 'Disk full');
    addToast('error', 'Disk full');
    addToast('warning', 'Disk nearly full');
    expect(get(toasts)).toHaveLength(3);
  });

  it('never folds a repeat into a toast offering an action', () => {
    const onExpire = vi.fn();
    addActionToast('info', 'Removed', { label: 'Undo', run: vi.fn() }, onExpire);
    addToast('info', 'Removed');
    expect(get(toasts)).toHaveLength(2);
    expect(onExpire).not.toHaveBeenCalled();
  });

  it('keeps a sticky toast sticky when it repeats, and a sticky repeat pins a timed one', () => {
    addToast('warning', 'Folder unavailable', 0);
    addToast('warning', 'Folder unavailable', 1000);
    addToast('info', 'Copied', 1000);
    addToast('info', 'Copied', 0);
    vi.advanceTimersByTime(60_000);
    expect(get(toasts).map((t) => t.message)).toEqual(['Folder unavailable', 'Copied']);
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
