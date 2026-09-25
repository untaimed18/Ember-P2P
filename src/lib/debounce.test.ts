import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createMaxWaitDebounce } from './debounce';

describe('createMaxWaitDebounce', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('runs once, `waitMs` after the last call of a short burst', () => {
    const fn = vi.fn();
    const d = createMaxWaitDebounce(fn);
    d.schedule(300, 2000);
    vi.advanceTimersByTime(200);
    d.schedule(300, 2000);
    vi.advanceTimersByTime(299);
    expect(fn).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(fn).toHaveBeenCalledTimes(1);
    expect(d.pending).toBe(false);
  });

  it('still fires within max-wait while calls keep arriving', () => {
    const fn = vi.fn();
    const d = createMaxWaitDebounce(fn);
    // A steady 200 ms stream would starve a plain 300 ms trailing debounce.
    for (let t = 0; t < 2000; t += 200) {
      d.schedule(300, 2000);
      vi.advanceTimersByTime(200);
    }
    expect(fn).toHaveBeenCalledTimes(1);
    // The next burst gets a fresh deadline.
    for (let t = 0; t < 1800; t += 200) {
      d.schedule(300, 2000);
      vi.advanceTimersByTime(200);
    }
    expect(fn).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(200);
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('lets a shorter max-wait pull an existing deadline in, never out', () => {
    const fn = vi.fn();
    const d = createMaxWaitDebounce(fn);
    d.schedule(3000, 15000);
    vi.advanceTimersByTime(1000);
    d.schedule(300, 500);
    vi.advanceTimersByTime(300);
    expect(fn).toHaveBeenCalledTimes(1);

    d.schedule(300, 1000);
    vi.advanceTimersByTime(200);
    d.schedule(3000, 15000);
    vi.advanceTimersByTime(799);
    expect(fn).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(1);
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('treats a max-wait below the wait as the wait', () => {
    const fn = vi.fn();
    const d = createMaxWaitDebounce(fn);
    d.schedule(300, 0);
    vi.advanceTimersByTime(299);
    expect(fn).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('cancel drops the scheduled run and the burst deadline', () => {
    const fn = vi.fn();
    const d = createMaxWaitDebounce(fn);
    d.schedule(300, 1000);
    vi.advanceTimersByTime(200);
    d.schedule(300, 1000);
    vi.advanceTimersByTime(200);
    expect(d.pending).toBe(true);
    d.cancel();
    expect(d.pending).toBe(false);
    vi.advanceTimersByTime(5000);
    expect(fn).not.toHaveBeenCalled();
    d.schedule(300, 1000);
    vi.advanceTimersByTime(299);
    expect(fn).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(fn).toHaveBeenCalledTimes(1);
  });
});
