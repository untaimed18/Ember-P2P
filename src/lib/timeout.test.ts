import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { TimeoutError, withTimeout } from './timeout';
import { translateError } from './i18n';
import * as m from '$lib/paraglide/messages';

describe('withTimeout', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('passes a settled result straight through', async () => {
    await expect(withTimeout(Promise.resolve(7), 'fast')).resolves.toBe(7);
    await expect(withTimeout(Promise.reject(new Error('boom')), 'fast')).rejects.toThrow('boom');
  });

  it('rejects with a TimeoutError once the deadline passes', async () => {
    const pending = withTimeout(new Promise(() => {}), 'pause_transfer', 20_000);
    const assertion = expect(pending).rejects.toBeInstanceOf(TimeoutError);
    await vi.advanceTimersByTimeAsync(20_000);
    await assertion;
  });

  it('keeps the command and deadline on the error for logs', async () => {
    const pending = withTimeout(new Promise(() => {}), 'get_kad_contacts', 10_000);
    const caught = pending.catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(10_000);
    const err = (await caught) as TimeoutError;
    expect(err.label).toBe('get_kad_contacts');
    expect(err.ms).toBe(10_000);
    expect(err.message).toContain('get_kad_contacts');
  });
});

describe('translateError on a timeout', () => {
  it('shows the translated message rather than the command name', () => {
    const text = translateError(new TimeoutError('pause_transfer', 20_000));
    expect(text).toBe(m.error_timed_out());
    expect(text).not.toContain('pause_transfer');
  });

  it('wins over a caller fallback', () => {
    expect(translateError(new TimeoutError('x', 1000), 'fallback')).toBe(m.error_timed_out());
  });
});
