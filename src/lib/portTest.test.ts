import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const events = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
const recheck = vi.hoisted(() => ({ resolve: null as null | (() => void), reject: null as null | ((e: unknown) => void) }));

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async (name: string, handler: (event: { payload: unknown }) => void) => {
    events.set(name, handler);
    return () => events.delete(name);
  }),
}));
vi.mock('$lib/api/kad', () => ({
  kadRecheckFirewall: vi.fn(
    () =>
      new Promise<void>((resolve, reject) => {
        recheck.resolve = resolve;
        recheck.reject = reject;
      }),
  ),
}));

import { parsePortTestResult, PortTestTimeout, runPortTest } from './portTest';

const finished = (payload: unknown) => events.get('firewall-check-finished')?.({ payload });
const flush = () => new Promise((r) => setTimeout(r, 0));

describe('parsePortTestResult', () => {
  it('reads each side, with no answer as untested', () => {
    expect(parsePortTestResult({ tcp_port: 4662, udp_port: 4672, tcp_open: true, udp_open: null })).toEqual({
      tcpPort: 4662,
      udpPort: 4672,
      tcp: 'open',
      udp: 'untested',
    });
    expect(parsePortTestResult({ tcp_port: 1, udp_port: 2, tcp_open: false, udp_open: false })?.tcp).toBe('closed');
    expect(parsePortTestResult({ tcp_open: true })).toBeNull();
    expect(parsePortTestResult(null)).toBeNull();
  });
});

describe('runPortTest', () => {
  beforeEach(() => events.clear());
  afterEach(() => vi.useRealTimers());

  it('ignores a check that finished before this one began', async () => {
    const run = runPortTest(10_000);
    await flush();
    finished({ tcp_port: 9, udp_port: 9, tcp_open: false, udp_open: false });
    recheck.resolve?.();
    await flush();
    finished({ tcp_port: 4662, udp_port: 4672, tcp_open: true, udp_open: true });
    await expect(run).resolves.toMatchObject({ tcpPort: 4662, tcp: 'open', udp: 'open' });
    expect(events.has('firewall-check-finished')).toBe(false);
  });

  it('passes the backend refusal on and stops listening', async () => {
    const run = runPortTest(10_000);
    await flush();
    recheck.reject?.(new Error('No verified contacts available for firewall recheck'));
    await expect(run).rejects.toThrow('No verified contacts');
    expect(events.has('firewall-check-finished')).toBe(false);
  });

  it('gives up when no answer comes', async () => {
    vi.useFakeTimers();
    const run = runPortTest(1_000);
    await vi.advanceTimersByTimeAsync(0);
    recheck.resolve?.();
    await vi.advanceTimersByTimeAsync(0);
    const assertion = expect(run).rejects.toBeInstanceOf(PortTestTimeout);
    await vi.advanceTimersByTimeAsync(1_000);
    await assertion;
  });
});
