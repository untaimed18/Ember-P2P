import { describe, expect, it } from 'vitest';
import { pickBestServer } from './bestServer';
import type { ServerInfo } from '$lib/types';

function server(name: string, over: Partial<ServerInfo> = {}): ServerInfo {
  return {
    ip: `10.0.0.${name.length}`,
    port: 4661,
    name,
    description: '',
    user_count: 0,
    file_count: 0,
    max_users: 0,
    soft_files: 0,
    hard_files: 0,
    is_static: false,
    priority: 'normal',
    fail_count: 0,
    client_id: 0,
    is_low_id: false,
    ...over,
  };
}

describe('pickBestServer', () => {
  it('takes High priority first, then eMule Sunrise, then the other Normal servers', () => {
    const big = server('Big', { user_count: 900_000 });
    const sunrise = server('Sunrise', { ip: '176.123.5.89', port: 4725, user_count: 1_000 });
    const high = server('High', { priority: 'high', user_count: 10 });
    expect(pickBestServer([big, sunrise, high])?.name).toBe('High');
    expect(pickBestServer([big, sunrise])?.name).toBe('Sunrise');
    expect(pickBestServer([big])?.name).toBe('Big');
  });

  it('knows Sunrise by name when it is listed under another address', () => {
    const big = server('Big', { user_count: 900_000 });
    const sunrise = server('eMule Sunrise', { ip: '1.2.3.4', user_count: 1 });
    expect(pickBestServer([big, sunrise])?.name).toBe('eMule Sunrise');
  });

  it('prefers fewer failures, then more users, within a rank', () => {
    const a = server('A', { priority: 'high', fail_count: 1, user_count: 500 });
    const b = server('B', { priority: 'high', fail_count: 0, user_count: 5 });
    const c = server('C', { priority: 'high', fail_count: 0, user_count: 50 });
    expect(pickBestServer([a, b, c])?.name).toBe('C');
  });

  it('tries the last server first while it is still listed', () => {
    const high = server('High', { priority: 'high', user_count: 900_000 });
    const last = server('Last', { ip: '10.9.9.9', port: 4242, user_count: 10 });
    expect(pickBestServer([high, last], { ip: '10.9.9.9', port: 4242 })?.name).toBe('Last');
    expect(pickBestServer([high, last], { ip: '10.9.9.9', port: 4661 })?.name).toBe('High');
    expect(pickBestServer([high], { ip: '10.9.9.9', port: 4242 })?.name).toBe('High');
    expect(pickBestServer([high, last], null)?.name).toBe('High');
  });

  it('passes over a last server that is Low or has failed repeatedly', () => {
    const high = server('High', { priority: 'high' });
    const addr = { ip: '10.9.9.9', port: 4242 };
    const low = server('Last', { ...addr, priority: 'low' });
    const failed = server('Last', { ...addr, fail_count: 3 });
    expect(pickBestServer([high, low], addr)?.name).toBe('High');
    expect(pickBestServer([high, failed], addr)?.name).toBe('High');
  });

  it('passes over Low priority servers and, while any other is left, ones that failed repeatedly', () => {
    const low = server('Low', { priority: 'low', user_count: 900_000 });
    const failedHigh = server('FailedHigh', { priority: 'high', fail_count: 3 });
    const failedSunrise = server('Sunrise', { ip: '176.123.5.89', port: 4725, fail_count: 5 });
    const normal = server('Normal', { fail_count: 2 });
    expect(pickBestServer([low, failedHigh, failedSunrise, normal])?.name).toBe('Normal');
    expect(pickBestServer([low])).toBeNull();
  });

  it('offers the least failed server, then the busiest, once every one has failed repeatedly', () => {
    const low = server('Low', { priority: 'low', fail_count: 0 });
    const high = server('High', { priority: 'high', fail_count: 6, user_count: 900_000 });
    const sunrise = server('Sunrise', { ip: '176.123.5.89', port: 4725, fail_count: 4 });
    const quiet = server('Quiet', { fail_count: 3, user_count: 10 });
    const busy = server('BusyOne', { fail_count: 3, user_count: 500 });
    expect(pickBestServer([low, high, sunrise, quiet])?.name).toBe('Quiet');
    expect(pickBestServer([low, high, sunrise, quiet, busy])?.name).toBe('BusyOne');
    const addr = { ip: '10.9.9.9', port: 4242 };
    const failedLast = server('Last', { ...addr, fail_count: 5 });
    expect(pickBestServer([failedLast, quiet], addr)?.name).toBe('Quiet');
  });
});
