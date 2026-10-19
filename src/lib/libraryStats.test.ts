import { describe, expect, it } from 'vitest';
import { compareAllTime } from './libraryStats';

describe('compareAllTime', () => {
  it('orders by the all-time total, not the session', () => {
    // Just after a restart: nothing this session, very different histories.
    expect(compareAllTime(0, 5_000, 0, 10)).toBeGreaterThan(0);
    expect(compareAllTime(3, 10, 0, 5_000)).toBeLessThan(0);
  });

  it('breaks equal totals on the session figure', () => {
    expect(compareAllTime(7, 100, 2, 100)).toBeGreaterThan(0);
    expect(compareAllTime(2, 100, 2, 100)).toBe(0);
  });

  it('counts the session as the total for a file with no all-time record yet', () => {
    expect(compareAllTime(50, 0, 0, 40)).toBeGreaterThan(0);
  });
});
