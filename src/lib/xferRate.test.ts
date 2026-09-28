import { describe, expect, it } from 'vitest';
import {
  XFER_RATE_STALE_MS,
  keepXferSamples,
  noteXferBytes,
  xferRate,
  xferSecondsLeft,
  type RateSamples,
} from './xferRate';

const EMPTY: RateSamples = new Map();

describe('noteXferBytes', () => {
  it('has no speed until a second report arrives', () => {
    const s = noteXferBytes(EMPTY, 'x', 1000, 0);
    expect(xferRate(s, 'x', 0)).toBe(0);
    const t = noteXferBytes(s, 'x', 3000, 1000);
    expect(xferRate(t, 'x', 1000)).toBe(2000);
  });

  it('smooths rather than jumping to each report', () => {
    let s = noteXferBytes(EMPTY, 'x', 0, 0);
    s = noteXferBytes(s, 'x', 1000, 1000);
    s = noteXferBytes(s, 'x', 4000, 2000);
    const rate = xferRate(s, 'x', 2000);
    expect(rate).toBeGreaterThan(1000);
    expect(rate).toBeLessThan(3000);
  });

  it('returns the same map for a report that changes nothing', () => {
    const s = noteXferBytes(EMPTY, 'x', 500, 0);
    expect(noteXferBytes(s, 'x', 500, 2000)).toBe(s);
    expect(noteXferBytes(s, 'x', 900, 100)).toBe(s);
  });

  it('starts over when the count goes backwards', () => {
    let s = noteXferBytes(EMPTY, 'x', 0, 0);
    s = noteXferBytes(s, 'x', 5000, 1000);
    s = noteXferBytes(s, 'x', 10, 2000);
    expect(xferRate(s, 'x', 2000)).toBe(0);
  });
});

describe('xferRate', () => {
  it('drops a speed that has gone stale', () => {
    let s = noteXferBytes(EMPTY, 'x', 0, 0);
    s = noteXferBytes(s, 'x', 1000, 1000);
    expect(xferRate(s, 'x', 1000 + XFER_RATE_STALE_MS)).toBe(1000);
    expect(xferRate(s, 'x', 1001 + XFER_RATE_STALE_MS)).toBe(0);
    expect(xferRate(s, 'other', 1000)).toBe(0);
  });
});

describe('xferSecondsLeft', () => {
  it('rounds up and gives up without a speed or with nothing left', () => {
    expect(xferSecondsLeft(1000, 0, 300)).toBe(4);
    expect(xferSecondsLeft(1000, 0, 0)).toBeNull();
    expect(xferSecondsLeft(1000, 1000, 50)).toBeNull();
    expect(xferSecondsLeft(1000, 0, Number.NaN)).toBeNull();
  });
});

describe('keepXferSamples', () => {
  it('drops finished transfers and keeps identity when none finished', () => {
    let s = noteXferBytes(EMPTY, 'a', 0, 0);
    s = noteXferBytes(s, 'b', 0, 0);
    expect(keepXferSamples(s, new Set(['a', 'b']))).toBe(s);
    const kept = keepXferSamples(s, new Set(['a']));
    expect([...kept.keys()]).toEqual(['a']);
  });
});
