import { describe, expect, it } from 'vitest';
import { uploadScaleFactor, uploadSumBound } from './uploadSpeed';

const KB = 1024;

/** The figures from issue 115: five slots against a 200 kB/s configured cap. */
const REPORTED_SLOTS = [125 * KB, 350 * KB, 200 * KB, 70 * KB, 90 * KB];
const REPORTED_CAP = 200 * KB;

function sumOf(speeds: readonly number[], factor: number): number {
  return speeds.reduce((total, speed) => total + speed * factor, 0);
}

describe('uploadSumBound', () => {
  it('takes the tighter of the cap and the status-bar total', () => {
    expect(uploadSumBound(200 * KB, 500 * KB)).toBe(200 * KB);
    // A slot handover dips the total below the cap; that is the binding figure,
    // so the rows follow it down instead of summing above it.
    expect(uploadSumBound(200 * KB, 120 * KB)).toBe(120 * KB);
  });

  it('falls back to whichever figure it has', () => {
    // Unlimited uploads: the total is still something the column adds up to.
    expect(uploadSumBound(0, 500 * KB)).toBe(500 * KB);
    // No total sampled yet (first paint, stats not polled): the cap still binds.
    expect(uploadSumBound(200 * KB, 0)).toBe(200 * KB);
  });

  it('reports no bound when neither figure is known', () => {
    expect(uploadSumBound(0, 0)).toBe(0);
  });
});

describe('uploadScaleFactor', () => {
  it('leaves a column that already fits alone', () => {
    const speeds = [50 * KB, 60 * KB];
    expect(uploadScaleFactor(200 * KB, speeds)).toBe(1);
    // Exactly at the bound is fitting, not overflowing.
    expect(uploadScaleFactor(110 * KB, speeds)).toBe(1);
  });

  it('never scales a rate up', () => {
    expect(uploadScaleFactor(10_000 * KB, [1 * KB])).toBe(1);
  });

  it('brings the reported column back under the configured cap', () => {
    // 835 kB/s of slots against a 200 kB/s limit — what the bug looked like.
    const factor = uploadScaleFactor(REPORTED_CAP, REPORTED_SLOTS);
    expect(factor).toBeLessThan(1);
    expect(sumOf(REPORTED_SLOTS, factor)).toBeCloseTo(REPORTED_CAP, 6);
    // No single slot may print above the limit either, which is the figure the
    // reporter's screenshot led with (one slot at 350 against a 200 cap).
    for (const speed of REPORTED_SLOTS) {
      expect(speed * factor).toBeLessThanOrEqual(REPORTED_CAP);
    }
  });

  it('holds the sum to a dipping total, not just the cap', () => {
    const bound = uploadSumBound(REPORTED_CAP, 120 * KB);
    const factor = uploadScaleFactor(bound, REPORTED_SLOTS);
    expect(sumOf(REPORTED_SLOTS, factor)).toBeCloseTo(120 * KB, 6);
  });

  it('is not diluted by rows that are printing nothing', () => {
    const withIdle = [...REPORTED_SLOTS, 0];
    expect(uploadScaleFactor(REPORTED_CAP, withIdle)).toBe(
      uploadScaleFactor(REPORTED_CAP, REPORTED_SLOTS),
    );
  });

  it('prints rows as measured when there is nothing to bound against', () => {
    expect(uploadScaleFactor(0, REPORTED_SLOTS)).toBe(1);
  });

  it('survives a single slot with no bound to share', () => {
    expect(uploadScaleFactor(REPORTED_CAP, [])).toBe(1);
    expect(uploadScaleFactor(REPORTED_CAP, [400 * KB])).toBeCloseTo(0.5, 6);
  });
});
