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
  it('binds the column to the configured cap', () => {
    expect(uploadSumBound(200 * KB)).toBe(200 * KB);
  });

  it('reports no bound when uploads are unlimited', () => {
    expect(uploadSumBound(0)).toBe(0);
    // A settings value that should never reach here is still not a bound.
    expect(uploadSumBound(-1)).toBe(0);
    expect(uploadSumBound(Number.NaN)).toBe(0);
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

  it('is not pulled down by a stale status-bar total', () => {
    // The case that made bounding by `networkStats.upload_speed` untenable: two
    // slots ramping to 300 kB/s each while the status bar still reads the 180
    // kB/s it sampled up to three seconds ago (and longer if the window was
    // hidden). Bounding by that figure printed each row at ~30% of its measured
    // rate. With uploads unlimited there is nothing to bound against at all…
    const ramping = [300 * KB, 300 * KB];
    const staleTotal = 180 * KB;
    expect(uploadScaleFactor(uploadSumBound(0), ramping)).toBe(1);
    // …and with a cap set, only the cap may tighten the column: the stale total
    // must never scale a row below the share of the cap it is entitled to.
    const factor = uploadScaleFactor(uploadSumBound(REPORTED_CAP), ramping);
    expect(sumOf(ramping, factor)).toBeCloseTo(REPORTED_CAP, 6);
    expect(sumOf(ramping, factor)).toBeGreaterThan(staleTotal);
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
