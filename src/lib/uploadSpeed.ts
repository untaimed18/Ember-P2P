/**
 * How the Uploads tab decides what rate to print next to each slot.
 *
 * Its own module rather than a private helper in `routes/transfers/+page.svelte`
 * for the reason `searchOverflow.ts` gives: a rule with no test drifts, and a
 * `$derived` inside a 7k-line page component cannot be loaded by a test process.
 * This is the arithmetic issue 115 came down to, so it is pinned here.
 *
 * The backend already clamps each row to the rate the limiter is allowed to
 * spend (`TransferManager::cap_active_speed`). This is the second half of that:
 * clamping rows one at a time bounds no *sum*, so a slot handover that briefly
 * overlaps two rows could still print a column adding up to more than the
 * configured limit.
 */

/**
 * The upload cap actually in force, in bytes/s (0 = unlimited).
 *
 * `effective` is the backend's `RuntimeStatus.effective_upload_speed`, which
 * follows a bandwidth schedule rule and the upload speed controller; the manual
 * setting says neither, so bounding by it let a column held to 15 kB/s by USS
 * sum to the 200 kB/s the user typed, and clipped rows a schedule had raised
 * above it. The manual figure is only the fallback until the backend has
 * published one. An effective 0 is a real answer ("unlimited"), not a gap.
 */
export function uploadCapInForce(
  effective: number | null | undefined,
  manual: number | null | undefined,
): number {
  if (typeof effective === 'number' && Number.isFinite(effective) && effective >= 0) {
    return effective;
  }
  return manual ?? 0;
}

/**
 * The ceiling the visible slot rates are allowed to add up to.
 *
 * The upload cap in force ({@link uploadCapInForce}), or 0 for "nothing to
 * bound against" — uploads
 * unlimited — which callers treat as "print the rows as measured".
 *
 * The status-bar total used to bound this as well, on the reasoning that a user
 * reads the column as a breakdown of that total. It cannot be used that way, and
 * this is why: the numerator refreshes from `transfer-progress` every ~200 ms,
 * while `networkStats.upload_speed` is sampled by a 3 s interval that also
 * returns early while the window is hidden, and the figure it carries is already
 * the backend's ~3 s-settling EWMA. A fresh numerator over a divisor several
 * seconds behind it made every slot print far below its real rate through the
 * whole ramp-up — roughly 30% of it one second in — and with uploads unlimited
 * the stale total was the *only* bound, so that understatement bought no
 * protection at all. Issue 115 was a row printing ABOVE the configured cap, and
 * the cap is the only figure that bounds that; a total that lags the rows it is
 * meant to describe cannot be allowed to shrink them.
 */
export function uploadSumBound(cap: number): number {
  return cap > 0 ? cap : 0;
}

/**
 * The factor every slot's rate is multiplied by so the column sums to at most
 * `bound`. Never above 1: this only ever scales rates down.
 *
 * `speeds` is the rates of the rows actually being displayed as active. Rows the
 * caller renders as idle must be left out — counting a zero cannot change the
 * sum, but counting a *stale* rate for a row printing 0 would thin every other
 * row by a share nothing on screen accounts for.
 */
export function uploadScaleFactor(bound: number, speeds: Iterable<number>): number {
  if (bound <= 0) {
    return 1;
  }
  let sum = 0;
  for (const speed of speeds) {
    if (speed > 0) {
      sum += speed;
    }
  }
  return sum > bound ? bound / sum : 1;
}
