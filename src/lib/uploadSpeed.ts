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
 * clamping rows one at a time bounds no *sum*, and the Uploads tab invites
 * adding the column up and comparing it to the status-bar total.
 */

/**
 * The ceiling the visible slot rates are allowed to add up to.
 *
 * The tighter of the configured cap and the status-bar total, because a user
 * reads the column as a breakdown of that total and neither number may be
 * exceeded. Returns 0 for "nothing to bound against" — unlimited uploads with no
 * total sampled yet — which callers treat as "print the rows as measured".
 *
 * Bounding by the total as well as the cap is deliberate, and the direction
 * matters: during a slot handover the total dips first (it is smoothed over
 * ~3.3 s) while the remaining rows still carry their pre-handover window rates,
 * so the rows are pulled down to meet it rather than being left summing above
 * it. That trades a transient understatement for never looking like the upload
 * limit has been breached — the same preference `SPEED_WINDOW_MS` is documented
 * with on the Rust side.
 */
export function uploadSumBound(cap: number, statusBarTotal: number): number {
  if (cap > 0 && statusBarTotal > 0) {
    return Math.min(cap, statusBarTotal);
  }
  return Math.max(cap, statusBarTotal, 0);
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
