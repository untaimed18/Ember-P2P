/**
 * When to offer the connection doctor unasked: once a session, after the
 * computer has been unreachable (firewalled, or a LowID) for ten minutes
 * without a break. Shorter and every startup would offer it while the checks
 * that settle reachability are still running.
 */

/** How long reachability has to stay limited before the offer. */
export const DOCTOR_OFFER_AFTER_MS = 10 * 60_000;

export interface DoctorOfferState {
  /** When the current stretch of limited reachability began; null when not
   *  limited. */
  limitedSince: number | null;
  /** Offered already this session. */
  offered: boolean;
}

export const initialDoctorOffer: DoctorOfferState = { limitedSince: null, offered: false };

/** The next state, and whether to offer now. */
export function stepDoctorOffer(
  prev: DoctorOfferState,
  limited: boolean,
  now: number,
): { next: DoctorOfferState; offer: boolean } {
  if (prev.offered) return { next: prev, offer: false };
  if (!limited) return { next: { ...prev, limitedSince: null }, offer: false };
  const since = prev.limitedSince ?? now;
  if (now - since >= DOCTOR_OFFER_AFTER_MS) {
    return { next: { limitedSince: since, offered: true }, offer: true };
  }
  return { next: { ...prev, limitedSince: since }, offer: false };
}

/** Milliseconds until the offer falls due, for a timer to step again then;
 *  null when none is pending (not limited, or offered already). Nothing else
 *  steps while reachability stays the same. */
export function doctorOfferDueIn(state: DoctorOfferState, now: number): number | null {
  if (state.offered || state.limitedSince === null) return null;
  return Math.max(0, state.limitedSince + DOCTOR_OFFER_AFTER_MS - now);
}
