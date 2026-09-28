/** Client-side window before a zero-contact Ember DHT is treated as
 *  "no peers" rather than still joining. Must span a couple of 60s
 *  backend maintenance ticks (the KAD bridge that finds first contacts).
 *  Search, Ember Network, and the status bar must stay in lockstep —
 *  30s made a healthy node look broken. */
export const EMBER_JOIN_TIMEOUT_MS = 150_000;

/** Consecutive `get_ember_diagnostics` failures before the readiness numbers
 *  are treated as unusable rather than merely late. Every poller that reports
 *  Ember readiness has to agree on this: a page that gives up sooner tells the
 *  user the DHT has no peers when the truth is that nothing has been asked. */
export const EMBER_DIAG_FAILURE_THRESHOLD = 3;

/** How long verified contacts must hold above zero before the join counts as
 *  real. Without a dwell this was level-triggered: every ~3s poll that caught
 *  `verified > 0` restarted the grace period, so a join oscillating around
 *  zero — cold start, partition recovery, eviction churn — never timed out and
 *  the user was never told the overlay had failed to join. */
export const EMBER_JOIN_DWELL_MS = 10_000;

export interface EmberJoinTracker {
  /** Feed one readiness sample. */
  update(enabled: boolean, verified: number, now?: number): void;
  /** Cancel the pending timeout. */
  stop(): void;
}

/**
 * Join/timeout state machine behind "no peers yet". `onChange` receives the
 * timed-out flag; it may be called repeatedly with the same value.
 */
export function createEmberJoinTracker(onChange: (timedOut: boolean) => void): EmberJoinTracker {
  let joinSince: number | null = null;
  let joinedSince: number | null = null;
  let expired = false;
  let timer: ReturnType<typeof setTimeout> | null = null;

  function clearTimer() {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
  }

  function setExpired(value: boolean) {
    expired = value;
    onChange(value);
  }

  return {
    update(enabled, verified, now = Date.now()) {
      if (!enabled) {
        clearTimer();
        joinSince = null;
        joinedSince = null;
        setExpired(false);
        return;
      }

      if (verified > 0) {
        if (joinedSince === null) joinedSince = now;
        // Stop the timer straight away so a join in progress cannot flash the
        // warning, but hold `joinSince` until the dwell elapses. If contacts
        // drop back before then, the branch below re-arms for the *remaining*
        // budget rather than a fresh full one.
        clearTimer();
        if (now - joinedSince >= EMBER_JOIN_DWELL_MS) {
          joinSince = null;
          setExpired(false);
        }
        return;
      }

      joinedSince = null;
      if (joinSince === null) {
        joinSince = now;
        setExpired(false);
      }
      if (!expired && timer === null) {
        const remaining = Math.max(0, EMBER_JOIN_TIMEOUT_MS - (now - joinSince));
        timer = setTimeout(() => {
          timer = null;
          setExpired(true);
        }, remaining);
      }
    },
    stop: clearTimer,
  };
}
