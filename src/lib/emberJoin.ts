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
