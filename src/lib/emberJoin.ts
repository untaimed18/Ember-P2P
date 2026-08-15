/** Client-side window before a zero-contact Ember DHT is treated as
 *  "no peers" rather than still joining. Must span a couple of 60s
 *  backend maintenance ticks (the KAD bridge that finds first contacts).
 *  Search, Ember Network, and the status bar must stay in lockstep —
 *  30s made a healthy node look broken. */
export const EMBER_JOIN_TIMEOUT_MS = 150_000;
