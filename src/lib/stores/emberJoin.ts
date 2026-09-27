import { readable } from 'svelte/store';
import { networkStats } from '$lib/stores/network';
import { createEmberJoinTracker } from '$lib/emberJoin';

/**
 * True once the Ember DHT has sat at zero verified contacts for longer than
 * `EMBER_JOIN_TIMEOUT_MS`. One app-wide timer: the status bar keeps it
 * subscribed for the whole session, so a page opened later sees the same
 * verdict instead of starting its own grace period from scratch.
 */
export const emberJoinTimedOut = readable(false, (set) => {
  const tracker = createEmberJoinTracker(set);
  const unsubscribe = networkStats.subscribe((stats) => {
    tracker.update(!!stats.ember_native_enabled, stats.ember_dht_verified_contacts ?? 0);
  });
  return () => {
    unsubscribe();
    tracker.stop();
  };
});
