import { writable } from 'svelte/store';
import { browser } from '$app/environment';

/** Kept beside the other window preferences a profile backup carries. */
export const HIGHLIGHT_MATCHES_KEY = 'ember.highlight-matches.v1';

function readStored(): boolean {
  try {
    return localStorage.getItem(HIGHLIGHT_MATCHES_KEY) === '1';
  } catch {
    return false;
  }
}

/**
 * Whether the searched words are marked in Search results and in Library file
 * names. Off unless turned on, so only the choice to turn it on is stored.
 */
export const highlightMatches = writable<boolean>(browser ? readStored() : false);

if (browser) {
  highlightMatches.subscribe((on) => {
    try {
      if (on) localStorage.setItem(HIGHLIGHT_MATCHES_KEY, '1');
      else localStorage.removeItem(HIGHLIGHT_MATCHES_KEY);
    } catch {
      // Storage disabled: the choice holds for this session.
    }
  });
}
