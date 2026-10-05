import { writable } from 'svelte/store';
import { browser } from '$app/environment';

/** Kept beside the other window preferences a profile backup carries. */
export const HIGHLIGHT_MATCHES_KEY = 'ember.highlight-matches.v1';

function readStored(): boolean {
  try {
    return localStorage.getItem(HIGHLIGHT_MATCHES_KEY) !== '0';
  } catch {
    return true;
  }
}

/**
 * Whether the searched words are marked in Search results and in Library file
 * names. On unless turned off, so only the choice to turn it off is stored.
 */
export const highlightMatches = writable<boolean>(browser ? readStored() : true);

if (browser) {
  highlightMatches.subscribe((on) => {
    try {
      if (on) localStorage.removeItem(HIGHLIGHT_MATCHES_KEY);
      else localStorage.setItem(HIGHLIGHT_MATCHES_KEY, '0');
    } catch {
      // Storage disabled: the choice holds for this session.
    }
  });
}
