import { writable } from 'svelte/store';
import type { Collection } from '$lib/api/collections';

/**
 * A collection opened from the OS (a double-clicked `.emulecollection` file),
 * handed off to the library page for display. The deep-link handler sets this
 * and navigates to `/library`; the library page consumes it on mount and
 * clears it so a later navigation doesn't re-open a stale collection.
 */
export const incomingCollection = writable<Collection | null>(null);
