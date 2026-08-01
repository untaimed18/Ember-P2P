import { writable } from 'svelte/store';
import type { Collection } from '$lib/api/collections';

/**
 * Collections opened from the OS are handed to the Library page in arrival
 * order. The promise returned by `presentIncomingCollection` resolves only
 * when the page has opened that collection, allowing its durable deep-link to
 * be acknowledged after presentation rather than after a lossy store write.
 */
export const incomingCollection = writable<Collection | null>(null);

interface PendingCollection {
  collection: Collection;
  resolve: () => void;
}

const pending: PendingCollection[] = [];
let presenting = false;

function showNext() {
  if (presenting || pending.length === 0) return;
  presenting = true;
  incomingCollection.set(pending[0].collection);
}

/** Queue a collection and resolve once the Library page presents it. */
export function presentIncomingCollection(collection: Collection): Promise<void> {
  return new Promise((resolve) => {
    pending.push({ collection, resolve });
    showNext();
  });
}

/** Called by the Library page after it has opened the current collection. */
export function markIncomingCollectionPresented(): void {
  if (!presenting) return;
  const current = pending.shift();
  presenting = false;
  incomingCollection.set(null);
  current?.resolve();
  // Let Svelte observe the cleared value before publishing the next entry;
  // otherwise synchronous `set(null); set(next)` can collapse into one update.
  queueMicrotask(showNext);
}

/**
 * Abandon the queued collection when the caller could not get the user to the
 * Library page. Resolves the waiter so the deep-link drain is never left
 * awaiting a presentation that will not happen — a blocked navigation would
 * otherwise wedge the whole pipeline for the rest of the session.
 */
export function cancelIncomingCollection(): void {
  if (!presenting) return;
  const current = pending.shift();
  presenting = false;
  incomingCollection.set(null);
  current?.resolve();
  queueMicrotask(showNext);
}
