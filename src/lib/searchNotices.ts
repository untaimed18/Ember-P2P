/**
 * What the backend says about a network a search could not ask or that never
 * answered. A tab keeps these once the search ends, so a partial answer does
 * not read as a complete one.
 *
 * The first three also arrive as `search-progress` phases, which is how they
 * were first reported; the rest come as `search-notice` events.
 */
export const SEARCH_NOTICES: ReadonlySet<string> = new Set([
  'KadNoContacts',
  'KadBusy',
  'EmberBusy',
  'EmberNoKeyword',
  'ServerUnavailable',
  'ServerNoAnswer',
  'NetworkNoKeyword',
]);
