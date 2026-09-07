/**
 * Helpers for the eMule-style web-service menus.
 *
 * The substitution itself is the backend's — a template's `#hashid` parses as a
 * URL fragment, so only the backend ever builds the final URL. What is needed
 * here is the one thing the menu has to know before it is drawn: whether an
 * entry can work for the file it is being offered for.
 */

/**
 * Whether this template needs the file's eD2K hash.
 *
 * A file that is still hashing has no hash yet, and an availability lookup with
 * an empty hash is a page that reports nothing — so the entry is disabled
 * rather than offered and left to fail. Templates that ask only for a name or a
 * size, and plain bookmarks with no placeholder at all, stay available.
 */
export function serviceNeedsHash(url: string): boolean {
  return url.includes('#hashid');
}

/**
 * Whether this service can be opened for a file with this hash.
 *
 * `hash` is whatever the row carries, which is an empty string while a file is
 * being hashed and for a search result that arrived without one.
 */
export function serviceAvailableFor(url: string, hash: string | null | undefined): boolean {
  return !serviceNeedsHash(url) || Boolean(hash && hash.length > 0);
}
