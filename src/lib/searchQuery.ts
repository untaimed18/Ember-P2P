/**
 * Shape checks on a search query, shared by the submit path on `/search`.
 *
 * Each one mirrors a rule the Rust side enforces — the IPC byte cap, the
 * server-directive grammar, the eD2k keyword floor — so they live here with
 * tests rather than inline in the page. A frontend copy of a backend rule
 * drifts silently: the guard keeps passing while the search it was guarding
 * starts failing somewhere further in. That is the same hazard
 * `scripts/merge-contract.test.mjs` exists for on the result-merge side.
 */

/** Shared because these run on every keystroke-length input, and because a
 *  `TextEncoder` is stateless. */
const encoder = new TextEncoder();

/**
 * Upper bound on a search query sent over IPC. Matches `MAX_SEARCH_QUERY_LEN`
 * in `commands/search.rs`, which counts UTF-8 **bytes**.
 */
export const MAX_SEARCH_QUERY_LEN = 1024;

/**
 * Clamp a query to `MAX_SEARCH_QUERY_LEN` UTF-8 bytes.
 *
 * The backend rejects the whole search once the string passes that many bytes,
 * and it is bytes on the wire too — but `String.length` counts UTF-16 units, so
 * a query in Chinese or with emoji is up to three or four times longer than it
 * looks. Slicing by character let one through to fail at IPC with
 * `search_query_too_long`, which is a search that refuses to run rather than
 * one that ran on slightly less than was typed. Cuts on a code-point boundary;
 * at this length the tail is a paste accident either way.
 */
export function clampQueryBytes(query: string): string {
  if (encoder.encode(query).length <= MAX_SEARCH_QUERY_LEN) return query;
  let bytes = 0;
  let out = '';
  // Iterating a string yields whole code points, so this cannot split a
  // surrogate pair and leave an unpaired half on the wire.
  for (const ch of query) {
    const size = encoder.encode(ch).length;
    if (bytes + size > MAX_SEARCH_QUERY_LEN) break;
    bytes += size;
    out += ch;
  }
  return out;
}

/**
 * Whether the query is a term an eD2K server resolves from its own index —
 * `ed2k::<hash>` (that exact file) or `related::<hash>` (what is shared
 * alongside it) — rather than a word to match against filenames. Mirrors
 * `search::query::server_directive`: an optional file-size field, then one or
 * more MD4 hashes, separated by colons.
 *
 * KAD and Ember have no such concept. Both walk to the MD4 of a keyword, and
 * the MD4 of the directive *text* is a key no publisher has ever written — so
 * the backend leaves them out of these searches (`search_legs`) and asks only
 * the legs that can answer. On KAD- or Ember-only that leaves a search with no
 * legs at all, which arrives as a bare "no results" explaining nothing; this is
 * what lets the page answer instead.
 *
 * Deliberately whole-query only, unlike the Rust side, which recognises a
 * directive per term and so also catches `ed2k::<hash> AND video`. Matching a
 * tree walk with a regex is not practical, and a substring test would fire on a
 * negated `-ed2k::<hash>` as well. The backend skips the DHT legs for every
 * form regardless, so the mixed query still costs no wasted walk and returns
 * nothing misleading — only this explanation is missing for it.
 */
export function isServerDirectiveQuery(query: string): boolean {
  return /^(?:related|ed2k):\d*(?::+[0-9a-f]{32})+:*$/i.test(query.trim());
}

/**
 * Whether the query carries a token KAD and Ember can actually look up.
 *
 * Same 3-byte floor as eD2K keyword indexing, measured in UTF-8 so a one- or
 * two-character CJK token is still a valid key, and split on the separator set
 * the publisher tokenizes filenames with.
 */
export function queryHasNetworkKeyword(query: string): boolean {
  return query
    .split(/[\s()[\]{}<>,._\-!?:;\\/"']+/)
    .some((token) => token && encoder.encode(token).length >= 3);
}

/**
 * Largest Min sources a search sends.
 *
 * `search_files` takes `min_availability` as `Option<u32>`, and serde rejects a
 * larger number while deserializing the arguments — before the command body
 * runs, so every search on every network fails with an argument error, and the
 * box is saved and restored with the value in it. Held well below that, to the
 * u16 eD2K carries a source count in: merged counts are capped there too
 * (`MAX_PLAUSIBLE_SOURCES` in the search store), so no row could pass a higher
 * minimum anyway.
 */
export const MAX_MIN_SOURCES = 65535;

/**
 * Min sources as a search sends it: a whole number from 1 to
 * `MAX_MIN_SOURCES`, or `undefined` for no constraint — empty, zero, negative
 * or not a number, which is what the backend makes of a zero too.
 */
export function clampMinSources(value: number | null | undefined): number | undefined {
  if (value === null || value === undefined || !Number.isFinite(value)) return undefined;
  const whole = Math.trunc(value);
  if (whole < 1) return undefined;
  return Math.min(whole, MAX_MIN_SOURCES);
}

/**
 * A size filter as a search sends it: a whole, non-negative byte count, or
 * `undefined` for no constraint.
 *
 * `min_size` / `max_size` are `Option<u64>`, and serde rejects a JSON float
 * outright, so a fractional count fails every search the same way an
 * out-of-range Min sources does. Held to `MAX_SAFE_INTEGER`: past that JS cannot
 * represent the count exactly, and `JSON.stringify` starts emitting an exponent,
 * which serde also reads as a float.
 */
export function clampFilterBytes(bytes: number | null | undefined): number | undefined {
  if (bytes === null || bytes === undefined) return undefined;
  const whole = Math.round(bytes);
  if (!Number.isFinite(whole) || whole < 0) return undefined;
  return Math.min(whole, Number.MAX_SAFE_INTEGER);
}

/** Whether a min and a max size, in bytes, leave no size that passes both.
 *  Zero or absent is no constraint on either side. */
export function sizeRangeInverted(minBytes: number | undefined, maxBytes: number | undefined): boolean {
  return !!minBytes && !!maxBytes && minBytes > maxBytes;
}

/**
 * If the query is only a dotted three-letter extension (`.mp3`, `.mp4`,
 * `.mkv`), return that extension in lowercase; otherwise `null`.
 *
 * Filename publishers drop a trailing 3-character / 3-byte token
 * (`extract_keywords` with `strip_trailing_extension`), so a DHT walk for
 * `mp3` almost never hits `Song.mp3` — only names that contain `mp3` as a
 * real word. The search page uses this to explain a flood of library
 * substring hits and a near-empty Ember/KAD list.
 */
export function extensionOnlyQueryToken(query: string): string | null {
  const match = query.trim().match(/^\.([A-Za-z0-9]{3})$/);
  return match ? match[1].toLowerCase() : null;
}
