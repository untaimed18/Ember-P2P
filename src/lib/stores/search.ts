import { get, writable, type Unsubscriber } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import type { SearchResult } from '$lib/types';
import type { UnlistenFn } from '@tauri-apps/api/event';
import type { SearchMethod, SearchFilters, RelationKind } from '$lib/api/search';
import { cancelSearch, rescoreSearchResults } from '$lib/api/search';
import { rememberShed, shedWeakestRows } from '$lib/searchOverflow';
import {
  PERSIST_RETRY_LIMITS,
  SEARCH_STORAGE_KEY,
  buildPersistPayload,
  parsePersistedSearch,
  trimPersistPayload,
  type PersistedSearch,
} from '$lib/searchPersistence';
import { appSettings } from './settings';
import { dev } from '$app/environment';

/** Marks a tab as the result of "find related files" rather than a typed
 *  query, so it can be labelled by the file it came from instead of by the
 *  derived keywords — which are an implementation detail the user never typed
 *  and would not recognise. */
export type RelatedSearchInfo = {
  /** Filename(s) the search was started from. */
  seedLabel: string;
  /** The most specific probe's query, which is what the tab is labelled with.
   *  Empty when the seed yielded no keywords at all and the co-share request is
   *  carrying the search on its own. */
  queryLabel: string;
  /** Signals in use, for explaining the tab. */
  kinds: RelationKind[];
};

export type SearchTab = {
  id: string;
  requestId: number;
  query: string;
  method: SearchMethod;
  fileType?: string;
  filters?: SearchFilters;
  /** Present only for a related search; see [`RelatedSearchInfo`]. */
  related?: RelatedSearchInfo;
  results: SearchResult[];
  /** Persistent `resultKey` -> index-into-`results` map. Kept on the tab so a
   *  streaming flush only touches the incoming batch instead of rebuilding an
   *  index over everything accumulated so far. Treated as a cache: any code
   *  that replaces `results` without maintaining it (e.g. Clear Results) is
   *  detected by the length check in `mergeIntoTab` and the map is rebuilt. */
  resultIndex?: Map<string, number>;
  isSearching: boolean;
  /** The finished search can be continued with Search More: it stopped on
   *  its own limits with eD2K servers left to ask, or with the connected
   *  server holding more pages. Only ever true on the latest search. */
  canSearchMore?: boolean;
  progress: { nodes_contacted: number; results_so_far: number; phase: string } | null;
  error: string | null;
  /** Results dropped because the tab reached its cap, least available first.
   *  Shown, so a broad search does not look as if it lost hits for no reason. */
  shed?: number;
  /** Keys of the dropped results, while the search can still send them
   *  again: one that comes back is shown and no longer dropped, and one
   *  dropped twice is counted once. Bounded by `MAX_REMEMBERED_SHED`. */
  shedKeys?: Set<string>;
};

/**
 * Restore the tabs a reload would otherwise have thrown away. The rules live in
 * `searchPersistence.ts`; what is left here is the storage itself.
 *
 * Written at `pagehide` rather than on every change: results arrive in batches
 * and a tab can hold thousands of rows, so serialising on each update would
 * cost far more than the one write that actually matters.
 */
/**
 * Whether anything has changed since the last write that landed.
 *
 * `visibilitychange`→hidden fires on every app switch, and building the payload
 * is not cheap — the row shed behind `forPersist` is several O(n log n) passes
 * over up to `PERSIST_MAX_TABS` tabs of up to `MAX_TAB_RESULTS` rows, all of it
 * synchronous on the thread that draws the window. Alt-tabbing away from a page
 * whose results have not moved since the last write now costs nothing.
 *
 * Every write to what gets persisted goes through `searchTabs` or
 * `activeSearchTabId`, so subscribing to both covers the whole surface. Cleared
 * only once `setItem` has actually succeeded: a write refused at every limit in
 * `PERSIST_RETRY_LIMITS` has to stay pending, or the quota that refused it would
 * cost the user the rest of the session's results as well.
 */
let persistDirty = true;

function persistSearch() {
  if (typeof sessionStorage === 'undefined') return;
  if (!persistDirty) return;
  const tabs = get(searchTabs);
  if (tabs.length === 0) {
    try {
      sessionStorage.removeItem(SEARCH_STORAGE_KEY);
      persistDirty = false;
    } catch {
      /* nothing to lose */
    }
    return;
  }
  const activeId = get(activeSearchTabId);
  // Built once at the largest limit and then trimmed down, rather than rebuilt
  // from the live tabs per limit — see `trimPersistPayload`.
  let payload: PersistedSearch | null = null;
  for (const limit of PERSIST_RETRY_LIMITS) {
    payload = payload === null
      ? buildPersistPayload(tabs, activeId, limit)
      : trimPersistPayload(payload, limit);
    try {
      sessionStorage.setItem(SEARCH_STORAGE_KEY, JSON.stringify(payload));
      persistDirty = false;
      return;
    } catch {
      // Quota, or a value that would not serialise. Try a smaller payload.
    }
  }
}

/** Read the persisted blob, or `null` if it cannot be read at all.
 *
 *  `persistSearch` already wraps its writes, but this read was guarded only
 *  against `sessionStorage` being undefined. A webview with storage disabled by
 *  policy throws `SecurityError` from the property access itself, and because
 *  this runs at module scope that throw takes the store — and the whole search
 *  page — down with it. */
function readPersistedSearch(): string | null {
  try {
    if (typeof sessionStorage === 'undefined') return null;
    return sessionStorage.getItem(SEARCH_STORAGE_KEY);
  } catch {
    return null;
  }
}

const persistedSearch = parsePersistedSearch(readPersistedSearch());

export const searchTabs = writable<SearchTab[]>(persistedSearch.tabs);
export const activeSearchTabId = writable<string | null>(persistedSearch.activeId);

/**
 * The tabs to carry across an update restart, in the same shape a reload keeps.
 *
 * Needed because session storage does not survive the process ending, which is
 * exactly what an update does. `null` when there is nothing worth carrying.
 */
export function searchResumeSnapshot(): string | null {
  const tabs = get(searchTabs);
  if (tabs.length === 0) return null;
  try {
    return JSON.stringify(buildPersistPayload(tabs, get(activeSearchTabId)));
  } catch {
    return null;
  }
}

/**
 * Put back the tabs an update restart carried over, through the same validation
 * a reload's restore uses. Tabs that already exist win: they are newer.
 */
export function restoreSearchFromResume(raw: string): void {
  if (get(searchTabs).length > 0) return;
  const restored = parsePersistedSearch(raw);
  if (restored.tabs.length === 0) return;
  searchTabs.set(restored.tabs);
  activeSearchTabId.set(restored.activeId);
}

if (typeof window !== 'undefined') {
  // `pagehide` covers the reload and the window going away; the hidden branch
  // of `visibilitychange` is the backstop for paths that do not fire it.
  window.addEventListener('pagehide', persistSearch);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') persistSearch();
  });
  // See `persistDirty`. Both fire once on subscribe, which leaves the first
  // persist after a restore to write the restored payload straight back — one
  // wasted write, and the safe direction to be wrong in.
  searchTabs.subscribe(() => {
    persistDirty = true;
  });
  activeSearchTabId.subscribe(() => {
    persistDirty = true;
  });
}
/** Bumped when learned spam data is wiped so the search page can drop
 *  tooltip caches that would otherwise outlive empty `spam_reasons`. */
export const spamFilterEpoch = writable(0);

/**
 * Bumped whenever a row is rewritten in place by something other than the
 * result stream — a spam mark, its undo, or a re-score.
 *
 * The search page reads a throttled snapshot of the active tab's results so a
 * streaming search cannot drive its whole-list passes at flush rate. That
 * throttle keys off the row *count*, which a spam mark does not change, so
 * hiding the row the user just marked could sit behind up to a full throttle
 * interval. These edits are user-initiated and arrive one at a time, so they
 * are exactly the case the throttle is not for: the page syncs immediately
 * when this changes.
 */
export const searchRowPatchEpoch = writable(0);

let initialized = false;
let unlisteners: UnlistenFn[] = [];
let unsubSettings: Unsubscriber | null = null;
let lastSpamSettingsKey: string | null = null;
// Seeded from the clock rather than 0: the backend outlives a webview reload,
// and a leg still running for the last page's request — an Ember walk emits
// its closing batch up to a minute on — would otherwise name an id this page
// is about to hand out again, and stream into that search. Searches are far
// rarer than milliseconds, so the ids keep rising across reloads, and stay
// well inside `Number.MAX_SAFE_INTEGER` and the backend's u64.
let searchNonce = Date.now();
// Bumped by `cleanupSearchStore`; see the matching comment in
// `stores/network.ts` for why `initSearchStore` needs to re-check this
// after its async listener registration before adopting the results.
let storeEpoch = 0;

export function newSearchNonce(): number {
  searchNonce += 1;
  return searchNonce;
}

function newTabId(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return `t-${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
}

/*
 * `resultKey`, `combineOrigin`, `pickEmberDigest`, `MAX_PLAUSIBLE_SOURCES`,
 * `MAX_SOURCE_ADDRS` and the first-non-empty fields inside `mergeResult` below all
 * re-implement rules the backend already has in `src-tauri/src/search/merge.rs`
 * (this store merges the streamed batches a second time, per tab).
 * `scripts/fixtures/merge-contract.json` is the shared source of truth for the
 * parts that must agree, and both sides are tested against it —
 * `scripts/merge-contract.test.mjs` here, `merge_contract_fixture` there — so a
 * divergence fails a test instead of shipping.
 *
 * That Node test cannot import this module (Svelte-app TypeScript, no bundler on
 * that path), so it lifts the three pure function bodies out of the source text
 * and runs them: keep them pure and closed over nothing, and keep their signatures
 * on one line. What it cannot lift — the inline field rules in `mergeResult` — it
 * asserts the *shape* of instead, so those expressions have to stay recognisable. The divergences from Rust *are* deliberate where commented
 * (availability, filename, address cap) and are deliberately not in the fixture.
 */
function resultKey(result: SearchResult): string {
  if (result.file.hash) return result.file.hash;
  if (result.file.id?.startsWith('pending:')) return `nohash-id:${result.file.id}`;
  if (result.file.path) return `nohash-path:${result.file.path}`;
  return `nohash:${result.file.name}:${result.file.size}`;
}

function combineOrigin(a: string, b: string): string {
  if (!b || a === b) return a || b;
  if (!a) return b;
  const parts = [...a.split(' · '), ...b.split(' · ')]
    .map((s) => s.trim())
    .filter(Boolean);
  return [...new Set(parts)].sort().join(' · ');
}

/**
 * Which Ember content digest a merged row keeps.
 *
 * Deliberately not "first non-empty wins", which is what this used to be. An
 * Ember keyword batch carries the plurality digest of the publishers in that
 * batch, and the closing batch is rebuilt from every record the walk gathered —
 * so the corrected value always arrives after the slice-local one it is meant to
 * replace, and keeping the first pinned a row to a digest a minority of
 * publishers claimed. That is what `startDownload` hands over as the digest to
 * enforce at completion, and enforcing a wrong one fails verification on every
 * retry.
 *
 * A `Local` digest still wins: it was computed from the bytes on this disk
 * (known.met), so no network claim replaces it.
 *
 * Mirrors `pick_ember_digest` in `src-tauri/src/search/merge.rs`; pinned for both
 * sides by `scripts/fixtures/merge-contract.json`. Keep it closed over nothing —
 * `scripts/merge-contract.test.mjs` lifts this body out and runs it.
 */
function pickEmberDigest(existingDigest: string, existingOrigin: string, incomingDigest: string): string {
  if (!incomingDigest) return existingDigest;
  if (!existingDigest) return incomingDigest;
  return existingOrigin.includes('Local') ? existingDigest : incomingDigest;
}

/**
 * Whether a merge adopts the incoming row's spam explanation or keeps the one
 * it holds.
 *
 * `spam_rating` is merged with max and `is_spam` with OR, so the two lists have
 * to follow the verdict that survived — otherwise a row shows a high score above
 * a signal list that only justifies a low one, which is exactly what a user
 * reads to decide whether to trust a file. The merged verdict is the OR, so the
 * explanation must come from a side that actually flagged the row; only once the
 * two agree on the verdict does the score decide. Asking merely "does incoming
 * newly flag, or outscore?" left a flagged 50 meeting an unflagged 60 keeping
 * `is_spam` while adopting the unflagged pass's reasons, and made the result
 * depend on which batch happened to arrive first.
 *
 * Mirrors `takes_incoming_spam_signals` in `src-tauri/src/search/merge.rs`;
 * pinned for both sides by `scripts/fixtures/merge-contract.json`. Keep it
 * closed over nothing — `scripts/merge-contract.test.mjs` lifts this body out
 * and runs it.
 */
function takesIncomingSpamSignals(existingIsSpam: boolean, existingRating: number, incomingIsSpam: boolean, incomingRating: number): boolean {
  if (incomingIsSpam !== existingIsSpam) return incomingIsSpam;
  return incomingRating > existingRating;
}

/** Per-hash user spam overrides. Honored by mergeResult so stream merges
 * cannot undo an explicit Mark spam / Mark not spam. Cleared on store cleanup,
 * and bounded by `SPAM_OVERRIDE_MAX` in between. */
const spamUserOverrides = new Map<string, { isSpam: boolean; spamRating: number; reasons?: string[] }>();
type SpamOverride = NonNullable<ReturnType<typeof spamUserOverrides.get>>;

/**
 * Ceiling on the override table, the same bound and the same treatment
 * `SPAM_CACHE_MAX` gives the search page's tooltip cache — and for the same
 * reason, that nothing else prunes it. This was emptied only by
 * `notifySpamFilterReset` and store teardown, so a long session spent marking
 * spam grew it for as long as the window stayed open.
 *
 * Set far above any plausible number of marks in flight at once, which is what
 * makes eviction safe here: `handleMarkSpam` reverts a failed IPC through the
 * entry this holds, so dropping one a request is still waiting on would lose the
 * revert. Reaching that would take 500 marks issued before the first came back.
 */
const SPAM_OVERRIDE_MAX = 500;

function setSpamOverride(hash: string, override: SpamOverride): void {
  // Deleted before it is set, so a re-mark moves the hash to the back of the
  // insertion order the eviction below reads: what gets dropped is then the mark
  // the user touched longest ago rather than whichever they happened to make
  // first, and never the one just written.
  spamUserOverrides.delete(hash);
  spamUserOverrides.set(hash, override);
  while (spamUserOverrides.size > SPAM_OVERRIDE_MAX) {
    const oldest = spamUserOverrides.keys().next().value;
    if (oldest === undefined) break;
    spamUserOverrides.delete(oldest);
  }
}

/** Ranking ceiling for peer-reported counts, matching MAX_PLAUSIBLE_SOURCES in
 * merge.rs (pinned by `scripts/fixtures/merge-contract.json`). ed2k carries this
 * count as a u16 on the wire, so anything above it is a claim no honest peer can
 * make. */
const MAX_PLAUSIBLE_SOURCES = 65535;
/** Pin with `scripts/fixtures/merge-contract.json` / `MAX_SOURCE_ADDRS` in merge.rs.
 * Sized to what `start_download` will actually accept (its `MAX_EXTRA_SOURCES_IPC`
 * is 64, and the network task seeds at most 49); addresses beyond that were kept
 * and shipped over IPC only to be dropped on arrival. */
const MAX_SOURCE_ADDRS = 64;

/** Whether a row carries anything that explains a spam verdict — the prose list
 *  or the coded one, since `spamReasonTexts` renders from either. */
function hasSpamExplanation(row: SearchResult): boolean {
  return !!(row.spam_reasons?.length || row.spam_reason_details?.length);
}

function mergeResult(existing: SearchResult, incoming: SearchResult): SearchResult {
  const mergedAddresses = Array.from(new Set([...(existing.source_addresses || []), ...(incoming.source_addresses || [])])).slice(0, MAX_SOURCE_ADDRS);
  // Backend ed2k resights emit absolute noted availability; take max so we do
  // not double-sum. Cross-server summing happens in Rust before the emit.
  // Kad / mixed origins also use max (matches merge.rs).
  const availability = Math.min(
    Math.max(existing.availability || 0, incoming.availability || 0, mergedAddresses.length),
    MAX_PLAUSIBLE_SOURCES,
  );
  const existingMedia = existing.media || {};
  const incomingMedia = incoming.media || {};
  const media = {
    duration: existingMedia.duration ?? incomingMedia.duration,
    bitrate: existingMedia.bitrate ?? incomingMedia.bitrate,
    codec: existingMedia.codec || incomingMedia.codec,
    artist: existingMedia.artist || incomingMedia.artist,
    album: existingMedia.album || incomingMedia.album,
    title: existingMedia.title || incomingMedia.title,
  };
  const hasMedia = Object.values(media).some((v) => v != null && v !== '');
  const existingName = existing.file.name || '';
  const incomingName = incoming.file.name || '';
  // First-seen wins so a padded attacker name cannot rename the row. Exception:
  // a Local (shared-library) name is the file we actually have — prefer it.
  const incomingIsLocal = (incoming.result_origin || '').includes('Local');
  const existingIsLocal = (existing.result_origin || '').includes('Local');
  const preferredName =
    incomingIsLocal && !existingIsLocal && incomingName
      ? incomingName
      : existingName || incomingName;
  const hash = incoming.file.hash || existing.file.hash || '';
  const override = hash ? spamUserOverrides.get(hash) : undefined;
  const spam_rating = override
    ? override.spamRating
    : Math.max(existing.spam_rating ?? 0, incoming.spam_rating ?? 0);
  const is_spam = override
    ? override.isSpam
    // Search channels can disagree or report partial spam evaluation. Treat a
    // positive classification and the highest observed score conservatively;
    // a later unflagged hit must not erase an earlier warning for the same file
    // unless the user explicitly unmarked it (override above).
    : existing.is_spam || incoming.is_spam;
  // The English list and the coded list explain the same verdict, so they have
  // to travel together: prose from one scoring pass beside codes from another
  // would render two different explanations for one row. A user override
  // carries no codes — its text is already in the active locale.
  //
  // Which verdict's explanation to keep is `takesIncomingSpamSignals`, the same
  // rule `merge_into` applies in merge.rs. This used to adopt the incoming pair
  // whenever the incoming row was flagged at all, ignoring the score.
  const takeIncomingSignals = takesIncomingSpamSignals(
    !!existing.is_spam,
    existing.spam_rating ?? 0,
    !!incoming.is_spam,
    incoming.spam_rating ?? 0,
  );
  // An empty list from the winning side is normally adopted as-is, which is the
  // point: if the verdict came from that row, so does its explanation, and
  // "flagged, no reasons given" is a truthful one. Falling back to the other
  // side's list whenever this one is empty is the mix-and-match the rule above
  // exists to prevent.
  //
  // The exception is a *flagged* row that neither list explains, which is the
  // one outcome a user cannot read at all: the badge says spam, the tooltip is
  // blank, and `spam_rating` — merged with max, so it can come from the side that
  // was overruled — shows a score nothing on screen justifies. A verdict from
  // `existing.is_spam` with `existing.spam_reasons` absent, which is what a
  // channel that classifies without reporting signal detail sends, landed there
  // every time. So a flagged row keeps whichever side actually has an
  // explanation; only an unflagged row, or one both sides leave unexplained,
  // ends up with nothing.
  //
  // A deliberate divergence from `merge_into`, alongside the availability,
  // filename and address-cap ones the module header lists, and deliberately not
  // in `merge-contract.json` for the same reason they are not: Rust merges rows
  // for the wire, where an unexplained flag costs nothing, while this copy is the
  // one feeding the tooltip the badge promises.
  const preferredSignals = takeIncomingSignals ? incoming : existing;
  const otherSignals = takeIncomingSignals ? existing : incoming;
  const spamSignals = override?.reasons
    ? { spam_reasons: override.reasons, spam_reason_details: undefined }
    : is_spam && !hasSpamExplanation(preferredSignals) && hasSpamExplanation(otherSignals)
      ? otherSignals
      : preferredSignals;
  return {
    ...existing,
    ...incoming,
    file: {
      ...existing.file,
      ...incoming.file,
      name: preferredName,
      size: existing.file.size || incoming.file.size,
      hash: incoming.file.hash || existing.file.hash,
      extension: incoming.file.extension || existing.file.extension,
      // An AICH root is not voted on the way the Ember digest is — it arrives
      // whole from an `h=` link or known.met — so first non-empty wins here.
      aich_hash: existing.file.aich_hash || incoming.file.aich_hash,
      ember_file_hash: pickEmberDigest(
        existing.file.ember_file_hash || '',
        existing.result_origin || '',
        incoming.file.ember_file_hash || '',
      ),
      complete_sources: Math.min(
        Math.max(existing.file.complete_sources || 0, incoming.file.complete_sources || 0),
        MAX_PLAUSIBLE_SOURCES,
      ),
    },
    peer_id: existing.peer_id || incoming.peer_id,
    peer_name: existing.peer_name || incoming.peer_name,
    availability,
    // First non-empty wins on all three, which is what `merge_into` does. They
    // used to take the *incoming* value here while Rust kept the existing one, so
    // the same two rows merged to a different type, rating and comment depending
    // on which layer did the merging. Keeping the first is also the rule the
    // filename already follows, and for the same reason: a later answer for a
    // public hash is not evidence, and letting it overwrite is a free rewrite.
    file_type: existing.file_type || incoming.file_type,
    source_addresses: mergedAddresses,
    rating: existing.rating ?? incoming.rating,
    comment: existing.comment ?? incoming.comment,
    media: hasMedia ? media : existing.media || incoming.media,
    spam_rating,
    is_spam,
    origin_server_ip: existing.origin_server_ip || incoming.origin_server_ip,
    spam_reasons: spamSignals.spam_reasons,
    spam_reason_details: spamSignals.spam_reason_details,
    // `clean_name` is derived from whichever `file.name` its own row carried, so
    // it has to follow the name we kept above. Taking the incoming one while
    // `file.name` keeps the first meant the row could display one filename and
    // hand a different one to `startDownload` — i.e. to disk. Falling back to
    // '' is safe: every consumer already falls back to `file.name`.
    clean_name:
      incomingName === preferredName
        ? incoming.clean_name || existing.clean_name
        : existing.clean_name,
    result_origin: combineOrigin(existing.result_origin || '', incoming.result_origin || ''),
  };
}

/**
 * Hard ceiling on the results one tab retains.
 *
 * Nothing upstream bounds accumulation: the ed2k TCP parser caps a single
 * packet at 1000 hits and UDP is bounded by the datagram, but a global search
 * keeps streaming those packets from every server and KAD node it reaches for
 * as long as it runs, so a broad query grew the array (and every full-list
 * pass the search page makes over it) without limit. 15k rows is far more than
 * any user scrolls and still merges and sorts in a few milliseconds.
 */
const MAX_TAB_RESULTS = 15_000;
/**
 * Overflowing a tab trims it to here rather than exactly to the cap, so the
 * eviction sort runs once per ~1.5k new results instead of once per flush for
 * the rest of the search.
 */
const TAB_RESULTS_LOW_WATER = MAX_TAB_RESULTS - 1_500;

/**
 * Merge one batch into a tab, preserving `mergeResult`'s dedup semantics
 * (source counts and origins are combined across duplicates) while touching
 * only the incoming rows. Returns a new tab object with a fresh `results`
 * array — consumers are `$derived` off it and would not see an in-place
 * mutation — but the id index is carried across flushes and updated in place.
 */
function mergeIntoTab(tab: SearchTab, incoming: SearchResult[]): SearchTab {
  if (incoming.length === 0) return tab;
  const results = tab.results.slice();
  let index = tab.resultIndex;
  // Results are deduplicated by key, so one entry per row is the invariant.
  // A mismatch means something replaced `results` without the index (Clear
  // Results empties it), and the cheapest correct answer is to rebuild.
  if (!index || index.size !== results.length) {
    index = new Map<string, number>();
    for (let i = 0; i < results.length; i++) index.set(resultKey(results[i]), i);
  }
  let shed = tab.shed ?? 0;
  let shedKeys = tab.shedKeys;
  for (const result of incoming) {
    const key = resultKey(result);
    const at = index.get(key);
    if (at === undefined) {
      if (shedKeys?.delete(key)) shed -= 1;
      index.set(key, results.length);
      results.push({
        ...result,
        availability: Math.min(result.availability || 0, MAX_PLAUSIBLE_SOURCES),
        file: {
          ...result.file,
          complete_sources: Math.min(result.file.complete_sources || 0, MAX_PLAUSIBLE_SOURCES),
        },
      });
    } else {
      results[at] = mergeResult(results[at], result);
    }
  }
  if (results.length > MAX_TAB_RESULTS) {
    shedWeakestRows(results, TAB_RESULTS_LOW_WATER);
    const kept = new Map<string, number>();
    for (let i = 0; i < results.length; i++) kept.set(resultKey(results[i]), i);
    shedKeys ??= new Set();
    shed += rememberShed(shedKeys, index.keys(), kept);
    index = kept;
  }
  return { ...tab, results, resultIndex: index, shed, shedKeys };
}

function updateTabByRequestId(
  tabs: SearchTab[],
  requestId: number,
  fn: (tab: SearchTab) => SearchTab,
): SearchTab[] {
  const i = tabs.findIndex((t) => t.requestId === requestId);
  if (i === -1) return tabs;
  const next = [...tabs];
  next[i] = fn(next[i]);
  return next;
}

/** Update a tab by network request id (for invoke completion / errors). */
export function patchSearchTabByRequestId(requestId: number, fn: (tab: SearchTab) => SearchTab) {
  searchTabs.update((tabs) => updateTabByRequestId(tabs, requestId, fn));
}

/** Merge results into the tab owning `requestId`. The only supported way to
 *  add results to a tab: it keeps the per-tab id index and the result cap in
 *  step, which a caller assembling `results` itself would not. */
export function appendSearchResults(requestId: number, incoming: SearchResult[]) {
  if (!Array.isArray(incoming) || incoming.length === 0) return;
  const activeId = get(activeSearchTabId);
  // The invoke reply can land after `search-complete` already trimmed an idle
  // background tab; the trim applies to what it brings too.
  searchTabs.update((tabs) =>
    updateTabByRequestId(tabs, requestId, (t) => trimIdleTab(mergeIntoTab(t, incoming), activeId)),
  );
}

/**
 * Where a hash sits in a tab, via the tab's own key index when it is usable.
 *
 * `resultKey` *is* the hash for any row that has one, so an index hit is the
 * row and an index miss is authoritative — the same lookup `mergeIntoTab`
 * makes, and the reason the index exists. The size check is its validity test
 * (one entry per row is the invariant); the identity check behind it costs one
 * comparison and keeps a stale index from patching the wrong row, which a
 * scan cannot do.
 */
function resultIndexOfHash(tab: SearchTab, fileHash: string): number {
  const index = tab.resultIndex;
  if (index && index.size === tab.results.length) {
    const at = index.get(fileHash);
    if (at === undefined) return -1;
    if (tab.results[at]?.file.hash === fileHash) return at;
  }
  return tab.results.findIndex((r) => r.file.hash === fileHash);
}

/** The fields a spam verdict owns. Restored together, because a score without
 *  the reasons that produced it explains nothing. */
function spamFieldsOf(r: SearchResult) {
  return {
    is_spam: r.is_spam,
    spam_rating: r.spam_rating,
    spam_reasons: r.spam_reasons,
    spam_reason_details: r.spam_reason_details,
  };
}

/**
 * Patch `is_spam` / `spam_rating` for a file hash across all tabs.
 * Only reallocates tabs/results that actually contain a match.
 * Records a user override so later stream merges cannot undo the choice.
 *
 * Returns the undo for the whole call — the rows *and* the override entry.
 * A failed `mark_spam` used to be reverted by patching the previous values
 * back through this same function, which restored the row but left
 * `spamUserOverrides` holding those values as though the user had chosen
 * them. `mergeResult` honours an override ahead of every later scoring pass,
 * so an IPC failure on a first-ever mark pinned the file to "not spam" for
 * the rest of the session: the backend could never flag it again, and nothing
 * short of resetting the learned data cleared it.
 */
export function patchSpamFlagByHash(
  fileHash: string,
  isSpam: boolean,
  spamRating: number,
  reasons?: string[],
): () => void {
  if (!fileHash) return () => {};
  const hadOverride = spamUserOverrides.has(fileHash);
  const previousOverride = spamUserOverrides.get(fileHash);
  setSpamOverride(fileHash, { isSpam, spamRating, reasons });
  // Keyed by tab id rather than by row position: the undo runs after an IPC
  // round-trip, by which time a streaming merge may have grown the tab.
  const undoRows: { tabId: string; fields: ReturnType<typeof spamFieldsOf> }[] = [];
  let patched = false;
  searchTabs.update((tabs) => {
    let anyChanged = false;
    const next = tabs.map((tab) => {
      const idx = resultIndexOfHash(tab, fileHash);
      if (idx === -1) return tab;
      const current = tab.results[idx];
      if (
        current.is_spam === isSpam
        && current.spam_rating === spamRating
        && (reasons === undefined || sameReasons(current.spam_reasons, reasons))
      ) {
        return tab;
      }
      anyChanged = true;
      undoRows.push({ tabId: tab.id, fields: spamFieldsOf(current) });
      const results = tab.results.slice();
      results[idx] = {
        ...current,
        is_spam: isSpam,
        spam_rating: spamRating,
        spam_reasons: reasons ?? current.spam_reasons,
        // The override's text is already translated, so it has no codes to
        // localize from; leaving the previous ones would re-render the
        // pre-override explanation.
        spam_reason_details: reasons ? undefined : current.spam_reason_details,
      };
      return { ...tab, results };
    });
    patched = anyChanged;
    return anyChanged ? next : tabs;
  });
  // After the tabs are committed, not inside the updater: the page reads both
  // stores in one effect, and bumping this while `searchTabs` is mid-update
  // would publish the signal ahead of the rows it is signalling.
  if (patched) searchRowPatchEpoch.update((n) => n + 1);
  return () => {
    if (hadOverride) setSpamOverride(fileHash, previousOverride!);
    else spamUserOverrides.delete(fileHash);
    if (undoRows.length === 0) return;
    let restored = false;
    searchTabs.update((tabs) => {
      let anyChanged = false;
      const next = tabs.map((tab) => {
        const undo = undoRows.find((u) => u.tabId === tab.id);
        if (!undo) return tab;
        const idx = resultIndexOfHash(tab, fileHash);
        if (idx === -1) return tab;
        anyChanged = true;
        const results = tab.results.slice();
        // Only the verdict goes back. Anything else the row picked up while
        // the IPC was in flight — a re-sight's source count, a second
        // origin — belongs to the merge, not to the mark being undone.
        results[idx] = { ...tab.results[idx], ...undo.fields };
        return { ...tab, results };
      });
      restored = anyChanged;
      return anyChanged ? next : tabs;
    });
    if (restored) searchRowPatchEpoch.update((n) => n + 1);
  };
}

function sameReasons(a: string[] | undefined, b: string[] | undefined): boolean {
  if (a === b) return true;
  if (!a || !b || a.length !== b.length) return false;
  return a.every((v, i) => v === b[i]);
}

/** Ceiling on open search tabs, evicting oldest-first — the same bound
 *  `chatTabs.ts` puts on the chat dock. Set well below that store's 50
 *  because a search tab is far heavier: each one holds its own result array,
 *  up to `MAX_TAB_RESULTS` rows. */
const MAX_SEARCH_TABS = 20;

/**
 * Rows a finished tab keeps once the user has moved off it.
 *
 * `MAX_TAB_RESULTS` bounds one tab; nothing bounded the set, so twenty finished
 * broad searches could sit on 300k rows no one was looking at. The tab being
 * viewed and the one still streaming keep their full cap.
 */
const IDLE_TAB_RESULTS = 3_000;

function trimIdleTab(tab: SearchTab, activeId: string | null): SearchTab {
  if (tab.id === activeId || tab.isSearching || tab.results.length <= IDLE_TAB_RESULTS) return tab;
  const results = tab.results.slice();
  shedWeakestRows(results, IDLE_TAB_RESULTS);
  const resultIndex = new Map<string, number>();
  for (let i = 0; i < results.length; i++) resultIndex.set(resultKey(results[i]), i);
  const shed = (tab.shed ?? 0) + (tab.results.length - results.length);
  // Finished, so nothing will come back to be told apart.
  return { ...tab, results, resultIndex, shed, shedKeys: undefined };
}

function trimIdleTabs(tabs: SearchTab[], activeId: string | null): SearchTab[] {
  let changed = false;
  const next = tabs.map((tab) => {
    const trimmed = trimIdleTab(tab, activeId);
    if (trimmed !== tab) changed = true;
    return trimmed;
  });
  return changed ? next : tabs;
}

/**
 * Cancel a search, retrying briefly when the network task is busy.
 *
 * A tab's request id is rotated the moment it stops being the active search,
 * so a cancel that never lands is invisible from here: nothing waits on it and
 * no late result will be attributed to the old id. What does not go away is the
 * walk — KAD and Ember keep querying until their own 60s expiry, holding
 * routing-table and search-manager slots the *next* search needs. `cancelSearch`
 * fails when the command channel is saturated, which is exactly when those
 * slots are scarcest, so one attempt is not enough.
 */
async function cancelSearchWithRetry(requestId: number): Promise<void> {
  const delaysMs = [0, 250, 1000];
  let lastError: unknown = null;
  for (const delay of delaysMs) {
    if (delay > 0) await new Promise((resolve) => setTimeout(resolve, delay));
    try {
      await cancelSearch(requestId);
      return;
    } catch (e) {
      lastError = e;
    }
  }
  console.warn(
    `Failed to cancel search ${requestId}; its DHT walks will expire on their own`,
    lastError,
  );
}

/** Start a new search tab and select it. Returns tab id and request id for invoke/searchFiles. */
export function openSearchTab(query: string, method: SearchMethod, fileType?: string, filters?: SearchFilters, related?: RelatedSearchInfo): { tabId: string; requestId: number; stoppedOthers: boolean } {
  const requestId = newSearchNonce();
  const id = newTabId();
  const tab: SearchTab = {
    id,
    requestId,
    query,
    method,
    fileType,
    filters,
    related,
    results: [],
    resultIndex: new Map(),
    isSearching: true,
    progress: null,
    error: null,
  };
  let stoppedOthers = false;
  searchTabs.update((tabs) => {
    // Capture original ids *before* rotating them: cancel and the pending
    // buffer are keyed by the in-flight request, not the discarded nonce.
    const searchingIds = tabs.filter((t) => t.isSearching).map((t) => t.requestId);
    const next = tabs.map((t) => {
      // The network keeps only the latest search to continue; a new one
      // replaces it, so no older tab can offer Search More any longer.
      if (!t.isSearching) return t.canSearchMore ? { ...t, canSearchMore: false } : t;
      stoppedOthers = true;
      return { ...t, isSearching: false, progress: null, requestId: newSearchNonce() };
    });
    next.push(tab);
    while (next.length > MAX_SEARCH_TABS) {
      const evicted = next.shift();
      if (!evicted) break;
      pendingByRequest.delete(evicted.requestId);
    }
    for (const rid of searchingIds) {
      pendingByRequest.delete(rid);
      void cancelSearchWithRetry(rid);
    }
    return trimIdleTabs(next, id);
  });
  activeSearchTabId.set(id);
  return { tabId: id, requestId, stoppedOthers };
}

export function setActiveSearchTab(tabId: string | null) {
  activeSearchTabId.set(tabId);
  // Checked before writing: an object store notifies on every `set`, even of
  // the same array, and the search page re-derives its whole list from it.
  const tabs = get(searchTabs);
  const trimmed = trimIdleTabs(tabs, tabId);
  if (trimmed !== tabs) searchTabs.set(trimmed);
}

export async function closeSearchTab(tabId: string): Promise<void> {
  const tabs = get(searchTabs);
  const idx = tabs.findIndex((t) => t.id === tabId);
  if (idx === -1) return;
  const tab = tabs[idx];
  if (tab.isSearching) {
    await cancelSearchWithRetry(tab.requestId);
  }
  const currentTabs = get(searchTabs);
  const currentIdx = currentTabs.findIndex((t) => t.id === tabId);
  if (currentIdx === -1) return;
  const remaining = currentTabs.filter((t) => t.id !== tabId);
  searchTabs.set(remaining);
  const active = get(activeSearchTabId);
  if (active === tabId) {
    const newIdx = Math.max(0, currentIdx - 1);
    activeSearchTabId.set(remaining[newIdx]?.id ?? remaining[0]?.id ?? null);
  }
}

// search-results coalescing buffer + flush scheduling. Hoisted to module
// scope (rather than living inside initSearchStore) so cleanupSearchStore can
// cancel a scheduled flush — otherwise a stale rAF/timeout could merge a
// buffered batch into the tabs we just cleared on teardown/re-init.
const pendingByRequest = new Map<number, SearchResult[]>();
let flushScheduled = false;
let flushRaf: number | null = null;
let flushTimeout: ReturnType<typeof setTimeout> | null = null;

/** Drop any coalesced `search-results` buffer for a request so a Clear
 * Results / discard cannot be refilled by a late flush (SF9). */
export function clearPendingSearchResults(requestId: number) {
  pendingByRequest.delete(requestId);
}

/** Merge any coalesced `search-results` for this request into its tab now.
 *  Stop / timeout / starting another search used to delete the buffer, which
 *  dropped LocalIndex hits that had arrived but not yet painted. */
export function flushPendingSearchResults(requestId: number) {
  const incoming = pendingByRequest.get(requestId);
  pendingByRequest.delete(requestId);
  if (!incoming || incoming.length === 0) return;
  searchTabs.update((tabs) =>
    updateTabByRequestId(tabs, requestId, (t) => mergeIntoTab(t, incoming)),
  );
}

function validRequestId(raw: unknown): number | null {
  return typeof raw === 'number' && Number.isSafeInteger(raw) && raw > 0 ? raw : null;
}

function validCount(raw: unknown): number {
  return typeof raw === 'number' && Number.isFinite(raw) ? Math.max(0, Math.floor(raw)) : 0;
}

function flushSearchResults() {
  flushScheduled = false;
  // Cancel rather than merely forget. `search-complete` calls this
  // synchronously, and an already-queued frame would otherwise survive with no
  // tracked handle — escaping `cleanupSearchStore`'s `cancelAnimationFrame`,
  // which exists precisely to stop a stale flush refilling cleared tabs.
  if (flushRaf !== null && typeof cancelAnimationFrame === 'function') cancelAnimationFrame(flushRaf);
  if (flushTimeout !== null) clearTimeout(flushTimeout);
  flushRaf = null;
  flushTimeout = null;
  if (pendingByRequest.size === 0) return;
  // Snapshot-and-clear the buffer up front rather than iterating the live
  // `pendingByRequest` reference and clearing it afterward. Both currently
  // execute back-to-back with no `await` between them, so nothing can slip
  // a new batch in between today — but aliasing instead of snapshotting
  // means any future change that adds an await (or a re-entrant caller)
  // would start silently dropping results. Matches the snapshot pattern
  // `flushProgress` already uses in `stores/transfers.ts`.
  const batch = new Map(pendingByRequest);
  pendingByRequest.clear();
  searchTabs.update((tabs) => {
    let next = tabs;
    for (const [requestId, incoming] of batch) {
      next = updateTabByRequestId(next, requestId, (t) => mergeIntoTab(t, incoming));
    }
    return next;
  });
}

function scheduleFlush() {
  if (flushScheduled) return;
  flushScheduled = true;
  if (typeof requestAnimationFrame === 'function' && typeof document !== 'undefined' && document.visibilityState === 'visible') {
    flushRaf = requestAnimationFrame(flushSearchResults);
    // Armed alongside the frame, not instead of it.
    //
    // The choice above is made when the batch arrives, and browsers do not run
    // frame callbacks for a hidden document — so a window minimized after a
    // frame was requested but before it fired left `flushScheduled` true with
    // nothing to clear it. Every later batch then appended to
    // `pendingByRequest` and returned here immediately, and because the
    // `MAX_TAB_RESULTS` ceiling lives inside `mergeIntoTab`, the buffer that
    // stopped draining was the one thing nothing else bounds. Whichever of the
    // two fires first flushes; `flushSearchResults` cancels the other.
    flushTimeout = setTimeout(flushSearchResults, 250);
  } else {
    // Hidden tab or non-DOM host (SSR / tests): fall back to a macrotask so we
    // still coalesce but don't hang the burst waiting for a visibilitychange
    // that might never come.
    flushTimeout = setTimeout(flushSearchResults, 32);
  }
}

function spamSettingsKey(
  s: { spam_filter_enabled: boolean; spam_filter_profile: string } | null | undefined,
): string | null {
  if (!s) return null;
  return `${s.spam_filter_enabled ? '1' : '0'}:${s.spam_filter_profile}`;
}

/**
 * Fold a re-scored batch back into the tab it came from.
 *
 * Only the verdict is adopted, so a row keeps everything the merge gave it.
 * `resultIndex` survives for the same reason: `resultKey` is derived from the
 * hash / id / path / name+size, none of which a re-score touches, and the map
 * is rebuilt in place order — so positions and keys are exactly what they
 * were and the next streamed batch can use the index instead of rebuilding it.
 */
function applyRescoredRows(tabId: string, scored: SearchResult[]) {
  if (scored.length === 0) return;
  // A chunked re-score outlives the tab it started on — closed, cleared, or
  // torn down with the page — so a chunk landing on nothing must not tell the
  // search page its rows changed and cost it a whole-list filter and sort.
  let applied = false;
  searchTabs.update((current) => {
    const i = current.findIndex((t) => t.id === tabId);
    if (i === -1) return current;
    // Keyed by `resultKey`, not `file.hash`. Hashless rows are a supported
    // case — `resultKey` has dedicated `nohash-id:` / `nohash-path:` /
    // `nohash:` branches for pending library entries and path-only local
    // hits — and every one of them keys to `''`, so a hash-keyed map kept
    // only the last and every other hashless row in the tab then adopted
    // that one row's spam verdict.
    const byKey = new Map(scored.map((r) => [resultKey(r), r]));
    const results = current[i].results.map((r) => {
      const n = byKey.get(resultKey(r));
      if (!n) return r;
      const override = r.file.hash ? spamUserOverrides.get(r.file.hash) : undefined;
      return {
        ...r,
        spam_rating: override?.spamRating ?? n.spam_rating,
        is_spam: override?.isSpam ?? n.is_spam,
        spam_reasons: override?.reasons ?? n.spam_reasons,
        spam_reason_details: override?.reasons ? undefined : n.spam_reason_details,
      };
    });
    const next = [...current];
    next[i] = { ...current[i], results };
    applied = true;
    return next;
  });
  if (applied) searchRowPatchEpoch.update((n) => n + 1);
}

/**
 * Rows per `rescore_search_results` call.
 *
 * The backend caps one call at 15,000 and chunks its own scoring so it cannot
 * sit on the spam lock; this is the other half of that, because the payload
 * crosses IPC and both `JSON.stringify` on the way out and the parse on the
 * way back run on the thread that draws the window. A whole tab is up to
 * `MAX_TAB_RESULTS` rows of several hundred bytes each — megabytes in one
 * blocking call. Split, the same rows cost the same total work in slices the
 * frame budget can absorb, and the tab updates as each lands instead of all
 * at the end.
 *
 * Safe to split because this pass looks at one row at a time: the command
 * deliberately scores without batch statistics, so a chunk boundary cannot
 * change a verdict.
 */
const RESCORE_IPC_CHUNK = 1_000;

async function rescoreRowsIntoTab(tabId: string, query: string, rows: SearchResult[]) {
  for (let i = 0; i < rows.length; i += RESCORE_IPC_CHUNK) {
    applyRescoredRows(tabId, await rescoreSearchResults(rows.slice(i, i + RESCORE_IPC_CHUNK), query));
  }
}

/** Re-score every open tab after spam settings change (SF8). Honors per-hash
 *  user mark/unmark overrides so an explicit classification is not overwritten. */
async function rescoreOpenTabs() {
  const tabs = get(searchTabs);
  // Active tab first, so the one the user is looking at is corrected before the
  // work for up to nineteen others they cannot see. Each call is a full re-pass
  // over that tab's results against every learned spam name, so fanning all of
  // them out at once was the heaviest thing a single settings change could ask
  // the backend to do.
  const activeId = get(activeSearchTabId);
  const ordered = [...tabs].sort((a, b) =>
    a.id === activeId ? -1 : b.id === activeId ? 1 : 0,
  );
  for (const tab of ordered) {
    if (tab.results.length === 0) continue;
    try {
      await rescoreRowsIntoTab(tab.id, tab.query, tab.results);
    } catch (e) {
      console.error('Failed to rescore search results:', e);
    }
  }
}

/**
 * Re-score the tab a spam mark was made in, which is what marking one row is
 * for: the backend learns the filename, the name with the query words removed,
 * the size and the source IPs, and every one of those is a rule about *other*
 * rows. Without this the user marks the obvious fake and its nine siblings sit
 * there unflagged until the next search.
 *
 * eMule does exactly this — `CSearchList::MarkFileAsSpam` learns, then
 * `RecalculateSpamRatings(nSearchID, bExpectHigher, bExpectLower, ...)` re-rates
 * that one search — including the part that keeps it affordable: a mark can
 * only push scores up, so rows already flagged cannot change and are skipped;
 * an unmark can only pull them down, so rows already clean are skipped. Only
 * the rows whose verdict can actually move are sent.
 *
 * Coalesced, because eMule marks a whole selection and re-rates once
 * (`CSearchListCtrl::OnCommand`, MP_MARKASSPAM) while our context menu marks
 * one row per click. A burst of marks in both directions leaves nothing safely
 * skippable, so that case re-scores the lot.
 */
const SPAM_MARK_RESCORE_DEBOUNCE_MS = 400;
let spamMarkRescoreTimer: ReturnType<typeof setTimeout> | null = null;
let spamMarkRescorePending: { tabId: string; expectHigher: boolean; expectLower: boolean } | null = null;

export function rescoreTabAfterSpamMark(tabId: string, marked: 'spam' | 'not-spam') {
  if (!tabId) return;
  const expectHigher = marked === 'spam';
  if (spamMarkRescorePending && spamMarkRescorePending.tabId === tabId) {
    spamMarkRescorePending.expectHigher ||= expectHigher;
    spamMarkRescorePending.expectLower ||= !expectHigher;
  } else {
    // A mark in another tab supersedes rather than queues: the pending one was
    // for a list the user has moved on from, and the new tab is the one they
    // are looking at.
    spamMarkRescorePending = { tabId, expectHigher, expectLower: !expectHigher };
  }
  if (spamMarkRescoreTimer !== null) clearTimeout(spamMarkRescoreTimer);
  spamMarkRescoreTimer = setTimeout(() => {
    spamMarkRescoreTimer = null;
    const pending = spamMarkRescorePending;
    spamMarkRescorePending = null;
    if (pending) void runSpamMarkRescore(pending);
  }, SPAM_MARK_RESCORE_DEBOUNCE_MS);
}

async function runSpamMarkRescore(pending: {
  tabId: string;
  expectHigher: boolean;
  expectLower: boolean;
}) {
  const tab = get(searchTabs).find((t) => t.id === pending.tabId);
  if (!tab || tab.results.length === 0) return;
  const { expectHigher, expectLower } = pending;
  // Marks in both directions coalesced into this pass, so nothing is safely
  // skippable and the whole list is re-scored. Running the filter below on both
  // expectations at once excluded *every* row instead — a flagged row fails the
  // first test, an unflagged row fails the second — so the re-rating this
  // function exists for silently did nothing whenever a mark was followed by a
  // correcting unmark.
  const candidates =
    expectHigher && expectLower
      ? tab.results
      : tab.results.filter(
          (r) => !(r.is_spam && expectHigher) && !(!r.is_spam && expectLower),
        );
  if (candidates.length === 0) return;
  try {
    await rescoreRowsIntoTab(tab.id, tab.query, candidates);
  } catch (e) {
    console.error('Failed to rescore search results after a spam mark:', e);
  }
}

/** After Settings resets learned spam data: drop in-session marks and rescore open tabs. */
export async function notifySpamFilterReset() {
  spamUserOverrides.clear();
  spamFilterEpoch.update((n) => n + 1);
  await rescoreOpenTabs();
}

export async function initSearchStore() {
  if (initialized) return;

  initialized = true;
  const myEpoch = storeEpoch;
  const registered: UnlistenFn[] = [];
  try {
    // `search-results` events are coalesced per request id across one
    // animation frame via the module-level `pendingByRequest`/`scheduleFlush`
    // (see above). A global-phase KAD/server search streams dozens of small
    // batches back-to-back; buffering folds them into one merge per tab per
    // frame instead of an O(N·B) rebuild per event.
    registered.push(await listen<{ request_id: number; results: SearchResult[] }>('search-results', (event) => {
      const requestId = validRequestId(event.payload?.request_id);
      if (requestId === null) return;
      const incoming = event.payload.results;
      if (!Array.isArray(incoming)) return;
      if (dev) {
        const origins = new Set(incoming.map((r) => r.result_origin).filter(Boolean));
        if (origins.size > 0) {
          console.debug(`[search-results] req=${requestId} count=${incoming.length} origins=${[...origins].join(', ')}`);
        }
      }
      const existing = pendingByRequest.get(requestId);
      if (existing) {
        // In-place concat beats recreating the array — the buffer is
        // internal, and we clear it at flush time.
        for (const r of incoming) existing.push(r);
      } else {
        pendingByRequest.set(requestId, incoming.slice());
      }
      scheduleFlush();
    }));
    registered.push(await listen<{ request_id: number; can_search_more?: boolean }>('search-complete', (event) => {
      const requestId = validRequestId(event.payload?.request_id);
      if (requestId === null) return;
      const canSearchMore = event.payload?.can_search_more === true;
      // Flush any buffered `search-results` for this request synchronously
      // before flipping `isSearching` off — otherwise the spinner could
      // disappear while the last batch of results is still queued for the
      // next animation frame, and the UI would briefly show "done with
      // N results" where N is missing the final chunk.
      if (pendingByRequest.has(requestId)) {
        flushSearchResults();
      }
      const activeId = get(activeSearchTabId);
      searchTabs.update((tabs) =>
        updateTabByRequestId(tabs, requestId, (t) =>
          trimIdleTab({ ...t, isSearching: false, progress: null, canSearchMore }, activeId),
        ),
      );
    }));
    registered.push(await listen<{ request_id: number; nodes_contacted: number; results_so_far: number; phase: string }>(
      'search-progress',
      (event) => {
        const requestId = validRequestId(event.payload?.request_id);
        if (requestId === null) return;
        searchTabs.update((tabs) =>
          updateTabByRequestId(tabs, requestId, (t) => {
            if (!t.isSearching) return t;
            return {
              ...t,
              progress: {
                nodes_contacted: validCount(event.payload?.nodes_contacted),
                results_so_far: validCount(event.payload?.results_so_far),
                phase: typeof event.payload?.phase === 'string' ? event.payload.phase : '',
              },
            };
          }),
        );
      },
    ));
  } catch (e) {
    for (const u of registered) u();
    initialized = false;
    console.error('Failed to initialize search store listeners:', e);
    throw e;
  }
  if (myEpoch !== storeEpoch) {
    // `cleanupSearchStore` ran while we were still registering (dev HMR
    // remount / rapid re-init). Unlisten what we just added rather than
    // adopting orphaned listeners into an already-torn-down store.
    for (const u of registered) u();
    return;
  }
  unlisteners.push(...registered);
  lastSpamSettingsKey = spamSettingsKey(get(appSettings));
  unsubSettings = appSettings.subscribe((s) => {
    const key = spamSettingsKey(s);
    if (key === lastSpamSettingsKey) return;
    lastSpamSettingsKey = key;
    if (key === null) return;
    void rescoreOpenTabs();
  });
}

export function cleanupSearchStore() {
  storeEpoch++;
  for (const unlisten of unlisteners) unlisten();
  unlisteners = [];
  unsubSettings?.();
  unsubSettings = null;
  lastSpamSettingsKey = null;
  initialized = false;
  // Cancel any scheduled result flush so a stale rAF/timeout can't merge a
  // buffered batch into the freshly-cleared tabs after teardown/re-init.
  if (flushRaf !== null && typeof cancelAnimationFrame === 'function') cancelAnimationFrame(flushRaf);
  if (flushTimeout !== null) clearTimeout(flushTimeout);
  flushRaf = null;
  flushTimeout = null;
  flushScheduled = false;
  pendingByRequest.clear();
  // The tab it was going to re-score is about to be dropped, and the overrides
  // it honours are cleared below.
  if (spamMarkRescoreTimer !== null) clearTimeout(spamMarkRescoreTimer);
  spamMarkRescoreTimer = null;
  spamMarkRescorePending = null;
  spamUserOverrides.clear();
  spamFilterEpoch.update((n) => n + 1);
  // Save the tabs before dropping them, and leave the emptied store unsaved.
  // The init-failure screen runs this and then offers Retry, which is a
  // reload: its `pagehide` persisted the empty list, deleting the saved tabs
  // the reload was going to restore.
  persistSearch();
  searchTabs.set([]);
  activeSearchTabId.set(null);
  persistDirty = false;
}
