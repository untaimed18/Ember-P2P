import { get, writable, type Unsubscriber } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import type { SearchResult } from '$lib/types';
import type { UnlistenFn } from '@tauri-apps/api/event';
import type { SearchMethod, SearchFilters } from '$lib/api/search';
import { cancelSearch, rescoreSearchResults } from '$lib/api/search';
import { appSettings } from './settings';
import { dev } from '$app/environment';

export type SearchTab = {
  id: string;
  requestId: number;
  query: string;
  method: SearchMethod;
  fileType?: string;
  filters?: SearchFilters;
  results: SearchResult[];
  /** Persistent `resultKey` -> index-into-`results` map. Kept on the tab so a
   *  streaming flush only touches the incoming batch instead of rebuilding an
   *  index over everything accumulated so far. Treated as a cache: any code
   *  that replaces `results` without maintaining it (e.g. Clear Results) is
   *  detected by the length check in `mergeIntoTab` and the map is rebuilt. */
  resultIndex?: Map<string, number>;
  isSearching: boolean;
  progress: { nodes_contacted: number; results_so_far: number; phase: string } | null;
  error: string | null;
};

export const searchTabs = writable<SearchTab[]>([]);
export const activeSearchTabId = writable<string | null>(null);
/** Bumped when learned spam data is wiped so the search page can drop
 *  tooltip caches that would otherwise outlive empty `spam_reasons`. */
export const spamFilterEpoch = writable(0);

let initialized = false;
let unlisteners: UnlistenFn[] = [];
let unsubSettings: Unsubscriber | null = null;
let lastSpamSettingsKey: string | null = null;
let searchNonce = 0;
// Bumped by `cleanupSearchStore`; see the matching comment in
// `stores/network.ts` for why `initSearchStore` needs to re-check this
// after its async listener registration before adopting the results.
let storeEpoch = 0;

export function newSearchNonce(): number {
  searchNonce += 1;
  return searchNonce;
}

export function currentSearchNonce(): number {
  return searchNonce;
}

function newTabId(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return `t-${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
}

/*
 * `resultKey`, `combineOrigin` and `MAX_PLAUSIBLE_SOURCES` below re-implement
 * rules the backend already has in `src-tauri/src/search/merge.rs` (this store
 * merges the streamed batches a second time, per tab).
 * `scripts/fixtures/merge-contract.json` is the shared source of truth for the
 * parts that must agree, and both sides are tested against it —
 * `scripts/merge-contract.test.mjs` here, `merge_contract_fixture` there — so a
 * divergence fails a test instead of shipping.
 *
 * That Node test cannot import this module (Svelte-app TypeScript, no bundler on
 * that path), so it lifts these two function bodies out of the source text and
 * runs them: keep them pure and closed over nothing, and keep their signatures
 * on one line. The divergences from Rust *are* deliberate where commented
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

/** Per-hash user spam overrides. Honored by mergeResult so stream merges
 * cannot undo an explicit Mark spam / Mark not spam. Cleared on store cleanup. */
const spamUserOverrides = new Map<string, { isSpam: boolean; spamRating: number; reasons?: string[] }>();

/** Ranking ceiling for peer-reported counts, matching MAX_PLAUSIBLE_SOURCES in
 * merge.rs (pinned by `scripts/fixtures/merge-contract.json`). ed2k carries this
 * count as a u16 on the wire, so anything above it is a claim no honest peer can
 * make. */
const MAX_PLAUSIBLE_SOURCES = 65535;
/** Pin with `scripts/fixtures/merge-contract.json` / `MAX_SOURCE_ADDRS` in merge.rs. */
const MAX_SOURCE_ADDRS = 500;

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
  const spamSignals = override?.reasons
    ? { spam_reasons: override.reasons, spam_reason_details: undefined }
    : incoming.is_spam && (incoming.spam_reasons?.length ?? 0) > 0
      ? incoming
      : existing.spam_reasons?.length
        ? existing
        : incoming;
  return {
    ...existing,
    ...incoming,
    file: {
      ...existing.file,
      ...incoming.file,
      name: preferredName,
      size: incoming.file.size ?? existing.file.size,
      hash: incoming.file.hash || existing.file.hash,
      extension: incoming.file.extension || existing.file.extension,
      aich_hash: incoming.file.aich_hash || existing.file.aich_hash,
      ember_file_hash: incoming.file.ember_file_hash || existing.file.ember_file_hash,
      complete_sources: Math.min(
        Math.max(existing.file.complete_sources || 0, incoming.file.complete_sources || 0),
        MAX_PLAUSIBLE_SOURCES,
      ),
    },
    peer_id: existing.peer_id || incoming.peer_id,
    peer_name: existing.peer_name || incoming.peer_name,
    availability,
    file_type: incoming.file_type || existing.file_type,
    source_addresses: mergedAddresses,
    rating: incoming.rating ?? existing.rating,
    comment: incoming.comment ?? existing.comment,
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
  for (const result of incoming) {
    const key = resultKey(result);
    const at = index.get(key);
    if (at === undefined) {
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
    // Shed the least useful rows first. `availability` is the merged source
    // count `mergeResult` maintains, so the rows dropped are the ones no peer
    // claims to have — the ones a user can least act on. `sort` is stable, so
    // ties keep the earlier-seen hit.
    results.sort((a, b) => (b.availability || 0) - (a.availability || 0));
    results.length = TAB_RESULTS_LOW_WATER;
    index.clear();
    for (let i = 0; i < results.length; i++) index.set(resultKey(results[i]), i);
  }
  return { ...tab, results, resultIndex: index };
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
  searchTabs.update((tabs) =>
    updateTabByRequestId(tabs, requestId, (t) => mergeIntoTab(t, incoming)),
  );
}

/**
 * Patch `is_spam` / `spam_rating` for a file hash across all tabs.
 * Only reallocates tabs/results that actually contain a match.
 * Records a user override so later stream merges cannot undo the choice.
 */
export function patchSpamFlagByHash(
  fileHash: string,
  isSpam: boolean,
  spamRating: number,
  reasons?: string[],
) {
  if (!fileHash) return;
  spamUserOverrides.set(fileHash, { isSpam, spamRating, reasons });
  searchTabs.update((tabs) => {
    let anyChanged = false;
    const next = tabs.map((tab) => {
      const idx = tab.results.findIndex((r) => r.file.hash === fileHash);
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
    return anyChanged ? next : tabs;
  });
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

/** Start a new search tab and select it. Returns tab id and request id for invoke/searchFiles. */
export function openSearchTab(query: string, method: SearchMethod, fileType?: string, filters?: SearchFilters): { tabId: string; requestId: number; stoppedOthers: boolean } {
  const requestId = newSearchNonce();
  const id = newTabId();
  const tab: SearchTab = {
    id,
    requestId,
    query,
    method,
    fileType,
    filters,
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
      if (!t.isSearching) return t;
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
      void cancelSearch(rid).catch(() => { /* best effort */ });
    }
    return next;
  });
  activeSearchTabId.set(id);
  return { tabId: id, requestId, stoppedOthers };
}

export function setActiveSearchTab(tabId: string | null) {
  activeSearchTabId.set(tabId);
}

export async function closeSearchTab(tabId: string): Promise<void> {
  const tabs = get(searchTabs);
  const idx = tabs.findIndex((t) => t.id === tabId);
  if (idx === -1) return;
  const tab = tabs[idx];
  if (tab.isSearching) {
    try {
      await cancelSearch(tab.requestId);
    } catch {
      /* best effort */
    }
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

/** Re-score every open tab after spam settings change (SF8). Honors per-hash
 *  user mark/unmark overrides so an explicit classification is not overwritten. */
async function rescoreOpenTabs() {
  const tabs = get(searchTabs);
  for (const tab of tabs) {
    if (tab.results.length === 0) continue;
    const tabId = tab.id;
    try {
      const scored = await rescoreSearchResults(tab.results, tab.query);
      searchTabs.update((current) => {
        const i = current.findIndex((t) => t.id === tabId);
        if (i === -1) return current;
        const byHash = new Map(scored.map((r) => [r.file.hash, r]));
        const results = current[i].results.map((r) => {
          const n = byHash.get(r.file.hash);
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
        next[i] = { ...current[i], results, resultIndex: undefined };
        return next;
      });
    } catch (e) {
      console.error('Failed to rescore search results:', e);
    }
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
    registered.push(await listen<{ request_id: number }>('search-complete', (event) => {
      const requestId = validRequestId(event.payload?.request_id);
      if (requestId === null) return;
      // Flush any buffered `search-results` for this request synchronously
      // before flipping `isSearching` off — otherwise the spinner could
      // disappear while the last batch of results is still queued for the
      // next animation frame, and the UI would briefly show "done with
      // N results" where N is missing the final chunk.
      if (pendingByRequest.has(requestId)) {
        flushSearchResults();
      }
      searchTabs.update((tabs) =>
        updateTabByRequestId(tabs, requestId, (t) => ({
          ...t,
          isSearching: false,
          progress: null,
        })),
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
  spamUserOverrides.clear();
  spamFilterEpoch.update((n) => n + 1);
  searchTabs.set([]);
  activeSearchTabId.set(null);
}
