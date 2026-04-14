import { get, writable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import type { SearchResult } from '$lib/types';
import type { UnlistenFn } from '@tauri-apps/api/event';
import type { SearchMethod, SearchFilters } from '$lib/api/search';
import { cancelSearch } from '$lib/api/search';

export type SearchTab = {
  id: string;
  requestId: number;
  query: string;
  method: SearchMethod;
  fileType?: string;
  filters?: SearchFilters;
  results: SearchResult[];
  isSearching: boolean;
  progress: { nodes_contacted: number; results_so_far: number; phase: string } | null;
  error: string | null;
};

export const searchTabs = writable<SearchTab[]>([]);
export const activeSearchTabId = writable<string | null>(null);

let initialized = false;
let unlisteners: UnlistenFn[] = [];
let searchNonce = 0;

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

function resultKey(result: SearchResult): string {
  if (result.file.hash) return result.file.hash;
  return `nohash:${result.result_origin}:${result.file.name}:${result.file.size}`;
}

function combineOrigin(a: string, b: string): string {
  if (!b || a === b) return a || b;
  if (!a) return b;
  const parts = [...a.split(' · '), ...b.split(' · ')]
    .map((s) => s.trim())
    .filter(Boolean);
  return [...new Set(parts)].sort().join(' · ');
}

function mergeResult(existing: SearchResult, incoming: SearchResult): SearchResult {
  const mergedAddresses = Array.from(new Set([...(existing.source_addresses || []), ...(incoming.source_addresses || [])]));
  const combinedAvailability = Math.max(existing.availability || 0, incoming.availability || 0);
  return {
    ...existing,
    ...incoming,
    file: {
      ...existing.file,
      ...incoming.file,
      name: incoming.file.name || existing.file.name,
      size: incoming.file.size ?? existing.file.size,
      hash: incoming.file.hash || existing.file.hash,
      extension: incoming.file.extension || existing.file.extension,
      aich_hash: incoming.file.aich_hash || existing.file.aich_hash,
      complete_sources: Math.max(existing.file.complete_sources || 0, incoming.file.complete_sources || 0),
    },
    peer_id: existing.peer_id || incoming.peer_id,
    peer_name: existing.peer_name || incoming.peer_name,
    availability: Math.max(combinedAvailability, mergedAddresses.length),
    file_type: incoming.file_type || existing.file_type,
    source_addresses: mergedAddresses,
    rating: incoming.rating ?? existing.rating,
    comment: incoming.comment ?? existing.comment,
    spam_rating: Math.max(existing.spam_rating ?? 0, incoming.spam_rating ?? 0),
    is_spam: existing.is_spam || incoming.is_spam,
    clean_name: incoming.clean_name || existing.clean_name,
    result_origin: combineOrigin(existing.result_origin || '', incoming.result_origin || ''),
  };
}

export function mergeSearchResults(existing: SearchResult[], incoming: SearchResult[]): SearchResult[] {
  const merged = new Map<string, SearchResult>();
  for (const result of existing) {
    merged.set(resultKey(result), result);
  }
  for (const result of incoming) {
    const key = resultKey(result);
    const current = merged.get(key);
    merged.set(key, current ? mergeResult(current, result) : result);
  }
  return [...merged.values()];
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

/** Start a new search tab and select it. Returns tab id and request id for invoke/searchFiles. */
export function openSearchTab(query: string, method: SearchMethod, fileType?: string, filters?: SearchFilters): { tabId: string; requestId: number } {
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
    isSearching: true,
    progress: null,
    error: null,
  };
  searchTabs.update((tabs) => [...tabs, tab]);
  activeSearchTabId.set(id);
  return { tabId: id, requestId };
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
  searchTabs.update((currentTabs) => currentTabs.filter((t) => t.id !== tabId));
  const active = get(activeSearchTabId);
  if (active === tabId) {
    const remaining = get(searchTabs);
    const newIdx = Math.max(0, idx - 1);
    activeSearchTabId.set(remaining[newIdx]?.id ?? remaining[0]?.id ?? null);
  }
}

export async function initSearchStore() {
  if (initialized) return;

  initialized = true;
  const registered: UnlistenFn[] = [];
  try {
    registered.push(await listen<{ request_id: number; results: SearchResult[] }>('search-results', (event) => {
      const requestId = event.payload.request_id;
      const incoming = event.payload.results;
      const origins = new Set(incoming.map((r) => r.result_origin).filter(Boolean));
      if (origins.size > 0) {
        console.debug(`[search-results] req=${requestId} count=${incoming.length} origins=${[...origins].join(', ')}`);
      }
      searchTabs.update((tabs) =>
        updateTabByRequestId(tabs, requestId, (t) => ({
          ...t,
          results: mergeSearchResults(t.results, incoming),
        })),
      );
    }));
    registered.push(await listen<{ request_id: number }>('search-complete', (event) => {
      const requestId = event.payload.request_id;
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
        const requestId = event.payload.request_id;
        searchTabs.update((tabs) =>
          updateTabByRequestId(tabs, requestId, (t) => {
            if (!t.isSearching) return t;
            return {
              ...t,
              progress: {
                nodes_contacted: event.payload.nodes_contacted,
                results_so_far: event.payload.results_so_far,
                phase: event.payload.phase,
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
  unlisteners.push(...registered);
}

export function cleanupSearchStore() {
  for (const unlisten of unlisteners) unlisten();
  unlisteners = [];
  initialized = false;
  searchTabs.set([]);
  activeSearchTabId.set(null);
}
