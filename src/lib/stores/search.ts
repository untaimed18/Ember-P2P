import { writable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import type { SearchResult } from '$lib/types';
import type { UnlistenFn } from '@tauri-apps/api/event';

export const searchResults = writable<SearchResult[]>([]);
export const searchQuery = writable<string>('');
export const isSearching = writable<boolean>(false);
export const searchProgress = writable<{ nodes_contacted: number; results_so_far: number; phase: string } | null>(null);

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

export async function initSearchStore() {
  if (initialized) return;
  initialized = true;

  unlisteners.push(
    await listen<SearchResult[]>('search-results', (event) => {
      searchResults.update((existing) => {
        const merged = [...existing];
        for (const result of event.payload) {
          const idx = merged.findIndex(
            (r) => r.file.hash === result.file.hash && r.peer_id === result.peer_id
          );
          if (idx >= 0) {
            merged[idx] = result;
          } else {
            merged.push(result);
          }
        }
        return merged;
      });
    })
  );

  unlisteners.push(
    await listen<void>('search-complete', () => {
      isSearching.set(false);
      searchProgress.set(null);
    })
  );

  unlisteners.push(
    await listen<{ nodes_contacted: number; results_so_far: number; phase: string }>('search-progress', (event) => {
      searchProgress.set(event.payload);
    })
  );
}

export function cleanupSearchStore() {
  for (const unlisten of unlisteners) unlisten();
  unlisteners = [];
  initialized = false;
}
