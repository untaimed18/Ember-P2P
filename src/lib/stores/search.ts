import { writable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import type { SearchResult } from '$lib/types';

export const searchResults = writable<SearchResult[]>([]);
export const searchQuery = writable<string>('');
export const isSearching = writable<boolean>(false);

let initialized = false;

export async function initSearchStore() {
  if (initialized) return;
  initialized = true;

  listen<SearchResult[]>('search-results', (event) => {
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
    isSearching.set(false);
  });
}
