import { invoke } from '@tauri-apps/api/core';
import type { SearchResult } from '$lib/types';

export async function searchFiles(query: string): Promise<SearchResult[]> {
  return invoke('search_files', { query });
}
