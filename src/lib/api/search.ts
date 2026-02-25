import { invoke } from '@tauri-apps/api/core';
import type { SearchResult } from '$lib/types';

export async function searchFiles(query: string): Promise<SearchResult[]> {
  return invoke('search_files', { query });
}

export async function formatEd2kLink(name: string, size: number, fileHash: string): Promise<string> {
  return invoke('format_ed2k_link', { name, size, fileHash });
}

export async function parseEd2kLink(link: string): Promise<{ name: string; size: number; hash: string }> {
  return invoke('parse_ed2k_link', { link });
}
