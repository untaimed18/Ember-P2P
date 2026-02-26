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

export async function findSources(fileHash: string, fileSize: number): Promise<[string, number][]> {
  return invoke('find_sources', { fileHash, fileSize });
}

export async function findNotes(fileHash: string, fileSize: number): Promise<SearchResult[]> {
  return invoke('find_notes', { fileHash, fileSize });
}

export async function publishNote(fileHash: string, rating: number, comment: string): Promise<void> {
  return invoke('publish_note', { fileHash, rating, comment });
}
