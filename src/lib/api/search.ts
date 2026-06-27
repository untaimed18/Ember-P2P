import { invoke } from '@tauri-apps/api/core';
import type { SearchResult, SpamExplanation, SpamStats, DownloadHistoryStats } from '$lib/types';

export type SearchMethod = 'global' | 'server' | 'kad';

export interface SearchFilters {
  fileType?: string;
  fileExtension?: string;
  minSize?: number;
  maxSize?: number;
  minAvailability?: number;
}

export async function searchFiles(query: string, method: SearchMethod = 'global', requestId: number, fileType?: string, filters?: SearchFilters): Promise<SearchResult[]> {
  return invoke('search_files', {
    query,
    method,
    requestId,
    fileType: fileType || filters?.fileType || null,
    fileExtension: filters?.fileExtension || null,
    minSize: filters?.minSize ?? null,
    maxSize: filters?.maxSize ?? null,
    minAvailability: filters?.minAvailability ?? null,
  });
}

export async function cancelSearch(requestId: number): Promise<void> {
  return invoke('cancel_search', { requestId });
}

export async function formatEd2kLink(name: string, size: number, fileHash: string): Promise<string> {
  return invoke('format_ed2k_link', { name, size, fileHash });
}

/**
 * Build an ed2k link variant. When `aichHash` (40-char hex) is supplied it is
 * embedded as a base32 `h=` segment; when `withSources` is true our reachable
 * endpoint is appended as a `sources,` segment (errors if firewalled).
 */
export async function buildEd2kLink(
  name: string,
  size: number,
  fileHash: string,
  opts: { aichHash?: string; withSources?: boolean } = {},
): Promise<string> {
  return invoke('build_ed2k_link', {
    name,
    size,
    fileHash,
    aichHash: opts.aichHash ?? null,
    withSources: opts.withSources ?? false,
  });
}

export async function parseEd2kLink(link: string): Promise<{ name: string; size: number; hash: string; aich?: string }> {
  return invoke('parse_ed2k_link', { link });
}

export async function findSources(fileHash: string, fileSize: number): Promise<[string, number][]> {
  return invoke('find_sources', { fileHash, fileSize });
}

export async function findNotes(fileHash: string, fileSize: number): Promise<SearchResult[]> {
  return invoke('find_notes', { fileHash, fileSize });
}

export async function publishNote(fileHash: string, rating: number, comment: string, fileName?: string, fileSize?: number): Promise<string> {
  return invoke('publish_note', { fileHash, rating, comment, fileName: fileName ?? null, fileSize: fileSize ?? null });
}

export async function markSpam(
  fileHash: string,
  fileName: string,
  fileSize: number,
  sourceAddresses: string[],
  searchKeywords: string[],
  serverIp?: string,
): Promise<void> {
  return invoke('mark_spam', { fileHash, fileName, fileSize, sourceAddresses, searchKeywords, serverIp: serverIp ?? null });
}

export async function markNotSpam(fileHash: string): Promise<void> {
  return invoke('mark_not_spam', { fileHash });
}

export async function getSpamStats(): Promise<SpamStats> {
  return invoke('get_spam_stats');
}

export async function explainSpamResult(
  fileHash: string,
  fileName: string,
  fileSize: number,
  sourceAddresses: string[],
  searchKeywords: string[],
  serverIp?: string,
): Promise<SpamExplanation> {
  return invoke('explain_spam_result', {
    fileHash,
    fileName,
    fileSize,
    sourceAddresses,
    searchKeywords,
    serverIp: serverIp ?? null,
  });
}

export async function resetSpamFilter(): Promise<string> {
  return invoke('reset_spam_filter');
}

export async function getDownloadHistoryStats(): Promise<DownloadHistoryStats> {
  return invoke('get_download_history_stats');
}

export async function getDownloadHistory(hashes: string[]): Promise<Record<string, string>> {
  return invoke('get_download_history', { hashes });
}

export async function clearDownloadHistory(status: string): Promise<void> {
  return invoke('clear_download_history', { status });
}

/**
 * Remove a single download-history row by file hash.
 *
 * Complements `clearDownloadHistory(status)`, which wipes an entire
 * status bucket at once. This function is the per-row delete used by
 * the search-results context menu so users can "forget" an individual
 * stale or mistagged history entry (e.g. a `cancelled` row they want
 * the search view to stop flagging) without blowing away every other
 * entry of the same status.
 */
export async function removeDownloadHistoryEntry(fileHash: string): Promise<void> {
  return invoke('remove_download_history_entry', { fileHash });
}
