import { invoke } from '@tauri-apps/api/core';
import type { SearchResult, SpamExplanation, SpamStats, DownloadHistoryStats } from '$lib/types';

export type SearchMethod = 'global' | 'server' | 'kad' | 'ember';

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

export type Ed2kLinkFile = {
  name: string;
  size: number;
  hash: string;
  emberFileHash?: string | null;
};

export async function formatEd2kLink(
  name: string,
  size: number,
  fileHash: string,
  emberFileHash?: string | null,
): Promise<string> {
  return invoke('format_ed2k_link', {
    name,
    size,
    fileHash,
    emberFileHash: emberFileHash?.trim() ? emberFileHash.trim() : null,
  });
}

/** Format many standard eD2K links in one IPC call (newline-separated). */
export async function formatEd2kLinks(files: Ed2kLinkFile[]): Promise<string> {
  return invoke('format_ed2k_links', { files });
}

/**
 * Build an ed2k link variant. When `aichHash` (40-char hex) is supplied it is
 * embedded as a base32 `h=` segment; when `emberFileHash` (64-char hex) is
 * supplied it is embedded as `eh=`; when `withSources` is true our reachable
 * endpoint is appended as a `sources,` segment (errors if firewalled).
 */
export async function buildEd2kLink(
  name: string,
  size: number,
  fileHash: string,
  opts: { aichHash?: string; emberFileHash?: string; withSources?: boolean } = {},
): Promise<string> {
  return invoke('build_ed2k_link', {
    name,
    size,
    fileHash,
    aichHash: opts.aichHash ?? null,
    emberFileHash: opts.emberFileHash ?? null,
    withSources: opts.withSources ?? false,
  });
}

export type Ed2kLinkInfo = {
  name: string;
  size: number;
  hash: string;
  aich?: string;
  ember?: string;
};

export async function parseEd2kLink(link: string): Promise<Ed2kLinkInfo> {
  return invoke('parse_ed2k_link', { link });
}

export type Ed2kLinkBatch = {
  links: Ed2kLinkInfo[];
  /** Non-blank lines that were not a valid ed2k file link. */
  invalid: number;
  /** Non-blank lines left unread once the per-paste cap was reached. */
  skipped: number;
};

/**
 * Parse a pasted block of newline-separated ed2k links. Use this for anything
 * that comes off the clipboard: `parseEd2kLink` accepts a multi-line blob and
 * silently returns only the first link, because the later lines survive as
 * `|`-segments its tag loop ignores.
 */
export async function parseEd2kLinks(text: string): Promise<Ed2kLinkBatch> {
  return invoke('parse_ed2k_links', { text });
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

export async function rescoreSearchResults(
  results: SearchResult[],
  searchKeywords: string[],
): Promise<SearchResult[]> {
  return invoke('rescore_search_results', { results, searchKeywords });
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
