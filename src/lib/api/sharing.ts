import { invoke } from '@tauri-apps/api/core';
import * as m from '$lib/paraglide/messages';
import { codedErrorOf } from '$lib/i18n';
import { withTimeout } from '$lib/utils';
import type { FileInfo, MediaMetadata } from '$lib/types';

/** Result of one trip through the folder picker. Both lists are empty when the
 *  user cancels. */
export interface SharedFolderPick {
  /** Folders this selection newly shared; a scan is running for each. */
  added: string[];
  /** Folders the user picked that were already shared. Reported separately
   *  because the system-dialog fallback cannot mark them in the tree. */
  already_shared: string[];
  /** Files shared into a folder that was already on the list. */
  files_shared?: string[];
  /** Coded errors for the part of the selection that did not land while the
   *  rest did. A selection that shares nothing rejects instead. */
  failed?: string[];
}

/** Open the backend-owned native picker and add every selected folder. */
export async function addSharedFolder(): Promise<SharedFolderPick> {
  return invoke('pick_shared_folder', { title: m.picker_shared_folders() });
}

export type ShareBrowserKind =
  | 'this_pc'
  | 'home'
  | 'desktop'
  | 'documents'
  | 'downloads'
  | 'music'
  | 'pictures'
  | 'videos'
  | 'drive'
  | 'folder'
  | 'file';

/** `inherited`: inside a folder shared whole, so shared with it.
 *  `overlap`: inside a partly shared folder and not among what it offers.
 *  `contains_shared`: holds a folder that is already shared. */
export type ShareBrowserStatus =
  | 'shareable'
  | 'partial'
  | 'already'
  | 'inherited'
  | 'overlap'
  | 'contains_shared'
  | 'blocked';

export interface ShareBrowserEntry {
  id: number;
  name: string;
  path: string;
  kind: ShareBrowserKind;
  letter?: string | null;
  parent_id: number | null;
  share_status: ShareBrowserStatus;
  /** Byte length. Present for files. */
  size?: number | null;
  /** Files currently offered from a partly shared folder. */
  shared_count?: number | null;
}

export interface ShareBrowserView {
  session_id: number;
  current: ShareBrowserEntry;
  children: ShareBrowserEntry[];
  /** `children` is the first page of a location with more folders and files
   *  than the backend lists in one call. */
  truncated: boolean;
}

export async function openShareBrowser(): Promise<ShareBrowserView> {
  return invoke('open_share_browser');
}

export async function listShareBrowserChildren(
  sessionId: number,
  entryId: number,
): Promise<ShareBrowserView> {
  return invoke('list_share_browser_children', { sessionId, entryId });
}

export async function navigateShareBrowser(
  sessionId: number,
  path: string,
): Promise<ShareBrowserView> {
  return invoke('navigate_share_browser', { sessionId, path });
}

export async function shareBrowserSelection(
  sessionId: number,
  entryIds: number[],
): Promise<SharedFolderPick> {
  return invoke('share_browser_selection', { sessionId, entryIds });
}

export interface ShareBrowserMeasure {
  files: number;
  bytes: number;
  /** False when counting stopped early; `files` and `bytes` are lower bounds. */
  complete: boolean;
}

/** Count the files, and their bytes, under the given folder entries, by the
 *  rules the scan will use. Starting a count stops the previous one. */
export async function measureShareBrowserEntries(
  sessionId: number,
  entryIds: number[],
): Promise<ShareBrowserMeasure> {
  return invoke('measure_share_browser_entries', { sessionId, entryIds });
}

export async function closeShareBrowser(sessionId: number): Promise<void> {
  return invoke('close_share_browser', { sessionId });
}

/** Approve the folders a dropped file asked about.
 *
 *  Takes only the token the backend issued with the prompt — the paths never
 *  leave the backend, because a dropped path is authorization by virtue of the
 *  OS handing it to the native window, and routing it through the renderer
 *  would throw that away. Returns how many folders were shared. */
export async function confirmDroppedFolders(
  token: number,
  onlyDroppedFiles?: boolean,
): Promise<number> {
  return invoke('confirm_dropped_folders', { token, onlyDroppedFiles: onlyDroppedFiles ?? null });
}

/** Discard a dropped-file prompt the user declined. */
export async function dismissDroppedFolders(token: number): Promise<void> {
  return invoke('dismiss_dropped_folders', { token });
}

export async function removeSharedFolder(path: string): Promise<void> {
  return invoke('remove_shared_folder', { path });
}

/** The backend's cap on one `library_hashes_among` request. */
const MAX_LIBRARY_HASH_QUERY = 20_000;

/** Which of `hashes` (eD2K hex) name a file in the library, without pulling
 *  the library over. */
export async function libraryHashesAmong(hashes: string[]): Promise<Set<string>> {
  const found = new Set<string>();
  for (let i = 0; i < hashes.length; i += MAX_LIBRARY_HASH_QUERY) {
    const chunk = hashes.slice(i, i + MAX_LIBRARY_HASH_QUERY);
    for (const hash of await invoke<string[]>('library_hashes_among', { hashes: chunk })) {
      found.add(hash.toLowerCase());
    }
  }
  return found;
}

/** `files` is `null` when the library still matches `etag`. */
export interface SharedFilesSnapshot {
  etag: string;
  files: FileInfo[] | null;
}

export async function getSharedFilesIfChanged(etag: string | null): Promise<SharedFilesSnapshot> {
  return invoke('get_shared_files_if_changed', { etag });
}

/**
 * Count and total size of files the user is actively sharing (the `shared`
 * flag is set), not the total number of files in the library. Lightweight
 * enough for the status bar.
 */
export async function getSharedFileCount(): Promise<{ count: number; total_bytes: number }> {
  return invoke('get_shared_file_count');
}

/** Which of `hashes` are in the library (shared or not), lowercased. At most
 *  5,000 per call. */
export async function libraryHasHashes(hashes: string[]): Promise<string[]> {
  return invoke('library_has_hashes', { hashes });
}

export async function getSharedFolders(): Promise<string[]> {
  return invoke('get_shared_folders');
}

/** Shared folders that are on disk but not approved, so none of their files
 *  can be uploaded. Offline folders are not included. */
export async function getUnapprovedSharedFolders(): Promise<string[]> {
  return invoke('get_unapproved_shared_folders');
}

/** Ask the user, in a native dialog, to re-approve a shared folder Ember no
 *  longer recognises. Resolves to whether it is approved afterwards. */
export async function reapproveSharedFolder(path: string): Promise<boolean> {
  return invoke('reapprove_shared_folder', { path });
}

export async function getFolderPriorities(): Promise<Record<string, string>> {
  return invoke('get_folder_priorities');
}

/** How long `getFileMediaMetadata` waits out another file's probe in total. */
const MEDIA_METADATA_WAIT_MS = 5_000;
const MEDIA_METADATA_RETRY_MS = 150;

/** On-demand media metadata for a shared file (null for non-media files).
 *
 *  The backend probes one file at a time and refuses a second request while
 *  one runs. Selecting another file while a slow probe (a network drive, say)
 *  was still reading the last one used to come back as "no metadata" for the
 *  file now selected, so this waits its turn instead, for a bounded time.
 *
 *  `stillWanted` is asked before each retry: a wait for a file the user has
 *  moved on from would otherwise keep competing for the one slot with the
 *  file now selected. Unwanted, it resolves null. */
export async function getFileMediaMetadata(
  filePath: string,
  stillWanted: () => boolean = () => true,
): Promise<MediaMetadata | null> {
  const deadline = Date.now() + MEDIA_METADATA_WAIT_MS;
  for (;;) {
    try {
      return await invoke<MediaMetadata | null>('get_file_media_metadata', { filePath });
    } catch (e: unknown) {
      if (codedErrorOf(e)?.code !== 'sharing_media_request_in_flight' || Date.now() >= deadline) {
        throw e;
      }
      await new Promise((resolve) => setTimeout(resolve, MEDIA_METADATA_RETRY_MS));
      if (!stillWanted()) return null;
    }
  }
}

/**
 * Set (or, with an empty/`none` priority, clear) the default upload priority
 * for a shared folder. Applies immediately to files under the folder and
 * persists so newly indexed files inherit it. Returns the count updated.
 */
export async function setFolderPriority(folderPath: string, priority: string): Promise<number> {
  return invoke('set_folder_priority', { folderPath, priority });
}

export async function setFilePriority(filePath: string, priority: 'verylow' | 'low' | 'normal' | 'high' | 'release' | 'auto'): Promise<void> {
  return invoke('set_file_priority', { filePath, priority });
}

export async function reloadSharedFiles(): Promise<void> {
  return invoke('reload_shared_files');
}

export async function getScanStatus(): Promise<boolean> {
  // Reads a flag, but the library page polls it every 3 s: without a deadline
  // a wedged backend latches that poll's in-flight guard for good and the
  // "hashing" banner never clears. Deliberately NOT applied to `startScan` /
  // `reloadSharedFiles` — those are legitimately long-running.
  return withTimeout(invoke<boolean>('get_scan_status'), 'get_scan_status', 8_000);
}

/** Whether hashing is held by a Stop. Kept by the backend, so the Library can
 *  show its Resume banner again after the page was left and reopened. */
export async function getHashingPaused(): Promise<boolean> {
  return withTimeout(invoke<boolean>('get_hashing_paused'), 'get_hashing_paused', 8_000);
}

export async function getLibraryScanTruncated(): Promise<boolean> {
  return invoke('get_library_scan_truncated');
}

export async function stopHashing(): Promise<string[]> {
  return invoke('stop_hashing');
}

/**
 * Which shared folders would actually lose files if hashing stopped now, without
 * stopping it. Empty means stopping costs nothing — every file in the Library
 * keeps its hash, its shares and its stats.
 */
export async function previewStopHashing(): Promise<string[]> {
  return invoke('preview_stop_hashing');
}

/**
 * Progress of the background pass that fills in missing AICH roots and Ember
 * digests, as `[done, total]`, or `null` when it isn't running.
 *
 * Separate from the scan's own progress because it is a different kind of work:
 * every file it touches is already shared and servable, so there is nothing at
 * stake and nothing to wait for. It is reported only so the drives are not busy
 * for an unexplained reason.
 */
export async function hashTopUpStatus(): Promise<[number, number] | null> {
  return invoke('hash_top_up_status');
}

export async function resumeHashing(): Promise<void> {
  return invoke('resume_hashing');
}

export async function unshareFile(filePath: string, fileHash?: string): Promise<void> {
  return invoke('unshare_file', { filePath, fileHash });
}

export async function batchSetPriority(filePaths: string[], priority: string): Promise<number> {
  return invoke('batch_set_priority', { filePaths, priority });
}

export async function batchUnshare(filePaths: string[]): Promise<number> {
  return invoke('batch_unshare', { filePaths });
}

/**
 * Restrict files to mutual friends, or return them to the open network.
 * Resolves with the number of files whose scope actually changed.
 */
export async function setFilesFriendsOnly(
  filePaths: string[],
  friendsOnly: boolean,
): Promise<number> {
  return invoke('set_files_friends_only', { filePaths, friendsOnly });
}

export async function unshareFolder(path: string): Promise<void> {
  return invoke('unshare_folder', { path });
}

export async function openSharedFile(filePath: string): Promise<void> {
  return invoke('open_shared_file', { filePath });
}

/** Open a folder of the Library's tree itself (a shared folder or one inside
 *  it), where `openSharedFolder` opens the folder a file is in. */
export async function openLibraryFolder(folderPath: string): Promise<void> {
  return invoke('open_library_folder', { folderPath });
}

export interface CategoryMoveReport {
  /** Files now in the category's folder. */
  moved: number;
  /** Files that were in it already. */
  unchanged: number;
  /** A coded error for each file that stayed where it was. */
  failed: string[];
}

/** Move Library files into the folder `category` names inside Downloads, as a
 *  finished download moves when its category changes. `'None'` is Downloads
 *  itself. A finished download in the transfer list takes the category too. */
export async function moveFilesToCategory(paths: string[], category: string): Promise<CategoryMoveReport> {
  return invoke('move_files_to_category', { paths, category });
}

export async function openSharedFolder(filePath: string): Promise<void> {
  return invoke('open_shared_folder', { filePath });
}

/** Canonical path safe for convertFileSrc / in-app media playback. */
export async function resolveMediaAssetPath(filePath: string): Promise<string> {
  return invoke('resolve_media_asset_path', { filePath });
}

export async function deleteSharedFile(filePath: string, fileHash?: string): Promise<void> {
  return invoke('delete_shared_file', { filePath, fileHash });
}

export async function republishFile(fileHash: string): Promise<void> {
  return invoke('republish_file', { fileHash });
}

export async function scanMissingFiles(): Promise<{
  paths: string[];
  truncated: boolean;
  totalMissing: number;
}> {
  return invoke('scan_missing_files');
}

export async function removeMissingFiles(paths: string[]): Promise<number> {
  return invoke('remove_missing_files', { paths });
}
