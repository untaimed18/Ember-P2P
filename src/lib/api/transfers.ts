import { invoke } from '@tauri-apps/api/core';
import { withTimeout } from '$lib/utils';
import * as m from '$lib/paraglide/messages';
import type {
  Transfer,
  SourceInfo,
  StartDownloadResponse,
  UploadQueueClient,
  KnownClient,
} from '$lib/types';

/** Normalize a trusted AICH pin while rejecting malformed non-empty values. */
export function validatedExpectedAich(
  value: string | null | undefined,
): string | null {
  const trimmed = value?.trim().toLowerCase() ?? '';
  if (!trimmed) return null;
  if (trimmed.length !== 40 || !/^[0-9a-f]+$/.test(trimmed)) {
    // Never silently downgrade a caller-supplied integrity pin to an
    // unpinned download. Rust performs the same validation at the IPC
    // boundary; failing here gives the renderer an immediate localized error.
    throw new Error(m.error_transfers_invalid_expected_aich());
  }
  return trimmed;
}

export async function startDownload(
  fileHash: string,
  fileName: string,
  fileSize: number,
  peerIp: string,
  peerPort: number,
  /**
   * Optional list of additional candidate sources known up-front
   * (e.g. the rest of `result.source_addresses` from a search hit
   * beyond the primary peer). Each entry must be an "ip:port"
   * string; placeholders like "0.0.0.0:0" or "local" are dropped
   * server-side. The network task runs IP-filter / ban / dedup
   * validation before seeding, and falls back to its normal KAD +
   * server source discovery whether or not extras are provided.
   */
  extraSources?: string[],
  /** Optional Ember content BLAKE3 hex for download completion verify. */
  emberFileHash?: string,
  expectedAich?: string,
  /**
   * Set when this download was started from a friend's browse listing
   * (their Ember hash, 32-char hex). Lets the backend register the
   * primary seed into its source manager with identity up front, so a
   * friend download that never completes a single handshake before both
   * peers restart can still be relocated once rendezvous finds the
   * friend again.
   */
  friendEmberHash?: string,
): Promise<StartDownloadResponse> {
  // A source address identifies a peer, not the file. Never let a source-bearing
  // result bypass the mandatory content hash used to identify and verify it.
  if (!fileHash?.trim()) {
    throw new Error(m.error_transfers_invalid_file_hash());
  }
  return invoke('start_download', {
    fileHash,
    fileName,
    fileSize,
    peerIp,
    peerPort,
    extraSources: extraSources ?? null,
    emberFileHash: emberFileHash?.trim() ? emberFileHash.trim() : null,
    expectedAich: validatedExpectedAich(expectedAich),
    friendEmberHash: friendEmberHash ?? null,
  });
}

export async function takePendingDownloadOverflowNotice(): Promise<number> {
  return invoke('take_pending_download_overflow_notice');
}

// The three row actions the transfers footer latches `selectedActionBusy` on
// while they run: without a deadline a wedged command leaves Pause / Resume /
// Stop disabled for the rest of the session. Each takes the transfer-manager
// write lock, persists a status, then hands the network task a command through
// `bounded_send` — which is itself capped at 10 s, so the deadline here has to
// clear that for the backend's own coded error to win when the channel is the
// thing that's blocked. `withTimeout`'s 20 s default does. The command is not
// cancelled by the rejection, so a late success still shows up in the next
// 3 s transfer poll.
export async function pauseTransfer(transferId: string): Promise<void> {
  return withTimeout(invoke<void>('pause_transfer', { transferId }), 'pause_transfer');
}

export async function stopTransfer(transferId: string): Promise<void> {
  return withTimeout(invoke<void>('stop_transfer', { transferId }), 'stop_transfer');
}

export async function resumeTransfer(transferId: string): Promise<void> {
  return withTimeout(invoke<void>('resume_transfer', { transferId }), 'resume_transfer');
}

export async function cancelTransfer(transferId: string): Promise<void> {
  return invoke('cancel_transfer', { transferId });
}

export async function removeTransfer(transferId: string): Promise<void> {
  return invoke('remove_transfer', { transferId });
}

export async function getTransfers(): Promise<Transfer[]> {
  return invoke('get_transfers');
}

/** Snapshot of peers waiting in our upload queue (transfers/uploads pane,
 *  "Queued" tab). Polled on demand while the tab is visible. */
export async function getUploadQueue(): Promise<UploadQueueClient[]> {
  // Polled every 3 s while the tab is open, so it needs a deadline or a wedged
  // backend leaves the caller's in-flight guard latched forever. Reads an
  // in-memory queue snapshot; 8 s is generous.
  return withTimeout(invoke<UploadQueueClient[]>('get_upload_queue'), 'get_upload_queue', 8_000);
}

/** Snapshot of every persistent SecIdent credit record (transfers bottom
 *  pane, Known ED2K Peers / Known Ember Peers tabs). Lifetime view
 *  independent of which peers are connected right now. */
export async function getKnownClients(): Promise<KnownClient[]> {
  // Also polled (8 s). Reads the persistent credit store, so allow more room
  // than the queue snapshot above.
  return withTimeout(invoke<KnownClient[]>('get_known_clients'), 'get_known_clients', 15_000);
}

export async function clearCompleted(): Promise<number> {
  return invoke('clear_completed');
}

export async function setTransferPriority(transferId: string, priority: 'verylow' | 'low' | 'normal' | 'high' | 'release' | 'auto'): Promise<void> {
  return invoke('set_transfer_priority', { transferId, priority });
}

export async function setTransferCategory(transferId: string, category: string): Promise<void> {
  return invoke('set_transfer_category', { transferId, category });
}

export async function setPreviewPriority(transferId: string, enabled: boolean): Promise<void> {
  return invoke('set_preview_priority', { transferId, enabled });
}

export async function pauseAllTransfers(): Promise<void> {
  return invoke('pause_all_transfers');
}

export async function pauseTransfersBatch(transferIds: string[]): Promise<void> {
  return invoke('pause_transfers_batch', { transferIds });
}

export async function resumeTransfersBatch(transferIds: string[]): Promise<void> {
  return invoke('resume_transfers_batch', { transferIds });
}

export async function stopTransfersBatch(transferIds: string[]): Promise<void> {
  return invoke('stop_transfers_batch', { transferIds });
}

export async function cancelTransfersBatch(transferIds: string[]): Promise<void> {
  return invoke('cancel_transfers_batch', { transferIds });
}

export async function resumeAllTransfers(): Promise<void> {
  return invoke('resume_all_transfers');
}

export async function getTransferSources(transferId: string): Promise<SourceInfo[]> {
  // Gates the source drawer's spinner, so a hang here is a spinner that never
  // clears. Clones an in-memory row list behind the transfer-manager read
  // lock; 8 s as for `get_upload_queue`.
  return withTimeout(
    invoke<SourceInfo[]>('get_transfer_sources', { transferId }),
    'get_transfer_sources',
    8_000,
  );
}

export async function openFile(transferId: string): Promise<void> {
  return invoke('open_file', { transferId });
}

export async function openTransferFileLocation(transferId: string): Promise<void> {
  return invoke('open_transfer_file_location', { transferId });
}

/** Open the Downloads directory itself, for the downloads-pane background menu.
 *  Unlike `openTransferFileLocation` this needs no transfer, so it still works
 *  when the list is empty. */
export async function openDownloadsFolder(): Promise<void> {
  return invoke('open_downloads_folder');
}

export async function recoverArchive(transferId: string): Promise<string> {
  return invoke('recover_archive', { transferId });
}
