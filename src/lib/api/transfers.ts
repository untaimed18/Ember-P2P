import { invoke } from '@tauri-apps/api/core';
import type { Transfer, SourceInfo } from '$lib/types';

export async function startDownload(
  fileHash: string,
  fileName: string,
  fileSize: number,
  peerIp: string,
  peerPort: number
): Promise<string> {
  return invoke('start_download', {
    fileHash,
    fileName,
    fileSize,
    peerIp,
    peerPort,
  });
}

export async function pauseTransfer(transferId: string): Promise<void> {
  return invoke('pause_transfer', { transferId });
}

export async function stopTransfer(transferId: string): Promise<void> {
  return invoke('stop_transfer', { transferId });
}

export async function resumeTransfer(transferId: string): Promise<void> {
  return invoke('resume_transfer', { transferId });
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

export async function clearCompleted(): Promise<number> {
  return invoke('clear_completed');
}

export async function setTransferPriority(transferId: string, priority: string): Promise<void> {
  return invoke('set_transfer_priority', { transferId, priority });
}

export async function setPreviewPriority(transferId: string, enabled: boolean): Promise<void> {
  return invoke('set_preview_priority', { transferId, enabled });
}

export async function pauseAllTransfers(): Promise<void> {
  return invoke('pause_all_transfers');
}

export async function resumeAllTransfers(): Promise<void> {
  return invoke('resume_all_transfers');
}

export async function getTransferSources(transferId: string): Promise<SourceInfo[]> {
  return invoke('get_transfer_sources', { transferId });
}

export async function openFile(transferId: string): Promise<void> {
  return invoke('open_file', { transferId });
}

export async function recoverArchive(transferId: string): Promise<string> {
  return invoke('recover_archive', { transferId });
}
