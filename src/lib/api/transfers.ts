import { invoke } from '@tauri-apps/api/core';
import type { Transfer } from '$lib/types';

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

export async function resumeTransfer(transferId: string): Promise<void> {
  return invoke('resume_transfer', { transferId });
}

export async function cancelTransfer(transferId: string): Promise<void> {
  return invoke('cancel_transfer', { transferId });
}

export async function getTransfers(): Promise<Transfer[]> {
  return invoke('get_transfers');
}
