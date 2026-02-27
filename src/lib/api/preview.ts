import { invoke } from '@tauri-apps/api/core';

export async function previewFile(transferId: string): Promise<string> {
  return invoke('preview_file', { transferId });
}
