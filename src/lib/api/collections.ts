import { invoke } from '@tauri-apps/api/core';

export interface CollectionFile {
  name: string;
  size: number;
  hash: string;
  aich_hash: string;
  /** Optional 64-char hex BLAKE3 digest when the collection includes it. */
  ember_file_hash?: string;
}

export interface Collection {
  name: string;
  author: string;
  files: CollectionFile[];
}

export interface CollectionDownloadResult {
  queuedCount: number;
  skippedCount: number;
  oversizeCount: number;
  failedCount: number;
}

/** Opens a native picker; files selected by the user may live outside Library roots. */
export async function pickAndLoadCollection(): Promise<Collection | null> {
  return invoke('pick_and_load_collection');
}

/** Opens a native save dialog and writes the collection to its selected path. */
export async function createCollectionWithDialog(
  name: string,
  author: string,
  files: CollectionFile[],
  binary: boolean
): Promise<string | null> {
  return invoke('create_collection_with_dialog', { name, author, files, binary });
}

export async function downloadCollectionFiles(files: CollectionFile[]): Promise<CollectionDownloadResult> {
  return invoke('download_collection_files', { files });
}
