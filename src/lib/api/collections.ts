import { invoke } from '@tauri-apps/api/core';

export interface CollectionFile {
  name: string;
  size: number;
  hash: string;
  aich_hash: string;
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

export async function loadCollection(path: string): Promise<Collection> {
  return invoke('load_collection', { path });
}

/** Opens a native picker; files selected by the user may live outside Library roots. */
export async function pickAndLoadCollection(): Promise<Collection | null> {
  return invoke('pick_and_load_collection');
}

export async function createCollection(
  name: string,
  author: string,
  files: CollectionFile[],
  outputPath: string,
  binary: boolean
): Promise<string> {
  return invoke('create_collection', { name, author, files, outputPath, binary });
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
