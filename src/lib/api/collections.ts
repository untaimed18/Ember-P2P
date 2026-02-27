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

export async function loadCollection(path: string): Promise<Collection> {
  return invoke('load_collection', { path });
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

export async function downloadCollectionFiles(files: CollectionFile[]): Promise<string> {
  return invoke('download_collection_files', { files });
}
