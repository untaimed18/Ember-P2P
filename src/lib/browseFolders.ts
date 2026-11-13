import { compareFileNames } from '$lib/utils';

/** A folder in a friend's browse, for the folder picker. */
export interface BrowseFolderOption {
  /** Its whole path, `/`-separated, from the friend's shared folder down. */
  path: string;
  /** Its own name. */
  name: string;
  /** How far below a shared folder it is: 0 for the shared folder itself. */
  depth: number;
  /** Files in it and in the folders below it. */
  count: number;
}

/** Every folder the files are in, and each folder above those, ordered as a
 *  tree: a folder, then the folders inside it, before its next sibling. */
export function browseFolderOptions(files: readonly { folder?: string }[]): BrowseFolderOption[] {
  const counts = new Map<string, number>();
  for (const file of files) {
    if (!file.folder) continue;
    const parts = file.folder.split('/');
    for (let i = 1; i <= parts.length; i++) {
      const path = parts.slice(0, i).join('/');
      counts.set(path, (counts.get(path) ?? 0) + 1);
    }
  }
  const options = [...counts].map(([path, count]) => {
    const parts = path.split('/');
    return { path, name: parts[parts.length - 1], depth: parts.length - 1, count };
  });
  options.sort((a, b) => {
    const pa = a.path.split('/');
    const pb = b.path.split('/');
    for (let i = 0; i < Math.min(pa.length, pb.length); i++) {
      const order = compareFileNames(pa[i], pb[i]);
      if (order !== 0) return order;
    }
    return pa.length - pb.length;
  });
  return options;
}

/** Whether a file is in `folder` or a folder below it. */
export function inBrowseFolder(file: { folder?: string }, folder: string): boolean {
  return file.folder === folder || (file.folder?.startsWith(`${folder}/`) ?? false);
}
