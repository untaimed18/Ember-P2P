/**
 * The folder each file goes in within a new collection: where it sits
 * relative to the deepest folder every selected file is under, `/`-separated,
 * empty for a file in that folder itself.
 *
 * Relative to what the selection shares rather than to the shared folder, so
 * picking a show's `Season 1` and `Season 2` gives exactly those two folders,
 * and picking files from one folder gives none. The backend cleans each folder
 * again before writing it.
 */
export function collectionFolders(paths: readonly string[]): string[] {
  const parents = paths.map((path) => {
    const parts = path.split(/[\\/]+/).filter((part) => part.length > 0);
    parts.pop();
    return parts;
  });
  if (parents.length === 0) return [];
  let common = parents[0].length;
  for (const parent of parents.slice(1)) {
    let shared = 0;
    while (shared < common && shared < parent.length && sameName(parent[shared], parents[0][shared])) shared++;
    common = shared;
  }
  return parents.map((parent) => parent.slice(common).join('/'));
}

/** Windows and macOS compare names without case, as the file system does. */
function sameName(a: string, b: string): boolean {
  return a === b || a.toLowerCase() === b.toLowerCase();
}
