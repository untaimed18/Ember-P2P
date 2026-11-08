/**
 * The folder each file goes in within a new collection: where it sits
 * relative to the deepest folder every selected file is under, `/`-separated,
 * empty for a file in that folder itself.
 *
 * Relative to what the selection shares rather than to the shared folder, so
 * picking a show's `Season 1` and `Season 2` gives exactly those two folders,
 * and picking files from one folder gives none. But never above the shared
 * folder the files are in: a collection is made to be passed on, and files
 * from two drives or two shared folders share nothing but the path to them,
 * which names the user's account (`C:/Users/<name>/…`). Those get no folders.
 * The backend cleans each folder again before writing it.
 *
 * `caseInsensitive` where the file system compares names that way (Windows).
 */
export function collectionFolders(
  paths: readonly string[],
  sharedFolders: readonly string[],
  caseInsensitive: boolean,
): string[] {
  const same = (a: string, b: string) => a === b || (caseInsensitive && a.toLowerCase() === b.toLowerCase());
  const startsWith = (path: string[], prefix: string[]) =>
    prefix.length <= path.length && prefix.every((segment, i) => same(segment, path[i]));
  const roots = sharedFolders.map(segmentsOf).filter((root) => root.length > 0);
  const parents = paths.map((path) => {
    const parts = segmentsOf(path);
    parts.pop();
    return parts;
  });
  if (parents.length === 0) return [];
  const rootOf = (parent: string[]) =>
    roots.filter((root) => startsWith(parent, root)).reduce<string[] | null>(
      (deepest, root) => (deepest && deepest.length >= root.length ? deepest : root),
      null,
    );
  const root = rootOf(parents[0]);
  const underRoot = (parent: string[]) => {
    const own = rootOf(parent);
    return own !== null && own.length === root?.length && startsWith(own, root);
  };
  if (!root || !parents.every(underRoot)) {
    return parents.map(() => '');
  }
  let common = parents[0].length;
  for (const parent of parents.slice(1)) {
    let shared = 0;
    while (shared < common && shared < parent.length && same(parent[shared], parents[0][shared])) shared++;
    common = shared;
  }
  return parents.map((parent) => parent.slice(Math.max(common, root.length)).join('/'));
}

/**
 * A path's folder names, outermost first, with the extended `\\?\` and
 * `\\?\UNC\` prefixes dropped: a finished download can be recorded in that
 * form while its shared folder is stored in the plain one.
 */
function segmentsOf(path: string): string[] {
  const parts = path.split(/[\\/]+/).filter((part) => part.length > 0);
  if (parts[0] === '?') {
    parts.shift();
    if (parts[0]?.toUpperCase() === 'UNC') parts.shift();
  }
  return parts;
}
