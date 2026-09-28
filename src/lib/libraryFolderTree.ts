/** Nested folder tree for the Library sidebar, built from share roots + indexed files. */

export type LibraryFolderNode = {
  path: string;
  name: string;
  count: number;
  size: number;
  isShare: boolean;
  children: LibraryFolderNode[];
};

export type LibraryFolderRow = {
  path: string;
  name: string;
  count: number;
  size: number;
  isShare: boolean;
  hasChildren: boolean;
  expanded: boolean;
  depth: number;
};

function lastSegment(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).pop() || path;
}

function joinUnder(base: string, segment: string): string {
  const sep = base.includes('\\') && !base.includes('/') ? '\\' : '/';
  return `${base.replace(/[\\/]+$/, '')}${sep}${segment}`;
}

type MutableNode = {
  path: string;
  name: string;
  count: number;
  size: number;
  isShare: boolean;
  children: Map<string, MutableNode>;
};

function childKey(segment: string, caseInsensitive: boolean): string {
  return caseInsensitive ? segment.toLowerCase() : segment;
}

function freeze(node: MutableNode): LibraryFolderNode {
  const children = [...node.children.values()]
    .map(freeze)
    .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
  return {
    path: node.path,
    name: node.name,
    count: node.count,
    size: node.size,
    isShare: node.isShare,
    children,
  };
}

/**
 * Build one tree per shared folder. Each file is attributed to the deepest
 * matching share (same rule as the Library's per-folder counts), then walked
 * into nested directory nodes. Counts include descendants, matching the
 * existing "all files under this folder" filter.
 */
export function buildLibraryFolderTree(
  shares: string[],
  files: { path: string; size: number }[],
  normalize: (path: string) => string,
): LibraryFolderNode[] {
  const shareNodes: MutableNode[] = shares.map((path) => ({
    path,
    name: lastSegment(path),
    count: 0,
    size: 0,
    isShare: true,
    children: new Map(),
  }));
  const normalizedShares = shareNodes.map((node) => ({
    node,
    norm: normalize(node.path),
  }));
  normalizedShares.sort((a, b) => b.norm.length - a.norm.length);
  // Probe the caller's own rule rather than inspecting the share paths: a
  // Windows library whose shares all happened to be stored lowercase would
  // otherwise be treated as case-sensitive, and `Albums` / `albums` under it
  // would split into two nodes.
  const caseInsensitive = normalize('A') !== 'A';

  for (const file of files) {
    const fileNorm = normalize(file.path);
    const match = normalizedShares.find(
      ({ norm }) => fileNorm === norm || fileNorm.startsWith(`${norm}/`),
    );
    if (!match) continue;
    const { node } = match;
    node.count += 1;
    node.size += file.size;

    const fileDirs = file.path.split(/[\\/]/).filter(Boolean);
    fileDirs.pop();
    const shareDirs = node.path.split(/[\\/]/).filter(Boolean);
    if (fileDirs.length <= shareDirs.length) continue;
    const segments = fileDirs.slice(shareDirs.length);

    let cursor = node;
    let cursorPath = node.path;
    for (const segment of segments) {
      cursorPath = joinUnder(cursorPath, segment);
      const key = childKey(segment, caseInsensitive);
      let child = cursor.children.get(key);
      if (!child) {
        child = {
          path: cursorPath,
          name: segment,
          count: 0,
          size: 0,
          isShare: false,
          children: new Map(),
        };
        cursor.children.set(key, child);
      }
      child.count += 1;
      child.size += file.size;
      cursor = child;
    }
  }

  return shareNodes.map(freeze);
}

export function flattenLibraryFolderTree(
  nodes: LibraryFolderNode[],
  expanded: ReadonlySet<string>,
  depth = 0,
): LibraryFolderRow[] {
  const rows: LibraryFolderRow[] = [];
  for (const node of nodes) {
    const hasChildren = node.children.length > 0;
    const isExpanded = hasChildren && expanded.has(node.path);
    rows.push({
      path: node.path,
      name: node.name,
      count: node.count,
      size: node.size,
      isShare: node.isShare,
      hasChildren,
      expanded: isExpanded,
      depth,
    });
    if (isExpanded) {
      rows.push(...flattenLibraryFolderTree(node.children, expanded, depth + 1));
    }
  }
  return rows;
}

/** Share roots and nested folders that must be expanded so `filterPath` is visible. */
export function ancestorFolderPaths(
  nodes: LibraryFolderNode[],
  filterPath: string,
  normalize: (path: string) => string,
): string[] {
  const target = normalize(filterPath);
  const found: string[] = [];

  function walk(list: LibraryFolderNode[], trail: string[]): boolean {
    for (const node of list) {
      const nextTrail = [...trail, node.path];
      if (normalize(node.path) === target) {
        found.push(...trail);
        return true;
      }
      if (walk(node.children, nextTrail)) return true;
    }
    return false;
  }

  walk(nodes, []);
  return found;
}
