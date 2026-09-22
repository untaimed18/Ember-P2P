import { describe, expect, it } from 'vitest';
import {
  ancestorFolderPaths,
  buildLibraryFolderTree,
  flattenLibraryFolderTree,
} from './libraryFolderTree';

function win(path: string): string {
  return path.replace(/\\/g, '/').toLowerCase();
}

describe('buildLibraryFolderTree', () => {
  it('nests subfolders of a share and counts descendants', () => {
    const tree = buildLibraryFolderTree(
      ['C:\\Music'],
      [
        { path: 'C:\\Music\\a.mp3', size: 10 },
        { path: 'C:\\Music\\Albums\\one.mp3', size: 20 },
        { path: 'C:\\Music\\Albums\\Live\\two.mp3', size: 40 },
      ],
      win,
    );

    expect(tree).toHaveLength(1);
    expect(tree[0].name).toBe('Music');
    expect(tree[0].isShare).toBe(true);
    expect(tree[0].count).toBe(3);
    expect(tree[0].size).toBe(70);
    expect(tree[0].children).toHaveLength(1);
    expect(tree[0].children[0].name).toBe('Albums');
    expect(tree[0].children[0].isShare).toBe(false);
    expect(tree[0].children[0].count).toBe(2);
    expect(tree[0].children[0].children[0].name).toBe('Live');
    expect(tree[0].children[0].children[0].count).toBe(1);
  });

  it('attributes a file to the deepest overlapping share', () => {
    const tree = buildLibraryFolderTree(
      ['C:\\Media', 'C:\\Media\\Music'],
      [
        { path: 'C:\\Media\\clip.mp4', size: 5 },
        { path: 'C:\\Media\\Music\\song.mp3', size: 9 },
      ],
      win,
    );
    const media = tree.find((n) => n.name === 'Media')!;
    const music = tree.find((n) => n.name === 'Music')!;
    expect(media.count).toBe(1);
    expect(music.count).toBe(1);
    expect(media.children).toHaveLength(0);
  });

  it('keeps an empty share visible', () => {
    const tree = buildLibraryFolderTree(['/home/user/Empty'], [], (p) => p);
    expect(tree[0].count).toBe(0);
    expect(tree[0].children).toHaveLength(0);
  });

  it('folds case variants of one folder together on Windows', () => {
    const tree = buildLibraryFolderTree(
      ['C:\\Music'],
      [
        { path: 'C:\\Music\\Albums\\a.mp3', size: 1 },
        { path: 'C:\\Music\\albums\\b.mp3', size: 2 },
      ],
      win,
    );
    expect(tree[0].children).toHaveLength(1);
    expect(tree[0].children[0].count).toBe(2);
  });

  it('keeps case variants apart where paths are case-sensitive', () => {
    const tree = buildLibraryFolderTree(
      ['/srv/Music'],
      [
        { path: '/srv/Music/Albums/a.mp3', size: 1 },
        { path: '/srv/Music/albums/b.mp3', size: 2 },
      ],
      (p) => p,
    );
    expect(tree[0].children).toHaveLength(2);
  });

  it('does not walk a file that only shares a name prefix with the share', () => {
    const tree = buildLibraryFolderTree(
      ['C:\\Music'],
      [{ path: 'C:\\MusicVideos\\a.mp4', size: 7 }],
      win,
    );
    expect(tree[0].count).toBe(0);
  });
});

describe('flattenLibraryFolderTree', () => {
  it('hides children until the parent is expanded', () => {
    const tree = buildLibraryFolderTree(
      ['C:\\Music'],
      [{ path: 'C:\\Music\\Albums\\a.mp3', size: 1 }],
      win,
    );
    const collapsed = flattenLibraryFolderTree(tree, new Set());
    expect(collapsed.map((r) => r.name)).toEqual(['Music']);
    const expanded = flattenLibraryFolderTree(tree, new Set(['C:\\Music']));
    expect(expanded.map((r) => r.name)).toEqual(['Music', 'Albums']);
    expect(expanded[1].depth).toBe(1);
    expect(expanded[1].isShare).toBe(false);
  });
});

describe('ancestorFolderPaths', () => {
  it('returns the share and nested parents of the filtered folder', () => {
    const tree = buildLibraryFolderTree(
      ['C:\\Music'],
      [{ path: 'C:\\Music\\Albums\\Live\\a.mp3', size: 1 }],
      win,
    );
    const live = tree[0].children[0].children[0].path;
    expect(ancestorFolderPaths(tree, live, win)).toEqual([
      'C:\\Music',
      tree[0].children[0].path,
    ]);
  });
});
