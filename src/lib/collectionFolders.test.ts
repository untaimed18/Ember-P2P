import { describe, expect, it } from 'vitest';
import { collectionFolders } from './collectionFolders';

describe('collectionFolders', () => {
  it('places files relative to the deepest folder they share', () => {
    expect(
      collectionFolders([
        'D:\\Anime\\Show\\Season 1\\e1.mkv',
        'D:\\Anime\\Show\\Season 1\\e2.mkv',
        'D:\\Anime\\Show\\Season 2\\Extras\\op.mkv',
      ]),
    ).toEqual(['Season 1', 'Season 1', 'Season 2/Extras']);
  });

  it('gives no folders to files from one folder', () => {
    expect(collectionFolders(['/home/me/Music/a.flac', '/home/me/Music/b.flac'])).toEqual(['', '']);
    expect(collectionFolders(['/home/me/Music/a.flac'])).toEqual(['']);
  });

  it('keeps a file at the top level beside files in folders below it', () => {
    expect(collectionFolders(['/s/Show/readme.txt', '/s/Show/S1/e1.mkv'])).toEqual(['', 'S1']);
  });

  it('compares folder names without case, as Windows does', () => {
    expect(collectionFolders(['C:\\Shows\\A\\x.mkv', 'c:\\shows\\B\\y.mkv'])).toEqual(['A', 'B']);
  });

  it('has nothing to say about nothing', () => {
    expect(collectionFolders([])).toEqual([]);
  });
});
