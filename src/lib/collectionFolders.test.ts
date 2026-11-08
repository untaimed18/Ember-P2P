import { describe, expect, it } from 'vitest';
import { collectionFolders } from './collectionFolders';

describe('collectionFolders', () => {
  it('places files relative to the deepest folder they share', () => {
    expect(
      collectionFolders(
        [
          'D:\\Anime\\Show\\Season 1\\e1.mkv',
          'D:\\Anime\\Show\\Season 1\\e2.mkv',
          'D:\\Anime\\Show\\Season 2\\Extras\\op.mkv',
        ],
        ['D:\\Anime'],
        true,
      ),
    ).toEqual(['Season 1', 'Season 1', 'Season 2/Extras']);
  });

  it('gives no folders to files from one folder', () => {
    expect(collectionFolders(['/home/me/Music/a.flac', '/home/me/Music/b.flac'], ['/home/me/Music'], false)).toEqual(['', '']);
    expect(collectionFolders(['/home/me/Music/a.flac'], ['/home/me/Music'], false)).toEqual(['']);
  });

  it('keeps a file at the top level beside files in folders below it', () => {
    expect(collectionFolders(['/s/Show/readme.txt', '/s/Show/S1/e1.mkv'], ['/s'], false)).toEqual(['', 'S1']);
  });

  it('never records the path above the shared folder, which names the account', () => {
    const shared = ['C:\\Users\\brady\\Videos', 'D:\\Media'];
    expect(collectionFolders(['C:\\Users\\brady\\Videos\\Show\\S1\\e1.mkv', 'D:\\Media\\x.mkv'], shared, true)).toEqual(['', '']);
    expect(collectionFolders(['/home/brady/Videos/Show/S1/a.mkv', '/mnt/usb/b.mkv'], ['/home/brady/Videos', '/mnt/usb'], false)).toEqual(['', '']);
    // A file in no shared folder.
    expect(collectionFolders(['/home/brady/Videos/a.mkv'], [], false)).toEqual(['']);
    // Two shows in one shared folder share it, and only it.
    expect(collectionFolders(['C:\\Users\\brady\\Videos\\A\\x.mkv', 'C:\\Users\\brady\\Videos\\B\\y.mkv'], shared, true)).toEqual(['A', 'B']);
  });

  it('reads a file recorded in the extended form under its plain shared folder', () => {
    expect(collectionFolders(['\\\\?\\D:\\Anime\\Show\\S1\\e1.mkv', 'D:\\Anime\\Show\\S2\\e1.mkv'], ['D:\\Anime'], true)).toEqual(['S1', 'S2']);
    expect(collectionFolders(['\\\\?\\UNC\\nas\\tv\\A\\x.mkv', '\\\\nas\\tv\\B\\y.mkv'], ['\\\\nas\\tv'], true)).toEqual(['A', 'B']);
  });

  it('compares folder names without case only where the file system does', () => {
    expect(collectionFolders(['C:\\Shows\\A\\x.mkv', 'c:\\shows\\B\\y.mkv'], ['C:\\Shows'], true)).toEqual(['A', 'B']);
    expect(collectionFolders(['/d/Show/a.mkv', '/d/show/b.mkv'], ['/d'], false)).toEqual(['Show', 'show']);
  });

  it('has nothing to say about nothing', () => {
    expect(collectionFolders([], ['/s'], false)).toEqual([]);
  });
});
