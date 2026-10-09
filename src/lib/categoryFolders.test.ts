import { describe, expect, it } from 'vitest';
import {
  CATEGORY_FOLDER_MAX_CHARS,
  categoriesWithFolder,
  categoryDestinationLabel,
  categoryFolderSegments,
  categorySubdir,
  downloadsSubdirOf,
  normalizeCategoryFolder,
} from './categoryFolders';

describe('downloadsSubdirOf', () => {
  const root = 'C:\\Users\\me\\Ember';

  it('names the folders below Downloads, extended form or not', () => {
    expect(downloadsSubdirOf('C:\\Users\\me\\Ember\\Downloads\\a.mkv', root, true)).toEqual([]);
    expect(downloadsSubdirOf('\\\\?\\C:\\Users\\me\\Ember\\Downloads\\TV Series\\Drama\\e.mkv', root, true))
      .toEqual(['TV Series', 'Drama']);
    expect(downloadsSubdirOf('c:/users/ME/ember/downloads/Video/v.mp4', root, true)).toEqual(['Video']);
  });

  it('is null outside Downloads, deeper than a category folder, or case-different on Linux', () => {
    expect(downloadsSubdirOf('C:\\Users\\me\\Ember\\Temp\\a.part', root, true)).toBeNull();
    expect(downloadsSubdirOf('D:\\Music\\a.mp3', root, true)).toBeNull();
    expect(downloadsSubdirOf('C:\\Users\\me\\Ember\\Downloads\\a\\b\\c\\d\\x.bin', root, true)).toBeNull();
    expect(downloadsSubdirOf('/home/me/Ember/Downloads/Video/v.mp4', '/home/me/Ember', false)).toEqual(['Video']);
    expect(downloadsSubdirOf('/home/me/ember/Downloads/v.mp4', '/home/me/Ember', false)).toBeNull();
    expect(downloadsSubdirOf('/x/Downloads/v.mp4', '', false)).toBeNull();
  });
});

describe('category folders', () => {
  const folders = { Video: 'Video', 'TV Series': 'Video/TV', Movies: 'video' };

  it('finds the categories that own a folder, and none for Downloads itself', () => {
    expect(categoriesWithFolder(['Video'], folders, true).sort()).toEqual(['Movies', 'Video']);
    expect(categoriesWithFolder(['Video'], folders, false)).toEqual(['Video']);
    expect(categoriesWithFolder(['Video', 'TV'], folders, true)).toEqual(['TV Series']);
    expect(categoriesWithFolder([], folders, true)).toEqual([]);
  });

  it('labels where a category files its downloads', () => {
    expect(categoryDestinationLabel(categorySubdir('TV Series', folders))).toBe('Downloads/Video/TV');
    expect(categoryDestinationLabel(categorySubdir('Audio', folders))).toBe('Downloads');
  });
});

// The same cases `storage::category_folders` pins on the backend, so the
// preview the dialog shows is the folder the download lands in.
describe('normalizeCategoryFolder', () => {
  it('cleans a folder the way finished file names are cleaned', () => {
    expect(normalizeCategoryFolder('TV Series')).toBe('TV Series');
    expect(normalizeCategoryFolder('  Video / TV Series ')).toBe('Video/TV Series');
    expect(normalizeCategoryFolder('Video\\Films')).toBe('Video/Films');
    expect(normalizeCategoryFolder('TV: Series?')).toBe('TV_ Series_');
    expect(normalizeCategoryFolder('Series.. ')).toBe('Series');
    expect(normalizeCategoryFolder('CON')).toBe('_CON');
    expect(normalizeCategoryFolder('com\u00B9.txt')).toBe('_com\u00B9.txt');
    expect(normalizeCategoryFolder('a//b')).toBe('a/b');
    expect(normalizeCategoryFolder('a/b/c/d')).toBe('a/b/c');
    expect(normalizeCategoryFolder('x'.repeat(CATEGORY_FOLDER_MAX_CHARS + 10))?.length).toBe(
      CATEGORY_FOLDER_MAX_CHARS,
    );
    expect(normalizeCategoryFolder('Films\u202E')).toBe('Films_');
  });

  it('reads nothing usable as Downloads itself', () => {
    for (const value of ['', '   ', '/', '.', '..', '../..', ' . / .. ', '...']) {
      expect(normalizeCategoryFolder(value)).toBeNull();
    }
    expect(normalizeCategoryFolder('../Films')).toBe('Films');
    expect(normalizeCategoryFolder('/abs/path')).toBe('abs/path');
    expect(normalizeCategoryFolder('C:/Films')).toBe('C_/Films');
  });

  it('counts characters, not UTF-16 units', () => {
    const clapper = '\u00E9'.repeat(CATEGORY_FOLDER_MAX_CHARS + 2);
    expect(Array.from(categoryFolderSegments(clapper)[0])).toHaveLength(CATEGORY_FOLDER_MAX_CHARS);
  });

  it('keeps a name within the 255 bytes Linux allows, as the backend does', () => {
    // 64 four-byte characters are 256 bytes; the backend keeps 63.
    const emoji = '\u{1F3AC}'.repeat(CATEGORY_FOLDER_MAX_CHARS + 2);
    const [segment] = categoryFolderSegments(emoji);
    expect(Array.from(segment)).toHaveLength(63);
    expect(new TextEncoder().encode(segment).length).toBeLessThanOrEqual(255);
  });
});
