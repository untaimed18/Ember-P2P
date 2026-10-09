import { describe, expect, it } from 'vitest';
import {
  CATEGORY_FOLDER_MAX_CHARS,
  categoryFolderSegments,
  normalizeCategoryFolder,
} from './categoryFolders';

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
    const emoji = '\u{1F3AC}'.repeat(CATEGORY_FOLDER_MAX_CHARS + 2);
    expect(Array.from(categoryFolderSegments(emoji)[0])).toHaveLength(CATEGORY_FOLDER_MAX_CHARS);
  });
});
