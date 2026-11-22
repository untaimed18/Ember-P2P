import { describe, expect, it } from 'vitest';
import { browseFolderOptions, inBrowseFolder } from './browseFolders';

describe('browseFolderOptions', () => {
  it('lists every folder and the ones above them as a tree, with counts', () => {
    const files = [
      { folder: 'Music/Rock/Album' },
      { folder: 'Music/Rock/Album' },
      { folder: 'Music Live' },
      { folder: 'Music/Jazz' },
      { folder: 'Films' },
      {},
    ];
    expect(browseFolderOptions(files).map((o) => [o.path, o.depth, o.count])).toEqual([
      ['Films', 0, 1],
      ['Music', 0, 3],
      ['Music/Jazz', 1, 1],
      ['Music/Rock', 1, 2],
      ['Music/Rock/Album', 2, 2],
      ['Music Live', 0, 1],
    ]);
  });

  it('is empty when the friend shows no folders', () => {
    expect(browseFolderOptions([{}, { folder: '' }])).toEqual([]);
  });
});

describe('inBrowseFolder', () => {
  it('takes the folder and those below it, not a sibling that shares its start', () => {
    expect(inBrowseFolder({ folder: 'Music' }, 'Music')).toBe(true);
    expect(inBrowseFolder({ folder: 'Music/Rock' }, 'Music')).toBe(true);
    expect(inBrowseFolder({ folder: 'Music Live' }, 'Music')).toBe(false);
    expect(inBrowseFolder({}, 'Music')).toBe(false);
  });
});
