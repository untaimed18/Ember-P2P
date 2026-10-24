import { describe, expect, it } from 'vitest';
import { menuKeyDownloadId } from './transfersMenuKey';

const nowhere = { focusRowId: null, inDownloadsTable: false, onPage: false, currentId: null };

describe('menuKeyDownloadId', () => {
  it('opens the menu of the row focus is in', () => {
    expect(menuKeyDownloadId({ ...nowhere, focusRowId: 'b', inDownloadsTable: true, currentId: 'a' })).toBe('b');
  });

  it('uses the highlighted row from the table or the page body', () => {
    expect(menuKeyDownloadId({ ...nowhere, inDownloadsTable: true, currentId: 'a' })).toBe('a');
    expect(menuKeyDownloadId({ ...nowhere, onPage: true, currentId: 'a' })).toBe('a');
  });

  it('leaves the key alone when focus is on another control', () => {
    expect(menuKeyDownloadId({ ...nowhere, currentId: 'a' })).toBeNull();
  });

  it('never falls back to the first row', () => {
    expect(menuKeyDownloadId({ ...nowhere, inDownloadsTable: true })).toBeNull();
    expect(menuKeyDownloadId({ ...nowhere, onPage: true })).toBeNull();
  });
});
