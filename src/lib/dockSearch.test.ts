import { describe, expect, it } from 'vitest';
import {
  defaultSwitcherRow,
  filterSwitcherRows,
  foldForSearch,
  searchNeedle,
  switcherMatch,
} from './dockSearch';

const DEB = { name: 'Deb', hash: '0123456789abcdef0123456789abcdef' };
const JOSE = { name: 'José', hash: 'ffffffffffffffffffffffffffffffff' };
/** Every hex letter in the alphabet, which is what made "de" match everyone. */
const HEXY = { name: 'Mo', hash: 'deadbeefdeadbeefdeadbeefdeadbeef' };

describe('foldForSearch', () => {
  it('strips accents and case', () => {
    expect(foldForSearch('José')).toBe('jose');
    expect(foldForSearch('ÅNGSTRÖM')).toBe('angstrom');
  });
});

describe('switcherMatch', () => {
  it('matches every row on an empty query', () => {
    expect(switcherMatch(HEXY, '')).toBe('name');
  });

  it('finds a name without its accents', () => {
    expect(switcherMatch(JOSE, searchNeedle('jose'))).toBe('name');
    expect(switcherMatch(JOSE, searchNeedle('  JOSÉ '))).toBe('name');
  });

  it('does not match a short hex query against the ID', () => {
    expect(switcherMatch(HEXY, 'de')).toBeNull();
    expect(switcherMatch(HEXY, 'beef')).toBeNull();
  });

  it('matches an ID by prefix once the query could be one', () => {
    expect(switcherMatch(HEXY, 'deadbeef')).toBe('id');
    expect(switcherMatch(HEXY, searchNeedle('DEADBEEFDEAD'))).toBe('id');
  });

  it('never matches the middle of an ID', () => {
    expect(switcherMatch(HEXY, 'adbeefde')).toBeNull();
  });
});

describe('filterSwitcherRows', () => {
  it('puts name matches ahead of ID matches, keeping order within each', () => {
    const named = { name: 'deadbeef fan', hash: 'aa'.repeat(16) };
    const other = { name: 'Deadbeef club', hash: 'bb'.repeat(16) };
    expect(filterSwitcherRows([HEXY, named, other], 'deadbeef')).toEqual([named, other, HEXY]);
  });

  it('keeps every row for an empty query', () => {
    expect(filterSwitcherRows([DEB, JOSE, HEXY], '')).toEqual([DEB, JOSE, HEXY]);
  });
});

describe('defaultSwitcherRow', () => {
  it('prefers a later name match over an earlier ID match', () => {
    const friend = { name: 'deadbeef', hash: 'cc'.repeat(16) };
    // Open conversations are listed first, so an ID match can sit above the
    // friend whose name is exactly what was typed.
    expect(defaultSwitcherRow([HEXY, friend], 'deadbeef')).toBe(friend);
  });

  it('falls back to the first row when nothing matches by name', () => {
    expect(defaultSwitcherRow([HEXY, DEB], 'deadbeef')).toBe(HEXY);
    expect(defaultSwitcherRow([], 'x')).toBeUndefined();
  });
});
