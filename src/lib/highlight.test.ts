import { describe, expect, it } from 'vitest';
import { highlightTerms, splitHighlights } from './highlight';

describe('highlightTerms', () => {
  it('keeps the words asked for and drops operators and exclusions', () => {
    expect(highlightTerms('linux iso -beta NOT torrent AND "live cd" -"old build" OR x')).toEqual([
      'linux',
      'iso',
      'live cd',
    ]);
  });

  it('strips grouping and merges the query with the result filter', () => {
    expect(highlightTerms('(ubuntu OR debian)', 'amd64 -i386')).toEqual(['ubuntu', 'debian', 'amd64']);
  });
});

describe('splitHighlights', () => {
  it('marks every case-insensitive occurrence and merges overlaps', () => {
    expect(splitHighlights('Linux Mint linux.iso', ['linux', 'nux.i'])).toEqual([
      { text: 'Linux', mark: true },
      { text: ' Mint ', mark: false },
      { text: 'linux.i', mark: true },
      { text: 'so', mark: false },
    ]);
  });

  it('leaves the text whole when nothing matches', () => {
    expect(splitHighlights('readme.txt', ['iso'])).toEqual([{ text: 'readme.txt', mark: false }]);
    expect(splitHighlights('readme.txt', [])).toEqual([{ text: 'readme.txt', mark: false }]);
  });
});
