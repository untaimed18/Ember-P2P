import { describe, expect, it } from 'vitest';
import {
  disambiguatedMemberName,
  formatBytes,
  linkifyMessage,
  shortPubkey,
  type MessageSegment,
} from './utils';

/** The rendered text, which must always reconstruct the original message. */
function plain(segments: MessageSegment[]): string {
  return segments.map((s) => s.text).join('');
}

function links(segments: MessageSegment[]): string[] {
  return segments.filter((s) => s.href).map((s) => s.href!);
}

describe('linkifyMessage', () => {
  it('leaves a message with no link as a single run', () => {
    expect(linkifyMessage('just talking')).toEqual([{ text: 'just talking' }]);
    expect(linkifyMessage('')).toEqual([]);
  });

  it('never drops or reorders a character of what was typed', () => {
    const samples = [
      'see https://example.com/a?b=c#d for details',
      'https://one.test and https://two.test',
      'trailing https://example.com.',
      'no links at all',
      '(https://example.com)',
      'https://example.com',
      'ftp://example.com is not matched',
    ];
    for (const sample of samples) {
      expect(plain(linkifyMessage(sample))).toBe(sample);
    }
  });

  it('finds several links in one message', () => {
    expect(links(linkifyMessage('a https://one.test b https://two.test c'))).toEqual([
      'https://one.test',
      'https://two.test',
    ]);
  });

  it('leaves sentence punctuation out of the link', () => {
    // The full stop belongs to the sentence, not the URL.
    expect(links(linkifyMessage('see https://example.com.'))).toEqual(['https://example.com']);
    expect(links(linkifyMessage('here: https://example.com, and more'))).toEqual([
      'https://example.com',
    ]);
    expect(links(linkifyMessage('really? https://example.com?'))).toEqual([
      'https://example.com',
    ]);
    // …but a query string ending in a real character keeps it.
    expect(links(linkifyMessage('https://example.com/?q=1'))).toEqual([
      'https://example.com/?q=1',
    ]);
  });

  it('gives back a closing bracket only when it is unbalanced', () => {
    expect(links(linkifyMessage('(see https://example.com)'))).toEqual(['https://example.com']);
    expect(links(linkifyMessage('https://en.example.org/wiki/Ember_(disambiguation)'))).toEqual([
      'https://en.example.org/wiki/Ember_(disambiguation)',
    ]);
    expect(links(linkifyMessage('[https://example.com/a[b]]'))).toEqual([
      'https://example.com/a[b]',
    ]);
  });

  it('matches only an explicit http or https scheme', () => {
    // Guessing a scheme for a bare host means guessing where the sender meant
    // to send you, so these stay plain text.
    for (const text of [
      'www.example.com',
      'example.com',
      'ftp://example.com',
      'file:///C:/Windows/System32/calc.exe',
      'javascript:alert(1)',
      'ms-msdt:/id PCWDiagnostic',
    ]) {
      expect(links(linkifyMessage(text))).toEqual([]);
      expect(plain(linkifyMessage(text))).toBe(text);
    }
    expect(links(linkifyMessage('HTTPS://Example.COM/x'))).toEqual(['HTTPS://Example.COM/x']);
  });

  it('refuses to make a link clickable when it carries a bidi override', () => {
    // The override reorders how the host reads without changing where it
    // points, so the text stays but the affordance does not.
    const spoofed = 'https://\u202Egnp.elpmaxe.moc\u202C/x';
    const segments = linkifyMessage(`look ${spoofed}`);
    expect(links(segments)).toEqual([]);
    expect(plain(segments)).toBe(`look ${spoofed}`);
  });

  it('refuses a link past the length the backend would accept', () => {
    const long = `https://example.com/${'a'.repeat(2100)}`;
    expect(links(linkifyMessage(long))).toEqual([]);
    expect(plain(linkifyMessage(long))).toBe(long);
  });

  it('sets href to exactly the text it renders', () => {
    // The two must never disagree: the confirmation dialog shows one of them.
    for (const seg of linkifyMessage('a https://example.com/x b https://other.test')) {
      if (seg.href) expect(seg.href).toBe(seg.text);
    }
  });
});

describe('formatBytes', () => {
  it('carries into the next unit rather than printing 1024 of the last', () => {
    // toFixed(1) rounds anything at or above 1023.95 up to "1024.0".
    expect(formatBytes(1024 * 1024 - 1)).toBe('1 MB');
    expect(formatBytes(1023)).toBe('1023 B');
    expect(formatBytes(1024)).toBe('1 KB');
  });

  it('reports nothing for a missing or nonsensical size', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(-1)).toBe('0 B');
    expect(formatBytes(Number.NaN)).toBe('0 B');
  });
});

describe('disambiguatedMemberName', () => {
  const key = 'ab'.repeat(32);

  it('leaves a unique nickname alone', () => {
    expect(disambiguatedMemberName('Ada', key, ['Ada', 'Grace'])).toBe('Ada');
  });

  it('appends a key fragment when two members share a nickname', () => {
    const shown = disambiguatedMemberName('Ada', key, ['Ada', 'ada', 'Grace']);
    expect(shown).not.toBe('Ada');
    expect(shown).toContain(shortPubkey(key));
  });
});
