import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parseNotesInline, parseReleaseNotes, type NotesInline } from './releaseNotes';

const plain = (nodes: NotesInline[]): string =>
  nodes.map((node) => ('text' in node ? node.text : plain(node.children))).join('');

describe('release notes', () => {
  it('reads the headings, lists and paragraphs the release script writes', () => {
    const notes = [
      '## Highlights',
      '',
      '### Linux',
      '',
      '- **The AppImage** no longer stops at the first emoji',
      '- A second item',
      '',
      '**Full Changelog**: [https://github.com/x/compare/a...b](https://github.com/x/compare/a...b)',
    ].join('\n');
    expect(parseReleaseNotes(notes)).toEqual([
      { kind: 'heading', level: 2, inline: [{ kind: 'text', text: 'Highlights' }] },
      { kind: 'heading', level: 3, inline: [{ kind: 'text', text: 'Linux' }] },
      {
        kind: 'list',
        items: [
          [
            { kind: 'strong', children: [{ kind: 'text', text: 'The AppImage' }] },
            { kind: 'text', text: ' no longer stops at the first emoji' },
          ],
          [{ kind: 'text', text: 'A second item' }],
        ],
      },
      {
        kind: 'paragraph',
        inline: [
          { kind: 'strong', children: [{ kind: 'text', text: 'Full Changelog' }] },
          { kind: 'text', text: ': https://github.com/x/compare/a...b' },
        ],
      },
    ]);
  });

  it('reads code and emphasis, also inside strong text', () => {
    expect(parseNotesInline('**The `.deb` is *signed* now**')).toEqual([
      {
        kind: 'strong',
        children: [
          { kind: 'text', text: 'The ' },
          { kind: 'code', text: '.deb' },
          { kind: 'text', text: ' is ' },
          { kind: 'em', children: [{ kind: 'text', text: 'signed' }] },
          { kind: 'text', text: ' now' },
        ],
      },
    ]);
  });

  it('reads a real release’s notes with no Markdown left showing', () => {
    // The very notes the release workflow would sign into latest.json.
    const script = fileURLToPath(new URL('../../scripts/release-notes.mjs', import.meta.url));
    const notes = execFileSync(process.execPath, [script, '--version', '1.7.6'], { encoding: 'utf8' });
    const blocks = parseReleaseNotes(notes);
    expect(blocks.filter((block) => block.kind === 'heading').length).toBeGreaterThan(2);
    expect(blocks.filter((block) => block.kind === 'list').length).toBeGreaterThan(2);
    const text = blocks
      .flatMap((block) => (block.kind === 'list' ? block.items : [block.inline]))
      .map(plain)
      .join('\n');
    expect(text).not.toMatch(/\*\*|`|\]\(/);
  });

  it('leaves markers it cannot pair as the text they are', () => {
    expect(parseNotesInline('5 * 3 and a ` tick and **open')).toEqual([
      { kind: 'text', text: '5 * 3 and a ` tick and **open' },
    ]);
  });

  it('keeps only a link’s text, so nothing in the notes becomes a link or markup', () => {
    expect(parseNotesInline('see [<b>the notes</b>](javascript:alert(1))')).toEqual([
      { kind: 'text', text: 'see <b>the notes</b>)' },
    ]);
    expect(parseReleaseNotes('<script>alert(1)</script>')).toEqual([
      { kind: 'paragraph', inline: [{ kind: 'text', text: '<script>alert(1)</script>' }] },
    ]);
  });
});
