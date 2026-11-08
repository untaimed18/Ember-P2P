/**
 * The release notes an update carries, read for display.
 *
 * `scripts/release-notes.mjs` writes them as Markdown from the website's
 * release history: `##` and `###` headings, `- ` list items, paragraphs, and
 * inline `**strong**`, `*emphasis*`, `` `code` `` and `[text](url)`. That is
 * all this reads. The result is plain data the component renders as text, so
 * nothing in the notes can become markup, and a link keeps only its text: the
 * full notes are one button away on the website.
 */

export type NotesInline =
  | { kind: 'text'; text: string }
  | { kind: 'code'; text: string }
  | { kind: 'strong' | 'em'; children: NotesInline[] };

export type NotesBlock =
  | { kind: 'heading'; level: 2 | 3; inline: NotesInline[] }
  | { kind: 'list'; items: NotesInline[][] }
  | { kind: 'paragraph'; inline: NotesInline[] };

const LINK = /^\[([^\]]*)\]\(([^)\s]*)\)/;

export function parseNotesInline(source: string): NotesInline[] {
  const out: NotesInline[] = [];
  let text = '';
  const flush = () => {
    if (text) out.push({ kind: 'text', text });
    text = '';
  };
  let i = 0;
  while (i < source.length) {
    const rest = source.slice(i);
    if (rest.startsWith('`')) {
      const end = source.indexOf('`', i + 1);
      if (end > i + 1) {
        flush();
        out.push({ kind: 'code', text: source.slice(i + 1, end) });
        i = end + 1;
        continue;
      }
    } else if (rest.startsWith('**')) {
      const end = source.indexOf('**', i + 2);
      if (end > i + 2) {
        flush();
        out.push({ kind: 'strong', children: parseNotesInline(source.slice(i + 2, end)) });
        i = end + 2;
        continue;
      }
    } else if (rest.startsWith('*') && rest[1] !== ' ') {
      const end = source.indexOf('*', i + 1);
      if (end > i + 1 && source[end - 1] !== ' ') {
        flush();
        out.push({ kind: 'em', children: parseNotesInline(source.slice(i + 1, end)) });
        i = end + 1;
        continue;
      }
    } else if (rest.startsWith('[')) {
      const link = LINK.exec(rest);
      if (link) {
        flush();
        out.push(...parseNotesInline(link[1]));
        i += link[0].length;
        continue;
      }
    }
    text += source[i];
    i += 1;
  }
  flush();
  // A link's text arrives as its own run; one run of text reads as one.
  return out.reduce<NotesInline[]>((merged, node) => {
    const last = merged[merged.length - 1];
    if (node.kind === 'text' && last?.kind === 'text') {
      merged[merged.length - 1] = { kind: 'text', text: last.text + node.text };
    } else {
      merged.push(node);
    }
    return merged;
  }, []);
}

export function parseReleaseNotes(markdown: string): NotesBlock[] {
  const blocks: NotesBlock[] = [];
  let list: NotesInline[][] | null = null;
  let paragraph: string[] = [];
  const endParagraph = () => {
    if (paragraph.length) blocks.push({ kind: 'paragraph', inline: parseNotesInline(paragraph.join(' ')) });
    paragraph = [];
  };
  const endList = () => {
    if (list) blocks.push({ kind: 'list', items: list });
    list = null;
  };
  for (const raw of markdown.replace(/\r\n?/g, '\n').split('\n')) {
    const line = raw.trim();
    const heading = /^(#{2,3})\s+(.*)$/.exec(line);
    const item = /^[-*]\s+(.*)$/.exec(line);
    if (!line) {
      endParagraph();
      endList();
    } else if (heading) {
      endParagraph();
      endList();
      blocks.push({ kind: 'heading', level: heading[1].length === 2 ? 2 : 3, inline: parseNotesInline(heading[2]) });
    } else if (item) {
      endParagraph();
      (list ??= []).push(parseNotesInline(item[1]));
    } else if (list) {
      // A wrapped list item continues the one above it.
      const last = list[list.length - 1];
      last.push({ kind: 'text', text: ' ' }, ...parseNotesInline(line));
    } else {
      paragraph.push(line);
    }
  }
  endParagraph();
  endList();
  return blocks;
}
