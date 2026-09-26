/**
 * Lightweight, display-only formatting for chat messages.
 *
 * `**bold**`, `*italic*` / `_italic_`, `~~strike~~`, `` `code` `` and fenced
 * code blocks. Nothing here changes what is sent: the wire carries the raw
 * text, so an older Ember shows the asterisks, and "Copy text" copies them.
 *
 * The output is a tree of plain objects the conversation renders with Svelte
 * elements — never markup. Messages come from untrusted peers, so no string
 * a peer typed is ever interpreted as HTML; the worst a crafted message can
 * do is choose which of five harmless elements its text sits in.
 *
 * The rules are deliberately stricter than CommonMark, because a chat line is
 * mostly prose that happens to contain asterisks and underscores, and mangling
 * `2*3*4`, `snake_case_name` or a shrug is worse than missing an intended
 * emphasis:
 *
 * - A marker opens only with non-space text after it and no letter or digit
 *   before it, and closes only with non-space text before it and no letter or
 *   digit after it. So `* not italic *`, `2*3*4` and `snake_case` stay as
 *   typed, and emphasis never starts or ends mid-word.
 * - `_` is a single-character marker only; `__init__` is literal. `~~` is the
 *   only strike marker; a lone `~` ("~5 min") is literal.
 * - An opener pairs only with a closer of the same character and run length,
 *   within one line. Anything left unmatched renders exactly as written.
 * - Code (spans and blocks) is opaque: nothing inside it is formatted,
 *   linkified or mention-matched.
 * - Links are found first (by `linkifyMessage`), so `*` and `_` inside a URL
 *   are never markers.
 */
import { linkifyMessage, type MessageSegment } from '$lib/utils';

export type InlineNode =
  | { type: 'text'; text: string }
  | LinkNode
  | { type: 'code'; text: string }
  | { type: 'bold' | 'italic' | 'strike'; children: InlineNode[] };

/** `href` is always equal to `text`, as with `linkifyMessage`. */
export type LinkNode = { type: 'link'; text: string; href: string };

export type FormatBlock =
  | { type: 'text'; children: InlineNode[] }
  | { type: 'code'; text: string };

/**
 * Past this the message is rendered with links only. The backend caps a
 * message at 4096 bytes, so this is never reached by a well-behaved peer; it
 * is what keeps a malformed row from a future protocol, or a local bug, from
 * costing more than linkification already does.
 */
export const FORMAT_MAX_CHARS = 8192;

/**
 * Open spans at once. Three covers bold + italic + strike; deeper nesting
 * has no visual meaning and each level multiplies what a closer has to
 * search, so further openers are left literal.
 */
export const FORMAT_MAX_DEPTH = 3;

const MARKER_RE = /[*_~`]/;
/** Up to three spaces of indent, an optional language tag (ignored), and
 *  nothing else on the line. */
const FENCE_OPEN_RE = /^ {0,3}```[A-Za-z0-9_+#.-]{0,32}[ \t]*\r?$/;
const FENCE_CLOSE_RE = /^ {0,3}```[ \t]*\r?$/;
const WORD_RE = /[\p{L}\p{N}]/u;
const SPACE_RE = /\s/;
/** A trailing run of one marker character that a URL match swallowed —
 *  `**https://example.com**` matches the link with the closing `**` on it. */
const TRAILING_MARKER_RE = /(?:\*+|_+|~+)$/;

/**
 * Stand-in for the character next to an opaque neighbour (a link or code
 * span): not a space, so a marker touching one can open or close, and not a
 * letter, so it does not count as mid-word.
 */
const OPAQUE = '\u0000';
/** The line edge reads as whitespace: a marker there can open (at the start)
 *  or close (at the end), never the other way round. */
const EDGE = ' ';

/** Split message text into blocks, and each text block into inline nodes. */
export function formatMessage(text: string): FormatBlock[] {
  if (!text) return [];
  // The common case — no marker character at all — costs one regex test on
  // top of the link scan the transcript already did.
  if (text.length > FORMAT_MAX_CHARS || !MARKER_RE.test(text)) {
    return [{ type: 'text', children: linkNodes(linkifyMessage(text)) }];
  }
  const lines = text.split('\n');
  // Index of the first closing-fence line after each line, or -1. Computed
  // once from the end so pairing fences stays linear however many there are.
  const nextClose = new Array<number>(lines.length);
  let upcoming = -1;
  for (let i = lines.length - 1; i >= 0; i--) {
    nextClose[i] = upcoming;
    if (FENCE_CLOSE_RE.test(lines[i])) upcoming = i;
  }
  const blocks: FormatBlock[] = [];
  let textStart = 0;
  let i = 0;
  while (i < lines.length) {
    const close = nextClose[i];
    // `close > i + 1`: an empty fence pair is two literal lines, not an empty
    // box. An opener with no closer below it is literal too.
    if (close > i + 1 && FENCE_OPEN_RE.test(lines[i])) {
      pushTextBlock(blocks, lines, textStart, i);
      blocks.push({ type: 'code', text: lines.slice(i + 1, close).map(stripCr).join('\n') });
      i = close + 1;
      textStart = i;
    } else {
      i++;
    }
  }
  pushTextBlock(blocks, lines, textStart, lines.length);
  return blocks;
}

function stripCr(line: string): string {
  return line.endsWith('\r') ? line.slice(0, -1) : line;
}

function linkNodes(segments: MessageSegment[]): InlineNode[] {
  return segments.map((seg) =>
    seg.href ? { type: 'link', text: seg.text, href: seg.href } : { type: 'text', text: seg.text },
  );
}

function pushTextBlock(blocks: FormatBlock[], lines: string[], from: number, to: number) {
  if (from >= to) return;
  const children: InlineNode[] = [];
  for (let i = from; i < to; i++) {
    if (i > from) pushText(children, '\n');
    for (const node of formatLine(lines[i])) pushNode(children, node);
  }
  if (children.length > 0) blocks.push({ type: 'text', children });
}

/** Append, merging into a preceding text node so runs stay one node. */
function pushText(list: InlineNode[], text: string) {
  if (!text) return;
  const last = list[list.length - 1];
  if (last && last.type === 'text') last.text += text;
  else list.push({ type: 'text', text });
}

function pushNode(list: InlineNode[], node: InlineNode) {
  if (node.type === 'text') pushText(list, node.text);
  else list.push(node);
}

// ---------------------------------------------------------------------------
// One line: code spans, then links, then emphasis.

type Atom =
  | { kind: 'text'; text: string }
  | { kind: 'opaque'; node: InlineNode }
  /** Marker characters peeled off the end of `link`. */
  | { kind: 'peel'; text: string; link: LinkNode };

type Delim = {
  kind: 'delim';
  ch: string;
  len: number;
  canOpen: boolean;
  canClose: boolean;
  /** Set for a run peeled off a link: if it closes nothing it goes back onto
   *  the link, so a URL that really ends in `_` still points where it did. */
  glue: LinkNode | null;
};

type Token = { kind: 'text'; text: string } | { kind: 'opaque'; node: InlineNode } | Delim;

function formatLine(line: string): InlineNode[] {
  if (!line) return [];
  if (!MARKER_RE.test(line)) return linkNodes(linkifyMessage(line));
  return matchDelimiters(tokenize(lineAtoms(line)));
}

function lineAtoms(line: string): Atom[] {
  const atoms: Atom[] = [];
  for (const piece of splitCodeSpans(line)) {
    if (piece.code) {
      atoms.push({ kind: 'opaque', node: { type: 'code', text: piece.text } });
      continue;
    }
    for (const seg of linkifyMessage(piece.text)) {
      if (!seg.href) {
        atoms.push({ kind: 'text', text: seg.text });
        continue;
      }
      const tail = TRAILING_MARKER_RE.exec(seg.text)?.[0] ?? '';
      const kept = seg.text.slice(0, seg.text.length - tail.length);
      // Only when something URL-shaped is left; otherwise leave the match be.
      if (tail && /^https?:\/\/./i.test(kept)) {
        const link: LinkNode = { type: 'link', text: kept, href: kept };
        atoms.push({ kind: 'opaque', node: link });
        atoms.push({ kind: 'peel', text: tail, link });
      } else {
        atoms.push({ kind: 'opaque', node: { type: 'link', text: seg.text, href: seg.href } });
      }
    }
  }
  return atoms;
}

/**
 * Backtick code spans: a run of N backticks up to the next run of exactly N.
 * An opener with no partner is literal. Once a run length has failed to find
 * a partner, no later run of that length can either, so each length is
 * scanned to the end at most once and the whole pass stays near-linear.
 */
function splitCodeSpans(line: string): Array<{ code: boolean; text: string }> {
  const runs: Array<{ start: number; len: number }> = [];
  for (let p = line.indexOf('`'); p !== -1; ) {
    let q = p;
    while (q < line.length && line[q] === '`') q++;
    runs.push({ start: p, len: q - p });
    p = line.indexOf('`', q);
  }
  if (runs.length < 2) return [{ code: false, text: line }];
  const pieces: Array<{ code: boolean; text: string }> = [];
  const exhausted = new Set<number>();
  let cursor = 0;
  for (let r = 0; r < runs.length; r++) {
    const open = runs[r];
    if (exhausted.has(open.len)) continue;
    let match = -1;
    for (let s = r + 1; s < runs.length; s++) {
      if (runs[s].len === open.len) {
        match = s;
        break;
      }
    }
    if (match === -1) {
      exhausted.add(open.len);
      continue;
    }
    const close = runs[match];
    if (open.start > cursor) pieces.push({ code: false, text: line.slice(cursor, open.start) });
    pieces.push({ code: true, text: trimCodePadding(line.slice(open.start + open.len, close.start)) });
    cursor = close.start + close.len;
    // Runs between the pair are content, not candidates.
    r = match;
  }
  if (cursor < line.length) pieces.push({ code: false, text: line.slice(cursor) });
  return pieces;
}

/** One space either side is padding (so `` ` `x` ` `` can show a backtick);
 *  a span that is only spaces keeps them. */
function trimCodePadding(inner: string): string {
  if (inner.length >= 2 && inner.startsWith(' ') && inner.endsWith(' ') && inner.trim()) {
    return inner.slice(1, -1);
  }
  return inner;
}

function isMarkerRun(ch: string, len: number): boolean {
  if (ch === '*') return len <= 3;
  if (ch === '_') return len === 1;
  return len === 2; // '~'
}

/** The character before `p`, whole code point, so an astral letter reads as
 *  a letter rather than as a lone surrogate. */
function charBefore(s: string, p: number): string {
  const code = s.charCodeAt(p - 1);
  if (p >= 2 && code >= 0xdc00 && code <= 0xdfff) return s.slice(p - 2, p);
  return s[p - 1];
}

function charAt(s: string, p: number): string {
  const cp = s.codePointAt(p);
  return cp === undefined ? '' : String.fromCodePoint(cp);
}

function tokenize(atoms: Atom[]): Token[] {
  const tokens: Token[] = [];
  const edgeBefore = (i: number): string => {
    if (i === 0) return EDGE;
    const prev = atoms[i - 1];
    return prev.kind === 'opaque' ? OPAQUE : charBefore(prev.text, prev.text.length);
  };
  const edgeAfter = (i: number): string => {
    if (i === atoms.length - 1) return EDGE;
    const next = atoms[i + 1];
    return next.kind === 'opaque' ? OPAQUE : charAt(next.text, 0);
  };
  atoms.forEach((atom, i) => {
    if (atom.kind === 'opaque') {
      tokens.push(atom);
      return;
    }
    const s = atom.text;
    const glue = atom.kind === 'peel' ? atom.link : null;
    let plainStart = 0;
    let p = 0;
    while (p < s.length) {
      const ch = s[p];
      if (ch !== '*' && ch !== '_' && ch !== '~') {
        p++;
        continue;
      }
      let q = p;
      while (q < s.length && s[q] === ch) q++;
      const len = q - p;
      if (isMarkerRun(ch, len)) {
        const before = p > 0 ? charBefore(s, p) : edgeBefore(i);
        const after = q < s.length ? charAt(s, q) : edgeAfter(i);
        // A peeled run sits hard against its link, so it may only close:
        // letting it open would steal a URL's trailing characters for
        // emphasis that starts after the link.
        const canOpen = !glue && !SPACE_RE.test(after) && !WORD_RE.test(before);
        const canClose = !SPACE_RE.test(before) && !WORD_RE.test(after);
        if (canOpen || canClose) {
          if (p > plainStart) tokens.push({ kind: 'text', text: s.slice(plainStart, p) });
          tokens.push({ kind: 'delim', ch, len, canOpen, canClose, glue });
          plainStart = q;
        }
      }
      p = q;
    }
    if (plainStart < s.length) {
      const rest = s.slice(plainStart);
      // A peeled run that could not even be a marker goes straight back.
      if (glue) appendToLink(glue, rest);
      else tokens.push({ kind: 'text', text: rest });
    }
  });
  return tokens;
}

function appendToLink(link: LinkNode, text: string) {
  link.text += text;
  link.href = link.text;
}

type Frame = { open: Delim | null; children: InlineNode[] };

function wrap(open: Delim, children: InlineNode[]): InlineNode {
  if (open.ch === '~') return { type: 'strike', children };
  if (open.ch === '_' || open.len === 1) return { type: 'italic', children };
  if (open.len === 2) return { type: 'bold', children };
  return { type: 'bold', children: [{ type: 'italic', children }] };
}

function literal(list: InlineNode[], delim: Delim) {
  const text = delim.ch.repeat(delim.len);
  if (delim.glue) appendToLink(delim.glue, text);
  else pushText(list, text);
}

/**
 * Pair markers with a stack of open spans. A closer pairs with the nearest
 * open span of the same character and length; spans opened after that one
 * and still unclosed become literal text inside it. Each closer searches at
 * most `FORMAT_MAX_DEPTH` frames, so the pass is linear in the line.
 */
function matchDelimiters(tokens: Token[]): InlineNode[] {
  const stack: Frame[] = [{ open: null, children: [] }];
  const top = () => stack[stack.length - 1];
  const collapseTop = () => {
    const frame = stack.pop()!;
    literal(top().children, frame.open!);
    for (const child of frame.children) pushNode(top().children, child);
  };
  for (const tok of tokens) {
    if (tok.kind === 'text') {
      pushText(top().children, tok.text);
      continue;
    }
    if (tok.kind === 'opaque') {
      top().children.push(tok.node);
      continue;
    }
    if (tok.canClose) {
      let k = stack.length - 1;
      while (k > 0 && !(stack[k].open!.ch === tok.ch && stack[k].open!.len === tok.len)) k--;
      if (k > 0) {
        while (stack.length - 1 > k) collapseTop();
        const frame = stack.pop()!;
        if (frame.children.length > 0) {
          top().children.push(wrap(frame.open!, frame.children));
        } else {
          // Nothing between the pair: both markers stay as typed.
          literal(top().children, frame.open!);
          literal(top().children, tok);
        }
        continue;
      }
    }
    if (tok.canOpen && stack.length - 1 < FORMAT_MAX_DEPTH) {
      stack.push({ open: tok, children: [] });
      continue;
    }
    literal(top().children, tok);
  }
  while (stack.length > 1) collapseTop();
  return stack[0].children;
}
