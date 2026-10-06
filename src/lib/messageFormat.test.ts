import { describe, expect, it } from 'vitest';
import { formatMessage, FORMAT_MAX_CHARS, type FormatBlock, type InlineNode } from './messageFormat';

/** Compact, readable rendering of the tree: `**x**` → `<b>x</b>` etc. */
function show(nodes: InlineNode[]): string {
  return nodes
    .map((n) => {
      switch (n.type) {
        case 'text':
          return n.text;
        case 'link':
          return `<a ${n.href}>${n.text}</a>`;
        case 'code':
          return `<code>${n.text}</code>`;
        case 'bold':
          return `<b>${show(n.children)}</b>`;
        case 'italic':
          return `<i>${show(n.children)}</i>`;
        case 'strike':
          return `<s>${show(n.children)}</s>`;
      }
    })
    .join('');
}

function render(text: string): string {
  return formatMessage(text)
    .map((b) => {
      if (b.type === 'code') return `[pre:${b.text}]`;
      if (b.type === 'list') {
        const tag = b.ordered ? `ol${b.start === 1 ? '' : ` start=${b.start}`}` : 'ul';
        return `[${tag}:${b.items.map(show).join(';')}]`;
      }
      return show(b.children);
    })
    .join('|');
}

/** Every character of the source that is not a consumed marker, in order. */
function visibleText(blocks: FormatBlock[]): string {
  const walk = (nodes: InlineNode[]): string =>
    nodes
      .map((n) => ('children' in n ? walk(n.children) : n.text))
      .join('');
  return blocks
    .map((b) => {
      if (b.type === 'code') return b.text;
      if (b.type === 'list') return b.items.map(walk).join('\n');
      return walk(b.children);
    })
    .join('\n');
}

function depth(nodes: InlineNode[]): number {
  let max = 0;
  for (const n of nodes) if ('children' in n) max = Math.max(max, 1 + depth(n.children));
  return max;
}

describe('formatMessage: basics', () => {
  it('returns nothing for empty input', () => {
    expect(formatMessage('')).toEqual([]);
  });

  it('leaves plain text as one text node', () => {
    expect(formatMessage('just talking')).toEqual([
      { type: 'text', children: [{ type: 'text', text: 'just talking' }] },
    ]);
  });

  it('renders each marker', () => {
    expect(render('**bold**')).toBe('<b>bold</b>');
    expect(render('*italic*')).toBe('<i>italic</i>');
    expect(render('_italic_')).toBe('<i>italic</i>');
    expect(render('~~gone~~')).toBe('<s>gone</s>');
    expect(render('`code`')).toBe('<code>code</code>');
    expect(render('***both***')).toBe('<b><i>both</i></b>');
  });

  it('formats inside a sentence and next to punctuation', () => {
    expect(render('this is **very** important.')).toBe('this is <b>very</b> important.');
    expect(render('(*aside*)')).toBe('(<i>aside</i>)');
    expect(render('"_quoted_", then')).toBe('"<i>quoted</i>", then');
    expect(render('**multi word bold**!')).toBe('<b>multi word bold</b>!');
  });

  it('keeps newlines as text between lines', () => {
    expect(render('**a**\n*b*')).toBe('<b>a</b>\n<i>b</i>');
  });
});

describe('formatMessage: nesting', () => {
  it('nests different markers', () => {
    expect(render('**bold *and italic* here**')).toBe('<b>bold <i>and italic</i> here</b>');
    expect(render('~~struck **bold**~~')).toBe('<s>struck <b>bold</b></s>');
    expect(render('*_both_*')).toBe('<i><i>both</i></i>');
  });

  it('caps nesting depth, leaving deeper markers literal', () => {
    const text = '~~a **b *c _d_ c* b** a~~';
    const [block] = formatMessage(text);
    expect(block.type).toBe('text');
    if (block.type !== 'text') return;
    // Three open spans at most; the fourth marker pair stays as typed.
    expect(depth(block.children)).toBeLessThanOrEqual(3);
    expect(show(block.children)).toContain('_d_');
    expect(visibleText([block]).length).toBeGreaterThan(0);
  });

  it('does not let emphasis cross a line break', () => {
    expect(render('*one\ntwo*')).toBe('*one\ntwo*');
  });

  it('closes the nearest matching opener and drops crossed spans to text', () => {
    expect(render('*a **b* c**')).toBe('<i>a **b</i> c**');
  });
});

describe('formatMessage: unmatched and non-markers', () => {
  it('renders unmatched markers literally', () => {
    for (const text of ['**bold', 'bold**', '*a', '_x', '~~x', '`x', '**bold*', 'a ** b', '*', '**', '``']) {
      expect(render(text)).toBe(text);
    }
  });

  it('requires markers to hug text', () => {
    expect(render('* not italic *')).toBe('* not italic *');
    expect(render('** not bold **')).toBe('** not bold **');
    expect(render('a * b * c')).toBe('a * b * c');
  });

  it('leaves arithmetic alone', () => {
    expect(render('2*3*4')).toBe('2*3*4');
    expect(render('2**10 is 1024')).toBe('2**10 is 1024');
    expect(render('x*y + y*x')).toBe('x*y + y*x');
  });

  it('leaves snake_case and dunder names alone', () => {
    expect(render('snake_case_name')).toBe('snake_case_name');
    expect(render('call my_func_name() now')).toBe('call my_func_name() now');
    expect(render('__init__')).toBe('__init__');
    expect(render('_private_var_name')).toBe('_private_var_name');
  });

  it('does not treat emphasis mid-word as a marker', () => {
    expect(render('foo*bar*baz')).toBe('foo*bar*baz');
    expect(render('un_believ_able')).toBe('un_believ_able');
  });

  it('keeps a lone tilde and long runs literal', () => {
    expect(render('~5 minutes')).toBe('~5 minutes');
    expect(render('~~~x~~~')).toBe('~~~x~~~');
    expect(render('****x****')).toBe('****x****');
  });

  it('does not read a bullet as an italic marker', () => {
    expect(render('* one\n* two')).toBe('[ul:one;two]');
  });

  it('preserves every character when nothing matches', () => {
    const text = 'a*b _c d_e ~f ** g `h ~~ i';
    expect(visibleText(formatMessage(text))).toBe(text);
  });
});

describe('formatMessage: lists', () => {
  it('draws runs of bullet lines as a list, with formatting inside', () => {
    expect(render('- one\n- **two**\n• three')).toBe('[ul:one;<b>two</b>;three]');
    expect(render('* a\n* b')).toBe('[ul:a;b]');
  });

  it('takes release-note dashes with no space before a word', () => {
    expect(render('What is new:\n-Faster search\n-Fewer bugs')).toBe(
      'What is new:|[ul:Faster search;Fewer bugs]',
    );
  });

  it('numbers from the first item', () => {
    expect(render('1. first\n2. second')).toBe('[ol:first;second]');
    expect(render('3) third\n4) fourth')).toBe('[ol start=3:third;fourth]');
  });

  it('keeps the text around a list, without the blank lines that set it apart', () => {
    expect(render('Before\n\n- a\n- b\n\nAfter')).toBe('Before|[ul:a;b]|After');
  });

  it('leaves a single dash line, negatives and years as they are', () => {
    expect(render('- just a dash')).toBe('- just a dash');
    expect(render('-5 today\n-3 tomorrow')).toBe('-5 today\n-3 tomorrow');
    expect(render('2024. What a year\n2025. Another')).toBe('2024. What a year\n2025. Another');
    expect(render('*italic* line\n*more* here')).toBe('<i>italic</i> line\n<i>more</i> here');
  });

  it('splits bullets and numbers into separate lists', () => {
    expect(render('- a\n- b\n1. c\n2. d')).toBe('[ul:a;b]|[ol:c;d]');
  });

  it('leaves list markers inside a code block alone', () => {
    expect(render('```\n- a\n- b\n```')).toBe('[pre:- a\n- b]');
  });
});

describe('formatMessage: code spans', () => {
  it('protects their content from formatting and linkification', () => {
    expect(render('`**not bold**`')).toBe('<code>**not bold**</code>');
    expect(render('`https://example.com`')).toBe('<code>https://example.com</code>');
    expect(render('`@ada`')).toBe('<code>@ada</code>');
    expect(render('`a_b_c`')).toBe('<code>a_b_c</code>');
  });

  it('matches runs of the same length', () => {
    expect(render('``a ` b``')).toBe('<code>a ` b</code>');
    expect(render('` `` `')).toBe('<code>``</code>');
    expect(render('```one line```')).toBe('<code>one line</code>');
  });

  it('nests inside emphasis', () => {
    expect(render('**use `x` here**')).toBe('<b>use <code>x</code> here</b>');
    expect(render('*`x`*')).toBe('<i><code>x</code></i>');
  });

  it('pairs markers around, not across, a span', () => {
    expect(render('*a `b*` c*')).toBe('<i>a <code>b*</code> c</i>');
  });

  it('leaves an unmatched backtick literal', () => {
    expect(render("it's `half done")).toBe("it's `half done");
    expect(render('a ` b `` c')).toBe('a ` b `` c');
  });
});

describe('formatMessage: code blocks', () => {
  it('renders a fenced block and ignores the language tag', () => {
    expect(formatMessage('```ts\nconst a = 1;\n  b();\n```')).toEqual([
      { type: 'code', text: 'const a = 1;\n  b();' },
    ]);
  });

  it('splits surrounding text into its own blocks', () => {
    expect(render('look:\n```\n**raw** https://x.test\n```\nnice *right*')).toBe(
      'look:|[pre:**raw** https://x.test]|nice <i>right</i>',
    );
  });

  it('preserves whitespace inside the block', () => {
    const [block] = formatMessage('```\n\tindented\n    four\n\n```');
    expect(block).toEqual({ type: 'code', text: '\tindented\n    four\n' });
  });

  it('handles CRLF line endings', () => {
    expect(formatMessage('```\r\na\r\nb\r\n```')).toEqual([{ type: 'code', text: 'a\nb' }]);
  });

  it('treats an unclosed fence as text', () => {
    const text = '```\nnot closed';
    expect(render(text)).toBe(text);
  });

  it('treats an empty fence pair as text', () => {
    expect(render('```\n```')).toBe('```\n```');
  });

  it('pairs several blocks in order', () => {
    expect(render('```\na\n```\nmid\n```\nb\n```')).toBe('[pre:a]|mid|[pre:b]');
  });

  it('requires the fence on its own line', () => {
    expect(render('text ```\ncode\n```')).toBe('text ```\ncode\n```');
  });
});

describe('formatMessage: links', () => {
  it('keeps link detection working inside bold', () => {
    expect(render('**see https://example.com/a**')).toBe(
      '<b>see <a https://example.com/a>https://example.com/a</a></b>',
    );
    expect(render('**https://example.com**')).toBe(
      '<b><a https://example.com>https://example.com</a></b>',
    );
  });

  it('never treats * or _ inside a URL as a marker', () => {
    expect(render('https://x.test/a_b_c')).toBe('<a https://x.test/a_b_c>https://x.test/a_b_c</a>');
    expect(render('_see https://x.test/a_b_c now_')).toBe(
      '<i>see <a https://x.test/a_b_c>https://x.test/a_b_c</a> now</i>',
    );
    expect(render('https://x.test/*star*/x')).toBe(
      '<a https://x.test/*star*/x>https://x.test/*star*/x</a>',
    );
  });

  it('keeps a trailing underscore on a URL when nothing is closed by it', () => {
    expect(render('https://x.test/wiki/Foo_')).toBe(
      '<a https://x.test/wiki/Foo_>https://x.test/wiki/Foo_</a>',
    );
    expect(render('go https://x.test/a** now')).toBe(
      'go <a https://x.test/a**>https://x.test/a**</a> now',
    );
  });

  it('closes emphasis with markers stuck to the end of a URL', () => {
    expect(render('*https://x.test/a*')).toBe('<i><a https://x.test/a>https://x.test/a</a></i>');
    expect(render('~~https://x.test~~,')).toBe('<s><a https://x.test>https://x.test</a></s>,');
  });

  it('never lets a link href differ from its text', () => {
    const walk = (nodes: InlineNode[]) => {
      for (const n of nodes) {
        if (n.type === 'link') expect(n.href).toBe(n.text);
        if ('children' in n) walk(n.children);
      }
    };
    for (const text of ['**https://a.test**', 'https://a.test/_', '_https://a.test/x_', 'x https://a.test~~']) {
      for (const b of formatMessage(text)) if (b.type === 'text') walk(b.children);
    }
  });
});

describe('formatMessage: mentions', () => {
  it('keeps a mention inside bold as ordinary text', () => {
    // Mention highlighting tests the raw message, so it is unaffected; the
    // formatter only has to keep the handle intact.
    expect(render('**@Ada** look')).toBe('<b>@Ada</b> look');
    expect(render('hey _@Ada_')).toBe('hey <i>@Ada</i>');
  });

  it('does not treat an e-mail-ish underscore as a marker', () => {
    expect(render('mail first_last@example.com')).toBe('mail first_last@example.com');
  });
});

describe('formatMessage: bidi and markup safety', () => {
  it('carries markup-looking text as plain text', () => {
    expect(render('**<img src=x onerror=alert(1)>**')).toBe('<b><img src=x onerror=alert(1)></b>');
    const [block] = formatMessage('**<script>**');
    expect(block).toEqual({
      type: 'text',
      children: [{ type: 'bold', children: [{ type: 'text', text: '<script>' }] }],
    });
  });

  it('does not linkify a URL carrying a bidi control, even inside formatting', () => {
    const [block] = formatMessage('**https://exa\u202Emple.com**');
    expect(block.type === 'text' && JSON.stringify(block.children).includes('"link"')).toBe(false);
  });
});

describe('formatMessage: limits', () => {
  it('stays fast on adversarial input at the message size limit', () => {
    const patterns = [
      '*a'.repeat(2048),
      '**'.repeat(2048),
      '`'.repeat(4096),
      '` `` ``` '.repeat(455),
      '*_~~'.repeat(1024),
      ('**a ' + '_b '.repeat(10)).repeat(120),
      '```\n'.repeat(1024),
      'https://x.test/_* '.repeat(227),
    ];
    const started = performance.now();
    for (let round = 0; round < 5; round++) {
      for (const text of patterns) formatMessage(text);
    }
    // Forty 4 KiB messages; a quadratic pass would take seconds here.
    expect(performance.now() - started).toBeLessThan(1500);
  });

  it('falls back to links only past the size cap', () => {
    const text = '**x** '.repeat(Math.ceil(FORMAT_MAX_CHARS / 6) + 1);
    const blocks = formatMessage(text);
    expect(blocks).toHaveLength(1);
    expect(blocks[0]).toEqual({ type: 'text', children: [{ type: 'text', text }] });
  });

  it('keeps a deep pile of openers from nesting past the cap', () => {
    const text = `${'*a _b ~~c '.repeat(50)}`;
    for (const b of formatMessage(text)) if (b.type === 'text') expect(depth(b.children)).toBeLessThanOrEqual(3);
  });
});
