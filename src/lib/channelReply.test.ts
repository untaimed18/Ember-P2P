import { describe, expect, it } from 'vitest';
import {
  cachedReplyExcerpt,
  getPendingReply,
  plainTextOf,
  replyExcerpt,
  resolveReplyQuote,
  setPendingReply,
  REPLY_EXCERPT_MAX,
  type QuotableMessage,
} from './channelReply';
import { formatMessage } from './messageFormat';

describe('replyExcerpt', () => {
  it('drops formatting markers but keeps what they wrap', () => {
    expect(replyExcerpt('**bold** and *italic* and ~~gone~~ and `code`')).toBe(
      'bold and italic and gone and code',
    );
  });

  it('leaves text that only looks like markup alone', () => {
    expect(replyExcerpt('2*3*4 snake_case_name')).toBe('2*3*4 snake_case_name');
  });

  it('keeps a link as its text', () => {
    expect(replyExcerpt('see https://example.com/a_b_c')).toBe('see https://example.com/a_b_c');
  });

  it('takes the first line that has anything on it and folds whitespace', () => {
    expect(replyExcerpt('\n   \nfirst   line\tof it\nsecond line')).toBe('first line of it');
  });

  it('reads a leading code block as its content', () => {
    expect(replyExcerpt('```js\nconst x = 1;\n```\nafter')).toBe('const x = 1;');
  });

  it('cuts long text with an ellipsis and without trailing space', () => {
    const cut = replyExcerpt(`${'word '.repeat(60)}`, 12);
    expect(cut).toBe('word word wo\u2026');
    expect(replyExcerpt('x'.repeat(REPLY_EXCERPT_MAX))).toBe('x'.repeat(REPLY_EXCERPT_MAX));
    expect(replyExcerpt('x'.repeat(REPLY_EXCERPT_MAX + 1))).toBe(
      `${'x'.repeat(REPLY_EXCERPT_MAX)}\u2026`,
    );
  });

  it('never splits an emoji sequence at the cut', () => {
    const family = '\u{1F468}\u200D\u{1F469}\u200D\u{1F467}';
    const cut = replyExcerpt(`${family}${family}${family}`, 2);
    expect(cut).toBe(`${family}${family}\u2026`);
  });

  it('is empty for a message with nothing visible', () => {
    expect(replyExcerpt('')).toBe('');
    expect(replyExcerpt('   \n  ')).toBe('');
  });

  it('caches by text without changing the answer', () => {
    expect(cachedReplyExcerpt('**hi** there')).toBe('hi there');
    expect(cachedReplyExcerpt('**hi** there')).toBe('hi there');
  });
});

describe('plainTextOf', () => {
  it('joins blocks with newlines', () => {
    expect(plainTextOf(formatMessage('a **b**\n```\ncode\n```\nc'))).toBe('a b\ncode\nc');
  });
});

describe('resolveReplyQuote', () => {
  const parentId = 'ab'.repeat(16);
  const loaded = new Map<string, QuotableMessage>([
    [parentId, { id: 7, sender_pubkey: 'alice', message: 'edited words' }],
  ]);
  const none = new Map<string, QuotableMessage>();

  it('is nothing for a plain line', () => {
    expect(resolveReplyQuote({ reply_to: null }, loaded, new Set())).toBeNull();
  });

  it('prefers the loaded parent, which live edits keep current', () => {
    expect(
      resolveReplyQuote(
        {
          reply_to: parentId,
          reply_parent: { id: 7, sender_pubkey: 'alice', excerpt: 'old words' },
        },
        loaded,
        new Set(),
      ),
    ).toEqual({ kind: 'parent', id: 7, senderPubkey: 'alice', text: 'edited words' });
  });

  it('falls back to the snapshot for a parent paged out of view', () => {
    expect(
      resolveReplyQuote(
        {
          reply_to: parentId,
          reply_parent: { id: 3, sender_pubkey: 'bob', excerpt: 'older words' },
        },
        none,
        new Set(),
      ),
    ).toEqual({ kind: 'parent', id: 3, senderPubkey: 'bob', text: 'older words' });
  });

  it('says deleted for a parent removed here, now or before', () => {
    const snapshot = { id: 3, sender_pubkey: 'bob', excerpt: 'older words' };
    expect(
      resolveReplyQuote({ reply_to: parentId, reply_parent: snapshot }, none, new Set([parentId])),
    ).toEqual({ kind: 'deleted' });
    expect(
      resolveReplyQuote({ reply_to: parentId, reply_parent_deleted: true }, none, new Set()),
    ).toEqual({ kind: 'deleted' });
  });

  it('says missing for a parent this device never received', () => {
    expect(resolveReplyQuote({ reply_to: parentId }, none, new Set())).toEqual({
      kind: 'missing',
    });
  });

  it('does not treat an optimistic bubble as a jump target', () => {
    const optimistic = new Map<string, QuotableMessage>([
      [parentId, { id: -1, sender_pubkey: 'me', message: 'pending' }],
    ]);
    expect(resolveReplyQuote({ reply_to: parentId }, optimistic, new Set())).toEqual({
      kind: 'missing',
    });
  });
});

describe('pending replies', () => {
  it('are kept per room, like drafts', () => {
    const reply = { id: 1, msgId: 'ab'.repeat(16), senderPubkey: 'alice', text: 'hi' };
    setPendingReply('room-a', reply);
    expect(getPendingReply('room-a')).toEqual(reply);
    expect(getPendingReply('room-b')).toBeNull();
    setPendingReply('room-a', null);
    expect(getPendingReply('room-a')).toBeNull();
  });
});
