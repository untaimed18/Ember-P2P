/**
 * Replies in rooms: the quote a reply draws, and the reply a room's composer
 * is holding.
 *
 * The reference itself is not built here. It is the parent's wire id, signed
 * into the message by the backend (`with_reply_trailer` in
 * `src-tauri/src/network/ember/channel.rs`) and handed back as `reply_to`, with
 * the text already stripped of it.
 */
import { formatMessage, type FormatBlock, type InlineNode } from '$lib/messageFormat';

/** Characters of the parent a quote shows before it is cut with an ellipsis. */
export const REPLY_EXCERPT_MAX = 120;

function inlineText(nodes: InlineNode[]): string {
  let out = '';
  for (const node of nodes) {
    if (node.type === 'text' || node.type === 'link' || node.type === 'code') out += node.text;
    else out += inlineText(node.children);
  }
  return out;
}

/** What a formatted message reads as with its markers taken away. */
export function plainTextOf(blocks: FormatBlock[]): string {
  return blocks
    .map((block) => {
      if (block.type === 'code') return block.text;
      if (block.type === 'list') return block.items.map(inlineText).join('\n');
      return inlineText(block.children);
    })
    .join('\n');
}

const segmenter: { segment(input: string): Iterable<{ segment: string }> } | null =
  typeof Intl !== 'undefined' && 'Segmenter' in Intl
    ? new Intl.Segmenter(undefined, { granularity: 'grapheme' })
    : null;

/** Whole user-perceived characters, so a cut never splits a flag, an emoji
 *  sequence or a combining mark from its base. */
function graphemes(text: string): string[] {
  return segmenter ? Array.from(segmenter.segment(text), (s) => s.segment) : Array.from(text);
}

/**
 * One line of a message for a reply's quote: formatting markers dropped, the
 * first line with anything on it, runs of whitespace folded, and cut to `max`
 * characters with an ellipsis. Empty when there is nothing to show.
 */
export function replyExcerpt(text: string, max = REPLY_EXCERPT_MAX): string {
  const line =
    plainTextOf(formatMessage(text))
      .split('\n')
      .map((l) => l.replace(/\s+/g, ' ').trim())
      .find((l) => l.length > 0) ?? '';
  if (line.length <= max) return line;
  const chars = graphemes(line);
  if (chars.length <= max) return line;
  return `${chars.slice(0, max).join('').trimEnd()}\u2026`;
}

/**
 * Excerpts by source text. The quote is drawn on every transcript rebuild,
 * and running the formatter over the same parent each time is what
 * `ChatConversation`'s row cache exists to avoid. Cleared wholesale when it
 * grows, which is cheaper than tracking use and costs one re-format each.
 */
const excerptCache = new Map<string, string>();
const EXCERPT_CACHE_MAX = 1000;

export function cachedReplyExcerpt(text: string): string {
  let hit = excerptCache.get(text);
  if (hit === undefined) {
    if (excerptCache.size >= EXCERPT_CACHE_MAX) excerptCache.clear();
    hit = replyExcerpt(text);
    excerptCache.set(text, hit);
  }
  return hit;
}

/** The parts of a reply the quote is resolved from. */
export interface ReplyFields {
  reply_to?: string | null;
  reply_parent?: { id: number; sender_pubkey: string; excerpt: string } | null;
  reply_parent_deleted?: boolean;
}

/** A loaded message a quote can be drawn from. */
export interface QuotableMessage {
  id: number;
  sender_pubkey?: string;
  message: string;
}

export type ReplyQuote =
  | { kind: 'parent'; id: number; senderPubkey: string; text: string }
  | { kind: 'deleted' }
  | { kind: 'missing' };

/**
 * What a reply's quote should show.
 *
 * A parent that is loaded wins, because it is the copy live edits patch; the
 * backend's snapshot is the fallback for one paged out of view. A parent
 * removed in this session is gone even though the snapshot, taken before the
 * removal, still has it.
 */
export function resolveReplyQuote(
  reply: ReplyFields,
  loaded: ReadonlyMap<string, QuotableMessage>,
  removed: ReadonlySet<string>,
): ReplyQuote | null {
  const parentId = reply.reply_to;
  if (!parentId) return null;
  const here = loaded.get(parentId);
  if (here && here.id > 0) {
    return { kind: 'parent', id: here.id, senderPubkey: here.sender_pubkey ?? '', text: here.message };
  }
  if (removed.has(parentId)) return { kind: 'deleted' };
  const snapshot = reply.reply_parent;
  if (snapshot) {
    return {
      kind: 'parent',
      id: snapshot.id,
      senderPubkey: snapshot.sender_pubkey,
      text: snapshot.excerpt,
    };
  }
  return reply.reply_parent_deleted ? { kind: 'deleted' } : { kind: 'missing' };
}

/** The message a room's composer is replying to. */
export interface PendingReply {
  /** Local row id, for jumping to it. */
  id: number;
  /** Wire id, which is what is sent. */
  msgId: string;
  senderPubkey: string;
  /** Text when Reply was chosen; the bar prefers the loaded copy if edited. */
  text: string;
}

/**
 * Per room, like the composer's draft (`getDraft` / `setDraft`): leaving a
 * room and coming back finds the reply still set, and nothing else sees it.
 * Module scope so it outlives the component when the page remounts it.
 */
const pendingReplies = new Map<string, PendingReply>();

export function getPendingReply(channelId: string): PendingReply | null {
  return pendingReplies.get(channelId) ?? null;
}

export function setPendingReply(channelId: string, reply: PendingReply | null): void {
  if (reply) pendingReplies.set(channelId, reply);
  else pendingReplies.delete(channelId);
}
