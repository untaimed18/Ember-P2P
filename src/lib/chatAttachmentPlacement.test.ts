import { describe, expect, it } from 'vitest';
import { placeAttachments } from './chatAttachmentPlacement';
import { parseChatAttachment } from './api/friends';

const rows = [
  { id: 1, timestamp: 100 },
  { id: 2, timestamp: 200 },
  { id: 3, timestamp: 300 },
];
const att = (id: string, created_at: number) => ({ id, created_at });

describe('placeAttachments', () => {
  it('puts a file before the first message newer than it', () => {
    const p = placeAttachments(rows, [att('a', 150)], false);
    expect(p.before.get(2)?.map((a) => a.id)).toEqual(['a']);
    expect(p.after).toEqual([]);
  });

  it('puts a file newer than every message after the last one', () => {
    const p = placeAttachments(rows, [att('a', 400)], false);
    expect(p.after.map((a) => a.id)).toEqual(['a']);
    expect(p.before.size).toBe(0);
  });

  // The message in the same second was almost always typed first, so the file
  // belongs below it rather than above the line that introduced it.
  it('puts a file sent in the same second as a message after that message', () => {
    const p = placeAttachments(rows, [att('a', 200)], false);
    expect(p.before.get(3)?.map((a) => a.id)).toEqual(['a']);
  });

  it('keeps several files in time order, whatever order they arrived in', () => {
    const p = placeAttachments(rows, [att('late', 180), att('early', 120)], false);
    expect(p.before.get(2)?.map((a) => a.id)).toEqual(['early', 'late']);
  });

  it('shows everything in a conversation with no messages', () => {
    const p = placeAttachments([], [att('a', 1), att('b', 2)], false);
    expect(p.after.map((a) => a.id)).toEqual(['a', 'b']);
    expect(p.count).toBe(2);
  });

  // Otherwise every old file would pile up at the top of a transcript that
  // starts yesterday.
  it('holds back files from history that is not loaded yet', () => {
    const p = placeAttachments(rows, [att('old', 50), att('new', 250)], true);
    expect(p.count).toBe(1);
    expect(p.before.get(3)?.map((a) => a.id)).toEqual(['new']);
  });

  it('shows old files once all history is loaded', () => {
    const p = placeAttachments(rows, [att('old', 50)], false);
    expect(p.before.get(1)?.map((a) => a.id)).toEqual(['old']);
  });

  it('passes over rows with no timestamp', () => {
    const withUndated = [{ id: 9, timestamp: 0 }, ...rows];
    const p = placeAttachments(withUndated, [att('a', 50)], true);
    expect(p.before.get(1)?.map((a) => a.id)).toBeUndefined();
    expect(p.count).toBe(0);
  });
});

describe('parseChatAttachment', () => {
  const good = {
    xfer_id: 'ab'.repeat(16),
    user_hash: 'cd'.repeat(16),
    direction: 'received',
    name: 'holiday.zip',
    size: 1024,
    transferred: 512,
    status: 'active',
    created_at: 1_700_000_000,
    has_file: false,
    risky: false,
  };

  it('accepts a well-formed payload', () => {
    expect(parseChatAttachment(good)).toEqual(good);
  });

  it('refuses a payload whose ids are not hex of the right length', () => {
    expect(parseChatAttachment({ ...good, xfer_id: 'zz'.repeat(16) })).toBeNull();
    expect(parseChatAttachment({ ...good, user_hash: 'cd' })).toBeNull();
  });

  it('refuses an unknown direction or status', () => {
    expect(parseChatAttachment({ ...good, direction: 'sideways' })).toBeNull();
    expect(parseChatAttachment({ ...good, status: 'pending' })).toBeNull();
  });

  it('treats a non-numeric or negative size as zero rather than trusting it', () => {
    const p = parseChatAttachment({ ...good, size: -5, transferred: 'lots' });
    expect(p?.size).toBe(0);
    expect(p?.transferred).toBe(0);
  });

  it('only believes has_file when it is literally true', () => {
    expect(parseChatAttachment({ ...good, has_file: 'yes' })?.has_file).toBe(false);
  });

  it('carries the risky-file flag only when it is literally true', () => {
    expect(parseChatAttachment({ ...good, risky: true })?.risky).toBe(true);
    expect(parseChatAttachment({ ...good, risky: 'yes' })?.risky).toBe(false);
    const { risky: _omitted, ...older } = good;
    expect(parseChatAttachment(older)?.risky).toBe(false);
  });

  it('refuses things that are not objects', () => {
    expect(parseChatAttachment(null)).toBeNull();
    expect(parseChatAttachment('attachment')).toBeNull();
  });
});
