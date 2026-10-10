import { describe, expect, it } from 'vitest';
import { mergeChatAttachment, parseChatAttachment, type ChatAttachment } from './friends';

const row = (status: ChatAttachment['status'], transferred = 0): ChatAttachment => ({
  xfer_id: 'ab'.repeat(16),
  user_hash: 'cd'.repeat(16),
  direction: 'received',
  name: 'holiday.zip',
  size: 1000,
  transferred,
  status,
  created_at: 1_700_000_000,
  has_file: status === 'complete',
  risky: false,
  attempt: 0,
  retryable: status === 'failed',
});

describe('mergeChatAttachment', () => {
  // The list is fetched after the listener is registered, so a completion
  // event can land while the snapshot that still says "active" is in flight.
  it('keeps a finished row when a stale snapshot arrives after it', () => {
    const done = row('complete', 1000);
    expect(mergeChatAttachment(done, row('active', 400))).toBe(done);
    const cancelled = row('cancelled', 400);
    expect(mergeChatAttachment(cancelled, row('active', 600))).toBe(cancelled);
    expect(mergeChatAttachment(row('expired'), row('awaiting')).status).toBe('expired');
  });

  it('lets a live row move on, including to an ending', () => {
    expect(mergeChatAttachment(row('awaiting'), row('active', 10)).status).toBe('active');
    expect(mergeChatAttachment(row('active', 900), row('complete', 1000)).status).toBe('complete');
    expect(mergeChatAttachment(row('active', 900), row('accepted', 900)).status).toBe('accepted');
  });

  it('takes the later of two endings', () => {
    expect(mergeChatAttachment(row('failed'), row('cancelled')).status).toBe('cancelled');
  });

  it('never drags a moving bar backwards', () => {
    expect(mergeChatAttachment(row('active', 700), row('active', 300)).transferred).toBe(700);
    expect(mergeChatAttachment(row('active', 300), row('active', 700)).transferred).toBe(700);
  });

  it('lets "Try again" leave an ending, and keeps late updates from the old attempt out', () => {
    const failed = row('failed', 300);
    const retried = { ...row('offered'), attempt: 1 };
    expect(mergeChatAttachment(failed, retried)).toBe(retried);
    expect(mergeChatAttachment(retried, failed)).toBe(retried);
    const moving = { ...row('active', 200), attempt: 1 };
    expect(mergeChatAttachment(moving, row('active', 900))).toBe(moving);
    expect(mergeChatAttachment(moving, { ...row('active', 500), attempt: 1 }).transferred).toBe(500);
  });

  // A queued file goes out as a new attempt once the friend is back, and one
  // that lapsed in the queue is an ending until it is tried again.
  it('moves a queued file on to its offer, and keeps an undelivered one ended', () => {
    const queued = row('queued');
    const offered = { ...row('offered'), attempt: 1 };
    expect(mergeChatAttachment(queued, offered)).toBe(offered);
    expect(mergeChatAttachment(queued, row('offered')).status).toBe('offered');
    const undelivered = row('undelivered');
    expect(mergeChatAttachment(undelivered, row('queued'))).toBe(undelivered);
    expect(mergeChatAttachment(undelivered, { ...row('queued'), attempt: 1 }).status).toBe('queued');
  });

  it('treats the specific failures as endings', () => {
    const unreachable = row('unreachable');
    expect(mergeChatAttachment(unreachable, row('active', 100))).toBe(unreachable);
    const gone = row('source_gone', 300);
    expect(mergeChatAttachment(gone, row('active', 400))).toBe(gone);
  });
});

describe('parseChatAttachment', () => {
  // An event whose status the parser does not know is dropped, so a status the
  // backend emits has to be listed here or its bubble never updates.
  it('accepts every status the backend can emit', () => {
    for (const status of ['unreachable', 'source_gone', 'failed', 'queued', 'undelivered'] as const) {
      expect(parseChatAttachment(row(status))?.status).toBe(status);
    }
  });

  it('drops an unknown status', () => {
    expect(parseChatAttachment({ ...row('failed'), status: 'exploded' })).toBeNull();
  });

  it('reads the attempt and whether it can be retried, defaulting for an older backend', () => {
    expect(parseChatAttachment({ ...row('failed'), attempt: 2, retryable: true })).toMatchObject({
      attempt: 2,
      retryable: true,
    });
    const { attempt: _a, retryable: _r, ...older } = row('failed');
    expect(parseChatAttachment(older)).toMatchObject({ attempt: 0, retryable: false });
  });
});
