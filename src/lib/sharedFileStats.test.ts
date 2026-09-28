import { describe, expect, it } from 'vitest';
import { applySharedFileStats, isUploadCounterPhase, type SharedFileStats } from './sharedFileStats';

type Row = SharedFileStats & { path: string; matchName: string };

function row(path: string, hash: string, over: Partial<Row> = {}): Row {
  return {
    path,
    hash,
    matchName: path.toLowerCase(),
    requests: 0,
    accepted: 0,
    bytes_transferred: 0,
    alltime_requests: 0,
    alltime_accepted: 0,
    alltime_transferred: 0,
    ...over,
  };
}

function stats(hash: string, over: Partial<SharedFileStats> = {}): SharedFileStats {
  return {
    hash,
    requests: 0,
    accepted: 0,
    bytes_transferred: 0,
    alltime_requests: 0,
    alltime_accepted: 0,
    alltime_transferred: 0,
    ...over,
  };
}

describe('isUploadCounterPhase', () => {
  it('matches only the upload counter phases', () => {
    expect(isUploadCounterPhase({ phase: 'upload-progress', count: 1 })).toBe(true);
    expect(isUploadCounterPhase({ phase: 'upload-stats', count: 1 })).toBe(true);
    expect(isUploadCounterPhase({ phase: 'publish-badges', count: 0 })).toBe(false);
    expect(isUploadCounterPhase({ count: 3 })).toBe(false);
    expect(isUploadCounterPhase(null)).toBe(false);
    expect(isUploadCounterPhase(undefined)).toBe(false);
    expect(isUploadCounterPhase('upload-progress')).toBe(false);
  });
});

describe('applySharedFileStats', () => {
  it('replaces only the affected rows and keeps their other fields', () => {
    const a = row('C:/a.bin', 'AAAA');
    const b = row('C:/b.bin', 'bbbb');
    const rows = [a, b];
    const out = applySharedFileStats(rows, [
      stats('aaaa', { requests: 3, accepted: 2, bytes_transferred: 500, alltime_transferred: 900 }),
    ]);
    expect(out.changed).toBe(true);
    expect(out.rows).not.toBe(rows);
    expect(out.rows[1]).toBe(b);
    expect(out.rows[0]).toEqual({
      ...a,
      requests: 3,
      accepted: 2,
      bytes_transferred: 500,
      alltime_transferred: 900,
    });
    expect(out.rows[0].matchName).toBe('c:/a.bin');
    expect(rows[0]).toBe(a);
    expect(a.requests).toBe(0);
  });

  it('returns the same array when nothing moved', () => {
    const rows = [row('C:/a.bin', 'aaaa', { requests: 1 })];
    const out = applySharedFileStats(rows, [stats('aaaa', { requests: 1 })]);
    expect(out).toEqual({ rows, changed: false, uploadedDelta: 0 });
    expect(out.rows).toBe(rows);
    expect(applySharedFileStats(rows, []).rows).toBe(rows);
    expect(applySharedFileStats(rows, [stats('ffff', { requests: 9 })]).rows).toBe(rows);
  });

  it('patches every row sharing a hash but counts its upload growth once', () => {
    const rows = [
      row('C:/one/a.bin', 'aaaa', { bytes_transferred: 100 }),
      row('D:/two/a.bin', 'aaaa', { bytes_transferred: 100 }),
      row('C:/b.bin', 'bbbb', { bytes_transferred: 50 }),
    ];
    const out = applySharedFileStats(rows, [
      stats('aaaa', { bytes_transferred: 400 }),
      stats('bbbb', { bytes_transferred: 70 }),
    ]);
    expect(out.rows.map((r) => r.bytes_transferred)).toEqual([400, 400, 70]);
    expect(out.uploadedDelta).toBe(320);
  });

  it('never reports negative growth when counters were reset under it', () => {
    const rows = [row('C:/a.bin', 'aaaa', { bytes_transferred: 1000 })];
    const out = applySharedFileStats(rows, [stats('aaaa', { bytes_transferred: 10 })]);
    expect(out.rows[0].bytes_transferred).toBe(10);
    expect(out.uploadedDelta).toBe(0);
  });

  it('lets the last entry for a hash win', () => {
    const rows = [row('C:/a.bin', 'aaaa')];
    const out = applySharedFileStats(rows, [
      stats('aaaa', { requests: 1 }),
      stats('AAAA', { requests: 2 }),
    ]);
    expect(out.rows[0].requests).toBe(2);
  });
});
