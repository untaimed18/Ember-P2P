import type { FileInfo } from '$lib/types';

/** Payload entry of the backend's `shared-file-stats` event: the latest upload
 *  counters for one file hash, coalesced and sent at most once a second. */
export type SharedFileStats = Pick<
  FileInfo,
  | 'hash'
  | 'requests'
  | 'accepted'
  | 'bytes_transferred'
  | 'alltime_requests'
  | 'alltime_accepted'
  | 'alltime_transferred'
>;

/** `shared-files-changed` phases that only ever carried upload counters. The
 *  backend now reports those on `shared-file-stats`; listeners still skip them
 *  so an older emitter can't drive a full library re-read per upload tick. */
const UPLOAD_PHASES = new Set(['upload-progress', 'upload-stats']);

export function isUploadCounterPhase(payload: unknown): boolean {
  const phase = (payload as { phase?: unknown } | null | undefined)?.phase;
  return typeof phase === 'string' && UPLOAD_PHASES.has(phase);
}

export interface AppliedSharedFileStats<T> {
  /** The input array itself when nothing changed, otherwise a copy in which
   *  only the affected rows are new objects. */
  rows: T[];
  changed: boolean;
  /** Growth in session upload bytes across the patched hashes, counted once
   *  per hash even when several rows share it. */
  uploadedDelta: number;
}

export function applySharedFileStats<T extends SharedFileStats>(
  rows: T[],
  stats: readonly SharedFileStats[],
): AppliedSharedFileStats<T> {
  const byHash = new Map<string, SharedFileStats>();
  for (const s of stats) {
    if (s?.hash) byHash.set(s.hash.toLowerCase(), s);
  }
  if (byHash.size === 0) return { rows, changed: false, uploadedDelta: 0 };

  let next: T[] | null = null;
  let uploadedDelta = 0;
  const counted = new Set<string>();
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const key = row.hash.toLowerCase();
    const s = byHash.get(key);
    if (!s) continue;
    if (!counted.has(key)) {
      counted.add(key);
      uploadedDelta += Math.max(0, s.bytes_transferred - row.bytes_transferred);
    }
    if (
      row.requests === s.requests &&
      row.accepted === s.accepted &&
      row.bytes_transferred === s.bytes_transferred &&
      row.alltime_requests === s.alltime_requests &&
      row.alltime_accepted === s.alltime_accepted &&
      row.alltime_transferred === s.alltime_transferred
    ) {
      continue;
    }
    next ??= rows.slice();
    next[i] = {
      ...row,
      requests: s.requests,
      accepted: s.accepted,
      bytes_transferred: s.bytes_transferred,
      alltime_requests: s.alltime_requests,
      alltime_accepted: s.alltime_accepted,
      alltime_transferred: s.alltime_transferred,
    };
  }
  return next
    ? { rows: next, changed: true, uploadedDelta }
    : { rows, changed: false, uploadedDelta };
}
