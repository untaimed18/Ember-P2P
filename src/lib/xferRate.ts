/**
 * Speed and time left for room file transfers, worked out from the progress
 * reports the backend sends while bytes move (`ProgressReporter` in
 * `src-tauri/src/network/ember/xfer.rs`: at most once a second, never while
 * nothing moved).
 */

/** A report older than this means the transfer stopped moving: the backend
 *  would have sent another one by now, so the last speed is no longer true. */
export const XFER_RATE_STALE_MS = 5000;

/** Reports closer together than this are folded into the next one. Two that
 *  land in the same event-loop turn would otherwise divide by almost nothing. */
const MIN_SPAN_MS = 250;

/** How far one report moves the shown speed. Low enough that a single slow
 *  second does not halve the number, high enough to follow a real change. */
const SMOOTHING = 0.35;

export interface RateSample {
  readonly bytes: number;
  readonly at: number;
  /** Bytes per second, smoothed. 0 until two reports have been seen. */
  readonly rate: number;
}

/** Transfer id to its latest sample. */
export type RateSamples = ReadonlyMap<string, RateSample>;

/** Fold a progress report into `samples`. The same map back when it changes
 *  nothing, so a caller assigning the result to state wakes nothing for it. */
export function noteXferBytes(samples: RateSamples, id: string, bytes: number, now: number): RateSamples {
  const prev = samples.get(id);
  if (!prev || bytes < prev.bytes) {
    return new Map(samples).set(id, { bytes, at: now, rate: 0 });
  }
  const span = now - prev.at;
  if (bytes === prev.bytes || span < MIN_SPAN_MS) return samples;
  const instant = ((bytes - prev.bytes) * 1000) / span;
  const rate = prev.rate > 0 ? prev.rate + SMOOTHING * (instant - prev.rate) : instant;
  return new Map(samples).set(id, { bytes, at: now, rate });
}

/** Bytes per second for `id` at `now`; 0 when unknown or stale. */
export function xferRate(samples: RateSamples, id: string, now: number): number {
  const sample = samples.get(id);
  if (!sample || now - sample.at > XFER_RATE_STALE_MS) return 0;
  return sample.rate;
}

/** Whole seconds until `size` is reached at `rate`, or null when that cannot
 *  be said honestly: no speed yet, or nothing left. */
export function xferSecondsLeft(size: number, transferred: number, rate: number): number | null {
  if (!(rate > 0) || transferred >= size) return null;
  return Math.ceil((size - transferred) / rate);
}

/** Only the samples for `ids`; the same map when nothing was dropped. */
export function keepXferSamples(samples: RateSamples, ids: ReadonlySet<string>): RateSamples {
  let next: Map<string, RateSample> | null = null;
  for (const id of samples.keys()) {
    if (ids.has(id)) continue;
    next ??= new Map(samples);
    next.delete(id);
  }
  return next ?? samples;
}
