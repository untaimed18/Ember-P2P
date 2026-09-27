/**
 * Rejection from {@link withTimeout}.
 *
 * The message names the command and the deadline for the console; users never
 * see it, because `translateError` recognises the class and shows the
 * translated `error_timed_out` instead.
 */
export class TimeoutError extends Error {
  readonly label: string;
  readonly ms: number;

  constructor(label: string, ms: number) {
    super(`${label} timed out after ${Math.round(ms / 1000)}s`);
    this.name = 'TimeoutError';
    this.label = label;
    this.ms = ms;
  }
}

/**
 * Race a promise (in practice a Tauri `invoke()`) against a deadline.
 *
 * K24: without this the UI hangs indefinitely when the backend is wedged —
 * blocked on a slow DNS resolution, a stuck oneshot receiver — and a poll's
 * in-flight guard stays latched for the rest of the session. Rejects with a
 * {@link TimeoutError} so callers can show a "timed out, please try again"
 * toast instead of a spinner that never resolves.
 *
 * Only for calls whose expected duration is short and bounded. Anything
 * legitimately long-running — library scans, file hashing, native file
 * dialogs waiting on the user — must not be wrapped: a deadline there
 * reports failure for an operation that is still succeeding.
 */
export function withTimeout<T>(promise: Promise<T>, label: string, ms = 20_000): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new TimeoutError(label, ms));
    }, ms);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}
