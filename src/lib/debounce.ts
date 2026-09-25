export interface MaxWaitDebouncer {
  /** Ask for a run `waitMs` after the last call, but no later than `maxWaitMs`
   *  after the first call of the current burst. A shorter max-wait passed
   *  mid-burst pulls the deadline in; a longer one never pushes it out. */
  schedule(waitMs: number, maxWaitMs: number): void;
  /** Drop a scheduled run. */
  cancel(): void;
  readonly pending: boolean;
}

/**
 * Trailing debounce that still fires while calls keep arriving. A plain
 * trailing debounce never runs at all if the gap between calls stays under
 * its window, which is exactly the case for a steady event stream.
 */
export function createMaxWaitDebounce(fn: () => void): MaxWaitDebouncer {
  let timer: ReturnType<typeof setTimeout> | null = null;
  let deadline: number | null = null;

  const fire = () => {
    timer = null;
    deadline = null;
    fn();
  };

  return {
    schedule(waitMs, maxWaitMs) {
      const now = Date.now();
      const burstDeadline = now + Math.max(waitMs, maxWaitMs);
      deadline = deadline === null ? burstDeadline : Math.min(deadline, burstDeadline);
      if (timer !== null) clearTimeout(timer);
      timer = setTimeout(fire, Math.max(0, Math.min(now + waitMs, deadline) - now));
    },
    cancel() {
      if (timer !== null) clearTimeout(timer);
      timer = null;
      deadline = null;
    },
    get pending() {
      return timer !== null;
    },
  };
}
