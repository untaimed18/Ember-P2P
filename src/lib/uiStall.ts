import { invoke } from '@tauri-apps/api/core';

/**
 * Notices when the main window stops answering, and says so in `ember.log`
 * once it answers again, so a freeze someone describes can be told apart
 * afterwards: this window's own thread busy (scripts, layout, paint), one
 * long task holding it, or the window waiting on a reply from the backend.
 */

/** How often the window checks it is still running. */
const TICK_MS = 250;
/** A tick this much later than due is a freeze. */
const STALL_MS = 2_000;
/** How often a round trip to the backend is timed, and how slow is slow. */
const PING_MS = 2_000;
const SLOW_PING_MS = 2_000;
/** A single task holding the thread this long is reported on its own. */
const LONG_TASK_MS = 1_000;

/** What the window did lately, so a freeze says what came just before it. */
const recent: { at: number; what: string }[] = [];
const RECENT_MAX = 24;
/** Activity this long before a freeze began is listed with it. */
const LEAD_MS = 2_000;

/** Note something the window is about to do, or just did, that could hold its
 *  thread: an event handled, a list refreshed, a page opened. */
export function noteUiActivity(what: string): void {
  recent.push({ at: performance.now(), what });
  if (recent.length > RECENT_MAX) recent.shift();
}

/** Run `run`, noting `what` before it and, when it held the thread a while,
 *  how long it took. */
export function timedUiActivity<T>(what: string, run: () => T): T {
  noteUiActivity(what);
  const started = performance.now();
  try {
    return run();
  } finally {
    const took = performance.now() - started;
    if (took >= SLOW_STEP_MS) noteUiActivity(`${what} took ${Math.round(took)} ms`);
  }
}

/** A step this slow is noted with its time. */
const SLOW_STEP_MS = 100;

/** The activity from `LEAD_MS` before `from` to now, oldest first, each with
 *  how long before the freeze began it was noted. */
function activitySince(from: number): string {
  return recent
    .filter((entry) => entry.at >= from - LEAD_MS)
    .map((entry) => `${entry.what} (${Math.round(entry.at - from)} ms)`)
    .join('; ');
}

function visible(): boolean {
  return document.visibilityState === 'visible';
}

/** The page, as a name: a leading `/` would read as a file path in the log
 *  and be pseudonymised. */
function pageName(): string {
  return location.pathname.replace(/^\/+|\/+$/g, '').replace(/\//g, '.') || 'home';
}

function report(kind: string, ms: number, shown: boolean, detail = ''): void {
  void invoke('log_ui_stall', {
    kind,
    ms: Math.round(ms),
    route: pageName(),
    visible: shown,
    detail,
  }).catch(() => {});
}

/** Backend events received since the last tick, by name: a flood of them
 *  holds the thread one small task at a time, which no single task being long
 *  would show. */
const received = new Map<string, number>();

/** Count one delivery of the backend event `name` to this window. */
export function noteDelivery(name: string): void {
  received.set(name, (received.get(name) ?? 0) + 1);
}

/** The most frequent deliveries since the last tick, e.g. `transfer-progress×812`. */
function topDeliveries(): string {
  const total = [...received.values()].reduce((sum, n) => sum + n, 0);
  if (total === 0) return '';
  const top = [...received.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, n]) => `${name}×${n}`)
    .join(' ');
  return `received ${total}: ${top}`;
}

/** Start watching; returns what stops it. Never throws: a diagnostic must not
 *  keep the app from starting. */
export function startStallDetector(): () => void {
  try {
    return watch();
  } catch (error) {
    console.warn('UI stall detector could not start:', error);
    return () => {};
  }
}

function watch(): () => void {
  let last = performance.now();
  let wasVisible = visible();
  // A hidden window's timers are throttled to a minute apart, which is not a
  // freeze: only a window shown before and after the gap counts.
  const tick = window.setInterval(() => {
    const now = performance.now();
    const late = now - last - TICK_MS;
    const shown = visible();
    if (late >= STALL_MS && wasVisible && shown) {
      report('blocked', late, true, [topDeliveries(), activitySince(last)].filter(Boolean).join(' | '));
    }
    received.clear();
    last = now;
    wasVisible = shown;
  }, TICK_MS);

  let pinging = false;
  const ping = window.setInterval(() => {
    if (pinging) return;
    pinging = true;
    const started = performance.now();
    const shown = visible();
    void invoke('ui_ping')
      .catch(() => {})
      .finally(() => {
        pinging = false;
        const ms = performance.now() - started;
        if (ms >= SLOW_PING_MS && shown && visible()) report('ipc', ms, true);
      });
  }, PING_MS);

  let observer: PerformanceObserver | null = null;
  try {
    observer = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (entry.duration < LONG_TASK_MS) continue;
        const where = (entry as PerformanceEntry & { attribution?: { containerType?: string; name?: string }[] })
          .attribution?.map((a) => `${a.containerType ?? ''} ${a.name ?? ''}`.trim())
          .filter(Boolean)
          .join(', ');
        report('long_task', entry.duration, visible(), [where, activitySince(entry.startTime)].filter(Boolean).join(' | '));
      }
    });
    observer.observe({ type: 'longtask', buffered: false });
  } catch {
    // Not every webview reports long tasks; the tick still sees the freeze.
    observer = null;
  }

  return () => {
    window.clearInterval(tick);
    window.clearInterval(ping);
    observer?.disconnect();
  };
}
