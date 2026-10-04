import { invoke } from '@tauri-apps/api/core';

/**
 * Tell the backend someone is using Ember, so a silent update waits for them
 * to be away (`auto_update::silent`). Runs in every Ember window.
 *
 * Throttled hard: the backend only needs to know about input within the last
 * ten minutes, so one report every half minute is plenty, and a mouse held
 * over a table must not become an IPC call per event.
 */
const REPORT_EVERY_MS = 30_000;

const EVENTS = ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const;

export function startUserActivityReporting(): () => void {
  let lastReport = 0;
  const report = () => {
    const now = Date.now();
    if (now - lastReport < REPORT_EVERY_MS) return;
    lastReport = now;
    void invoke('note_user_activity').catch(() => {});
  };
  for (const name of EVENTS) {
    window.addEventListener(name, report, { passive: true, capture: true });
  }
  return () => {
    for (const name of EVENTS) {
      window.removeEventListener(name, report, { capture: true });
    }
  };
}
