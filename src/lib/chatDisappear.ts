/**
 * Disappearing messages as the UI shows them: the timers offered, their
 * names, and how long one has left.
 */
import * as m from '$lib/paraglide/messages';
import { CHAT_DISAPPEAR_CHOICES } from '$lib/friendSettings';

export { CHAT_DISAPPEAR_CHOICES };

/** A timer's name, "Off" for none. An unknown value is named by the nearest
 *  offered one, as the backend stores it. */
export function disappearLabel(secs: number): string {
  if (!(secs > 0)) return m.chat_disappear_off();
  const nearest = CHAT_DISAPPEAR_CHOICES.reduce((best, choice) =>
    Math.abs(choice - secs) < Math.abs(best - secs) ? choice : best,
  );
  switch (nearest) {
    case 300:
      return m.chat_disappear_5m();
    case 3_600:
      return m.chat_disappear_1h();
    case 86_400:
      return m.chat_disappear_1d();
    case 604_800:
      return m.chat_disappear_1w();
    default:
      return m.chat_disappear_4w();
  }
}

/** How long until `expiresAt` (Unix seconds), roughly, for a bubble's tooltip:
 *  minutes under an hour, hours under a day, then days. */
export function disappearsIn(expiresAt: number, nowMs: number = Date.now()): string {
  const left = Math.max(0, expiresAt - Math.floor(nowMs / 1000));
  if (left < 3_600) return m.chat_disappears_in_minutes({ count: Math.max(1, Math.ceil(left / 60)) });
  if (left < 86_400) return m.chat_disappears_in_hours({ count: Math.ceil(left / 3_600) });
  return m.chat_disappears_in_days({ count: Math.ceil(left / 86_400) });
}
