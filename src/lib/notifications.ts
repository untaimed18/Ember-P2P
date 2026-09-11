/**
 * Desktop notifications: one place that decides whether an event is worth
 * interrupting the user for.
 *
 * The events themselves are already handled — a finished download updates the
 * Transfers list, a chat message bumps an unread badge, a room message raises a
 * toast. All of that is invisible the moment the window is hidden to the tray,
 * which is exactly when a P2P client is most useful and least watched. This
 * module is the bridge from those existing listeners to the OS.
 *
 * ## Why the policy lives here and not in the backend
 *
 * The backend performs the OS call ({@link showNotification}) but cannot decide
 * whether to make it: whether the user is looking at the window, which
 * conversation is open, whether a room is muted, and what the sentence reads
 * like in the active locale are all facts the renderer owns. So the renderer
 * decides and composes; the backend sanitizes, re-checks the master switch, and
 * rate-limits.
 *
 * ## What is deliberately suppressed
 *
 * - Anything while Ember is the focused window, unless the user opted out of
 *   that (`notifications_only_when_unfocused`). Being told about something you
 *   are looking at is noise.
 * - Repeats of the same notification inside {@link DEDUPE_WINDOW_MS}. The
 *   backend can emit an event twice — the upload- and download-side session
 *   loops both surface a chat message — and the stores already dedupe for their
 *   own badges, but not every caller does.
 * - Bursts past {@link MAX_PER_WINDOW}. Fifty finished downloads at once is a
 *   queue draining, not fifty things to read.
 */

import { get } from 'svelte/store';
import { showNotification } from '$lib/api/system';
import { appSettings } from '$lib/stores/settings';
import type { AppSettings } from '$lib/types';

/** The categories a user can switch off independently, keyed to their setting. */
export type NotifyCategory =
  | 'download_complete'
  | 'download_failed'
  | 'friend_online'
  | 'friend_message'
  | 'friend_request'
  | 'channel_message';

const CATEGORY_SETTING: Record<NotifyCategory, keyof AppSettings> = {
  download_complete: 'notify_download_complete',
  download_failed: 'notify_download_failed',
  friend_online: 'notify_friend_online',
  // Chat messages and file offers share one switch: both are "a friend is
  // trying to reach you", and splitting them would be a setting nobody wants to
  // reason about.
  friend_message: 'notify_friend_message',
  friend_request: 'notify_friend_request',
  channel_message: 'notify_channel_message',
};

/** Identical notifications inside this window collapse into one. */
const DEDUPE_WINDOW_MS = 5_000;
/** Rolling burst ceiling, well under the backend's own limiter. */
const MAX_PER_WINDOW = 4;
const RATE_WINDOW_MS = 10_000;

const recentSignatures = new Map<string, number>();
let recentSends: number[] = [];

/**
 * Set once the OS has refused to show a notification, so a machine with
 * notifications disabled at the system level stops paying for an IPC round trip
 * per event. Lasts for the rest of the session; restarting Ember is how a
 * user who later allows notifications at the OS level gets another try.
 */
let deliveryUnavailable = false;

/**
 * Whether Ember is the window the user is currently looking at.
 *
 * Both halves matter. `visibilityState` covers hidden-to-tray and minimized;
 * `hasFocus` covers the far more common case of the window being on screen
 * behind whatever the user is actually working in. Treating a background but
 * visible window as "being watched" is what made the first cut of this silent
 * on a second monitor.
 *
 * This is the only place that question is answered for a notification. The
 * store handlers have their own, looser "is the user looking at this
 * conversation" test for the unread badge and the in-app toast, and gating the
 * notification on *that* put the second-monitor case straight back — the
 * handler returned before this check was ever consulted.
 */
function emberIsFocused(): boolean {
  if (typeof document === 'undefined') return false;
  return document.visibilityState === 'visible' && document.hasFocus();
}

function withinRateLimit(now: number): boolean {
  recentSends = recentSends.filter((at) => now - at < RATE_WINDOW_MS);
  if (recentSends.length >= MAX_PER_WINDOW) return false;
  recentSends.push(now);
  return true;
}

function isDuplicate(signature: string, now: number): boolean {
  for (const [key, expiry] of recentSignatures) {
    if (expiry <= now) recentSignatures.delete(key);
  }
  if (recentSignatures.has(signature)) return true;
  recentSignatures.set(signature, now + DEDUPE_WINDOW_MS);
  return false;
}

/**
 * Whether a notification of this category should be shown right now.
 *
 * Exported so callers with expensive bodies to build — resolving a friend's
 * nickname, formatting a size — can bail before doing the work.
 */
export function shouldNotify(category: NotifyCategory): boolean {
  if (deliveryUnavailable) return false;
  const settings = get(appSettings);
  // Unknown settings means the app has not finished booting. Staying silent is
  // the conservative reading: a missed notification during the first second is
  // nothing, an unwanted one is a broken promise.
  if (!settings) return false;
  if (!settings.notifications_enabled) return false;
  if (!settings[CATEGORY_SETTING[category]]) return false;
  if (settings.notifications_only_when_unfocused && emberIsFocused()) return false;
  return true;
}

/**
 * Show a desktop notification, subject to {@link shouldNotify}, deduplication
 * and the burst ceiling.
 *
 * Never throws and never rejects: every caller is an event listener whose real
 * job is updating a store, and a failed notification must not take that down.
 */
export async function notify(
  category: NotifyCategory,
  title: string,
  body = '',
): Promise<void> {
  if (!shouldNotify(category)) return;
  const trimmedTitle = title.trim();
  if (!trimmedTitle) return;

  const now = Date.now();
  if (isDuplicate(`${category}|${trimmedTitle}|${body}`, now)) return;
  if (!withinRateLimit(now)) return;

  try {
    await showNotification(trimmedTitle, body);
  } catch (error) {
    // Only a refusal by the shell may latch the "give up" flag, because only
    // that will keep happening until something changes. The two codes below are
    // facts about *this* message: the backend's own ceiling doing its job, and
    // a title that sanitized away to nothing. Latching on either would be
    // wrong in principle, and there is no longer any way back from it —
    // `resetNotificationAvailability` was removed once the Settings test button
    // went — so one bad message would silently cost the whole feature for the
    // rest of the session.
    const aboutThisMessage =
      isCodedError(error, 'notification_rate_limited')
      || isCodedError(error, 'notification_empty_title');
    if (!aboutThisMessage) {
      deliveryUnavailable = true;
      console.warn('Desktop notifications unavailable; suppressing further attempts:', error);
    }
  }
}

function isCodedError(error: unknown, code: string): boolean {
  if (typeof error !== 'string') return false;
  try {
    const parsed: unknown = JSON.parse(error);
    return (
      !!parsed
      && typeof parsed === 'object'
      && (parsed as { __coded?: unknown }).__coded === true
      && (parsed as { code?: unknown }).code === code
    );
  } catch {
    return false;
  }
}

/** Test seam: drop the dedupe and burst state between cases. */
export function resetNotificationThrottleForTest(): void {
  recentSignatures.clear();
  recentSends = [];
  deliveryUnavailable = false;
}
