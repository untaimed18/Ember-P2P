import { derived, get, writable } from 'svelte/store';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import {
  FEEDS_CHANGED_EVENT,
  discoverFeeds,
  listFollowedFeeds,
  type DiscoveredFeed,
  type FeedsChangedEvent,
  type FollowedFeed,
} from '$lib/api/feeds';
import { notify } from '$lib/notifications';
import { formatNumber } from '$lib/utils';
import * as m from '$lib/paraglide/messages';

/** The feeds this identity follows, for the sidebar badge and the page. */
export const followedFeeds = writable<FollowedFeed[]>([]);

/** New items across every followed feed. */
export const totalFeedUnread = derived(followedFeeds, (feeds) => feeds.reduce((sum, f) => sum + f.unread, 0));

/** Whether the followed feeds have been read once, and whether the last read
 *  failed: an empty list is not "you follow nothing" until then. */
export const followedFeedsLoaded = writable(false);
export const followedFeedsFailed = writable(false);

let refreshSeq = 0;

export async function refreshFollowedFeeds(): Promise<void> {
  const seq = ++refreshSeq;
  try {
    const feeds = await listFollowedFeeds();
    if (seq === refreshSeq) {
      followedFeeds.set(feeds);
      followedFeedsLoaded.set(true);
      followedFeedsFailed.set(false);
    }
  } catch (e) {
    console.warn('feeds: could not read followed feeds', e);
    if (seq === refreshSeq) followedFeedsFailed.set(true);
  }
}

let unlisten: UnlistenFn | null = null;
let initialized = false;
let epoch = 0;

export async function initFeedsStore(): Promise<void> {
  if (initialized) return;
  initialized = true;
  const mine = ++epoch;
  let registered: UnlistenFn;
  try {
    registered = await listen<FeedsChangedEvent>(FEEDS_CHANGED_EVENT, (event) => {
      const { publisher, salt, added, title } = event.payload ?? {};
      // One naming only a salt is of a feed of ours.
      if (publisher || !salt) void refreshFollowedFeeds();
      // `notify` stays quiet while the user is looking at Ember.
      if (added && added > 0) {
        void notify('feed_update', m.feeds_notify_new({ title: title?.trim() || m.feeds_untitled(), count: formatNumber(added) }));
      }
    });
  } catch (e) {
    initialized = false;
    throw e;
  }
  // Cleaned up while `listen` was pending.
  if (mine !== epoch) {
    registered();
    return;
  }
  unlisten = registered;
  await refreshFollowedFeeds();
}

export function cleanupFeedsStore(): void {
  epoch++;
  unlisten?.();
  unlisten = null;
  initialized = false;
  refreshSeq++;
  followedFeeds.set([]);
  followedFeedsLoaded.set(false);
  followedFeedsFailed.set(false);
  lastWalkAt = 0;
  runningWalk = null;
  feedsPageMemory.tab = 'following';
  feedsPageMemory.own = null;
}

/** Where the Feeds page was left: its tab and the user's own feed open,
 *  by salt. Kept here, not on the page, which is made anew on each visit;
 *  for this run of the app only, and forgotten with the identity. The
 *  followed feed open is kept by the page itself, across runs. */
export const feedsPageMemory: { tab: 'following' | 'discover' | 'mine'; own: string | null } = {
  tab: 'following',
  own: null,
};

/** The followed feed `publisher`/`salt`, if followed. */
export function followedFeed(publisher: string, salt: string): FollowedFeed | undefined {
  return get(followedFeeds).find((f) => f.publisher === publisher && f.salt === salt);
}

/** A walk of the public feed index: the id its shards are tagged with, and
 *  the whole set it answers. */
export interface DiscoverWalk {
  walk: string;
  result: Promise<DiscoveredFeed[]>;
}

// Kept here, not on the Feeds page, which is made anew on each visit: a
// visit soon after a walk reads its cache rather than walking again, and
// one during a walk takes that walk's shards rather than starting another.
let lastWalkAt = 0;
let runningWalk: DiscoverWalk | null = null;

/** When the last walk began, in milliseconds; 0 before the first. */
export const lastDiscoverWalkAt = (): number => lastWalkAt;
export const discoverWalkRunning = (): boolean => runningWalk !== null;

function newWalk(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
  return `w-${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
}

/** Walk the index, or join the walk already running. */
export function startDiscoverWalk(): DiscoverWalk {
  if (runningWalk) return runningWalk;
  const walk = newWalk();
  const before = lastWalkAt;
  const startedAt = Date.now();
  lastWalkAt = startedAt;
  const result = discoverFeeds(walk)
    .catch((e: unknown) => {
      // A walk that failed does not put off the next one a visit starts.
      if (lastWalkAt === startedAt) lastWalkAt = before;
      throw e;
    })
    .finally(() => {
      if (runningWalk?.walk === walk) runningWalk = null;
    });
  runningWalk = { walk, result };
  return runningWalk;
}
