import { derived, get, writable } from 'svelte/store';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { FEEDS_CHANGED_EVENT, listFollowedFeeds, type FeedsChangedEvent, type FollowedFeed } from '$lib/api/feeds';
import { notify } from '$lib/notifications';
import { formatNumber } from '$lib/utils';
import * as m from '$lib/paraglide/messages';

/** The feeds this identity follows, for the sidebar badge and the page. */
export const followedFeeds = writable<FollowedFeed[]>([]);

/** New items across every followed feed. */
export const totalFeedUnread = derived(followedFeeds, (feeds) => feeds.reduce((sum, f) => sum + f.unread, 0));

let refreshSeq = 0;

export async function refreshFollowedFeeds(): Promise<void> {
  const seq = ++refreshSeq;
  try {
    const feeds = await listFollowedFeeds();
    if (seq === refreshSeq) followedFeeds.set(feeds);
  } catch (e) {
    console.warn('feeds: could not read followed feeds', e);
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
      void refreshFollowedFeeds();
      const { added, title } = event.payload ?? {};
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
}

/** The followed feed `publisher`/`salt`, if followed. */
export function followedFeed(publisher: string, salt: string): FollowedFeed | undefined {
  return get(followedFeeds).find((f) => f.publisher === publisher && f.salt === salt);
}
