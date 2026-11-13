import { writable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import { describeFeedLink, type FeedLinkInfo } from '$lib/api/feedLinks';

/** `FEEDS_CHANGED_EVENT`, named here too: the popped-out chat draws feed
 *  cards and may not load the module that follows feeds. */
const FEEDS_CHANGED = 'ember:feeds-changed';

/** A feed link as Ember writes one, or the website's address for it: the
 *  publisher's key and the salt, 48 bytes in unpadded base32. */
const FEED_LINK_RE = /(?:ember-feed:|https:\/\/(?:www\.)?emberp2p\.org\/feed\/)[a-z2-7]{77}(?![a-z2-7])/gi;

/** Cards drawn under one message at most: a list of links is a list, not a
 *  wall of cards. */
const MAX_CARDS = 3;

/** The feed links in a message, each once, in the order they appear. */
export function feedLinksIn(text: string): string[] {
  if (!text.includes('feed')) return [];
  const seen = new Set<string>();
  for (const match of text.matchAll(FEED_LINK_RE)) {
    const body = match[0].slice(match[0].length - 77).toLowerCase();
    seen.add(`ember-feed:${body}`);
    if (seen.size === MAX_CARDS) break;
  }
  return [...seen];
}

/** Asked once per link while the app runs: every message holding it draws
 *  the same card. A failed ask is forgotten, so a later card asks again. */
const described = new Map<string, Promise<FeedLinkInfo>>();

/** Moves on whenever a feed is followed, unfollowed or changed, so cards ask
 *  again rather than go on offering to follow one already followed. */
export const feedDescriptionsVersion = writable(0);
let listening = false;

export function describeFeed(link: string): Promise<FeedLinkInfo> {
  if (!listening) {
    listening = true;
    void listen(FEEDS_CHANGED, () => {
      described.clear();
      feedDescriptionsVersion.update((n) => n + 1);
    }).catch(() => (listening = false));
  }
  let pending = described.get(link);
  if (!pending) {
    pending = describeFeedLink(link);
    described.set(link, pending);
    pending.catch(() => described.delete(link));
  }
  return pending;
}