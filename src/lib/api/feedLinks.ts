import { invoke } from '@tauri-apps/api/core';

/** What this device already knows of the feed a link names. Kept apart from
 *  `feeds.ts` so the popped-out chat, which may not follow feeds itself, can
 *  draw a card for one. */
export interface FeedLinkInfo {
  /** The link as Ember writes it. */
  link: string;
  publisher: string;
  salt: string;
  /** Empty when this device has not seen the feed. */
  title: string;
  description: string;
  item_count: number;
  following: boolean;
  own: boolean;
}

export const describeFeedLink = (link: string): Promise<FeedLinkInfo> => invoke('describe_feed_link', { link });
