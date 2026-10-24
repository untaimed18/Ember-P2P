import { invoke } from '@tauri-apps/api/core';

/** One file in a feed. */
export interface FeedItem {
  ed2k: string;
  name: string;
  size: number;
  aich: string;
  blake3: string;
  note: string;
}

/** A feed this identity publishes. */
export interface OwnFeed {
  salt: string;
  title: string;
  description: string;
  /** 0 before the first publish. */
  sequence: number;
  list_ed2k: string;
  list_blake3: string;
  list_size: number;
  item_count: number;
  created_at: number;
  published_at: number;
  /** Details or items edited since the last publish. */
  changed: boolean;
  link: string;
  items: FeedItem[];
}

/** A feed this identity follows. */
export interface FollowedFeed {
  publisher: string;
  salt: string;
  title: string;
  description: string;
  sequence: number;
  item_count: number;
  /** `waiting`: no list yet. `fetching`: a newer one on its way. `broken`:
   *  the list did not match its head. */
  state: 'waiting' | 'ok' | 'fetching' | 'broken';
  list_sequence: number;
  unread: number;
  followed_at: number;
  checked_at: number;
  auto_download: boolean;
  auto_max_item_mib: number;
  auto_max_day_mib: number;
  auto_category: string;
  link: string;
}

export interface FollowedItem extends FeedItem {
  first_seen: number;
  is_new: boolean;
  removed: boolean;
  downloaded: boolean;
}

export const FEEDS_CHANGED_EVENT = 'ember:feeds-changed';

export interface FeedsChangedEvent {
  publisher?: string;
  salt?: string;
  added?: number;
  title?: string;
}

export const listMyFeeds = (): Promise<OwnFeed[]> => invoke('list_my_feeds');
export const createFeed = (title: string, description: string): Promise<OwnFeed> =>
  invoke('create_feed', { title, description });
export const setFeedDetails = (salt: string, title: string, description: string): Promise<void> =>
  invoke('set_feed_details', { salt, title, description });
export const setFeedItems = (salt: string, items: { ed2k: string; note: string }[]): Promise<number> =>
  invoke('set_feed_items', { salt, items });
export const publishFeed = (salt: string): Promise<OwnFeed> => invoke('publish_feed', { salt });
export const deleteFeed = (salt: string): Promise<void> => invoke('delete_feed', { salt });

export const listFollowedFeeds = (): Promise<FollowedFeed[]> => invoke('list_followed_feeds');
export const followFeed = (link: string): Promise<FollowedFeed> => invoke('follow_feed', { link });
export const refreshFeed = (publisher: string, salt: string): Promise<void> =>
  invoke('refresh_feed', { publisher, salt });
export const getFeedItems = (publisher: string, salt: string): Promise<FollowedItem[]> =>
  invoke('get_feed_items', { publisher, salt });
export const markFeedRead = (publisher: string, salt: string): Promise<void> =>
  invoke('mark_feed_read', { publisher, salt });
export const setFeedAutoDownload = (
  publisher: string,
  salt: string,
  enabled: boolean,
  maxItemMib: number,
  maxDayMib: number,
  category: string,
): Promise<void> =>
  invoke('set_feed_auto_download', { publisher, salt, enabled, maxItemMib, maxDayMib, category });
export const downloadFeedItems = (publisher: string, salt: string, ed2ks: string[]): Promise<number> =>
  invoke('download_feed_items', { publisher, salt, ed2ks });
export const unfollowFeed = (publisher: string, salt: string): Promise<void> =>
  invoke('unfollow_feed', { publisher, salt });
