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
  /** Listed in the public index, for anyone to find in Discover, as well as
   *  by its link. */
  listed: boolean;
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
  /** The folder in Feeds its files finish in; empty before the first. */
  folder: string;
  link: string;
}

export interface FollowedItem extends FeedItem {
  first_seen: number;
  is_new: boolean;
  removed: boolean;
  downloaded: boolean;
  /** A type that can run code or change settings: asked about before it is
   *  downloaded, and never downloaded automatically. */
  risky: boolean;
}

/** A feed listed in the public index. */
export interface DiscoveredFeed {
  publisher: string;
  salt: string;
  title: string;
  description: string;
  item_count: number;
  list_size: number;
  /** The publisher's clock, in milliseconds, at its last publish. */
  sequence: number;
  /** When the publisher last signed its listing, in seconds. */
  listed_at: number;
  first_seen: number;
  link: string;
  /** Its publisher signed the listing in the last day or so: running. */
  active: boolean;
  following: boolean;
  own: boolean;
}

export const FEEDS_CHANGED_EVENT = 'ember:feeds-changed';
export const FEEDS_FOUND_EVENT = 'ember:feeds-found';

export interface FeedsChangedEvent {
  publisher?: string;
  salt?: string;
  added?: number;
  title?: string;
}

/** One shard of a Discover walk: feeds it found or changed, and those it
 *  found withdrawn, as of `listed_at`: a listing signed later stands. */
export interface FeedsFoundEvent {
  walk: string;
  feeds: DiscoveredFeed[];
  gone: { publisher: string; salt: string; listed_at: number }[];
}

export const listMyFeeds = (): Promise<OwnFeed[]> => invoke('list_my_feeds');
export const createFeed = (title: string, description: string, listed: boolean): Promise<OwnFeed> =>
  invoke('create_feed', { title, description, listed });
/** The title and description as saved: cleaned and cut to length. */
export const setFeedDetails = (
  salt: string,
  title: string,
  description: string,
): Promise<{ title: string; description: string }> => invoke('set_feed_details', { salt, title, description });
export const setFeedListed = (salt: string, listed: boolean): Promise<OwnFeed> =>
  invoke('set_feed_listed', { salt, listed });
/** `items`: the files saved, in order, as saved. `dropped`: the names of
 *  files left out because they are no longer shared with everyone. */
export const setFeedItems = (
  salt: string,
  items: { ed2k: string; note: string }[],
): Promise<{ items: FeedItem[]; dropped: string[] }> => invoke('set_feed_items', { salt, items });
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
/** Open the folder in Feeds a followed feed's files finish in. */
export const openFeedFolder = (publisher: string, salt: string): Promise<void> =>
  invoke('open_feed_folder', { publisher, salt });

/** Walk the public feed index. Shards arrive on {@link FEEDS_FOUND_EVENT}
 *  tagged `walk` as they land; the result is the whole set. */
export const discoverFeeds = (walk: string): Promise<DiscoveredFeed[]> => invoke('discover_feeds', { walk });
/** What the last walk found, without the network. */
export const cachedDiscoveredFeeds = (): Promise<DiscoveredFeed[]> => invoke('cached_discovered_feeds');
/** Hide a feed from Discover, or with no `salt` all of its publisher's. */
export const setDiscoveredFeedHidden = (publisher: string, salt: string | null, hidden: boolean): Promise<void> =>
  invoke('set_discovered_feed_hidden', { publisher, salt, hidden });
export const hiddenDiscoveredFeedCount = (): Promise<number> => invoke('hidden_discovered_feed_count');
export const clearHiddenDiscoveredFeeds = (): Promise<void> => invoke('clear_hidden_discovered_feeds');
