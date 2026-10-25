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
  /** This identity's key: with the salt, what followers know the feed by. */
  publisher: string;
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
  /** When auto-download was last turned on; it takes files first seen since. */
  auto_since: number;
  /** When a head of the feed was last found on the network, newer or not;
   *  0 before the first. */
  seen_at: number;
  /** The folder in Feeds its files finish in; empty before the first. */
  folder: string;
  link: string;
  /** What its lookups and fetches are doing now. */
  activity: FeedActivity;
  /** Set by a follow of a feed already followed. */
  already_following: boolean;
}

export interface FeedActivity {
  looking: boolean;
  /** Its last lookup reached no node. */
  unreachable: boolean;
  /** Its newest head names a list larger than Ember takes. */
  too_large: boolean;
  /** A fetch of its list running: seconds, bytes so far, sources. */
  fetching: { secs: number; bytes: number; sources: number } | null;
  /** When the next fetch may start after one gave up, in seconds; 0 if none did. */
  retry_at: number;
}

/** What a lookup of a followed feed came to. */
export type LookupOutcome = 'updated' | 'unchanged' | 'not_found' | 'unreachable' | 'too_large' | 'busy';

/** What the download of a feed's file is doing. */
export type FeedItemStatus =
  | 'none'
  | 'queued'
  | 'downloading'
  | 'paused'
  | 'failed'
  | 'done'
  | 'in_library'
  | 'missing'
  | 'cancelled'
  /** Not in this feed's folder, but in another followed feed's. */
  | 'elsewhere';

export interface FollowedItem extends FeedItem {
  first_seen: number;
  is_new: boolean;
  removed: boolean;
  /** Downloaded or started from the feed at some point. */
  downloaded: boolean;
  /** A type that can run code or change settings: asked about before it is
   *  downloaded, and never downloaded automatically. */
  risky: boolean;
  status: FeedItemStatus;
  /** 0 to 100, for one on its way. */
  progress: number;
  /** Why auto-download has not started it. */
  held: 'risky' | 'too_large' | 'day_limit' | 'disk' | null;
  /** Its download, while it is in the transfer list. */
  transfer: FeedItemTransfer | null;
  /** For one held in another followed feed's folder: that feed's title. */
  elsewhere: string | null;
}

/** The download of a feed's file, for the controls the Feeds page gives it. */
export interface FeedItemTransfer {
  id: string;
  /** Bytes per second. */
  speed: number;
  sources: number;
  active_sources: number;
  /** Bytes of the file held so far. */
  done: number;
  /** Still asked of the publisher alone, before the rest of the network. */
  from_publisher: boolean;
  /** The user's own download, started outside the feed: on the Transfers
   *  page, and controlled there. */
  in_transfers: boolean;
  /** Another followed feed's download of the same file, controlled there. */
  other_feed: boolean;
  /** Why it failed, for one that did. */
  failure_reason: string | null;
  failure_code: string | null;
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
  /** Its publisher signed the listing in the last few hours: running. */
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
/** Look again now, and fetch its list now if owed one. */
export const refreshFeed = (publisher: string, salt: string): Promise<LookupOutcome> =>
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
/** Cancel the feed's download of a file: what has arrived is deleted. */
export const cancelFeedDownload = (publisher: string, salt: string, ed2k: string): Promise<void> =>
  invoke('cancel_feed_download', { publisher, salt, ed2k });
export const unfollowFeed = (publisher: string, salt: string): Promise<void> =>
  invoke('unfollow_feed', { publisher, salt });
/** Open the folder in Feeds a followed feed's files finish in. */
export const openFeedFolder = (publisher: string, salt: string): Promise<void> =>
  invoke('open_feed_folder', { publisher, salt });
/** Open `Feeds`, where every followed feed's folder is. It is not shared,
 *  unlike `Downloads`. */
export const openFeedFilesFolder = (): Promise<void> => invoke('open_feed_files_folder');

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
