//! Discover: the feeds publishers listed in the public index, found by
//! walking its sixteen shards (see `network::ember::feed`). A listing names a
//! feed by its publisher and salt, as its link does, and carries its head,
//! so a feed can be shown, and followed, without a lookup of its own.

use std::collections::{HashMap, HashSet};

use tauri::Emitter;

use crate::app_state::AppState;
use crate::commands::errors::{coded, coded_ctx};
use crate::commands::feeds::clip;
use crate::network::ember::dht::publish::SignedRecord;
use crate::network::ember::feed::{
    all_feed_index_keys, feed_index_shard, FeedLink, FEEDS_PER_IDENTITY, FEED_DESCRIPTION_MAX,
    FEED_LISTING_ACTIVE_SECS, FEED_LISTING_TTL_SECS, FEED_TITLE_MAX,
};
use crate::storage::database::DiscoveredFeed;

/// Emitted as each shard of a Discover walk lands: `{ walk, feeds, gone }`,
/// the feeds it found or changed and those found withdrawn, as
/// `{ publisher, salt }`.
pub const FEEDS_FOUND_EVENT: &str = "ember:feeds-found";

/// Longest walk token echoed back.
const WALK_MAX: usize = 64;
/// A listing stamped further ahead of this side's clock is not taken: it
/// would read as running for as long as it lived.
const CLOCK_SKEW_SECS: i64 = 10 * 60;

/// A listed feed, for Discover.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiscoveredFeedInfo {
    #[serde(flatten)]
    pub feed: DiscoveredFeed,
    pub link: String,
    /// Its publisher signed the listing lately, so is running.
    pub active: bool,
    pub following: bool,
    /// One of this identity's own feeds.
    pub own: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
struct FeedId {
    publisher: String,
    salt: String,
}

/// A feed found withdrawn, as of its withdrawal: a listing signed later
/// stands.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct Gone {
    publisher: String,
    salt: String,
    listed_at: i64,
}

#[derive(Clone, serde::Serialize)]
struct FoundBatch<'a> {
    /// Echoed from the caller, so shards of an earlier walk still landing
    /// are told from this one's.
    walk: &'a str,
    feeds: &'a [DiscoveredFeedInfo],
    gone: &'a [Gone],
}

/// One listing as the index holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listing {
    feed: DiscoveredFeed,
    withdrawn: bool,
    /// Settles two listings of a feed stamped the same second, as storers do.
    signature: [u8; 64],
}

impl Listing {
    fn outranks(&self, other: &Listing) -> bool {
        (self.feed.listed_at, self.signature) > (other.feed.listed_at, other.signature)
    }
}

/// The feed listings among one shard's blobs: signed, filed where their
/// publisher and salt say, and stamped within a listing's life of `now`.
/// Titles and descriptions are cleaned for display.
fn listings_from_blobs(blobs: Vec<Vec<u8>>, now: i64) -> Vec<Listing> {
    let mut out = Vec::new();
    for blob in blobs {
        let Some(record) = SignedRecord::from_value_blob(&blob) else {
            continue;
        };
        if !record.feed_listing_store_ok()
            || record.timestamp > now + CLOCK_SKEW_SECS
            || record.timestamp < now - FEED_LISTING_TTL_SECS
        {
            continue;
        }
        let Some((salt, head, withdrawn)) = record.feed_listing() else {
            continue;
        };
        let title = clip(&crate::security::sanitize_remote_text(&head.title, 1024), FEED_TITLE_MAX);
        if title.is_empty() {
            continue;
        }
        let description = clip(&crate::security::sanitize_remote_text(&head.description, 4096), FEED_DESCRIPTION_MAX);
        // A head is published before its listing is signed, so a sequence
        // past the listing's own time is made up, and would sort first.
        let signed_ms = record.timestamp.saturating_add(1).saturating_mul(1000);
        out.push(Listing {
            feed: DiscoveredFeed {
                publisher: hex::encode(record.publisher_key),
                salt: hex::encode(salt),
                title,
                description,
                item_count: i64::from(head.item_count),
                list_size: head.list_size.min(i64::MAX as u64) as i64,
                total_size: head.total_size.min(i64::MAX as u64) as i64,
                sequence: head.sequence.min(i64::MAX as u64).min(signed_ms.max(0) as u64) as i64,
                listed_at: record.timestamp,
                first_seen: 0,
            },
            withdrawn,
            signature: record.signature,
        });
    }
    out
}

/// The listings a walk has heard, newest of each feed, with at most
/// [`FEEDS_PER_IDENTITY`] feeds listed a publisher: one identity may keep no
/// more, so a publisher filing more is flooding the index. Withdrawals are
/// not counted: a publisher that deleted feeds may list new ones.
#[derive(Default)]
struct Heard {
    newest: HashMap<FeedId, Listing>,
    listed_per_publisher: HashMap<String, usize>,
}

impl Heard {
    /// Fold in `listing`. Whether it changed what is heard.
    fn take(&mut self, listing: Listing) -> bool {
        let id = FeedId { publisher: listing.feed.publisher.clone(), salt: listing.feed.salt.clone() };
        let was_listed = match self.newest.get(&id) {
            Some(held) if !listing.outranks(held) => return false,
            Some(held) => !held.withdrawn,
            None => false,
        };
        let count = self.listed_per_publisher.entry(id.publisher.clone()).or_default();
        match (was_listed, !listing.withdrawn) {
            (false, true) if *count >= FEEDS_PER_IDENTITY => return false,
            (false, true) => *count += 1,
            (true, false) => *count -= 1,
            _ => {}
        }
        self.newest.insert(id, listing);
        true
    }
}

/// What Discover shows of the feeds' own state on this side.
struct Local {
    own_key: String,
    followed: HashSet<FeedId>,
    hidden: HashSet<FeedId>,
}

impl Local {
    async fn read(state: &AppState) -> Result<Self, String> {
        let db = state.db.clone();
        let (followed, hidden) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            Ok((db.feeds_followed()?, db.feeds_hidden()?))
        })
        .await
        .map_err(|e| coded_ctx("feeds_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("feeds_failed", "Could not read feeds", e))?;
        Ok(Self {
            own_key: hex::encode(state.identity.ed25519_public_key),
            followed: followed.into_iter().map(|f| FeedId { publisher: f.publisher, salt: f.salt }).collect(),
            hidden: hidden.into_iter().map(|(publisher, salt)| FeedId { publisher, salt }).collect(),
        })
    }

    fn hides(&self, feed: &DiscoveredFeed) -> bool {
        self.hidden.contains(&FeedId { publisher: feed.publisher.clone(), salt: feed.salt.clone() })
            || self.hidden.contains(&FeedId { publisher: feed.publisher.clone(), salt: String::new() })
    }

    /// `feed` as Discover shows it; `None` when hidden or not a feed id.
    fn info(&self, feed: DiscoveredFeed, now: i64) -> Option<DiscoveredFeedInfo> {
        if self.hides(&feed) {
            return None;
        }
        let mut link = FeedLink { publisher: [0; 32], salt: [0; 16] };
        hex::decode_to_slice(&feed.publisher, &mut link.publisher).ok()?;
        hex::decode_to_slice(&feed.salt, &mut link.salt).ok()?;
        Some(DiscoveredFeedInfo {
            link: link.format(),
            active: listed_lately(feed.listed_at, now),
            following: self.followed.contains(&FeedId { publisher: feed.publisher.clone(), salt: feed.salt.clone() }),
            own: feed.publisher == self.own_key,
            feed,
        })
    }
}

/// Whether a listing signed `listed_at` says its publisher is running.
fn listed_lately(listed_at: i64, now: i64) -> bool {
    now - listed_at <= FEED_LISTING_ACTIVE_SECS
}

/// Running publishers' feeds first, then the most lately published.
fn sort_for_display(feeds: &mut [DiscoveredFeedInfo]) {
    feeds.sort_by(|a, b| b.active.cmp(&a.active).then(b.feed.sequence.cmp(&a.feed.sequence)));
}

/// The cached feeds this walk did not hear from, split into those it cannot
/// rule out, filed under a shard that did not settle, and those it can, whose
/// shard settled without them: their listings lapsed.
fn sort_cached(
    cached: Vec<DiscoveredFeed>,
    unsettled: &HashSet<u8>,
    heard: &Heard,
) -> (Vec<DiscoveredFeed>, Vec<DiscoveredFeed>) {
    cached
        .into_iter()
        .filter(|feed| !heard.newest.contains_key(&FeedId { publisher: feed.publisher.clone(), salt: feed.salt.clone() }))
        .partition(|feed| {
            let (mut publisher, mut salt) = ([0u8; 32], [0u8; 16]);
            hex::decode_to_slice(&feed.publisher, &mut publisher).is_ok()
                && hex::decode_to_slice(&feed.salt, &mut salt).is_ok()
                && unsettled.contains(&feed_index_shard(&publisher, &salt))
        })
}

/// At most [`FEEDS_PER_IDENTITY`] feeds of each publisher, those listed
/// last: as [`Heard`] keeps them, for feeds gathered across walks.
fn cap_per_publisher(mut feeds: Vec<DiscoveredFeed>) -> Vec<DiscoveredFeed> {
    feeds.sort_by_key(|feed| std::cmp::Reverse(feed.listed_at));
    let mut kept: HashMap<String, usize> = HashMap::new();
    feeds.retain(|feed| {
        let count = kept.entry(feed.publisher.clone()).or_default();
        *count += 1;
        *count <= FEEDS_PER_IDENTITY
    });
    feeds
}

/// Walk the public feed index and return the feeds listed in it. Each shard
/// is emitted on [`FEEDS_FOUND_EVENT`] as it lands; the return value is the
/// whole set, which is cached for the next open.
#[tauri::command]
pub async fn discover_feeds(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    walk: String,
) -> Result<Vec<DiscoveredFeedInfo>, String> {
    use futures::StreamExt;

    let walk: String = walk.chars().take(WALK_MAX).collect();
    crate::commands::channels::require_ember(&state).await?;
    let local = Local::read(&state).await?;
    let now = chrono::Utc::now().timestamp();
    let db = state.db.clone();
    let cached = tokio::task::spawn_blocking(move || db.feeds_discovered(now, FEED_LISTING_TTL_SECS))
        .await
        .map_err(|e| coded_ctx("feeds_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("feeds_failed", "Could not read feeds", e))?;

    let mut walks: futures::stream::FuturesUnordered<_> = all_feed_index_keys()
        .into_iter()
        .zip(0u8..)
        .map(|(key, shard)| crate::commands::channels::walk_index_shard(&state, shard, key))
        .collect();
    let mut heard = Heard::default();
    let mut unsettled = HashSet::new();
    while let Some(shard) = walks.next().await {
        if !shard.settled {
            unsettled.insert(shard.shard);
        }
        let mut changed = Vec::new();
        let mut gone = Vec::new();
        for listing in listings_from_blobs(shard.blobs, now) {
            let id = FeedId { publisher: listing.feed.publisher.clone(), salt: listing.feed.salt.clone() };
            if !heard.take(listing) {
                continue;
            }
            changed.retain(|info: &DiscoveredFeedInfo| info.feed.publisher != id.publisher || info.feed.salt != id.salt);
            gone.retain(|g: &Gone| g.publisher != id.publisher || g.salt != id.salt);
            let listing = &heard.newest[&id];
            if listing.withdrawn {
                gone.push(Gone { publisher: id.publisher, salt: id.salt, listed_at: listing.feed.listed_at });
            } else if let Some(info) = local.info(listing.feed.clone(), now) {
                changed.push(info);
            }
        }
        if !changed.is_empty() || !gone.is_empty() {
            let _ = app.emit(FEEDS_FOUND_EVENT, FoundBatch { walk: &walk, feeds: &changed, gone: &gone });
        }
    }

    let (carried, lapsed) = sort_cached(cached, &unsettled, &heard);
    let (found, withdrawn): (Vec<Listing>, Vec<Listing>) = heard.newest.into_values().partition(|l| !l.withdrawn);
    let found: Vec<DiscoveredFeed> = found.into_iter().map(|l| l.feed).collect();
    // Forgotten as of their withdrawal, or whatever was cached when lapsed.
    let forget: Vec<(String, String, i64)> = withdrawn
        .into_iter()
        .map(|l| (l.feed.publisher, l.feed.salt, l.feed.listed_at))
        .chain(lapsed.into_iter().map(|feed| (feed.publisher, feed.salt, i64::MAX)))
        .collect();
    let db = state.db.clone();
    let task_found = found.clone();
    let first_seen = tokio::task::spawn_blocking(move || db.feeds_discovered_put(&task_found, &forget, now))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();

    let found = found.into_iter().map(|mut feed| {
        feed.first_seen = first_seen.get(&(feed.publisher.clone(), feed.salt.clone())).copied().unwrap_or(now);
        feed
    });
    // Hidden or followed meanwhile, as the page now shows.
    let local = Local::read(&state).await.unwrap_or(local);
    let mut out: Vec<DiscoveredFeedInfo> = cap_per_publisher(found.chain(carried).collect())
        .into_iter()
        .filter_map(|feed| local.info(feed, now))
        .collect();
    sort_for_display(&mut out);
    Ok(out)
}

/// The feeds the last Discover walk found, from the local cache, for the
/// page to show while a walk runs.
#[tauri::command]
pub async fn cached_discovered_feeds(state: tauri::State<'_, AppState>) -> Result<Vec<DiscoveredFeedInfo>, String> {
    let local = Local::read(&state).await?;
    let now = chrono::Utc::now().timestamp();
    let db = state.db.clone();
    let cached = tokio::task::spawn_blocking(move || db.feeds_discovered(now, FEED_LISTING_TTL_SECS))
        .await
        .map_err(|e| coded_ctx("feeds_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("feeds_failed", "Could not read feeds", e))?;
    let mut out: Vec<DiscoveredFeedInfo> =
        cap_per_publisher(cached).into_iter().filter_map(|feed| local.info(feed, now)).collect();
    sort_for_display(&mut out);
    Ok(out)
}

/// Hide a feed from Discover, or with no `salt` every feed of its publisher;
/// with `hidden` false, show it again.
#[tauri::command]
pub async fn set_discovered_feed_hidden(
    state: tauri::State<'_, AppState>,
    publisher: String,
    salt: Option<String>,
    hidden: bool,
) -> Result<(), String> {
    let not_found = || coded("feeds_not_found", "That feed could not be found");
    let mut publisher_bytes = [0u8; 32];
    hex::decode_to_slice(publisher.trim(), &mut publisher_bytes).map_err(|_| not_found())?;
    let salt = match salt {
        Some(salt) => {
            let mut salt_bytes = [0u8; 16];
            hex::decode_to_slice(salt.trim(), &mut salt_bytes).map_err(|_| not_found())?;
            hex::encode(salt_bytes)
        }
        None => String::new(),
    };
    let publisher = hex::encode(publisher_bytes);
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || db.feed_set_hidden(&publisher, &salt, hidden))
        .await
        .map_err(|e| coded_ctx("feeds_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("feeds_failed", "Could not save the feed", e))
}

/// How many feeds and publishers are hidden from Discover.
#[tauri::command]
pub async fn hidden_discovered_feed_count(state: tauri::State<'_, AppState>) -> Result<usize, String> {
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || db.feeds_hidden().map(|hidden| hidden.len()))
        .await
        .map_err(|e| coded_ctx("feeds_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("feeds_failed", "Could not read feeds", e))
}

/// Show every hidden feed and publisher in Discover again.
#[tauri::command]
pub async fn clear_hidden_discovered_feeds(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || db.feeds_hidden_clear())
        .await
        .map_err(|e| coded_ctx("feeds_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("feeds_failed", "Could not save the feed", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::ember::feed::FeedHead;

    fn head(title: &str, sequence: u64) -> FeedHead {
        FeedHead {
            sequence,
            list_ed2k_hash: [7u8; 16],
            list_size: 1234,
            list_blake3: [8u8; 32],
            item_count: 3,
            total_size: 3_000,
            title: title.into(),
            description: "About".into(),
            deleted: false,
        }
    }

    fn blob(key: u8, salt: u8, head: &FeedHead, withdrawn: bool, at: i64) -> Vec<u8> {
        let identity = crate::network::ember::crypto::signing_key_from_bytes(&[key; 32]);
        let record = SignedRecord::feed_listing_record(&[salt; 16], head, withdrawn, &identity, at).unwrap();
        [record.data, record.signature.to_vec()].concat()
    }

    const NOW: i64 = 1_900_000_000;

    #[test]
    fn listings_are_read_cleaned_and_dated() {
        let listings = listings_from_blobs(
            vec![
                blob(1, 1, &head("Mixes\u{202e}", 5), false, NOW - 10),
                blob(1, 2, &head("Old", 5), false, NOW - FEED_LISTING_TTL_SECS - 1),
                blob(1, 3, &head("Ahead", 5), false, NOW + CLOCK_SKEW_SECS + 1),
                blob(1, 4, &head("Gone", 5), true, NOW - 10),
                vec![0u8; 200],
            ],
            NOW,
        );
        assert_eq!(listings.len(), 2, "the stale, the future-dated and the junk are dropped");
        assert_eq!(listings[0].feed.title, "Mixes", "bidi controls are cleaned out");
        assert_eq!(listings[0].feed.salt, hex::encode([1u8; 16]));
        assert_eq!(listings[0].feed.listed_at, NOW - 10);
        assert!(!listings[0].withdrawn);
        assert!(listings[1].withdrawn);
    }

    #[test]
    fn a_tampered_listing_is_dropped() {
        let mut tampered = blob(1, 1, &head("Mixes", 5), false, NOW);
        tampered[120] ^= 1;
        assert!(listings_from_blobs(vec![tampered], NOW).is_empty());
    }

    #[test]
    fn the_newest_listing_of_a_feed_wins_and_a_publisher_is_capped() {
        let mut heard = Heard::default();
        let take = |heard: &mut Heard, salt: u8, at: i64, withdrawn: bool| {
            let listing = listings_from_blobs(vec![blob(1, salt, &head("T", 5), withdrawn, at)], NOW).remove(0);
            heard.take(listing)
        };
        assert!(take(&mut heard, 1, NOW - 20, false));
        assert!(!take(&mut heard, 1, NOW - 30, true), "an older withdrawal does not undo a newer listing");
        assert!(take(&mut heard, 1, NOW - 10, true), "a newer withdrawal does");
        let id = FeedId { publisher: hex::encode(crate::network::ember::crypto::signing_key_from_bytes(&[1; 32]).verifying_key().to_bytes()), salt: hex::encode([1u8; 16]) };
        assert!(heard.newest[&id].withdrawn);

        for salt in 2..(FEEDS_PER_IDENTITY as u8 + 2) {
            assert!(take(&mut heard, salt, NOW, false), "a withdrawn feed does not count");
        }
        assert!(!take(&mut heard, 100, NOW, false), "past the feeds one identity keeps");
        assert!(take(&mut heard, 2, NOW + 1, false), "a feed already heard is still updated");
        assert!(take(&mut heard, 3, NOW + 1, true));
        assert!(take(&mut heard, 100, NOW, false), "room again once one is withdrawn");
    }

    #[test]
    fn hidden_feeds_and_publishers_are_left_out() {
        let listing = listings_from_blobs(vec![blob(1, 1, &head("T", 5), false, NOW)], NOW).remove(0);
        let publisher = listing.feed.publisher.clone();
        let mut local = Local { own_key: String::new(), followed: HashSet::new(), hidden: HashSet::new() };
        let info = local.info(listing.feed.clone(), NOW).unwrap();
        assert!(info.active && !info.following && !info.own);
        assert_eq!(FeedLink::parse(&info.link).map(|link| hex::encode(link.salt)), Some(listing.feed.salt.clone()));
        assert!(!local.info(listing.feed.clone(), NOW + FEED_LISTING_ACTIVE_SECS + 1).unwrap().active);

        local.hidden.insert(FeedId { publisher: publisher.clone(), salt: String::new() });
        assert!(local.info(listing.feed.clone(), NOW).is_none(), "the publisher is hidden");
        local.hidden.clear();
        local.hidden.insert(FeedId { publisher, salt: listing.feed.salt.clone() });
        assert!(local.info(listing.feed, NOW).is_none(), "the feed is hidden");
    }

    #[test]
    fn unsettled_shards_carry_cached_feeds_forward_and_settled_ones_drop_them() {
        let feeds: Vec<DiscoveredFeed> = (1..=40u8)
            .map(|salt| listings_from_blobs(vec![blob(1, salt, &head("T", 5), false, NOW)], NOW).remove(0).feed)
            .collect();
        let shard_of = |feed: &DiscoveredFeed| {
            let (mut publisher, mut salt) = ([0u8; 32], [0u8; 16]);
            hex::decode_to_slice(&feed.publisher, &mut publisher).unwrap();
            hex::decode_to_slice(&feed.salt, &mut salt).unwrap();
            feed_index_shard(&publisher, &salt)
        };
        let unsettled: HashSet<u8> = [shard_of(&feeds[0])].into();
        let mut heard = Heard::default();
        heard.newest.insert(
            FeedId { publisher: feeds[0].publisher.clone(), salt: feeds[0].salt.clone() },
            Listing { feed: feeds[0].clone(), withdrawn: true, signature: [0; 64] },
        );
        let (carried, lapsed) = sort_cached(feeds.clone(), &unsettled, &heard);
        assert!(carried.iter().all(|feed| shard_of(feed) == shard_of(&feeds[0])));
        assert!(lapsed.iter().all(|feed| shard_of(feed) != shard_of(&feeds[0])));
        assert!(!carried.contains(&feeds[0]) && !lapsed.contains(&feeds[0]), "heard from, so neither");
        assert_eq!(carried.len() + lapsed.len(), feeds.len() - 1);
    }

    #[test]
    fn a_sequence_past_the_listing_is_not_believed() {
        let listing = listings_from_blobs(vec![blob(1, 1, &head("T", u64::MAX), false, NOW)], NOW).remove(0);
        assert_eq!(listing.feed.sequence, (NOW + 1) * 1000);
        let listing = listings_from_blobs(vec![blob(1, 1, &head("T", 5), false, NOW)], NOW).remove(0);
        assert_eq!(listing.feed.sequence, 5);
    }

    #[test]
    fn listings_stamped_the_same_second_settle_on_the_signature() {
        let a = listings_from_blobs(vec![blob(1, 1, &head("A", 5), false, NOW)], NOW).remove(0);
        let b = listings_from_blobs(vec![blob(1, 1, &head("B", 5), true, NOW)], NOW).remove(0);
        let (winner, loser) = if a.signature > b.signature { (a, b) } else { (b, a) };
        for order in [[loser.clone(), winner.clone()], [winner.clone(), loser.clone()]] {
            let mut heard = Heard::default();
            for listing in order {
                heard.take(listing);
            }
            assert_eq!(heard.newest.values().next(), Some(&winner), "whichever was heard first");
        }
    }

    fn shard_of(feed: &DiscoveredFeed) -> u8 {
        let (mut publisher, mut salt) = ([0u8; 32], [0u8; 16]);
        hex::decode_to_slice(&feed.publisher, &mut publisher).unwrap();
        hex::decode_to_slice(&feed.salt, &mut salt).unwrap();
        feed_index_shard(&publisher, &salt)
    }

    fn cached(publisher: u8, salt: u8, sequence: i64, listed_at: i64) -> DiscoveredFeed {
        DiscoveredFeed {
            publisher: hex::encode([publisher; 32]),
            salt: hex::encode([salt; 16]),
            title: "T".into(),
            description: String::new(),
            item_count: 1,
            list_size: 10,
            total_size: 100,
            sequence,
            listed_at,
            first_seen: 0,
        }
    }

    /// A shard that comes back with as many records as a lookup returns may
    /// hold more, so its cached feeds are carried forward, as a shard too
    /// few nodes answered; one that settled without a cached feed drops it.
    #[test]
    fn a_shard_that_comes_back_full_carries_its_cached_feeds() {
        use crate::commands::channel_recovery::MIN_RESPONDERS_FOR_ABSENCE as ENOUGH;
        use crate::commands::channels::shard_settled;
        use crate::network::ember::dht::search::MAX_SEARCH_RESULTS as FULL;
        assert!(shard_settled(ENOUGH, FULL - 1));
        assert!(!shard_settled(ENOUGH, FULL), "it may hold more than a lookup returns");
        assert!(!shard_settled(ENOUGH - 1, 0), "too few answered to say it is empty");

        let feeds: Vec<DiscoveredFeed> = (1..=60u8).map(|salt| cached(1, salt, 5, NOW)).collect();
        let full = shard_of(&feeds[0]);
        let unsettled: HashSet<u8> = (0..crate::network::ember::feed::FEED_INDEX_SHARDS)
            .filter(|shard| !shard_settled(ENOUGH, if *shard == full { FULL } else { 0 }))
            .collect();
        assert_eq!(unsettled, HashSet::from([full]));
        let (carried, lapsed) = sort_cached(feeds.clone(), &unsettled, &Heard::default());
        assert!(carried.contains(&feeds[0]));
        assert!(carried.iter().all(|feed| shard_of(feed) == full), "only the full shard's");
        assert!(lapsed.iter().all(|feed| shard_of(feed) != full), "the settled shards' lapsed");
        assert_eq!(carried.len() + lapsed.len(), feeds.len());
    }

    /// What a walk heard and what the cache carries forward come to one
    /// list: a feed heard is taken as heard, withdrawn or not, each publisher
    /// keeps its last listed eight, and running publishers' feeds come
    /// first, then the most lately published.
    #[test]
    fn a_walk_and_the_cache_merge_capped_and_in_display_order() {
        let listing = |feed: DiscoveredFeed, withdrawn: bool| Listing { feed, withdrawn, signature: [0; 64] };
        let mut heard = Heard::default();
        assert!(heard.take(listing(cached(1, 1, 50, NOW), false)));
        assert!(heard.take(listing(cached(1, 2, 10, NOW - 60), false)));
        assert!(heard.take(listing(cached(1, 4, 60, NOW - 30), true)));
        let stale = NOW - FEED_LISTING_ACTIVE_SECS - 60;
        let mut cache = vec![cached(1, 4, 40, stale), cached(1, 3, 99, stale), cached(1, 1, 45, stale)];
        cache.extend((1..=10u8).map(|salt| cached(2, salt, 100 + i64::from(salt), stale - i64::from(salt))));
        let every_shard: HashSet<u8> = (0..crate::network::ember::feed::FEED_INDEX_SHARDS).collect();

        let (carried, lapsed) = sort_cached(cache, &every_shard, &heard);
        assert!(lapsed.is_empty(), "no shard settled");
        assert!(!carried.iter().any(|feed| feed.publisher == hex::encode([1u8; 32]) && feed.salt != hex::encode([3u8; 16])), "heard, so not carried");
        let found = heard.newest.into_values().filter(|l| !l.withdrawn).map(|l| l.feed);
        let local = Local { own_key: String::new(), followed: HashSet::new(), hidden: HashSet::new() };
        let mut out: Vec<DiscoveredFeedInfo> =
            cap_per_publisher(found.chain(carried).collect()).into_iter().filter_map(|feed| local.info(feed, NOW)).collect();
        sort_for_display(&mut out);
        let order: Vec<(String, String)> = out.iter().map(|info| (info.feed.publisher[..2].to_string(), info.feed.salt[..2].to_string())).collect();
        let id = |publisher: u8, salt: u8| (hex::encode([publisher]), hex::encode([salt]));
        let mut want = vec![id(1, 1), id(1, 2)];
        want.extend((1..=8u8).rev().map(|salt| id(2, salt)));
        want.push(id(1, 3));
        assert_eq!(order, want, "active first, then by sequence; the publisher's two staler listings dropped");
        assert!(out[0].active && !out[2].active);
        let json = serde_json::to_value(&out[0]).unwrap();
        assert_eq!(json["total_size"], 100, "the frontend's field");
    }

    #[test]
    fn cached_feeds_keep_a_publishers_last_listed() {
        let feeds: Vec<DiscoveredFeed> = (0..(FEEDS_PER_IDENTITY as u8 + 3))
            .map(|salt| listings_from_blobs(vec![blob(1, salt, &head("T", 5), false, NOW - i64::from(salt))], NOW).remove(0).feed)
            .chain(listings_from_blobs(vec![blob(2, 1, &head("T", 5), false, NOW - 100)], NOW).into_iter().map(|l| l.feed))
            .collect();
        let kept = cap_per_publisher(feeds.clone());
        assert_eq!(kept.len(), FEEDS_PER_IDENTITY + 1);
        assert!(kept.contains(&feeds[0]) && !kept.contains(&feeds[FEEDS_PER_IDENTITY]), "the last listed");
        assert!(kept.contains(feeds.last().unwrap()), "another publisher's own");
    }
}
