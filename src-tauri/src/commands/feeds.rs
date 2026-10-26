//! Feeds: publishing this identity's, following others', and keeping both
//! current. See `network::ember::feed` for the head and `sharing::feed_files`
//! for how a list is served and fetched without being the user's file.
//!
//! Publishing writes the list into the feeds folder, serves it hidden, and
//! signs and publishes the head; heads are republished hourly. Following looks
//! the head up every half hour, fetches a newer list through the download
//! pipeline (pinned to the head's BLAKE3), checks it against the head, works
//! out what is new, and starts what auto-download allows.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tauri::{Emitter, Manager};

use crate::app_state::AppState;
use crate::commands::errors::{bounded_send, coded, coded_ctx};
use crate::network::ed2k::collection::{Collection, CollectionFile};
use crate::network::ember::dht::publish::SignedRecord;
use crate::network::ember::feed::{
    feed_index_key, feed_index_shard, feed_key, generate_feed_salt, next_sequence, withdrawal_head, FeedHead, FeedLink,
    FeedSalt, FEEDS_PER_IDENTITY, FEED_DESCRIPTION_MAX, FEED_ITEMS_MAX, FEED_LISTING_TTL_SECS, FEED_NOTE_MAX,
    FEED_TITLE_MAX,
};
use crate::network::{EmberPublishResult, NetworkCommand};
use crate::sharing::feed_files::{self, FetchOutcome, HiddenShare};
use crate::sharing::manager::TransferControl;
use crate::storage::database::{DueListing, FeedItem, FollowedFeed, FollowedItem, OwnFeed, OwnPublish};
use crate::storage::part_folders::DownloadFolders;
use crate::types::{Transfer, TransferDirection, TransferStatus};

/// Emitted when a feed, published or followed, changed: `{ salt }` for one
/// of ours, `{ publisher, salt }` for one followed, and with `added` (the
/// number of new items a list brought) and `title` when a list was taken
/// up.
pub const FEEDS_CHANGED_EVENT: &str = "ember:feeds-changed";

/// How often a followed feed's head is looked up.
const POLL_SECS: i64 = 30 * 60;
/// Spread over this much more, by feed, so a hundred feeds do not all look
/// at once.
const POLL_JITTER_SECS: i64 = 5 * 60;
/// How long a lookup may take.
const LOOKUP_TIMEOUT_MS: u64 = 20_000;
/// Lookups per tick of the service's one-minute timer.
const LOOKUPS_PER_TICK: usize = 3;
/// How soon a lookup that reached no node is tried again.
const LOOKUP_RETRY_SECS: i64 = 5 * 60;
/// How often a feed whose head has never been found is looked up, for
/// [`WAITING_FAST_FOR_SECS`] after it was followed: the user is waiting on
/// it, and its publisher may be about to republish.
const WAITING_POLL_SECS: i64 = 3 * 60;
const WAITING_FAST_FOR_SECS: i64 = 24 * 3600;
/// How long after a feed's own key gave nothing its index shard is read for
/// a listing of it, which carries the same head: a shard is many records.
const LISTING_FALLBACK_SECS: i64 = 15 * 60;
/// How often the publisher republishes a head nothing has changed, and its
/// listing with it. Most storers are builds that keep a head they cannot
/// read for a day and never hand it on when they leave, so a day between
/// republishes let a head vanish as its storers came and went.
const REPUBLISH_SECS: i64 = 60 * 60;
/// How often a deleted feed's withdrawal is sent again.
const WITHDRAWAL_RESEND_SECS: i64 = 24 * 3600;
/// How soon a republish that reached no node is tried again.
const REPUBLISH_RETRY_SECS: i64 = 10 * 60;
/// Pushed heads taken for one feed: one per this long. The newest of those
/// pushed meanwhile waits for the next.
const PUSHED_HEAD_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// How long a list fetch may go with no byte arriving and no source, queued
/// at one included, before it is given up and tried again later.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// The longest a list fetch runs in all, sources or not.
const FETCH_MAX: Duration = Duration::from_secs(6 * 3600);
/// How long after a fetch gave up the next one starts.
const FETCH_RETRY_SECS: i64 = 30 * 60;
/// The largest list followed, in bytes. 2,000 items fit in far less.
const MAX_LIST_BYTES: u64 = 2 * 1024 * 1024;
/// Free space auto-download leaves on the download folder's drive.
const AUTO_DOWNLOAD_HEADROOM: u64 = 64 * 1024 * 1024;

fn publish_unreachable() -> String {
    coded("feeds_publish_unreachable", "Could not reach the Ember network to publish the feed. Try again in a minute.")
}

fn hex_salt(salt: &str) -> Result<FeedSalt, String> {
    let mut out = [0u8; 16];
    hex::decode_to_slice(salt.trim(), &mut out).map_err(|_| coded("feeds_not_found", "That feed could not be found"))?;
    Ok(out)
}

fn hex_publisher(publisher: &str) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(publisher.trim(), &mut out)
        .map_err(|_| coded("feeds_not_found", "That feed could not be found"))?;
    Ok(out)
}

fn feeds_dir(app: &tauri::AppHandle) -> PathBuf {
    feed_files::feeds_dir(&crate::storage::paths::resolve_data_dir_with_app(app))
}

/// Under the first of `feed_files::list_dirs`, which are approved roots.
fn own_list_path(dir: &Path, salt: &str, sequence: i64) -> PathBuf {
    dir.join("own").join(format!("{salt}-{sequence}.emulecollection"))
}

/// Under the second of `feed_files::list_dirs`.
fn followed_list_path(dir: &Path, publisher: &str, salt: &str, sequence: i64) -> PathBuf {
    dir.join("followed").join(format!("{publisher}-{salt}-{sequence}.emulecollection"))
}

/// The name a list is served under: the same for every feed, as a list's
/// title is sealed in it.
fn list_share_name() -> String {
    "ember-feed-list".to_string()
}

/// Who holds a hidden share: one of our feeds, or one we follow.
fn own_owner(salt: &str) -> String {
    format!("own:{salt}")
}

fn followed_owner(publisher: &str, salt: &str) -> String {
    format!("follow:{publisher}:{salt}")
}

/// `owner` no longer serves `hash`. The hash, for [`withdraw_lists`], when
/// nothing serves it now.
fn release_list(hash: &[u8; 16], owner: &str) -> Option<[u8; 16]> {
    feed_files::unshare_hidden(hash, owner).then_some(*hash)
}

/// Withdraw the source records of lists no feed serves any more, rather than
/// leave them to lapse. Not for a hash the user shares or downloads as a
/// file of their own, nor one shared again meanwhile.
async fn withdraw_lists(state: &AppState, hashes: impl IntoIterator<Item = [u8; 16]>) {
    let mut gone = Vec::new();
    for hash in hashes {
        let hex = hex::encode(hash);
        if feed_files::hidden_share(&hash).is_some()
            || state.local_index.read().await.get_by_hash(&hex).is_some()
            || state.transfer_manager.read().await.has_pending_for_hash(&hex)
        {
            continue;
        }
        gone.push(hex);
    }
    if !gone.is_empty() {
        let (tx, _) = tokio::sync::oneshot::channel();
        let _ = state.network_tx.try_send(NetworkCommand::UnpublishEmberFiles { file_hashes: gone, tx });
    }
}

/// Held while a feed of ours is published or deleted, and while a republish
/// reads, settles or records a head, so two can never record their
/// sequences out of order. A Publish holds it across its network wait, so
/// publishes keep their order; a republish does not.
fn publish_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    &LOCK
}

/// Held while a feed's details or items are saved, and while a Publish
/// reads them and drops those no longer shared. Never across a network
/// wait, so a Save does not wait for a Publish to reach the network; what
/// is saved while a head is out stays marked changed (see
/// `Database::feed_own_published`).
fn edit_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    &LOCK
}

/// Delete a followed feed's list files: all of them, or with `keep` those of
/// earlier sequences and other copies of its own. A newer one, still being
/// taken up, stays.
fn remove_followed_files(dir: &Path, publisher: &str, salt: &str, keep: Option<(i64, &Path)>) {
    let prefix = format!("{publisher}-{salt}-");
    let Ok(entries) = std::fs::read_dir(dir.join("followed")) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let Some(rest) = name.to_str().and_then(|name| name.strip_prefix(&prefix)) else {
            continue;
        };
        let sequence: Option<i64> = rest
            .find(|c: char| !c.is_ascii_digit())
            .map_or(Some(rest), |end| rest.get(..end))
            .and_then(|digits| digits.parse().ok());
        let goes = match keep {
            None => true,
            Some((kept, kept_path)) => match sequence {
                Some(sequence) if sequence > kept => false,
                Some(sequence) if sequence == kept => path != kept_path,
                _ => true,
            },
        };
        if goes {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn link_for(publisher: &[u8; 32], salt: &FeedSalt) -> String {
    FeedLink { publisher: *publisher, salt: *salt }.format()
}

/// `text` cut to at most `max` bytes, at a character boundary.
pub(crate) fn clip(text: &str, max: usize) -> String {
    let text = text.trim();
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn blocking<T: Send + 'static>(
    task: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
    code: &'static str,
    message: &'static str,
) -> Result<T, String> {
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|e| coded_ctx("feeds_task_error", "Task error", e))?
        .map_err(|e| coded_ctx(code, message, e))
}

// ── Publishing ─────────────────────────────────────────────────────────────

/// A feed of ours, with its link and items, for the editor.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OwnFeedInfo {
    #[serde(flatten)]
    pub feed: OwnFeed,
    /// This identity's key, lowercase hex: what followers know the feed by.
    pub publisher: String,
    pub link: String,
    pub items: Vec<FeedItem>,
    /// Its followers, once counted (see [`count_followers`]).
    pub followers: Option<FollowerCount>,
    /// Followers who downloaded each file from us, by lowercase eD2K hash.
    pub downloads: HashMap<String, u32>,
}

async fn own_feed_info(state: &AppState, feed: OwnFeed) -> Result<OwnFeedInfo, String> {
    let salt = hex_salt(&feed.salt)?;
    let db = state.db.clone();
    let key = feed.salt.clone();
    let (items, downloads) = blocking(
        move || Ok((db.feed_own_items(&key)?, db.feed_own_download_counts(&key)?)),
        "feeds_failed",
        "Could not read feeds",
    )
    .await?;
    let followers = follower_counts().lock().get(&feed.salt).and_then(|held| held.count);
    Ok(OwnFeedInfo {
        publisher: hex::encode(state.identity.ed25519_public_key),
        link: link_for(&state.identity.ed25519_public_key, &salt),
        feed,
        items,
        followers,
        downloads,
    })
}

/// How often a published feed's followers are counted, and how soon a count
/// no node answered is tried again.
const FOLLOWER_COUNT_SECS: i64 = 30 * 60;
const FOLLOWER_RETRY_SECS: i64 = 2 * 60;
/// Lists of a feed counted across, the newest first: followers still on the
/// one before a publish keep counting until they take the new one.
const FOLLOWER_LISTS: usize = 3;

/// A feed's followers, as last counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct FollowerCount {
    pub count: u32,
    /// A lookup came back as full as a search takes: there may be more.
    pub at_least: bool,
    pub checked_at: i64,
}

#[derive(Debug, Default)]
struct HeldCount {
    count: Option<FollowerCount>,
    tried_at: i64,
    /// The lists counted across, newest first.
    lists: Vec<[u8; 16]>,
}

impl HeldCount {
    fn due(&self, now: i64) -> bool {
        elapsed(now, self.tried_at, FOLLOWER_RETRY_SECS)
            && self.count.is_none_or(|count| elapsed(now, count.checked_at, FOLLOWER_COUNT_SECS))
    }
}

/// Whether `interval` seconds have passed since `at`, by the clock at `now`.
/// A time ahead of the clock was taken while it ran fast and counts as long
/// past: otherwise, once it was put right, every schedule would wait out the
/// lead, and a feed's head would lapse unpublished meanwhile.
fn elapsed(now: i64, at: i64, interval: i64) -> bool {
    at > now || now - at >= interval
}

fn follower_counts() -> &'static parking_lot::Mutex<HashMap<String, HeldCount>> {
    static COUNTS: std::sync::OnceLock<parking_lot::Mutex<HashMap<String, HeldCount>>> = std::sync::OnceLock::new();
    COUNTS.get_or_init(Default::default)
}

/// The identities, ours aside, that published a source record for any of
/// `lists`. Every follower serves the list it holds, with such a record, and
/// keeps it standing while online, so this is the feed's followers online in
/// the last few hours, those who never downloaded a file included.
fn followers_in(
    blobs: &[Vec<u8>],
    list: &[u8; 16],
    own: &[u8; 32],
    into: &mut std::collections::HashSet<[u8; 32]>,
) {
    use crate::network::ember::dht::publish::RECORD_TYPE_SOURCE;
    into.extend(
        blobs
            .iter()
            .filter_map(|blob| SignedRecord::from_value_blob(blob))
            .filter(|record| {
                record.record_type == RECORD_TYPE_SOURCE && record.file_hash == *list && record.publisher_key != *own
            })
            .map(|record| record.publisher_key),
    );
}

/// Count `feed`'s followers across the lists it serves and the last few it
/// served, one lookup each: a lookup's further keys narrow it to records
/// naming all of them, which a list's sources never do. `None` when no node
/// answered any of them.
async fn count_followers(state: &AppState, dir: &Path, feed: &OwnFeed) -> Option<(u32, bool)> {
    let mut lists: Vec<[u8; 16]> = own_lists(dir, feed).iter().map(|list| list.hash).collect();
    let earlier = follower_counts().lock().get(&feed.salt).map(|held| held.lists.clone()).unwrap_or_default();
    for hash in earlier {
        if !lists.contains(&hash) {
            lists.push(hash);
        }
    }
    lists.truncate(FOLLOWER_LISTS);
    if lists.is_empty() {
        return Some((0, false));
    }
    let own = state.identity.ed25519_public_key;
    let mut followers = std::collections::HashSet::new();
    let (mut answered, mut at_least) = (false, false);
    for list in &lists {
        let key = crate::network::ember::dht::publish::source_key(list);
        let Some((blobs, responded)) =
            crate::commands::channels::find_raw_keys_counted(state, vec![key], LOOKUP_TIMEOUT_MS).await.ok().flatten()
        else {
            continue;
        };
        if responded == 0 {
            continue;
        }
        answered = true;
        at_least |= blobs.len() >= crate::network::ember::dht::search::MAX_SEARCH_RESULTS;
        followers_in(&blobs, list, &own, &mut followers);
    }
    if !answered {
        return None;
    }
    if let Some(held) = follower_counts().lock().get_mut(&feed.salt) {
        held.lists = lists;
    }
    Some((u32::try_from(followers.len()).unwrap_or(u32::MAX), at_least))
}

/// Count the followers of the published feed of ours counted longest ago, if
/// one is due, and say so to the page.
async fn count_due_followers(app: &tauri::AppHandle, state: &AppState, own: &[OwnFeed], now: i64) {
    let due = {
        let mut counts = follower_counts().lock();
        counts.retain(|salt, _| own.iter().any(|feed| feed.salt == *salt));
        own.iter()
            .filter(|feed| feed.sequence > 0)
            .filter(|feed| counts.get(&feed.salt).is_none_or(|held| held.due(now)))
            .min_by_key(|feed| counts.get(&feed.salt).and_then(|held| held.count).map_or(0, |count| count.checked_at))
            .cloned()
    };
    let Some(feed) = due else { return };
    follower_counts().lock().entry(feed.salt.clone()).or_default().tried_at = now;
    let Some((count, at_least)) = count_followers(state, &feeds_dir(app), &feed).await else { return };
    let changed = {
        let mut counts = follower_counts().lock();
        let held = counts.entry(feed.salt.clone()).or_default();
        let changed = held.count.map(|old| (old.count, old.at_least)) != Some((count, at_least));
        held.count = Some(FollowerCount { count, at_least, checked_at: now });
        changed
    };
    if changed {
        let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "salt": feed.salt }));
    }
}

fn counting_followers() -> &'static std::sync::Arc<std::sync::atomic::AtomicBool> {
    static COUNTING: std::sync::OnceLock<std::sync::Arc<std::sync::atomic::AtomicBool>> = std::sync::OnceLock::new();
    COUNTING.get_or_init(Default::default)
}

/// Save the downloads followers made from us since the last tick, and say
/// so to the page for each feed they were of.
async fn record_feed_downloads(app: &tauri::AppHandle, state: &AppState, now: i64) {
    let downloads = crate::network::feed_direct::take_downloads();
    if downloads.is_empty() {
        return;
    }
    let rows: Vec<(String, String, String)> = downloads
        .iter()
        .map(|(salt, ed2k, follower)| (hex::encode(salt), hex::encode(ed2k), hex::encode(follower)))
        .collect();
    let mut salts: Vec<String> = rows.iter().map(|(salt, _, _)| salt.clone()).collect();
    salts.sort();
    salts.dedup();
    let db = state.db.clone();
    let failed = match tokio::task::spawn_blocking(move || db.feed_own_note_downloads(&rows, now)).await {
        Ok(Ok(())) => {
            for salt in salts {
                let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "salt": salt }));
            }
            return;
        }
        Ok(Err(e)) => format!("{e:#}"),
        Err(e) => e.to_string(),
    };
    // Kept for another go: a follower is counted once, when they finish, and
    // a busy or full disk would otherwise lose them for good.
    tracing::warn!("Could not save feed downloads; trying again shortly: {failed}");
    crate::network::feed_direct::requeue_downloads(downloads);
    // One retry waiting at a time, however many saves fail meanwhile.
    if !DOWNLOADS_RETRY_DUE.swap(true, std::sync::atomic::Ordering::AcqRel) {
        tauri::async_runtime::spawn(async {
            tokio::time::sleep(DOWNLOADS_RETRY).await;
            DOWNLOADS_RETRY_DUE.store(false, std::sync::atomic::Ordering::Release);
            crate::network::feed_direct::downloads_noted().notify_one();
        });
    }
}

/// How long after a failed save of followers' downloads it is tried again.
const DOWNLOADS_RETRY: Duration = Duration::from_secs(30);
static DOWNLOADS_RETRY_DUE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[tauri::command]
pub async fn list_my_feeds(state: tauri::State<'_, AppState>) -> Result<Vec<OwnFeedInfo>, String> {
    let db = state.db.clone();
    let feeds = blocking(move || db.feeds_own(), "feeds_failed", "Could not read feeds").await?;
    let mut out = Vec::with_capacity(feeds.len());
    for feed in feeds {
        out.push(own_feed_info(&state, feed).await?);
    }
    Ok(out)
}

fn checked_details(title: &str, description: &str) -> Result<(String, String), String> {
    let title = clip(&crate::security::sanitize_remote_text(title, 1024), FEED_TITLE_MAX);
    if title.is_empty() {
        return Err(coded("feeds_title_required", "Give the feed a title"));
    }
    let description = clip(&crate::security::sanitize_remote_text(description, 4096), FEED_DESCRIPTION_MAX);
    Ok((title, description))
}

/// Start a feed, `listed` in the public index or found only by its link.
/// Nothing is published until [`publish_feed`].
#[tauri::command]
pub async fn create_feed(
    state: tauri::State<'_, AppState>,
    title: String,
    description: String,
    listed: bool,
) -> Result<OwnFeedInfo, String> {
    let (title, description) = checked_details(&title, &description)?;
    let salt = hex::encode(generate_feed_salt());
    let db = state.db.clone();
    let now = chrono::Utc::now().timestamp();
    let key = salt.clone();
    let made = blocking(
        move || db.feed_own_create(&key, &title, &description, listed, now, FEEDS_PER_IDENTITY),
        "feeds_failed",
        "Could not create the feed",
    )
    .await?;
    if !made {
        return Err(coded("feeds_too_many", "You already have as many feeds as one identity may"));
    }
    let db = state.db.clone();
    let feed = blocking(move || db.feed_own(&salt), "feeds_failed", "Could not read feeds")
        .await?
        .ok_or_else(|| coded("feeds_not_found", "That feed could not be found"))?;
    own_feed_info(&state, feed).await
}

/// A feed's title and description as saved: cleaned and cut to length.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FeedDetails {
    pub title: String,
    pub description: String,
}

#[tauri::command]
pub async fn set_feed_details(
    state: tauri::State<'_, AppState>,
    salt: String,
    title: String,
    description: String,
) -> Result<FeedDetails, String> {
    let salt = hex::encode(hex_salt(&salt)?);
    let (title, description) = checked_details(&title, &description)?;
    let _editing = edit_lock().lock().await;
    let (db, task_title, task_description) = (state.db.clone(), title.clone(), description.clone());
    let found = blocking(
        move || db.feed_own_set_details(&salt, &task_title, &task_description),
        "feeds_failed",
        "Could not save the feed",
    )
    .await?;
    if !found {
        return Err(coded("feeds_not_found", "That feed could not be found"));
    }
    Ok(FeedDetails { title, description })
}

/// List a feed of ours in the public index, or take it out. A published
/// feed's listing, or its withdrawal, goes out at once; one not yet
/// published is listed when it is.
#[tauri::command]
pub async fn set_feed_listed(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    salt: String,
    listed: bool,
) -> Result<OwnFeedInfo, String> {
    let salt = hex::encode(hex_salt(&salt)?);
    let (db, key) = (state.db.clone(), salt.clone());
    let feed = blocking(
        move || {
            if !db.feed_own_set_listed(&key, listed)? {
                return Ok(None);
            }
            db.feed_own(&key)
        },
        "feeds_failed",
        "Could not save the feed",
    )
    .await?
    .ok_or_else(|| coded("feeds_not_found", "That feed could not be found"))?;
    send_listing(&state, &feed, chrono::Utc::now().timestamp()).await;
    let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "salt": salt }));
    own_feed_info(&state, feed).await
}

/// Sign and send `feed`'s listing in the public index, as last published,
/// or, while a listing of it may live on at storers, its withdrawal. Whether
/// it is listed is read again as the listing is stamped, so a listing
/// decided before the user took the feed out cannot outrank the withdrawal.
/// Not waited on: one that does not get out goes again with the next
/// publish or republish.
async fn send_listing(state: &AppState, feed: &OwnFeed, now: i64) {
    let head = own_head(feed);
    let (db, key, published) = (state.db.clone(), feed.salt.clone(), head.is_some());
    let due = tokio::task::spawn_blocking(move || db.feed_own_take_listing(&key, published, now, FEED_LISTING_TTL_SECS))
        .await
        .ok()
        .and_then(Result::ok)
        .flatten();
    if let Some(due) = due {
        queue_listing(state, &due, &head.unwrap_or_else(withdrawal_head)).await;
    }
}

/// Sign and queue `due`: the feed's listing naming `head`, or its
/// withdrawal, which names nothing of the feed.
async fn queue_listing(state: &AppState, due: &DueListing, head: &FeedHead) {
    let Ok(salt) = hex_to16(&due.salt) else {
        return;
    };
    let head = if due.withdrawn { withdrawal_head() } else { head.clone() };
    let signing = crate::network::ember::crypto::signing_key_from_bytes(&state.identity.ed25519_secret_key);
    let Some(record) = SignedRecord::feed_listing_record(&salt, &head, due.withdrawn, &signing, due.stamp) else {
        return;
    };
    if let Err(error) = crate::commands::channels::queue_signed_record(state, record).await {
        tracing::info!("feed {}: its listing was not sent: {error}", due.salt);
    }
}

/// Send the withdrawals of deleted feeds that are due: at once, and daily
/// until each listing they displace has lapsed.
async fn send_due_withdrawals(state: &AppState, now: i64) {
    let db = state.db.clone();
    let due = tokio::task::spawn_blocking(move || db.feed_withdrawals_due(now, WITHDRAWAL_RESEND_SECS, FEED_LISTING_TTL_SECS))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    for withdrawal in due {
        queue_listing(state, &withdrawal, &withdrawal_head()).await;
    }
}

/// One item as the editor sends it: a file from the Library, and a note.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct FeedItemInput {
    pub ed2k: String,
    #[serde(default)]
    pub note: String,
}

/// What saving a feed's items kept and left out.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct SavedFeedItems {
    /// The items saved, in order, as saved.
    pub items: Vec<FeedItem>,
    /// The names of items no longer shared with everyone (made
    /// friends-only, or gone from the Library), in the order sent.
    pub dropped: Vec<String>,
}

/// Set a feed's items, in order, from files the user shares publicly. Every
/// item then has at least one source, and a BLAKE3 a follower can check.
/// An item no longer shared with everyone is left out, not the whole save
/// refused, as a publish would leave it out.
#[tauri::command]
pub async fn set_feed_items(
    state: tauri::State<'_, AppState>,
    salt: String,
    items: Vec<FeedItemInput>,
) -> Result<SavedFeedItems, String> {
    let salt = hex::encode(hex_salt(&salt)?);
    if items.len() > FEED_ITEMS_MAX {
        return Err(coded("feeds_too_many_items", "A feed holds at most 2,000 files"));
    }
    // For the names of items gone from the Library.
    let (db, key) = (state.db.clone(), salt.clone());
    let held: HashMap<String, String> = blocking(move || db.feed_own_items(&key), "feeds_failed", "Could not read feeds")
        .await?
        .into_iter()
        .map(|item| (item.ed2k, item.name))
        .collect();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    let mut saved = SavedFeedItems::default();
    {
        let index = state.local_index.read().await;
        for input in items {
            let ed2k = input.ed2k.trim().to_ascii_lowercase();
            if !seen.insert(ed2k.clone()) {
                continue;
            }
            let shared = index.get_by_hash(&ed2k).filter(|file| file.is_public_listable() && file.ember_file_hash.len() == 64);
            let Some(file) = shared else {
                let name = index.get_by_hash(&ed2k).map(|file| file.name.clone()).or_else(|| held.get(&ed2k).cloned());
                saved.dropped.push(name.unwrap_or(ed2k));
                continue;
            };
            out.push(FeedItem {
                ed2k,
                name: file.name.clone(),
                size: file.size as i64,
                aich: file.aich_hash.clone(),
                blake3: file.ember_file_hash.to_ascii_lowercase(),
                note: clip(&crate::security::sanitize_remote_text(&input.note, 4096), FEED_NOTE_MAX),
            });
        }
    }
    if !saved.dropped.is_empty() && crate::commands::sharing::startup_library_loading() {
        return Err(library_loading());
    }
    // Not while a Publish reads the items and drops those no longer shared.
    let _editing = edit_lock().lock().await;
    let db = state.db.clone();
    let (found, out) = blocking(move || Ok((db.feed_own_set_items(&salt, &out)?, out)), "feeds_failed", "Could not save the feed").await?;
    if !found {
        return Err(coded("feeds_not_found", "That feed could not be found"));
    }
    saved.items = out;
    Ok(saved)
}

/// Refusal for a save or publish that would drop items while the startup scan
/// is still putting last session's files back in the Library: missing from
/// the index then is not gone, and a dropped item is gone from the feed for
/// good.
fn library_loading() -> String {
    coded(
        "feeds_library_loading",
        "The Library is still loading its files; try again in a moment",
    )
}

/// Whether `item` is still a file the user shares with everyone, as it was
/// when added: one since made friends-only, or gone, must not be published.
fn still_public(index: &crate::search::index::LocalIndex, item: &FeedItem) -> bool {
    still_public_file(index, &item.ed2k, &item.blake3)
}

/// [`still_public`], for the file of eD2K hash `ed2k` and BLAKE3 `blake3`.
fn still_public_file(index: &crate::search::index::LocalIndex, ed2k: &str, blake3: &str) -> bool {
    index
        .get_by_hash(ed2k)
        .is_some_and(|file| file.is_public_listable() && file.ember_file_hash.eq_ignore_ascii_case(blake3))
}

/// The files a list of ours names, `(ed2k, blake3)` in lowercase hex, by the
/// list's eD2K hash. A list's bytes never change under its hash, so each is
/// read once, from the file it is shared from.
fn own_list_files_cache() -> &'static parking_lot::Mutex<HashMap<[u8; 16], std::sync::Arc<Vec<(String, String)>>>> {
    static CACHE: std::sync::OnceLock<parking_lot::Mutex<HashMap<[u8; 16], std::sync::Arc<Vec<(String, String)>>>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// [`own_list_files_cache`]'s entry for `hash`, a list of our feed `salt`,
/// read now if it has none. `None` for a list not shared, not whole, or not
/// that feed's. Blocking: reads the list.
fn own_list_files(hash: &[u8; 16], publisher: &str, salt: &str) -> Option<std::sync::Arc<Vec<(String, String)>>> {
    if let Some(files) = own_list_files_cache().lock().get(hash) {
        return Some(files.clone());
    }
    let share = feed_files::hidden_share(hash)?;
    let bytes = std::fs::read(&share.path).ok()?;
    if crate::network::ed2k::hash::ed2k_hash_bytes(&bytes) != hex::encode(hash) {
        return None;
    }
    let collection = open_list_collection(publisher, salt, &bytes)?;
    let files = std::sync::Arc::new(
        collection
            .files
            .iter()
            .map(|file| (file.hash.to_ascii_lowercase(), file.ember_file_hash.to_ascii_lowercase()))
            .collect(),
    );
    own_list_files_cache().lock().insert(*hash, std::sync::Arc::clone(&files));
    Some(files)
}

/// Held while the served files are rebuilt, so one that read the database
/// before a publish or delete cannot replace what a later one set.
fn served_rebuild_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(Default::default)
}

/// Let followers stream our feeds' files (see `network::feed_direct`): every
/// file the published or pending list of a feed of ours names, as followers
/// may hold either, that is still shared with everyone, from where the
/// Library has it. Not the items the editor saved since, which no follower
/// has been sent. Left as it was while the Library is still loading or busy
/// re-indexing.
async fn refresh_served_files(state: &AppState) {
    if crate::commands::sharing::startup_library_loading() {
        return;
    }
    let _rebuilding = served_rebuild_lock().lock().await;
    let db = state.db.clone();
    let us = hex::encode(state.identity.ed25519_public_key);
    let feeds = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<(String, Vec<(String, String)>)>> {
        let mut out = Vec::new();
        let mut lists_used = std::collections::HashSet::new();
        for feed in db.feeds_own()? {
            let published = (feed.sequence > 0).then_some(feed.list_ed2k.as_str());
            let pending = feed.pending.as_ref().map(|pending| pending.list_ed2k.as_str());
            let mut files = Vec::new();
            let mut lists = published.into_iter().chain(pending).filter_map(|hash| hex_to16(hash).ok()).collect::<Vec<_>>();
            lists.dedup();
            for hash in lists {
                lists_used.insert(hash);
                match own_list_files(&hash, &us, &feed.salt) {
                    Some(listed) => files.extend(listed.iter().cloned()),
                    None => tracing::debug!("Feed {}: list {} is not served; its files are not either", feed.salt, hex::encode(hash)),
                }
            }
            out.push((feed.salt, files));
        }
        own_list_files_cache().lock().retain(|hash, _| lists_used.contains(hash));
        Ok(out)
    })
    .await;
    let Ok(Ok(feeds)) = feeds else { return };
    let publisher = state.identity.ed25519_public_key;
    let Ok(index) = state.local_index.try_read() else { return };
    let mut served = HashMap::new();
    for (salt, files) in &feeds {
        let Ok(salt) = hex_to16(salt) else { continue };
        for (ed2k_hex, blake3) in files {
            let (Some(file), Ok(ed2k)) = (index.get_by_hash(ed2k_hex), hex_to16(ed2k_hex)) else { continue };
            if still_public_file(&index, ed2k_hex, blake3) {
                let (id, entry) =
                    crate::network::feed_direct::served_entry(&publisher, &salt, &ed2k, PathBuf::from(&file.path), file.size);
                served.insert(id, entry);
            }
        }
    }
    drop(index);
    crate::network::feed_direct::set_served(served);
}

/// The list a feed's items make: a collection file's bytes, sealed for the
/// feed `salt` of `publisher` (see `ember::feed::seal_list`). The same items,
/// title and author make the same bytes.
fn build_list(publisher: &[u8; 32], salt: &FeedSalt, title: &str, author: &str, items: &[FeedItem]) -> anyhow::Result<Vec<u8>> {
    let collection = Collection {
        name: title.to_string(),
        author: author.to_string(),
        files: items
            .iter()
            .map(|item| CollectionFile {
                name: item.name.clone(),
                size: item.size.max(0) as u64,
                hash: item.ed2k.clone(),
                aich_hash: item.aich.clone(),
                ember_file_hash: item.blake3.clone(),
                note: item.note.clone(),
            })
            .collect(),
    }
    .to_binary_bytes()?;
    crate::network::ember::feed::seal_list(publisher, salt, &collection).ok_or_else(|| anyhow::anyhow!("the list could not be sealed"))
}

/// The collection file a list file of the feed `salt` of `publisher` (both
/// lowercase hex) seals, parsed. `None` for one of another feed, cut short,
/// tampered with, or that does not parse.
fn open_list_collection(publisher: &str, salt: &str, bytes: &[u8]) -> Option<Collection> {
    let (publisher, salt) = (hex_to32(publisher).ok()?, hex_to16(salt).ok()?);
    let opened = crate::network::ember::feed::open_list(&publisher, &salt, bytes)?;
    Collection::from_binary_bytes(&opened).ok()
}

/// Write the feed's list, serve it, and publish a head naming it. Holds
/// [`publish_lock`] throughout, so two publishes never cross.
#[tauri::command]
pub async fn publish_feed(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    salt: String,
) -> Result<OwnFeedInfo, String> {
    let salt_bytes = hex_salt(&salt)?;
    let salt = hex::encode(salt_bytes);
    crate::commands::channels::require_ember(&state).await?;
    let _publishing = publish_lock().lock().await;
    let author = state.config.read().await.settings.channel_username.trim().to_string();
    let dir = feeds_dir(&app);
    let owner = own_owner(&salt);
    let (feed, kept) = {
        let _editing = edit_lock().lock().await;
        let db = state.db.clone();
        let key = salt.clone();
        let (feed, items) =
            blocking(move || Ok((db.feed_own(&key)?, db.feed_own_items(&key)?)), "feeds_failed", "Could not read feeds").await?;
        let feed = feed.ok_or_else(|| coded("feeds_not_found", "That feed could not be found"))?;
        let kept: Vec<FeedItem> = {
            let index = state.local_index.read().await;
            items.iter().filter(|item| still_public(&index, item)).cloned().collect()
        };
        if kept.len() != items.len() {
            if crate::commands::sharing::startup_library_loading() {
                return Err(library_loading());
            }
            let db = state.db.clone();
            let (key, kept) = (salt.clone(), kept.clone());
            blocking(move || db.feed_own_set_items(&key, &kept), "feeds_failed", "Could not save the feed").await?;
        }
        (feed, kept)
    };

    // The new list is served beside the feed's others until its head is out.
    let (key, task_feed, task_owner, task_dir, task_kept) = (salt.clone(), feed.clone(), owner.clone(), dir.clone(), kept.clone());
    let publisher = state.identity.ed25519_public_key;
    let built = blocking(
        move || {
            let (feed, kept) = (task_feed, task_kept);
            let bytes = build_list(&publisher, &salt_bytes, &feed.title, &author, &kept)?;
            // Followers refuse a list past this; refused here instead, rather
            // than published to nobody.
            if bytes.len() as u64 > MAX_LIST_BYTES {
                return Ok(None);
            }
            // After a pending head too, which storers may hold.
            let last = feed.pending.as_ref().map_or(feed.sequence, |pending| pending.sequence.max(feed.sequence));
            let sequence = next_sequence(last.max(0) as u64, now_ms()).min(i64::MAX as u64);
            let head = FeedHead {
                sequence,
                list_ed2k_hash: hex_to16(&crate::network::ed2k::hash::ed2k_hash_bytes(&bytes))?,
                list_size: bytes.len() as u64,
                list_blake3: *blake3::hash(&bytes).as_bytes(),
                item_count: kept.len() as u32,
                title: feed.title.clone(),
                description: feed.description.clone(),
            };
            anyhow::ensure!(head.valid(), "the head would not be valid");
            let path = own_list_path(&task_dir, &key, sequence as i64);
            write_list(&path, &bytes)?;
            feed_files::share_hidden(
                head.list_ed2k_hash,
                &task_owner,
                HiddenShare {
                    path: path.clone(),
                    size: head.list_size,
                    name: list_share_name(),
                    ember_file_hash: hex::encode(head.list_blake3),
                },
            );
            Ok(Some((head, path)))
        },
        "feeds_publish_failed",
        "Could not publish the feed",
    )
    .await?;
    let Some((head, path)) = built else {
        return Err(coded(
            "feeds_list_too_large",
            "This feed's list is too large to publish. Remove some files, or shorten their notes.",
        ));
    };
    let published = OwnPublish {
        sequence: head.sequence as i64,
        list_ed2k: hex::encode(head.list_ed2k_hash),
        list_blake3: hex::encode(head.list_blake3),
        list_size: head.list_size as i64,
        item_count: i64::from(head.item_count),
        title: head.title.clone(),
        description: head.description.clone(),
    };
    let new_list = OwnList {
        sequence: published.sequence,
        hash: head.list_ed2k_hash,
        share: HiddenShare {
            path,
            size: head.list_size,
            name: list_share_name(),
            ember_file_hash: published.list_blake3.clone(),
        },
    };
    let held = own_lists(&dir, &feed);
    // Unchanged bytes have a held list's hash, whose share now names the new
    // file: a failure puts that one back rather than unserving both.
    let withdraw_new = || swap_own_lists(&owner, std::slice::from_ref(&new_list), &held);
    let Some((record, blob)) = sign_head(&state, &salt_bytes, &head) else {
        withdraw_lists(&state, withdraw_new()).await;
        return Err(coded("feeds_publish_failed", "Could not publish the feed"));
    };
    match send_head(&state, &salt_bytes, record).await {
        Placed::Stored => {
            let _ = state.network_tx.try_send(NetworkCommand::PushFeedHead { blob });
        }
        Placed::Nowhere => {
            withdraw_lists(&state, withdraw_new()).await;
            return Err(publish_unreachable());
        }
        Placed::Unknown => {
            keep_pending(&state, &owner, &feed, &held, new_list.clone(), &published).await;
            refresh_served_files(&state).await;
            return Err(publish_unreachable());
        }
    }

    let now = chrono::Utc::now().timestamp();
    // The head is out: losing this record would leave a list nobody keeps
    // named by it, so a passing write error is tried again.
    let mut recorded = Err(String::new());
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let (db, key, published, kept) = (state.db.clone(), salt.clone(), published.clone(), kept.clone());
        recorded = blocking(
            move || db.feed_own_published(&key, &published, Some(&kept), now),
            "feeds_publish_failed",
            "Could not publish the feed",
        )
        .await;
        if recorded.is_ok() {
            break;
        }
    }
    match recorded {
        // The lists before this one are no longer the feed's.
        Ok(true) => withdraw_lists(&state, swap_own_lists(&owner, &held, std::slice::from_ref(&new_list))).await,
        Ok(false) => withdraw_lists(&state, withdraw_new()).await,
        // Followers may be sent after the new list already. As the pending
        // head, the next republish sends it and records it once stored.
        Err(error) => {
            keep_pending(&state, &owner, &feed, &held, new_list, &published).await;
            refresh_served_files(&state).await;
            return Err(error);
        }
    }
    let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "salt": salt }));
    refresh_served_files(&state).await;
    let db = state.db.clone();
    let recorded = blocking(move || db.feed_own(&salt), "feeds_failed", "Could not read feeds").await?;
    if let Some(feed) = &recorded {
        send_listing(&state, feed, now).await;
    }
    own_feed_info(&state, recorded.unwrap_or(feed)).await
}

fn hex_to16(text: &str) -> anyhow::Result<[u8; 16]> {
    let mut out = [0u8; 16];
    hex::decode_to_slice(text, &mut out)?;
    Ok(out)
}

fn hex_to32(text: &str) -> anyhow::Result<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(text, &mut out)?;
    Ok(out)
}

/// Write a list in full or not at all: on disk before its name is, so a
/// power cut cannot leave a short file under it (ext4 and XFS can, for a
/// rename of data not yet flushed).
fn write_list(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    let dir = path.parent().ok_or_else(|| anyhow::anyhow!("no folder"))?;
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("tmp");
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    // The rename itself, on a file system that orders it apart from the data.
    #[cfg(unix)]
    if let Ok(folder) = std::fs::File::open(dir) {
        let _ = folder.sync_all();
    }
    Ok(())
}

/// Whether the list at `path` is there whole: a file of the size its head
/// names. One cut short by a crash is not served, but written or fetched
/// again.
fn list_file_whole(path: &Path, size: i64) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() as i64 == size)
}

/// A list a feed of ours serves, kept in the file its sequence names.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnList {
    sequence: i64,
    hash: [u8; 16],
    share: HiddenShare,
}

/// The lists `feed` serves: the one its last head names, once published,
/// and its pending one.
fn own_lists(dir: &Path, feed: &OwnFeed) -> Vec<OwnList> {
    let published = (feed.sequence > 0).then_some((feed.sequence, &feed.list_ed2k, &feed.list_blake3, feed.list_size));
    let pending = feed
        .pending
        .as_ref()
        .map(|pending| (pending.sequence, &pending.list_ed2k, &pending.list_blake3, pending.list_size));
    published
        .into_iter()
        .chain(pending)
        .filter_map(|(sequence, ed2k, blake3, size)| {
            Some(OwnList {
                sequence,
                hash: hex_to16(ed2k).ok()?,
                share: HiddenShare {
                    path: own_list_path(dir, &feed.salt, sequence),
                    size: size.max(0) as u64,
                    name: list_share_name(),
                    ember_file_hash: blake3.clone(),
                },
            })
        })
        .collect()
}

/// Serve `after`, the lists a feed of ours (`owner`) keeps, in place of
/// `before`: a list of `before` that `after` does not name stops being
/// served by it, and its file is deleted. Lists of one hash are one share,
/// served from the last of them in `after`. Returns the lists nothing
/// serves now, for [`withdraw_lists`].
fn swap_own_lists(owner: &str, before: &[OwnList], after: &[OwnList]) -> Vec<[u8; 16]> {
    for list in after {
        feed_files::share_hidden(list.hash, owner, list.share.clone());
    }
    let mut released = Vec::new();
    for list in before {
        if !after.iter().any(|kept| kept.share.path == list.share.path) {
            let _ = std::fs::remove_file(&list.share.path);
        }
        if !after.iter().any(|kept| kept.hash == list.hash) && !released.contains(&list.hash) {
            released.extend(release_list(&list.hash, owner));
        }
    }
    released
}

/// A publish of `feed` sent its head, `published`, and did not record it as
/// published. Storers may hold it, and followers be sent after its list, so
/// that list, `new`, stays served as the feed's pending one, in place of any
/// pending before it. When the pending head cannot be recorded, the one
/// before it stays recorded and served, and `new` is served beside it for as
/// long as the app runs. Called with [`publish_lock`] held.
async fn keep_pending(state: &AppState, owner: &str, feed: &OwnFeed, held: &[OwnList], new: OwnList, published: &OwnPublish) {
    // The republish that sends a pending head again waits as after a try.
    republish_retry().lock().insert(feed.salt.clone(), chrono::Utc::now().timestamp() + REPUBLISH_RETRY_SECS);
    let (db, pending) = (state.db.clone(), published.clone());
    let (owner, feed, held) = (owner.to_string(), feed.clone(), held.to_vec());
    let released = tokio::task::spawn_blocking(move || {
        serve_pending(&owner, &feed, &held, new, || matches!(db.feed_own_set_pending(&feed.salt, Some(&pending)), Ok(true)))
    })
    .await
    .unwrap_or_default();
    withdraw_lists(state, released).await;
}

/// Record a pending head of `feed` with `record`, and only once it is
/// recorded serve its list, `new`, in place of the pending one before it.
/// Returns the lists nothing serves now, for [`withdraw_lists`].
fn serve_pending(owner: &str, feed: &OwnFeed, held: &[OwnList], new: OwnList, record: impl FnOnce() -> bool) -> Vec<[u8; 16]> {
    if !record() {
        tracing::warn!("feed {}: could not keep the head whose publish was not confirmed", feed.salt);
        return Vec::new();
    }
    let mut after: Vec<OwnList> = held.iter().filter(|list| list.sequence == feed.sequence).cloned().collect();
    after.push(new);
    swap_own_lists(owner, held, &after)
}

/// How a head's publish ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placed {
    /// At least one node acked storing it.
    Stored,
    /// Surely nowhere: never handed to the network, or no STORE of it went
    /// out.
    Nowhere,
    /// Not known: STOREs went out and none was acked, or no verdict came in
    /// time. A node may hold it, its ack lost or late.
    Unknown,
}

/// How a publish the network finished ended, by what it got through.
fn placed(result: &EmberPublishResult) -> Placed {
    if result.stored_on > 0 {
        Placed::Stored
    } else if result.sent == 0 {
        Placed::Nowhere
    } else {
        Placed::Unknown
    }
}

/// How long a head's publish may take once the network has taken it up.
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(30);

/// `head` signed now, as a record for the DHT and as the value blob friends
/// are pushed. Signed now, so a republish of an unchanged head is newer than
/// the copy storers hold.
fn sign_head(state: &AppState, salt: &FeedSalt, head: &FeedHead) -> Option<(SignedRecord, Vec<u8>)> {
    let signing = crate::network::ember::crypto::signing_key_from_bytes(&state.identity.ed25519_secret_key);
    let record = SignedRecord::feed_head_record(salt, head, &signing, chrono::Utc::now().timestamp())?;
    let blob = [record.data.clone(), record.signature.to_vec()].concat();
    Some((record, blob))
}

/// Store a signed head in the DHT. Until a node has, no follower can find
/// it: only [`Placed::Stored`] is published, and friends are pushed a head
/// only then.
async fn send_head(state: &AppState, salt: &FeedSalt, record: SignedRecord) -> Placed {
    let (tx, rx) = tokio::sync::oneshot::channel();
    if state.network_tx.try_send(NetworkCommand::PublishEmberRecord { record: Box::new(record), tx }).is_err() {
        return Placed::Nowhere;
    }
    let started = match tokio::time::timeout(crate::commands::errors::CMD_REPLY_TIMEOUT, rx).await {
        Ok(Ok(Ok(started))) => started,
        Ok(Ok(Err(error))) => {
            tracing::info!("feed {} head was not sent: {error}", hex::encode(salt));
            return Placed::Nowhere;
        }
        Ok(Err(_)) => return Placed::Nowhere,
        // Still queued, and the network may yet send it.
        Err(_) => return Placed::Unknown,
    };
    match tokio::time::timeout(PUBLISH_TIMEOUT, started.result_rx).await {
        Ok(Ok(result)) => {
            if result.stored_on == 0 {
                tracing::info!(
                    "feed {} head: no ack from {} nodes, {} STOREs sent",
                    hex::encode(salt),
                    result.targets,
                    result.sent
                );
            }
            placed(&result)
        }
        Ok(Err(_)) | Err(_) => {
            tracing::info!("feed {} head's publish gave no verdict in time", hex::encode(salt));
            Placed::Unknown
        }
    }
}

/// The head of a published feed, as last published: an edit made since is
/// not signed until it is published.
fn own_head(feed: &OwnFeed) -> Option<FeedHead> {
    // Published by a development build that did not record these.
    let (title, description) = if feed.published_title.is_empty() {
        (&feed.title, &feed.description)
    } else {
        (&feed.published_title, &feed.published_description)
    };
    head_of(&OwnPublish {
        sequence: feed.sequence,
        list_ed2k: feed.list_ed2k.clone(),
        list_blake3: feed.list_blake3.clone(),
        list_size: feed.list_size,
        item_count: feed.item_count,
        title: title.clone(),
        description: description.clone(),
    })
}

/// The head `published` records.
fn head_of(published: &OwnPublish) -> Option<FeedHead> {
    Some(FeedHead {
        sequence: published.sequence.max(0) as u64,
        list_ed2k_hash: hex_to16(&published.list_ed2k).ok()?,
        list_size: published.list_size.max(0) as u64,
        list_blake3: hex_to32(&published.list_blake3).ok()?,
        item_count: published.item_count.max(0) as u32,
        title: published.title.clone(),
        description: published.description.clone(),
    })
    .filter(FeedHead::valid)
}

/// Stop publishing a feed. Its head lapses from the DHT within its lifetime;
/// followers keep what they hold. A feed listed in the public index is
/// withdrawn from it by the service's tick, daily until its listing lapses.
#[tauri::command]
pub async fn delete_feed(app: tauri::AppHandle, state: tauri::State<'_, AppState>, salt: String) -> Result<(), String> {
    let salt = hex::encode(hex_salt(&salt)?);
    let _publishing = publish_lock().lock().await;
    let dir = feeds_dir(&app);
    let db = state.db.clone();
    let key = salt.clone();
    let now = chrono::Utc::now().timestamp();
    let released = blocking(
        move || {
            let mut released = Vec::new();
            if let Some(feed) = db.feed_own(&key)? {
                released = swap_own_lists(&own_owner(&key), &own_lists(&dir, &feed), &[]);
            }
            db.feed_own_delete(&key, now, FEED_LISTING_TTL_SECS)?;
            Ok(released)
        },
        "feeds_failed",
        "Could not delete the feed",
    )
    .await?;
    republish_retry().lock().remove(&salt);
    withdraw_lists(&state, released).await;
    refresh_served_files(&state).await;
    let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "salt": salt }));
    Ok(())
}

// ── Following ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct FollowedFeedInfo {
    #[serde(flatten)]
    pub feed: FollowedFeed,
    pub link: String,
    pub activity: FeedActivity,
    /// Set by a follow of a feed already followed.
    pub already_following: bool,
}

/// What a followed feed's lookups and fetches are doing now, beyond what its
/// row records: what the page shows while it waits.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct FeedActivity {
    /// A lookup of its head is running.
    pub looking: bool,
    /// Its last lookup reached no node.
    pub unreachable: bool,
    /// Its newest head names a list larger than Ember takes.
    pub too_large: bool,
    /// A fetch of its list is running.
    pub fetching: Option<FetchActivity>,
    /// When the next fetch of its list may start, after one gave up; 0 if
    /// none did.
    pub retry_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FetchActivity {
    /// Seconds since it started.
    pub secs: u64,
    pub bytes: u64,
    /// Sources sending or queued at, as of the last tick.
    pub sources: u32,
}

fn activity_of(feed: &FollowedFeed) -> FeedActivity {
    let key = (feed.publisher.clone(), feed.salt.clone());
    let fetching = fetching()
        .lock()
        .values()
        .filter(|f| f.publisher == feed.publisher && f.salt == feed.salt)
        .max_by_key(|f| f.sequence)
        .map(|f| FetchActivity { secs: f.started.elapsed().as_secs(), bytes: f.bytes, sources: f.sources });
    FeedActivity {
        looking: looking().lock().contains(&key),
        unreachable: missed_lookups().lock().contains_key(&key),
        too_large: too_large().lock().contains(&key),
        fetching,
        retry_at: gave_up().lock().get(&key).map_or(0, |at| at + FETCH_RETRY_SECS),
    }
}

fn followed_info(feed: FollowedFeed) -> FollowedFeedInfo {
    let link = match (hex_to32(&feed.publisher), hex_to16(&feed.salt)) {
        (Ok(publisher), Ok(salt)) => link_for(&publisher, &salt),
        _ => String::new(),
    };
    let activity = activity_of(&feed);
    FollowedFeedInfo { feed, link, activity, already_following: false }
}

#[tauri::command]
pub async fn list_followed_feeds(state: tauri::State<'_, AppState>) -> Result<Vec<FollowedFeedInfo>, String> {
    let db = state.db.clone();
    let feeds = blocking(move || db.feeds_followed(), "feeds_failed", "Could not read feeds").await?;
    Ok(feeds.into_iter().map(followed_info).collect())
}

/// Follow the feed a link names, and look for its head at once.
#[tauri::command]
pub async fn follow_feed(app: tauri::AppHandle, state: tauri::State<'_, AppState>, link: String) -> Result<FollowedFeedInfo, String> {
    let link = FeedLink::parse(&link).ok_or_else(|| coded("feeds_bad_link", "That is not a feed link"))?;
    if link.publisher == state.identity.ed25519_public_key {
        return Err(coded("feeds_own", "That is one of your own feeds"));
    }
    let (publisher, salt) = (hex::encode(link.publisher), hex::encode(link.salt));
    let db = state.db.clone();
    let (key_pub, key_salt) = (publisher.clone(), salt.clone());
    let now = chrono::Utc::now().timestamp();
    let (added, feed) = blocking(
        move || {
            let added = db.feed_follow(&key_pub, &key_salt, now)?;
            Ok((added, db.feed_followed(&key_pub, &key_salt)?))
        },
        "feeds_failed",
        "Could not follow the feed",
    )
    .await?;
    let feed = feed.ok_or_else(|| coded("feeds_failed", "Could not follow the feed"))?;
    if added {
        let looked = app.clone();
        tauri::async_runtime::spawn(async move {
            if let Some(state) = looked.try_state::<AppState>() {
                look_up_head(&looked, &state, &publisher, &salt).await;
            }
        });
        let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "publisher": feed.publisher, "salt": feed.salt }));
    }
    Ok(FollowedFeedInfo { already_following: !added, ..followed_info(feed) })
}

/// Look again now, rather than at the next half hour, and fetch its list at
/// once if it is owed one, even while resting after a fetch gave up or after
/// its list did not match: the user asked. What the lookup came to.
#[tauri::command]
pub async fn refresh_feed(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    publisher: String,
    salt: String,
) -> Result<LookupOutcome, String> {
    let (publisher, salt) = (hex::encode(hex_publisher(&publisher)?), hex::encode(hex_salt(&salt)?));
    let outcome = look_up_head(&app, &state, &publisher, &salt).await;
    if outcome != LookupOutcome::Updated {
        gave_up().lock().remove(&(publisher.clone(), salt.clone()));
        // A list that did not match its head is fetched once more, from the
        // network rather than a copy left here, which may be what was bad.
        let (db, key_pub, key_salt, dir) = (state.db.clone(), publisher.clone(), salt.clone(), feeds_dir(&app));
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(Some(sequence)) = db.feed_clear_broken(&key_pub, &key_salt) {
                let _ = std::fs::remove_file(followed_list_path(&dir, &key_pub, &key_salt, sequence));
            }
        })
        .await;
        fetch_owed(&app, &state, &publisher, &salt, chrono::Utc::now().timestamp()).await;
    }
    let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "publisher": publisher, "salt": salt }));
    Ok(outcome)
}

#[tauri::command]
pub async fn get_feed_items(
    state: tauri::State<'_, AppState>,
    publisher: String,
    salt: String,
) -> Result<Vec<FollowedItemInfo>, String> {
    let (publisher, salt) = (hex::encode(hex_publisher(&publisher)?), hex::encode(hex_salt(&salt)?));
    // The page asks every few seconds while files download; a slow answer is
    // logged with where the time went.
    let started = Instant::now();
    let mut phases: Vec<(&str, u128)> = Vec::new();
    let mut mark = |phase: &'static str, at: &mut Instant| {
        phases.push((phase, at.elapsed().as_millis()));
        *at = Instant::now();
    };
    let mut at = Instant::now();
    let db = state.db.clone();
    let now = chrono::Utc::now().timestamp();
    let (key_pub, key_salt) = (publisher.clone(), salt.clone());
    let (feed, items, spent, copies) = blocking(
        move || {
            Ok((
                db.feed_followed(&key_pub, &key_salt)?,
                db.feed_followed_items(&key_pub, &key_salt)?,
                db.feed_auto_bytes(&key_pub, &key_salt, now)?,
                db.feed_downloaded_elsewhere(&key_pub, &key_salt)?,
            ))
        },
        "feeds_failed",
        "Could not read feeds",
    )
    .await?;
    let feed = feed.ok_or_else(|| coded("feeds_not_found", "That feed could not be found"))?;
    mark("database", &mut at);
    // What each file's download is doing: the transfer list's own word for
    // it, newest first, then the file on disk.
    let transfers: HashMap<String, (ItemStatus, f64, Option<String>, ItemTransfer)> = {
        let manager = state.transfer_manager.read().await;
        mark("transfer list lock", &mut at);
        let mut by_hash = HashMap::new();
        for t in manager.completed.iter().chain(manager.queue.iter()).chain(manager.active.values()) {
            if t.direction == crate::types::TransferDirection::Download {
                by_hash.insert(
                    t.file_hash.to_ascii_lowercase(),
                    (ItemStatus::of(&t.status), t.progress, t.completed_path.clone(), ItemTransfer::of(t, &feed.folder)),
                );
            }
        }
        by_hash
    };
    mark("transfer list", &mut at);
    // A library scan holds the index through a whole re-index: the page asks
    // every few seconds, so a busy index counts as holding none of them.
    let in_library: std::collections::HashSet<String> = match state.local_index.try_read() {
        Ok(index) => items
            .iter()
            .map(|i| i.item.ed2k.to_ascii_lowercase())
            .filter(|hash| index.get_by_hash(hash).is_some())
            .collect(),
        Err(_) => Default::default(),
    };
    let folders = state.config.read().await.settings.download_folders();
    let folder = feed.folder.clone();
    let finished: Vec<(String, String)> = transfers
        .iter()
        .filter_map(|(hash, (status, _, path, _))| (*status == ItemStatus::Done).then_some((hash.clone(), path.clone()?)))
        .collect();
    let finished_count = finished.len();
    let wanted: std::collections::HashSet<String> = items.iter().map(|i| i.item.ed2k.to_ascii_lowercase()).collect();
    let ((on_disk, gone), held_elsewhere) = tokio::task::spawn_blocking(move || {
        let copies = copies.into_iter().filter(|copy| wanted.contains(&copy.ed2k.to_ascii_lowercase())).collect();
        (feed_folder_files(&folders, &folder, &finished), copies_elsewhere(&folders, copies))
    })
    .await
    .unwrap_or_default();
    mark("files on disk", &mut at);
    let mut spent = spent;
    // As the auto-download pass measures it, so a file it leaves for want of
    // space says so rather than nothing.
    let mut room = if feed.auto_download { auto_download_room(&state).await } else { u64::MAX };
    mark("free space", &mut at);
    let elapsed = started.elapsed();
    if elapsed >= Duration::from_secs(1) {
        let phases: Vec<String> = phases.iter().map(|(phase, ms)| format!("{phase} {ms} ms")).collect();
        tracing::warn!(
            "get_feed_items took {} ms for {} item(s), {} finished download(s) checked on disk: {}",
            elapsed.as_millis(),
            items.len(),
            finished_count,
            phases.join(", ")
        );
    }
    Ok(items
        .into_iter()
        .map(|item| {
            let hash = item.item.ed2k.to_ascii_lowercase();
            let name = crate::security::sanitize_filename(&item.item.name);
            let tagged = crate::sharing::name_tag::completed_download_name(&name);
            let size = u64::try_from(item.item.size).unwrap_or(u64::MAX);
            let file_here = [&name, &tagged]
                .into_iter()
                .any(|name| on_disk.get(&file_name_key(name)).is_some_and(|sizes| sizes.contains(&size)));
            // Another followed feed's finished copy, still in its folder.
            let copy_elsewhere = if file_here { None } else { held_elsewhere.get(&hash).cloned() };
            // Not here, by this feed's record of it.
            let absent = || {
                if copy_elsewhere.is_some() {
                    (ItemStatus::Elsewhere, 100.0)
                } else if item.cancelled {
                    (ItemStatus::Cancelled, 0.0)
                } else if item.downloaded {
                    (ItemStatus::Missing, 0.0)
                } else {
                    (ItemStatus::None, 0.0)
                }
            };
            let (status, progress) = match transfers.get(&hash) {
                // Finished for another feed, into its folder: not this one's.
                Some((ItemStatus::Done, _, _, t)) if t.other_feed && !file_here => absent(),
                Some((ItemStatus::Done, _, Some(_), _)) if gone.contains(&hash) && !file_here => {
                    if copy_elsewhere.is_some() {
                        (ItemStatus::Elsewhere, 100.0)
                    } else if item.downloaded {
                        (ItemStatus::Missing, 0.0)
                    } else {
                        (ItemStatus::None, 0.0)
                    }
                }
                Some((status, progress, _, _)) => (*status, *progress),
                None if file_here => (ItemStatus::Done, 100.0),
                None if in_library.contains(&hash) => (ItemStatus::InLibrary, 100.0),
                None => absent(),
            };
            // The controls are for a download still in the list, done or not.
            let transfer = transfers
                .get(&hash)
                .filter(|_| {
                    !matches!(
                        status,
                        ItemStatus::Missing | ItemStatus::None | ItemStatus::Cancelled | ItemStatus::Elsewhere
                    )
                })
                .map(|(_, _, _, transfer)| transfer.clone());
            let elsewhere = copy_elsewhere.filter(|_| status == ItemStatus::Elsewhere);
            // In the order a pass takes them, each counted off the 24-hour
            // cap as it would be started.
            let held = if status == ItemStatus::None && auto_takes(&feed, &item) {
                let reason = auto_hold_reason(&feed, &item.item, spent)
                    .or_else(|| (room < size.saturating_add(AUTO_DOWNLOAD_HEADROOM)).then_some("disk"));
                if reason.is_none() {
                    spent = spent.saturating_add(item.item.size);
                    room = room.saturating_sub(size);
                }
                reason
            } else {
                None
            };
            FollowedItemInfo {
                risky: auto_download_refuses(&item.item.name),
                status,
                progress,
                held,
                transfer,
                elsewhere,
                item,
            }
        })
        .collect())
}

/// Of the files other followed feeds downloaded, those still where they
/// finished, in their feed's folder under the current download folder or an
/// earlier one: by eD2K hash, the title of the feed that has it. A feed takes
/// such a file as held rather than downloading a second copy of it.
fn copies_elsewhere(folders: &DownloadFolders, copies: Vec<crate::storage::database::ElsewhereCopy>) -> HashMap<String, String> {
    let mut found = HashMap::new();
    for copy in copies {
        let ed2k = copy.ed2k.to_ascii_lowercase();
        let Ok(size) = u64::try_from(copy.size) else { continue };
        if found.contains_key(&ed2k) || copy.folder.is_empty() {
            continue;
        }
        let name = crate::security::sanitize_filename(&copy.name);
        let tagged = crate::sharing::name_tag::completed_download_name(&name);
        let held = std::iter::once(&folders.current).chain(&folders.previous).any(|root| {
            let dir = crate::sharing::feed_downloads::folder_dir(root, &copy.folder);
            [&name, &tagged]
                .into_iter()
                .any(|name| std::fs::metadata(dir.join(name)).is_ok_and(|meta| meta.is_file() && meta.len() == size))
        });
        if held {
            found.insert(ed2k, copy.title);
        }
    }
    found
}

/// A file name as the download folder's file system compares it: Windows'
/// and macOS's ignore case, Linux's do not.
fn file_name_key(name: &str) -> String {
    if cfg!(any(windows, target_os = "macos")) {
        name.to_lowercase()
    } else {
        name.to_string()
    }
}

/// The files in a feed's folder, under the current download folder or an
/// earlier one, by [`file_name_key`] with their sizes; and of `finished`
/// downloads, by hash, those whose file is no longer where it finished.
fn feed_folder_files(
    folders: &crate::storage::part_folders::DownloadFolders,
    folder: &str,
    finished: &[(String, String)],
) -> (HashMap<String, Vec<u64>>, std::collections::HashSet<String>) {
    let mut on_disk: HashMap<String, Vec<u64>> = HashMap::new();
    if !folder.is_empty() {
        for root in std::iter::once(&folders.current).chain(&folders.previous) {
            let dir = crate::sharing::feed_downloads::folder_dir(root, folder);
            for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                match entry.metadata() {
                    Ok(meta) if meta.is_file() => {
                        on_disk.entry(file_name_key(&entry.file_name().to_string_lossy())).or_default().push(meta.len())
                    }
                    _ => {}
                }
            }
        }
    }
    let gone = finished.iter().filter(|(_, path)| !Path::new(path).is_file()).map(|(hash, _)| hash.clone()).collect();
    (on_disk, gone)
}

/// What the download of a feed's file is doing, as the page shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemStatus {
    /// Not downloaded, nor on its way.
    None,
    /// Waiting for sources or a slot.
    Queued,
    Downloading,
    Paused,
    Failed,
    /// In the feed's folder.
    Done,
    /// The user has it in their Library already, from elsewhere.
    InLibrary,
    /// Downloaded or started from the feed before, and gone since: removed
    /// from the transfer list or deleted from the folder.
    Missing,
    /// Its download was cancelled from the feed.
    Cancelled,
    /// Not in this feed's folder, but downloaded for another followed feed
    /// and still in that one's: auto-download takes it as held.
    Elsewhere,
}

impl ItemStatus {
    fn of(status: &crate::types::TransferStatus) -> Self {
        use crate::types::TransferStatus as S;
        match status {
            S::Active | S::Verifying | S::Completing | S::Hashing => Self::Downloading,
            S::Searching | S::Queued | S::Insufficient => Self::Queued,
            S::Paused | S::Stopped => Self::Paused,
            S::Failed => Self::Failed,
            S::Completed | S::NoneNeeded => Self::Done,
        }
    }
}

/// Whether `feed`'s auto-download is to take `item`: on, the file first seen
/// since it was turned on, never asked for, and still listed.
fn auto_takes(feed: &FollowedFeed, item: &FollowedItem) -> bool {
    feed.auto_download && feed.auto_since > 0 && item.first_seen >= feed.auto_since && !item.downloaded && !item.removed
}

/// Why auto-download is holding `item` back, if a cap or its type is why.
fn auto_hold_reason(feed: &FollowedFeed, item: &FeedItem, spent: i64) -> Option<&'static str> {
    const MIB: i64 = 1024 * 1024;
    if auto_download_refuses(&item.name) {
        Some("risky")
    } else if feed.auto_max_item_mib != 0 && item.size > feed.auto_max_item_mib.saturating_mul(MIB) {
        Some("too_large")
    } else if feed.auto_max_day_mib != 0 && spent.saturating_add(item.size) > feed.auto_max_day_mib.saturating_mul(MIB) {
        Some("day_limit")
    } else {
        None
    }
}

/// An item of a followed feed, as the page shows it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FollowedItemInfo {
    #[serde(flatten)]
    pub item: FollowedItem,
    /// A type that can run code or change settings, which automatic
    /// downloads never take: the page asks before downloading it.
    pub risky: bool,
    pub status: ItemStatus,
    /// Of a download on its way, 0 to 100.
    pub progress: f64,
    /// Why auto-download has not started it: `risky`, `too_large`,
    /// `day_limit` or `disk` (too little free space, or none could be read).
    pub held: Option<&'static str>,
    /// Its download, while it is in the transfer list.
    pub transfer: Option<ItemTransfer>,
    /// For one held in another followed feed's folder: that feed's title.
    pub elsewhere: Option<String>,
}

/// The download of a feed's file, for the controls the Feeds page gives it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ItemTransfer {
    pub id: String,
    /// Bytes per second.
    pub speed: u64,
    pub sources: u32,
    pub active_sources: u32,
    /// Bytes of the file held so far.
    pub done: u64,
    /// Still asked of the publisher alone (see `network::feed_direct`).
    pub from_publisher: bool,
    /// The user's own download, started outside the feed: on the Transfers
    /// page, and controlled there.
    pub in_transfers: bool,
    /// Another followed feed's download of the same file, finishing in its
    /// folder, and controlled from that feed.
    pub other_feed: bool,
    /// Why it failed, for one that did.
    pub failure_reason: Option<String>,
    pub failure_code: Option<String>,
}

impl ItemTransfer {
    /// `folder`: the feed's own, in `Feeds`.
    fn of(t: &Transfer, folder: &str) -> Self {
        let feed_folder = crate::sharing::feed_downloads::folder_of(&t.id);
        Self {
            id: t.id.clone(),
            speed: t.speed,
            sources: t.sources,
            active_sources: t.active_sources,
            done: t.completed_size,
            from_publisher: crate::network::feed_direct::holds(&t.id),
            in_transfers: feed_folder.is_none(),
            other_feed: feed_folder.is_some_and(|other| other != folder),
            failure_reason: t.failure_reason.clone(),
            failure_code: t.failure_code.clone(),
        }
    }
}

#[tauri::command]
pub async fn mark_feed_read(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    publisher: String,
    salt: String,
) -> Result<(), String> {
    let (publisher, salt) = (hex::encode(hex_publisher(&publisher)?), hex::encode(hex_salt(&salt)?));
    let db = state.db.clone();
    let (key_pub, key_salt) = (publisher.clone(), salt.clone());
    blocking(move || db.feed_mark_read(&key_pub, &key_salt), "feeds_failed", "Could not update the feed").await?;
    let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "publisher": publisher, "salt": salt }));
    Ok(())
}

/// An auto-download cap as saved, in MiB: 0 is no limit.
fn auto_cap(mib: i64) -> i64 {
    mib.clamp(0, 1 << 30)
}

/// Auto-download for one feed: off by default, and bounded per item and per
/// 24 hours by the caps given, each 0 for no limit. Returns the feed as
/// saved.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn set_feed_auto_download(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    publisher: String,
    salt: String,
    enabled: bool,
    max_item_mib: i64,
    max_day_mib: i64,
) -> Result<FollowedFeedInfo, String> {
    let (publisher, salt) = (hex::encode(hex_publisher(&publisher)?), hex::encode(hex_salt(&salt)?));
    let db = state.db.clone();
    let (key_pub, key_salt) = (publisher.clone(), salt.clone());
    let now = chrono::Utc::now().timestamp();
    let feed = blocking(
        move || {
            let (item, day) = (auto_cap(max_item_mib), auto_cap(max_day_mib));
            if !db.feed_set_auto_download(&key_pub, &key_salt, enabled, item, day, now)? {
                return Ok(None);
            }
            db.feed_followed(&key_pub, &key_salt)
        },
        "feeds_failed",
        "Could not save the feed",
    )
    .await?
    .ok_or_else(|| coded("feeds_not_found", "That feed could not be found"))?;
    let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "publisher": publisher, "salt": salt }));
    Ok(followed_info(feed))
}

/// Every transfer that has not finished: running, queued, or failed and
/// still listed with its partial file, which only the feed's page shows.
fn unfinished_downloads(manager: &crate::sharing::manager::TransferManager) -> impl Iterator<Item = &Transfer> {
    manager
        .active
        .values()
        .chain(manager.queue.iter())
        .chain(manager.completed.iter().filter(|t| t.status == TransferStatus::Failed))
}

/// Cancel an item's download from the feed: the download and what has
/// arrived of it go, and the item shows as cancelled. Only this feed's own
/// download is cancelled: one the user started from Transfers is theirs, and
/// another followed feed's is that feed's.
#[tauri::command]
pub async fn cancel_feed_download(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    publisher: String,
    salt: String,
    ed2k: String,
) -> Result<(), String> {
    let (publisher, salt) = (hex::encode(hex_publisher(&publisher)?), hex::encode(hex_salt(&salt)?));
    let ed2k = hex_to16(ed2k.trim())
        .map(hex::encode)
        .map_err(|_| coded("transfers_invalid_file_hash", "Invalid file hash"))?;
    let db = state.db.clone();
    let (key_pub, key_salt) = (publisher.clone(), salt.clone());
    let folder = blocking(move || db.feed_followed(&key_pub, &key_salt), "feeds_failed", "Could not read feeds")
        .await?
        .ok_or_else(|| coded("feeds_not_found", "That feed could not be found"))?
        .folder;
    let transfer_id = {
        let manager = state.transfer_manager.read().await;
        let found = unfinished_downloads(&manager)
            .find(|t| {
                t.direction == TransferDirection::Download
                    && t.file_hash.eq_ignore_ascii_case(&ed2k)
                    && !folder.is_empty()
                    && crate::sharing::feed_downloads::folder_of(&t.id).as_deref() == Some(folder.as_str())
            })
            .map(|t| t.id.clone());
        found
    };
    if let Some(id) = transfer_id {
        crate::commands::transfers::discard_transfer(&state, id, false).await?;
    }
    let db = state.db.clone();
    let (key_pub, key_salt) = (publisher.clone(), salt.clone());
    blocking(
        move || db.feed_mark_cancelled(&key_pub, &key_salt, &ed2k),
        "feeds_failed",
        "Could not update the feed",
    )
    .await?;
    let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "publisher": publisher, "salt": salt }));
    Ok(())
}

/// Start downloads of some of a feed's items, by hand.
#[tauri::command]
pub async fn download_feed_items(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    publisher: String,
    salt: String,
    ed2ks: Vec<String>,
) -> Result<usize, String> {
    let (publisher, salt) = (hex::encode(hex_publisher(&publisher)?), hex::encode(hex_salt(&salt)?));
    let db = state.db.clone();
    let (key_pub, key_salt) = (publisher.clone(), salt.clone());
    let (feed, items) = blocking(
        move || Ok((db.feed_followed(&key_pub, &key_salt)?, db.feed_followed_items(&key_pub, &key_salt)?)),
        "feeds_failed",
        "Could not read feeds",
    )
    .await?;
    let feed = feed.ok_or_else(|| coded("feeds_not_found", "That feed could not be found"))?;
    let wanted: std::collections::HashSet<String> = ed2ks.iter().map(|h| h.trim().to_ascii_lowercase()).collect();
    let mut started = 0;
    let mut first_error = None;
    for item in items.into_iter().filter(|i| wanted.contains(&i.item.ed2k)) {
        match start_item_download(&app, &feed, &item.item).await {
            Ok(()) => started += 1,
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "publisher": publisher, "salt": salt }));
    // Nothing started: say why, rather than "0 started".
    match first_error {
        Some(error) if started == 0 => Err(error),
        _ => Ok(started),
    }
}

/// Start one item's download, and mark it so. It
/// finishes in the feed's folder in `Feeds`, kept private (see
/// `sharing::feed_downloads`), and is streamed from the publisher first,
/// friend or not; a friend's last address is tried at once (see
/// `network::feed_direct`).
async fn start_item_download(app: &tauri::AppHandle, feed: &FollowedFeed, item: &FeedItem) -> Result<(), String> {
    let state = app.state::<AppState>();
    let db = state.db.clone();
    let (publisher, salt, title) = (feed.publisher.clone(), feed.salt.clone(), feed.title.clone());
    let folder = blocking(
        move || db.feed_followed_folder(&publisher, &salt, &title),
        "feeds_failed",
        "Could not read feeds",
    )
    .await?
    .ok_or_else(|| coded("feeds_not_found", "That feed could not be found"))?;
    let (key, salt) = match (hex_to32(&feed.publisher), hex_to16(&feed.salt)) {
        (Ok(key), Ok(salt)) if crate::network::ember::crypto::node_id_from_ed25519_bytes(&key).is_some() => (key, salt),
        _ => return Err(coded("feeds_not_found", "That feed could not be found")),
    };
    let friend = friend_source(&state, &feed.publisher).await;
    // Not handed over as a peer to dial over eD2K: the stream asks it first,
    // and every network is asked, the friends' path with them, if it fails.
    let friend_tcp = match &friend {
        Some((_, Some((ip, port)))) => ip
            .parse::<std::net::Ipv4Addr>()
            .ok()
            .filter(|ip| *port != 0 && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast())
            .map(|ip| std::net::SocketAddr::from((ip, *port))),
        _ => None,
    };
    let started = crate::commands::transfers::start_download_to(
        app.clone(),
        state.clone(),
        item.ed2k.clone(),
        item.name.clone(),
        item.size.max(0) as u64,
        String::new(),
        0,
        None,
        Some(item.blake3.clone()),
        (!item.aich.is_empty()).then(|| item.aich.clone()),
        friend.as_ref().map(|(hash, _)| hex::encode(hash)),
        None,
        Some(crate::commands::transfers::FeedStart {
            folder,
            publisher: crate::network::feed_direct::Publisher { key, salt, friend_tcp },
        }),
    )
    .await?;
    if !started.already_queued {
        // Unfollow takes the feed's downloads only after its row is gone, so
        // a download started while it ran either is seen there or sees the
        // row gone here; one left would be shown nowhere and never stopped.
        let db = state.db.clone();
        let (publisher, salt) = (feed.publisher.clone(), feed.salt.clone());
        let still_followed = tokio::task::spawn_blocking(move || db.feed_followed(&publisher, &salt))
            .await
            .ok()
            .and_then(Result::ok)
            .is_none_or(|row| row.is_some());
        if !still_followed {
            let _ = crate::commands::transfers::discard_transfer(&state, started.transfer_id.clone(), false).await;
            return Err(coded("feeds_not_found", "That feed could not be found"));
        }
    }
    let db = state.db.clone();
    let (publisher, salt, ed2k) = (feed.publisher.clone(), feed.salt.clone(), item.ed2k.clone());
    let _ = tokio::task::spawn_blocking(move || db.feed_mark_downloaded(&publisher, &salt, &ed2k)).await;
    Ok(())
}

/// How often the downloads held for their publishers are looked at.
const HOLD_POLL: Duration = Duration::from_secs(2);
/// How long a download just begun may be missing from the transfer list, or
/// still show the failure it is being revived from, before it is forgotten.
const HOLD_GRACE: Duration = Duration::from_secs(10);

/// Watch every download held for its publisher (see `network::feed_direct`),
/// however it was begun, and the moment one is let go ask every network for
/// its sources, rather than leave it to their next sweeps, the slowest of
/// which is half an hour.
fn spawn_hold_watcher(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut tick = tokio::time::interval(HOLD_POLL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if let Some(state) = app.try_state::<AppState>() {
                watch_holds(&state).await;
            }
        }
    });
}

async fn watch_holds(state: &AppState) {
    use crate::network::feed_direct::{self, Poll};
    use TransferStatus as S;
    let watched = feed_direct::watched();
    if watched.is_empty() {
        return;
    }
    let rows: Vec<_> = {
        let manager = state.transfer_manager.read().await;
        watched
            .into_iter()
            .map(|(id, begun)| {
                let active = manager.active.contains_key(&id);
                let row = manager
                    .get_transfer(&id)
                    .map(|t| (t.transferred, t.status.clone(), t.file_hash.clone(), t.total_size, active));
                (id, begun, row)
            })
            .collect()
    };
    let now = Instant::now();
    for (transfer_id, begun, row) in rows {
        let ended = row.as_ref().is_none_or(|(_, status, ..)| matches!(status, S::Completed | S::NoneNeeded | S::Failed));
        if ended {
            if now.saturating_duration_since(begun) >= HOLD_GRACE {
                feed_direct::forget(&transfer_id);
            }
            continue;
        }
        let Some((transferred, status, hash, size, active)) = row else { continue };
        // Waiting for a download slot is not the publisher's to answer for.
        let counting = active && !matches!(status, S::Paused | S::Stopped);
        // Watched on once let go, for as long as the download lasts: its
        // publisher's stream outlives the hold, and is forgotten with it.
        if let Poll::Released(why) = feed_direct::poll(&transfer_id, transferred, counting, now) {
            tracing::info!("Feed download {transfer_id}: asking every network for sources ({why:?})");
            let Ok(file_hash) = hex_to16(&hash) else { continue };
            let (tx, _answer) = tokio::sync::oneshot::channel();
            let _ = bounded_send(
                &state.network_tx,
                NetworkCommand::FindSources { transfer_id: transfer_id.clone(), file_hash, file_size: size, tx },
            )
            .await;
        }
    }
}

/// Open the folder a followed feed's files finish in, or `Feeds` before the
/// first has been downloaded. Under the current download folder, unless its
/// files are only under an earlier one, where they finished before the
/// download folder was changed.
#[tauri::command]
pub async fn open_feed_folder(state: tauri::State<'_, AppState>, publisher: String, salt: String) -> Result<(), String> {
    let (publisher, salt) = (hex::encode(hex_publisher(&publisher)?), hex::encode(hex_salt(&salt)?));
    let db = state.db.clone();
    let feed = blocking(move || db.feed_followed(&publisher, &salt), "feeds_failed", "Could not read feeds")
        .await?
        .ok_or_else(|| coded("feeds_not_found", "That feed could not be found"))?;
    let folders = state.config.read().await.settings.download_folders();
    tokio::task::spawn_blocking(move || {
        let holds_files = |root: &Path| {
            std::fs::read_dir(crate::sharing::feed_downloads::folder_dir(root, &feed.folder))
                .is_ok_and(|mut entries| entries.any(|entry| entry.is_ok_and(|entry| entry.path().is_file())))
        };
        let root = if feed.folder.is_empty() || holds_files(&folders.current) {
            folders.current.as_path()
        } else {
            folders.previous.iter().find(|root| holds_files(root)).unwrap_or(&folders.current).as_path()
        };
        let dir = if feed.folder.is_empty() {
            crate::security::filesystem::prepare_approved_subdir(
                root,
                crate::sharing::feed_downloads::FEEDS_DIR,
                &[root.to_string_lossy().into_owned()],
            )
            .inspect(|feeds| crate::sharing::feed_downloads::mark_feeds_dir(feeds))
            .map_err(anyhow::Error::from)
        } else {
            crate::network::ed2k::transfer::prepare_feed_completed_dir(root, &feed.folder)
        }
        .map_err(|e| coded_ctx("transfers_invalid_path", "Invalid or changed download path", e))?;
        crate::security::filesystem::open_with_default_app(&dir)
            .map_err(|e| coded_ctx("transfers_open_explorer_failed", "Failed to open the folder", e))
    })
    .await
    .map_err(|e| coded_ctx("feeds_task_error", "Task error", e))?
}

/// Open the Feeds folder of the current download folder, creating it if
/// nothing has landed there yet.
#[tauri::command]
pub async fn open_feed_files_folder(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let root = state.config.read().await.settings.download_folders().current;
    tokio::task::spawn_blocking(move || {
        let dir = crate::security::filesystem::prepare_approved_subdir(
            &root,
            crate::sharing::feed_downloads::FEEDS_DIR,
            &[root.to_string_lossy().into_owned()],
        )
        .inspect(|feeds| crate::sharing::feed_downloads::mark_feeds_dir(feeds))
        .map_err(|e| coded_ctx("transfers_invalid_path", "Invalid or changed download path", e))?;
        crate::security::filesystem::open_with_default_app(&dir)
            .map_err(|e| coded_ctx("transfers_open_explorer_failed", "Failed to open the Feed Files folder", e))
    })
    .await
    .map_err(|e| coded_ctx("feeds_task_error", "Task error", e))?
}

/// Stop following a feed: its list stops being served and is deleted, and
/// its items are forgotten. Downloaded files stay.
#[tauri::command]
pub async fn unfollow_feed(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    publisher: String,
    salt: String,
) -> Result<(), String> {
    let (publisher, salt) = (hex::encode(hex_publisher(&publisher)?), hex::encode(hex_salt(&salt)?));
    let followed = followed_lock().lock().await;
    for id in fetches_for(&publisher, &salt) {
        cancel_fetch(&state, &id).await;
    }
    let key = (publisher.clone(), salt.clone());
    push_gates().lock().remove(&key);
    missed_lookups().lock().remove(&key);
    gave_up().lock().remove(&key);
    too_large().lock().remove(&key);
    listing_fallbacks().lock().remove(&key);
    let dir = feeds_dir(&app);
    let db = state.db.clone();
    let (key_pub, key_salt) = (publisher.clone(), salt.clone());
    let (released, folder) = blocking(
        move || {
            let mut released = None;
            let mut folder = String::new();
            if let Some(feed) = db.feed_followed(&key_pub, &key_salt)? {
                if let Ok(hash) = hex_to16(&feed.held_ed2k) {
                    released = release_list(&hash, &followed_owner(&key_pub, &key_salt));
                }
                folder = feed.folder;
            }
            remove_followed_files(&dir, &key_pub, &key_salt, None);
            db.feed_unfollow(&key_pub, &key_salt)?;
            Ok((released, folder))
        },
        "feeds_failed",
        "Could not unfollow the feed",
    )
    .await?;
    drop(followed);
    withdraw_lists(&state, released).await;
    // Its unfinished downloads go with it: they are shown nowhere but the
    // feed's page, so left running they could be neither seen nor stopped.
    // What finished stays in its folder.
    if !folder.is_empty() {
        let unfinished: Vec<String> = {
            let manager = state.transfer_manager.read().await;
            unfinished_downloads(&manager)
                .filter(|t| crate::sharing::feed_downloads::folder_of(&t.id).as_deref() == Some(folder.as_str()))
                .map(|t| t.id.clone())
                .collect()
        };
        for id in unfinished {
            if let Err(e) = crate::commands::transfers::discard_transfer(&state, id.clone(), false).await {
                tracing::warn!("Unfollow: could not cancel feed download {id}: {e}");
            }
        }
    }
    let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "publisher": publisher, "salt": salt }));
    Ok(())
}

// ── Heads and lists ────────────────────────────────────────────────────────

/// What a lookup of a followed feed came to, for "Check now" to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupOutcome {
    /// A newer head was found and taken up; its list is being fetched.
    Updated,
    /// The head found is the one held.
    Unchanged,
    /// Nodes answered, and none holds the feed.
    NotFound,
    /// No node answered.
    Unreachable,
    /// The newest head names a list larger than Ember takes.
    TooLarge,
    /// A lookup of it was running already.
    Busy,
}

/// Look up a followed feed's head and take up a newer one, starting the
/// fetch of its list.
async fn look_up_head(app: &tauri::AppHandle, state: &AppState, publisher: &str, salt: &str) -> LookupOutcome {
    let (Ok(publisher_key), Ok(salt_bytes)) = (hex_to32(publisher), hex_to16(salt)) else {
        return LookupOutcome::NotFound;
    };
    // One lookup of a feed at a time: a tick's and the user's "Check now".
    let looking_at = (publisher.to_string(), salt.to_string());
    if !looking().lock().insert(looking_at.clone()) {
        return LookupOutcome::Busy;
    }
    let key = feed_key(&publisher_key, &salt_bytes);
    let looked = LookedAt(looking_at.clone());
    let found = crate::commands::channels::find_raw_keys_counted(state, vec![key], LOOKUP_TIMEOUT_MS)
        .await
        .ok()
        .flatten();
    let (blobs, mut responded) = found.unwrap_or_default();
    let mut best = newest_head(&blobs, &publisher_key, &salt_bytes);
    let now = chrono::Utc::now().timestamp();
    // A listed feed's listing carries its head, signed alike, and lives
    // under another key: found there when its own key's storers are gone.
    if best.is_none() && listing_fallback_due(&looking_at, now) {
        let shard = feed_index_key(feed_index_shard(&publisher_key, &salt_bytes));
        let listed = crate::commands::channels::find_raw_keys_counted(state, vec![shard], LOOKUP_TIMEOUT_MS)
            .await
            .ok()
            .flatten();
        if let Some((blobs, shard_responded)) = listed {
            responded = responded.max(shard_responded);
            best = newest_listed_head(&blobs, &publisher_key, &salt_bytes);
            if best.is_some() {
                tracing::info!("feed {salt}: its head was not at its key; taken from its Discover listing");
            }
        }
    }
    // A lookup no node answered says nothing about the head: it is not a
    // check, and is tried again sooner than the next one would be.
    if responded > 0 {
        missed_lookups().lock().remove(&looking_at);
        let db = state.db.clone();
        let (key_pub, key_salt) = looking_at.clone();
        let _ = tokio::task::spawn_blocking(move || db.feed_checked(&key_pub, &key_salt, now)).await;
    } else {
        missed_lookups().lock().insert(looking_at.clone(), now);
    }
    drop(looked);
    if best.is_some() {
        note_seen(state, publisher, salt, now).await;
    }
    let too_large = best.as_ref().is_some_and(|head| head.list_size > MAX_LIST_BYTES);
    if best.is_some() || responded > 0 {
        set_too_large(&looking_at, too_large);
    }
    match best {
        Some(_) if too_large => {
            tracing::info!("feed {salt}: its list is larger than {MAX_LIST_BYTES} bytes; not fetched");
            LookupOutcome::TooLarge
        }
        Some(head) => {
            if take_head(app, state, publisher, salt, head).await {
                LookupOutcome::Updated
            } else {
                LookupOutcome::Unchanged
            }
        }
        None if responded == 0 => LookupOutcome::Unreachable,
        None => LookupOutcome::NotFound,
    }
}

/// A head of the feed was found, so it is still published (see
/// `FollowedFeed::seen_at`).
async fn note_seen(state: &AppState, publisher: &str, salt: &str, now: i64) {
    let (db, publisher, salt) = (state.db.clone(), publisher.to_string(), salt.to_string());
    let _ = tokio::task::spawn_blocking(move || db.feed_seen(&publisher, &salt, now)).await;
}

/// Feeds whose newest head names a list larger than Ember takes.
fn too_large() -> &'static parking_lot::Mutex<std::collections::HashSet<(String, String)>> {
    static TOO_LARGE: std::sync::OnceLock<parking_lot::Mutex<std::collections::HashSet<(String, String)>>> =
        std::sync::OnceLock::new();
    TOO_LARGE.get_or_init(Default::default)
}

fn set_too_large(key: &(String, String), is: bool) {
    let mut set = too_large().lock();
    if is {
        set.insert(key.clone());
    } else {
        set.remove(key);
    }
}

/// When each feed's own key last gave nothing and its index shard was read.
fn listing_fallbacks() -> &'static parking_lot::Mutex<HashMap<(String, String), i64>> {
    static LAST: std::sync::OnceLock<parking_lot::Mutex<HashMap<(String, String), i64>>> = std::sync::OnceLock::new();
    LAST.get_or_init(Default::default)
}

/// Whether a lookup of the feed `key` whose own key gave nothing may read its
/// index shard now, at most every [`LISTING_FALLBACK_SECS`]; noted as read.
fn listing_fallback_due(key: &(String, String), now: i64) -> bool {
    let mut last = listing_fallbacks().lock();
    if last.get(key).is_some_and(|at| !elapsed(now, *at, LISTING_FALLBACK_SECS)) {
        return false;
    }
    last.insert(key.clone(), now);
    true
}

/// The newest head among `blobs` that a listing of this feed by its
/// publisher carries, unless the newest listing withdraws it. Of any size.
fn newest_listed_head(blobs: &[Vec<u8>], publisher: &[u8; 32], salt: &FeedSalt) -> Option<FeedHead> {
    blobs
        .iter()
        .filter_map(|blob| SignedRecord::from_value_blob(blob))
        .filter(|record| record.publisher_key == *publisher && record.feed_listing_store_ok())
        .filter_map(|record| record.feed_listing().map(|listing| (record.timestamp, listing)))
        .filter(|(_, (found_salt, _, _))| found_salt == salt)
        .max_by_key(|(at, _)| *at)
        .and_then(|(_, (_, head, withdrawn))| (!withdrawn).then_some(head))
}

/// When a followed feed's last lookup reached no node.
fn missed_lookups() -> &'static parking_lot::Mutex<HashMap<(String, String), i64>> {
    static MISSED: std::sync::OnceLock<parking_lot::Mutex<HashMap<(String, String), i64>>> = std::sync::OnceLock::new();
    MISSED.get_or_init(Default::default)
}

/// Feeds whose head is being looked up now.
fn looking() -> &'static parking_lot::Mutex<std::collections::HashSet<(String, String)>> {
    static LOOKING: std::sync::OnceLock<parking_lot::Mutex<std::collections::HashSet<(String, String)>>> =
        std::sync::OnceLock::new();
    LOOKING.get_or_init(Default::default)
}

/// Takes a feed out of [`looking`] however its lookup ends.
struct LookedAt((String, String));

impl Drop for LookedAt {
    fn drop(&mut self) {
        looking().lock().remove(&self.0);
    }
}

/// A head a friend pushed: taken like a looked-up one, if the friend who sent
/// it signed it, the feed is followed and the head is newer than the one
/// held. At most one per feed per [`PUSHED_HEAD_INTERVAL`]: a friend
/// pushing head after head would otherwise start and give up a fetch for
/// each.
async fn on_pushed_head(app: &tauri::AppHandle, state: &AppState, from: [u8; 32], blob: Vec<u8>) {
    let Some(record) = SignedRecord::from_value_blob(&blob) else {
        return;
    };
    if record.record_type != crate::network::ember::dht::publish::RECORD_TYPE_FEED || record.publisher_key != from {
        return;
    }
    // Which of their feeds it is, of those followed: a head names its feed
    // by the salt's locator, and only a follower has the salt.
    let (db, key_pub) = (state.db.clone(), hex::encode(from));
    let followed = tokio::task::spawn_blocking(move || db.feeds_followed())
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default()
        .into_iter()
        .filter(|feed| feed.publisher == key_pub)
        .find_map(|feed| {
            let salt = hex_to16(&feed.salt).ok()?;
            (crate::network::ember::feed::feed_locator(&salt) == record.file_hash).then_some((salt, feed.sequence))
        });
    let Some((salt, held)) = followed else {
        return;
    };
    let Some(head) = best_head(&[blob], &from, &salt) else {
        return;
    };
    let (publisher, salt) = (hex::encode(from), hex::encode(salt));
    note_seen(state, &publisher, &salt, chrono::Utc::now().timestamp()).await;
    if head.sequence.min(i64::MAX as u64) as i64 <= held {
        return;
    }
    let key = (publisher, salt);
    let take = gate_pushed_head(&mut push_gates().lock(), key.clone(), head, Instant::now());
    if let Some(head) = take {
        take_head(app, state, &key.0, &key.1, head).await;
    }
}

/// Each followed feed's pushed heads: when the next may be taken, and the
/// newest pushed before then.
#[derive(Debug, Default)]
struct PushGate {
    next: Option<Instant>,
    pending: Option<FeedHead>,
}

type PushGates = HashMap<(String, String), PushGate>;

fn push_gates() -> &'static parking_lot::Mutex<PushGates> {
    static GATES: std::sync::OnceLock<parking_lot::Mutex<PushGates>> = std::sync::OnceLock::new();
    GATES.get_or_init(Default::default)
}

/// The head to take now of one pushed at `now` for feed `key`, if its gate
/// is open: the newer of it and any kept. Otherwise it is kept, if newer
/// than the one kept, for [`due_pushed_heads`].
fn gate_pushed_head(gates: &mut PushGates, key: (String, String), head: FeedHead, now: Instant) -> Option<FeedHead> {
    let gate = gates.entry(key).or_default();
    let newest = match gate.pending.take() {
        Some(kept) if kept.sequence > head.sequence => kept,
        _ => head,
    };
    if gate.next.is_none_or(|next| now >= next) {
        gate.next = Some(now + PUSHED_HEAD_INTERVAL);
        return Some(newest);
    }
    gate.pending = Some(newest);
    None
}

/// The kept heads whose gates have opened by `now`, to take up. A gate open
/// with nothing kept is forgotten.
fn due_pushed_heads(gates: &mut PushGates, now: Instant) -> Vec<((String, String), FeedHead)> {
    let mut due = Vec::new();
    gates.retain(|key, gate| {
        if gate.next.is_some_and(|next| now < next) {
            return true;
        }
        let Some(head) = gate.pending.take() else {
            return false;
        };
        gate.next = Some(now + PUSHED_HEAD_INTERVAL);
        due.push((key.clone(), head));
        true
    });
    due
}

/// Held while a followed feed's row, list files, fetches and hidden share
/// change together: by unfollowing, by taking up a head or a list, and by
/// starting a fetch. Unfollowing between a list's being recorded and its
/// being served would otherwise leave it served from a deleted file.
/// Never held across a lookup or auto-download.
fn followed_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    &LOCK
}

/// Take up `head` if newer than the one held, and fetch its list. Whether
/// it was newer.
async fn take_head(app: &tauri::AppHandle, state: &AppState, publisher: &str, salt: &str, head: FeedHead) -> bool {
    let followed = followed_lock().lock().await;
    let now = chrono::Utc::now().timestamp();
    let db = state.db.clone();
    let (key_pub, key_salt) = (publisher.to_string(), salt.to_string());
    // The publisher's own words, shown in the app and in notifications: no
    // controls, no bidi overrides.
    let title = clip(&crate::security::sanitize_remote_text(&head.title, 1024), FEED_TITLE_MAX);
    let description = clip(&crate::security::sanitize_remote_text(&head.description, 4096), FEED_DESCRIPTION_MAX);
    let taken = tokio::task::spawn_blocking(move || {
        db.feed_take_head(
            &key_pub,
            &key_salt,
            head.sequence.min(i64::MAX as u64) as i64,
            &title,
            &description,
            &hex::encode(head.list_ed2k_hash),
            &hex::encode(head.list_blake3),
            head.list_size as i64,
            i64::from(head.item_count),
            now,
        )
        .unwrap_or(false)
    })
    .await
    .unwrap_or(false);
    if !taken {
        return false;
    }
    let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "publisher": publisher, "salt": salt }));
    let db = state.db.clone();
    let (key_pub, key_salt) = (publisher.to_string(), salt.to_string());
    let list = match tokio::task::spawn_blocking(move || db.feed_followed(&key_pub, &key_salt)).await {
        Ok(Ok(Some(feed))) => start_fetch(app, state, &feed).await,
        _ => None,
    };
    drop(followed);
    if let Some(list) = list {
        after_list(app, state, list).await;
    }
    true
}

/// Fetch the list a followed feed's head names, if it is owed one: none
/// held for this head, not broken, and not resting after a fetch gave up.
async fn fetch_owed(app: &tauri::AppHandle, state: &AppState, publisher: &str, salt: &str, now: i64) {
    let resting = gave_up()
        .lock()
        .get(&(publisher.to_string(), salt.to_string()))
        .is_some_and(|at| !elapsed(now, *at, FETCH_RETRY_SECS));
    if resting {
        return;
    }
    let followed = followed_lock().lock().await;
    let db = state.db.clone();
    let (key_pub, key_salt) = (publisher.to_string(), salt.to_string());
    let list = match tokio::task::spawn_blocking(move || db.feed_followed(&key_pub, &key_salt)).await {
        Ok(Ok(Some(feed))) if feed.sequence > 0 && feed.list_sequence != feed.sequence && feed.state != "broken" => {
            start_fetch(app, state, &feed).await
        }
        _ => None,
    };
    drop(followed);
    if let Some(list) = list {
        after_list(app, state, list).await;
    }
}

/// The newest valid head among `blobs`, by its publisher for this feed.
fn best_head(blobs: &[Vec<u8>], publisher: &[u8; 32], salt: &FeedSalt) -> Option<FeedHead> {
    heads(blobs, publisher, salt).filter(|head| head.list_size <= MAX_LIST_BYTES).max_by_key(|head| head.sequence)
}

/// The newest valid head among `blobs`, by its publisher for this feed, of
/// any size: a lookup says when it is too large rather than taking an older.
fn newest_head(blobs: &[Vec<u8>], publisher: &[u8; 32], salt: &FeedSalt) -> Option<FeedHead> {
    heads(blobs, publisher, salt).max_by_key(|head| head.sequence)
}

fn heads<'a>(blobs: &'a [Vec<u8>], publisher: &'a [u8; 32], salt: &'a FeedSalt) -> impl Iterator<Item = FeedHead> + 'a {
    blobs
        .iter()
        .filter_map(|blob| SignedRecord::from_value_blob(blob))
        .filter(move |record| record.publisher_key == *publisher && record.feed_store_ok())
        .filter_map(move |record| record.feed_head(salt))
}

/// A fetch of a list in flight.
#[derive(Debug, Clone)]
struct Fetching {
    publisher: String,
    salt: String,
    sequence: i64,
    started: Instant,
    /// When it last gained bytes or held a source, queued at one included.
    progressed: Instant,
    /// Bytes it held then.
    bytes: u64,
    /// Sources it has now, sending or queued at.
    sources: u32,
}

impl Fetching {
    fn new(publisher: &str, salt: &str, sequence: i64) -> Self {
        let now = Instant::now();
        Self { publisher: publisher.into(), salt: salt.into(), sequence, started: now, progressed: now, bytes: 0, sources: 0 }
    }

    /// Note what its transfer holds now: `bytes` on disk and `sources`.
    fn note(&mut self, bytes: u64, sources: u32, now: Instant) {
        if bytes > self.bytes || sources > 0 {
            self.progressed = now;
        }
        self.bytes = self.bytes.max(bytes);
        self.sources = sources;
    }

    /// Given up: no byte and no source for [`FETCH_TIMEOUT`], or running
    /// [`FETCH_MAX`] in all. Waiting in a busy publisher's queue is a source.
    fn stalled(&self, now: Instant) -> bool {
        now.duration_since(self.progressed) >= FETCH_TIMEOUT || now.duration_since(self.started) >= FETCH_MAX
    }
}

fn fetching() -> &'static parking_lot::Mutex<HashMap<String, Fetching>> {
    static FETCHING: std::sync::OnceLock<parking_lot::Mutex<HashMap<String, Fetching>>> = std::sync::OnceLock::new();
    FETCHING.get_or_init(Default::default)
}

/// When each feed's last fetch gave up, so the next waits a while.
fn gave_up() -> &'static parking_lot::Mutex<HashMap<(String, String), i64>> {
    static GAVE_UP: std::sync::OnceLock<parking_lot::Mutex<HashMap<(String, String), i64>>> = std::sync::OnceLock::new();
    GAVE_UP.get_or_init(Default::default)
}

fn fetches_for(publisher: &str, salt: &str) -> Vec<String> {
    fetching()
        .lock()
        .iter()
        .filter(|(_, f)| f.publisher == publisher && f.salt == salt)
        .map(|(id, _)| id.clone())
        .collect()
}

/// The publisher of a feed, when they are a friend: their Ember hash and the
/// address last seen for them. Their own list is fetched from them first,
/// over the friends' path, which a firewalled publisher whose list no source
/// record names can still be reached by.
async fn friend_source(state: &AppState, publisher: &str) -> Option<([u8; 16], Option<(String, u16)>)> {
    let publisher = hex_to32(publisher).ok()?;
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || {
        let hash = db
            .get_friend_public_keys()
            .ok()?
            .into_iter()
            .find(|(_, key)| *key == publisher)
            .map(|(hash, _)| hash)?;
        let address = db.get_friend_address(&hex::encode(hash)).ok().flatten();
        Some((hash, address))
    })
    .await
    .ok()
    .flatten()
}

/// Fetch the list `feed`'s head names, unless it is on its way. A fetch of
/// an older list is given up: its sources may well have moved on. Called
/// with [`followed_lock`] held; a list held already is taken up at once,
/// and returned for [`after_list`] once the lock is let go.
async fn start_fetch(app: &tauri::AppHandle, state: &AppState, feed: &FollowedFeed) -> Option<TakenList> {
    if feed.sequence <= 0 || feed.list_sequence == feed.sequence {
        return None;
    }
    let list_hash = hex_to16(&feed.list_ed2k).ok()?;
    let transfer_id = uuid::Uuid::new_v4().to_string();
    // Claimed before any await, so a tick and "Check now" cannot both start one.
    let superseded: Vec<String> = {
        let mut fetching = fetching().lock();
        let ours = |f: &Fetching| f.publisher == feed.publisher && f.salt == feed.salt;
        if fetching.values().any(|f| ours(f) && f.sequence >= feed.sequence) {
            return None;
        }
        let older: Vec<String> = fetching.iter().filter(|(_, f)| ours(f)).map(|(id, _)| id.clone()).collect();
        fetching.insert(transfer_id.clone(), Fetching::new(&feed.publisher, &feed.salt, feed.sequence));
        older
    };
    for id in superseded {
        cancel_fetch(state, &id).await;
    }
    let dest = followed_list_path(&feeds_dir(app), &feed.publisher, &feed.salt, feed.sequence);
    let held = feed_files::hidden_share(&list_hash).map(|share| share.path);
    let (to, from, size) = (dest.clone(), held.clone(), feed.list_size.max(0) as u64);
    let copied = tokio::task::spawn_blocking(move || {
        // A whole list left there, by an attempt that could not read it then
        // or a restart before it was taken up: read it again, rather than
        // fetch it again. `take_list_held` checks it against the head.
        if from.is_none() && std::fs::metadata(&to).is_ok_and(|meta| meta.is_file() && meta.len() == size) {
            return Some(());
        }
        // Anything else left there would push this one to "(1)".
        if from.as_ref() != Some(&to) {
            let _ = std::fs::remove_file(&to);
        }
        // Held already, as another feed's list or ours: copy it.
        let from = from?;
        std::fs::create_dir_all(to.parent()?).ok()?;
        if from != to {
            std::fs::copy(&from, &to).ok()?;
        }
        Some(())
    })
    .await
    .ok()
    .flatten()
    .is_some();
    if copied {
        // Still claimed while it is taken up, so nothing fetches it again.
        let list = take_list_held(app, state, feed.clone(), dest).await;
        fetching().lock().remove(&transfer_id);
        return list;
    }
    let control = TransferControl::new();
    let transfer = list_transfer(&transfer_id, feed, &list_hash);
    feed_files::begin_internal_fetch(&transfer_id, dest);
    let added = {
        let mut manager = state.transfer_manager.write().await;
        let added = manager.start_internal(transfer);
        if added {
            manager.register_control(&transfer_id, control.clone());
        }
        added
    };
    if !added {
        feed_files::end_internal_fetch(&transfer_id);
        fetching().lock().remove(&transfer_id);
        return None;
    }
    let (peer_ip, peer_port, friend_ember_hash) = match friend_source(state, &feed.publisher).await {
        Some((hash, Some((ip, port)))) => (ip, port, Some(hash)),
        Some((hash, None)) => (String::new(), 0, Some(hash)),
        None => (String::new(), 0, None),
    };
    let sent = bounded_send(
        &state.network_tx,
        NetworkCommand::StartDownload {
            file_hash: hex::encode(list_hash),
            file_name: list_share_name(),
            file_size: feed.list_size.max(0) as u64,
            peer_ip,
            peer_port,
            extra_sources: Vec::new(),
            ember_file_hash: feed.list_blake3.clone(),
            expected_aich: None,
            transfer_id: transfer_id.clone(),
            control,
            discovery_only: false,
            friend_ember_hash,
        },
    )
    .await;
    if sent.is_err() {
        cancel_fetch(state, &transfer_id).await;
    }
    None
}

fn list_transfer(id: &str, feed: &FollowedFeed, list_hash: &[u8; 16]) -> Transfer {
    Transfer {
        id: id.to_string(),
        file_name: list_share_name(),
        file_hash: hex::encode(list_hash),
        peer_id: String::new(),
        peer_name: String::new(),
        direction: TransferDirection::Download,
        status: TransferStatus::Searching,
        progress: 0.0,
        speed: 0,
        total_size: feed.list_size.max(0) as u64,
        transferred: 0,
        completed_size: 0,
        started_at: chrono::Utc::now().timestamp(),
        failure_reason: None,
        failure_code: None,
        failure_kind: None,
        failure_stage: None,
        priority: "high".to_string(),
        sources: 0,
        active_sources: 0,
        queued_sources: 0,
        queue_rank: None,
        last_seen_complete: None,
        last_received: None,
        health: crate::types::TransferHealth::Healthy,
        health_reason: None,
        health_code: None,
        stalled_since: None,
        category: String::new(),
        wait_time: 0,
        upload_time: 0,
        a4af_sources: 0,
        max_sources: 0,
        preview_priority: false,
        preview_ready: false,
        ember_sources: 0,
        client_software: String::new(),
        country_code: None,
        user_hash: None,
        ember_hash: None,
        expected_aich: None,
        ember_file_hash: Some(feed.list_blake3.clone()),
        completed_path: None,
        up_part_status: None,
        up_part_count: None,
        up_part_fill: None,
        up_peer_part_status: None,
        ember_verified: false,
        friends_only: false,
    }
}

/// How long a fetch given up on stays marked internal, in case its transfer
/// still finishes: far longer than the last write of a list takes.
const CANCELLED_FETCH_GRACE: Duration = Duration::from_secs(10 * 60);

/// Give up on a fetch: stop it and forget it. It stays marked internal
/// until its transfer ends, or the tick's sweep after
/// [`CANCELLED_FETCH_GRACE`], so a completion racing this lands in the feeds
/// folder and is thrown away, never in the user's Library.
async fn cancel_fetch(state: &AppState, transfer_id: &str) {
    fetching().lock().remove(transfer_id);
    feed_files::cancel_internal_fetch(transfer_id);
    let promoted = {
        let mut manager = state.transfer_manager.write().await;
        if let Some(control) = manager.get_control(transfer_id) {
            control.discard();
        }
        manager.remove(transfer_id)
    };
    crate::commands::transfers::start_promoted_downloads(state, &promoted).await;
    // The deleting form, as Cancel uses: the partial goes, not kept for a
    // resume that will never come.
    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
    let sent = state
        .network_tx
        .try_send(NetworkCommand::CancelDownload { transfer_id: transfer_id.to_string(), cleanup_ack: Some(ack_tx) })
        .is_ok();
    let db = state.db.clone();
    let roots = state.config.read().await.settings.download_roots();
    let id = transfer_id.to_string();
    tauri::async_runtime::spawn(async move {
        if sent {
            let _ = tokio::time::timeout(crate::commands::errors::CMD_REPLY_TIMEOUT, ack_rx).await;
        }
        crate::commands::transfers::cleanup_partial_files(&db, &roots, &id).await;
    });
}

/// A list arrived (or failed to).
async fn on_fetch_done(app: &tauri::AppHandle, state: &AppState, transfer_id: String, outcome: FetchOutcome) {
    let followed = followed_lock().lock().await;
    let fetch = fetching().lock().remove(&transfer_id);
    let feed = match &fetch {
        Some(fetch) => {
            let db = state.db.clone();
            let (key_pub, key_salt) = (fetch.publisher.clone(), fetch.salt.clone());
            tokio::task::spawn_blocking(move || db.feed_followed(&key_pub, &key_salt)).await.ok().and_then(Result::ok).flatten()
        }
        None => None,
    };
    let (Some(fetch), Some(feed)) = (fetch, feed) else {
        // Unfollowed meanwhile: nothing will take the file.
        if let FetchOutcome::Done(path) = outcome {
            let _ = std::fs::remove_file(path);
        }
        return;
    };
    let list = match outcome {
        FetchOutcome::Done(path) if feed.sequence == fetch.sequence => take_list_held(app, state, feed, path).await,
        FetchOutcome::Done(path) => {
            // A newer head arrived while this list was on its way.
            let _ = std::fs::remove_file(path);
            None
        }
        FetchOutcome::Mismatch(error) if feed.sequence == fetch.sequence => {
            // Fetching it again would bring the same bytes: the feed waits
            // for a newer head.
            tracing::info!("feed list for {}/{} does not match its head: {error}", fetch.publisher, fetch.salt);
            let db = state.db.clone();
            let (key_pub, key_salt, sequence) = (feed.publisher.clone(), feed.salt.clone(), feed.sequence);
            let _ = tokio::task::spawn_blocking(move || db.feed_mark_broken(&key_pub, &key_salt, sequence)).await;
            let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "publisher": feed.publisher, "salt": feed.salt }));
            None
        }
        FetchOutcome::Mismatch(error) | FetchOutcome::Failed(error) => {
            tracing::debug!("feed list fetch for {}/{} failed: {error}", fetch.publisher, fetch.salt);
            gave_up().lock().insert((fetch.publisher, fetch.salt), chrono::Utc::now().timestamp());
            None
        }
    };
    drop(followed);
    if let Some(list) = list {
        after_list(app, state, list).await;
    }
}

/// Why a list file was not taken up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListError {
    /// It could not be read (held open by a scanner, say): read it again
    /// later.
    Unreadable,
    /// It does not match its head, does not parse, or holds an entry that
    /// is not a file one could fetch: the feed is broken, not shown in part.
    Broken,
}

/// The items of a list file, checked against `feed`'s head.
fn read_list(path: &Path, feed: &FollowedFeed) -> Result<Vec<FeedItem>, ListError> {
    let bytes = std::fs::read(path).map_err(|_| ListError::Unreadable)?;
    if bytes.len() as i64 != feed.list_size
        || crate::network::ed2k::hash::ed2k_hash_bytes(&bytes) != feed.list_ed2k
        || blake3::hash(&bytes).to_hex().as_str() != feed.list_blake3
    {
        return Err(ListError::Broken);
    }
    let collection = open_list_collection(&feed.publisher, &feed.salt, &bytes).ok_or(ListError::Broken)?;
    if collection.files.len() > FEED_ITEMS_MAX || collection.files.len() as i64 != feed.item_count {
        return Err(ListError::Broken);
    }
    let hex = |text: &str, len: usize| text.len() == len && text.bytes().all(|b| b.is_ascii_hexdigit());
    let mut seen = std::collections::HashSet::new();
    let mut items = Vec::with_capacity(collection.files.len());
    for file in collection.files {
        let name = crate::security::sanitize_filename(&file.name);
        let ed2k = file.hash.to_ascii_lowercase();
        if !hex(&ed2k, 32) || !hex(&file.ember_file_hash, 64) || file.size == 0 || name.is_empty() {
            return Err(ListError::Broken);
        }
        // Ember's own lists hold each file once; another client's may not,
        // and a repeat is no reason to refuse the rest.
        if !seen.insert(ed2k.clone()) {
            continue;
        }
        items.push(FeedItem {
            ed2k,
            name,
            size: file.size.min(i64::MAX as u64) as i64,
            // Optional: a malformed one is dropped, as the download would
            // refuse to start with it.
            aich: crate::security::parse_expected_aich(Some(&file.aich_hash)).ok().flatten().unwrap_or_default(),
            blake3: file.ember_file_hash.to_ascii_lowercase(),
            // As titles and descriptions are: no controls or bidi overrides
            // from a publisher's hand.
            note: clip(&crate::security::sanitize_remote_text(&file.note, 4096), FEED_NOTE_MAX),
        });
    }
    Ok(items)
}

/// A list just taken up, for [`after_list`].
#[derive(Debug)]
struct TakenList {
    publisher: String,
    salt: String,
    added: Vec<FeedItem>,
}

/// What became of a list file handed to [`take_list_held`].
enum Took {
    /// Taken up: the items it added, and the list it replaced if nothing
    /// serves that now.
    Taken(Vec<FeedItem>, Option<[u8; 16]>),
    Unreadable,
    /// Broken, or for a head no longer current.
    Refused,
}

/// Take up a list that arrived for `feed`'s current head: check it, work out
/// what is new, and serve it in place of the one held. Called with
/// [`followed_lock`] held; what it added is returned for [`after_list`].
async fn take_list_held(app: &tauri::AppHandle, state: &AppState, feed: FollowedFeed, path: PathBuf) -> Option<TakenList> {
    let dir = feeds_dir(app);
    let db = state.db.clone();
    let task_feed = feed.clone();
    let now = chrono::Utc::now().timestamp();
    let took = tokio::task::spawn_blocking(move || {
        let feed = task_feed;
        let owner = followed_owner(&feed.publisher, &feed.salt);
        // Where the list is kept, whatever name the download finished under;
        // a file already there is an earlier copy of the same list.
        let canonical = followed_list_path(&dir, &feed.publisher, &feed.salt, feed.sequence);
        let path = if path != canonical && std::fs::rename(&path, &canonical).is_ok() { canonical } else { path };
        let items = match read_list(&path, &feed) {
            Ok(items) => items,
            // Kept where it is, for the next attempt to read again.
            Err(ListError::Unreadable) => return Took::Unreadable,
            Err(ListError::Broken) => {
                let _ = std::fs::remove_file(&path);
                let _ = db.feed_mark_broken(&feed.publisher, &feed.salt, feed.sequence);
                return Took::Refused;
            }
        };
        let update = match db.feed_take_list(&feed.publisher, &feed.salt, feed.sequence, &items, now) {
            Ok(Some(update)) => update,
            // No longer the current head.
            Ok(None) => {
                let _ = std::fs::remove_file(&path);
                return Took::Refused;
            }
            // Not saved, a full disk say: kept to be read again after the
            // wait, rather than fetched again at once and again after that.
            Err(e) => {
                tracing::warn!("Could not save the list of feed {}/{}: {e:#}", feed.publisher, feed.salt);
                return Took::Unreadable;
            }
        };
        // Serve this list in place of the one held before.
        if let Ok(hash) = hex_to16(&feed.list_ed2k) {
            feed_files::share_hidden(
                hash,
                &owner,
                HiddenShare {
                    path: path.clone(),
                    size: feed.list_size.max(0) as u64,
                    name: list_share_name(),
                    ember_file_hash: feed.list_blake3.clone(),
                },
            );
        }
        let released = (feed.held_ed2k != feed.list_ed2k)
            .then(|| hex_to16(&feed.held_ed2k).ok())
            .flatten()
            .and_then(|old| release_list(&old, &owner));
        remove_followed_files(&dir, &feed.publisher, &feed.salt, Some((feed.sequence, &path)));
        Took::Taken(update.added, released)
    })
    .await
    .unwrap_or(Took::Refused);
    let added = match took {
        Took::Taken(added, released) => {
            withdraw_lists(state, released).await;
            Some(added)
        }
        Took::Unreadable => {
            tracing::info!("feed list for {}/{} could not be read; trying again later", feed.publisher, feed.salt);
            gave_up().lock().insert((feed.publisher.clone(), feed.salt.clone()), now);
            return None;
        }
        Took::Refused => None,
    };
    let _ = app.emit(
        FEEDS_CHANGED_EVENT,
        serde_json::json!({
            "publisher": feed.publisher,
            "salt": feed.salt,
            "added": added.as_ref().map_or(0, Vec::len),
            "title": feed.title,
        }),
    );
    added.map(|added| TakenList { publisher: feed.publisher, salt: feed.salt, added })
}

/// Start what auto-download allows of what a list added, and say so once
/// the items it started are marked. Not under [`followed_lock`]: starting
/// downloads is no part of keeping a feed's files in step.
async fn after_list(app: &tauri::AppHandle, state: &AppState, list: TakenList) {
    if list.added.is_empty() {
        return;
    }
    if auto_download(app, state, &list.publisher, &list.salt, &list.added).await > 0 {
        let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "publisher": list.publisher, "salt": list.salt }));
    }
}

/// Extensions auto-download never starts, whatever the caps: programs,
/// scripts, libraries, installers, shortcuts and launchers on Windows,
/// macOS and Linux; disc and disk images; macro-enabled documents; and the
/// configuration and data files programs load by name (`desktop.ini`, a
/// launch agent's `.plist`, an app's `.config`). Every one can run
/// something, or change what runs, once it lands. A name with no extension
/// is allowed.
const AUTO_DOWNLOAD_REFUSED: &[&str] = &[
    // Windows programs, scripts, libraries, installers and shortcuts.
    "exe", "msi", "msp", "msu", "bat", "cmd", "com", "scr", "pif", "cpl", "ps1", "psm1", "vbs", "vbe", "js",
    "jse", "wsf", "wsh", "hta", "lnk", "url", "reg", "jar", "dll", "sys", "drv", "ocx", "msc", "chm", "appx",
    "appxbundle", "msix", "msixbundle", "appref-ms", "settingcontent-ms", "scf", "xll", "application",
    "gadget", "inf",
    // macOS and Linux programs, scripts, libraries, installers and launchers.
    "sh", "bash", "zsh", "py", "app", "dmg", "pkg", "command", "tool", "scpt", "scptd", "workflow", "so",
    "dylib", "desktop", "appimage", "deb", "rpm", "run", "flatpak", "flatpakref", "flatpakrepo", "snap",
    "pl", "rb",
    // Electron app archives.
    "asar",
    // Disc and disk images.
    "iso", "img", "vhd", "vhdx",
    // Macro-enabled documents.
    "docm", "xlsm", "pptm", "dotm", "xltm", "potm",
    // Configuration and data programs load by name.
    "cfg", "conf", "config", "db", "ini", "json", "pak", "plist", "sqlite", "toml", "xml", "yaml", "yml",
];

/// Whether auto-download refuses `name` by its type: a hidden file (a name
/// starting with a dot, as a shell profile's does), one of
/// [`AUTO_DOWNLOAD_REFUSED`], or what Ember counts as dangerous anywhere
/// (which also looks behind a second extension). Trailing dots and spaces,
/// which Windows drops, do not hide an extension.
fn auto_download_refuses(name: &str) -> bool {
    let name = name.trim_end_matches(['.', ' ']);
    let extension = Path::new(name).extension().and_then(|e| e.to_str()).unwrap_or_default();
    name.trim_start().starts_with('.')
        || AUTO_DOWNLOAD_REFUSED.iter().any(|refused| refused.eq_ignore_ascii_case(extension))
        || crate::security::is_dangerous_extension(name)
}

/// Whether auto-download may start `item` for `feed`, with `spent` bytes
/// started for it in the last 24 hours: not a type it refuses, not over
/// either cap.
fn auto_download_allows(feed: &FollowedFeed, item: &FeedItem, spent: i64) -> bool {
    const MIB: i64 = 1024 * 1024;
    !auto_download_refuses(&item.name)
        && (feed.auto_max_item_mib == 0 || item.size <= feed.auto_max_item_mib.saturating_mul(MIB))
        && (feed.auto_max_day_mib == 0 || spent.saturating_add(item.size) <= feed.auto_max_day_mib.saturating_mul(MIB))
}

/// Held for a whole auto-download pass, so two lists arriving together do
/// not both count the same free space and the same cap.
fn auto_download_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    &LOCK
}

/// How often auto-download looks again at a feed's files it has not started:
/// held back by the 24-hour cap, the disk, or a start that failed.
const AUTO_RETRY_SECS: i64 = 10 * 60;

/// Give each feed with auto-download on another pass over the files it is
/// to take and has not started, at most every [`AUTO_RETRY_SECS`]. A feed
/// turned on before the window was kept starts it now, rather than taking
/// every file it was ever listed.
async fn retry_auto_downloads(app: &tauri::AppHandle, state: &AppState, followed: &[FollowedFeed], now: i64) {
    static LAST: std::sync::OnceLock<parking_lot::Mutex<HashMap<(String, String), i64>>> = std::sync::OnceLock::new();
    for feed in followed.iter().filter(|feed| feed.auto_download) {
        let key = (feed.publisher.clone(), feed.salt.clone());
        {
            let mut last = LAST.get_or_init(Default::default).lock();
            if last.get(&key).is_some_and(|at| !elapsed(now, *at, AUTO_RETRY_SECS)) {
                continue;
            }
            last.insert(key.clone(), now);
        }
        let db = state.db.clone();
        let feed = feed.clone();
        let pending = tokio::task::spawn_blocking(move || {
            if feed.auto_since == 0 {
                let _ = db.feed_start_auto_since(&feed.publisher, &feed.salt, now);
                return Vec::new();
            }
            db.feed_followed_items(&feed.publisher, &feed.salt)
                .unwrap_or_default()
                .into_iter()
                .filter(|item| auto_takes(&feed, item))
                .map(|item| item.item)
                .collect::<Vec<_>>()
        })
        .await
        .unwrap_or_default();
        if !pending.is_empty() && auto_download(app, state, &key.0, &key.1, &pending).await > 0 {
            let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "publisher": key.0, "salt": key.1 }));
        }
    }
}

/// Start what auto-download allows of a list's new items, by the feed's
/// settings as they are now rather than when the list was asked for.
/// Returns how many it started.
async fn auto_download(app: &tauri::AppHandle, state: &AppState, publisher: &str, salt: &str, added: &[FeedItem]) -> usize {
    let _pass = auto_download_lock().lock().await;
    let now = chrono::Utc::now().timestamp();
    let db = state.db.clone();
    let (key_pub, key_salt) = (publisher.to_string(), salt.to_string());
    let read = tokio::task::spawn_blocking(move || {
        let feed = db.feed_followed(&key_pub, &key_salt).ok().flatten()?;
        let spent = db.feed_auto_bytes(&key_pub, &key_salt, now).unwrap_or(0);
        let downloaded: std::collections::HashSet<String> = db
            .feed_followed_items(&key_pub, &key_salt)
            .unwrap_or_default()
            .into_iter()
            .filter(|item| item.downloaded)
            .map(|item| item.item.ed2k)
            .collect();
        let copies = db.feed_downloaded_elsewhere(&key_pub, &key_salt).unwrap_or_default();
        Some((feed, spent, downloaded, copies))
    })
    .await
    .ok()
    .flatten();
    let Some((feed, mut spent, downloaded, copies)) = read.filter(|(feed, ..)| feed.auto_download) else {
        return 0;
    };
    // A file another followed feed already has, in its folder: held, not
    // fetched a second time.
    let folders = state.config.read().await.settings.download_folders();
    let elsewhere = tokio::task::spawn_blocking(move || copies_elsewhere(&folders, copies))
        .await
        .unwrap_or_default();
    // Measured once: what this pass starts is not on disk yet, so it is
    // counted off as it goes.
    let mut room = auto_download_room(state).await;
    let mut started = 0;
    for item in added {
        if !auto_download_allows(&feed, item, spent) {
            continue;
        }
        // Held already, or on its way: nothing to start. A feed's files are
        // in no library, so one this feed started before counts as held.
        if downloaded.contains(&item.ed2k)
            || elsewhere.contains_key(&item.ed2k.to_ascii_lowercase())
            || state.local_index.read().await.get_by_hash(&item.ed2k).is_some()
            || state.transfer_manager.read().await.has_pending_for_hash(&item.ed2k)
        {
            continue;
        }
        let size = item.size.max(0) as u64;
        if room < size.saturating_add(AUTO_DOWNLOAD_HEADROOM) {
            continue;
        }
        if start_item_download(app, &feed, item).await.is_ok() {
            started += 1;
            room -= size;
            spent = spent.saturating_add(item.size);
            let db = state.db.clone();
            let (key_pub, key_salt, size) = (feed.publisher.clone(), feed.salt.clone(), item.size);
            let _ = tokio::task::spawn_blocking(move || db.feed_add_auto_bytes(&key_pub, &key_salt, now, size)).await;
        }
    }
    started
}

/// Free space on the download folder's drive, less what the downloads that
/// will write there have still to write. A `.part` grows as it fills, so
/// the drive's free space alone would count every byte they owe as free.
async fn auto_download_room(state: &AppState) -> u64 {
    let folders = state.config.read().await.settings.download_folders();
    let owed: Vec<(String, u64)> = state
        .transfer_manager
        .read()
        .await
        .get_all()
        .into_iter()
        .filter(|t| {
            matches!(t.direction, TransferDirection::Download)
                && !matches!(t.status, TransferStatus::Completed | TransferStatus::Failed)
        })
        .map(|t| {
            let left = t.total_size.saturating_sub(t.completed_size);
            (t.id, left)
        })
        .filter(|(_, left)| *left > 0)
        .collect();
    tokio::task::spawn_blocking(move || {
        let free = fs2::available_space(&folders.current).unwrap_or(0);
        free.saturating_sub(owed_on_current(&folders, &owed))
    })
    .await
    .unwrap_or(0)
}

/// What of `owed` (each download's id and bytes still to come) is owed to
/// the current download folder's volume: everything, unless an earlier
/// folder that may hold some of their `.part` files is on another volume.
/// Blocking when it is.
fn owed_on_current(folders: &DownloadFolders, owed: &[(String, u64)]) -> u64 {
    let elsewhere = folders.previous.iter().any(|folder| !same_volume(folder, &folders.current));
    owed.iter()
        .filter(|(id, _)| !elsewhere || same_volume(&folders.part_folder_for(id), &folders.current))
        .fold(0u64, |sum, (_, left)| sum.saturating_add(*left))
}

/// Whether `a` and `b` are on one volume, so what fills one fills the
/// other. Unknown counts as one: counting a download that is elsewhere only
/// holds auto-download back.
fn same_volume(a: &Path, b: &Path) -> bool {
    match (volume_of(a), volume_of(b)) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    }
}

#[cfg(windows)]
fn volume_of(path: &Path) -> Option<String> {
    use std::path::{Component, Prefix};
    match path.components().next()? {
        Component::Prefix(prefix) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => Some(char::from(letter).to_ascii_uppercase().to_string()),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(unix)]
fn volume_of(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    path.ancestors().find_map(|ancestor| std::fs::metadata(ancestor).ok()).map(|meta| meta.dev().to_string())
}

#[cfg(not(any(windows, unix)))]
fn volume_of(_path: &Path) -> Option<String> {
    None
}

// ── The service ────────────────────────────────────────────────────────────

/// Whether `bytes` are the list `head` names.
fn list_matches(bytes: &[u8], head: &FeedHead) -> bool {
    bytes.len() as u64 == head.list_size
        && hex_to16(&crate::network::ed2k::hash::ed2k_hash_bytes(bytes)).is_ok_and(|hash| hash == head.list_ed2k_hash)
        && *blake3::hash(bytes).as_bytes() == head.list_blake3
}

/// Write again the list a published feed's head names, gone from disk, from
/// its items: the same items, title and author make the same bytes. `false`
/// when they no longer do (an edit since, or another name to publish under)
/// or it could not be written.
fn rebuild_own_list(
    path: &Path,
    publisher: &[u8; 32],
    salt: &FeedSalt,
    head: &FeedHead,
    author: &str,
    items: &[FeedItem],
) -> bool {
    build_list(publisher, salt, &head.title, author, items)
        .is_ok_and(|bytes| list_matches(&bytes, head) && write_list(path, &bytes).is_ok())
}

/// Whether the list file at `path` is sealed, as every list since feeds
/// stopped naming their contents to the network is. One that is not was
/// written by an earlier build, in the clear.
fn list_is_sealed(path: &Path) -> bool {
    use std::io::Read;
    let mut magic = [0u8; 8];
    std::fs::File::open(path).and_then(|mut file| file.read_exact(&mut magic)).is_ok()
        && magic == *crate::network::ember::feed::SEALED_LIST_MAGIC
}

/// Serve again what was served before a restart: each published feed's
/// list and pending one, and each followed feed's held one. A published
/// list gone from disk is written again from its items when they still
/// make it; otherwise the feed is marked changed, to be published again,
/// and its head is not republished meanwhile (see [`republish`]). A pending
/// list gone from disk is forgotten.
///
/// A list an earlier build wrote in the clear is no longer served, and is
/// deleted: what it names is no longer told to whoever asks for its hash. A
/// feed of ours published with one is published again, sealed.
async fn reshare_held(app: &tauri::AppHandle, state: &AppState) {
    let dir = feeds_dir(app);
    let db = state.db.clone();
    let author = state.config.read().await.settings.channel_username.trim().to_string();
    let publisher = state.identity.ed25519_public_key;
    let resealed = {
        let _publishing = publish_lock().lock().await;
        let _followed = followed_lock().lock().await;
        tokio::task::spawn_blocking(move || reshare_lists(&db, &dir, &publisher, &author)).await.unwrap_or_default()
    };
    for salt in resealed {
        tracing::info!("feed {salt}: publishing it again with its list sealed");
        if let Err(error) = publish_feed(app.clone(), app.state::<AppState>(), salt.clone()).await {
            tracing::warn!("feed {salt}: could not publish it again sealed, so it waits for Publish: {error}");
        }
    }
}

/// [`reshare_held`]'s part on the blocking pool. The feeds of ours whose
/// list was in the clear, for publishing again.
fn reshare_lists(db: &crate::storage::database::Database, dir: &Path, publisher: &[u8; 32], author: &str) -> Vec<String> {
    let mut kept = std::collections::HashSet::new();
    let mut resealed = Vec::new();
    for feed in db.feeds_own().unwrap_or_default() {
        let path = own_list_path(dir, &feed.salt, feed.sequence);
        kept.insert(path.clone());
        let mut lists = own_lists(dir, &feed);
        let Ok(salt) = hex_to16(&feed.salt) else { continue };
        match own_head(&feed) {
            Some(head) if !list_file_whole(&path, head.list_size as i64) => {
                let _ = std::fs::remove_file(&path);
                let items = db.feed_own_items(&feed.salt).unwrap_or_default();
                if rebuild_own_list(&path, publisher, &salt, &head, author, &items) {
                    tracing::info!("feed {}: wrote its missing list again", feed.salt);
                } else {
                    tracing::warn!("feed {}: its list is missing and its items no longer make it", feed.salt);
                    let _ = db.feed_own_mark_changed(&feed.salt);
                    lists.retain(|list| list.sequence != feed.sequence);
                }
            }
            Some(_) if !list_is_sealed(&path) => {
                let _ = std::fs::remove_file(&path);
                let _ = db.feed_own_mark_changed(&feed.salt);
                lists.retain(|list| list.sequence != feed.sequence);
                resealed.push(feed.salt.clone());
            }
            Some(_) => {}
            None => lists.retain(|list| list.sequence != feed.sequence),
        }
        if let Some(pending) = &feed.pending {
            let path = own_list_path(dir, &feed.salt, pending.sequence);
            if list_file_whole(&path, pending.list_size) && list_is_sealed(&path) {
                kept.insert(path);
            } else {
                let _ = db.feed_own_set_pending(&feed.salt, None);
                lists.retain(|list| list.sequence != pending.sequence);
            }
        }
        for list in lists {
            feed_files::share_hidden(list.hash, &own_owner(&feed.salt), list.share);
        }
    }
    for feed in db.feeds_followed().unwrap_or_default() {
        let path = followed_list_path(dir, &feed.publisher, &feed.salt, feed.list_sequence);
        kept.insert(path.clone());
        if feed.list_sequence > 0 && !(list_file_whole(&path, feed.held_size) && list_is_sealed(&path)) {
            let _ = std::fs::remove_file(&path);
            let _ = db.feed_lost_held(&feed.publisher, &feed.salt);
            continue;
        }
        if let Ok(hash) = hex_to16(&feed.held_ed2k) {
            feed_files::share_hidden(
                hash,
                &followed_owner(&feed.publisher, &feed.salt),
                HiddenShare {
                    path,
                    size: feed.held_size.max(0) as u64,
                    name: list_share_name(),
                    ember_file_hash: feed.held_blake3.clone(),
                },
            );
        }
    }
    sweep_stray_lists(dir, &kept);
    resealed
}

/// Delete list files no feed holds: left by a crash, a failed write, or a
/// fetch that finished after its feed was unfollowed. Recent ones are left,
/// as a fetch or publish may be writing them now.
fn sweep_stray_lists(dir: &Path, kept: &std::collections::HashSet<PathBuf>) {
    const RECENT: Duration = Duration::from_secs(10 * 60);
    for sub in ["own", "followed"] {
        let Ok(entries) = std::fs::read_dir(dir.join(sub)) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let recent = entry
                .metadata()
                .and_then(|meta| meta.modified())
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_none_or(|age| age < RECENT);
            if !recent && path.is_file() && !kept.contains(&path) {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

/// When each feed of ours whose republish did not get through may try again.
fn republish_retry() -> &'static parking_lot::Mutex<HashMap<String, i64>> {
    static RETRY: std::sync::OnceLock<parking_lot::Mutex<HashMap<String, i64>>> = std::sync::OnceLock::new();
    RETRY.get_or_init(Default::default)
}

/// When `feed`'s head was last sent, by a publish or a republish.
fn last_sent(feed: &OwnFeed) -> i64 {
    feed.published_at.max(feed.refreshed_at)
}

/// Whether `feed` is due a republish at `now`: [`REPUBLISH_SECS`] after its
/// last, or at once while it has a pending head, which the user published
/// and no node is known to hold. Either waits for a retry set after a try.
fn republish_due(feed: &OwnFeed, now: i64) -> bool {
    let published = feed.published_at > 0 && elapsed(now, last_sent(feed), REPUBLISH_SECS);
    // A retry is set at most [`REPUBLISH_SECS`] ahead; one further off was
    // set before the clock went back.
    let retry_due = |at: &i64| now >= *at || *at - now > REPUBLISH_SECS;
    (published || feed.pending.is_some()) && republish_retry().lock().get(&feed.salt).is_none_or(retry_due)
}

/// Whether a republish is running: the tick starts at most one at a time.
fn republishing() -> &'static std::sync::Arc<std::sync::atomic::AtomicBool> {
    static RUNNING: std::sync::OnceLock<std::sync::Arc<std::sync::atomic::AtomicBool>> = std::sync::OnceLock::new();
    RUNNING.get_or_init(Default::default)
}

/// What a republish does with a feed of ours, given the newest head of it
/// the DHT holds.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Republish {
    /// Sign and send its head again (see [`republish_head`]).
    Send,
    /// Leave a newer head be: another device of this identity published
    /// it, and ours, re-signed now, would displace it.
    Yield,
    /// Record the newer head as published, then send it: it is the feed's
    /// pending one (see `OwnFeed::pending`), which did get out.
    Adopt(OwnPublish),
}

/// What to do with `feed` when `found` is the newest head of it the DHT
/// holds. A newer head is the pending one when its sequence and list are.
/// One naming the pending list or the last published one is ours all the
/// same, its publish not recorded: a pending head a later publish replaced,
/// say. Only a newer head naming another list is another device's.
fn republish_step(feed: &OwnFeed, found: Option<&FeedHead>) -> Republish {
    let Some(found) = found.filter(|found| found.sequence > feed.sequence.max(0) as u64) else {
        return Republish::Send;
    };
    let pending_list = feed.pending.as_ref().and_then(|pending| hex_to16(&pending.list_ed2k).ok());
    if let Some(pending) = &feed.pending {
        if pending.sequence.max(0) as u64 == found.sequence && pending_list == Some(found.list_ed2k_hash) {
            return Republish::Adopt(pending.clone());
        }
    }
    let ours = pending_list.into_iter().chain(hex_to16(&feed.list_ed2k).ok()).any(|hash| hash == found.list_ed2k_hash);
    if ours {
        Republish::Send
    } else {
        Republish::Yield
    }
}

/// The head a republish of `feed` signs, and whether it is the pending one.
/// The pending one while its list is on disk: that list is served, and the
/// user asked for it to be published, so the published head signed anew
/// would displace it at whichever storers hold it. Otherwise the published
/// one while its list is on disk. `None` when neither list is: followers
/// would be sent after nothing.
fn republish_head(dir: &Path, feed: &OwnFeed) -> Option<(FeedHead, bool)> {
    let on_disk = |head: &FeedHead| own_list_path(dir, &feed.salt, head.sequence as i64).is_file();
    if let Some(head) = feed.pending.as_ref().and_then(head_of).filter(on_disk) {
        return Some((head, true));
    }
    own_head(feed).filter(on_disk).map(|head| (head, false))
}

async fn read_own(state: &AppState, salt: &str) -> Option<OwnFeed> {
    let (db, key) = (state.db.clone(), salt.to_string());
    tokio::task::spawn_blocking(move || db.feed_own(&key)).await.ok().and_then(Result::ok).flatten()
}

/// Record `feed`'s pending head as published at `at`, and stop serving the
/// list it replaces. The feed as recorded; `None` when it could not be.
/// Called with [`publish_lock`] held.
async fn adopt_pending(state: &AppState, dir: &Path, feed: &OwnFeed, pending: &OwnPublish, at: i64) -> Option<OwnFeed> {
    let author = state.config.read().await.settings.channel_username.trim().to_string();
    let (db, key, task_pending) = (state.db.clone(), feed.salt.clone(), pending.clone());
    let publisher = state.identity.ed25519_public_key;
    let adopted = tokio::task::spawn_blocking(move || {
        let items = db.feed_own_items(&key)?;
        let salt = hex_to16(&key)?;
        // Up to date only if the items held still make its list.
        let made = build_list(&publisher, &salt, &task_pending.title, &author, &items)
            .is_ok_and(|bytes| crate::network::ed2k::hash::ed2k_hash_bytes(&bytes).eq_ignore_ascii_case(&task_pending.list_ed2k));
        if !db.feed_own_published(&key, &task_pending, made.then_some(items.as_slice()), at)? {
            return Ok(None);
        }
        db.feed_own(&key)
    })
    .await
    .ok()
    .and_then(Result::ok)
    .flatten()?;
    tracing::info!("feed {}: its pending head {} is stored", feed.salt, pending.sequence);
    let released = swap_own_lists(&own_owner(&feed.salt), &own_lists(dir, feed), &own_lists(dir, &adopted));
    withdraw_lists(state, released).await;
    Some(adopted)
}

/// What a republish records of its send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Republished {
    /// The published head is stored again: due again in [`REPUBLISH_SECS`].
    Refreshed,
    /// The pending head is stored: recorded as published, and the list it
    /// replaces no longer served.
    Adopted,
    /// Not known to be stored: tried again after [`REPUBLISH_RETRY_SECS`].
    /// A pending head stays pending, its list served, whether or not it got
    /// out: the user published it.
    Retry,
}

/// What a republish records when its send ended `placed`, having sent the
/// feed's pending head when `sent_pending`.
fn republished(placed: Placed, sent_pending: bool) -> Republished {
    match (placed, sent_pending) {
        (Placed::Stored, false) => Republished::Refreshed,
        (Placed::Stored, true) => Republished::Adopted,
        (Placed::Nowhere | Placed::Unknown, _) => Republished::Retry,
    }
}

/// Sign and send a head of ours again, so storers keep it: the pending one
/// while there is one (see [`republish_head`]). Waits on the network for the
/// lookup and the send without [`publish_lock`]; reads the feed and signs,
/// and records what came of it, with it held, and a publish or delete in
/// between wins. A feed with no head to send is not looked up, and waits
/// [`REPUBLISH_SECS`] or a publish. One that does not get through is tried
/// again after [`REPUBLISH_RETRY_SECS`].
async fn republish(app: &tauri::AppHandle, state: &AppState, salt: &str, now: i64) {
    let retry = || republish_retry().lock().insert(salt.to_string(), now + REPUBLISH_RETRY_SECS);
    let Ok(salt_bytes) = hex_to16(salt) else {
        retry();
        return;
    };
    let dir = feeds_dir(app);
    let Some(feed) = read_own(state, salt).await.filter(|feed| republish_due(feed, now)) else {
        return;
    };
    if republish_head(&dir, &feed).is_none() {
        tracing::info!("feed {salt}: no list on disk for a head to name; not republishing until it is published");
        republish_retry().lock().insert(salt.to_string(), now + REPUBLISH_SECS);
        return;
    }
    let publisher = state.identity.ed25519_public_key;
    let found = crate::commands::channels::find_raw_keys_counted(state, vec![feed_key(&publisher, &salt_bytes)], LOOKUP_TIMEOUT_MS)
        .await
        .ok()
        .flatten()
        .and_then(|(blobs, _)| best_head(&blobs, &publisher, &salt_bytes));
    let (record, blob, sent_pending, feed) = {
        let _publishing = publish_lock().lock().await;
        let Some(mut feed) = read_own(state, salt).await.filter(|feed| republish_due(feed, now)) else {
            return;
        };
        match republish_step(&feed, found.as_ref()) {
            Republish::Send => {}
            Republish::Yield => {
                tracing::info!("feed {salt} has a newer head from another device; not republishing ours");
                republish_retry().lock().insert(salt.to_string(), now + REPUBLISH_SECS);
                if feed.sequence > 0 {
                    let (db, key, sequence) = (state.db.clone(), salt.to_string(), feed.sequence);
                    let _ = tokio::task::spawn_blocking(move || db.feed_own_republished(&key, sequence, now)).await;
                }
                return;
            }
            // Its publish time stays the last one's, so a send that does not
            // get through is retried soon; a feed never published before has
            // none to keep.
            Republish::Adopt(pending) => {
                let at = if feed.published_at > 0 { feed.published_at } else { now };
                match adopt_pending(state, &dir, &feed, &pending, at).await {
                    Some(adopted) => feed = adopted,
                    None => {
                        retry();
                        return;
                    }
                }
            }
        }
        let Some((head, pending)) = republish_head(&dir, &feed) else {
            retry();
            return;
        };
        let Some((record, blob)) = sign_head(state, &salt_bytes, &head) else {
            retry();
            return;
        };
        let sent_pending = if pending { feed.pending.clone() } else { None };
        (record, blob, sent_pending, feed)
    };
    let placed = send_head(state, &salt_bytes, record).await;
    // Friends who follow and hold it already ignore it; one who followed
    // since, and whose lookup found nothing, takes it.
    if placed == Placed::Stored {
        let _ = state.network_tx.try_send(NetworkCommand::PushFeedHead { blob });
    }
    let _publishing = publish_lock().lock().await;
    // Published, settled or deleted meanwhile: that stands.
    let Some(current) = read_own(state, salt).await.filter(|current| {
        current.sequence == feed.sequence && current.published_at == feed.published_at && current.pending == feed.pending
    }) else {
        return;
    };
    let outcome = republished(placed, sent_pending.is_some());
    if outcome == Republished::Refreshed {
        republish_retry().lock().remove(salt);
        let (db, key, sequence) = (state.db.clone(), salt.to_string(), current.sequence);
        let _ = tokio::task::spawn_blocking(move || db.feed_own_republished(&key, sequence, now)).await;
        send_listing(state, &current, now).await;
        return;
    }
    let adopted = match (outcome, sent_pending) {
        (Republished::Adopted, Some(pending)) => adopt_pending(state, &dir, &current, &pending, now).await,
        _ => None,
    };
    if let Some(adopted) = adopted {
        republish_retry().lock().remove(salt);
        send_listing(state, &adopted, now).await;
        let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "salt": salt }));
    } else {
        retry();
    }
}

/// When `feed` is next due a lookup, spread by feed so they do not all come
/// at once. One whose last lookup reached no node is due again
/// [`LOOKUP_RETRY_SECS`] after it, and one never found every
/// [`WAITING_POLL_SECS`] for its first day.
fn lookup_due(feed: &FollowedFeed, now: i64) -> bool {
    let spread = i64::from(u16::from_str_radix(feed.salt.get(..4).unwrap_or("0"), 16).unwrap_or(0)) % POLL_JITTER_SECS;
    let missed = missed_lookups()
        .lock()
        .get(&(feed.publisher.clone(), feed.salt.clone()))
        .is_some_and(|at| !elapsed(now, *at, LOOKUP_RETRY_SECS));
    let waiting = feed.sequence == 0 && !elapsed(now, feed.followed_at, WAITING_FAST_FOR_SECS);
    let interval = if waiting { WAITING_POLL_SECS } else { POLL_SECS + spread };
    !missed && elapsed(now, feed.checked_at, interval)
}

async fn on_tick(app: &tauri::AppHandle, state: &AppState) {
    let now = chrono::Utc::now().timestamp();
    // What each fetch holds now, then those that have stalled, given up on
    // whether or not Ember is on now.
    let held: HashMap<String, (u64, u32)> = {
        let ids: Vec<String> = fetching().lock().keys().cloned().collect();
        let manager = state.transfer_manager.read().await;
        ids.into_iter()
            .filter_map(|id| {
                let t = manager.get_transfer(&id)?;
                Some((id, (t.completed_size.max(t.transferred), t.active_sources + t.queued_sources)))
            })
            .collect()
    };
    let stale: Vec<(String, Fetching)> = {
        let mut fetching = fetching().lock();
        let instant = Instant::now();
        for (id, fetch) in fetching.iter_mut() {
            if let Some((bytes, sources)) = held.get(id) {
                fetch.note(*bytes, *sources, instant);
            }
        }
        fetching.iter().filter(|(_, f)| f.stalled(instant)).map(|(id, f)| (id.clone(), f.clone())).collect()
    };
    for (id, fetch) in stale {
        tracing::info!(
            "feed {}: gave up fetching its list after {} min ({} bytes, no source for {} min)",
            fetch.salt,
            fetch.started.elapsed().as_secs() / 60,
            fetch.bytes,
            fetch.progressed.elapsed().as_secs() / 60
        );
        cancel_fetch(state, &id).await;
        gave_up().lock().insert((fetch.publisher.clone(), fetch.salt.clone()), now);
        let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "publisher": fetch.publisher, "salt": fetch.salt }));
    }
    feed_files::forget_cancelled_fetches(CANCELLED_FETCH_GRACE);
    record_feed_downloads(app, state, now).await;
    refresh_served_files(state).await;
    // Not held back by a locked chat key: nothing of a feed is sealed with it.
    if crate::commands::channels::require_ember(state).await.is_err() {
        return;
    }
    send_due_withdrawals(state, now).await;
    // Our own heads, republished before they age: the longest due, off the
    // tick, unless one is being republished now.
    let db = state.db.clone();
    let own = tokio::task::spawn_blocking(move || db.feeds_own().unwrap_or_default()).await.unwrap_or_default();
    let due = own.iter().filter(|feed| republish_due(feed, now)).min_by_key(|feed| last_sent(feed));
    if let Some(feed) = due {
        if !republishing().swap(true, std::sync::atomic::Ordering::AcqRel) {
            let (app, salt) = (app.clone(), feed.salt.clone());
            tauri::async_runtime::spawn(async move {
                let _done = ClearOnDrop(republishing().clone());
                if let Some(state) = app.try_state::<AppState>() {
                    republish(&app, &state, &salt, now).await;
                }
            });
        }
    }
    // Our feeds' followers, counted off the tick, one feed at a time.
    if !counting_followers().swap(true, std::sync::atomic::Ordering::AcqRel) {
        let app = app.clone();
        let own = own.clone();
        tauri::async_runtime::spawn(async move {
            let _done = ClearOnDrop(counting_followers().clone());
            if let Some(state) = app.try_state::<AppState>() {
                count_due_followers(&app, &state, &own, now).await;
            }
        });
    }
    // Heads friends pushed while their feeds' gates were shut.
    let due = due_pushed_heads(&mut push_gates().lock(), Instant::now());
    for ((publisher, salt), head) in due {
        take_head(app, state, &publisher, &salt, head).await;
    }
    // Followed feeds: a list owed, or a lookup due, the longest unchecked
    // first.
    let db = state.db.clone();
    let mut followed =
        tokio::task::spawn_blocking(move || db.feeds_followed().unwrap_or_default()).await.unwrap_or_default();
    for feed in &followed {
        if feed.sequence > 0 && feed.list_sequence != feed.sequence && feed.state != "broken" {
            fetch_owed(app, state, &feed.publisher, &feed.salt, now).await;
        }
    }
    retry_auto_downloads(app, state, &followed, now).await;
    followed.sort_by_key(|feed| feed.checked_at);
    for feed in followed.iter().filter(|feed| lookup_due(feed, now)).take(LOOKUPS_PER_TICK) {
        look_up_head(app, state, &feed.publisher, &feed.salt).await;
    }
}

struct ClearOnDrop(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Drop for ClearOnDrop {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}

/// Keep feeds current for the life of the app.
pub fn spawn_feeds(app: tauri::AppHandle) {
    spawn_hold_watcher(app.clone());
    tauri::async_runtime::spawn(async move {
        let mut reports = feed_files::listen_for_fetches();
        let mut pushed = feed_files::listen_for_pushed_heads();
        // Long enough for the network to come up.
        tokio::time::sleep(Duration::from_secs(30)).await;
        if let Some(state) = app.try_state::<AppState>() {
            reshare_held(&app, &state).await;
        }
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // A tick's lookups take up to a minute; run off the loop, one at a
        // time, so lists and pushed heads are not kept waiting meanwhile.
        let ticking = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        loop {
            tokio::select! {
                report = reports.recv() => {
                    let Some((id, outcome)) = report else { return };
                    if let Some(state) = app.try_state::<AppState>() {
                        on_fetch_done(&app, &state, id, outcome).await;
                    }
                }
                head = pushed.recv() => {
                    let Some((from, blob)) = head else { return };
                    if let Some(state) = app.try_state::<AppState>() {
                        on_pushed_head(&app, &state, from, blob).await;
                    }
                }
                () = crate::network::feed_direct::downloads_noted().notified() => {
                    if let Some(state) = app.try_state::<AppState>() {
                        record_feed_downloads(&app, &state, chrono::Utc::now().timestamp()).await;
                    }
                }
                _ = tick.tick() => {
                    if ticking.swap(true, std::sync::atomic::Ordering::AcqRel) {
                        continue;
                    }
                    let (app, ticking) = (app.clone(), ticking.clone());
                    tauri::async_runtime::spawn(async move {
                        // Cleared however the tick ends, a panic included.
                        let _ticked = ClearOnDrop(ticking);
                        if let Some(state) = app.try_state::<AppState>() {
                            on_tick(&app, &state).await;
                        }
                    });
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn followed(auto_item: i64, auto_day: i64) -> FollowedFeed {
        FollowedFeed {
            publisher: "p".into(),
            salt: "0010".into(),
            title: "T".into(),
            description: String::new(),
            sequence: 2,
            list_ed2k: String::new(),
            list_blake3: String::new(),
            list_size: 0,
            item_count: 0,
            state: "ok".into(),
            list_sequence: 2,
            held_ed2k: String::new(),
            held_blake3: String::new(),
            held_size: 0,
            unread: 0,
            followed_at: 0,
            checked_at: 0,
            auto_download: true,
            auto_max_item_mib: auto_item,
            auto_max_day_mib: auto_day,
            folder: String::new(),
            auto_since: 0,
            seen_at: 0,
        }
    }

    fn item(name: &str, mib: i64) -> FeedItem {
        FeedItem { ed2k: "e".into(), name: name.into(), size: mib * 1024 * 1024, aich: String::new(), blake3: String::new(), note: String::new() }
    }

    #[test]
    fn auto_download_keeps_to_its_caps_and_never_starts_a_program() {
        let feed = followed(100, 150);
        assert!(auto_download_allows(&feed, &item("track.flac", 50), 0));
        assert!(!auto_download_allows(&feed, &item("big.mkv", 101), 0), "over the item cap");
        assert!(!auto_download_allows(&feed, &item("track.flac", 60), 100 * 1024 * 1024), "over the day's");
        assert!(!auto_download_allows(&feed, &item("setup.exe", 1), 0), "a program");
        assert!(!auto_download_allows(&feed, &item("invoice.pdf.bat", 1), 0), "a script behind a document's name");
        assert!(auto_download_allows(&followed(0, 0), &item("huge.mkv", 4000), 0), "no caps set");
    }

    #[test]
    fn auto_download_refuses_what_can_run_and_allows_files() {
        for name in [
            "setup.EXE", "patch.msp", "tool.ps1", "page.hta", "Start.lnk", "game.iso", "disk.vhdx", "budget.xlsm",
            "notes.docm", "app.appref-ms", "x.settingcontent-ms", "install.sh", "run.py", "Thing.dmg", "lib.dll",
            "setup.exe.", "setup.exe  ", "data.application",
            // Unix shells and launchers, libraries, and Electron archives.
            "build.bash", "start.desktop", "libfoo.so", "libbar.dylib", "app.asar",
            // macOS.
            "Run.command", "fix.tool", "do.scpt", "Clean.workflow", "Setup.pkg", "Thing.app",
            // Configuration programs load by name.
            "desktop.ini", "launch.plist", "app.exe.config", "settings.json",
            // Hidden files.
            ".bashrc", ".hidden.zip", ".profile",
        ] {
            assert!(auto_download_refuses(name), "{name}");
        }
        for name in ["track.flac", "Show.S01E01.mkv", "photo.JPG", "book.pdf", "notes.docx", "README", "archive.zip"] {
            assert!(!auto_download_refuses(name), "{name}");
        }
    }

    #[test]
    fn auto_download_refuses_program_files_and_allows_untyped_ones() {
        let feed = followed(0, 0);
        assert!(!auto_download_allows(&feed, &item("setup.exe", 1), 0));
        assert!(!auto_download_allows(&feed, &item("run.bat", 1), 0));
        assert!(auto_download_allows(&feed, &item("Show.S01E01.mkv", 1), 0));
        assert!(auto_download_allows(&feed, &item("readme", 1), 0), "a name with no extension");
    }

    #[test]
    fn an_auto_download_cap_is_saved_as_given_with_0_for_no_limit() {
        assert_eq!(auto_cap(0), 0);
        assert_eq!(auto_cap(50), 50);
        assert_eq!(auto_cap(-5), 0, "clamped");
        assert_eq!(auto_cap(i64::MAX), 1 << 30, "clamped");
    }

    #[test]
    fn downloads_to_come_count_against_the_room_on_their_drive() {
        let folders = DownloadFolders { current: PathBuf::from("C:\\Downloads"), previous: Vec::new() };
        let owed = vec![("a".to_string(), 100), ("b".to_string(), u64::MAX)];
        assert_eq!(owed_on_current(&folders, &owed), u64::MAX, "saturates");
        assert_eq!(owed_on_current(&folders, &owed[..1]), 100);
        assert_eq!(owed_on_current(&folders, &[]), 0);
    }

    #[cfg(windows)]
    #[test]
    fn a_download_whose_part_file_is_on_another_drive_leaves_the_room_alone() {
        let previous = std::env::temp_dir().join(format!("ember-feed-room-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir_all(previous.join("Temp")).unwrap();
        let there = format!("feed-room-there-{}", rand::random::<u64>());
        let fresh = format!("feed-room-new-{}", rand::random::<u64>());
        std::fs::write(previous.join("Temp").join(format!("{there}.part")), b"x").unwrap();
        // The current folder on a drive other than the temp folder's.
        let drive = if volume_of(&previous).as_deref() == Some("Q") { "R" } else { "Q" };
        let folders = DownloadFolders { current: PathBuf::from(format!("{drive}:\\Downloads")), previous: vec![previous.clone()] };
        assert_eq!(folders.part_folder_for(&there), previous, "found by its .part");
        let owed = vec![(there, 1_000), (fresh, 7)];
        assert_eq!(owed_on_current(&folders, &owed), 7, "only the one that will write to the current drive");
        let _ = std::fs::remove_dir_all(&previous);
    }

    #[cfg(windows)]
    #[test]
    fn volumes_are_told_apart_by_drive() {
        assert!(same_volume(Path::new("C:\\a"), Path::new("c:\\b\\c")));
        assert!(same_volume(Path::new("\\\\?\\C:\\a"), Path::new("C:\\b")));
        assert!(!same_volume(Path::new("C:\\a"), Path::new("D:\\a")));
        assert!(same_volume(Path::new("\\\\server\\share\\a"), Path::new("D:\\a")), "unknown counts as the same");
    }

    fn pushed(sequence: u64) -> FeedHead {
        FeedHead {
            sequence,
            list_ed2k_hash: [1; 16],
            list_size: 100,
            list_blake3: [2; 32],
            item_count: 1,
            title: "T".into(),
            description: String::new(),
        }
    }

    #[test]
    fn pushed_heads_are_taken_once_per_interval_and_the_newest_waits() {
        let mut gates = PushGates::new();
        let key = ("p".to_string(), "s".to_string());
        let start = Instant::now();
        assert_eq!(gate_pushed_head(&mut gates, key.clone(), pushed(1), start).map(|h| h.sequence), Some(1));
        for sequence in [5, 3, 4] {
            assert!(gate_pushed_head(&mut gates, key.clone(), pushed(sequence), start + Duration::from_secs(1)).is_none());
        }
        assert!(due_pushed_heads(&mut gates, start + Duration::from_secs(60)).is_empty(), "the gate is shut");
        let later = start + PUSHED_HEAD_INTERVAL;
        let due = due_pushed_heads(&mut gates, later);
        assert_eq!(due.iter().map(|(k, h)| (k.clone(), h.sequence)).collect::<Vec<_>>(), vec![(key.clone(), 5)]);
        assert!(gate_pushed_head(&mut gates, key.clone(), pushed(6), later).is_none(), "taking it shut the gate again");
        // Open again: the one pushed now is taken, or the newer one kept.
        let again = later + PUSHED_HEAD_INTERVAL;
        assert_eq!(gate_pushed_head(&mut gates, key.clone(), pushed(2), again).map(|h| h.sequence), Some(6));
        assert!(due_pushed_heads(&mut gates, again + PUSHED_HEAD_INTERVAL).is_empty());
        assert!(gates.is_empty(), "an open gate with nothing kept is forgotten");
    }

    #[test]
    fn a_missing_own_list_is_written_again_only_when_its_items_still_make_it() {
        let items = vec![FeedItem {
            ed2k: "00112233445566778899aabbccddeeff".into(),
            name: "song.flac".into(),
            size: 9,
            aich: String::new(),
            blake3: "cd".repeat(32),
            note: String::new(),
        }];
        let (publisher, salt) = ([0x51; 32], [0x52; 16]);
        let bytes = build_list(&publisher, &salt, "T", "me", &items).unwrap();
        let head = FeedHead {
            sequence: 3,
            list_ed2k_hash: hex_to16(&crate::network::ed2k::hash::ed2k_hash_bytes(&bytes)).unwrap(),
            list_size: bytes.len() as u64,
            list_blake3: *blake3::hash(&bytes).as_bytes(),
            item_count: 1,
            title: "T".into(),
            description: String::new(),
        };
        let dir = std::env::temp_dir().join(format!("ember-feed-rebuild-{}-{}", std::process::id(), rand::random::<u64>()));
        let path = dir.join("own").join("list.emulecollection");
        assert!(!rebuild_own_list(&path, &publisher, &salt, &head, "someone else", &items), "another author");
        assert!(!path.exists());
        let edited = vec![FeedItem { note: "new".into(), ..items[0].clone() }];
        assert!(!rebuild_own_list(&path, &publisher, &salt, &head, "me", &edited), "an edit since");
        assert!(!rebuild_own_list(&path, &publisher, &[0x53; 16], &head, "me", &items), "another feed's");
        assert!(rebuild_own_list(&path, &publisher, &salt, &head, "me", &items));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(list_is_sealed(&path));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A list names nothing to whoever fetches it by its hash: its title,
    /// author and files are sealed under its feed's salt, which only the
    /// feed's link holds.
    #[test]
    fn a_list_is_sealed_to_its_feed() {
        let items = vec![FeedItem {
            ed2k: "00112233445566778899aabbccddeeff".into(),
            name: "Secret holiday film.mkv".into(),
            size: 9,
            aich: String::new(),
            blake3: "cd".repeat(32),
            note: String::new(),
        }];
        let (publisher, salt) = ([0x51; 32], [0x52; 16]);
        let bytes = build_list(&publisher, &salt, "Private title", "me", &items).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("Secret holiday") && !text.contains("Private title") && !text.contains("0011223344"));
        let (key, salt_hex) = (hex::encode(publisher), hex::encode(salt));
        let opened = open_list_collection(&key, &salt_hex, &bytes).expect("opens for its feed");
        assert_eq!(opened.name, "Private title");
        assert_eq!(opened.files[0].name, "Secret holiday film.mkv");
        assert!(open_list_collection(&key, &hex::encode([0x53u8; 16]), &bytes).is_none(), "another feed");
        assert!(open_list_collection(&hex::encode([0x54u8; 32]), &salt_hex, &bytes).is_none(), "another publisher");
        let mut tampered = bytes.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open_list_collection(&key, &salt_hex, &tampered).is_none(), "tampered with");
    }

    #[test]
    fn followers_are_the_distinct_others_serving_a_list_of_the_feed() {
        use crate::network::ember::dht::publish::SourceContact;
        let key = |seed: u8| crate::network::ember::crypto::signing_key_from_bytes(&[seed; 32]);
        let (me, ann, bob, eve) = (key(4), key(5), key(6), key(7));
        let (current, earlier, other) = ([1u8; 16], [2u8; 16], [3u8; 16]);
        let source = |list: [u8; 16], key: &ed25519_dalek::SigningKey| {
            let record = SignedRecord::source(list, [0; 32], 100, "", SourceContact::default(), key);
            [record.data, record.signature.to_vec()].concat()
        };
        let mut tampered = source(current, &eve);
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        let blobs = vec![
            source(current, &me),
            source(current, &ann),
            source(earlier, &ann),
            source(earlier, &bob),
            source(other, &eve),
            tampered,
            vec![0u8; 10],
        ];
        let own = me.verifying_key().to_bytes();
        let mut followers = std::collections::HashSet::new();
        followers_in(&blobs, &current, &own, &mut followers);
        assert_eq!(followers.len(), 1, "Ann: not us, nor Eve's tampered record");
        followers_in(&blobs, &earlier, &own, &mut followers);
        assert_eq!(followers.len(), 2, "Ann once across both lists, and Bob");
        followers_in(&blobs, &[9u8; 16], &own, &mut followers);
        assert_eq!(followers.len(), 2, "a list nobody serves adds none");
    }

    #[test]
    fn a_follower_count_is_due_after_its_interval_and_a_failed_one_sooner() {
        let fresh = HeldCount::default();
        assert!(fresh.due(1_000_000), "never counted");
        let counted = HeldCount {
            count: Some(FollowerCount { count: 3, at_least: false, checked_at: 1_000 }),
            tried_at: 1_000,
            lists: Vec::new(),
        };
        assert!(!counted.due(1_000 + FOLLOWER_COUNT_SECS - 1));
        assert!(counted.due(1_000 + FOLLOWER_COUNT_SECS));
        let unanswered = HeldCount { tried_at: 1_000, ..HeldCount::default() };
        assert!(!unanswered.due(1_000 + FOLLOWER_RETRY_SECS - 1));
        assert!(unanswered.due(1_000 + FOLLOWER_RETRY_SECS), "no node answered: tried again soon");
    }

    #[test]
    fn the_newest_head_by_its_publisher_wins_and_others_are_ignored() {
        let me = crate::network::ember::crypto::signing_key_from_bytes(&[4u8; 32]);
        let stranger = crate::network::ember::crypto::signing_key_from_bytes(&[5u8; 32]);
        let salt = [6u8; 16];
        let head = |sequence: u64| FeedHead {
            sequence,
            list_ed2k_hash: [1; 16],
            list_size: 100,
            list_blake3: [2; 32],
            item_count: 1,
            title: "T".into(),
            description: String::new(),
        };
        let blob = |key: &ed25519_dalek::SigningKey, sequence: u64| {
            let record = SignedRecord::feed_head_record(&salt, &head(sequence), key, 1).unwrap();
            [record.data, record.signature.to_vec()].concat()
        };
        let pk = me.verifying_key().to_bytes();
        let blobs = vec![blob(&me, 5), blob(&me, 9), blob(&stranger, 50), vec![0u8; 10]];
        assert_eq!(best_head(&blobs, &pk, &salt).map(|h| h.sequence), Some(9));
        assert!(best_head(&blobs, &pk, &[7u8; 16]).is_none(), "another feed of theirs");

        let large = {
            let record = SignedRecord::feed_head_record(
                &salt,
                &FeedHead { list_size: MAX_LIST_BYTES + 1, ..head(12) },
                &me,
                1,
            )
            .unwrap();
            [record.data, record.signature.to_vec()].concat()
        };
        let blobs = [blobs, vec![large]].concat();
        assert_eq!(newest_head(&blobs, &pk, &salt).map(|h| h.sequence), Some(12), "a lookup sees it is too large");
        assert_eq!(best_head(&blobs, &pk, &salt).map(|h| h.sequence), Some(9), "a republish keeps to one it can serve");
    }

    #[test]
    fn a_list_fetch_gives_up_only_with_nothing_coming_or_after_its_most() {
        let fetch = Fetching::new("p", "s", 1);
        let start = fetch.started;
        assert!(!fetch.stalled(start + FETCH_TIMEOUT - Duration::from_secs(1)));
        assert!(fetch.stalled(start + FETCH_TIMEOUT), "no byte and no source");

        let mut fetch = Fetching::new("p", "s", 1);
        let start = fetch.started;
        fetch.note(0, 1, start + FETCH_TIMEOUT - Duration::from_secs(1));
        assert!(!fetch.stalled(start + FETCH_TIMEOUT), "queued at a source");
        let later = start + FETCH_TIMEOUT * 2;
        fetch.note(500, 0, later);
        assert!(!fetch.stalled(later + FETCH_TIMEOUT - Duration::from_secs(1)), "bytes came");
        fetch.note(400, 0, later + Duration::from_secs(60));
        assert_eq!(fetch.bytes, 500, "a part file read short is not a loss");
        assert!(fetch.stalled(later + FETCH_TIMEOUT), "fewer bytes are no progress");
        fetch.note(0, 3, start + FETCH_MAX);
        assert!(fetch.stalled(start + FETCH_MAX), "however busy, it has run its most");
        assert_eq!(fetch.sources, 3);
    }

    #[test]
    fn a_transfers_status_is_shown_as_its_items() {
        use crate::types::TransferStatus as S;
        assert_eq!(ItemStatus::of(&S::Active), ItemStatus::Downloading);
        assert_eq!(ItemStatus::of(&S::Hashing), ItemStatus::Downloading);
        assert_eq!(ItemStatus::of(&S::Searching), ItemStatus::Queued);
        assert_eq!(ItemStatus::of(&S::Insufficient), ItemStatus::Queued);
        assert_eq!(ItemStatus::of(&S::Stopped), ItemStatus::Paused);
        assert_eq!(ItemStatus::of(&S::Failed), ItemStatus::Failed);
        assert_eq!(ItemStatus::of(&S::Completed), ItemStatus::Done);
        assert_eq!(serde_json::to_value(ItemStatus::InLibrary).unwrap(), "in_library");
    }

    #[test]
    fn auto_download_takes_only_what_came_since_it_was_turned_on() {
        let mut feed = followed(0, 0);
        feed.auto_since = 100;
        let listed = |first_seen: i64| FollowedItem {
            item: item("a.flac", 1),
            first_seen,
            is_new: true,
            removed: false,
            downloaded: false,
            cancelled: false,
        };
        assert!(auto_takes(&feed, &listed(100)));
        assert!(!auto_takes(&feed, &listed(99)), "there before");
        assert!(!auto_takes(&feed, &FollowedItem { downloaded: true, ..listed(200) }), "asked for already");
        assert!(!auto_takes(&feed, &FollowedItem { removed: true, ..listed(200) }), "no longer listed");
        feed.auto_since = 0;
        assert!(!auto_takes(&feed, &listed(200)), "no window yet");
        feed.auto_since = 100;
        feed.auto_download = false;
        assert!(!auto_takes(&feed, &listed(200)), "off");
    }

    #[test]
    fn auto_download_says_why_it_holds_a_file_back() {
        let feed = followed(100, 150);
        const MIB: i64 = 1024 * 1024;
        assert_eq!(auto_hold_reason(&feed, &item("setup.exe", 1), 0), Some("risky"));
        assert_eq!(auto_hold_reason(&feed, &item("big.mkv", 101), 0), Some("too_large"));
        assert_eq!(auto_hold_reason(&feed, &item("track.flac", 60), 100 * MIB), Some("day_limit"));
        assert_eq!(auto_hold_reason(&feed, &item("track.flac", 50), 100 * MIB), None, "exactly at the day's cap");
        assert_eq!(auto_hold_reason(&followed(0, 0), &item("huge.mkv", 4000), i64::MAX), None, "no caps");
    }

    #[test]
    fn a_feeds_files_are_found_in_its_folder_under_any_download_folder() {
        let base = std::env::temp_dir().join(format!("ember-feed-files-{}-{}", std::process::id(), rand::random::<u64>()));
        let (current, previous) = (base.join("now"), base.join("before"));
        let put = |root: &Path, name: &str, bytes: &[u8]| {
            let dir = crate::sharing::feed_downloads::folder_dir(root, "Mixes");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(name), bytes).unwrap();
            dir.join(name)
        };
        let here = put(&current, "One.flac", b"abc");
        put(&previous, "Two.flac", b"abcdef");
        std::fs::create_dir_all(crate::sharing::feed_downloads::folder_dir(&current, "Mixes").join("sub")).unwrap();
        let folders = DownloadFolders { current: current.clone(), previous: vec![previous.clone()] };
        let finished = vec![
            ("aa".to_string(), here.to_string_lossy().into_owned()),
            ("bb".to_string(), current.join("gone.flac").to_string_lossy().into_owned()),
        ];
        let (on_disk, gone) = feed_folder_files(&folders, "Mixes", &finished);
        assert_eq!(on_disk.get(&file_name_key("One.flac")), Some(&vec![3]));
        assert_eq!(on_disk.get(&file_name_key("Two.flac")), Some(&vec![6]), "under an earlier download folder");
        assert!(!on_disk.contains_key(&file_name_key("sub")), "a folder is not a file");
        assert_eq!(gone.into_iter().collect::<Vec<_>>(), vec!["bb".to_string()]);
        assert!(feed_folder_files(&folders, "", &[]).0.is_empty(), "no folder yet");
        assert_eq!(file_name_key("A.flac") == file_name_key("a.flac"), cfg!(any(windows, target_os = "macos")));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_copy_another_feed_has_counts_only_while_it_is_there() {
        use crate::storage::database::ElsewhereCopy;
        let base = std::env::temp_dir().join(format!("ember-feed-elsewhere-{}-{}", std::process::id(), rand::random::<u64>()));
        let (current, previous) = (base.join("now"), base.join("before"));
        let dir = crate::sharing::feed_downloads::folder_dir(&previous, "Other");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("One.flac"), b"abc").unwrap();
        let folders = DownloadFolders { current, previous: vec![previous] };
        let copy = |ed2k: &str, name: &str, size: i64| ElsewhereCopy {
            ed2k: ed2k.into(),
            folder: "Other".into(),
            title: "Other feed".into(),
            name: name.into(),
            size,
        };
        let found = copies_elsewhere(
            &folders,
            vec![copy("AA", "One.flac", 3), copy("bb", "One.flac", 4), copy("cc", "Two.flac", 3)],
        );
        assert_eq!(found.get("aa").map(String::as_str), Some("Other feed"), "under an earlier download folder");
        assert!(!found.contains_key("bb"), "not the size it was listed at");
        assert!(!found.contains_key("cc"), "not there");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_list_is_whole_only_at_the_size_its_head_names() {
        let dir = std::env::temp_dir().join(format!("ember-feed-whole-{}-{}", std::process::id(), rand::random::<u64>()));
        let path = dir.join("lists").join("3.emulecollection");
        assert!(!list_file_whole(&path, 0), "not there");
        write_list(&path, b"hello").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        assert!(!path.with_extension("tmp").exists(), "renamed into place");
        assert!(list_file_whole(&path, 5));
        assert!(!list_file_whole(&path, 6), "cut short");
        write_list(&path, b"hi").unwrap();
        assert!(list_file_whole(&path, 2), "replaced");
        assert!(!list_file_whole(&dir, 0), "a folder");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_list_that_does_not_match_its_head_is_refused() {
        let items = vec![FeedItem {
            ed2k: "00112233445566778899aabbccddeeff".into(),
            name: "song.flac".into(),
            size: 9,
            aich: String::new(),
            blake3: "cd".repeat(32),
            note: "best one".into(),
        }];
        let path = std::env::temp_dir().join(format!("ember-feed-list-{}-{}.emulecollection", std::process::id(), rand::random::<u64>()));
        let (publisher, salt) = ([0x61; 32], [0x62; 16]);
        let matching = |items: &[FeedItem]| {
            let bytes = build_list(&publisher, &salt, "T", "me", items).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            let mut feed = followed(0, 0);
            (feed.publisher, feed.salt) = (hex::encode(publisher), hex::encode(salt));
            feed.list_size = bytes.len() as i64;
            feed.list_ed2k = crate::network::ed2k::hash::ed2k_hash_bytes(&bytes);
            feed.list_blake3 = blake3::hash(&bytes).to_hex().to_string();
            feed.item_count = items.len() as i64;
            feed
        };
        let mut feed = matching(&items);
        assert_eq!(read_list(&path, &feed), Ok(items.clone()));
        feed.item_count = 2;
        assert_eq!(read_list(&path, &feed), Err(ListError::Broken), "not the head's item count");
        feed.item_count = 1;
        feed.list_blake3 = "00".repeat(32);
        assert_eq!(read_list(&path, &feed), Err(ListError::Broken));

        let malformed = [
            FeedItem { ed2k: "ff".repeat(16), blake3: String::new(), ..items[0].clone() },
            FeedItem { ed2k: "zz".repeat(16), ..items[0].clone() },
            FeedItem { ed2k: "ee".repeat(16), size: 0, ..items[0].clone() },
        ];
        for bad in malformed {
            let both = vec![items[0].clone(), bad];
            let feed = matching(&both);
            assert_eq!(read_list(&path, &feed), Err(ListError::Broken), "one entry no one could fetch");
        }
        let feed = matching(&[items[0].clone(), items[0].clone()]);
        assert_eq!(read_list(&path, &feed), Ok(items.clone()), "an entry twice is taken once");

        let _ = std::fs::remove_file(&path);
        assert_eq!(read_list(&path, &feed), Err(ListError::Unreadable), "a file that cannot be read is not broken");
    }

    #[test]
    fn a_republish_signs_what_was_published_not_an_edit_since() {
        let mut feed = OwnFeed {
            salt: "00".repeat(16),
            title: "Edited".into(),
            description: "new words".into(),
            sequence: 7,
            list_ed2k: "11".repeat(16),
            list_blake3: "22".repeat(32),
            list_size: 50,
            item_count: 1,
            created_at: 0,
            published_at: 1,
            refreshed_at: 0,
            published_title: "Published".into(),
            published_description: "old words".into(),
            changed: true,
            pending: None,
            listed: false,
            listing_sent_at: 0,
        };
        let head = own_head(&feed).unwrap();
        assert_eq!((head.title.as_str(), head.description.as_str(), head.sequence), ("Published", "old words", 7));
        feed.published_title.clear();
        assert_eq!(own_head(&feed).unwrap().title, "Edited", "published by a build that kept no copy");
    }

    fn own(sequence: i64, pending: Option<OwnPublish>) -> OwnFeed {
        OwnFeed {
            salt: "00".repeat(16),
            title: "T".into(),
            description: String::new(),
            sequence,
            list_ed2k: "11".repeat(16),
            list_blake3: "22".repeat(32),
            list_size: 50,
            item_count: 1,
            created_at: 0,
            published_at: 1,
            refreshed_at: 0,
            published_title: "T".into(),
            published_description: String::new(),
            changed: false,
            pending,
            listed: false,
            listing_sent_at: 0,
        }
    }

    fn pending(sequence: i64, list: u8) -> OwnPublish {
        OwnPublish {
            sequence,
            list_ed2k: hex::encode([list; 16]),
            list_blake3: "33".repeat(32),
            list_size: 60,
            item_count: 2,
            title: "T".into(),
            description: String::new(),
        }
    }

    fn found(sequence: u64, list: u8) -> FeedHead {
        FeedHead { list_ed2k_hash: [list; 16], ..pushed(sequence) }
    }

    #[test]
    fn a_republish_sends_yields_to_another_device_or_adopts_its_pending_head() {
        let plain = own(7, None);
        assert_eq!(republish_step(&plain, None), Republish::Send, "nothing found");
        assert_eq!(republish_step(&plain, Some(&found(7, 0x11))), Republish::Send, "its own head");
        assert_eq!(republish_step(&plain, Some(&found(5, 0x44))), Republish::Send, "an older one");
        assert_eq!(republish_step(&plain, Some(&found(9, 0x44))), Republish::Yield, "another device's");

        let waiting = own(7, Some(pending(9, 0x44)));
        assert_eq!(republish_step(&waiting, Some(&found(9, 0x44))), Republish::Adopt(pending(9, 0x44)));
        assert_eq!(republish_step(&waiting, Some(&found(9, 0x55))), Republish::Yield, "another list at that sequence");
        assert_eq!(republish_step(&waiting, Some(&found(7, 0x11))), Republish::Send, "the pending head did not land there");
    }

    #[test]
    fn a_newer_head_naming_a_list_of_ours_is_not_taken_for_another_devices() {
        let waiting = own(7, Some(pending(9, 0x44)));
        assert_eq!(republish_step(&waiting, Some(&found(12, 0x44))), Republish::Send, "the pending list under a replaced head");
        assert_eq!(republish_step(&waiting, Some(&found(12, 0x11))), Republish::Send, "the published list");
        assert_eq!(republish_step(&waiting, Some(&found(12, 0x55))), Republish::Yield);
        assert_eq!(republish_step(&own(7, None), Some(&found(9, 0x11))), Republish::Send, "the published list, nothing pending");
    }

    fn sent(stored_on: usize, targets: usize, sent: usize) -> EmberPublishResult {
        EmberPublishResult { stored_on, targets, sent }
    }

    #[test]
    fn a_head_is_surely_nowhere_only_when_no_store_of_it_went_out() {
        assert_eq!(placed(&sent(1, 8, 8)), Placed::Stored);
        assert_eq!(placed(&sent(0, 8, 8)), Placed::Unknown, "acks lost or late");
        assert_eq!(placed(&sent(0, 8, 1)), Placed::Unknown, "one sent, the rest unreachable");
        assert_eq!(placed(&sent(0, 8, 0)), Placed::Nowhere, "none could be sent");
        assert_eq!(placed(&sent(0, 0, 0)), Placed::Nowhere, "no node to send to");
    }

    #[test]
    fn a_republish_sends_the_pending_head_while_its_list_is_on_disk() {
        let dir = std::env::temp_dir().join(format!("ember-feed-republish-{}-{}", std::process::id(), rand::random::<u64>()));
        let mut feed = own(7, Some(pending(9, 0x44)));
        assert_eq!(republish_head(&dir, &feed), None, "no list on disk");

        write_list(&own_list_path(&dir, &feed.salt, 7), b"list").unwrap();
        assert_eq!(republish_head(&dir, &feed).map(|(head, pending)| (head.sequence, pending)), Some((7, false)), "the pending list is gone");

        write_list(&own_list_path(&dir, &feed.salt, 9), b"list").unwrap();
        let (head, is_pending) = republish_head(&dir, &feed).unwrap();
        assert!(is_pending);
        assert_eq!((head.sequence, head.list_ed2k_hash, head.item_count), (9, [0x44; 16], 2));

        feed.pending = None;
        assert_eq!(republish_head(&dir, &feed).map(|(head, pending)| (head.sequence, pending)), Some((7, false)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pending_head_is_adopted_once_stored_and_kept_otherwise() {
        assert_eq!(republished(Placed::Stored, true), Republished::Adopted);
        assert_eq!(republished(Placed::Unknown, true), Republished::Retry);
        assert_eq!(republished(Placed::Nowhere, true), Republished::Retry);
        assert_eq!(republished(Placed::Stored, false), Republished::Refreshed);
        assert_eq!(republished(Placed::Unknown, false), Republished::Retry);
        assert_eq!(republished(Placed::Nowhere, false), Republished::Retry);
    }

    #[test]
    fn a_feed_with_a_pending_head_is_due_without_waiting_a_day() {
        let now = 10 * REPUBLISH_SECS;
        let mut feed = own(7, None);
        feed.salt = format!("{:032x}", rand::random::<u128>());
        feed.published_at = now - 60;
        assert!(!republish_due(&feed, now));
        feed.pending = Some(pending(9, 0x44));
        assert!(republish_due(&feed, now));
        republish_retry().lock().insert(feed.salt.clone(), now + REPUBLISH_RETRY_SECS);
        assert!(!republish_due(&feed, now), "after a try, not before its retry");
        assert!(republish_due(&feed, now + REPUBLISH_RETRY_SECS));
        feed.published_at = 0;
        assert!(republish_due(&feed, now + REPUBLISH_RETRY_SECS), "never published, its first head pending");
        republish_retry().lock().remove(&feed.salt);
    }

    /// A republish is due an interval after the last send, whether that was
    /// the user's publish or a republish, and does not move the publish.
    #[test]
    fn a_republish_is_due_an_interval_after_the_last_send() {
        let now = 10 * REPUBLISH_SECS;
        let mut feed = own(7, None);
        feed.salt = format!("{:032x}", rand::random::<u128>());
        feed.published_at = now - 2 * REPUBLISH_SECS;
        assert!(republish_due(&feed, now));
        feed.refreshed_at = now - 60;
        assert!(!republish_due(&feed, now), "republished a minute ago");
        assert!(republish_due(&feed, now - 60 + REPUBLISH_SECS));
        assert_eq!(last_sent(&feed), now - 60);
    }

    /// A feed never found is looked for every few minutes for a day, then as
    /// any other.
    #[test]
    fn a_feed_never_found_is_looked_for_often_at_first() {
        let now = 100 * POLL_SECS;
        let mut feed = followed(0, 0);
        feed.salt = format!("{:032x}", rand::random::<u128>());
        feed.sequence = 0;
        feed.followed_at = now - 600;
        feed.checked_at = now - WAITING_POLL_SECS;
        assert!(lookup_due(&feed, now));
        feed.checked_at = now - WAITING_POLL_SECS + 1;
        assert!(!lookup_due(&feed, now));
        feed.followed_at = now - WAITING_FAST_FOR_SECS;
        feed.checked_at = now - WAITING_POLL_SECS;
        assert!(!lookup_due(&feed, now), "past its first day");
        feed.followed_at = now - 600;
        feed.sequence = 5;
        assert!(!lookup_due(&feed, now), "found once: every half hour");
    }

    /// A listing of the feed carries its head, unless the newest withdraws it;
    /// another feed's or another publisher's does not count.
    #[test]
    fn a_feeds_listing_stands_in_for_its_head() {
        let identity = crate::network::ember::crypto::signing_key_from_bytes(&[21u8; 32]);
        let publisher = identity.verifying_key().to_bytes();
        let salt = [4u8; 16];
        let head = FeedHead {
            sequence: 7,
            list_ed2k_hash: [1; 16],
            list_size: 100,
            list_blake3: [2; 32],
            item_count: 1,
            title: "T".into(),
            description: String::new(),
        };
        let blob = |salt: &FeedSalt, head: &FeedHead, withdrawn: bool, at: i64| {
            let record = SignedRecord::feed_listing_record(salt, head, withdrawn, &identity, at).unwrap();
            [record.data, record.signature.to_vec()].concat()
        };
        let listed = blob(&salt, &head, false, 100);
        let other = blob(&[5u8; 16], &head, false, 200);
        assert_eq!(newest_listed_head(&[listed.clone(), other.clone()], &publisher, &salt), Some(head.clone()));
        assert_eq!(newest_listed_head(std::slice::from_ref(&other), &publisher, &salt), None, "another feed's");
        assert_eq!(newest_listed_head(std::slice::from_ref(&listed), &[9u8; 32], &salt), None, "another publisher's");
        let withdrawn = blob(&salt, &crate::network::ember::feed::withdrawal_head(), true, 300);
        assert_eq!(newest_listed_head(&[listed.clone(), withdrawn.clone()], &publisher, &salt), None);
        let relisted = blob(&salt, &head, false, 400);
        assert_eq!(newest_listed_head(&[withdrawn, relisted], &publisher, &salt), Some(head));
    }

    #[test]
    fn listing_fallback_is_read_at_most_every_so_often() {
        let key = (format!("{:064x}", rand::random::<u128>()), "s".to_string());
        assert!(listing_fallback_due(&key, 1000));
        assert!(!listing_fallback_due(&key, 1000 + LISTING_FALLBACK_SECS - 1));
        assert!(listing_fallback_due(&key, 1000 + LISTING_FALLBACK_SECS));
    }

    #[test]
    fn a_pending_list_replaces_the_one_before_only_once_it_is_recorded() {
        let dir = std::env::temp_dir().join(format!("ember-feed-pending-{}-{}", std::process::id(), rand::random::<u64>()));
        let owner = format!("own:test-{}", rand::random::<u64>());
        let mut feed = own(7, Some(pending(9, 0x47)));
        feed.salt = format!("{:032x}", rand::random::<u128>());
        feed.list_ed2k = hex::encode([0x17; 16]);
        let held = own_lists(&dir, &feed);
        for list in &held {
            write_list(&list.share.path, b"list").unwrap();
        }
        swap_own_lists(&owner, &[], &held);
        let new = OwnList { sequence: 11, hash: [0x67; 16], share: HiddenShare { path: own_list_path(&dir, &feed.salt, 11), ..held[1].share.clone() } };
        write_list(&new.share.path, b"list").unwrap();
        feed_files::share_hidden(new.hash, &owner, new.share.clone());

        assert!(serve_pending(&owner, &feed, &held, new.clone(), || false).is_empty());
        assert!(feed_files::hidden_share(&[0x47; 16]).is_some() && held[1].share.path.exists(), "the pending one recorded still");
        assert!(feed_files::hidden_share(&[0x67; 16]).is_some(), "the new one, which the head sent names");

        assert_eq!(serve_pending(&owner, &feed, &held, new.clone(), || true), vec![[0x47; 16]]);
        assert!(feed_files::hidden_share(&[0x47; 16]).is_none() && !held[1].share.path.exists());
        assert!(feed_files::hidden_share(&[0x17; 16]).is_some() && feed_files::hidden_share(&[0x67; 16]).is_some());

        swap_own_lists(&owner, &[held[0].clone(), new], &[]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_feeds_lists_are_served_until_none_of_its_heads_names_them() {
        let dir = std::env::temp_dir().join(format!("ember-feed-own-{}-{}", std::process::id(), rand::random::<u64>()));
        let owner = format!("own:test-{}", rand::random::<u64>());
        let mut feed = own(7, Some(pending(9, 0x44)));
        feed.salt = format!("{:032x}", rand::random::<u128>());
        let lists = own_lists(&dir, &feed);
        assert_eq!(lists.iter().map(|list| (list.sequence, list.hash)).collect::<Vec<_>>(), vec![(7, [0x11; 16]), (9, [0x44; 16])]);
        for list in &lists {
            write_list(&list.share.path, b"list").unwrap();
        }
        assert!(swap_own_lists(&owner, &[], &lists).is_empty());
        assert!(feed_files::hidden_share(&[0x44; 16]).is_some());

        // A publish of unknown outcome replaces the pending list, keeping the published one.
        let newer = OwnList { sequence: 11, hash: [0x66; 16], share: HiddenShare { path: own_list_path(&dir, &feed.salt, 11), ..lists[1].share.clone() } };
        write_list(&newer.share.path, b"list").unwrap();
        let after = vec![lists[0].clone(), newer.clone()];
        assert_eq!(swap_own_lists(&owner, &lists, &after), vec![[0x44; 16]]);
        assert!(!lists[1].share.path.exists() && lists[0].share.path.exists());

        // The same bytes as the published list: one share, the newer file's,
        // and the published one served again from its own if that goes.
        let same = OwnList { sequence: 13, hash: [0x11; 16], share: HiddenShare { path: own_list_path(&dir, &feed.salt, 13), ..lists[0].share.clone() } };
        write_list(&same.share.path, b"list").unwrap();
        assert!(swap_own_lists(&owner, &[], std::slice::from_ref(&same)).is_empty());
        assert_eq!(feed_files::hidden_share(&[0x11; 16]).map(|share| share.path), Some(same.share.path.clone()));
        assert!(swap_own_lists(&owner, std::slice::from_ref(&same), &after).is_empty());
        assert_eq!(feed_files::hidden_share(&[0x11; 16]).map(|share| share.path), Some(lists[0].share.path.clone()));
        assert!(!same.share.path.exists());

        // Deleted: nothing of it is served.
        let mut released = swap_own_lists(&owner, &after, &[]);
        released.sort();
        assert_eq!(released, vec![[0x11; 16], [0x66; 16]]);
        assert!(feed_files::hidden_share(&[0x11; 16]).is_none() && feed_files::hidden_share(&[0x66; 16]).is_none());
        assert!(!lists[0].share.path.exists() && !newer.share.path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_followed_feeds_files_go_but_the_one_kept_and_other_feeds_stay() {
        let dir = std::env::temp_dir().join(format!("ember-feed-files-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir_all(dir.join("followed")).unwrap();
        let keep = followed_list_path(&dir, "aa", "bb", 2);
        let old = followed_list_path(&dir, "aa", "bb", 1);
        let duplicate = dir.join("followed").join("aa-bb-2 (1).emulecollection");
        let newer = followed_list_path(&dir, "aa", "bb", 3);
        let other = followed_list_path(&dir, "aa", "cc", 1);
        for path in [&keep, &old, &duplicate, &newer, &other] {
            std::fs::write(path, b"x").unwrap();
        }
        remove_followed_files(&dir, "aa", "bb", Some((2, &keep)));
        assert!(keep.exists() && other.exists());
        assert!(newer.exists(), "a newer list being taken up stays");
        assert!(!old.exists() && !duplicate.exists());
        remove_followed_files(&dir, "aa", "bb", None);
        assert!(!keep.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
