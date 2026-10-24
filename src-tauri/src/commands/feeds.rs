//! Feeds: publishing this identity's, following others', and keeping both
//! current. See `network::ember::feed` for the head and `sharing::feed_files`
//! for how a list is served and fetched without being the user's file.
//!
//! Publishing writes the list into the feeds folder, serves it hidden, and
//! signs and publishes the head; heads are republished daily. Following looks
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
    feed_key, generate_feed_salt, next_sequence, FeedHead, FeedLink, FeedSalt, FEEDS_PER_IDENTITY,
    FEED_DESCRIPTION_MAX, FEED_ITEMS_MAX, FEED_NOTE_MAX, FEED_TITLE_MAX,
};
use crate::network::NetworkCommand;
use crate::sharing::feed_files::{self, FetchOutcome, HiddenShare};
use crate::sharing::manager::TransferControl;
use crate::storage::database::{FeedItem, FollowedFeed, FollowedItem, OwnFeed, OwnPublish};
use crate::types::{Transfer, TransferDirection, TransferStatus};

/// Emitted when a feed, published or followed, changed: `{ publisher,
/// salt, added }`, `added` the number of new items a list brought.
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
/// How often the publisher republishes a head nothing has changed.
const REPUBLISH_SECS: i64 = 24 * 3600 - 15 * 60;
/// How long a list may take to arrive before the fetch is given up and
/// tried again later.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// How long after a fetch gave up the next one starts.
const FETCH_RETRY_SECS: i64 = 30 * 60;
/// The largest list followed, in bytes. 2,000 items fit in far less.
const MAX_LIST_BYTES: u64 = 2 * 1024 * 1024;
/// Free space auto-download leaves on the download folder's drive.
const AUTO_DOWNLOAD_HEADROOM: u64 = 64 * 1024 * 1024;

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

fn own_list_path(dir: &Path, salt: &str, sequence: i64) -> PathBuf {
    dir.join("own").join(format!("{salt}-{sequence}.emulecollection"))
}

fn followed_list_path(dir: &Path, publisher: &str, salt: &str, sequence: i64) -> PathBuf {
    dir.join("followed").join(format!("{publisher}-{salt}-{sequence}.emulecollection"))
}

fn list_share_name(title: &str) -> String {
    crate::security::sanitize_filename(&format!("{title}.emulecollection"))
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

/// Held while a feed of ours is published or deleted, and while heads are
/// republished, so two can never record their sequences out of order.
fn publish_lock() -> &'static tokio::sync::Mutex<()> {
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
fn clip(text: &str, max: usize) -> String {
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
    pub link: String,
    pub items: Vec<FeedItem>,
}

async fn own_feed_info(state: &AppState, feed: OwnFeed) -> Result<OwnFeedInfo, String> {
    let salt = hex_salt(&feed.salt)?;
    let db = state.db.clone();
    let key = feed.salt.clone();
    let items = blocking(move || db.feed_own_items(&key), "feeds_failed", "Could not read feeds").await?;
    Ok(OwnFeedInfo { link: link_for(&state.identity.ed25519_public_key, &salt), feed, items })
}

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

/// Start a feed. Nothing is published until [`publish_feed`].
#[tauri::command]
pub async fn create_feed(
    state: tauri::State<'_, AppState>,
    title: String,
    description: String,
) -> Result<OwnFeedInfo, String> {
    let (title, description) = checked_details(&title, &description)?;
    let salt = hex::encode(generate_feed_salt());
    let db = state.db.clone();
    let now = chrono::Utc::now().timestamp();
    let key = salt.clone();
    let made = blocking(
        move || db.feed_own_create(&key, &title, &description, now, FEEDS_PER_IDENTITY),
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

#[tauri::command]
pub async fn set_feed_details(
    state: tauri::State<'_, AppState>,
    salt: String,
    title: String,
    description: String,
) -> Result<(), String> {
    let salt = hex::encode(hex_salt(&salt)?);
    let (title, description) = checked_details(&title, &description)?;
    let _publishing = publish_lock().lock().await;
    let db = state.db.clone();
    let found = blocking(move || db.feed_own_set_details(&salt, &title, &description), "feeds_failed", "Could not save the feed").await?;
    if !found {
        return Err(coded("feeds_not_found", "That feed could not be found"));
    }
    Ok(())
}

/// One item as the editor sends it: a file from the Library, and a note.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct FeedItemInput {
    pub ed2k: String,
    #[serde(default)]
    pub note: String,
}

/// Set a feed's items, in order, from files the user shares publicly. Every
/// item then has at least one source, and a BLAKE3 a follower can check.
#[tauri::command]
pub async fn set_feed_items(
    state: tauri::State<'_, AppState>,
    salt: String,
    items: Vec<FeedItemInput>,
) -> Result<usize, String> {
    let salt = hex::encode(hex_salt(&salt)?);
    if items.len() > FEED_ITEMS_MAX {
        return Err(coded("feeds_too_many_items", "A feed holds at most 2,000 files"));
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    {
        let index = state.local_index.read().await;
        for input in items {
            let ed2k = input.ed2k.trim().to_ascii_lowercase();
            if !seen.insert(ed2k.clone()) {
                continue;
            }
            let Some(file) = index.get_by_hash(&ed2k) else {
                return Err(coded("feeds_item_not_shared", "Only files you share with everyone can go in a feed"));
            };
            if !file.is_public_listable() || file.ember_file_hash.len() != 64 {
                return Err(coded("feeds_item_not_shared", "Only files you share with everyone can go in a feed"));
            }
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
    let count = out.len();
    // Not in the middle of a publish, which reads the items and records
    // them as published.
    let _publishing = publish_lock().lock().await;
    let db = state.db.clone();
    let found = blocking(move || db.feed_own_set_items(&salt, &out), "feeds_failed", "Could not save the feed").await?;
    if !found {
        return Err(coded("feeds_not_found", "That feed could not be found"));
    }
    Ok(count)
}

/// Whether `item` is still a file the user shares with everyone, as it was
/// when added: one since made friends-only, or gone, must not be published.
fn still_public(index: &crate::search::index::LocalIndex, item: &FeedItem) -> bool {
    index
        .get_by_hash(&item.ed2k)
        .is_some_and(|file| file.is_public_listable() && file.ember_file_hash.eq_ignore_ascii_case(&item.blake3))
}

/// The list a feed's items make, as a collection file's bytes.
fn build_list(title: &str, author: &str, items: &[FeedItem]) -> anyhow::Result<Vec<u8>> {
    Collection {
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
    .to_binary_bytes()
}

/// Write the feed's list, serve it, and publish a head naming it.
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
    let db = state.db.clone();
    let key = salt.clone();
    let (feed, items) = blocking(move || Ok((db.feed_own(&key)?, db.feed_own_items(&key)?)), "feeds_failed", "Could not read feeds").await?;
    let feed = feed.ok_or_else(|| coded("feeds_not_found", "That feed could not be found"))?;
    let kept: Vec<FeedItem> = {
        let index = state.local_index.read().await;
        items.iter().filter(|item| still_public(&index, item)).cloned().collect()
    };
    if kept.len() != items.len() {
        let db = state.db.clone();
        let (key, kept) = (salt.clone(), kept.clone());
        blocking(move || db.feed_own_set_items(&key, &kept), "feeds_failed", "Could not save the feed").await?;
    }

    // The new list is served beside the old one until its head is out.
    let (key, task_feed, task_owner) = (salt.clone(), feed.clone(), owner.clone());
    let (head, path) = blocking(
        move || {
            let feed = task_feed;
            let bytes = build_list(&feed.title, &author, &kept)?;
            let sequence = next_sequence(feed.sequence.max(0) as u64, now_ms()).min(i64::MAX as u64);
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
            let path = own_list_path(&dir, &key, sequence as i64);
            write_list(&path, &bytes)?;
            feed_files::share_hidden(
                head.list_ed2k_hash,
                &task_owner,
                HiddenShare {
                    path: path.clone(),
                    size: head.list_size,
                    name: list_share_name(&feed.title),
                    ember_file_hash: hex::encode(head.list_blake3),
                },
            );
            Ok((head, path))
        },
        "feeds_publish_failed",
        "Could not publish the feed",
    )
    .await?;
    // Unchanged bytes have the old list's hash, whose share now names the
    // new file: a failure puts the old one back rather than unserving both.
    let same_list = feed.sequence > 0 && feed.list_ed2k == hex::encode(head.list_ed2k_hash);
    let withdraw_new = || {
        let _ = std::fs::remove_file(&path);
        if same_list {
            feed_files::share_hidden(
                head.list_ed2k_hash,
                &owner,
                HiddenShare {
                    path: own_list_path(&feeds_dir(&app), &salt, feed.sequence),
                    size: head.list_size,
                    name: list_share_name(&feed.title),
                    ember_file_hash: hex::encode(head.list_blake3),
                },
            );
            None
        } else {
            release_list(&head.list_ed2k_hash, &owner)
        }
    };
    if let Err(error) = publish_head(&state, &salt_bytes, &head, true).await {
        withdraw_lists(&state, withdraw_new()).await;
        return Err(error);
    }

    let published = OwnPublish {
        sequence: head.sequence as i64,
        list_ed2k: hex::encode(head.list_ed2k_hash),
        list_blake3: hex::encode(head.list_blake3),
        list_size: head.list_size as i64,
        item_count: i64::from(head.item_count),
        title: head.title.clone(),
        description: head.description.clone(),
    };
    let now = chrono::Utc::now().timestamp();
    // The head is out: losing this record would leave a list nobody keeps
    // named by it, so a passing write error is tried again.
    let mut recorded = Err(String::new());
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let (db, key, published) = (state.db.clone(), salt.clone(), published.clone());
        recorded = blocking(move || db.feed_own_published(&key, &published, now), "feeds_publish_failed", "Could not publish the feed").await;
        if recorded.is_ok() {
            break;
        }
    }
    if recorded? {
        // The list before this one is no longer the feed's.
        if feed.sequence > 0 && !same_list {
            if let Ok(old) = hex_to16(&feed.list_ed2k) {
                withdraw_lists(&state, release_list(&old, &owner)).await;
            }
        }
        if feed.sequence > 0 {
            let _ = std::fs::remove_file(own_list_path(&feeds_dir(&app), &salt, feed.sequence));
        }
    } else {
        withdraw_lists(&state, withdraw_new()).await;
    }
    let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "salt": salt }));
    let db = state.db.clone();
    let feed = blocking(move || db.feed_own(&salt), "feeds_failed", "Could not read feeds")
        .await?
        .unwrap_or(feed);
    own_feed_info(&state, feed).await
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

fn write_list(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let dir = path.parent().ok_or_else(|| anyhow::anyhow!("no folder"))?;
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Sign `head` and send it into the DHT, and to every friend connected now
/// when `push`. Signed now, so a republish of an unchanged head is newer than
/// the copy storers hold.
async fn publish_head(state: &AppState, salt: &FeedSalt, head: &FeedHead, push: bool) -> Result<(), String> {
    let signing = crate::network::ember::crypto::signing_key_from_bytes(&state.identity.ed25519_secret_key);
    let record = SignedRecord::feed_head_record(salt, head, &signing, chrono::Utc::now().timestamp())
        .ok_or_else(|| coded("feeds_publish_failed", "Could not publish the feed"))?;
    let blob = [record.data.clone(), record.signature.to_vec()].concat();
    crate::commands::channels::queue_signed_record(state, record).await?;
    if push {
        let _ = state.network_tx.try_send(NetworkCommand::PushFeedHead { blob });
    }
    Ok(())
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
    Some(FeedHead {
        sequence: feed.sequence.max(0) as u64,
        list_ed2k_hash: hex_to16(&feed.list_ed2k).ok()?,
        list_size: feed.list_size.max(0) as u64,
        list_blake3: hex_to32(&feed.list_blake3).ok()?,
        item_count: feed.item_count.max(0) as u32,
        title: title.clone(),
        description: description.clone(),
    })
    .filter(FeedHead::valid)
}

/// Stop publishing a feed. Its head lapses from the DHT within its lifetime;
/// followers keep what they hold.
#[tauri::command]
pub async fn delete_feed(app: tauri::AppHandle, state: tauri::State<'_, AppState>, salt: String) -> Result<(), String> {
    let salt = hex::encode(hex_salt(&salt)?);
    let _publishing = publish_lock().lock().await;
    let dir = feeds_dir(&app);
    let db = state.db.clone();
    let key = salt.clone();
    let released = blocking(
        move || {
            let mut released = None;
            if let Some(feed) = db.feed_own(&key)? {
                if let Ok(hash) = hex_to16(&feed.list_ed2k) {
                    released = release_list(&hash, &own_owner(&key));
                }
                let _ = std::fs::remove_file(own_list_path(&dir, &key, feed.sequence));
            }
            db.feed_own_delete(&key)?;
            Ok(released)
        },
        "feeds_failed",
        "Could not delete the feed",
    )
    .await?;
    withdraw_lists(&state, released).await;
    let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "salt": salt }));
    Ok(())
}

// ── Following ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct FollowedFeedInfo {
    #[serde(flatten)]
    pub feed: FollowedFeed,
    pub link: String,
}

fn followed_info(feed: FollowedFeed) -> FollowedFeedInfo {
    let link = match (hex_to32(&feed.publisher), hex_to16(&feed.salt)) {
        (Ok(publisher), Ok(salt)) => link_for(&publisher, &salt),
        _ => String::new(),
    };
    FollowedFeedInfo { feed, link }
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
    let feed = blocking(
        move || {
            db.feed_follow(&key_pub, &key_salt, now)?;
            db.feed_followed(&key_pub, &key_salt)
        },
        "feeds_failed",
        "Could not follow the feed",
    )
    .await?
    .ok_or_else(|| coded("feeds_failed", "Could not follow the feed"))?;
    let looked = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Some(state) = looked.try_state::<AppState>() {
            look_up_head(&looked, &state, &publisher, &salt).await;
        }
    });
    let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "publisher": feed.publisher, "salt": feed.salt }));
    Ok(followed_info(feed))
}

/// Look again now, rather than at the next half hour.
#[tauri::command]
pub async fn refresh_feed(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    publisher: String,
    salt: String,
) -> Result<(), String> {
    let (publisher, salt) = (hex::encode(hex_publisher(&publisher)?), hex::encode(hex_salt(&salt)?));
    look_up_head(&app, &state, &publisher, &salt).await;
    Ok(())
}

#[tauri::command]
pub async fn get_feed_items(
    state: tauri::State<'_, AppState>,
    publisher: String,
    salt: String,
) -> Result<Vec<FollowedItem>, String> {
    let (publisher, salt) = (hex::encode(hex_publisher(&publisher)?), hex::encode(hex_salt(&salt)?));
    let db = state.db.clone();
    blocking(move || db.feed_followed_items(&publisher, &salt), "feeds_failed", "Could not read feeds").await
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

/// Auto-download for one feed: off by default, and bounded per item and per
/// day when on.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn set_feed_auto_download(
    state: tauri::State<'_, AppState>,
    publisher: String,
    salt: String,
    enabled: bool,
    max_item_mib: i64,
    max_day_mib: i64,
    category: String,
) -> Result<(), String> {
    let (publisher, salt) = (hex::encode(hex_publisher(&publisher)?), hex::encode(hex_salt(&salt)?));
    let category = clip(&category, 256);
    let db = state.db.clone();
    let found = blocking(
        move || {
            db.feed_set_auto_download(&publisher, &salt, enabled, max_item_mib.clamp(0, 1 << 30), max_day_mib.clamp(0, 1 << 30), &category)
        },
        "feeds_failed",
        "Could not save the feed",
    )
    .await?;
    if !found {
        return Err(coded("feeds_not_found", "That feed could not be found"));
    }
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

/// Start one item's download, in the feed's category, and mark it so.
async fn start_item_download(app: &tauri::AppHandle, feed: &FollowedFeed, item: &FeedItem) -> Result<(), String> {
    let state = app.state::<AppState>();
    let started = crate::commands::transfers::start_download(
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
        None,
        None,
    )
    .await?;
    if !feed.auto_category.trim().is_empty() && !started.already_queued {
        let _ = crate::commands::transfers::set_transfers_category(
            app.clone(),
            state.clone(),
            vec![started.transfer_id],
            feed.auto_category.clone(),
            None,
        )
        .await;
    }
    let db = state.db.clone();
    let (publisher, salt, ed2k) = (feed.publisher.clone(), feed.salt.clone(), item.ed2k.clone());
    let _ = tokio::task::spawn_blocking(move || db.feed_mark_downloaded(&publisher, &salt, &ed2k)).await;
    Ok(())
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
    for id in fetches_for(&publisher, &salt) {
        cancel_fetch(&state, &id).await;
    }
    let dir = feeds_dir(&app);
    let db = state.db.clone();
    let (key_pub, key_salt) = (publisher.clone(), salt.clone());
    let released = blocking(
        move || {
            let mut released = None;
            if let Some(feed) = db.feed_followed(&key_pub, &key_salt)? {
                if let Ok(hash) = hex_to16(&feed.held_ed2k) {
                    released = release_list(&hash, &followed_owner(&key_pub, &key_salt));
                }
            }
            remove_followed_files(&dir, &key_pub, &key_salt, None);
            db.feed_unfollow(&key_pub, &key_salt)?;
            Ok(released)
        },
        "feeds_failed",
        "Could not unfollow the feed",
    )
    .await?;
    withdraw_lists(&state, released).await;
    let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "publisher": publisher, "salt": salt }));
    Ok(())
}

// ── Heads and lists ────────────────────────────────────────────────────────

/// Look up a followed feed's head and take up a newer one, starting the
/// fetch of its list.
async fn look_up_head(app: &tauri::AppHandle, state: &AppState, publisher: &str, salt: &str) {
    let (Ok(publisher_key), Ok(salt_bytes)) = (hex_to32(publisher), hex_to16(salt)) else {
        return;
    };
    // One lookup of a feed at a time: a tick's and the user's "Check now".
    let looking_at = (publisher.to_string(), salt.to_string());
    if !looking().lock().insert(looking_at.clone()) {
        return;
    }
    let key = feed_key(&publisher_key, &salt_bytes);
    let found = {
        let _done = LookedAt(looking_at.clone());
        crate::commands::channels::find_raw_keys_counted(state, vec![key], LOOKUP_TIMEOUT_MS)
            .await
            .ok()
            .flatten()
    };
    let best = found
        .map(|(blobs, _)| best_head(&blobs, &publisher_key, &salt_bytes))
        .unwrap_or_default();
    let db = state.db.clone();
    let now = chrono::Utc::now().timestamp();
    let _ = tokio::task::spawn_blocking(move || db.feed_checked(&looking_at.0, &looking_at.1, now)).await;
    if let Some(head) = best {
        take_head(app, state, publisher, salt, head).await;
    }
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
/// it signed it and the feed is followed.
async fn on_pushed_head(app: &tauri::AppHandle, state: &AppState, from: [u8; 32], blob: Vec<u8>) {
    let Some(record) = SignedRecord::from_value_blob(&blob) else {
        return;
    };
    let Some((salt, _)) = record.feed_head() else {
        return;
    };
    let Some(head) = best_head(&[blob], &from, &salt) else {
        return;
    };
    let (publisher, salt) = (hex::encode(from), hex::encode(salt));
    let db = state.db.clone();
    let (key_pub, key_salt) = (publisher.clone(), salt.clone());
    let followed = tokio::task::spawn_blocking(move || db.feed_followed(&key_pub, &key_salt))
        .await
        .ok()
        .and_then(Result::ok)
        .flatten()
        .is_some();
    if followed {
        take_head(app, state, &publisher, &salt, head).await;
    }
}

/// Take up `head` if newer than the one held, and fetch its list.
async fn take_head(app: &tauri::AppHandle, state: &AppState, publisher: &str, salt: &str, head: FeedHead) {
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
    if taken {
        let _ = app.emit(FEEDS_CHANGED_EVENT, serde_json::json!({ "publisher": publisher, "salt": salt }));
        let db = state.db.clone();
        let (key_pub, key_salt) = (publisher.to_string(), salt.to_string());
        if let Ok(Ok(Some(feed))) = tokio::task::spawn_blocking(move || db.feed_followed(&key_pub, &key_salt)).await {
            start_fetch(app, state, &feed).await;
        }
    }
}

/// The newest valid head among `blobs`, by its publisher for this feed.
fn best_head(blobs: &[Vec<u8>], publisher: &[u8; 32], salt: &FeedSalt) -> Option<FeedHead> {
    blobs
        .iter()
        .filter_map(|blob| SignedRecord::from_value_blob(blob))
        .filter(|record| record.publisher_key == *publisher && record.feed_store_ok())
        .filter_map(|record| record.feed_head())
        .filter(|(found_salt, head)| found_salt == salt && head.list_size <= MAX_LIST_BYTES)
        .map(|(_, head)| head)
        .max_by_key(|head| head.sequence)
}

/// A fetch of a list in flight.
#[derive(Debug, Clone)]
struct Fetching {
    publisher: String,
    salt: String,
    sequence: i64,
    started: Instant,
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

/// Fetch the list `feed`'s head names, unless it is on its way. A fetch of
/// an older list is given up: its sources may well have moved on.
async fn start_fetch(app: &tauri::AppHandle, state: &AppState, feed: &FollowedFeed) {
    if feed.sequence <= 0 || feed.list_sequence == feed.sequence {
        return;
    }
    let Ok(list_hash) = hex_to16(&feed.list_ed2k) else {
        return;
    };
    let transfer_id = uuid::Uuid::new_v4().to_string();
    // Claimed before any await, so a tick and "Check now" cannot both start one.
    let superseded: Vec<String> = {
        let mut fetching = fetching().lock();
        let ours = |f: &Fetching| f.publisher == feed.publisher && f.salt == feed.salt;
        if fetching.values().any(|f| ours(f) && f.sequence >= feed.sequence) {
            return;
        }
        let older: Vec<String> = fetching.iter().filter(|(_, f)| ours(f)).map(|(id, _)| id.clone()).collect();
        fetching.insert(
            transfer_id.clone(),
            Fetching { publisher: feed.publisher.clone(), salt: feed.salt.clone(), sequence: feed.sequence, started: Instant::now() },
        );
        older
    };
    for id in superseded {
        cancel_fetch(state, &id).await;
    }
    let dest = followed_list_path(&feeds_dir(app), &feed.publisher, &feed.salt, feed.sequence);
    // A file left there by an earlier attempt would push this one to "(1)".
    let held = feed_files::hidden_share(&list_hash).map(|share| share.path);
    let (to, from) = (dest.clone(), held.clone());
    let copied = tokio::task::spawn_blocking(move || {
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
        take_list(app, state, feed.clone(), dest).await;
        fetching().lock().remove(&transfer_id);
        return;
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
        return;
    }
    let sent = bounded_send(
        &state.network_tx,
        NetworkCommand::StartDownload {
            file_hash: hex::encode(list_hash),
            file_name: list_share_name(&feed.title),
            file_size: feed.list_size.max(0) as u64,
            peer_ip: String::new(),
            peer_port: 0,
            extra_sources: Vec::new(),
            ember_file_hash: feed.list_blake3.clone(),
            expected_aich: None,
            transfer_id: transfer_id.clone(),
            control,
            discovery_only: false,
            friend_ember_hash: None,
        },
    )
    .await;
    if sent.is_err() {
        cancel_fetch(state, &transfer_id).await;
    }
}

fn list_transfer(id: &str, feed: &FollowedFeed, list_hash: &[u8; 16]) -> Transfer {
    Transfer {
        id: id.to_string(),
        file_name: list_share_name(&feed.title),
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
/// until its transfer ends, so a completion racing this lands in the feeds
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
        tokio::time::sleep(CANCELLED_FETCH_GRACE).await;
        feed_files::forget_cancelled_fetch(&id);
    });
}

/// A list arrived (or failed to).
async fn on_fetch_done(app: &tauri::AppHandle, state: &AppState, transfer_id: String, outcome: FetchOutcome) {
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
    match outcome {
        FetchOutcome::Done(path) if feed.sequence == fetch.sequence => take_list(app, state, feed, path).await,
        FetchOutcome::Done(path) => {
            // A newer head arrived while this list was on its way.
            let _ = std::fs::remove_file(path);
        }
        FetchOutcome::Failed(error) => {
            tracing::debug!("feed list fetch for {}/{} failed: {error}", fetch.publisher, fetch.salt);
            gave_up().lock().insert((fetch.publisher, fetch.salt), chrono::Utc::now().timestamp());
        }
    }
}

/// The items of a list file, checked against `feed`'s head, or `None` for a
/// list that does not match it or does not parse.
fn read_list(path: &Path, feed: &FollowedFeed) -> Option<Vec<FeedItem>> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() as i64 != feed.list_size
        || crate::network::ed2k::hash::ed2k_hash_bytes(&bytes) != feed.list_ed2k
        || blake3::hash(&bytes).to_hex().as_str() != feed.list_blake3
    {
        return None;
    }
    let collection = Collection::from_binary_bytes(&bytes).ok()?;
    if collection.files.len() > FEED_ITEMS_MAX {
        return None;
    }
    let mut seen = std::collections::HashSet::new();
    let items = collection
        .files
        .into_iter()
        .filter(|file| {
            file.hash.len() == 32
                && file.hash.bytes().all(|b| b.is_ascii_hexdigit())
                && file.ember_file_hash.len() == 64
                && file.size > 0
        })
        .filter_map(|file| {
            let name = crate::security::sanitize_filename(&file.name);
            (!name.is_empty() && seen.insert(file.hash.to_ascii_lowercase())).then(|| FeedItem {
                ed2k: file.hash.to_ascii_lowercase(),
                name,
                size: file.size.min(i64::MAX as u64) as i64,
                // A malformed one would make the download refuse to start.
                aich: crate::security::parse_expected_aich(Some(&file.aich_hash)).ok().flatten().unwrap_or_default(),
                blake3: file.ember_file_hash.to_ascii_lowercase(),
                note: clip(&file.note, FEED_NOTE_MAX),
            })
        })
        .collect();
    Some(items)
}

/// Take up a list that arrived for `feed`'s current head: check it, work out
/// what is new, serve it in place of the one held, and start what
/// auto-download allows.
async fn take_list(app: &tauri::AppHandle, state: &AppState, feed: FollowedFeed, path: PathBuf) {
    let dir = feeds_dir(app);
    let db = state.db.clone();
    let task_feed = feed.clone();
    let now = chrono::Utc::now().timestamp();
    let taken = tokio::task::spawn_blocking(move || {
        let feed = task_feed;
        let owner = followed_owner(&feed.publisher, &feed.salt);
        // Where the list is kept, whatever name the download finished under;
        // a file already there is an earlier copy of the same list.
        let canonical = followed_list_path(&dir, &feed.publisher, &feed.salt, feed.sequence);
        let path = if path != canonical && std::fs::rename(&path, &canonical).is_ok() { canonical } else { path };
        let Some(items) = read_list(&path, &feed) else {
            let _ = std::fs::remove_file(&path);
            let _ = db.feed_mark_broken(&feed.publisher, &feed.salt, feed.sequence);
            return None;
        };
        let Some(update) = db.feed_take_list(&feed.publisher, &feed.salt, feed.sequence, &items, now).ok().flatten() else {
            let _ = std::fs::remove_file(&path);
            return None;
        };
        // Serve this list in place of the one held before.
        if let Ok(hash) = hex_to16(&feed.list_ed2k) {
            feed_files::share_hidden(
                hash,
                &owner,
                HiddenShare {
                    path: path.clone(),
                    size: feed.list_size.max(0) as u64,
                    name: list_share_name(&feed.title),
                    ember_file_hash: feed.list_blake3.clone(),
                },
            );
        }
        let released = (feed.held_ed2k != feed.list_ed2k)
            .then(|| hex_to16(&feed.held_ed2k).ok())
            .flatten()
            .and_then(|old| release_list(&old, &owner));
        remove_followed_files(&dir, &feed.publisher, &feed.salt, Some((feed.sequence, &path)));
        Some((update, released))
    })
    .await
    .ok()
    .flatten();
    let update = match taken {
        Some((update, released)) => {
            withdraw_lists(state, released).await;
            Some(update)
        }
        None => None,
    };
    let added = update.as_ref().map_or(0, |u| u.added.len());
    let _ = app.emit(
        FEEDS_CHANGED_EVENT,
        serde_json::json!({ "publisher": feed.publisher, "salt": feed.salt, "added": added, "title": feed.title }),
    );
    if let Some(update) = update {
        if feed.auto_download && !update.added.is_empty() {
            auto_download(app, state, &feed, &update.added).await;
        }
    }
}

/// Whether auto-download may start `item` for `feed`, with `spent_today`
/// bytes already started today: not a type Ember never starts by itself, not
/// over either cap.
fn auto_download_allows(feed: &FollowedFeed, item: &FeedItem, spent_today: i64) -> bool {
    const MIB: i64 = 1024 * 1024;
    crate::sharing::name_tag::may_auto_tag(&item.name)
        && !crate::security::is_dangerous_extension(&item.name)
        && (feed.auto_max_item_mib == 0 || item.size <= feed.auto_max_item_mib.saturating_mul(MIB))
        && (feed.auto_max_day_mib == 0
            || spent_today.saturating_add(item.size) <= feed.auto_max_day_mib.saturating_mul(MIB))
}

/// Start what auto-download allows of a list's new items.
async fn auto_download(app: &tauri::AppHandle, state: &AppState, feed: &FollowedFeed, added: &[FeedItem]) {
    let day = chrono::Utc::now().timestamp() / 86_400;
    let db = state.db.clone();
    let (key_pub, key_salt) = (feed.publisher.clone(), feed.salt.clone());
    let mut spent = tokio::task::spawn_blocking(move || db.feed_auto_bytes(&key_pub, &key_salt, day).unwrap_or(0))
        .await
        .unwrap_or(0);
    let root = state.config.read().await.settings.download_folders().current.clone();
    // Measured once: what this pass starts is not on disk yet, so it is
    // counted off as it goes.
    let mut free = tokio::task::spawn_blocking(move || fs2::available_space(&root).unwrap_or(0)).await.unwrap_or(0);
    for item in added {
        if !auto_download_allows(feed, item, spent) {
            continue;
        }
        // Held already, or on its way: nothing to start.
        if state.local_index.read().await.get_by_hash(&item.ed2k).is_some()
            || state.transfer_manager.read().await.has_pending_for_hash(&item.ed2k)
        {
            continue;
        }
        let size = item.size.max(0) as u64;
        if free < size.saturating_add(AUTO_DOWNLOAD_HEADROOM) {
            continue;
        }
        if start_item_download(app, feed, item).await.is_ok() {
            free -= size;
            spent = spent.saturating_add(item.size);
            let db = state.db.clone();
            let (key_pub, key_salt, size) = (feed.publisher.clone(), feed.salt.clone(), item.size);
            let _ = tokio::task::spawn_blocking(move || db.feed_add_auto_bytes(&key_pub, &key_salt, day, size)).await;
        }
    }
}

// ── The service ────────────────────────────────────────────────────────────

/// Serve again what was served before a restart: each published feed's
/// list, and each followed feed's held one.
async fn reshare_held(app: &tauri::AppHandle, state: &AppState) {
    let dir = feeds_dir(app);
    let db = state.db.clone();
    let _publishing = publish_lock().lock().await;
    let _ = tokio::task::spawn_blocking(move || {
        let mut kept = std::collections::HashSet::new();
        for feed in db.feeds_own().unwrap_or_default() {
            let path = own_list_path(&dir, &feed.salt, feed.sequence);
            kept.insert(path.clone());
            if let (Some(head), true) = (own_head(&feed), path.exists()) {
                feed_files::share_hidden(
                    head.list_ed2k_hash,
                    &own_owner(&feed.salt),
                    HiddenShare {
                        path,
                        size: head.list_size,
                        name: list_share_name(&head.title),
                        ember_file_hash: hex::encode(head.list_blake3),
                    },
                );
            }
        }
        for feed in db.feeds_followed().unwrap_or_default() {
            let path = followed_list_path(&dir, &feed.publisher, &feed.salt, feed.list_sequence);
            kept.insert(path.clone());
            if feed.list_sequence > 0 && !path.exists() {
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
                        name: list_share_name(&feed.title),
                        ember_file_hash: feed.held_blake3.clone(),
                    },
                );
            }
        }
        sweep_stray_lists(&dir, &kept);
    })
    .await;
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

/// Sign and send an unchanged head of ours again, so storers keep it. Not
/// when another device of this identity has published a newer one since:
/// re-signed now, ours would displace it.
async fn republish(state: &AppState, feed: &OwnFeed, now: i64) {
    let (Some(head), Ok(salt)) = (own_head(feed), hex_to16(&feed.salt)) else {
        return;
    };
    // Looked up without the publish lock, which a Publish would wait on.
    let publisher = state.identity.ed25519_public_key;
    let found = crate::commands::channels::find_raw_keys_counted(state, vec![feed_key(&publisher, &salt)], LOOKUP_TIMEOUT_MS)
        .await
        .ok()
        .flatten();
    let newer = found
        .and_then(|(blobs, _)| best_head(&blobs, &publisher, &salt))
        .is_some_and(|found| found.sequence > head.sequence);
    // A publish or delete meanwhile has done this feed's work already.
    let Ok(_publishing) = publish_lock().try_lock() else {
        return;
    };
    let db = state.db.clone();
    let key = feed.salt.clone();
    let current = tokio::task::spawn_blocking(move || db.feed_own(&key)).await.ok().and_then(Result::ok).flatten();
    if current.is_none_or(|current| current.sequence != feed.sequence || current.published_at != feed.published_at) {
        return;
    }
    if newer {
        tracing::info!("feed {} has a newer head from another device; not republishing ours", feed.salt);
    }
    if newer || publish_head(state, &salt, &head, false).await.is_ok() {
        let db = state.db.clone();
        let (key, sequence) = (feed.salt.clone(), feed.sequence);
        let _ = tokio::task::spawn_blocking(move || db.feed_own_republished(&key, sequence, now)).await;
    }
}

/// When `feed` is next due a lookup, spread by feed so they do not all come
/// at once.
fn lookup_due(feed: &FollowedFeed, now: i64) -> bool {
    let spread = i64::from(u16::from_str_radix(feed.salt.get(..4).unwrap_or("0"), 16).unwrap_or(0)) % POLL_JITTER_SECS;
    now - feed.checked_at >= POLL_SECS + spread
}

async fn on_tick(app: &tauri::AppHandle, state: &AppState) {
    if crate::commands::channels::require_ember(state).await.is_err() || state.db.chat_locked() {
        return;
    }
    let now = chrono::Utc::now().timestamp();
    // Fetches that have waited too long for sources.
    let stale: Vec<(String, Fetching)> = fetching()
        .lock()
        .iter()
        .filter(|(_, f)| f.started.elapsed() >= FETCH_TIMEOUT)
        .map(|(id, f)| (id.clone(), f.clone()))
        .collect();
    for (id, fetch) in stale {
        cancel_fetch(state, &id).await;
        gave_up().lock().insert((fetch.publisher, fetch.salt), now);
    }
    // Our own heads, republished before they age.
    let db = state.db.clone();
    let own = tokio::task::spawn_blocking(move || db.feeds_own().unwrap_or_default()).await.unwrap_or_default();
    for feed in own.iter().filter(|f| f.published_at > 0 && now - f.published_at >= REPUBLISH_SECS) {
        republish(state, feed, now).await;
    }
    // Followed feeds: a list owed, or a lookup due, the longest unchecked
    // first.
    let db = state.db.clone();
    let mut followed =
        tokio::task::spawn_blocking(move || db.feeds_followed().unwrap_or_default()).await.unwrap_or_default();
    for feed in &followed {
        let resting = gave_up()
            .lock()
            .get(&(feed.publisher.clone(), feed.salt.clone()))
            .is_some_and(|at| now - at < FETCH_RETRY_SECS);
        if feed.sequence > 0 && feed.list_sequence != feed.sequence && feed.state != "broken" && !resting {
            start_fetch(app, state, feed).await;
        }
    }
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
            auto_category: String::new(),
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
        assert!(auto_download_allows(&followed(0, 0), &item("huge.iso", 4000), 0), "no caps set");
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
        let bytes = build_list("T", "me", &items).unwrap();
        let path = std::env::temp_dir().join(format!("ember-feed-list-{}-{}.emulecollection", std::process::id(), rand::random::<u64>()));
        std::fs::write(&path, &bytes).unwrap();
        let mut feed = followed(0, 0);
        feed.list_size = bytes.len() as i64;
        feed.list_ed2k = crate::network::ed2k::hash::ed2k_hash_bytes(&bytes);
        feed.list_blake3 = blake3::hash(&bytes).to_hex().to_string();
        assert_eq!(read_list(&path, &feed), Some(items));
        feed.list_blake3 = "00".repeat(32);
        assert_eq!(read_list(&path, &feed), None);
        let _ = std::fs::remove_file(&path);
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
            published_title: "Published".into(),
            published_description: "old words".into(),
            changed: true,
        };
        let head = own_head(&feed).unwrap();
        assert_eq!((head.title.as_str(), head.description.as_str(), head.sequence), ("Published", "old words", 7));
        feed.published_title.clear();
        assert_eq!(own_head(&feed).unwrap().title, "Edited", "published by a build that kept no copy");
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
