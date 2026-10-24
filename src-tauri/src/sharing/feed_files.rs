//! Files kept for feeds: served without being listed, and fetched without
//! being a download the user sees.
//!
//! A feed's list is a collection file the publisher keeps under the app data
//! folder, and that each follower keeps as long as it follows. It has to be
//! served to anyone who asks for its hash and found through Ember source
//! records, yet never appear in the Library, a browse answer, a keyword
//! record, KAD or a server — the index carries every one of those, so a list
//! never enters it. [`hidden_shares`] is what the upload server and the Ember
//! source publisher read instead.
//!
//! A follower fetches a list through the ordinary download pipeline, which
//! finds sources and verifies the bytes, as an [`internal_fetch`]: kept out of
//! the transfer list, its row never saved, and on completion moved into the
//! feeds folder and handed to the feeds code rather than added to the Library.
//!
//! Static, as `category_folders` is: the upload server, the download workers
//! and the network loop all read these, and none has a handle the others do.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// A list kept for a feed and served to whoever asks for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenShare {
    pub path: PathBuf,
    pub size: u64,
    /// The name a downloader is told.
    pub name: String,
    /// Lowercase hex, 64 characters.
    pub ember_file_hash: String,
}

/// Each list served, with every holder of it: two feeds can hold the same
/// bytes (one publisher's feeds with the same title and files), and one
/// letting go must not stop the other's being served.
type Shares = HashMap<[u8; 16], Vec<(String, HiddenShare)>>;

fn hidden() -> &'static parking_lot::RwLock<Shares> {
    static SHARES: std::sync::OnceLock<parking_lot::RwLock<Shares>> = std::sync::OnceLock::new();
    SHARES.get_or_init(Default::default)
}

/// Serve `share` to anyone asking for `ed2k_hash`, held by `owner` (a feed).
pub fn share_hidden(ed2k_hash: [u8; 16], owner: &str, share: HiddenShare) {
    let mut shares = hidden().write();
    let holders = shares.entry(ed2k_hash).or_default();
    holders.retain(|(held_by, _)| held_by != owner);
    holders.push((owner.to_string(), share));
}

/// `owner` no longer holds `ed2k_hash`. Whether that was the last holder,
/// so nothing serves it now; `false` when `owner` held nothing there.
pub fn unshare_hidden(ed2k_hash: &[u8; 16], owner: &str) -> bool {
    let mut shares = hidden().write();
    let Some(holders) = shares.get_mut(ed2k_hash) else {
        return false;
    };
    let before = holders.len();
    holders.retain(|(held_by, _)| held_by != owner);
    if holders.len() == before {
        return false;
    }
    if holders.is_empty() {
        shares.remove(ed2k_hash);
        true
    } else {
        false
    }
}

/// The first of `holders` whose file is there, or the first at all: one
/// holder's copy deleted under it must not stop the others' being served.
fn served(holders: &[(String, HiddenShare)]) -> Option<&HiddenShare> {
    holders
        .iter()
        .find(|(_, share)| share.path.is_file())
        .or_else(|| holders.first())
        .map(|(_, share)| share)
}

/// The hidden share for `ed2k_hash`, if one is kept.
pub fn hidden_share(ed2k_hash: &[u8; 16]) -> Option<HiddenShare> {
    hidden().read().get(ed2k_hash).and_then(|holders| served(holders)).cloned()
}

/// Every hidden share, once per list, for the Ember source publisher.
pub fn hidden_shares() -> Vec<([u8; 16], HiddenShare)> {
    hidden()
        .read()
        .iter()
        .filter_map(|(hash, holders)| served(holders).map(|share| (*hash, share.clone())))
        .collect()
}

/// A download run for the feeds code rather than the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalFetch {
    /// Where the finished file goes, by its own name.
    pub dest: PathBuf,
    /// When the feeds code gave up on it, while the transfer may still be
    /// finishing. Still internal, so a late completion lands in the feeds
    /// folder rather than the user's, and is thrown away there.
    pub cancelled: Option<Instant>,
}

fn fetches() -> &'static parking_lot::Mutex<HashMap<String, InternalFetch>> {
    static FETCHES: std::sync::OnceLock<parking_lot::Mutex<HashMap<String, InternalFetch>>> =
        std::sync::OnceLock::new();
    FETCHES.get_or_init(Default::default)
}

/// Mark transfer `id` as a fetch for the feeds code, finishing at `dest`.
/// Before it is queued, so nothing that sees it first takes it for the
/// user's.
pub fn begin_internal_fetch(id: &str, dest: PathBuf) {
    fetches().lock().insert(id.to_string(), InternalFetch { dest, cancelled: None });
}

/// The feeds code gave up on fetch `id`. It stays internal until its
/// transfer reports an end, or [`forget_cancelled_fetches`] once it surely
/// will not.
pub fn cancel_internal_fetch(id: &str) {
    if let Some(fetch) = fetches().lock().get_mut(id) {
        fetch.cancelled.get_or_insert_with(Instant::now);
    }
}

/// Forget the fetches given up on at least `grace` ago whose transfers
/// never reported an end. One sweep for all of them, rather than a timer
/// each.
pub fn forget_cancelled_fetches(grace: Duration) {
    fetches().lock().retain(|_, fetch| fetch.cancelled.is_none_or(|at| at.elapsed() < grace));
}

/// Whether transfer `id` is a fetch for the feeds code.
pub fn is_internal_fetch(id: &str) -> bool {
    fetches().lock().contains_key(id)
}

/// Where internal fetch `id` finishes, if it is one.
pub fn internal_fetch_dest(id: &str) -> Option<PathBuf> {
    fetches().lock().get(id).map(|fetch| fetch.dest.clone())
}

/// Forget internal fetch `id`: finished, failed or given up on.
pub fn end_internal_fetch(id: &str) -> Option<InternalFetch> {
    fetches().lock().remove(id)
}

/// How an internal fetch ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// Verified and moved to where it asked to finish.
    Done(PathBuf),
    /// The bytes the eD2K hash names are not what the head pinned (its
    /// BLAKE3 or AICH): the list does not match its head, and no source can
    /// change that.
    Mismatch(String),
    Failed(String),
}

impl FetchOutcome {
    /// A failure with `error`: [`FetchOutcome::Mismatch`] for a pin the
    /// finished file missed, otherwise [`FetchOutcome::Failed`].
    pub fn failed(error: String) -> Self {
        use crate::network::ed2k::transfer::{is_ember_blake3_mismatch, is_expected_aich_mismatch};
        if is_ember_blake3_mismatch(&error) || is_expected_aich_mismatch(&error) {
            Self::Mismatch(error)
        } else {
            Self::Failed(error)
        }
    }
}

type FetchReports = tokio::sync::mpsc::UnboundedSender<(String, FetchOutcome)>;

fn fetch_reports() -> &'static parking_lot::Mutex<Option<FetchReports>> {
    static REPORTS: std::sync::OnceLock<parking_lot::Mutex<Option<FetchReports>>> = std::sync::OnceLock::new();
    REPORTS.get_or_init(Default::default)
}

/// Where the feeds code hears how its fetches end.
pub fn listen_for_fetches() -> tokio::sync::mpsc::UnboundedReceiver<(String, FetchOutcome)> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    *fetch_reports().lock() = Some(tx);
    rx
}

/// Tell the feeds code how internal fetch `id` ended, and forget it. A file
/// a cancelled fetch finished with is deleted instead.
pub fn report_fetch(id: &str, outcome: FetchOutcome) {
    if end_internal_fetch(id).is_some_and(|fetch| fetch.cancelled.is_some()) {
        if let FetchOutcome::Done(path) = outcome {
            let _ = std::fs::remove_file(path);
        }
        return;
    }
    if let Some(tx) = fetch_reports().lock().as_ref() {
        let _ = tx.send((id.to_string(), outcome));
    }
}

type PushedHeads = tokio::sync::mpsc::Sender<([u8; 32], Vec<u8>)>;

fn pushed_heads() -> &'static parking_lot::Mutex<Option<PushedHeads>> {
    static PUSHED: std::sync::OnceLock<parking_lot::Mutex<Option<PushedHeads>>> = std::sync::OnceLock::new();
    PUSHED.get_or_init(Default::default)
}

/// Where the feeds code hears of feed heads friends push over their
/// sessions: `(the friend's identity key, the signed head as a value blob)`.
pub fn listen_for_pushed_heads() -> tokio::sync::mpsc::Receiver<([u8; 32], Vec<u8>)> {
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    *pushed_heads().lock() = Some(tx);
    rx
}

/// A friend with identity key `from` pushed `blob`. Dropped when the feeds
/// code is behind: the next lookup finds the head anyway.
pub fn report_pushed_head(from: [u8; 32], blob: Vec<u8>) {
    if let Some(tx) = pushed_heads().lock().as_ref() {
        let _ = tx.try_send((from, blob));
    }
}

/// The folder feeds keep their lists in, under the app data folder.
pub fn feeds_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("feeds")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hidden_share_is_found_by_hash_until_it_is_dropped() {
        let hash = [0xA7u8; 16];
        let share = HiddenShare { path: PathBuf::from("x"), size: 3, name: "n".into(), ember_file_hash: "e".into() };
        share_hidden(hash, "a", share.clone());
        assert_eq!(hidden_share(&hash), Some(share.clone()));
        assert!(hidden_shares().iter().any(|(h, _)| *h == hash));
        share_hidden(hash, "b", HiddenShare { path: PathBuf::from("y"), ..share.clone() });
        assert!(!unshare_hidden(&hash, "a"), "the other holder still serves it");
        assert_eq!(hidden_share(&hash).map(|s| s.path), Some(PathBuf::from("y")));
        assert!(unshare_hidden(&hash, "b"));
        assert!(hidden_share(&hash).is_none());
        assert!(!unshare_hidden(&hash, "b"), "nothing was held");
    }

    #[test]
    fn an_internal_fetch_is_known_until_it_ends() {
        let id = "feed-fetch-test-id";
        assert!(!is_internal_fetch(id));
        begin_internal_fetch(id, PathBuf::from("d/list"));
        assert!(is_internal_fetch(id));
        assert_eq!(internal_fetch_dest(id), Some(PathBuf::from("d/list")));
        assert!(end_internal_fetch(id).is_some());
        assert!(!is_internal_fetch(id));
    }

    #[test]
    fn a_cancelled_fetch_stays_internal_and_its_file_is_dropped() {
        let id = "feed-fetch-cancelled-id";
        let file = std::env::temp_dir().join(format!("ember-feed-cancelled-{}", std::process::id()));
        std::fs::write(&file, b"list").unwrap();
        begin_internal_fetch(id, file.clone());
        cancel_internal_fetch(id);
        assert!(is_internal_fetch(id), "a late completion must still be taken as internal");
        report_fetch(id, FetchOutcome::Done(file.clone()));
        assert!(!is_internal_fetch(id));
        assert!(!file.exists());

        begin_internal_fetch(id, file.clone());
        forget_cancelled_fetches(Duration::ZERO);
        assert!(is_internal_fetch(id), "only a cancelled fetch is forgotten");
        cancel_internal_fetch(id);
        forget_cancelled_fetches(Duration::from_secs(600));
        assert!(is_internal_fetch(id), "not before its grace is up");
        forget_cancelled_fetches(Duration::ZERO);
        assert!(!is_internal_fetch(id));
    }

    #[test]
    fn a_pin_the_finished_file_missed_is_a_mismatch_and_anything_else_a_failure() {
        let pin = crate::network::ed2k::transfer::EMBER_BLAKE3_MISMATCH_MSG.to_string();
        assert_eq!(FetchOutcome::failed(pin.clone()), FetchOutcome::Mismatch(pin));
        let aich = "expected AICH hash mismatch for part 3".to_string();
        assert_eq!(FetchOutcome::failed(aich.clone()), FetchOutcome::Mismatch(aich));
        let reset = "connection reset by peer".to_string();
        assert_eq!(FetchOutcome::failed(reset.clone()), FetchOutcome::Failed(reset));
    }

    #[test]
    fn a_list_is_served_from_a_holder_whose_file_is_there() {
        let hash = [0xB3u8; 16];
        let dir = std::env::temp_dir().join(format!("ember-feed-holders-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let (gone, there) = (dir.join("gone"), dir.join("there"));
        std::fs::write(&there, b"list").unwrap();
        let share = |path: &Path| HiddenShare { path: path.to_path_buf(), size: 4, name: "n".into(), ember_file_hash: "e".into() };
        share_hidden(hash, "first", share(&gone));
        share_hidden(hash, "second", share(&there));
        assert_eq!(hidden_share(&hash).map(|s| s.path), Some(there.clone()));
        assert!(hidden_shares().iter().any(|(h, s)| *h == hash && s.path == there));
        std::fs::remove_file(&there).unwrap();
        assert_eq!(hidden_share(&hash).map(|s| s.path), Some(gone), "none there: still the first");
        unshare_hidden(&hash, "first");
        unshare_hidden(&hash, "second");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
