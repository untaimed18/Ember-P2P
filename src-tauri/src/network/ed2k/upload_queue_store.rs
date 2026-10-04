//! `upload-queue.json`: the upload waiting queue, carried across a restart.
//!
//! The queue lives in memory, so every restart used to drop everyone waiting on
//! this node, however long they had waited. eMule itself does the same, but a
//! remote eMule keeps *our* place in its queue for an hour after our last
//! re-ask (`MAX_PURGEQUEUETIME`), so a short restart costs this user nothing
//! while it cost the people queued here their whole wait. Saving the queue on
//! every graceful shutdown and restoring the rows still inside that same purge
//! window treats them the way they treat us.
//!
//! What comes back is a waiter's *seniority*, not its standing: rows are
//! restored unbound, with friend-slot and Ember verification cleared, and earn
//! both again on the peer's next re-ask exactly as a reconnecting peer does.
//! The file is untrusted like everything in the data directory, and a row
//! restored as HighID is one the upload queue may dial for a push-grant, so
//! rows naming a private or special-use address, or anything malformed, are
//! dropped on the way in.
//!
//! Restored rows do not join the live queue at once. At launch the library
//! index is still empty while the startup scan runs, so the queue's own purge
//! would evict every one of them as a waiter for a file we do not share — and
//! a push-grant dialled in that window would offer a file we cannot yet find.
//! They wait in [`PendingRestore`] until the startup scan says the library is
//! in the index (`NetworkCommand::StartupLibraryIndexed`, sent at once for a
//! node with no shared folders) and the last session's downloads are back in
//! the transfer manager, and then only the rows for files we serve are merged.
//! A long fallback deadline covers a scan that fails without saying so.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::upload::{
    index_offers_hash, QueueEntry, QueueIdentity, UploadQueueRef, MAX_PURGEQUEUETIME_SECS,
    MAX_QUEUE_ENTRIES_PER_IP, MAX_UPLOAD_QUEUE_SIZE,
};
use crate::search::index::LocalIndex;
use crate::sharing::manager::TransferManager;
use crate::types::TransferDirection;

pub const FILE: &str = "upload-queue.json";

const VERSION: u32 = 1;
/// Far above any real queue; a file claiming more is corrupt.
const MAX_ENTRIES: usize = 10_000;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TEXT_CHARS: usize = 256;
/// When restored rows are merged if the startup scan never said the library is
/// indexed — it failed, or was cancelled before discovery finished. Long, since
/// merging early drops every waiter for a file not indexed yet; waiters re-ask
/// within the purge window anyway.
const MERGE_FALLBACK: Duration = Duration::from_secs(20 * 60);
/// A row stamped in the future by more than this was written under a wrong
/// clock, and its age says nothing.
const MAX_FUTURE_SKEW_SECS: i64 = 5 * 60;

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotFile {
    version: u32,
    entries: Vec<SavedEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SavedEntry {
    /// `None` for a row keyed on its address because the peer sent no user hash.
    #[serde(default)]
    user_hash: Option<String>,
    last_ip: IpAddr,
    udp_port: u16,
    tcp_port: u16,
    crypt_options: u8,
    is_high_id: bool,
    file_hash: String,
    /// Unix seconds.
    joined_at: i64,
    /// Unix seconds.
    last_request_at: i64,
    emule_version: u8,
    #[serde(default)]
    ember_pubkey: Option<String>,
    #[serde(default)]
    peer_name: String,
    #[serde(default)]
    client_software: String,
}

fn decode_16(hex_text: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(hex_text).ok()?;
    bytes.try_into().ok()
}

fn decode_32(hex_text: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_text).ok()?;
    bytes.try_into().ok()
}

fn clip(text: &str) -> String {
    text.chars().take(MAX_TEXT_CHARS).collect()
}

/// An address a restored row may be dialled at: eD2K is IPv4, and a private or
/// special-use address in a file anything local can write is not one the queue
/// should be made to call.
fn restorable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !crate::security::is_special_use_v4(v4),
        IpAddr::V6(_) => false,
    }
}

/// Wall-clock seconds for an `Instant` in the past.
fn unix_of(instant: Instant, now: Instant, now_unix: i64) -> i64 {
    let ago = i64::try_from(now.saturating_duration_since(instant).as_secs()).unwrap_or(i64::MAX);
    now_unix.saturating_sub(ago)
}

/// The `Instant` for wall-clock `at`, or `None` when the monotonic clock cannot
/// reach back that far. Only Windows, whose clock counts from boot, has that
/// floor; elsewhere an `Instant` reaches back past a reboot, and a row from
/// before one keeps its true age and leaves the purge window on time.
fn instant_of(at: i64, now: Instant, now_unix: i64) -> Option<Instant> {
    let ago = now_unix.saturating_sub(at).max(0);
    now.checked_sub(Duration::from_secs(ago as u64))
}

fn to_saved(entry: &QueueEntry, now: Instant, now_unix: i64) -> Option<SavedEntry> {
    if entry.last_request.elapsed().as_secs() >= MAX_PURGEQUEUETIME_SECS {
        return None;
    }
    let last_ip = entry.last_ip?;
    let user_hash = match &entry.identity {
        QueueIdentity::UserHash(hash) => Some(hex::encode(hash)),
        QueueIdentity::Ip(_) => None,
    };
    Some(SavedEntry {
        user_hash,
        last_ip,
        udp_port: entry.udp_port,
        tcp_port: entry.tcp_port,
        crypt_options: entry.crypt_options,
        is_high_id: entry.is_high_id,
        file_hash: hex::encode(entry.file_hash),
        joined_at: unix_of(entry.join_time, now, now_unix),
        last_request_at: unix_of(entry.last_request, now, now_unix),
        emule_version: entry.emule_version,
        ember_pubkey: entry.ember_pubkey.map(hex::encode),
        peer_name: clip(&entry.peer_name),
        client_software: clip(&entry.client_software),
    })
}

fn from_saved(
    saved: SavedEntry,
    now: Instant,
    now_unix: i64,
    instant_at: &impl Fn(i64) -> Option<Instant>,
) -> Option<QueueEntry> {
    let waited_since_ask = now_unix.saturating_sub(saved.last_request_at);
    if !(-MAX_FUTURE_SKEW_SECS..MAX_PURGEQUEUETIME_SECS as i64).contains(&waited_since_ask) {
        return None;
    }
    if !restorable_ip(saved.last_ip) {
        return None;
    }
    let file_hash = decode_16(&saved.file_hash).filter(|hash| *hash != [0u8; 16])?;
    let (identity, user_hash) = match saved.user_hash.as_deref() {
        Some(text) => {
            let hash = decode_16(text).filter(|hash| *hash != [0u8; 16])?;
            (QueueIdentity::UserHash(hash), hash)
        }
        None => (QueueIdentity::Ip(saved.last_ip), [0u8; 16]),
    };
    let ember_pubkey = match saved.ember_pubkey.as_deref() {
        Some(text) => Some(decode_32(text)?),
        None => None,
    };
    // A last request the monotonic clock cannot reach was made before a
    // reboot. Stamped `now`, it would restart the purge window and be dialled
    // for a push-grant as if it had just asked; its seniority is lost anyway.
    let last_request = instant_at(saved.last_request_at)?;
    // A join after the last request cannot happen; clamp rather than let a
    // rewritten file hand a row more wait than it could have accrued.
    let join_time = instant_at(saved.joined_at.min(saved.last_request_at)).unwrap_or(now);
    Some(QueueEntry {
        identity,
        current_addr: None,
        last_ip: Some(saved.last_ip),
        udp_port: saved.udp_port,
        tcp_port: saved.tcp_port,
        crypt_options: saved.crypt_options,
        is_high_id: saved.is_high_id && saved.tcp_port != 0,
        user_hash,
        file_hash,
        join_time,
        last_request,
        add_next_connect: false,
        emule_version: saved.emule_version,
        is_friend_slot: false,
        ember_pubkey,
        ember_verified: false,
        peer_name: clip(&saved.peer_name),
        client_software: clip(&saved.client_software),
    })
}

/// The file's bytes, and how many rows went into it.
fn encode(entries: &[QueueEntry], now: Instant, now_unix: i64) -> serde_json::Result<(Vec<u8>, usize)> {
    let entries: Vec<SavedEntry> = entries
        .iter()
        .filter_map(|entry| to_saved(entry, now, now_unix))
        .take(MAX_ENTRIES)
        .collect();
    let count = entries.len();
    let bytes = serde_json::to_vec(&SnapshotFile {
        version: VERSION,
        entries,
    })?;
    Ok((bytes, count))
}

fn decode(bytes: &[u8], now: Instant, now_unix: i64) -> Vec<QueueEntry> {
    decode_on(bytes, now, now_unix, |at| instant_of(at, now, now_unix))
}

/// [`decode`] with the wall-clock-to-`Instant` conversion supplied.
fn decode_on(
    bytes: &[u8],
    now: Instant,
    now_unix: i64,
    instant_at: impl Fn(i64) -> Option<Instant>,
) -> Vec<QueueEntry> {
    let Ok(file) = serde_json::from_slice::<SnapshotFile>(bytes) else {
        tracing::warn!("Discarding an unreadable {FILE}");
        return Vec::new();
    };
    if file.version != VERSION {
        tracing::warn!("Discarding a {FILE} this build does not understand");
        return Vec::new();
    }
    let mut per_ip: HashMap<IpAddr, usize> = HashMap::new();
    // One row per peer, as the live queue keeps it: rank, removal and slot
    // grants all find a peer by identity alone, so a second row for another
    // file would be one they never reach, or reach instead of the right one.
    // The first row wins; the file is saved live rows first.
    let mut seen: HashSet<QueueIdentity> = HashSet::new();
    file.entries
        .into_iter()
        .take(MAX_ENTRIES)
        .filter_map(|saved| from_saved(saved, now, now_unix, &instant_at))
        .filter(|entry| seen.insert(entry.identity.clone()))
        .filter(|entry| {
            let Some(ip) = entry.last_ip else {
                return false;
            };
            let count = per_ip.entry(ip).or_default();
            *count += 1;
            *count <= MAX_QUEUE_ENTRIES_PER_IP
        })
        .collect()
}

/// Waiters restored from the last session, held until the library is known.
#[derive(Debug)]
pub(crate) struct PendingRestore {
    entries: Vec<QueueEntry>,
    deadline: Instant,
}

impl PendingRestore {
    /// Whether the fallback deadline has passed without the startup signal.
    pub(crate) fn overdue(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// The startup signal came, so merge at the next check instead of waiting
    /// for the fallback.
    pub(crate) fn make_due(&mut self) {
        self.deadline = Instant::now();
    }

    /// The rows themselves, for a shutdown before the merge that could not
    /// read the live queue: they are saved again rather than lost.
    pub(crate) fn into_entries(self) -> Vec<QueueEntry> {
        self.entries
    }
}

/// Merge restored rows into the live queue, keeping only rows for files
/// `servable` says we serve and applying the caps the live queue applies.
///
/// A peer that re-asked before the merge already has a live row, which wins —
/// whichever file it now wants, since the live queue holds one row per peer.
/// It inherits the restored row's earlier join only under the rule a
/// reconnect is held to ([`may_inherit_join`]).
/// A peer in `asked` that has no live row left it for a reason newer than
/// its restored row (a slot, a cancel, a ban), so that row stays out.
fn merge_into(
    queue: &mut Vec<QueueEntry>,
    restored: Vec<QueueEntry>,
    asked: &HashSet<QueueIdentity>,
    servable: impl Fn(&[u8; 16]) -> bool,
) -> usize {
    let mut merged = 0;
    for row in restored {
        if row.last_request.elapsed().as_secs() >= MAX_PURGEQUEUETIME_SECS {
            continue;
        }
        if let Some(live) = queue.iter_mut().find(|e| e.identity == row.identity) {
            if may_inherit_join(live, &row) && row.join_time < live.join_time {
                live.join_time = row.join_time;
            }
            continue;
        }
        if asked.contains(&row.identity) || !servable(&row.file_hash) {
            continue;
        }
        if queue.len() >= MAX_UPLOAD_QUEUE_SIZE {
            break;
        }
        let same_ip = queue.iter().filter(|e| e.last_ip == row.last_ip).count();
        if same_ip >= MAX_QUEUE_ENTRIES_PER_IP {
            continue;
        }
        queue.push(row);
        merged += 1;
    }
    merged
}

/// Whether a peer's live row may take its restored row's earlier join: it
/// asked from the address the row was last seen on, or proved the Ember key
/// the row recorded. The rule `session_may_inherit_seniority` holds a
/// reconnect to, since the user hash alone is replayable.
fn may_inherit_join(live: &QueueEntry, row: &QueueEntry) -> bool {
    live.last_ip == row.last_ip
        || (live.ember_verified && live.ember_pubkey.is_some() && live.ember_pubkey == row.ember_pubkey)
}

/// Fold rows still held into the live rows a shutdown is about to save, by the
/// merge's own rules minus the served-file check (the library may not be
/// indexed yet). The file keeps one row per peer, the live one, so a peer that
/// re-asked keeps its older wait only if it inherits it here.
pub(crate) fn fold_for_save(queue: &mut Vec<QueueEntry>, pending: PendingRestore) {
    let asked = asked_while_held().lock().take().unwrap_or_default();
    merge_into(queue, pending.entries, &asked, |_| true);
}

/// Merge `held` into the live queue once it is due — the library is indexed or
/// the fallback has passed — and the last session's downloads have been
/// restored. Until then a file we are still downloading is not in the
/// transfer manager yet, and everyone queued for it would be dropped as
/// waiting for a file we do not serve. Call from each side that can complete
/// last; the merge runs once, whichever it is.
pub(crate) async fn merge_when_ready(
    held: &mut Option<PendingRestore>,
    queue: &UploadQueueRef,
    local_index: &RwLock<LocalIndex>,
    transfer_manager: &RwLock<TransferManager>,
) {
    if !held.as_ref().is_some_and(PendingRestore::overdue) {
        return;
    }
    if !transfer_manager.read().await.restored {
        return;
    }
    if let Some(pending) = held.take() {
        merge_pending(pending, queue, local_index, transfer_manager).await;
    }
}

/// Merge a pending restore into the live queue now.
///
/// Takes the index, the transfer manager and the queue one at a time, never
/// nested, for the lock discipline `purge_unshared_queue_entries` keeps.
async fn merge_pending(
    pending: PendingRestore,
    queue: &UploadQueueRef,
    local_index: &RwLock<LocalIndex>,
    transfer_manager: &RwLock<TransferManager>,
) {
    let hashes: HashSet<[u8; 16]> = pending.entries.iter().map(|e| e.file_hash).collect();
    let shared: HashSet<[u8; 16]> = {
        let index = local_index.read().await;
        hashes
            .iter()
            .copied()
            .filter(|h| index_offers_hash(&index, h))
            .collect()
    };
    let downloading: HashSet<[u8; 16]> = {
        let mgr = transfer_manager.read().await;
        hashes
            .iter()
            .copied()
            .filter(|h| {
                let hex_h = hex::encode(h);
                mgr.active
                    .values()
                    .any(|t| t.direction == TransferDirection::Download && t.file_hash == hex_h)
                    || mgr
                        .queue
                        .iter()
                        .any(|t| t.direction == TransferDirection::Download && t.file_hash == hex_h)
            })
            .collect()
    };
    let offered = pending.entries.len();
    let asked = asked_while_held().lock().take().unwrap_or_default();
    let merged = merge_into(&mut *queue.lock().await, pending.entries, &asked, |h| {
        shared.contains(h) || downloading.contains(h)
    });
    tracing::info!("Upload queue: {merged} of {offered} waiter(s) from the last session rejoined");
}

/// Write the waiting rows still inside the purge window to `dir`.
pub fn save(dir: &Path, entries: &[QueueEntry]) -> anyhow::Result<usize> {
    let (bytes, count) = encode(entries, Instant::now(), chrono::Utc::now().timestamp())?;
    crate::security::atomic_write(&dir.join(FILE), &bytes, true)?;
    Ok(count)
}

/// Take the saved queue from `dir`, once, as a restore waiting to be merged.
/// `None` when there is nothing to restore.
pub(crate) fn restore(dir: &Path) -> Option<PendingRestore> {
    let entries = read_saved(dir);
    if entries.is_empty() {
        return None;
    }
    *asked_while_held().lock() = Some(HashSet::new());
    Some(PendingRestore {
        entries,
        deadline: Instant::now() + MERGE_FALLBACK,
    })
}

/// Identities that asked for an upload while restored rows were held,
/// collected only then. See [`merge_into`].
fn asked_while_held() -> &'static parking_lot::Mutex<Option<HashSet<QueueIdentity>>> {
    static ASKED: std::sync::OnceLock<parking_lot::Mutex<Option<HashSet<QueueIdentity>>>> =
        std::sync::OnceLock::new();
    ASKED.get_or_init(Default::default)
}

/// Note a peer whose ask got it a live row, a slot or a ban, for a restore
/// still held. Not one refused a row (queue full, per-IP cap): the restored
/// row is the place it still has.
pub(crate) fn note_asked(identity: &QueueIdentity) {
    if let Some(asked) = asked_while_held().lock().as_mut() {
        if asked.len() < MAX_UPLOAD_QUEUE_SIZE * 10 {
            asked.insert(identity.clone());
        }
    }
}

/// The file is removed whether or not it parses, so a crash before the next
/// save cannot restore the same rows twice.
fn read_saved(dir: &Path) -> Vec<QueueEntry> {
    let path = dir.join(FILE);
    let Ok(meta) = std::fs::metadata(&path) else {
        return Vec::new();
    };
    let bytes = if meta.len() > MAX_FILE_BYTES {
        tracing::warn!("Discarding an oversized {FILE}");
        None
    } else {
        std::fs::read(&path).ok()
    };
    if let Err(error) = std::fs::remove_file(&path) {
        tracing::warn!("Not restoring the upload queue: could not remove {FILE}: {error}");
        return Vec::new();
    }
    let Some(bytes) = bytes else {
        return Vec::new();
    };
    let entries = decode(&bytes, Instant::now(), chrono::Utc::now().timestamp());
    if !entries.is_empty() {
        tracing::info!(
            "Holding {} upload queue waiter(s) from the last session until the library loads",
            entries.len()
        );
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const NOW_UNIX: i64 = 1_790_000_000;

    fn entry(user_hash: [u8; 16], ip: [u8; 4], waited_secs: u64, since_ask_secs: u64) -> QueueEntry {
        let now = Instant::now();
        let ip = IpAddr::V4(Ipv4Addr::from(ip));
        QueueEntry {
            identity: QueueIdentity::UserHash(user_hash),
            current_addr: Some(std::net::SocketAddr::new(ip, 50_000)),
            last_ip: Some(ip),
            udp_port: 4672,
            tcp_port: 4662,
            crypt_options: 0x03,
            is_high_id: true,
            user_hash,
            file_hash: [0xAB; 16],
            join_time: now - Duration::from_secs(waited_secs),
            last_request: now - Duration::from_secs(since_ask_secs),
            add_next_connect: true,
            emule_version: 0x99,
            is_friend_slot: true,
            ember_pubkey: Some([0x11; 32]),
            ember_verified: true,
            peer_name: "Aoife".to_string(),
            client_software: "eMule 0.50a".to_string(),
        }
    }

    fn round_trip(entries: &[QueueEntry], later_secs: i64) -> Vec<QueueEntry> {
        let now = Instant::now();
        let (bytes, _) = encode(entries, now, NOW_UNIX).unwrap();
        decode(&bytes, now + Duration::from_secs(later_secs as u64), NOW_UNIX + later_secs)
    }

    #[test]
    fn a_waiter_keeps_its_seniority_but_not_its_standing() {
        let saved = entry([1; 16], [8, 8, 8, 8], 7200, 600);
        let restored = round_trip(std::slice::from_ref(&saved), 60);
        assert_eq!(restored.len(), 1);
        let row = &restored[0];
        assert_eq!(row.identity, saved.identity);
        assert_eq!(row.file_hash, saved.file_hash);
        assert_eq!(row.tcp_port, 4662);
        assert!(row.is_high_id);
        assert!(row.join_time.elapsed() >= Duration::from_secs(7200 - 5));
        assert!(row.last_request.elapsed() >= Duration::from_secs(600));

        assert_eq!(row.current_addr, None, "restored unbound, like a reconnect");
        assert!(!row.is_friend_slot, "friend standing is re-earned on the re-ask");
        assert!(!row.ember_verified, "so is Ember verification");
        assert!(!row.add_next_connect);
        assert_eq!(row.ember_pubkey, saved.ember_pubkey);
    }

    #[test]
    fn rows_past_the_purge_window_do_not_come_back() {
        let fresh = entry([1; 16], [8, 8, 8, 8], 7200, 1800);
        let stale = entry([2; 16], [8, 8, 4, 4], 7200, MAX_PURGEQUEUETIME_SECS + 1);
        // Inside the window when saved, outside it by the time Ember is back.
        let expiring = entry([3; 16], [1, 1, 1, 1], 7200, MAX_PURGEQUEUETIME_SECS - 30);
        let restored = round_trip(&[fresh, stale, expiring], 60);
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].identity, QueueIdentity::UserHash([1; 16]));
    }

    #[test]
    fn private_addresses_and_malformed_rows_are_dropped() {
        let lan = entry([1; 16], [192, 168, 1, 20], 60, 60);
        let loopback = entry([2; 16], [127, 0, 0, 1], 60, 60);
        let mut no_file = entry([3; 16], [8, 8, 8, 8], 60, 60);
        no_file.file_hash = [0; 16];
        assert!(round_trip(&[lan, loopback, no_file], 1).is_empty());

        let now = Instant::now();
        let (bytes, _) = encode(&[entry([4; 16], [8, 8, 8, 8], 60, 60)], now, NOW_UNIX).unwrap();
        let text = String::from_utf8(bytes).unwrap().replace(&"04".repeat(16), "zz");
        assert!(decode(text.as_bytes(), now, NOW_UNIX).is_empty(), "bad hex");
        assert!(decode(b"{not json", now, NOW_UNIX).is_empty());
        assert!(decode(br#"{"version":99,"entries":[]}"#, now, NOW_UNIX).is_empty());
    }

    #[test]
    fn a_rewritten_file_cannot_flood_one_address_or_duplicate_a_row() {
        let rows: Vec<QueueEntry> = (0..6u8)
            .map(|i| entry([i + 1; 16], [8, 8, 8, 8], 60, 60))
            .collect();
        assert_eq!(round_trip(&rows, 1).len(), MAX_QUEUE_ENTRIES_PER_IP);

        let twice = [entry([9; 16], [8, 8, 8, 8], 60, 60), entry([9; 16], [9, 9, 9, 9], 60, 60)];
        assert_eq!(round_trip(&twice, 1).len(), 1);
    }

    #[test]
    fn a_join_cannot_be_later_than_the_last_request() {
        let now = Instant::now();
        let (bytes, _) = encode(&[entry([1; 16], [8, 8, 8, 8], 60, 60)], now, NOW_UNIX).unwrap();
        let mut file: SnapshotFile = serde_json::from_slice(&bytes).unwrap();
        file.entries[0].joined_at = file.entries[0].last_request_at + 10_000;
        let bytes = serde_json::to_vec(&file).unwrap();
        let row = &decode(&bytes, now, NOW_UNIX)[0];
        assert!(row.join_time <= row.last_request);
    }

    #[test]
    fn restore_consumes_the_file() {
        let dir = std::env::temp_dir().join(format!(
            "ember-upload-queue-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(save(&dir, &[entry([1; 16], [8, 8, 8, 8], 60, 60)]).unwrap(), 1);
        let pending = restore(&dir).unwrap();
        assert_eq!(pending.entries.len(), 1);
        assert!(!pending.overdue());
        assert!(!dir.join(FILE).exists());
        assert!(restore(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn restored(user_hash: [u8; 16], ip: [u8; 4], waited_secs: u64) -> QueueEntry {
        let mut row = entry(user_hash, ip, waited_secs, 60);
        row.current_addr = None;
        row
    }

    #[test]
    fn only_rows_for_files_we_serve_rejoin() {
        let served = restored([1; 16], [8, 8, 8, 8], 600);
        let mut unserved = restored([2; 16], [9, 9, 9, 9], 600);
        unserved.file_hash = [0xCD; 16];
        let mut queue = Vec::new();
        let merged = merge_into(&mut queue, vec![served, unserved], &HashSet::new(), |h| *h == [0xAB; 16]);
        assert_eq!(merged, 1);
        assert_eq!(queue[0].identity, QueueIdentity::UserHash([1; 16]));
    }

    #[test]
    fn a_peer_that_re_asked_first_keeps_its_live_row_and_its_older_wait() {
        let old = restored([1; 16], [8, 8, 8, 8], 3000);
        let mut live = entry([1; 16], [8, 8, 8, 8], 10, 10);
        let live_join = live.join_time;
        let mut queue = vec![live.clone()];
        assert_eq!(merge_into(&mut queue, vec![old.clone()], &HashSet::new(), |_| true), 0);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].current_addr, live.current_addr, "the live row wins");
        assert_eq!(queue[0].join_time, old.join_time, "and inherits the earlier join");

        // From another address and without proving the row's Ember key, the
        // wait is not inherited — the rule a reconnect is held to.
        live.last_ip = Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
        live.ember_verified = false;
        live.join_time = live_join;
        let mut queue = vec![live];
        merge_into(&mut queue, vec![old], &HashSet::new(), |_| true);
        assert_eq!(queue[0].join_time, live_join);
    }

    #[test]
    fn a_verified_ember_key_inherits_the_wait_from_another_address() {
        let old = restored([1; 16], [8, 8, 8, 8], 3000);
        let mut live = entry([1; 16], [9, 9, 9, 9], 10, 10);
        let live_join = live.join_time;
        let mut queue = vec![live.clone()];
        merge_into(&mut queue, vec![old.clone()], &HashSet::new(), |_| true);
        assert_eq!(queue[0].join_time, old.join_time, "the key the row recorded, proven");

        live.ember_pubkey = Some([0x22; 32]);
        let mut queue = vec![live.clone()];
        merge_into(&mut queue, vec![old.clone()], &HashSet::new(), |_| true);
        assert_eq!(queue[0].join_time, live_join, "another key proves nothing");

        live.ember_pubkey = old.ember_pubkey;
        live.ember_verified = false;
        let mut queue = vec![live];
        merge_into(&mut queue, vec![old], &HashSet::new(), |_| true);
        assert_eq!(queue[0].join_time, live_join, "an unproven key is only a claim");
    }

    /// A peer that re-asked while its row was held, then a shutdown before the
    /// merge: the file keeps only the first row per peer, the live one, so the
    /// older wait has to be on it by then.
    #[test]
    fn a_shutdown_before_the_merge_saves_the_older_wait_on_the_live_row() {
        let held = restored([1; 16], [8, 8, 8, 8], 3000);
        let other = restored([2; 16], [9, 9, 9, 9], 3000);
        let mut queue = vec![entry([1; 16], [8, 8, 8, 8], 10, 10)];
        fold_for_save(
            &mut queue,
            PendingRestore {
                entries: vec![held, other],
                deadline: Instant::now(),
            },
        );
        assert_eq!(queue.len(), 2, "one row per peer");

        let now = Instant::now();
        let (bytes, _) = encode(&queue, now, NOW_UNIX).unwrap();
        let rows = decode(&bytes, now, NOW_UNIX);
        assert_eq!(rows.len(), 2);
        let row = rows
            .iter()
            .find(|r| r.identity == QueueIdentity::UserHash([1; 16]))
            .unwrap();
        assert!(row.join_time.elapsed() >= Duration::from_secs(3000 - 5));
    }

    #[test]
    fn a_row_last_asked_before_a_reboot_is_dropped() {
        // Two minutes of uptime: the monotonic clock reaches no further back.
        let now = Instant::now();
        let uptime_secs = 120;
        let clock = move |at: i64| {
            if NOW_UNIX - at <= uptime_secs {
                instant_of(at, now, NOW_UNIX)
            } else {
                None
            }
        };
        let before_boot = entry([1; 16], [8, 8, 8, 8], 7200, 600);
        let since_boot = entry([2; 16], [9, 9, 9, 9], 7200, 60);
        let (bytes, _) = encode(&[before_boot, since_boot], now, NOW_UNIX).unwrap();
        let rows = decode_on(&bytes, now, NOW_UNIX, clock);
        assert_eq!(rows.len(), 1, "its purge clock would restart at a full hour");
        let row = &rows[0];
        assert_eq!(row.identity, QueueIdentity::UserHash([2; 16]));
        assert!(row.last_request < now, "keeps the age it has");
        assert!(row.join_time >= now, "a join from before the boot is not kept");
    }

    /// A peer that asked while the rows were held and has no live row left
    /// was served, cancelled or refused since; its old row must not give it a
    /// second turn.
    #[test]
    fn a_peer_that_asked_while_held_and_left_does_not_rejoin() {
        let old = restored([1; 16], [8, 8, 8, 8], 3000);
        let other = restored([2; 16], [9, 9, 9, 9], 3000);
        let asked = HashSet::from([QueueIdentity::UserHash([1; 16])]);
        let mut queue = Vec::new();
        assert_eq!(merge_into(&mut queue, vec![old, other], &asked, |_| true), 1);
        assert_eq!(queue[0].identity, QueueIdentity::UserHash([2; 16]));
    }

    #[test]
    fn a_peer_that_switched_files_keeps_one_row() {
        // Queued for file A last session, re-asked for file B before the merge.
        let old = restored([1; 16], [8, 8, 8, 8], 3000);
        let mut live = entry([1; 16], [8, 8, 8, 8], 10, 10);
        live.file_hash = [0xCD; 16];
        let mut queue = vec![live];
        assert_eq!(merge_into(&mut queue, vec![old.clone()], &HashSet::new(), |_| true), 0);
        assert_eq!(queue.len(), 1, "the live queue holds one row per peer");
        assert_eq!(queue[0].file_hash, [0xCD; 16], "for the file it wants now");
        assert_eq!(queue[0].join_time, old.join_time, "keeping the wait it had");

        // And a saved file carrying both rows restores only the first.
        let now = Instant::now();
        let mut for_a = entry([2; 16], [9, 9, 9, 9], 60, 60);
        let mut for_b = for_a.clone();
        for_b.file_hash = [0xCD; 16];
        for_a.current_addr = None;
        let (bytes, _) = encode(&[for_a, for_b], now, NOW_UNIX).unwrap();
        let rows = decode(&bytes, now, NOW_UNIX);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].file_hash, [0xAB; 16]);
    }

    fn download_of(file_hash: [u8; 16]) -> crate::types::Transfer {
        serde_json::from_value(serde_json::json!({
            "id": "restored",
            "file_name": "restored.bin",
            "file_hash": hex::encode(file_hash),
            "peer_id": "",
            "peer_name": "",
            "direction": "download",
            "status": "searching",
            "progress": 0.0,
            "speed": 0,
            "total_size": 4096,
            "transferred": 0,
            "started_at": 0,
        }))
        .unwrap()
    }

    /// The library can be indexed long before last session's downloads are
    /// back in the transfer manager, and a merge in between dropped everyone
    /// queued for a file we were still downloading.
    #[tokio::test]
    async fn the_merge_waits_for_the_downloads_to_be_restored() {
        let file_hash = [0x5A; 16];
        let mut row = restored([0x5A; 16], [8, 8, 8, 8], 3000);
        row.file_hash = file_hash;
        let mut held = Some(PendingRestore {
            entries: vec![row],
            deadline: Instant::now() + MERGE_FALLBACK,
        });
        let queue: UploadQueueRef = Default::default();
        let index = RwLock::new(LocalIndex::new());
        let manager = RwLock::new(TransferManager::new(1));

        held.as_mut().unwrap().make_due();
        merge_when_ready(&mut held, &queue, &index, &manager).await;
        assert!(held.is_some(), "downloads not restored yet: the rows stay held");
        assert!(queue.lock().await.is_empty());

        {
            let mut mgr = manager.write().await;
            mgr.enqueue(download_of(file_hash));
            mgr.restored = true;
        }
        merge_when_ready(&mut held, &queue, &index, &manager).await;
        assert!(held.is_none(), "merged once both sides are ready");
        let live = queue.lock().await;
        assert_eq!(live.len(), 1, "a waiter for a file still downloading rejoins");
        assert_eq!(live[0].identity, QueueIdentity::UserHash([0x5A; 16]));
    }

    #[tokio::test]
    async fn restored_downloads_alone_do_not_merge_before_the_library_is_indexed() {
        let mut held = Some(PendingRestore {
            entries: vec![restored([0x5B; 16], [8, 8, 8, 8], 3000)],
            deadline: Instant::now() + MERGE_FALLBACK,
        });
        let queue: UploadQueueRef = Default::default();
        let index = RwLock::new(LocalIndex::new());
        let manager = RwLock::new(TransferManager::new(1));
        manager.write().await.restored = true;

        merge_when_ready(&mut held, &queue, &index, &manager).await;
        assert!(held.is_some());
    }

    #[test]
    fn a_merge_respects_the_live_queue_caps() {
        let mut queue: Vec<QueueEntry> = (0..MAX_QUEUE_ENTRIES_PER_IP as u8)
            .map(|i| entry([i + 1; 16], [8, 8, 8, 8], 60, 60))
            .collect();
        assert_eq!(merge_into(&mut queue, vec![restored([99; 16], [8, 8, 8, 8], 60)], &HashSet::new(), |_| true), 0);
    }
}
