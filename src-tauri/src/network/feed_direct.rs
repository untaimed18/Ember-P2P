//! A feed's files are fetched from their publisher first, over the feed
//! stream: the same request, chunk list and BLAKE3-checked chunks a chat
//! file crosses, on QUIC pinned to the publisher's identity or, when its QUIC
//! port does not answer, a secure stream on its TCP upload port. Nobody need
//! be a friend: a feed is public to whoever has its link, and the request
//! names the file by what only the link and list let one compute (see
//! `ember::attach::feed_stream_id`).
//!
//! While a feed download is held here, the only source looked for is the
//! publisher: KAD, the servers and other publishers' Ember records wait. The
//! publisher is found by its own signed Ember source record for the file; a
//! friend publisher's last address is tried at once, before any lookup. The
//! stream is a source of the download like a web mirror is, inside its worker
//! (`ed2k::multi_source::feed_worker`), so progress, pause, cancel and the
//! final checks are the download's own. The hold ends, and every network is
//! asked, as soon as the publisher is found not to be there, the stream
//! fails, or nothing has arrived for [`HOLD_IDLE`] once the lookup has
//! answered ([`LOOKUP_MAX`] before then). Time paused or waiting for a
//! download slot is not counted.
//!
//! Held in memory only, and held again when a feed's download is restored
//! after a restart (see `network::event_loop::resume_downloads`). Every
//! download held is watched by the feeds service, which ends its hold when
//! it is due and forgets it once the download ends (see [`watched`]).
//!
//! The publisher's half is here too: which files a follower may ask for,
//! and how many are served at once.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::ember::attach::{feed_stream_capability, feed_stream_id, AttachStreamStatus, FEED_STREAM_MAX_BYTES};
use super::ember::dht::publish::DiscoveredSource;

/// How long a held download may go without a byte before the rest of the
/// network is asked: from the lookup's answer, and again whenever the
/// publisher stops sending.
pub const HOLD_IDLE: Duration = Duration::from_secs(45);
/// How long the first lookup may take to answer. One on a cold routing table
/// can run most of its 60-second cap.
pub const LOOKUP_MAX: Duration = Duration::from_secs(75);
/// More feed downloads than every followed feed's auto-download starts; past
/// it a download is simply not held, and looks everywhere at once.
const MAX_HOLDS: usize = 16_384;
/// Feed files a publisher streams at once. Each is a priority upload, ahead
/// of the eD2K queue, so a few rather than every follower who asks: one
/// refused is told it is busy, and asks again later.
const MAX_SERVES: usize = 8;

/// Why a download stopped waiting on its publisher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Release {
    /// A lookup for the file found no record of the publisher's that the
    /// stream could reach, and none was tried.
    NotFound,
    /// The stream to the publisher failed, or was refused.
    StreamFailed,
    /// Nothing arrived for [`HOLD_IDLE`].
    Idle,
}

/// Who publishes the feed a download is of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Publisher {
    pub key: [u8; 32],
    pub salt: [u8; 16],
    /// The publisher's last address and TCP upload port, when they are a
    /// friend: their stream is tried there at once.
    pub friend_tcp: Option<SocketAddr>,
}

/// Where and how to stream a file from its publisher.
#[derive(Debug, Clone)]
pub struct StreamSource {
    /// The publisher's node id, which the QUIC certificate and the secure
    /// stream must prove.
    pub publisher: [u8; 16],
    pub xfer_id: [u8; 16],
    pub capability: [u8; 32],
    pub quic: Option<SocketAddr>,
    pub tcp: Option<SocketAddr>,
    pub endpoint: Option<Arc<quinn::Endpoint>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dial {
    None,
    /// A stream source is registered; the download's worker dials it.
    Registered,
    Connected,
}

#[derive(Debug)]
struct Hold {
    file_hash: [u8; 16],
    size: u64,
    publisher: [u8; 16],
    key: [u8; 32],
    salt: [u8; 16],
    dial: Dial,
    /// A lookup for the file has answered.
    looked: bool,
    last_bytes: u64,
    last_progress: Instant,
    released: Option<Release>,
}

#[derive(Default)]
struct Registry {
    holds: HashMap<String, Hold>,
    /// Kept apart from the holds: a stream outlives the hold that found it,
    /// and a run of the download started again picks it up again.
    streams: HashMap<String, StreamSource>,
    /// Every download begun here and not yet forgotten, with when it was
    /// begun: what the feeds service watches.
    watched: HashMap<String, Instant>,
}

fn registry() -> &'static parking_lot::Mutex<Registry> {
    static REGISTRY: std::sync::OnceLock<parking_lot::Mutex<Registry>> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

/// Whether the stream carries a file of `size` bytes.
fn streamable(size: u64) -> bool {
    size > 0 && size <= FEED_STREAM_MAX_BYTES
}

/// Hold `transfer_id`, a download of `file_hash` (`size` bytes) from a feed
/// `publisher` publishes, until its publisher has had the first go. Whether
/// it is held: past [`MAX_HOLDS`], or for a key that is no identity, not.
pub fn begin(transfer_id: &str, file_hash: [u8; 16], size: u64, publisher: Publisher) -> bool {
    let Some(node) = super::ember::crypto::node_id_from_ed25519_bytes(&publisher.key) else {
        return false;
    };
    let mut reg = registry().lock();
    if reg.holds.len() >= MAX_HOLDS && !reg.holds.contains_key(transfer_id) {
        return false;
    }
    reg.watched.insert(transfer_id.to_string(), Instant::now());
    let tcp = publisher.friend_tcp.filter(|_| streamable(size));
    reg.holds.insert(
        transfer_id.to_string(),
        Hold {
            file_hash,
            size,
            publisher: node,
            key: publisher.key,
            salt: publisher.salt,
            dial: if tcp.is_some() { Dial::Registered } else { Dial::None },
            looked: false,
            last_bytes: 0,
            last_progress: Instant::now(),
            released: None,
        },
    );
    match tcp {
        Some(tcp) => {
            let source = StreamSource {
                publisher: node,
                xfer_id: feed_stream_id(&publisher.key, &publisher.salt, &file_hash),
                capability: feed_stream_capability(&publisher.key, &publisher.salt, &file_hash),
                quic: None,
                tcp: Some(tcp),
                endpoint: None,
            };
            reg.streams.insert(transfer_id.to_string(), source);
        }
        None => {
            reg.streams.remove(transfer_id);
        }
    }
    true
}

/// Stop holding `transfer_id`, whatever it was waiting on, and forget its
/// stream.
pub fn forget(transfer_id: &str) {
    let mut reg = registry().lock();
    reg.holds.remove(transfer_id);
    reg.streams.remove(transfer_id);
    reg.watched.remove(transfer_id);
}

/// The downloads begun and not forgotten, with when each was begun: to be
/// [`poll`]ed while they run and [`forget`]ten when they end.
pub fn watched() -> Vec<(String, Instant)> {
    registry().lock().watched.iter().map(|(id, at)| (id.clone(), *at)).collect()
}

/// Whether `transfer_id` is still waiting on its publisher, so no other
/// network is to be asked for its sources.
pub fn holds(transfer_id: &str) -> bool {
    registry()
        .lock()
        .holds
        .get(transfer_id)
        .is_some_and(|hold| hold.released.is_none())
}

/// [`holds`], for the download of `file_hash`.
pub fn holds_file(file_hash: &[u8; 16]) -> bool {
    registry()
        .lock()
        .holds
        .values()
        .any(|hold| hold.released.is_none() && hold.file_hash == *file_hash)
}

/// The sources a finished Ember lookup for `file_hash` may hand on.
///
/// For a held download: none while its publisher can be streamed from. A
/// record the stream can reach becomes the download's stream source (the
/// QUIC port added to one already known by TCP alone), and the publisher's
/// other records go the ordinary routes. When the publisher has no record
/// and no stream is under way, the hold ends and every source found is
/// handed on.
pub fn take_lookup(
    file_hash: [u8; 16],
    sources: Vec<DiscoveredSource>,
    endpoint: Option<Arc<quinn::Endpoint>>,
) -> Vec<DiscoveredSource> {
    let mut reg = registry().lock();
    let Registry { holds, streams, .. } = &mut *reg;
    let Some((transfer_id, hold)) = holds
        .iter_mut()
        .find(|(_, hold)| hold.released.is_none() && hold.file_hash == file_hash)
    else {
        return sources;
    };
    if !hold.looked {
        hold.looked = true;
        hold.last_progress = Instant::now();
    }
    let (theirs, others): (Vec<_>, Vec<_>) =
        sources.into_iter().partition(|src| src.publisher_id == hold.publisher);
    // One naming a QUIC port first: QUIC is what the stream tries first.
    let reachable = theirs
        .iter()
        .position(|src| directly_dialable(src) && quic_addr(src).is_some())
        .or_else(|| theirs.iter().position(directly_dialable))
        .filter(|_| streamable(hold.size));
    if let Some(stream) = streams.get_mut(transfer_id) {
        if let Some(src) = reachable.map(|at| &theirs[at]).filter(|_| stream.quic.is_none()) {
            stream.quic = quic_addr(src);
            stream.tcp = stream.tcp.or(Some(SocketAddr::from((src.ip, src.tcp_port))));
            stream.endpoint = stream.endpoint.clone().or(endpoint);
        }
        return Vec::new();
    }
    if theirs.is_empty() {
        if hold.dial == Dial::None {
            hold.released = Some(Release::NotFound);
            return others;
        }
        return Vec::new();
    }
    match reachable {
        Some(at) => {
            let src = theirs[at];
            hold.dial = Dial::Registered;
            streams.insert(
                transfer_id.clone(),
                StreamSource {
                    publisher: hold.publisher,
                    xfer_id: feed_stream_id(&hold.key, &hold.salt, &file_hash),
                    capability: feed_stream_capability(&hold.key, &hold.salt, &file_hash),
                    quic: quic_addr(&src),
                    tcp: Some(SocketAddr::from((src.ip, src.tcp_port))),
                    endpoint,
                },
            );
            theirs.into_iter().filter(|other| other.ip != src.ip).collect()
        }
        // Reached over eD2K TCP, or by asking its buddy to have it call us:
        // the publisher still, by the ordinary routes.
        None => theirs,
    }
}

/// No Ember lookup could be started for `transfer_id`, so its publisher
/// cannot be found that way: the hold ends unless a stream is under way.
pub fn lookup_unavailable(transfer_id: &str) {
    let mut reg = registry().lock();
    if let Some(hold) = reg.holds.get_mut(transfer_id) {
        if hold.released.is_none() && hold.dial == Dial::None {
            hold.released = Some(Release::NotFound);
        }
    }
}

/// A record the stream can reach the publisher at: a reachable address,
/// which an honest storer bound to the address the record came from, with a
/// TCP port, and a QUIC port when the record names one. A firewalled record
/// names an address nobody vouched for, and is left to the buddy callback.
fn directly_dialable(src: &DiscoveredSource) -> bool {
    src.flags & super::ember::SOURCE_FLAG_FIREWALLED == 0
        && src.tcp_port != 0
        && !crate::security::is_special_use_v4(src.ip)
}

/// The QUIC address a record names, if it names a port.
fn quic_addr(src: &DiscoveredSource) -> Option<SocketAddr> {
    src.quic_port.filter(|port| *port != 0).map(|port| SocketAddr::from((src.ip, port)))
}

/// The stream `transfer_id` is to be fetched over, if any.
pub fn stream_for(transfer_id: &str) -> Option<StreamSource> {
    registry().lock().streams.get(transfer_id).cloned()
}

/// Whether `transfer_id` has a stream to fetch over: its download can start
/// on that alone.
pub fn stream_ready(transfer_id: &str) -> bool {
    registry().lock().streams.contains_key(transfer_id)
}

/// [`stream_ready`], for a held download of `file_hash`.
pub fn stream_ready_for_file(file_hash: &[u8; 16]) -> bool {
    let reg = registry().lock();
    reg.holds
        .iter()
        .any(|(id, hold)| hold.file_hash == *file_hash && reg.streams.contains_key(id))
}

/// The stream for `transfer_id` connected and the publisher answered.
pub fn stream_connected(transfer_id: &str) {
    let mut reg = registry().lock();
    if let Some(hold) = reg.holds.get_mut(transfer_id) {
        hold.dial = Dial::Connected;
        hold.last_progress = Instant::now();
    }
}

/// The stream for `transfer_id` is over: the file came whole, or the stream
/// failed for good. One that failed ends the hold, so the rest of the
/// network is asked at once.
pub fn stream_finished(transfer_id: &str, complete: bool) {
    let mut reg = registry().lock();
    reg.streams.remove(transfer_id);
    if let Some(hold) = reg.holds.get_mut(transfer_id) {
        if !complete && hold.released.is_none() {
            hold.dial = Dial::None;
            hold.released = Some(Release::StreamFailed);
        }
    }
}

/// What a download being watched should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poll {
    /// Still waiting on its publisher.
    Holding,
    /// No longer: ask every network for its sources now.
    Released(Release),
    /// Not held.
    Gone,
}

/// Look at `transfer_id` again, with `transferred` bytes so far. `counting`
/// is false while the download is paused or waiting for a download slot,
/// which does not use up its wait.
pub fn poll(transfer_id: &str, transferred: u64, counting: bool, now: Instant) -> Poll {
    let mut reg = registry().lock();
    let Some(hold) = reg.holds.get_mut(transfer_id) else {
        return Poll::Gone;
    };
    if let Some(release) = hold.released {
        reg.holds.remove(transfer_id);
        return Poll::Released(release);
    }
    if transferred > hold.last_bytes || !counting {
        hold.last_bytes = hold.last_bytes.max(transferred);
        hold.last_progress = now;
    }
    let wait = if hold.looked { HOLD_IDLE } else { LOOKUP_MAX };
    if now.saturating_duration_since(hold.last_progress) >= wait {
        reg.holds.remove(transfer_id);
        return Poll::Released(Release::Idle);
    }
    Poll::Holding
}

/// A file of ours a follower may stream, by the id they ask for it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Served {
    pub path: PathBuf,
    pub size: u64,
    pub capability: [u8; 32],
    /// The feed and file it is, for counting who downloaded it.
    pub salt: [u8; 16],
    pub ed2k: [u8; 16],
}

/// A follower who read a file of one of our feeds to its end from us, and
/// said they had it: `(salt, ed2k, follower node id)`.
pub type FeedDownload = ([u8; 16], [u8; 16], [u8; 16]);

/// Downloads waiting for the feeds service to record. Far more than a minute
/// of them; past it the oldest are dropped rather than the service held up.
const MAX_PENDING_DOWNLOADS: usize = 4096;

fn pending_downloads() -> &'static parking_lot::Mutex<std::collections::VecDeque<FeedDownload>> {
    static PENDING: std::sync::OnceLock<parking_lot::Mutex<std::collections::VecDeque<FeedDownload>>> =
        std::sync::OnceLock::new();
    PENDING.get_or_init(Default::default)
}

/// Woken when a download is noted, for the feeds service to record it.
pub fn downloads_noted() -> &'static tokio::sync::Notify {
    static NOTED: std::sync::OnceLock<tokio::sync::Notify> = std::sync::OnceLock::new();
    NOTED.get_or_init(tokio::sync::Notify::new)
}

/// Followers' tallies past which the least lately added to are dropped.
const MAX_SERVED_TALLIES: usize = 8192;

/// Bytes of each served file sent to each follower, `(follower, xfer id)`,
/// over every stream of it. A download is counted once they come to a whole
/// file's worth, not when one stream reaches the file's end, which one asking
/// for its last chunk alone would.
fn served_tallies() -> &'static parking_lot::Mutex<HashMap<([u8; 16], [u8; 16]), (u64, Instant)>> {
    static TALLIES: std::sync::OnceLock<parking_lot::Mutex<HashMap<([u8; 16], [u8; 16]), (u64, Instant)>>> =
        std::sync::OnceLock::new();
    TALLIES.get_or_init(Default::default)
}

/// `follower` was sent `bytes` of the file served as `xfer_id`. Whether they
/// have now been sent a whole file's worth of it.
pub fn note_served(xfer_id: &[u8; 16], follower: [u8; 16], bytes: u64) -> bool {
    let Some(size) = served_files().read().get(xfer_id).map(|file| file.size) else {
        return false;
    };
    let key = (follower, *xfer_id);
    let mut tallies = served_tallies().lock();
    if tallies.len() >= MAX_SERVED_TALLIES && !tallies.contains_key(&key) {
        if let Some(oldest) = tallies.iter().min_by_key(|(_, (_, at))| *at).map(|(key, _)| *key) {
            tallies.remove(&oldest);
        }
    }
    let (sent, at) = tallies.entry(key).or_insert((0, Instant::now()));
    *sent = sent.saturating_add(bytes).min(size);
    *at = Instant::now();
    *sent >= size
}

/// `follower` was sent the whole file served as `xfer_id` (see
/// [`note_served`]), and said they had it.
pub fn note_downloaded(xfer_id: &[u8; 16], follower: [u8; 16]) {
    served_tallies().lock().remove(&(follower, *xfer_id));
    let Some((salt, ed2k)) = served_files().read().get(xfer_id).map(|file| (file.salt, file.ed2k)) else {
        return;
    };
    let mut pending = pending_downloads().lock();
    if pending.len() >= MAX_PENDING_DOWNLOADS {
        pending.pop_front();
    }
    pending.push_back((salt, ed2k, follower));
    drop(pending);
    downloads_noted().notify_one();
}

/// The downloads noted since the last call.
pub fn take_downloads() -> Vec<FeedDownload> {
    pending_downloads().lock().drain(..).collect()
}

/// Put back `downloads` taken but not recorded, ahead of any noted since,
/// for the next try. Past [`MAX_PENDING_DOWNLOADS`] the oldest go.
pub fn requeue_downloads(downloads: Vec<FeedDownload>) {
    let mut pending = pending_downloads().lock();
    for download in downloads.into_iter().rev() {
        pending.push_front(download);
    }
    while pending.len() > MAX_PENDING_DOWNLOADS {
        pending.pop_front();
    }
}

fn served_files() -> &'static parking_lot::RwLock<HashMap<[u8; 16], Served>> {
    static SERVED: std::sync::OnceLock<parking_lot::RwLock<HashMap<[u8; 16], Served>>> = std::sync::OnceLock::new();
    SERVED.get_or_init(Default::default)
}

/// The files of our feeds a follower may stream, replacing any before.
pub fn set_served(files: HashMap<[u8; 16], Served>) {
    *served_files().write() = files;
}

/// The entry of [`set_served`] for `(publisher, salt, ed2k)`.
pub fn served_entry(publisher: &[u8; 32], salt: &[u8; 16], ed2k: &[u8; 16], path: PathBuf, size: u64) -> ([u8; 16], Served) {
    (
        feed_stream_id(publisher, salt, ed2k),
        Served { path, size, capability: feed_stream_capability(publisher, salt, ed2k), salt: *salt, ed2k: *ed2k },
    )
}

/// What a follower's request is checked against when it comes, as an eMule
/// upload is (`ed2k::upload::UploadHandler::resolve_upload_file`): the table
/// of served files is rebuilt only every minute, and a file made
/// friends-only, unshared, or moved out of every shared and download folder
/// since is not to be streamed meanwhile.
pub struct ServeChecks {
    pub local_index: Arc<tokio::sync::RwLock<crate::search::index::LocalIndex>>,
    pub friends_only: crate::network::ed2k::upload::SharedFriendsOnlyHashes,
    pub shared_folders: Arc<tokio::sync::RwLock<Vec<String>>>,
    pub download_folders: crate::storage::part_folders::SharedDownloadFolders,
}

fn serve_checks() -> &'static parking_lot::RwLock<Option<Arc<ServeChecks>>> {
    static CHECKS: std::sync::OnceLock<parking_lot::RwLock<Option<Arc<ServeChecks>>>> = std::sync::OnceLock::new();
    CHECKS.get_or_init(Default::default)
}

/// Check requests against `checks` from now on. Until this is called, as
/// when the network has not started, nothing is streamed.
pub fn set_serve_checks(checks: ServeChecks) {
    *serve_checks().write() = Some(Arc::new(checks));
}

/// A file of ours a follower may stream now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedFile {
    pub path: PathBuf,
    pub size: u64,
    /// What the request must be tagged under.
    pub capability: [u8; 32],
    /// The shared and download folders the file must be opened within.
    pub roots: Vec<String>,
}

/// A follower's request for `xfer_id`: the file, if it is one of ours a feed
/// lists that may be streamed now. Still shared with everyone by the Library
/// when the Library can be read without waiting (it was when the table was
/// built), not friends-only by known.met, and opened within the folders
/// returned. Otherwise the status the follower is refused with: busy while
/// what decides it cannot be read yet, which the follower asks again after,
/// and unknown for a file not ours to stream.
pub fn served(xfer_id: &[u8; 16]) -> Result<ServedFile, AttachStreamStatus> {
    use crate::network::ed2k::upload::{friends_only_snapshot_contains, friends_only_snapshot_ready};
    let file = served_file(xfer_id).ok_or(AttachStreamStatus::Unknown)?;
    let checks = serve_checks().read().clone().ok_or(AttachStreamStatus::Busy)?;
    if !friends_only_snapshot_ready(&checks.friends_only) {
        return Err(AttachStreamStatus::Busy);
    }
    if friends_only_snapshot_contains(&checks.friends_only, &file.ed2k) {
        return Err(AttachStreamStatus::Unknown);
    }
    if let Ok(index) = checks.local_index.try_read() {
        let listed = index.get_by_hash(&hex::encode(file.ed2k)).ok_or(AttachStreamStatus::Unknown)?;
        if !listed.is_public_listable() || std::path::Path::new(&listed.path) != file.path {
            return Err(AttachStreamStatus::Unknown);
        }
    }
    let mut roots = checks.shared_folders.try_read().map_err(|_| AttachStreamStatus::Busy)?.clone();
    roots.extend(checks.download_folders.read().roots());
    Ok(ServedFile { path: file.path, size: file.size, capability: file.capability, roots })
}

/// The table's entry for `xfer_id`, if it is a file the stream carries.
fn served_file(xfer_id: &[u8; 16]) -> Option<Served> {
    served_files().read().get(xfer_id).filter(|file| streamable(file.size)).cloned()
}

/// Of the [`MAX_SERVES`], how many one follower may hold: one fetching every
/// file of a feed at once would otherwise take them all.
const MAX_SERVES_PER_FOLLOWER: usize = 2;

/// The feed streams being served, in all and to each follower by node id
/// (`None` for one whose identity was not proven).
#[derive(Default)]
struct Serving {
    total: usize,
    by_follower: HashMap<Option<[u8; 16]>, usize>,
}

fn serving() -> &'static parking_lot::Mutex<Serving> {
    static SERVING: std::sync::OnceLock<parking_lot::Mutex<Serving>> = std::sync::OnceLock::new();
    SERVING.get_or_init(Default::default)
}

/// One of the [`MAX_SERVES`] feed streams served at once, while held.
pub struct ServeSlot {
    follower: Option<[u8; 16]>,
}

impl Drop for ServeSlot {
    fn drop(&mut self) {
        let mut serving = serving().lock();
        serving.total = serving.total.saturating_sub(1);
        if let Some(held) = serving.by_follower.get_mut(&self.follower) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                serving.by_follower.remove(&self.follower);
            }
        }
    }
}

/// A slot to serve `follower` a feed stream in, or `None` while
/// [`MAX_SERVES`] run, or [`MAX_SERVES_PER_FOLLOWER`] for them.
pub fn serve_slot(follower: Option<[u8; 16]>) -> Option<ServeSlot> {
    let mut serving = serving().lock();
    let theirs = serving.by_follower.get(&follower).copied().unwrap_or(0);
    if serving.total >= MAX_SERVES || theirs >= MAX_SERVES_PER_FOLLOWER {
        return None;
    }
    serving.total += 1;
    *serving.by_follower.entry(follower).or_default() += 1;
    Some(ServeSlot { follower })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const SALT: [u8; 16] = [3; 16];

    fn key() -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()
    }

    fn node() -> [u8; 16] {
        super::super::ember::crypto::node_id_from_ed25519_bytes(&key()).expect("node id")
    }

    fn publisher(friend_tcp: Option<SocketAddr>) -> Publisher {
        Publisher { key: key(), salt: SALT, friend_tcp }
    }

    fn source(publisher: [u8; 16], ip: [u8; 4], flags: u8, quic: Option<u16>) -> DiscoveredSource {
        DiscoveredSource {
            ip: Ipv4Addr::from(ip),
            tcp_port: 4662,
            udp_port: 4672,
            flags,
            user_hash: None,
            buddy: None,
            callback_token: None,
            publisher_id: publisher,
            quic_port: quic,
        }
    }

    #[test]
    fn a_reachable_record_of_the_publisher_becomes_the_stream() {
        let (id, hash) = ("feed-direct-stream", [0x31; 16]);
        begin(id, hash, 1_000, publisher(None));
        assert!(holds(id) && holds_file(&hash) && !stream_ready(id));
        let found = vec![source([1; 16], [8, 8, 8, 8], 0, Some(4672)), source(node(), [9, 9, 9, 9], 0, Some(4673))];
        assert!(take_lookup(hash, found, None).is_empty(), "nobody is dialled over eD2K meanwhile");
        let stream = stream_for(id).expect("a stream");
        assert_eq!(stream.publisher, node());
        assert_eq!(stream.quic, Some(SocketAddr::from(([9, 9, 9, 9], 4673))));
        assert_eq!(stream.tcp, Some(SocketAddr::from(([9, 9, 9, 9], 4662))));
        assert_eq!(stream.xfer_id, feed_stream_id(&key(), &SALT, &hash));
        assert!(holds(id), "still held while the stream runs");
        stream_finished(id, false);
        assert!(!holds(id) && !stream_ready(id));
        assert_eq!(poll(id, 0, true, Instant::now()), Poll::Released(Release::StreamFailed));
        assert_eq!(poll(id, 0, true, Instant::now()), Poll::Gone);
    }

    #[test]
    fn a_publisher_with_no_record_releases_everything_found() {
        let (id, hash) = ("feed-direct-absent", [0x32; 16]);
        begin(id, hash, 1_000, publisher(None));
        let found = vec![source([1; 16], [8, 8, 8, 8], 0, None)];
        assert_eq!(take_lookup(hash, found, None).len(), 1);
        assert!(!holds(id));
        assert_eq!(poll(id, 0, true, Instant::now()), Poll::Released(Release::NotFound));
    }

    #[test]
    fn a_friend_is_streamed_from_at_once_and_gains_the_quic_port_from_a_lookup() {
        let (id, hash) = ("feed-direct-friend", [0x33; 16]);
        let tcp = SocketAddr::from(([9, 9, 9, 9], 4662));
        begin(id, hash, 1_000, publisher(Some(tcp)));
        let stream = stream_for(id).expect("streamed before any lookup");
        assert_eq!((stream.tcp, stream.quic), (Some(tcp), None));
        lookup_unavailable(id);
        assert!(holds(id), "the stream is under way");
        let found = vec![source([1; 16], [8, 8, 8, 8], 0, None)];
        assert!(take_lookup(hash, found, None).is_empty(), "held for the stream, not released");
        let theirs = vec![source(node(), [9, 9, 9, 9], 0, Some(4673))];
        assert!(take_lookup(hash, theirs, None).is_empty());
        assert_eq!(stream_for(id).and_then(|s| s.quic), Some(SocketAddr::from(([9, 9, 9, 9], 4673))));
        stream_finished(id, true);
        assert!(holds(id), "a whole file leaves the hold to end with the download");
        forget(id);
    }

    #[test]
    fn a_record_with_no_quic_port_is_streamed_from_over_tcp() {
        let (id, hash) = ("feed-direct-tcp-only", [0x3A; 16]);
        begin(id, hash, 1_000, publisher(None));
        assert!(take_lookup(hash, vec![source(node(), [9, 9, 9, 9], 0, None)], None).is_empty());
        let stream = stream_for(id).expect("a stream");
        assert_eq!((stream.quic, stream.tcp), (None, Some(SocketAddr::from(([9, 9, 9, 9], 4662)))));
        forget(id);
    }

    #[test]
    fn a_firewalled_publisher_is_left_to_its_buddy() {
        let (id, hash) = ("feed-direct-firewalled", [0x34; 16]);
        begin(id, hash, 1_000, publisher(None));
        let theirs = vec![source(node(), [9, 9, 9, 9], super::super::ember::SOURCE_FLAG_FIREWALLED, Some(4672))];
        assert_eq!(take_lookup(hash, theirs, None).len(), 1);
        assert!(!stream_ready(id));
        assert!(holds(id));
        forget(id);
    }

    #[test]
    fn a_file_past_the_stream_limit_goes_the_ordinary_routes() {
        let (id, hash) = ("feed-direct-large", [0x39; 16]);
        begin(id, hash, FEED_STREAM_MAX_BYTES + 1, publisher(Some(SocketAddr::from(([9, 9, 9, 9], 4662)))));
        assert!(!stream_ready(id));
        let theirs = vec![source(node(), [9, 9, 9, 9], 0, Some(4672))];
        assert_eq!(take_lookup(hash, theirs, None).len(), 1);
        assert!(!stream_ready(id));
        forget(id);
    }

    #[test]
    fn the_first_lookup_is_given_longer_than_the_idle_wait() {
        let (id, hash) = ("feed-direct-lookup-wait", [0x38; 16]);
        begin(id, hash, 1_000, publisher(None));
        let start = Instant::now();
        assert_eq!(poll(id, 0, true, start + HOLD_IDLE + Duration::from_secs(5)), Poll::Holding);
        assert_eq!(poll(id, 0, false, start + Duration::from_secs(300)), Poll::Holding, "waiting for a slot");
        assert_eq!(
            poll(id, 0, true, start + Duration::from_secs(300) + LOOKUP_MAX),
            Poll::Released(Release::Idle)
        );
    }

    #[test]
    fn the_hold_lasts_while_bytes_arrive_and_ends_when_they_stop() {
        let (id, hash) = ("feed-direct-idle", [0x35; 16]);
        begin(id, hash, 1_000, publisher(None));
        let firewalled = super::super::ember::SOURCE_FLAG_FIREWALLED;
        assert_eq!(take_lookup(hash, vec![source(node(), [9, 9, 9, 9], firewalled, None)], None).len(), 1);
        let start = Instant::now();
        assert_eq!(poll(id, 0, true, start + Duration::from_secs(30)), Poll::Holding);
        assert_eq!(poll(id, 1_000, true, start + Duration::from_secs(40)), Poll::Holding);
        assert_eq!(poll(id, 1_000, true, start + Duration::from_secs(80)), Poll::Holding);
        assert_eq!(poll(id, 1_000, false, start + Duration::from_secs(200)), Poll::Holding, "paused");
        assert_eq!(
            poll(id, 1_000, true, start + Duration::from_secs(200) + HOLD_IDLE),
            Poll::Released(Release::Idle)
        );
        assert!(!holds_file(&hash));
    }

    #[test]
    fn no_lookup_releases_unless_a_stream_is_under_way() {
        let (id, hash) = ("feed-direct-no-lookup", [0x37; 16]);
        begin(id, hash, 1_000, publisher(None));
        lookup_unavailable(id);
        assert!(!holds(id));
        assert_eq!(poll(id, 0, true, Instant::now()), Poll::Released(Release::NotFound));
    }

    #[test]
    fn a_download_not_held_keeps_every_source() {
        let found = vec![source([1; 16], [8, 8, 8, 8], 0, Some(4672))];
        assert_eq!(take_lookup([0x36; 16], found, None).len(), 1);
        assert_eq!(poll("feed-direct-never", 0, true, Instant::now()), Poll::Gone);
    }

    #[test]
    fn a_served_file_is_found_by_the_id_a_follower_computes() {
        let (key, ed2k) = (key(), [0x44; 16]);
        let (id, entry) = served_entry(&key, &SALT, &ed2k, PathBuf::from("f"), 10);
        set_served(HashMap::from([(id, entry)]));
        let file = served_file(&feed_stream_id(&key, &SALT, &ed2k)).expect("served");
        assert_eq!((file.path, file.size), (PathBuf::from("f"), 10));
        assert_eq!(file.capability, feed_stream_capability(&key, &SALT, &ed2k));
        assert!(served_file(&feed_stream_id(&key, &[4; 16], &ed2k)).is_none(), "another feed's id");

        take_downloads();
        note_downloaded(&feed_stream_id(&key, &SALT, &ed2k), [9; 16]);
        note_downloaded(&feed_stream_id(&key, &[4; 16], &ed2k), [8; 16]);
        assert_eq!(take_downloads(), vec![(SALT, ed2k, [9; 16])], "only a file of ours is counted");
        assert!(take_downloads().is_empty());

        // A follower comes to the whole file over every stream of it.
        let (id, entry) = served_entry(&key, &[5; 16], &[0x45; 16], PathBuf::from("g"), 1_000);
        set_served(HashMap::from([(id, entry)]));
        assert!(!note_served(&id, [1; 16], 300), "the end alone is not the file");
        assert!(!note_served(&id, [2; 16], 900), "another follower's bytes are theirs");
        assert!(note_served(&id, [1; 16], 700));
        assert!(note_served(&id, [1; 16], 0), "still whole until counted");
        note_downloaded(&id, [1; 16]);
        assert!(!note_served(&id, [1; 16], 0), "counted, and begun again");
        assert!(!note_served(&[0x99; 16], [1; 16], 5_000), "not a file of ours");
        set_served(HashMap::new());
    }

    #[test]
    fn serve_slots_run_out_and_come_back() {
        let followers: Vec<Option<[u8; 16]>> = (0..MAX_SERVES as u8).map(|n| Some([n; 16])).collect();
        let held: Vec<_> = followers.iter().filter_map(|follower| serve_slot(*follower)).collect();
        assert_eq!(held.len(), MAX_SERVES);
        assert!(serve_slot(Some([0xEE; 16])).is_none(), "every slot is taken");
        drop(held);
        assert!(serve_slot(Some([0xEE; 16])).is_some());

        let theirs: Vec<_> = (0..MAX_SERVES).filter_map(|_| serve_slot(Some([0xAA; 16]))).collect();
        assert_eq!(theirs.len(), MAX_SERVES_PER_FOLLOWER, "one follower holds only their share");
        assert!(serve_slot(Some([0xBB; 16])).is_some(), "another is still served");
    }

    #[test]
    fn a_begun_download_is_watched_until_forgotten() {
        let (id, hash) = ("feed-direct-watched", [0x3B; 16]);
        assert!(begin(id, hash, 1_000, publisher(None)));
        assert!(watched().iter().any(|(watched, _)| watched == id));
        assert_eq!(poll(id, 0, true, Instant::now()), Poll::Holding);
        forget(id);
        assert!(!watched().iter().any(|(watched, _)| watched == id));
    }
}
