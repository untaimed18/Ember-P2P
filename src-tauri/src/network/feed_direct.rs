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
//! Held in memory only: a download resumed after a restart looks everywhere
//! at once, as any other does.
//!
//! The publisher's half is here too: which files a follower may ask for,
//! and how many are served at once.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::ember::attach::{feed_stream_capability, feed_stream_id, FEED_STREAM_MAX_BYTES};
use super::ember::dht::publish::DiscoveredSource;

/// How long a held download may go without a byte before the rest of the
/// network is asked: from the lookup's answer, and again whenever the
/// publisher stops sending.
pub const HOLD_IDLE: Duration = Duration::from_secs(45);
/// How long the first lookup may take to answer. One on a cold routing table
/// can run most of its 60-second cap.
pub const LOOKUP_MAX: Duration = Duration::from_secs(75);
/// Far more feed downloads than a user starts at once; past it a download is
/// simply not held.
const MAX_HOLDS: usize = 512;
/// Feed files a publisher streams at once. Each is a priority upload, ahead
/// of the eD2K queue, so a few rather than every follower who asks: one
/// refused fetches over eD2K instead.
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
/// `publisher` publishes, until its publisher has had the first go.
pub fn begin(transfer_id: &str, file_hash: [u8; 16], size: u64, publisher: Publisher) {
    let Some(node) = super::ember::crypto::node_id_from_ed25519_bytes(&publisher.key) else {
        return;
    };
    let mut reg = registry().lock();
    if reg.holds.len() >= MAX_HOLDS && !reg.holds.contains_key(transfer_id) {
        return;
    }
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
}

/// Stop holding `transfer_id`, whatever it was waiting on, and forget its
/// stream.
pub fn forget(transfer_id: &str) {
    let mut reg = registry().lock();
    reg.holds.remove(transfer_id);
    reg.streams.remove(transfer_id);
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
    let Registry { holds, streams } = &mut *reg;
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
        Served { path, size, capability: feed_stream_capability(publisher, salt, ed2k) },
    )
}

/// A follower's request for `xfer_id`: the file, its size and the capability
/// the request must be tagged under, if it is one of ours a feed lists.
pub fn served(xfer_id: &[u8; 16]) -> Option<(PathBuf, u64, [u8; 32])> {
    served_files()
        .read()
        .get(xfer_id)
        .filter(|file| streamable(file.size))
        .map(|file| (file.path.clone(), file.size, file.capability))
}

/// One of the [`MAX_SERVES`] feed streams served at once, while held.
pub struct ServeSlot(());

static SERVING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl Drop for ServeSlot {
    fn drop(&mut self) {
        SERVING.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// A slot to serve a feed stream in, or `None` while [`MAX_SERVES`] run.
pub fn serve_slot() -> Option<ServeSlot> {
    SERVING
        .fetch_update(std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Acquire, |n| {
            (n < MAX_SERVES).then_some(n + 1)
        })
        .ok()
        .map(|_| ServeSlot(()))
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
        let (path, size, capability) = served(&feed_stream_id(&key, &SALT, &ed2k)).expect("served");
        assert_eq!((path, size), (PathBuf::from("f"), 10));
        assert_eq!(capability, feed_stream_capability(&key, &SALT, &ed2k));
        assert!(served(&feed_stream_id(&key, &[4; 16], &ed2k)).is_none(), "another feed's id");
        set_served(HashMap::new());
    }

    #[test]
    fn serve_slots_run_out_and_come_back() {
        let held: Vec<_> = (0..MAX_SERVES).filter_map(|_| serve_slot()).collect();
        assert_eq!(held.len(), MAX_SERVES);
        assert!(serve_slot().is_none());
        drop(held);
        assert!(serve_slot().is_some());
    }
}
