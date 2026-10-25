//! A feed's files are fetched from their publisher first.
//!
//! While a feed download is held here, the only source looked for is the
//! publisher: KAD, the servers and other publishers' Ember records wait. The
//! publisher is found by its own signed Ember source record for the file and
//! dialled over QUIC, pinned to the feed's key, so nobody else can answer in
//! its place; a friend publisher is reached the friends' way instead. The
//! hold ends, and every network is asked, as soon as the publisher is found
//! not to be there, the direct connection fails, or nothing has arrived for
//! [`HOLD_IDLE`] once the lookup has answered ([`LOOKUP_MAX`] before then).
//! Time paused or waiting for a download slot is not counted.
//!
//! Held in memory only: a download resumed after a restart looks everywhere
//! at once, as any other does.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::ember::dht::publish::DiscoveredSource;

/// How long a held download may go without a byte before the rest of the
/// network is asked: from the lookup's answer, and again whenever the
/// publisher stops sending.
pub const HOLD_IDLE: Duration = Duration::from_secs(45);
/// How long the first lookup may take to answer. One on a cold routing table
/// can run most of its 60-second cap.
pub const LOOKUP_MAX: Duration = Duration::from_secs(75);
/// How long the direct dial and its Hello may take.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(20);
/// Far more feed downloads than a user starts at once; past it a download is
/// simply not held.
const MAX_HOLDS: usize = 512;

/// Why a download stopped waiting on its publisher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Release {
    /// A lookup for the file found no record of the publisher's, and no
    /// friend session stands in for one.
    NotFound,
    /// The direct connection to the publisher could not be made.
    DialFailed,
    /// Nothing arrived for [`HOLD_IDLE`].
    Idle,
}

/// A direct connection to make to a publisher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialJob {
    pub transfer_id: String,
    pub file_hash: [u8; 16],
    /// The publisher's node id, which the QUIC certificate must carry.
    pub publisher: [u8; 16],
    pub ip: Ipv4Addr,
    pub tcp_port: u16,
    pub quic_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dial {
    None,
    Running,
    Connected,
}

#[derive(Debug)]
struct Hold {
    file_hash: [u8; 16],
    publisher: [u8; 16],
    /// The publisher is a friend, reached over the friends' path.
    friend: bool,
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
    dials: Vec<DialJob>,
}

fn registry() -> &'static parking_lot::Mutex<Registry> {
    static REGISTRY: std::sync::OnceLock<parking_lot::Mutex<Registry>> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

/// Hold `transfer_id`, a download of `file_hash` from the feed `publisher`
/// (its node id) publishes, until its publisher has had the first go.
pub fn begin(transfer_id: &str, file_hash: [u8; 16], publisher: [u8; 16], friend: bool) {
    let mut reg = registry().lock();
    if reg.holds.len() >= MAX_HOLDS && !reg.holds.contains_key(transfer_id) {
        return;
    }
    reg.holds.insert(
        transfer_id.to_string(),
        Hold {
            file_hash,
            publisher,
            friend,
            dial: Dial::None,
            looked: false,
            last_bytes: 0,
            last_progress: Instant::now(),
            released: None,
        },
    );
}

/// Stop holding `transfer_id`, whatever it was waiting on.
pub fn forget(transfer_id: &str) {
    let mut reg = registry().lock();
    reg.holds.remove(transfer_id);
    reg.dials.retain(|job| job.transfer_id != transfer_id);
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
/// For a held download: the publisher's own records only. One the publisher
/// can be dialled at directly is taken off the list and queued for
/// [`take_dials`], so it is not also dialled over TCP. When the publisher has
/// no record and no friend session can reach it, the hold ends and every
/// source found is handed on.
pub fn take_lookup(
    file_hash: [u8; 16],
    sources: Vec<DiscoveredSource>,
    friend_online: impl Fn(&[u8; 16]) -> bool,
) -> Vec<DiscoveredSource> {
    let mut reg = registry().lock();
    let Registry { holds, dials } = &mut *reg;
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
    if theirs.is_empty() {
        if hold.dial == Dial::None && !(hold.friend && friend_online(&hold.publisher)) {
            hold.released = Some(Release::NotFound);
            return others;
        }
        return Vec::new();
    }
    if hold.friend {
        return theirs;
    }
    match hold.dial {
        Dial::None => match theirs.iter().position(directly_dialable) {
            Some(at) => {
                let src = theirs[at];
                hold.dial = Dial::Running;
                dials.push(DialJob {
                    transfer_id: transfer_id.clone(),
                    file_hash,
                    publisher: hold.publisher,
                    ip: src.ip,
                    tcp_port: src.tcp_port,
                    quic_port: src.quic_port.unwrap_or_default(),
                });
                theirs.into_iter().filter(|other| other.ip != src.ip).collect()
            }
            // Reached over TCP, or by asking its buddy to have it call us:
            // the publisher still, by the ordinary routes.
            None => theirs,
        },
        // Already on its way, or here: not dialled a second time over TCP.
        Dial::Running | Dial::Connected => Vec::new(),
    }
}

/// No Ember lookup could be started for `transfer_id`, so its publisher
/// cannot be found that way: the hold ends unless a friend session reaches
/// them or a dial is already under way.
pub fn lookup_unavailable(transfer_id: &str, friend_online: impl Fn(&[u8; 16]) -> bool) {
    let mut reg = registry().lock();
    if let Some(hold) = reg.holds.get_mut(transfer_id) {
        if hold.released.is_none() && hold.dial == Dial::None && !(hold.friend && friend_online(&hold.publisher)) {
            hold.released = Some(Release::NotFound);
        }
    }
}

/// A record the publisher can be dialled at over QUIC: a reachable address,
/// which an honest storer bound to the address the record came from. A
/// firewalled record names an address nobody vouched for, and is left to the
/// buddy callback.
fn directly_dialable(src: &DiscoveredSource) -> bool {
    src.flags & super::ember::SOURCE_FLAG_FIREWALLED == 0
        && src.quic_port.is_some_and(|port| port != 0)
        && src.tcp_port != 0
        && !crate::security::is_special_use_v4(src.ip)
}

/// The direct connections waiting to be made.
pub fn take_dials() -> Vec<DialJob> {
    let mut reg = registry().lock();
    if reg.dials.is_empty() {
        return Vec::new();
    }
    std::mem::take(&mut reg.dials)
}

/// How the direct connection for `transfer_id` went. One that failed ends the
/// hold, so the rest of the network is asked at once.
pub fn dial_finished(transfer_id: &str, connected: bool) {
    let mut reg = registry().lock();
    if let Some(hold) = reg.holds.get_mut(transfer_id) {
        if connected {
            hold.dial = Dial::Connected;
            hold.last_progress = Instant::now();
        } else if hold.released.is_none() {
            hold.dial = Dial::None;
            hold.released = Some(Release::DialFailed);
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
        reg.dials.retain(|job| job.transfer_id != transfer_id);
        return Poll::Released(Release::Idle);
    }
    Poll::Holding
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLISHER: [u8; 16] = [7; 16];

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
    fn only_the_publisher_is_handed_on_and_its_reachable_record_is_dialled() {
        let (id, hash) = ("feed-direct-dial", [0x31; 16]);
        begin(id, hash, PUBLISHER, false);
        assert!(holds(id) && holds_file(&hash));
        let found = vec![
            source([1; 16], [8, 8, 8, 8], 0, Some(4672)),
            source(PUBLISHER, [9, 9, 9, 9], 0, Some(4672)),
        ];
        assert!(take_lookup(hash, found, |_| false).is_empty(), "neither is dialled over TCP now");
        let dials: Vec<_> = take_dials().into_iter().filter(|job| job.transfer_id == id).collect();
        assert_eq!(dials.len(), 1);
        assert_eq!(dials[0].ip, Ipv4Addr::new(9, 9, 9, 9));
        assert_eq!(dials[0].publisher, PUBLISHER);
        assert!(holds(id), "still held while the dial runs");
        dial_finished(id, false);
        assert!(!holds(id));
        assert_eq!(poll(id, 0, true, Instant::now()), Poll::Released(Release::DialFailed));
        assert_eq!(poll(id, 0, true, Instant::now()), Poll::Gone);
    }

    #[test]
    fn a_publisher_with_no_record_releases_everything_found() {
        let (id, hash) = ("feed-direct-absent", [0x32; 16]);
        begin(id, hash, PUBLISHER, false);
        let found = vec![source([1; 16], [8, 8, 8, 8], 0, None)];
        assert_eq!(take_lookup(hash, found, |_| false).len(), 1);
        assert!(!holds(id));
        assert_eq!(poll(id, 0, true, Instant::now()), Poll::Released(Release::NotFound));
    }

    #[test]
    fn an_online_friend_publisher_is_waited_on_without_a_record() {
        let (id, hash) = ("feed-direct-friend", [0x33; 16]);
        begin(id, hash, PUBLISHER, true);
        let found = vec![source([1; 16], [8, 8, 8, 8], 0, None)];
        assert!(take_lookup(hash, found.clone(), |p| *p == PUBLISHER).is_empty());
        assert!(holds(id));
        let theirs = vec![source(PUBLISHER, [9, 9, 9, 9], 0, Some(4672))];
        assert_eq!(take_lookup(hash, theirs, |_| true).len(), 1, "the friends' path dials it");
        assert!(take_dials().iter().all(|job| job.transfer_id != id));
        assert_eq!(take_lookup(hash, found, |_| false).len(), 1, "gone offline");
        forget(id);
    }

    #[test]
    fn a_firewalled_publisher_is_left_to_its_buddy() {
        let (id, hash) = ("feed-direct-firewalled", [0x34; 16]);
        begin(id, hash, PUBLISHER, false);
        let theirs = vec![source(PUBLISHER, [9, 9, 9, 9], super::super::ember::SOURCE_FLAG_FIREWALLED, Some(4672))];
        assert_eq!(take_lookup(hash, theirs, |_| false).len(), 1);
        assert!(take_dials().iter().all(|job| job.transfer_id != id));
        assert!(holds(id));
        forget(id);
    }

    #[test]
    fn the_first_lookup_is_given_longer_than_the_idle_wait() {
        let (id, hash) = ("feed-direct-lookup-wait", [0x38; 16]);
        begin(id, hash, PUBLISHER, false);
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
        begin(id, hash, PUBLISHER, false);
        let firewalled = super::super::ember::SOURCE_FLAG_FIREWALLED;
        assert_eq!(take_lookup(hash, vec![source(PUBLISHER, [9, 9, 9, 9], firewalled, None)], |_| false).len(), 1);
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
    fn no_lookup_releases_unless_a_friend_session_reaches_the_publisher() {
        let (id, hash) = ("feed-direct-no-lookup", [0x37; 16]);
        begin(id, hash, PUBLISHER, true);
        lookup_unavailable(id, |_| true);
        assert!(holds(id), "the friends' path still reaches them");
        lookup_unavailable(id, |_| false);
        assert!(!holds(id));
        assert_eq!(poll(id, 0, true, Instant::now()), Poll::Released(Release::NotFound));
    }

    #[test]
    fn a_download_not_held_keeps_every_source() {
        let found = vec![source([1; 16], [8, 8, 8, 8], 0, Some(4672))];
        assert_eq!(take_lookup([0x36; 16], found, |_| false).len(), 1);
        assert_eq!(poll("feed-direct-never", 0, true, Instant::now()), Poll::Gone);
    }
}
