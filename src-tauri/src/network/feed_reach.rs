//! Reaching a feed's publisher when no source record names them.
//!
//! A follower fetches a feed's list from whoever has a source record for it.
//! A firewalled publisher with no buddy places none, while its head and
//! listing still go out, so its feed is found and never loads. Each publisher
//! therefore also registers its newest feeds on the rendezvous server, under
//! a capability only holders of a feed's link can compute
//! ([`derive_feed_presence_capability`]), and a follower whose fetch finds no
//! source reaches the publisher through it: directly at the address it
//! registered, by a hole punch, or over the server's relay. Whichever
//! connects carries the feed stream, which serves the list by its id (see
//! `feed_direct`), checked chunk by chunk against the BLAKE3 the signed head
//! names.
//!
//! The server relay carries lists only. Items are arbitrary files and often
//! large, and relaying them would make the server a distributor of whatever
//! strangers publish; they come over a direct or punched path, or from any
//! other source for their hash.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

use crate::network::ember::attach::{
    feed_stream_capability, feed_stream_id, ATTACH_CHUNK_SIZE, ATTACH_CLOSE_ABANDONED, ATTACH_CLOSE_RECEIVED,
    FEED_STREAM_MSG_TYPE,
};
use crate::network::ember::crypto::{
    derive_feed_presence_capability, derive_pairwise_presence_capability, node_id_from_ed25519_bytes,
    pairwise_capability_epoch,
};
use crate::network::ember::{attach_stream, attach_tcp, relay};
use crate::network::rendezvous;

/// How many of our feeds are registered: the newest published.
pub const MAX_REGISTERED_FEEDS: usize = 16;

/// How long a registration counts as standing: past the server's entry TTL
/// with a missed heartbeat's slack.
const REGISTERED_FRESH: Duration = Duration::from_secs(10 * 60);

/// Feed punches from followers answered per minute. Each costs a reciprocal
/// registration and a dial, and anyone with a feed's link can ask.
const FEED_PUNCHES_PER_MINUTE: usize = 6;

/// Lists served over the server relay at once.
const MAX_FEED_RELAY_SESSIONS: usize = 2;

/// How long a relayed list session may run in all.
const FEED_RELAY_SESSION_MAX: Duration = Duration::from_secs(120);

/// How long the publisher's answer to a request may take.
const STATUS_WAIT: Duration = Duration::from_secs(60);

/// How long a follower waits for the publisher's reciprocal punch. The
/// publisher polls every 20 s while idle.
const PUNCH_WAIT: Duration = Duration::from_secs(45);
const PUNCH_POLL_EVERY: Duration = Duration::from_secs(2);

/// How long a follower waits for the publisher to accept a relay ticket.
const RELAY_ACCEPT_WAIT: Duration = rendezvous::FRIEND_RELAY_TICKET_INITIATOR_WAIT;

const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

// ── Publisher ────────────────────────────────────────────────────────────

fn own_feed_salts() -> &'static parking_lot::RwLock<Vec<[u8; 16]>> {
    static OWN: std::sync::OnceLock<parking_lot::RwLock<Vec<[u8; 16]>>> = std::sync::OnceLock::new();
    OWN.get_or_init(Default::default)
}

/// Our published feeds, newest first; past [`MAX_REGISTERED_FEEDS`] the rest
/// are not registered.
pub fn set_own_feeds(mut salts: Vec<[u8; 16]>) {
    salts.truncate(MAX_REGISTERED_FEEDS);
    *own_feed_salts().write() = salts;
}

/// The feeds to register, newest first.
pub fn own_feeds() -> Vec<[u8; 16]> {
    own_feed_salts().read().clone()
}

/// The feed of ours whose presence capability at `epoch` is `capability`.
pub fn own_feed_for_capability(our_pubkey: &[u8; 32], epoch: i64, capability: &[u8; 32]) -> Option<[u8; 16]> {
    own_feed_salts()
        .read()
        .iter()
        .copied()
        .find(|salt| derive_feed_presence_capability(our_pubkey, salt, epoch).0 == *capability)
}

struct Registered {
    at: Instant,
    salts: HashSet<[u8; 16]>,
}

fn registered() -> &'static parking_lot::Mutex<Option<Registered>> {
    static REGISTERED: std::sync::OnceLock<parking_lot::Mutex<Option<Registered>>> = std::sync::OnceLock::new();
    REGISTERED.get_or_init(Default::default)
}

/// The feeds a heartbeat registered, replacing those of the last.
pub fn note_registered(salts: Vec<[u8; 16]>) {
    *registered().lock() = Some(Registered { at: Instant::now(), salts: salts.into_iter().collect() });
}

fn is_registered(salt: &[u8; 16]) -> bool {
    registered()
        .lock()
        .as_ref()
        .is_some_and(|held| held.at.elapsed() < REGISTERED_FRESH && held.salts.contains(salt))
}

/// Whether we can place source records: 0 not known yet, 1 yes, 2 no.
static SOURCE_PUBLISHING: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// What the source publisher found this pass: whether it may place records,
/// which a firewalled node with no buddy, or one with no known address,
/// may not. Logged when it changes.
pub fn note_source_publishing(can: bool) {
    let now = if can { 1 } else { 2 };
    let was = SOURCE_PUBLISHING.swap(now, std::sync::atomic::Ordering::Relaxed);
    if was != now {
        if can {
            info!("Feeds: followers can find our feeds' lists through source records again");
        } else {
            info!("Feeds: no source records can be placed now (no buddy relays for us); followers must reach our feeds through the rendezvous server");
        }
    }
}

fn source_publishing() -> Option<bool> {
    match SOURCE_PUBLISHING.load(std::sync::atomic::Ordering::Relaxed) {
        1 => Some(true),
        2 => Some(false),
        _ => None,
    }
}

/// How followers can fetch a feed of ours now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reach {
    /// Not known yet.
    Unknown,
    /// Through source records, as any file.
    Direct,
    /// Only through the rendezvous server: no source record can be placed,
    /// so followers on Ember 1.7.5 or older cannot fetch it.
    Server,
    /// Not at all until a buddy relays for us or the server takes our
    /// registration.
    None,
}

/// How followers can fetch our feed `salt` now.
pub fn reach(salt: &[u8; 16]) -> Reach {
    match source_publishing() {
        None => Reach::Unknown,
        Some(true) => Reach::Direct,
        Some(false) if is_registered(salt) => Reach::Server,
        Some(false) => Reach::None,
    }
}

/// Whether followers can fetch our feed `salt` at all now, for the flag its
/// Discover listing carries: `false` only when known not to.
pub fn can_share(salt: &[u8; 16]) -> bool {
    reach(salt) != Reach::None
}

/// Of the [`FEED_PUNCHES_PER_MINUTE`], how many one follower may have: one
/// asking over and over would otherwise take them all.
const FEED_PUNCHES_PER_FOLLOWER_PER_MINUTE: usize = 2;

/// A feed punch from `follower` may be answered now: at most
/// [`FEED_PUNCHES_PER_MINUTE`] in all, [`FEED_PUNCHES_PER_FOLLOWER_PER_MINUTE`]
/// from one follower.
fn take_punch_slot(follower: [u8; 16]) -> bool {
    type Answered = Vec<(Instant, [u8; 16])>;
    static ANSWERED: std::sync::OnceLock<parking_lot::Mutex<Answered>> = std::sync::OnceLock::new();
    let mut answered = ANSWERED.get_or_init(Default::default).lock();
    answered.retain(|(at, _)| at.elapsed() < Duration::from_secs(60));
    let theirs = answered.iter().filter(|(_, by)| *by == follower).count();
    if answered.len() >= FEED_PUNCHES_PER_MINUTE || theirs >= FEED_PUNCHES_PER_FOLLOWER_PER_MINUTE {
        return false;
    }
    answered.push((Instant::now(), follower));
    true
}

/// One of the [`MAX_FEED_RELAY_SESSIONS`], while held.
pub struct RelaySlot(());

static RELAY_SESSIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl Drop for RelaySlot {
    fn drop(&mut self) {
        RELAY_SESSIONS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// A slot to serve a relayed list in, or `None` while all are taken.
pub fn relay_slot() -> Option<RelaySlot> {
    RELAY_SESSIONS
        .fetch_update(std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Acquire, |held| {
            (held < MAX_FEED_RELAY_SESSIONS).then_some(held + 1)
        })
        .ok()
        .map(|_| RelaySlot(()))
}

/// What the punch responder needs to answer a follower's feed punch.
pub struct PunchResponder {
    pub rendezvous_url: String,
    pub endpoint: std::sync::Arc<quinn::Endpoint>,
    pub our_hash: [u8; 16],
    pub our_secret: [u8; 32],
    /// Our QUIC port as followers should dial it.
    pub quic_port: u16,
    pub nat_type: u8,
    pub external_ip: Option<IpAddr>,
}

/// Answer `info`, a punch whose capability is the presence of our feed: a
/// follower who found no source for its list. Verified, rate-limited and
/// acknowledged; then registered back, so the follower learns where to dial,
/// and dialled toward, which opens our NAT to its dial. Its connection lands
/// in the QUIC accept loop, which serves the feed stream to anyone.
pub async fn answer_feed_punch(responder: PunchResponder, info: relay::PunchInfo) {
    let ack = |info: &relay::PunchInfo| {
        let info = info.clone();
        let (url, hash, secret) = (responder.rendezvous_url.clone(), responder.our_hash, responder.our_secret);
        async move {
            if let Err(e) = relay::ack_punch(&url, &hash, &info.punch_id, &info.capability, info.epoch, &secret).await {
                debug!("Feed punch: ack failed: {e}");
            }
        }
    };
    let protocol = match rendezvous::negotiate_protocol(&responder.rendezvous_url).await {
        Ok(protocol) => protocol,
        Err(e) => {
            debug!("Feed punch: protocol probe failed: {e}");
            return;
        }
    };
    // The follower's key comes from its signed registration, which only an
    // IP-bound one carries.
    if protocol != rendezvous::RendezvousProtocol::IpBoundV4
        || relay::verify_punch_register_proof(&info, protocol).is_err()
    {
        ack(&info).await;
        return;
    }
    let Some(follower) = node_id_from_ed25519_bytes(&info.from_pubkey) else {
        ack(&info).await;
        return;
    };
    let Ok(ip) = info.ip.parse::<IpAddr>() else {
        ack(&info).await;
        return;
    };
    let routable = match ip {
        IpAddr::V4(v4) => !crate::security::is_special_use_v4(v4),
        IpAddr::V6(_) => false,
    };
    let our_pubkey = ed25519_dalek::SigningKey::from_bytes(&responder.our_secret).verifying_key().to_bytes();
    let ours = own_feed_for_capability(&our_pubkey, info.epoch, &info.capability).is_some();
    if !ours || !routable || info.port == 0 || !take_punch_slot(follower) {
        ack(&info).await;
        return;
    }
    ack(&info).await;
    let follower_addr = SocketAddr::new(ip, info.port);
    debug!("Feed punch: answering a follower at {follower_addr}");
    let reciprocate = async {
        let Some(external_ip) = responder.external_ip else {
            return;
        };
        if let Err(e) = relay::register_punch_with_ip(
            &responder.rendezvous_url,
            &responder.our_hash,
            &follower,
            responder.quic_port,
            responder.nat_type,
            external_ip,
            &responder.our_secret,
            &responder.our_hash,
        )
        .await
        {
            debug!("Feed punch: reciprocal register failed: {e}");
        }
    };
    let dial = async {
        let Ok((cert, key)) = crate::network::ember::quic::generate_self_signed_cert(&responder.our_secret) else {
            return;
        };
        let dialled = tokio::time::timeout(
            Duration::from_secs(4),
            crate::network::ember::quic::connect_pinned(
                &responder.endpoint,
                follower_addr,
                "ember",
                Some((&cert, &key, follower)),
            ),
        )
        .await;
        // Only opens the mapping: the follower's own dial carries the stream.
        if let Ok(Ok(conn)) = dialled {
            conn.close(0u32.into(), b"feed punch");
        }
    };
    tokio::join!(reciprocate, dial);
}

/// Serve the list a follower asks for over a relayed `ws`, as the feed's
/// publisher: the secure handshake a direct TCP stream runs, then the feed
/// stream, for lists only.
pub async fn serve_relayed_list(
    ws: relay::WsStream,
    our_hash: [u8; 16],
    our_pubkey: [u8; 32],
    our_secret: [u8; 32],
    limiter: std::sync::Arc<crate::bandwidth::limiter::BandwidthLimiter>,
) {
    let session = async {
        let (reader, writer) = tokio::io::split(ws);
        let mut reader = tokio::io::BufReader::new(reader);
        let first = reader.read_u8().await?;
        let mut parts = crate::network::ed2k::secure_stream::accept_after_first(
            Box::new(reader),
            Box::new(writer),
            first,
            our_hash,
            our_pubkey,
            our_secret,
        )
        .await?;
        let mut header = [0u8; 7];
        parts.reader.read_exact(&mut header).await?;
        if header[0] != FEED_STREAM_MSG_TYPE {
            anyhow::bail!("a relayed feed session asked for something other than a feed stream");
        }
        let served = relay::serve_feed_stream(
            &mut parts.reader,
            &mut parts.writer,
            &header,
            Some(parts.peer.ember_hash),
            &limiter,
            None,
            true,
        )
        .await?;
        if served.is_some() {
            attach_tcp::tcp_stream_delivered(&mut parts.reader, &mut parts.writer).await;
        }
        let _ = parts.writer.shutdown().await;
        anyhow::Ok(())
    };
    match tokio::time::timeout(FEED_RELAY_SESSION_MAX, session).await {
        Ok(Ok(())) => debug!("Feed relay: served a list"),
        Ok(Err(e)) => debug!("Feed relay: session ended: {e}"),
        Err(_) => debug!("Feed relay: session ran out of time"),
    }
}

// ── Follower ─────────────────────────────────────────────────────────────

/// What the network task holds that a follower needs to reach a publisher.
pub struct NetworkReach {
    pub rendezvous_url: String,
    pub external_ip: Option<Ipv4Addr>,
    /// Our TCP port, registered for the publisher to punch back to.
    pub tcp_port: u16,
    pub nat: crate::network::ember::nat::SharedFriendNatContext,
}

impl std::fmt::Debug for NetworkReach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkReach").field("tcp_port", &self.tcp_port).finish_non_exhaustive()
    }
}

/// What a follower needs to reach a publisher.
pub struct ReachContext {
    pub rendezvous_url: String,
    pub our_hash: [u8; 16],
    pub our_pubkey: [u8; 32],
    pub our_secret: [u8; 32],
    pub external_ip: Option<Ipv4Addr>,
    /// Our TCP port, registered for the publisher to punch back to.
    pub tcp_port: u16,
    pub nat: crate::network::ember::nat::SharedFriendNatContext,
}

impl ReachContext {
    pub fn new(network: NetworkReach, our_hash: [u8; 16], our_pubkey: [u8; 32], our_secret: [u8; 32]) -> Self {
        Self {
            rendezvous_url: network.rendezvous_url,
            our_hash,
            our_pubkey,
            our_secret,
            external_ip: network.external_ip,
            tcp_port: network.tcp_port,
            nat: network.nat,
        }
    }
}

/// The list a feed's head names.
#[derive(Debug, Clone)]
pub struct ListTarget {
    pub publisher: [u8; 32],
    pub salt: [u8; 16],
    pub ed2k: [u8; 16],
    pub blake3: [u8; 32],
    pub size: u64,
}

/// How a list was fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachedBy {
    Direct,
    Punch,
    Relay,
}

/// Fetch `target`'s list from its publisher through the rendezvous server:
/// at the address it registered, then by a hole punch, then over the
/// server's relay. The bytes are checked against the head's BLAKE3 chunk by
/// chunk; the caller checks them against the head again before taking them.
pub async fn fetch_list(ctx: &ReachContext, target: &ListTarget) -> Result<(Vec<u8>, ReachedBy), String> {
    let publisher_hash =
        node_id_from_ed25519_bytes(&target.publisher).ok_or_else(|| "the feed's publisher key is invalid".to_string())?;
    let found = rendezvous::lookup_feed_presence(
        &ctx.rendezvous_url,
        &ctx.our_hash,
        &ctx.our_pubkey,
        &ctx.our_secret,
        &target.publisher,
        &target.salt,
    )
    .await?;
    let Some((ip, port)) = found else {
        return Err("the publisher is not on the rendezvous server".to_string());
    };
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    match direct(ctx, target, publisher_hash, addr).await {
        Ok(bytes) => return Ok((bytes, ReachedBy::Direct)),
        Err(e) => debug!("Feed list: direct connection failed: {e}"),
    }
    match punch(ctx, target, publisher_hash).await {
        Ok(bytes) => return Ok((bytes, ReachedBy::Punch)),
        Err(e) => debug!("Feed list: hole punch failed: {e}"),
    }
    relayed(ctx, target, publisher_hash).await.map(|bytes| (bytes, ReachedBy::Relay))
}

async fn direct(ctx: &ReachContext, target: &ListTarget, publisher_hash: [u8; 16], addr: SocketAddr) -> Result<Vec<u8>, String> {
    let mut parts = tokio::time::timeout(
        DIAL_TIMEOUT,
        attach_tcp::dial_secure(addr, ctx.our_hash, ctx.our_pubkey, ctx.our_secret, publisher_hash),
    )
    .await
    .map_err(|_| "timed out".to_string())?
    .map_err(|e| e.to_string())?;
    fetch_over(&mut parts.reader, &mut parts.writer, target, true).await
}

async fn punch(ctx: &ReachContext, target: &ListTarget, publisher_hash: [u8; 16]) -> Result<Vec<u8>, String> {
    let (conn, _, _) = punch_publisher(ctx, &target.publisher, &target.salt, publisher_hash).await?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    let fetched = fetch_over(&mut recv, &mut send, target, false).await;
    let _ = send.finish();
    conn.close(0u32.into(), if fetched.is_ok() { ATTACH_CLOSE_RECEIVED } else { ATTACH_CLOSE_ABANDONED });
    fetched
}

/// How long a punched connection is kept open for the item downloads that
/// dial the publisher after it, so its NAT keeps the way open meanwhile.
const PUNCH_HOLD_OPEN: Duration = Duration::from_secs(60);

/// Reach the publisher of the feed `salt` by a hole punch for its items, as
/// its list is reached: where it can be dialled, and through which endpoint
/// of ours. The connection stays open a minute for the downloads that dial
/// it next.
pub async fn punch_for_items(
    ctx: &ReachContext,
    publisher: &[u8; 32],
    salt: &[u8; 16],
) -> Result<(SocketAddr, std::sync::Arc<quinn::Endpoint>), String> {
    let publisher_hash =
        node_id_from_ed25519_bytes(publisher).ok_or_else(|| "the feed's publisher key is invalid".to_string())?;
    let (conn, addr, endpoint) = punch_publisher(ctx, publisher, salt, publisher_hash).await?;
    tokio::spawn(async move {
        tokio::time::sleep(PUNCH_HOLD_OPEN).await;
        conn.close(0u32.into(), b"feed punch");
    });
    Ok((addr, endpoint))
}

/// A QUIC connection to the publisher of the feed `salt`, pinned to its
/// identity, by a hole punch under the feed's presence capability.
async fn punch_publisher(
    ctx: &ReachContext,
    publisher: &[u8; 32],
    salt: &[u8; 16],
    publisher_hash: [u8; 16],
) -> Result<(quinn::Connection, SocketAddr, std::sync::Arc<quinn::Endpoint>), String> {
    let (nat_type, external_addr, endpoint, quic_port) = {
        let nat = ctx.nat.read().unwrap_or_else(|p| p.into_inner());
        (nat.nat_type, nat.external_addr, nat.quic_endpoint.clone(), nat.quic_public_port())
    };
    let endpoint = endpoint.ok_or_else(|| "no QUIC endpoint".to_string())?;
    let external_addr = external_addr.ok_or_else(|| "our address is not known yet".to_string())?;
    let external_ip = ctx.external_ip.ok_or_else(|| "our address is not known yet".to_string())?;
    if nat_type == crate::network::ember::nat::NatType::Symmetric {
        return Err("a symmetric NAT cannot be punched".to_string());
    }
    // The publisher's reply is registered under the pairwise capability our
    // two keys share, which the server takes only while we hold an entry
    // for it; a friend has one from the heartbeat, a publisher does not.
    rendezvous::register_peer_presence(
        &ctx.rendezvous_url,
        &ctx.our_pubkey,
        &ctx.our_secret,
        publisher,
        ctx.tcp_port,
        external_ip,
    )
    .await?;
    let advertise_port = quic_port
        .filter(|port| *port != 0)
        .or_else(|| endpoint.local_addr().map(|a| a.port()).ok())
        .unwrap_or_else(|| external_addr.port());
    let publisher_id = rendezvous::hashed_id(&publisher_hash);
    let _awaiting = relay::await_punch_from(publisher_id.clone());
    let epoch = pairwise_capability_epoch(rendezvous::current_timestamp());
    let mut registered = false;
    for epoch in [epoch, epoch - 1] {
        let (capability, _) = derive_feed_presence_capability(publisher, salt, epoch);
        match relay::register_punch_status(
            &ctx.rendezvous_url,
            &ctx.our_hash,
            &publisher_hash,
            capability,
            epoch,
            advertise_port,
            nat_type.as_u8(),
            external_addr.ip(),
            &ctx.our_secret,
        )
        .await?
        {
            status if status.is_success() => {
                registered = true;
                break;
            }
            reqwest::StatusCode::FORBIDDEN => {}
            status => return Err(format!("punch register: status {status}")),
        }
    }
    if !registered {
        return Err("punch register: status 403 Forbidden".to_string());
    }
    let deadline = tokio::time::Instant::now() + PUNCH_WAIT;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(PUNCH_POLL_EVERY).await;
        let polled = tokio::time::timeout_at(deadline, relay::poll_punch(&ctx.rendezvous_url, &ctx.our_hash, &ctx.our_secret)).await;
        let info = match polled {
            Ok(Ok(Some(info))) if info.from_id == publisher_id => info,
            Ok(Ok(_)) => continue,
            Ok(Err(e)) => {
                debug!("Feed punch poll: {e}");
                continue;
            }
            Err(_) => break,
        };
        let ack = relay::ack_punch(&ctx.rendezvous_url, &ctx.our_hash, &info.punch_id, &info.capability, info.epoch, &ctx.our_secret);
        let expected = derive_pairwise_presence_capability(&ctx.our_secret, publisher, &ctx.our_pubkey, info.epoch);
        let addr = info
            .ip
            .parse::<IpAddr>()
            .ok()
            .filter(|ip| matches!(ip, IpAddr::V4(v4) if !crate::security::is_special_use_v4(*v4)))
            .filter(|_| info.port != 0)
            .map(|ip| SocketAddr::new(ip, info.port));
        let _ = ack.await;
        let (Some(addr), true) = (addr, expected == Some(info.capability)) else {
            continue;
        };
        let (cert, key) = crate::network::ember::quic::generate_self_signed_cert(&ctx.our_secret).map_err(|e| e.to_string())?;
        let conn = tokio::time::timeout(
            DIAL_TIMEOUT,
            crate::network::ember::quic::connect_pinned(&endpoint, addr, "ember", Some((&cert, &key, publisher_hash))),
        )
        .await
        .map_err(|_| "QUIC dial timed out".to_string())?
        .map_err(|e| e.to_string())?;
        return Ok((conn, addr, endpoint));
    }
    Err("no reciprocal punch from the publisher".to_string())
}

async fn relayed(ctx: &ReachContext, target: &ListTarget, publisher_hash: [u8; 16]) -> Result<Vec<u8>, String> {
    let offer = tokio::time::timeout(
        Duration::from_secs(20),
        rendezvous::offer_feed_relay_ticket(
            &ctx.rendezvous_url,
            &ctx.our_hash,
            &publisher_hash,
            &ctx.our_pubkey,
            &ctx.our_secret,
            &target.salt,
        ),
    )
    .await
    .map_err(|_| "relay offer timed out".to_string())??;
    let deadline = tokio::time::Instant::now() + RELAY_ACCEPT_WAIT;
    let mut accepted = false;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(1)).await;
        match tokio::time::timeout(
            rendezvous::FRIEND_RELAY_TICKET_ACTION_TIMEOUT,
            rendezvous::friend_relay_ticket_accepted(&ctx.rendezvous_url, &ctx.our_hash, &offer.ticket_id, &ctx.our_secret),
        )
        .await
        {
            Ok(Ok(true)) => {
                accepted = true;
                break;
            }
            Ok(Ok(false)) => {}
            Ok(Err(e)) if rendezvous::is_transient_relay_ticket_read_error(&e) => {}
            Ok(Err(e)) => return Err(format!("relay ticket status failed: {e}")),
            Err(_) => {}
        }
    }
    if !accepted {
        return Err("the publisher did not take the relay".to_string());
    }
    let ws = tokio::time::timeout(
        DIAL_TIMEOUT,
        relay::connect_server_relay(&ctx.rendezvous_url, &offer.ticket_id, &offer.initiator_token),
    )
    .await
    .map_err(|_| "relay connect timed out".to_string())??;
    let (reader, writer) = tokio::io::split(ws);
    let mut parts = crate::network::ed2k::secure_stream::initiate(
        Box::new(reader),
        Box::new(writer),
        ctx.our_hash,
        publisher_hash,
        ctx.our_pubkey,
        ctx.our_secret,
    )
    .await
    .map_err(|e| e.to_string())?;
    let fetched = fetch_over(&mut parts.reader, &mut parts.writer, target, true).await;
    let _ = parts.writer.shutdown().await;
    fetched
}

/// Ask for `target`'s list on a connected feed stream and read it whole,
/// each chunk checked against the list's BLAKE3 tree.
async fn fetch_over<R, W>(recv: &mut R, send: &mut W, target: &ListTarget, tcp: bool) -> Result<Vec<u8>, String>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let xfer_id = feed_stream_id(&target.publisher, &target.salt, &target.ed2k);
    let capability = feed_stream_capability(&target.publisher, &target.salt, &target.ed2k);
    let info = attach_stream::request_chunks(FEED_STREAM_MSG_TYPE, recv, send, &xfer_id, &capability, target.size, 0, STATUS_WAIT)
        .await
        .map_err(|e| e.to_string())?;
    if crate::network::ember::feed::root_of_chunk_values(&info.chunk_hashes) != Some(target.blake3) {
        return Err("the publisher's chunk list is not the list its head names".to_string());
    }
    let mut buf = vec![0u8; ATTACH_CHUNK_SIZE];
    let mut bytes = Vec::with_capacity(usize::try_from(target.size).unwrap_or(0));
    for index in 0..info.chunk_count() {
        let len = attach_stream::read_verified_feed_chunk(recv, &info, index, &mut buf)
            .await
            .map_err(|e| e.to_string())?;
        bytes.extend_from_slice(&buf[..len]);
    }
    if bytes.len() as u64 != target.size {
        return Err("the list came short".to_string());
    }
    if tcp {
        let _ = send.write_all(&[attach_tcp::TCP_STREAM_RECEIVED]).await;
        let _ = send.flush().await;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test, as the table is shared by the whole process.
    #[test]
    fn our_feeds_are_found_by_capability_and_only_the_newest_registered() {
        let publisher = [7u8; 32];
        let (a, b) = ([1u8; 16], [2u8; 16]);
        set_own_feeds(vec![a, b]);
        let (capability, _) = derive_feed_presence_capability(&publisher, &b, 100);
        assert_eq!(own_feed_for_capability(&publisher, 100, &capability), Some(b));
        assert_eq!(own_feed_for_capability(&publisher, 101, &capability), None, "another epoch");
        assert_eq!(own_feed_for_capability(&[8u8; 32], 100, &capability), None, "another publisher");

        set_own_feeds((0..40u8).map(|i| [i; 16]).collect());
        assert_eq!(own_feeds().len(), MAX_REGISTERED_FEEDS);
        assert_eq!(own_feeds()[0], [0u8; 16]);

        set_own_feeds(Vec::new());
        assert_eq!(own_feed_for_capability(&publisher, 100, &capability), None, "no longer ours");
    }

    #[test]
    fn a_feed_capability_is_none_of_the_intro_capabilities() {
        let publisher = [9u8; 32];
        let (feed, _) = derive_feed_presence_capability(&publisher, &[0u8; 16], 5);
        assert_ne!(feed, crate::network::ember::crypto::derive_legacy_intro_presence_capability(&publisher, 5));
        assert_ne!(feed, crate::network::ember::crypto::derive_sealed_intro_presence_capability(&publisher, &[0u8; 16], 5).0);
        assert_ne!(feed, derive_feed_presence_capability(&publisher, &[0u8; 16], 6).0);
    }

    #[test]
    fn feed_punches_are_capped_in_all_and_per_follower() {
        assert!(take_punch_slot([1; 16]) && take_punch_slot([1; 16]));
        assert!(!take_punch_slot([1; 16]), "one follower has had their share");
        for follower in 2..=5u8 {
            assert!(take_punch_slot([follower; 16]));
        }
        assert!(!take_punch_slot([9; 16]), "the minute's punches are spent");
    }

    #[test]
    fn relay_sessions_are_capped_and_given_back() {
        let held: Vec<_> = (0..MAX_FEED_RELAY_SESSIONS).map(|_| relay_slot().expect("room")).collect();
        assert!(relay_slot().is_none());
        drop(held);
        assert!(relay_slot().is_some());
    }
}
