use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    future::Future,
    hash::Hash,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, OnceLock,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, DefaultBodyLimit, Path, Query, State,
    },
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::FutureExt;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

mod registry;

const MAX_HTTP_CONNECTIONS: usize = 256;
const RESERVED_HEALTH_CONNECTIONS: usize = 16;
/// Ordinary connections one client network (see [`client_network`]) may hold
/// at once: a tenth of the ordinary pool, so starving it takes at least ten
/// distinct /24s or /64s. Every non-upgrade response closes its connection, so
/// a household NAT full of well-behaved clients holds a slot only for the
/// duration of each request and stays far below this.
///
/// The client is whatever [`extract_client_ip`] derives, so this (like every
/// per-network limit) is only meaningful when `TRUST_PROXY`/`TRUSTED_PROXY_HOPS`
/// match the deployment: behind an unconfigured reverse proxy, all traffic is
/// one network. Loopback is exempt so a local reverse proxy is not capped as a
/// single client, and `/health` is exempt so monitoring is never refused here.
const MAX_HTTP_CONNECTIONS_PER_NETWORK: usize = 24;
const HTTP_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// A body can make byte-level progress forever, so the idle timeout alone
/// cannot bound permit ownership. This covers request parsing and handlers;
/// WebSocket upgrades complete their HTTP request immediately and retain their
/// separate relay lifetime rules.
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

fn http_path_admitted(reserve_only: bool, path: &str) -> bool {
    !reserve_only || path == "/health"
}

/// Concurrent ordinary connections per client network. A slot is released
/// when its [`NetworkConnectionSlot`] drops, which for an upgraded WebSocket
/// is as soon as the upgrade completes — exactly like the admission permits.
/// Relay sockets are bounded by [`MAX_RELAY_SESSIONS_PER_NETWORK`] instead.
#[derive(Clone, Default)]
struct NetworkConnectionLimiter {
    counts: Arc<std::sync::Mutex<HashMap<IpAddr, usize>>>,
}

struct NetworkConnectionSlot {
    limiter: NetworkConnectionLimiter,
    network: IpAddr,
}

impl NetworkConnectionLimiter {
    fn try_acquire(&self, client_ip: IpAddr, limit: usize) -> Option<NetworkConnectionSlot> {
        let network = client_network(client_ip);
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if counts.get(&network).copied().unwrap_or(0) >= limit {
            return None;
        }
        *counts.entry(network).or_insert(0) += 1;
        Some(NetworkConnectionSlot {
            limiter: self.clone(),
            network,
        })
    }
}

/// Charges a connection to the client network its first request names. This
/// waits for headers even for direct peers: behind the trusted proxy the peer
/// address is the proxy's, and charging at accept would refuse `/health`
/// before its path is known.
fn admit_client_network(
    limiter: &NetworkConnectionLimiter,
    slot: &std::sync::Mutex<Option<NetworkConnectionSlot>>,
    path: &str,
    client_ip: IpAddr,
) -> bool {
    if path == "/health" || canonical_ip(client_ip).is_loopback() {
        return true;
    }
    let mut slot = slot.lock().unwrap_or_else(|poison| poison.into_inner());
    if slot.is_some() {
        return true;
    }
    match limiter.try_acquire(client_ip, MAX_HTTP_CONNECTIONS_PER_NETWORK) {
        Some(acquired) => {
            *slot = Some(acquired);
            true
        }
        None => false,
    }
}

impl Drop for NetworkConnectionSlot {
    fn drop(&mut self) {
        let mut counts = self
            .limiter
            .counts
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(count) = counts.get_mut(&self.network) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.network);
            }
        }
    }
}

struct IdleTimeoutStream {
    inner: tokio::net::TcpStream,
    idle: Duration,
    deadline: Pin<Box<tokio::time::Sleep>>,
}

impl IdleTimeoutStream {
    fn new(inner: tokio::net::TcpStream, idle: Duration) -> Self {
        Self {
            inner,
            idle,
            deadline: Box::pin(tokio::time::sleep(idle)),
        }
    }

    fn reset(&mut self) {
        self.deadline
            .as_mut()
            .reset(tokio::time::Instant::now() + self.idle);
    }

    fn timed_out(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.deadline.as_mut().poll(cx).is_ready() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP connection idle timeout",
            ))
        } else {
            Ok(())
        }
    }
}

impl tokio::io::AsyncRead for IdleTimeoutStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.timed_out(cx)?;
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        if matches!(&result, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
            self.reset();
        }
        result
    }
}

impl tokio::io::AsyncWrite for IdleTimeoutStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.timed_out(cx)?;
        let result = Pin::new(&mut self.inner).poll_write(cx, buffer);
        if matches!(result, Poll::Ready(Ok(written)) if written > 0) {
            self.reset();
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.timed_out(cx)?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Authentication: every endpoint that mutates per-id state, or dequeues
// per-id signaling, requires an Ed25519 signature from the keypair that
// owns the id. The id is `SHA256(BLAKE3(pubkey)[..16])` (hex-encoded),
// matching the client-side derivation in
// `src-tauri/src/network/rendezvous.rs::hashed_id`. Once `/register`
// has succeeded for a given id, the pubkey is pinned on the server side
// and all later operations on that id MUST verify against the same
// pubkey — closing the squat-and-steer hole that earlier let any
// network actor compute a victim's id and POST a fake address for it.
// ---------------------------------------------------------------------------

/// Domain-separation prefix included in every signed message. Bumping
/// this string is a clean way to invalidate all previously-issued
/// signatures (e.g. if we ever need to migrate the schema).
const RDV_DOMAIN: &[u8] = b"ember-rdv-v1";
const OP_REGISTER: u8 = 0x01;
const OP_UNREGISTER: u8 = 0x02;
const OP_RELAY_TICKET_ACCEPT: u8 = 0x09;
const OP_RELAY_TICKET_STATUS: u8 = 0x0a;
const OP_CAPABILITY_REGISTER: u8 = 0x0c;
const OP_CAPABILITY_LOOKUP: u8 = 0x0d;
const OP_RELAY_MAILBOX_OFFER: u8 = 0x0e;
const OP_RELAY_MAILBOX_POLL: u8 = 0x0f;
const OP_PUNCH_REGISTER_V3: u8 = 0x10;
const OP_PUNCH_POLL_V3: u8 = 0x11;
const OP_PUNCH_ACK_V3: u8 = 0x12;
/// Version 4 is the first IP-family-bound rendezvous protocol.  It uses a
/// separate domain, operation range, and route namespace so rolling deploys
/// can never interpret a v4 signature as a legacy v3 signature (or vice versa).
const RDV_V4_DOMAIN: &[u8] = b"ember-rdv-v4";
const OP_IDENTITY_LOOKUP_V4: u8 = 0x20;
const OP_CAPABILITY_REGISTER_V4: u8 = 0x21;
const OP_CAPABILITY_LOOKUP_V4: u8 = 0x22;
const OP_PUNCH_REGISTER_V4: u8 = 0x23;
const OP_PUNCH_POLL_V4: u8 = 0x24;
const OP_PUNCH_ACK_V4: u8 = 0x25;
const OP_CHANNEL_USERNAME_V4: u8 = 0x26;
const OP_CHANNEL_NAME_V4: u8 = 0x27;
const OP_CHANNEL_DELETE_V4: u8 = 0x28;
const OP_CHANNEL_NOMINEE_V4: u8 = 0x29;
const OP_CHANNEL_HANDOVER_V4: u8 = 0x2a;
/// Channel-name claim that also commits to the published display string.
/// See [`build_channel_name_display_v4_msg`].
const OP_CHANNEL_NAME_DISPLAY_V4: u8 = 0x2b;
/// Rename of a room's registry name. Its own opcode, so no claim signature —
/// which an owner's client re-sends on a timer — can ever be read as one.
const OP_CHANNEL_RENAME_V4: u8 = 0x2c;

/// Canonical signed-IP encoding: `4 || ipv4` or `6 || ipv6`.
const SIGNED_IP_V4: u8 = 4;
const SIGNED_IP_V6: u8 = 6;

fn encode_signed_ip(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => {
            let mut out = Vec::with_capacity(5);
            out.push(SIGNED_IP_V4);
            out.extend_from_slice(&v4.octets());
            out
        }
        IpAddr::V6(v6) => {
            let mut out = Vec::with_capacity(17);
            out.push(SIGNED_IP_V6);
            out.extend_from_slice(&v6.octets());
            out
        }
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        IpAddr::V4(_) => ip,
    }
}

/// Prefix lengths treated as one client for per-client caps: a /24 is the
/// smallest IPv4 block routed on the internet, and a /64 is one IPv6 subnet,
/// which a single host usually controls in its entirety. Keying on the exact
/// address let one operator multiply every per-client cap by rotating
/// addresses inside a block it already holds.
const CLIENT_NETWORK_V4_PREFIX: u32 = 24;
const CLIENT_NETWORK_V6_PREFIX: u32 = 64;

fn client_network(ip: IpAddr) -> IpAddr {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(
            u32::from(v4) & (u32::MAX << (32 - CLIENT_NETWORK_V4_PREFIX)),
        )),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(
            u128::from(v6) & (u128::MAX << (128 - CLIENT_NETWORK_V6_PREFIX)),
        )),
    }
}

fn parse_routable_ip(s: &str) -> Option<IpAddr> {
    let ip = canonical_ip(s.parse::<IpAddr>().ok()?);
    match ip {
        IpAddr::V4(v4) if is_routable_public_v4(v4) => Some(ip),
        // Presence and punch stay IPv4-only until clients verify IPv6 end-to-end.
        IpAddr::V4(_) | IpAddr::V6(_) => None,
    }
}

/// Maximum allowed clock skew between the client and server timestamps
/// in a signed request. 5 minutes covers normal NTP-skewed clients
/// without giving an attacker a useful replay window.
const MAX_TIMESTAMP_SKEW_SECS: i64 = 300;
/// Signing keys with live replay state. See [`ReplayGuard`].
const MAX_REPLAY_KEYS: usize = 100_000;
/// Scope marks across all keys.
const MAX_REPLAY_MARKS: usize = 200_000;
/// Scope marks one key may hold. Punch registration takes one per target, and
/// the per-IP punch budget keeps an honest client well below this within one
/// second, which is the burst that must never be squeezed.
const MAX_REPLAY_MARKS_PER_KEY: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplayAdmission {
    Accepted,
    /// Byte-identical repeat of the newest request in an idempotent scope.
    Repeat,
    Replay,
    /// Outside the freshness window as of the guard's clock.
    Stale,
    Full,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplayMode {
    /// Every request in the scope is accepted at most once.
    OneTime,
    /// A scope whose request sets state: re-sending the newest request
    /// re-applies the state it already set, so it is allowed; anything older
    /// would roll that state back and is refused.
    IdempotentRepeat,
}

/// Read-only ticket poll/status requests intentionally reuse a stable nonce
/// and are safe to serve idempotently. Keep just one nonce per read scope,
/// rather than one entry per periodic request.
#[derive(Clone, Copy)]
struct IdempotentReadNonce {
    nonce: [u8; 16],
    last_ts: i64,
    expires_at: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdempotentReadAdmission {
    New,
    Idempotent,
    Replay,
    NonceConflict,
    Full,
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn timestamp_fresh(ts: i64) -> bool {
    fresh_at(ts, now_unix_secs())
}

fn fresh_at(ts: i64, now: i64) -> bool {
    // `ts` is unauthenticated request data, and `(now - ts).abs()` overflows for
    // `ts == now - i64::MIN`: the subtraction wraps to `i64::MIN`, whose `abs`
    // wraps to itself, which compares `<=` and passes the gate. A security
    // predicate must not fail open on an input an attacker chooses, and with
    // overflow checks enabled the same expression is an unauthenticated panic.
    now.abs_diff(ts) <= MAX_TIMESTAMP_SKEW_SECS.unsigned_abs()
}

fn decode_hex_pubkey(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    if hex::decode_to_slice(s, &mut out).is_ok() {
        Some(out)
    } else {
        None
    }
}

fn decode_hex_sig(s: &str) -> Option<[u8; 64]> {
    let mut out = [0u8; 64];
    if hex::decode_to_slice(s, &mut out).is_ok() {
        Some(out)
    } else {
        None
    }
}

fn decode_hex_id(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    if hex::decode_to_slice(s, &mut out).is_ok() {
        Some(out)
    } else {
        None
    }
}

fn decode_hex_nonce(s: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    if hex::decode_to_slice(s, &mut out).is_ok() {
        Some(out)
    } else {
        None
    }
}

/// Re-derive the rendezvous id from a pubkey and check it matches the
/// claimed id. Mirrors the client-side derivation chain
/// `pubkey -> ember_hash (BLAKE3 truncated) -> id (SHA256)`.
fn pubkey_matches_id(pubkey: &[u8; 32], claimed_id: &str) -> bool {
    id_from_pubkey(pubkey).eq_ignore_ascii_case(claimed_id)
}

fn id_from_pubkey(pubkey: &[u8; 32]) -> String {
    let pk_blake = blake3::hash(pubkey);
    let ember_hash = &pk_blake.as_bytes()[..16];
    let mut sha = Sha256::new();
    sha.update(ember_hash);
    hex::encode(sha.finalize())
}

fn ed25519_verify(pubkey: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let signature = Signature::from_bytes(sig);
    // verify_strict rejects malleable signatures and small-subgroup
    // attacks; the strict flavour is what the protocol audit
    // recommended, so use it everywhere on the server.
    vk.verify_strict(message, &signature).is_ok()
}

fn build_register_msg(
    id_raw: &[u8; 32],
    port: u16,
    ip4: [u8; 4],
    pubkey: &[u8; 32],
    ts: i64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(RDV_DOMAIN.len() + 1 + 32 + 2 + 4 + 32 + 8);
    m.extend_from_slice(RDV_DOMAIN);
    m.push(OP_REGISTER);
    m.extend_from_slice(id_raw);
    m.extend_from_slice(&port.to_le_bytes());
    m.extend_from_slice(&ip4);
    m.extend_from_slice(pubkey);
    m.extend_from_slice(&ts.to_le_bytes());
    m
}

fn build_unregister_msg(id_raw: &[u8; 32], ts: i64) -> Vec<u8> {
    let mut m = Vec::with_capacity(RDV_DOMAIN.len() + 1 + 32 + 8);
    m.extend_from_slice(RDV_DOMAIN);
    m.push(OP_UNREGISTER);
    m.extend_from_slice(id_raw);
    m.extend_from_slice(&ts.to_le_bytes());
    m
}

fn build_relay_ticket_action_msg(
    operation: u8,
    identity_id: &[u8; 32],
    ticket_id: &[u8; 32],
    nonce: &[u8; 16],
    ts: i64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(RDV_DOMAIN.len() + 1 + 32 + 32 + 16 + 8);
    m.extend_from_slice(RDV_DOMAIN);
    m.push(operation);
    m.extend_from_slice(identity_id);
    m.extend_from_slice(ticket_id);
    m.extend_from_slice(nonce);
    m.extend_from_slice(&ts.to_le_bytes());
    m
}

fn build_capability_register_v3_msg(
    capability: &[u8; 32],
    epoch: i64,
    port: u16,
    ip4: [u8; 4],
    pubkey: &[u8; 32],
    peer_pubkey: &[u8; 32],
    ts: i64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(RDV_DOMAIN.len() + 1 + 32 + 8 + 2 + 4 + 32 + 32 + 8);
    m.extend_from_slice(RDV_DOMAIN);
    m.push(OP_CAPABILITY_REGISTER);
    m.extend_from_slice(capability);
    m.extend_from_slice(&epoch.to_le_bytes());
    m.extend_from_slice(&port.to_le_bytes());
    m.extend_from_slice(&ip4);
    m.extend_from_slice(pubkey);
    m.extend_from_slice(peer_pubkey);
    m.extend_from_slice(&ts.to_le_bytes());
    m
}

fn build_capability_register_v4_msg(
    capability: &[u8; 32],
    epoch: i64,
    port: u16,
    signed_ip: &[u8],
    pubkey: &[u8; 32],
    peer_pubkey: &[u8; 32],
    ts: i64,
) -> Vec<u8> {
    let mut m =
        Vec::with_capacity(RDV_V4_DOMAIN.len() + 1 + 32 + 8 + 2 + signed_ip.len() + 32 + 32 + 8);
    m.extend_from_slice(RDV_V4_DOMAIN);
    m.push(OP_CAPABILITY_REGISTER_V4);
    m.extend_from_slice(capability);
    m.extend_from_slice(&epoch.to_le_bytes());
    m.extend_from_slice(&port.to_le_bytes());
    m.extend_from_slice(signed_ip);
    m.extend_from_slice(pubkey);
    m.extend_from_slice(peer_pubkey);
    m.extend_from_slice(&ts.to_le_bytes());
    m
}

fn build_identity_lookup_v4_msg(
    target_id: &[u8; 32],
    requester_id: &[u8; 32],
    requester_pubkey: &[u8; 32],
    nonce: &[u8; 16],
    ts: i64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(RDV_V4_DOMAIN.len() + 1 + 32 + 32 + 32 + 16 + 8);
    m.extend_from_slice(RDV_V4_DOMAIN);
    m.push(OP_IDENTITY_LOOKUP_V4);
    m.extend_from_slice(target_id);
    m.extend_from_slice(requester_id);
    m.extend_from_slice(requester_pubkey);
    m.extend_from_slice(nonce);
    m.extend_from_slice(&ts.to_le_bytes());
    m
}

fn build_capability_lookup_v3_msg(
    capability: &[u8; 32],
    epoch: i64,
    requester_id: &[u8; 32],
    requester_pubkey: &[u8; 32],
    nonce: &[u8; 16],
    ts: i64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(RDV_DOMAIN.len() + 1 + 32 + 8 + 32 + 32 + 16 + 8);
    m.extend_from_slice(RDV_DOMAIN);
    m.push(OP_CAPABILITY_LOOKUP);
    m.extend_from_slice(capability);
    m.extend_from_slice(&epoch.to_le_bytes());
    m.extend_from_slice(requester_id);
    m.extend_from_slice(requester_pubkey);
    m.extend_from_slice(nonce);
    m.extend_from_slice(&ts.to_le_bytes());
    m
}

fn build_capability_lookup_v4_msg(
    capability: &[u8; 32],
    epoch: i64,
    requester_id: &[u8; 32],
    requester_pubkey: &[u8; 32],
    nonce: &[u8; 16],
    ts: i64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(RDV_V4_DOMAIN.len() + 1 + 32 + 8 + 32 + 32 + 16 + 8);
    m.extend_from_slice(RDV_V4_DOMAIN);
    m.push(OP_CAPABILITY_LOOKUP_V4);
    m.extend_from_slice(capability);
    m.extend_from_slice(&epoch.to_le_bytes());
    m.extend_from_slice(requester_id);
    m.extend_from_slice(requester_pubkey);
    m.extend_from_slice(nonce);
    m.extend_from_slice(&ts.to_le_bytes());
    m
}

#[allow(clippy::too_many_arguments)]
fn build_relay_mailbox_offer_msg(
    initiator_id: &[u8; 32],
    responder_id: &[u8; 32],
    capability: &[u8; 32],
    epoch: i64,
    ticket_id: &[u8; 32],
    envelope: &[u8],
    nonce: &[u8; 16],
    ts: i64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(RDV_DOMAIN.len() + 1 + 32 * 4 + 8 + 4 + envelope.len() + 16 + 8);
    m.extend_from_slice(RDV_DOMAIN);
    m.push(OP_RELAY_MAILBOX_OFFER);
    m.extend_from_slice(initiator_id);
    m.extend_from_slice(responder_id);
    m.extend_from_slice(capability);
    m.extend_from_slice(&epoch.to_le_bytes());
    m.extend_from_slice(ticket_id);
    m.extend_from_slice(&(envelope.len() as u32).to_le_bytes());
    m.extend_from_slice(envelope);
    m.extend_from_slice(nonce);
    m.extend_from_slice(&ts.to_le_bytes());
    m
}

fn build_relay_mailbox_poll_msg(responder_id: &[u8; 32], nonce: &[u8; 16], ts: i64) -> Vec<u8> {
    let mut m = Vec::with_capacity(RDV_DOMAIN.len() + 1 + 32 + 16 + 8);
    m.extend_from_slice(RDV_DOMAIN);
    m.push(OP_RELAY_MAILBOX_POLL);
    m.extend_from_slice(responder_id);
    m.extend_from_slice(nonce);
    m.extend_from_slice(&ts.to_le_bytes());
    m
}

#[allow(clippy::too_many_arguments)]
fn build_punch_register_v3_msg(
    from_id: &[u8; 32],
    target_id: &[u8; 32],
    capability: &[u8; 32],
    epoch: i64,
    port: u16,
    nat_type: u8,
    nonce: &[u8; 16],
    ts: i64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(RDV_DOMAIN.len() + 1 + 32 * 3 + 8 + 2 + 1 + 16 + 8);
    message.extend_from_slice(RDV_DOMAIN);
    message.push(OP_PUNCH_REGISTER_V3);
    message.extend_from_slice(from_id);
    message.extend_from_slice(target_id);
    message.extend_from_slice(capability);
    message.extend_from_slice(&epoch.to_le_bytes());
    message.extend_from_slice(&port.to_le_bytes());
    message.push(nat_type);
    message.extend_from_slice(nonce);
    message.extend_from_slice(&ts.to_le_bytes());
    message
}

#[allow(clippy::too_many_arguments)]
fn build_punch_register_v4_msg(
    from_id: &[u8; 32],
    target_id: &[u8; 32],
    capability: &[u8; 32],
    epoch: i64,
    port: u16,
    signed_ip: &[u8],
    nat_type: u8,
    nonce: &[u8; 16],
    ts: i64,
) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(RDV_V4_DOMAIN.len() + 1 + 32 * 3 + 8 + 2 + signed_ip.len() + 1 + 16 + 8);
    message.extend_from_slice(RDV_V4_DOMAIN);
    message.push(OP_PUNCH_REGISTER_V4);
    message.extend_from_slice(from_id);
    message.extend_from_slice(target_id);
    message.extend_from_slice(capability);
    message.extend_from_slice(&epoch.to_le_bytes());
    message.extend_from_slice(&port.to_le_bytes());
    message.extend_from_slice(signed_ip);
    message.push(nat_type);
    message.extend_from_slice(nonce);
    message.extend_from_slice(&ts.to_le_bytes());
    message
}

fn build_punch_poll_v3_msg(target_id: &[u8; 32], nonce: &[u8; 16], ts: i64) -> Vec<u8> {
    let mut message = Vec::with_capacity(RDV_DOMAIN.len() + 1 + 32 + 16 + 8);
    message.extend_from_slice(RDV_DOMAIN);
    message.push(OP_PUNCH_POLL_V3);
    message.extend_from_slice(target_id);
    message.extend_from_slice(nonce);
    message.extend_from_slice(&ts.to_le_bytes());
    message
}

fn build_punch_ack_v3_msg(
    target_id: &[u8; 32],
    capability: &[u8; 32],
    epoch: i64,
    punch_id: &[u8; 32],
    nonce: &[u8; 16],
    ts: i64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(RDV_DOMAIN.len() + 1 + 32 * 3 + 8 + 16 + 8);
    message.extend_from_slice(RDV_DOMAIN);
    message.push(OP_PUNCH_ACK_V3);
    message.extend_from_slice(target_id);
    message.extend_from_slice(capability);
    message.extend_from_slice(&epoch.to_le_bytes());
    message.extend_from_slice(punch_id);
    message.extend_from_slice(nonce);
    message.extend_from_slice(&ts.to_le_bytes());
    message
}

fn build_punch_poll_v4_msg(target_id: &[u8; 32], nonce: &[u8; 16], ts: i64) -> Vec<u8> {
    let mut message = Vec::with_capacity(RDV_V4_DOMAIN.len() + 1 + 32 + 16 + 8);
    message.extend_from_slice(RDV_V4_DOMAIN);
    message.push(OP_PUNCH_POLL_V4);
    message.extend_from_slice(target_id);
    message.extend_from_slice(nonce);
    message.extend_from_slice(&ts.to_le_bytes());
    message
}

fn build_punch_ack_v4_msg(
    target_id: &[u8; 32],
    capability: &[u8; 32],
    epoch: i64,
    punch_id: &[u8; 32],
    nonce: &[u8; 16],
    ts: i64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(RDV_V4_DOMAIN.len() + 1 + 32 * 3 + 8 + 16 + 8);
    message.extend_from_slice(RDV_V4_DOMAIN);
    message.push(OP_PUNCH_ACK_V4);
    message.extend_from_slice(target_id);
    message.extend_from_slice(capability);
    message.extend_from_slice(&epoch.to_le_bytes());
    message.extend_from_slice(punch_id);
    message.extend_from_slice(nonce);
    message.extend_from_slice(&ts.to_le_bytes());
    message
}

fn build_channel_username_v4_msg(pubkey: &[u8; 32], name: &str, ts: i64) -> Vec<u8> {
    let mut message = Vec::with_capacity(RDV_V4_DOMAIN.len() + 1 + 32 + name.len() + 8);
    message.extend_from_slice(RDV_V4_DOMAIN);
    message.push(OP_CHANNEL_USERNAME_V4);
    message.extend_from_slice(pubkey);
    message.extend_from_slice(name.as_bytes());
    message.extend_from_slice(&ts.to_le_bytes());
    message
}

fn build_channel_name_v4_msg(
    channel_id: &[u8; 16],
    pubkey: &[u8; 32],
    name: &str,
    private: bool,
    ts: i64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(RDV_V4_DOMAIN.len() + 1 + 16 + 32 + name.len() + 1 + 8);
    message.extend_from_slice(RDV_V4_DOMAIN);
    message.push(OP_CHANNEL_NAME_V4);
    message.extend_from_slice(channel_id);
    message.extend_from_slice(pubkey);
    message.extend_from_slice(name.as_bytes());
    message.push(u8::from(private));
    message.extend_from_slice(&ts.to_le_bytes());
    message
}

/// Signed form of a channel-name claim that also commits to the *display*
/// string the directory will publish.
///
/// [`build_channel_name_v4_msg`] covers only the normalised key, so the bytes
/// actually served to every client were never signed by anyone. Case folding
/// is not injective — U+212A KELVIN SIGN folds to ASCII `k`, U+0130 to `i`
/// plus a combining dot — so the published string can contain scalars absent
/// from the signed one, and the replay key (computed over the signed message)
/// collided for two requests differing only in their display bytes.
///
/// Both strings are length-prefixed, so no pair of (normalised, display)
/// values can encode the same as a different pair, and the opcode differs from
/// [`OP_CHANNEL_NAME_V4`] so a legacy signature can never be reinterpreted as
/// one of these.
fn build_channel_name_display_v4_msg(
    channel_id: &[u8; 16],
    pubkey: &[u8; 32],
    normalized: &str,
    display: &str,
    private: bool,
    ts: i64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        RDV_V4_DOMAIN.len() + 1 + 16 + 32 + 4 + normalized.len() + 4 + display.len() + 1 + 8,
    );
    message.extend_from_slice(RDV_V4_DOMAIN);
    message.push(OP_CHANNEL_NAME_DISPLAY_V4);
    message.extend_from_slice(channel_id);
    message.extend_from_slice(pubkey);
    message.extend_from_slice(&(normalized.len() as u32).to_le_bytes());
    message.extend_from_slice(normalized.as_bytes());
    message.extend_from_slice(&(display.len() as u32).to_le_bytes());
    message.extend_from_slice(display.as_bytes());
    message.push(u8::from(private));
    message.extend_from_slice(&ts.to_le_bytes());
    message
}

/// Signed form of a rename: the same layout as
/// [`build_channel_name_display_v4_msg`] under [`OP_CHANNEL_RENAME_V4`].
fn build_channel_rename_v4_msg(
    channel_id: &[u8; 16],
    pubkey: &[u8; 32],
    normalized: &str,
    display: &str,
    private: bool,
    ts: i64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        RDV_V4_DOMAIN.len() + 1 + 16 + 32 + 4 + normalized.len() + 4 + display.len() + 1 + 8,
    );
    message.extend_from_slice(RDV_V4_DOMAIN);
    message.push(OP_CHANNEL_RENAME_V4);
    message.extend_from_slice(channel_id);
    message.extend_from_slice(pubkey);
    message.extend_from_slice(&(normalized.len() as u32).to_le_bytes());
    message.extend_from_slice(normalized.as_bytes());
    message.extend_from_slice(&(display.len() as u32).to_le_bytes());
    message.extend_from_slice(display.as_bytes());
    message.push(u8::from(private));
    message.extend_from_slice(&ts.to_le_bytes());
    message
}

fn build_channel_delete_v4_msg(channel_id: &[u8; 16], pubkey: &[u8; 32], ts: i64) -> Vec<u8> {
    let mut message = Vec::with_capacity(RDV_V4_DOMAIN.len() + 1 + 16 + 32 + 8);
    message.extend_from_slice(RDV_V4_DOMAIN);
    message.push(OP_CHANNEL_DELETE_V4);
    message.extend_from_slice(channel_id);
    message.extend_from_slice(pubkey);
    message.extend_from_slice(&ts.to_le_bytes());
    message
}

fn build_channel_nominee_v4_msg(
    channel_id: &[u8; 16],
    pubkey: &[u8; 32],
    nominee: &[u8; 32],
    claim_after_days: u32,
    ts: i64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(RDV_V4_DOMAIN.len() + 1 + 16 + 32 + 32 + 4 + 8);
    message.extend_from_slice(RDV_V4_DOMAIN);
    message.push(OP_CHANNEL_NOMINEE_V4);
    message.extend_from_slice(channel_id);
    message.extend_from_slice(pubkey);
    message.extend_from_slice(nominee);
    message.extend_from_slice(&claim_after_days.to_le_bytes());
    message.extend_from_slice(&ts.to_le_bytes());
    message
}

/// The signer is bound into the message so one signature cannot be replayed as
/// the other authorization path: the server decides *which* rule to apply from
/// the key that signed, and that key has to be what the owner actually signed.
fn build_channel_handover_v4_msg(
    old_channel_id: &[u8; 16],
    new_channel_id: &[u8; 16],
    new_pubkey: &[u8; 32],
    signer: &[u8; 32],
    ts: i64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(RDV_V4_DOMAIN.len() + 1 + 16 + 16 + 32 + 32 + 8);
    message.extend_from_slice(RDV_V4_DOMAIN);
    message.push(OP_CHANNEL_HANDOVER_V4);
    message.extend_from_slice(old_channel_id);
    message.extend_from_slice(new_channel_id);
    message.extend_from_slice(new_pubkey);
    message.extend_from_slice(signer);
    message.extend_from_slice(&ts.to_le_bytes());
    message
}

fn decode_hex_channel_id(s: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    if hex::decode_to_slice(s, &mut out).is_ok() {
        Some(out)
    } else {
        None
    }
}

fn channel_id_matches_pubkey(pubkey: &[u8; 32], channel_id: &[u8; 16]) -> bool {
    let hash = blake3::hash(pubkey);
    &hash.as_bytes()[..16] == channel_id.as_slice()
}

fn registry_error_status(err: registry::RegistryError) -> StatusCode {
    match err {
        registry::RegistryError::InvalidName => StatusCode::BAD_REQUEST,
        registry::RegistryError::Taken => StatusCode::CONFLICT,
        registry::RegistryError::Forbidden => StatusCode::FORBIDDEN,
        // Not the caller's fault and not about the name they asked for, so
        // neither 400 nor 409: the server has no capacity to record it.
        registry::RegistryError::Full => StatusCode::SERVICE_UNAVAILABLE,
        registry::RegistryError::ReadOnly => StatusCode::SERVICE_UNAVAILABLE,
        // Distinct from 429, which is the per-IP limiter: the client tells the
        // owner when they can rename again rather than to slow down.
        registry::RegistryError::RenameTooSoon => StatusCode::TOO_EARLY,
    }
}

fn load_channels_registry() -> Arc<RwLock<registry::ChannelRegistry>> {
    match std::env::var("CHANNELS_REGISTRY_PATH") {
        Ok(path) if !path.trim().is_empty() => {
            info!("channels registry at {path}");
            Arc::new(RwLock::new(registry::ChannelRegistry::load(
                std::path::PathBuf::from(path),
            )))
        }
        _ => {
            warn!(
                "CHANNELS_REGISTRY_PATH unset; channel usernames and names are in-memory only"
            );
            Arc::new(RwLock::new(registry::ChannelRegistry::in_memory()))
        }
    }
}

fn signed_request_digest(message: &[u8], sig: &[u8; 64]) -> u128 {
    let mut sha = Sha256::new();
    sha.update(message);
    sha.update(sig);
    let digest: [u8; 32] = sha.finalize().into();
    u128::from_le_bytes(digest[..16].try_into().expect("16-byte prefix"))
}

/// Replay scope of an operation, optionally narrowed to its target. A
/// collision merges two of one signer's scopes, which only ever refuses more.
fn replay_scope(operation: u8, subject: &[u8]) -> u64 {
    let mut sha = Sha256::new();
    sha.update([operation]);
    sha.update(subject);
    let digest: [u8; 32] = sha.finalize().into();
    u64::from_le_bytes(digest[..8].try_into().expect("8-byte prefix"))
}

const ENTRY_TTL: Duration = Duration::from_secs(300);
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const MAX_REQUESTS_PER_MINUTE: u64 = 60;
/// Keep authenticated mailbox/status reads isolated from general and punch
/// budgets. The generous ceiling absorbs bounded retries without letting
/// signaling consume mutation capacity.
const MAX_TICKET_READS_PER_MINUTE: u64 = 600;
const RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_STORE_ENTRIES: usize = 100_000;
const MAX_RATE_ENTRIES: usize = 200_000;

const PUNCH_TTL: Duration = Duration::from_secs(30);
/// Per-IP punch register rate limit. Was `10/min`, but a single
/// LowID Ember client may legitimately fire 5–10 punch attempts per
/// active download in a sub-second burst (one per discovered LowID
/// peer), then retry every 15 s. At `10/min` the second retry round
/// for two concurrent downloads exhausts the budget and the server
/// returns `429 Too Many Requests` for the rest, leaving them stuck
/// on the relay fallback for no good reason. `60/min` covers the
/// realistic worst case (2 downloads × 8 peers × 2 retries within a
/// minute = 32) with comfortable headroom.
const MAX_PUNCH_PER_MINUTE: u64 = 60;
/// New channel names, usernames and tombstones one [`rate_key`] (an IPv4
/// address or an IPv6 /64) may create per hour.
///
/// A room name is reserved the moment it is claimed and held for a long time
/// afterwards, so mass creation is not a load problem — it is a land grab that
/// takes words out of circulation and buries Discover under rooms nobody is
/// in. Six an hour is far more than anyone opens by hand and far less than a
/// script wants.
///
/// Only *new* names count. Re-claiming a name the same room already holds is
/// how an owner refreshes it, and a refresh must never be refused for looking
/// like creation. Retries after a failed create do spend budget, which is
/// intended: a client looping on create is exactly what this bounds.
const MAX_CHANNEL_CREATES_PER_HOUR: u64 = 6;
/// The same budget pooled across one [`client_network`] (/24 or /64).
///
/// What this budget guards is permanent: usernames are held for a year and
/// tombstones forever, and the registry refuses every new claim once a map is
/// full. Per-address alone, one rented /24 bought 256 x 6 of those an hour.
/// The pool is deliberately larger than one address's share rather than equal
/// to it, because carrier-grade NAT puts many unrelated subscribers in one
/// /24; refreshes are never charged, so only genuinely new names compete for
/// it. For IPv6 both tiers key on the /64, so this adds nothing there.
const MAX_CHANNEL_CREATES_PER_NETWORK_PER_HOUR: u64 = 24;
const CHANNEL_CREATE_WINDOW: Duration = Duration::from_secs(3600);
/// Cap on simultaneous pending punch entries per `target_id`. Bounds
/// the impact of `punch_register` spam against a victim once the
/// per-IP rate limit is exhausted (the attacker would have to source
/// from many IPs to fill more slots, which is also bounded by
/// `MAX_GLOBAL_RELAY_SESSIONS` upstream).
const MAX_PUNCH_PER_TARGET: usize = 8;
/// Of [`MAX_PUNCH_PER_TARGET`], how many slots requesters authorized only by a
/// public friend-code intro capability may hold at once. Everyone else's claim
/// rests on a pairwise capability the target itself handed out, so reserving the
/// remainder keeps a stranger with the target's friend code from crowding its
/// actual friends out of the queue.
const MAX_PUNCH_PER_TARGET_OPEN_INTRO: usize = 2;
const MAX_PUNCH_REQUESTS_TOTAL: usize = 100_000;
/// Relay session cap per client network. Was `2`, which was the cause of every
/// `WebSocket protocol error: Sending after closing is not allowed`
/// failure the Ember client saw on adoption: the server accepts the
/// WS handshake (so `connect_async` returns Ok), THEN this check
/// runs, finds the IP already has 2 sessions, and immediately sends
/// `Close(None)` and returns. From the client's POV the connection
/// is "open", multi_source adopts the stream, the first write fails
/// with the close-after-send error.
///
/// One Ember client legitimately wants N concurrent relay sessions:
/// each (file × LowID peer) pair gets its own room (since each
/// peer dials its own session_id from the relay-invite). With ~5–10
/// LowID peers per active download and 2–3 active downloads, the
/// realistic working set is 16–32 simultaneous sessions per client
/// IP. `32` covers that with a small buffer; the global cap
/// (`MAX_GLOBAL_RELAY_SESSIONS = 200`) still bounds total resource
/// consumption to ~6 maxed-out clients before backpressure kicks in.
///
/// Counted per [`client_network`] rather than per address, so those ~6
/// clients must sit in distinct /24s or /64s: identities are free, and an
/// exact-address key let one IPv6 host (or a handful of IPv4 addresses in one
/// rented block) hold every relay slot. Not lowered below `32` because
/// carrier-grade NAT puts many subscribers in one /24, and they are the users
/// most likely to need the relay.
const MAX_RELAY_SESSIONS_PER_NETWORK: usize = 32;
const MAX_GLOBAL_RELAY_SESSIONS: usize = 200;
/// Combined (both directions summed) byte ceiling for a single relay
/// session — see `RelaySessionEntry` for why both directions share one
/// counter. This is the server-relay counterpart to
/// `ember::relay::RELAY_MAX_BYTES_PER_DIRECTION` on the client, and
/// suffers from the same class of bug that constant's doc comment
/// describes: the previous value here (`256 KiB`) was smaller than a
/// *single* eD2K part (~9.28 MiB), so every LowID-to-LowID transfer
/// that fell back to the server relay (both peers firewalled/symmetric,
/// no volunteer peer-relay available) tripped the cap and was torn
/// down almost immediately — `bridge_relay`/`run_peer1_loop` `break`
/// unconditionally once `new_total > RELAY_BANDWIDTH_CAP_BYTES`, there
/// is no partial-credit or backoff.
///
/// `256 MiB` covers dozens of parts per session while still bounding
/// worst-case server egress: with `MAX_GLOBAL_RELAY_SESSIONS = 200`
/// and `RELAY_SESSION_TIMEOUT` below, the absolute worst case is
/// `200 * 256 MiB = 50 GiB` of relay traffic per timeout window, which
/// is a deliberately smaller blast radius than the client's own
/// volunteer-relay ceiling (`4 sessions * 2 dirs * 8 GiB = 64 GiB` per
/// `RELAY_MAX_DURATION`) since this server is shared infrastructure
/// rather than a single peer's own uplink.
const RELAY_BANDWIDTH_CAP_BYTES: usize = 256 * 1024 * 1024;
/// Hard per-session lifetime, independent of activity. Was `120s`,
/// which is far too short for the byte cap above to ever be reached
/// at realistic relay throughput (256 MiB in 120s needs a sustained
/// ~2.1 MiB/s just from this one session) — the timeout, not the
/// bandwidth cap, was the binding constraint that killed most
/// server-relayed transfers. `30` minutes gives a session a realistic
/// chance to move the full byte budget (≈142 KiB/s sustained) while
/// still bounding how long any one session can occupy a slot against
/// `MAX_GLOBAL_RELAY_SESSIONS`. Transfers that need longer than this
/// simply reconnect through a fresh relay session and resume, same as
/// any other eD2K peer disconnect — see `multi_source.rs` reconnect
/// handling.
const RELAY_SESSION_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Pre-bridge only: how long peer1 waits for peer2 to dial in and join
/// before giving up (see the `if peer2_tx.is_none()` guard in
/// `run_peer1_loop`). Unrelated to in-transfer inactivity — once
/// peer2 joins, this timeout is no longer consulted — so it does not
/// need to scale with the bandwidth/duration changes above.
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Once both peers are bridged, retain the relay only while it carries
/// application traffic. This is deliberately longer than the pre-bridge
/// window so legitimate transfers can pause briefly, but it releases shared
/// admission capacity long before the 30-minute absolute ceiling.
const RELAY_BRIDGE_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
/// How often a bridged relay pings its peer purely to keep the transport's
/// `HTTP_IDLE_TIMEOUT` from expiring under it. Comfortably inside that window so
/// a single dropped tick cannot close a healthy session; see `bridge_relay`.
const RELAY_TRANSPORT_KEEPALIVE: Duration = Duration::from_secs(10);
/// A downstream WebSocket or relay inbox must never hold a relay task inside
/// a forwarding await long enough to bypass its idle and absolute deadlines.
const RELAY_FORWARD_TIMEOUT: Duration = Duration::from_secs(10);
/// A pre-upgrade reservation is short-lived and is rolled back if Axum never
/// invokes the upgrade callback (client disconnect / failed handshake).
const RELAY_UPGRADE_RESERVATION_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PREBRIDGE_RELAY_FRAMES: usize = 32;
const MAX_PREBRIDGE_RELAY_BYTES: usize = 256 * 1024;
const MAX_RELAY_FRAME_BYTES: usize = 16 * 1024;
const MAX_RELAY_QUEUE_BYTES: usize = 256 * 1024;
/// A ticket outlives the client's 45-second initiator wait and repeated
/// one-second self-mailbox polls, while remaining brief enough that an
/// abandoned offer cannot become a reusable relay capability later.
const RELAY_TICKET_TTL: Duration = Duration::from_secs(90);
const MAX_RELAY_TICKETS: usize = 100_000;
/// Served mailbox pages retained for idempotent re-reads. Bounded like every
/// other map here; see `RelayTicketStore::store_mailbox_page`.
const MAX_MAILBOX_PAGE_CACHE: usize = 10_000;
/// The offerer can have a small burst for several friends, but cannot hold
/// every pending-ticket slot by targeting arbitrary responders.
const MAX_PENDING_RELAY_TICKETS_PER_INITIATOR: usize = 16;
/// Bound only tickets a responder has explicitly accepted. Unaccepted offers
/// are intentionally not counted here: the server cannot know which
/// initiators are friends, so applying this cap at offer time would let
/// arbitrary non-friends block a legitimate friend from ever reaching the
/// responder's local authorization check.
const MAX_ACCEPTED_RELAY_TICKETS_PER_RESPONDER: usize = 8;
/// Encrypted envelopes are hex-encoded and relatively large;
/// eight keep the complete JSON response below the client's 8 KiB cap.
const MAX_RELAY_MAILBOX_RESULTS: usize = 8;
/// Bound work per poll while advancing a persistent round-robin cursor.
/// Walks only the pending-offer index, so accepted tickets cannot consume budget.
const MAX_RELAY_MAILBOX_SCAN_PER_POLL: usize = 512;
/// How long a punched entry stays leased to one poller before re-entering the queue.
const PUNCH_LEASE: Duration = Duration::from_secs(5);
const POLL_READ_NONCE_TTL: Duration = Duration::from_secs(10 * 60);
const STATUS_READ_NONCE_TTL: Duration = RELAY_TICKET_TTL;
const MAX_POLL_READ_NONCES: usize = 100_000;
const MAX_STATUS_READ_NONCES: usize = MAX_RELAY_TICKETS;
const MAX_LEGACY_IDENTITY_LOOKUPS_PER_MINUTE: u64 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RendezvousVersion {
    LegacyV3,
    IpBoundV4,
}

impl RendezvousVersion {
    fn wire_value(self) -> u8 {
        match self {
            Self::LegacyV3 => 3,
            Self::IpBoundV4 => 4,
        }
    }
}

#[derive(Clone)]
struct PresenceEntry {
    expires_at: Instant,
    /// The Ed25519 pubkey the rendezvous id binds to. Pinned on first
    /// `/register` for this id and re-checked on every subsequent
    /// `/register`, `/unregister`, `/punch`, and poll request that
    /// targets this id. Closes the squat-and-steer hole that earlier
    /// let any network actor compute a victim's id and POST a fake
    /// address for it.
    pubkey: [u8; 32],
}

#[derive(Clone)]
struct PairwisePresenceEntry {
    ip: IpAddr,
    port: u16,
    expires_at: Instant,
    /// The sole peer authorized to use this capability for lookup, punch, or
    /// mailbox offers. The presence owner signs this binding at registration.
    /// Ignored when `open_intro` is set (friend-code intro presence).
    peer_pubkey: [u8; 32],
    /// When true, any currently-registered requester may look up / punch this
    /// capability. Used for friend-code intro presence (holders of the owner's
    /// `ember3:` code, or of any identifier for an older client).
    open_intro: bool,
    pubkey: [u8; 32],
    epoch: i64,
    legacy_proof: Option<(i64, [u8; 64])>,
    v4_proof: Option<(i64, [u8; 64])>,
}

fn capability_allows_peer(
    entry: &PairwisePresenceEntry,
    peer_pubkey: &[u8; 32],
    epoch: i64,
    now: Instant,
) -> bool {
    entry.expires_at > now
        && entry.epoch == epoch
        && (entry.open_intro || entry.peer_pubkey == *peer_pubkey)
}

/// Whether requesters holding only the target's public intro capability have
/// already taken their share of its punch queue.
///
/// Identities are free to mint and the per-target cap is keyed on
/// `(target, from)`, so without this a handful of throwaway keys filled all of
/// [`MAX_PUNCH_PER_TARGET`] — the cap's own rationale assumes an attacker must
/// source from many IPs, which the open-intro path removes.
fn open_intro_punch_slots_exhausted(punches: &PunchStore, target: &str) -> bool {
    punches.by_target.get(target).map_or(0, |entries| {
        entries.values().filter(|entry| entry.via_open_intro).count()
    }) >= MAX_PUNCH_PER_TARGET_OPEN_INTRO
}

/// A live capability remains owned by the identity that first registered it.
/// An expired entry is not presence and may be claimed by a new owner.
fn capability_owner_allows_register(
    entry: &PairwisePresenceEntry,
    pubkey: &[u8; 32],
    now: Instant,
) -> bool {
    entry.expires_at <= now || entry.pubkey == *pubkey
}

/// Recompute a friend-code intro capability from the owner's public key.
///
/// Must stay byte-identical to the client's `derive_intro_presence_capability`.
/// Because the inputs are public, the server can check that an intro registrant
/// actually owns the namespace it claims instead of merely owning some key.
/// Pairwise capabilities come from a shared secret and remain unverifiable
/// here, which is why they rely on secrecy plus the owner pin above.
fn derive_intro_presence_capability(owner_pubkey: &[u8; 32], epoch: i64) -> [u8; 32] {
    let context = format!("ember-intro-presence-v1:{epoch}");
    blake3::derive_key(&context, owner_pubkey)
}

/// Recompute a sealed (`ember3:`) intro capability from the owner's public key
/// and the per-epoch key it sent with the registration.
///
/// Must stay byte-identical to the client's
/// `derive_sealed_intro_capability_from_key`. The epoch key comes from a secret
/// only the owner and holders of its friend code know, so the capability can no
/// longer be derived from a roster-visible public key — but the server still
/// binds the namespace to the registering key exactly as for the legacy form,
/// without ever learning the long-lived secret.
fn derive_sealed_intro_presence_capability(
    owner_pubkey: &[u8; 32],
    epoch_key: &[u8; 32],
    epoch: i64,
) -> [u8; 32] {
    let context = format!("ember-intro-presence-v2:{epoch}");
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(owner_pubkey);
    input[32..].copy_from_slice(epoch_key);
    blake3::derive_key(&context, &input)
}

/// Status for a sealed intro registration whose `intro_key` is malformed,
/// misplaced, or does not derive the capability. Deliberately unused by any
/// other check: clients treat it — and only it — as "this server will not take
/// my sealed intro" and fall back to the legacy one, while the 400s and 403s
/// shared with every registration (stale timestamp, owner not registered after
/// a restart) are retried as sealed on the next heartbeat.
const SEALED_INTRO_REJECTED: StatusCode = StatusCode::UNPROCESSABLE_ENTITY;

/// The intro capability `pubkey` is entitled to register for `epoch`: sealed
/// when the request carries an epoch key, legacy otherwise (older clients).
fn expected_intro_capability(
    pubkey: &[u8; 32],
    intro_key: Option<&[u8; 32]>,
    epoch: i64,
) -> [u8; 32] {
    match intro_key {
        Some(epoch_key) => derive_sealed_intro_presence_capability(pubkey, epoch_key, epoch),
        None => derive_intro_presence_capability(pubkey, epoch),
    }
}

#[derive(Clone)]
struct RateEntry {
    count: u64,
    window_start: Instant,
}

/// Key a general rate-limit bucket charges: the exact address for IPv4, the
/// /64 for IPv6.
///
/// IPv4 stays per-address because carrier-grade NAT puts many unrelated
/// subscribers in one /24, and a per-minute request budget shared across them
/// would 429 ordinary users. IPv6 cannot stay per-address: a single host
/// usually owns its whole /64, so an exact-address key handed it 2^64 fresh
/// budgets and let it fill a bucket's map on its own.
fn rate_key(ip: IpAddr) -> IpAddr {
    match canonical_ip(ip) {
        v4 @ IpAddr::V4(_) => v4,
        v6 @ IpAddr::V6(_) => client_network(v6),
    }
}

/// One rate-limit bucket: the per-key windows (see [`rate_key`]), plus an age
/// index over them.
///
/// At capacity the bucket evicts its oldest window instead of refusing the
/// newcomer. Refusing meant a flood of distinct keys, once it filled the map,
/// 429'd every legitimate client the server had not already seen until the
/// flood's entries aged out. Evicting only ever hands a key a fresh budget,
/// which any unseen key already gets, so it grants the flood nothing extra.
/// The index keeps that eviction O(log n): a scan for the oldest entry, run
/// on every request from an unseen key under exactly that flood, would turn
/// the limiter into the amplifier.
#[derive(Default)]
struct RateBucket {
    entries: HashMap<IpAddr, RateEntry>,
    /// Exactly one `(window_start, key)` per entry in `entries`.
    by_age: std::collections::BTreeSet<(Instant, IpAddr)>,
}

impl RateBucket {
    fn charge(
        &mut self,
        key: IpAddr,
        max_requests: u64,
        window: Duration,
        now: Instant,
        max_entries: usize,
    ) -> bool {
        match self.entries.get_mut(&key) {
            Some(entry) if now.duration_since(entry.window_start) >= window => {
                self.by_age.remove(&(entry.window_start, key));
                entry.count = 1;
                entry.window_start = now;
                self.by_age.insert((now, key));
                true
            }
            Some(entry) => {
                entry.count += 1;
                entry.count <= max_requests
            }
            None => {
                while self.entries.len() >= max_entries.max(1) {
                    let Some((_, oldest)) = self.by_age.pop_first() else {
                        break;
                    };
                    self.entries.remove(&oldest);
                }
                self.entries.insert(
                    key,
                    RateEntry {
                        count: 1,
                        window_start: now,
                    },
                );
                self.by_age.insert((now, key));
                max_requests >= 1
            }
        }
    }

    fn exhausted(&self, key: IpAddr, max_requests: u64, window: Duration, now: Instant) -> bool {
        self.entries.get(&key).is_some_and(|entry| {
            now.duration_since(entry.window_start) < window && entry.count >= max_requests
        })
    }

    /// Drop every window that started at least `retain_for` ago.
    fn prune(&mut self, now: Instant, retain_for: Duration) {
        while let Some(&(started, key)) = self.by_age.first() {
            if now.duration_since(started) < retain_for {
                break;
            }
            self.by_age.pop_first();
            self.entries.remove(&key);
        }
    }
}

type RateLimitBucket = Arc<RwLock<RateBucket>>;

/// A hole-punch coordination request waiting for the other peer to poll.
#[derive(Clone)]
struct PunchEntry {
    punch_id: String,
    from_id: String,
    from_ip: IpAddr,
    from_port: u16,
    nat_type: u8,
    capability: [u8; 32],
    epoch: i64,
    created_at: Instant,
    /// Set while a poller holds this entry; expired leases return to the queue.
    leased_until: Option<Instant>,
    proof_version: RendezvousVersion,
    /// Present only for v4. Legacy v3 deliberately preserves its original
    /// response shape and relies on the server-observed source address.
    register_nonce: Option<[u8; 16]>,
    /// This requester was authorized only by the target's public intro
    /// capability, not by a pairwise one the target handed it. Bounds how many of
    /// the target's slots strangers can hold — see
    /// [`MAX_PUNCH_PER_TARGET_OPEN_INTRO`].
    via_open_intro: bool,
    register_ts: Option<i64>,
    register_sig: Option<[u8; 64]>,
    from_pubkey: Option<[u8; 32]>,
}

/// Tracks a relay session: two WebSocket halves bridged together.
///
/// `peer1_inbox_tx` is peer1's inbound channel — peer2 forwards its WS
/// payloads here, and peer1's loop drains the matching `Receiver` to its
/// socket. The `Option` is `Some` until peer2 grabs it on join.
///
/// `peer2_announce_tx` is a one-shot used by peer2 (on join) to hand its
/// own inbound `Sender<Vec<u8>>` — along with a clone of the shared
/// `total_bytes` counter — to peer1's still-running loop. Peer1 awaits
/// the receiver side; once it fires, peer1 forwards inbound WS payloads
/// to peer2's inbox and counts bytes against the same shared cap that
/// `bridge_relay` uses on peer2's side. Previously each half tracked
/// its own local counter, which double-counted peer1→peer2 traffic (it
/// passed through both loops) and never combined with peer2→peer1
/// traffic — making the `RELAY_BANDWIDTH_CAP_BYTES` cap effectively
/// vary per-direction and per-attach-order.
///
/// Replaces the older single-direction relay where peer1's WS frames
/// were silently dropped. The bridge is now genuinely full-duplex.
#[derive(Clone)]
struct RelayQueueSender {
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    queued_bytes: Arc<AtomicUsize>,
}

struct RelayQueueReceiver {
    receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    queued_bytes: Arc<AtomicUsize>,
}

impl RelayQueueSender {
    async fn send(&self, frame: Vec<u8>) -> Result<(), ()> {
        let len = frame.len();
        let reserved = self
            .queued_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
                current
                    .checked_add(len)
                    .filter(|next| *next <= MAX_RELAY_QUEUE_BYTES)
            })
            .is_ok();
        if !reserved {
            return Err(());
        }
        struct Reservation<'a> {
            counter: &'a AtomicUsize,
            len: usize,
            armed: bool,
        }
        impl Drop for Reservation<'_> {
            fn drop(&mut self) {
                if self.armed {
                    self.counter.fetch_sub(self.len, Ordering::AcqRel);
                }
            }
        }
        let mut reservation = Reservation {
            counter: &self.queued_bytes,
            len,
            armed: true,
        };
        // Bounded await, not `try_send`. The byte reservation above only binds
        // for frames averaging 4 KiB or more; below that the channel's 64-frame
        // capacity fills first, so `try_send` reported Full with most of the
        // byte budget free. Every caller treats an error as fatal and tears the
        // relay down, which turned ordinary backpressure — a peer sitting in a
        // send for up to RELAY_FORWARD_TIMEOUT — into a dropped session. The
        // timeout still keeps the goal this replaced `send().await` for: no
        // relay task parks in a forwarding await indefinitely.
        match tokio::time::timeout(RELAY_FORWARD_TIMEOUT, self.sender.send(frame)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => return Err(()),
        }
        reservation.armed = false;
        Ok(())
    }
}

impl RelayQueueReceiver {
    async fn recv(&mut self) -> Option<Vec<u8>> {
        let frame = self.receiver.recv().await?;
        self.queued_bytes.fetch_sub(frame.len(), Ordering::AcqRel);
        Some(frame)
    }
}

fn relay_queue() -> (RelayQueueSender, RelayQueueReceiver) {
    let (sender, receiver) = tokio::sync::mpsc::channel(64);
    let queued_bytes = Arc::new(AtomicUsize::new(0));
    (
        RelayQueueSender {
            sender,
            queued_bytes: queued_bytes.clone(),
        },
        RelayQueueReceiver {
            receiver,
            queued_bytes,
        },
    )
}

type RelayPeerChannel = (RelayQueueSender, Arc<AtomicUsize>);

struct RelaySessionEntry {
    peer1_inbox_tx: Option<RelayQueueSender>,
    peer2_announce_tx: Option<tokio::sync::oneshot::Sender<RelayPeerChannel>>,
    deadline: Instant,
}

struct BridgedRelayEntry {
    deadline: Instant,
}

/// A server-relay ticket never retains either raw bearer token. The matching
/// client receives exactly one role token over its authenticated HTTPS
/// request; later WebSocket admission hashes the presented value and compares
/// only that digest.
struct RelayTicket {
    initiator_id: String,
    responder_id: String,
    capability: [u8; 32],
    epoch: i64,
    mailbox_envelope: Vec<u8>,
    initiator_token_hash: [u8; 32],
    responder_token_hash: [u8; 32],
    initiator_joined: bool,
    responder_joined: bool,
    initiator_reservation: Option<u64>,
    responder_reservation: Option<u64>,
    accepted: bool,
    expires_at: Instant,
}

/// Ticket state and its admission indexes are mutated atomically under one
/// lock. Mailbox polling walks only the authenticated responder's bounded
/// per-initiator index.
#[derive(Default)]
struct RelayTicketStore {
    tickets: HashMap<String, RelayTicket>,
    by_responder: HashMap<String, BTreeMap<String, String>>,
    /// Pending (unaccepted) offers only — mailbox rotation never scans accepted slots.
    pending_by_responder: HashMap<String, BTreeMap<String, String>>,
    mailbox_cursors: HashMap<String, String>,
    /// Last page served for an idempotent poll `(nonce, ts)`. Retries with the
    /// same read credentials must observe the same offers without advancing the
    /// round-robin cursor again.
    mailbox_page_cache: HashMap<String, MailboxServedPage>,
    initiator_counts: HashMap<String, usize>,
    accepted_responder_counts: HashMap<String, usize>,
    expirations: VecDeque<(Instant, String)>,
}

struct MailboxServedPage {
    nonce: [u8; 16],
    ts: i64,
    ticket_ids: Vec<String>,
    expires_at: Instant,
}

fn select_mailbox_candidate(
    tickets: &HashMap<String, RelayTicket>,
    initiator: &str,
    ticket_id: &String,
    now: Instant,
    scanned: &mut usize,
    last_scanned: &mut Option<String>,
    selected: &mut Vec<String>,
) -> bool {
    if *scanned >= MAX_RELAY_MAILBOX_SCAN_PER_POLL || selected.len() >= MAX_RELAY_MAILBOX_RESULTS {
        return false;
    }
    *scanned += 1;
    *last_scanned = Some(initiator.to_owned());
    if tickets
        .get(ticket_id)
        .is_some_and(|ticket| !ticket.accepted && ticket.expires_at > now)
    {
        selected.push(ticket_id.clone());
    }
    true
}

impl RelayTicketStore {
    fn insert(&mut self, ticket_id: String, ticket: RelayTicket) {
        self.by_responder
            .entry(ticket.responder_id.clone())
            .or_default()
            .insert(ticket.initiator_id.clone(), ticket_id.clone());
        if !ticket.accepted {
            self.pending_by_responder
                .entry(ticket.responder_id.clone())
                .or_default()
                .insert(ticket.initiator_id.clone(), ticket_id.clone());
        }
        *self
            .initiator_counts
            .entry(ticket.initiator_id.clone())
            .or_insert(0) += 1;
        if ticket.accepted {
            *self
                .accepted_responder_counts
                .entry(ticket.responder_id.clone())
                .or_insert(0) += 1;
        }
        self.expirations
            .push_back((ticket.expires_at, ticket_id.clone()));
        self.tickets.insert(ticket_id, ticket);
    }

    fn remove(&mut self, ticket_id: &str) -> Option<RelayTicket> {
        let ticket = self.tickets.remove(ticket_id)?;
        if let Some(by_initiator) = self.by_responder.get_mut(&ticket.responder_id) {
            if by_initiator
                .get(&ticket.initiator_id)
                .is_some_and(|id| id == ticket_id)
            {
                by_initiator.remove(&ticket.initiator_id);
            }
            if by_initiator.is_empty() {
                self.by_responder.remove(&ticket.responder_id);
                self.mailbox_cursors.remove(&ticket.responder_id);
            }
        }
        if let Some(pending) = self.pending_by_responder.get_mut(&ticket.responder_id) {
            if pending
                .get(&ticket.initiator_id)
                .is_some_and(|id| id == ticket_id)
            {
                pending.remove(&ticket.initiator_id);
            }
            if pending.is_empty() {
                self.pending_by_responder.remove(&ticket.responder_id);
            }
        }
        if let Some(count) = self.initiator_counts.get_mut(&ticket.initiator_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.initiator_counts.remove(&ticket.initiator_id);
            }
        }
        if ticket.accepted {
            if let Some(count) = self.accepted_responder_counts.get_mut(&ticket.responder_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.accepted_responder_counts.remove(&ticket.responder_id);
                }
            }
        }
        Some(ticket)
    }

    fn prune_expired(&mut self, now: Instant) {
        while self
            .expirations
            .front()
            .is_some_and(|(expires_at, _)| *expires_at <= now)
        {
            let (_, ticket_id) = self
                .expirations
                .pop_front()
                .expect("front was checked above");
            let Some(ticket) = self.tickets.get(&ticket_id) else {
                continue;
            };
            if ticket.expires_at > now {
                continue;
            }
            if ticket.initiator_reservation.is_some() || ticket.responder_reservation.is_some() {
                // A pre-upgrade capacity reservation is outstanding. Removing
                // the ticket now would strand its `relay_network_counts` increment
                // forever, because `rollback_relay_ticket_reservation` bails
                // out when the ticket is gone and never decrements the count.
                // Retain the ticket until the reservation watchdog window has
                // passed (commit or rollback clears the reservation within
                // `RELAY_UPGRADE_RESERVATION_TIMEOUT`), then let a later
                // sweep remove it.
                self.expirations
                    .push_back((now + RELAY_UPGRADE_RESERVATION_TIMEOUT, ticket_id));
                continue;
            }
            self.remove(&ticket_id);
        }
    }

    fn mark_accepted(&mut self, ticket_id: &str) -> bool {
        let Some(ticket) = self.tickets.get_mut(ticket_id) else {
            return false;
        };
        if ticket.accepted {
            return false;
        }
        ticket.accepted = true;
        let responder_id = ticket.responder_id.clone();
        let initiator_id = ticket.initiator_id.clone();
        *self
            .accepted_responder_counts
            .entry(responder_id.clone())
            .or_insert(0) += 1;
        if let Some(pending) = self.pending_by_responder.get_mut(&responder_id) {
            pending.remove(&initiator_id);
            if pending.is_empty() {
                self.pending_by_responder.remove(&responder_id);
            }
        }
        true
    }

    fn mailbox_page_ids(&mut self, responder_id: &str, now: Instant) -> Vec<String> {
        self.mailbox_page_ids_inner(responder_id, now, true)
    }

    /// Select a mailbox page without advancing the round-robin cursor. Used for
    /// idempotent retries after a process restart dropped the served-page cache.
    fn mailbox_peek_page_ids(&self, responder_id: &str, now: Instant) -> Vec<String> {
        // Reborrow as mutable via interior selection that does not write cursors.
        // Implemented by duplicating the scan with a local-only last_scanned.
        let Some(by_initiator) = self.pending_by_responder.get(responder_id) else {
            return Vec::new();
        };
        let cursor = self.mailbox_cursors.get(responder_id).cloned();
        let mut selected = Vec::with_capacity(MAX_RELAY_MAILBOX_RESULTS);
        let mut last_scanned = None;
        let mut scanned = 0usize;

        if let Some(cursor) = cursor {
            use std::ops::Bound::{Excluded, Included, Unbounded};
            for (initiator, ticket_id) in by_initiator.range((Excluded(cursor.clone()), Unbounded))
            {
                if !select_mailbox_candidate(
                    &self.tickets,
                    initiator,
                    ticket_id,
                    now,
                    &mut scanned,
                    &mut last_scanned,
                    &mut selected,
                ) {
                    break;
                }
            }
            if scanned < MAX_RELAY_MAILBOX_SCAN_PER_POLL
                && selected.len() < MAX_RELAY_MAILBOX_RESULTS
            {
                for (initiator, ticket_id) in by_initiator.range((Unbounded, Included(cursor))) {
                    if !select_mailbox_candidate(
                        &self.tickets,
                        initiator,
                        ticket_id,
                        now,
                        &mut scanned,
                        &mut last_scanned,
                        &mut selected,
                    ) {
                        break;
                    }
                }
            }
        } else {
            for (initiator, ticket_id) in by_initiator {
                if !select_mailbox_candidate(
                    &self.tickets,
                    initiator,
                    ticket_id,
                    now,
                    &mut scanned,
                    &mut last_scanned,
                    &mut selected,
                ) {
                    break;
                }
            }
        }
        let _ = last_scanned;
        selected
    }

    fn mailbox_page_ids_inner(
        &mut self,
        responder_id: &str,
        now: Instant,
        advance_cursor: bool,
    ) -> Vec<String> {
        let Some(by_initiator) = self.pending_by_responder.get(responder_id) else {
            self.mailbox_cursors.remove(responder_id);
            self.mailbox_page_cache.remove(responder_id);
            return Vec::new();
        };
        let cursor = self.mailbox_cursors.get(responder_id).cloned();
        let mut selected = Vec::with_capacity(MAX_RELAY_MAILBOX_RESULTS);
        let mut last_scanned = None;
        let mut scanned = 0usize;

        if let Some(cursor) = cursor {
            use std::ops::Bound::{Excluded, Included, Unbounded};
            for (initiator, ticket_id) in by_initiator.range((Excluded(cursor.clone()), Unbounded))
            {
                if !select_mailbox_candidate(
                    &self.tickets,
                    initiator,
                    ticket_id,
                    now,
                    &mut scanned,
                    &mut last_scanned,
                    &mut selected,
                ) {
                    break;
                }
            }
            if scanned < MAX_RELAY_MAILBOX_SCAN_PER_POLL
                && selected.len() < MAX_RELAY_MAILBOX_RESULTS
            {
                for (initiator, ticket_id) in by_initiator.range((Unbounded, Included(cursor))) {
                    if !select_mailbox_candidate(
                        &self.tickets,
                        initiator,
                        ticket_id,
                        now,
                        &mut scanned,
                        &mut last_scanned,
                        &mut selected,
                    ) {
                        break;
                    }
                }
            }
        } else {
            for (initiator, ticket_id) in by_initiator {
                if !select_mailbox_candidate(
                    &self.tickets,
                    initiator,
                    ticket_id,
                    now,
                    &mut scanned,
                    &mut last_scanned,
                    &mut selected,
                ) {
                    break;
                }
            }
        }

        if advance_cursor {
            if let Some(last_scanned) = last_scanned {
                self.mailbox_cursors
                    .insert(responder_id.to_owned(), last_scanned);
            }
        }
        selected
    }

    fn store_mailbox_page(
        &mut self,
        responder_id: &str,
        nonce: [u8; 16],
        ts: i64,
        ticket_ids: Vec<String>,
        now: Instant,
    ) {
        // An empty page has nothing to replay-protect, and caching one is what made
        // this map grow with every identity that ever polled: `mailbox_page_ids_inner`
        // removes the entry for a responder with no pending offers, and the caller
        // re-inserted it on the very next line, so the removal never stuck.
        if ticket_ids.is_empty() {
            self.mailbox_page_cache.remove(responder_id);
            return;
        }
        // Entries carry `expires_at` but nothing swept them — `RelayTicketStore::remove`,
        // `prune_expired` and the sweep task all leave this map alone — so its size was
        // the number of distinct identities seen over the process lifetime, unbounded
        // and cheap to drive with register+poll pairs on fresh keypairs. Prune on
        // insert and cap, evicting the soonest-to-expire so a legitimate poller is
        // never refused a cache slot.
        if self.mailbox_page_cache.len() >= MAX_MAILBOX_PAGE_CACHE {
            self.mailbox_page_cache
                .retain(|_, page| page.expires_at > now);
            while self.mailbox_page_cache.len() >= MAX_MAILBOX_PAGE_CACHE {
                let Some(soonest) = self
                    .mailbox_page_cache
                    .iter()
                    .min_by_key(|(_, page)| page.expires_at)
                    .map(|(id, _)| id.clone())
                else {
                    break;
                };
                self.mailbox_page_cache.remove(&soonest);
            }
        }
        self.mailbox_page_cache.insert(
            responder_id.to_owned(),
            MailboxServedPage {
                nonce,
                ts,
                ticket_ids,
                expires_at: now + POLL_READ_NONCE_TTL,
            },
        );
    }

    fn cached_mailbox_page(
        &mut self,
        responder_id: &str,
        nonce: &[u8; 16],
        ts: i64,
        now: Instant,
    ) -> Option<Vec<String>> {
        let stale = self
            .mailbox_page_cache
            .get(responder_id)
            .is_some_and(|entry| entry.expires_at <= now);
        if stale {
            self.mailbox_page_cache.remove(responder_id);
        }
        let entry = self.mailbox_page_cache.get(responder_id)?;
        if entry.nonce == *nonce && entry.ts == ts {
            Some(entry.ticket_ids.clone())
        } else {
            None
        }
    }
}

/// Whether `ts` is below the freshness window at `now`.
fn lapsed_at(ts: i64, now: i64) -> bool {
    ts < now.saturating_sub(MAX_TIMESTAMP_SKEW_SECS)
}

/// The replay guard's clock.
///
/// Client timestamps are checked against `wall`, so a server whose clock was
/// wrong and then corrected accepts correctly timed requests again. What a
/// backward step must not do is re-admit a request whose protection was
/// already dropped; the guard refuses everything at or below the newest
/// timestamp it ever dropped for that (see `ReplayGuard::dropped_through`).
/// Dropping itself runs at [`Self::prune_clock`]: never ahead of the wall
/// clock, so after a backward step nothing more is dropped until wall time
/// catches up, and never ahead of monotonic time since startup (`lapse`), so
/// a forward jump that is later undone drops nothing early either.
#[derive(Clone, Copy, Debug)]
struct ReplayNow {
    lapse: i64,
    wall: i64,
}

impl ReplayNow {
    fn from_parts(start_wall: i64, elapsed_secs: i64, wall: i64) -> Self {
        Self {
            lapse: start_wall.saturating_add(elapsed_secs),
            wall,
        }
    }

    fn prune_clock(&self) -> i64 {
        self.lapse.min(self.wall)
    }

    fn current() -> Self {
        static START: OnceLock<(i64, Instant)> = OnceLock::new();
        let (start_wall, started) = *START.get_or_init(|| (now_unix_secs(), Instant::now()));
        let elapsed = i64::try_from(started.elapsed().as_secs()).unwrap_or(i64::MAX);
        Self::from_parts(start_wall, elapsed, now_unix_secs())
    }

    #[cfg(test)]
    fn at(now: i64) -> Self {
        Self {
            lapse: now,
            wall: now,
        }
    }
}

#[derive(Clone, Copy)]
struct ReplayMark {
    scope: u64,
    ts: i64,
    digest: u128,
}

struct KeyReplayState {
    /// Every request signed by this key with `ts < floor` is refused.
    floor: i64,
    /// Upper bound on every timestamp this state protects (`floor - 1` and
    /// each mark's `ts`). Never decreases.
    horizon: i64,
    /// Per scope, the requests seen at that scope's newest timestamp, in
    /// arrival order. A scope's older requests need no mark: they are below
    /// its newest timestamp and refused for that.
    marks: Vec<ReplayMark>,
}

/// Replay protection keyed by signing key.
///
/// Each signed operation names a scope (the operation, plus its target where
/// the operation has one). Within a scope a key's requests must not go back in
/// time: one older than the scope's newest is refused, and at the newest
/// timestamp each distinct request is accepted once. So a key needs one mark
/// per scope it used in the last few minutes, not one per request, and
/// replaying an older state-setting request cannot roll that state back.
///
/// Bounds, and why none of them reopens a replay:
/// - A mark below the freshness window is dropped: the freshness gate
///   (re-checked here) already refuses everything it protected, and keeps
///   refusing it after a backward clock step through `dropped_through`.
/// - Past [`MAX_REPLAY_MARKS_PER_KEY`], or when the global pool is full, a key
///   gives up its own oldest mark and raises its `floor` above it, which
///   refuses everything that mark protected and more. Only that key pays.
/// - A key's whole state is evicted, oldest `horizon` first, only once the
///   horizon has left the freshness window. A key that is still inside it is
///   never evicted: a new key is refused (`Full`) instead. Idempotent
///   endpoints never create state, so that refusal cannot reach them.
struct ReplayGuard {
    keys: HashMap<[u8; 32], KeyReplayState>,
    by_horizon: BTreeSet<(i64, [u8; 32])>,
    marks: usize,
    max_keys: usize,
    max_marks: usize,
    max_marks_per_key: usize,
    /// Newest timestamp whose protection was dropped (a lapsed mark or an
    /// evicted key's horizon). Every one-time request at or below it is
    /// refused, so a wall clock stepping back cannot make a dropped request
    /// fresh again. Normally below the freshness window and so never binding;
    /// after a backward step it holds such requests back only until wall time
    /// passes it.
    dropped_through: i64,
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::with_limits(MAX_REPLAY_KEYS, MAX_REPLAY_MARKS, MAX_REPLAY_MARKS_PER_KEY)
    }
}

impl ReplayGuard {
    fn with_limits(max_keys: usize, max_marks: usize, max_marks_per_key: usize) -> Self {
        Self {
            keys: HashMap::new(),
            by_horizon: BTreeSet::new(),
            marks: 0,
            max_keys: max_keys.max(1),
            max_marks: max_marks.max(1),
            max_marks_per_key: max_marks_per_key.max(1),
            dropped_through: i64::MIN,
        }
    }

    fn fresh(&self, ts: i64, now: ReplayNow) -> bool {
        fresh_at(ts, now.wall) && ts > self.dropped_through
    }

    /// Evict every key whose horizon has left the freshness window.
    fn prune(&mut self, now: ReplayNow) {
        let clock = now.prune_clock();
        while let Some(&(horizon, key)) = self.by_horizon.first() {
            if !lapsed_at(horizon, clock) {
                break;
            }
            self.by_horizon.pop_first();
            if let Some(state) = self.keys.remove(&key) {
                self.marks -= state.marks.len();
                self.dropped_through = self.dropped_through.max(horizon);
            }
        }
    }

    /// For endpoints that keep no replay state: refuse only what a
    /// state-setting request from this key has already superseded.
    ///
    /// Checked against the wall clock alone, not `dropped_through`: these are
    /// register keep-alives and reads, which a replay can only repeat, and
    /// after a large backward clock step the watermark would refuse every
    /// presence registration on the server until wall time caught up.
    fn check_floor(&self, key: &[u8; 32], ts: i64, now: ReplayNow) -> ReplayAdmission {
        if !fresh_at(ts, now.wall) {
            return ReplayAdmission::Stale;
        }
        match self.keys.get(key) {
            Some(state) if ts < state.floor => ReplayAdmission::Replay,
            _ => ReplayAdmission::Accepted,
        }
    }

    /// Room for one more key, evicting only lapsed ones.
    fn make_room_for_key(&mut self, now: ReplayNow) -> bool {
        self.prune(now);
        self.keys.len() < self.max_keys && self.marks < self.max_marks
    }

    fn state_mut(&mut self, key: [u8; 32], now: ReplayNow) -> Option<&mut KeyReplayState> {
        if !self.keys.contains_key(&key) && !self.make_room_for_key(now) {
            return None;
        }
        Some(self.keys.entry(key).or_insert(KeyReplayState {
            floor: i64::MIN,
            horizon: i64::MIN,
            marks: Vec::new(),
        }))
    }

    fn reindex(&mut self, key: [u8; 32], old_horizon: i64) {
        let Some(state) = self.keys.get_mut(&key) else {
            return;
        };
        let newest = state.marks.iter().map(|mark| mark.ts).max().unwrap_or(i64::MIN);
        state.horizon = state
            .horizon
            .max(newest)
            .max(state.floor.saturating_sub(1));
        if state.horizon != old_horizon || !self.by_horizon.contains(&(old_horizon, key)) {
            self.by_horizon.remove(&(old_horizon, key));
            self.by_horizon.insert((state.horizon, key));
        }
    }

    /// Raise `floor` to `new_floor` and drop the marks it now covers.
    fn raise_floor_of(state: &mut KeyReplayState, new_floor: i64) -> usize {
        state.floor = state.floor.max(new_floor);
        let before = state.marks.len();
        let floor = state.floor;
        state.marks.retain(|mark| mark.ts >= floor);
        before - state.marks.len()
    }

    fn admit(
        &mut self,
        key: [u8; 32],
        scope: u64,
        ts: i64,
        digest: u128,
        mode: ReplayMode,
        now: ReplayNow,
    ) -> ReplayAdmission {
        if !self.fresh(ts, now) {
            return ReplayAdmission::Stale;
        }
        self.prune(now);
        let pool_full = self.marks >= self.max_marks;
        let max_per_key = self.max_marks_per_key;
        let clock = now.prune_clock();
        let Some(state) = self.state_mut(key, now) else {
            return ReplayAdmission::Full;
        };
        let old_horizon = state.horizon;
        let mut released = 0;
        let dropped = state
            .marks
            .iter()
            .filter(|mark| lapsed_at(mark.ts, clock))
            .map(|mark| mark.ts)
            .max();
        let before = state.marks.len();
        state.marks.retain(|mark| !lapsed_at(mark.ts, clock));
        released += before - state.marks.len();

        let outcome = 'decide: {
            if ts < state.floor {
                break 'decide ReplayAdmission::Replay;
            }
            let newest = state
                .marks
                .iter()
                .filter(|mark| mark.scope == scope)
                .map(|mark| mark.ts)
                .max();
            match newest {
                Some(newest) if ts < newest => break 'decide ReplayAdmission::Replay,
                Some(newest) if ts == newest => {
                    let latest = state.marks.iter().rev().find(|mark| mark.scope == scope);
                    if mode == ReplayMode::IdempotentRepeat
                        && latest.is_some_and(|mark| mark.digest == digest)
                    {
                        break 'decide ReplayAdmission::Repeat;
                    }
                    if state
                        .marks
                        .iter()
                        .any(|mark| mark.scope == scope && mark.digest == digest)
                    {
                        break 'decide ReplayAdmission::Replay;
                    }
                }
                Some(_) => {
                    let before = state.marks.len();
                    state.marks.retain(|mark| mark.scope != scope);
                    released += before - state.marks.len();
                }
                None => {}
            }
            let pool_full = pool_full && released == 0;
            if state.marks.len() >= max_per_key || (pool_full && !state.marks.is_empty()) {
                let oldest = state
                    .marks
                    .iter()
                    .map(|mark| mark.ts)
                    .min()
                    .expect("a key at its mark limit holds marks");
                released += Self::raise_floor_of(state, oldest.saturating_add(1));
                if ts < state.floor {
                    break 'decide ReplayAdmission::Replay;
                }
            } else if pool_full {
                break 'decide ReplayAdmission::Full;
            }
            state.marks.push(ReplayMark { scope, ts, digest });
            ReplayAdmission::Accepted
        };
        self.marks -= released;
        if outcome == ReplayAdmission::Accepted {
            self.marks += 1;
        }
        if let Some(dropped) = dropped {
            self.dropped_through = self.dropped_through.max(dropped);
        }
        self.reindex(key, old_horizon);
        outcome
    }

    /// Refuse every earlier request from this key (unregister).
    fn raise_floor(&mut self, key: [u8; 32], ts: i64, now: ReplayNow) -> ReplayAdmission {
        if !self.fresh(ts, now) {
            return ReplayAdmission::Stale;
        }
        self.prune(now);
        let Some(state) = self.state_mut(key, now) else {
            return ReplayAdmission::Full;
        };
        if ts < state.floor {
            return ReplayAdmission::Replay;
        }
        let old_horizon = state.horizon;
        let released = Self::raise_floor_of(state, ts.saturating_add(1));
        self.marks -= released;
        self.reindex(key, old_horizon);
        ReplayAdmission::Accepted
    }
}

/// Minimum spacing between full expiry scans of a presence map that is at
/// [`MAX_STORE_ENTRIES`]. The sweeper does the same scan every
/// [`SWEEP_INTERVAL`]; this only lets a full map recover sooner.
const STORE_PURGE_MIN_INTERVAL: Duration = Duration::from_secs(5);

/// At capacity, every registration for a new id used to run a full `retain`
/// over the map under its write lock, so a flood of new ids at the cap turned
/// each request into a 100k-entry scan.
#[derive(Default)]
struct PurgeThrottle {
    last: std::sync::Mutex<Option<Instant>>,
}

impl PurgeThrottle {
    /// Whether the caller may run a full purge now; if so, it is recorded.
    fn try_begin(&self, now: Instant) -> bool {
        let mut last = self.last.lock().unwrap_or_else(|poison| poison.into_inner());
        if last.is_some_and(|at| now.saturating_duration_since(at) < STORE_PURGE_MIN_INTERVAL) {
            return false;
        }
        *last = Some(now);
        true
    }
}

/// Pending punch requests indexed by target, so a register, poll or ack
/// touches only its target's (at most [`MAX_PUNCH_PER_TARGET`]) entries, and
/// expiry costs only what expired.
#[derive(Default)]
struct PunchStore {
    by_target: HashMap<String, HashMap<String, PunchEntry>>,
    len: usize,
    /// `(expires_at, target, from)` in insertion order. An item whose entry
    /// was replaced or acked since is skipped when it comes up.
    expirations: VecDeque<(Instant, String, String)>,
}

impl PunchStore {
    fn len(&self) -> usize {
        self.len
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn contains(&self, target: &str, from: &str) -> bool {
        self.by_target
            .get(target)
            .is_some_and(|entries| entries.contains_key(from))
    }

    fn target_len(&self, target: &str) -> usize {
        self.by_target.get(target).map_or(0, HashMap::len)
    }

    fn remove(&mut self, target: &str, from: &str) -> Option<PunchEntry> {
        let entries = self.by_target.get_mut(target)?;
        let removed = entries.remove(from)?;
        if entries.is_empty() {
            self.by_target.remove(target);
        }
        self.len -= 1;
        Some(removed)
    }

    fn insert(&mut self, target: String, from: String, entry: PunchEntry) {
        self.expirations
            .push_back((entry.created_at + PUNCH_TTL, target.clone(), from.clone()));
        if self
            .by_target
            .entry(target)
            .or_default()
            .insert(from, entry)
            .is_none()
        {
            self.len += 1;
        }
    }

    fn prune_expired(&mut self, now: Instant) -> usize {
        let mut removed = 0;
        while self
            .expirations
            .front()
            .is_some_and(|(expires_at, _, _)| *expires_at <= now)
        {
            let (_, target, from) = self
                .expirations
                .pop_front()
                .expect("front was checked above");
            let expired = self
                .by_target
                .get(&target)
                .and_then(|entries| entries.get(&from))
                .is_some_and(|entry| !punch_live(entry, now));
            if expired && self.remove(&target, &from).is_some() {
                removed += 1;
            }
        }
        removed
    }

    /// Lease the oldest entry for `target` that `version` may observe: an
    /// unleased one if any, else (an idempotent re-poll mid-handshake) the
    /// oldest leased one.
    fn lease_next(
        &mut self,
        target: &str,
        version: RendezvousVersion,
        now: Instant,
    ) -> Option<&PunchEntry> {
        let entries = self.by_target.get_mut(target)?;
        // v4 clients must only observe IP-bound registrations. Serving a
        // legacy entry on /v4/punch/poll would force the desktop to either
        // fail open (previous bug) or 404 mid-handshake.
        let visible = |entry: &PunchEntry| {
            punch_live(entry, now)
                && (version == RendezvousVersion::LegacyV3
                    || entry.proof_version == RendezvousVersion::IpBoundV4)
        };
        let from = entries
            .iter()
            .filter(|(_, entry)| visible(entry) && punch_available(entry, now))
            .min_by_key(|(_, entry)| entry.created_at)
            .or_else(|| {
                entries
                    .iter()
                    .filter(|(_, entry)| visible(entry))
                    .min_by_key(|(_, entry)| entry.created_at)
            })
            .map(|(from, _)| from.clone())?;
        let entry = entries.get_mut(&from)?;
        entry.leased_until = Some(now + PUNCH_LEASE);
        Some(entry)
    }

    fn remove_acked(
        &mut self,
        target: &str,
        punch_id: &str,
        capability: &[u8; 32],
        epoch: i64,
    ) -> bool {
        let from = self.by_target.get(target).and_then(|entries| {
            entries
                .iter()
                .find(|(_, entry)| {
                    entry.punch_id.eq_ignore_ascii_case(punch_id)
                        && entry.capability == *capability
                        && entry.epoch == epoch
                })
                .map(|(from, _)| from.clone())
        });
        from.is_some_and(|from| self.remove(target, &from).is_some())
    }
}

/// The scope of a status read: one `(initiator, ticket)` pair.
type StatusReadScope = ([u8; 32], [u8; 32]);

/// Bounded, scope-keyed nonce cache with O(expired) pruning. `K` is either
/// one responder identity (poll) or one `(initiator, ticket)` pair (status).
struct ScopedNonceCache<K> {
    entries: HashMap<K, IdempotentReadNonce>,
    expirations: VecDeque<(Instant, K)>,
}

impl<K: Eq + Hash + Copy> ScopedNonceCache<K> {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            expirations: VecDeque::new(),
        }
    }

    fn prune_expired(&mut self, now: Instant) {
        while self
            .expirations
            .front()
            .is_some_and(|(expires_at, _)| *expires_at <= now)
        {
            let (_, key) = self
                .expirations
                .pop_front()
                .expect("front was checked above");
            if self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.expires_at <= now)
            {
                self.entries.remove(&key);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum RelayRole {
    Initiator,
    Responder,
}

#[derive(Clone)]
struct RelayReservation {
    ticket_id: String,
    role: RelayRole,
    client_ip: IpAddr,
    id: u64,
}

#[derive(Clone)]
struct AppState {
    store: Arc<RwLock<HashMap<String, PresenceEntry>>>,
    /// Public reachability is indexed only by rotating pairwise capability,
    /// never by the stable Friend ID kept in `store` for mailbox auth.
    capability_store: Arc<RwLock<HashMap<String, PairwisePresenceEntry>>>,
    /// Rate-limit window for the **general** API surface
    /// (`register`, `lookup`, `unregister`, `relay-invite`, etc.). Every
    /// bucket here is keyed by [`rate_key`].
    /// Punch traffic now lives in `punch_rate_limits` so a flood of
    /// punch registrations no longer steals the budget from unrelated
    /// endpoints — earlier this map was shared, and a single LowID
    /// peer's punch retries could 429 lookup/register for the same IP.
    rate_limits: RateLimitBucket,
    /// Temporary unauthenticated v3 identity oracle budget. It must not share
    /// counters with authenticated registration/lookup traffic: otherwise a
    /// normal rollout registration burst can consume the tighter legacy cap
    /// before an old client performs its first identity lookup.
    legacy_identity_rate_limits: RateLimitBucket,
    /// Separate per-IP budget for authenticated relay ticket poll/status
    /// reads. This prevents normal fallback traffic from consuming punch or
    /// general API capacity.
    ticket_read_rate_limits: RateLimitBucket,
    /// Per-IP rate-limit window for hole-punch register traffic.
    /// Counted separately from `rate_limits` so the documented
    /// `MAX_PUNCH_PER_MINUTE` budget is the only thing throttling
    /// punch attempts.
    punch_rate_limits: RateLimitBucket,
    /// Per-*hour* budget for first-time channel name claims. Separate
    /// map because it is the only bucket measured over an hour rather than a
    /// minute; sharing one would either let a minute's worth of room creation
    /// through unchecked or throttle ordinary traffic to a creation rate.
    channel_create_rate_limits: RateLimitBucket,
    /// The pooled tier of the same budget, keyed by [`client_network`]. Its
    /// own map because a /24 key would collide with the exact address that
    /// ends in `.0` in the per-address tier.
    channel_create_network_rate_limits: RateLimitBucket,
    /// Pending hole-punch registrations, keyed by `(target_id, from_id)`.
    /// Keying by both IDs (rather than just `target_id`) prevents an
    /// unauthenticated attacker from overwriting a legit registrant's
    /// slot for a given victim — the worst they can do now is fill an
    /// extra slot under their own attacker-controlled `from_id`, which
    /// the per-target cap below bounds.
    punch_requests: Arc<RwLock<PunchStore>>,
    relay_sessions: Arc<RwLock<HashMap<String, RelaySessionEntry>>>,
    bridged_relays: Arc<RwLock<HashMap<String, BridgedRelayEntry>>>,
    relay_admissions: Arc<RwLock<HashMap<(String, RelayRole), IpAddr>>>,
    /// Joined or reserved relay sockets, keyed by [`client_network`].
    relay_network_counts: Arc<RwLock<HashMap<IpAddr, usize>>>,
    next_relay_reservation_id: Arc<AtomicU64>,
    relay_tickets: Arc<RwLock<RelayTicketStore>>,
    /// Process-lifetime secret used to issue role tokens on demand. Ticket
    /// records retain only SHA-256 token hashes; rotating this key on restart
    /// invalidates every outstanding short-lived ticket.
    relay_token_key: [u8; 32],
    /// Per-signing-key replay protection for signed requests inside the
    /// timestamp skew window. Ticket reads use the scope-bounded caches below.
    replay_guard: Arc<RwLock<ReplayGuard>>,
    /// Throttles the full expiry scan a registration runs when `store` or
    /// `capability_store` is at [`MAX_STORE_ENTRIES`].
    store_purge: Arc<PurgeThrottle>,
    capability_purge: Arc<PurgeThrottle>,
    /// One stable poll nonce per live responder identity. Replays are
    /// idempotent reads, while a different nonce for the same identity is
    /// rejected until the entry expires.
    poll_read_nonces: Arc<RwLock<ScopedNonceCache<[u8; 32]>>>,
    /// One stable status nonce per `(initiator, ticket)` pair. Keeping this
    /// separate bounds rapid initiator status checks without weakening the
    /// one-time mutation cache used by offer/accept.
    status_read_nonces: Arc<RwLock<ScopedNonceCache<StatusReadScope>>>,
    started_at: Instant,
    /// Unique Channel usernames and room names. Persistence is a JSON file
    /// when `CHANNELS_REGISTRY_PATH` is set; otherwise names live only in
    /// this process and vanish on restart.
    channels_registry: Arc<RwLock<registry::ChannelRegistry>>,
    registry_persister: Arc<RegistryPersister>,
}

#[derive(Deserialize)]
struct RegisterRequest {
    id: String,
    port: u16,
    /// Routable public IP the client wants registered as its
    /// presence address. Required (we removed the `client_ip`
    /// fallback so VPN / split-tunnel users aren't pinned to the
    /// wrong egress) — the request handler returns `BAD_REQUEST`
    /// when this is missing, unparseable, or non-routable. Kept
    /// `Option` purely so older clients (which omit the field) get a
    /// crisp 400 from the handler instead of a serde reject before
    /// we can log it.
    ip: Option<String>,
    /// Ed25519 pubkey (64 hex chars). Required: server pins on first
    /// register, then refuses any later /register that doesn't match.
    pubkey: String,
    /// Unix-seconds timestamp of the request. Replays >5min stale are
    /// rejected; without this, an attacker could capture a registration
    /// off the wire and re-post it indefinitely.
    ts: i64,
    /// Hex-encoded Ed25519 signature over
    /// `RDV_DOMAIN || OP_REGISTER || sha256_id_raw || port_le || ipv4 || pubkey || ts_le`.
    sig: String,
}

#[derive(Serialize)]
struct IdentityResponse {
    pubkey: String,
}

#[derive(Deserialize)]
struct CapabilityRegisterRequest {
    capability: String,
    epoch: i64,
    port: u16,
    ip: String,
    pubkey: String,
    peer_pubkey: String,
    ts: i64,
    sig: String,
    /// Friend-code intro presence: open ACL for any registered requester.
    /// Requires `peer_pubkey == pubkey` (self-bound).
    #[serde(default)]
    intro: bool,
    /// During v4 rollout the client includes the exact v3 registration proof
    /// in the same request. The server verifies and stores both under one
    /// logical/rate-limited admission, avoiding a second mutation request.
    #[serde(default)]
    legacy_sig: Option<String>,
    /// Per-epoch key proving a sealed (`ember3:`) intro capability belongs to
    /// `pubkey`. Absent on legacy intro registrations; refused without `intro`.
    #[serde(default)]
    intro_key: Option<String>,
}

#[derive(Deserialize)]
struct CapabilityLookupRequest {
    capability: String,
    epoch: i64,
    requester_id: String,
    requester_pubkey: String,
    nonce: String,
    ts: i64,
    sig: String,
}

#[derive(Serialize)]
struct CapabilityLookupResponse {
    acknowledged: bool,
    capability: String,
    epoch: i64,
    ip: String,
    port: u16,
    pubkey: String,
    ts: i64,
    sig: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_version: Option<u8>,
}

#[derive(Deserialize)]
struct UnregisterRequest {
    id: String,
    ts: i64,
    /// Signature over `RDV_DOMAIN || OP_UNREGISTER || sha256_id_raw || ts_le`.
    sig: String,
}

#[derive(Deserialize)]
struct RelayMailboxOfferRequest {
    initiator_id: String,
    responder_id: String,
    capability: String,
    epoch: i64,
    ticket_id: String,
    envelope: String,
    ts: i64,
    nonce: String,
    sig: String,
}

#[derive(Deserialize)]
struct RelayMailboxPollRequest {
    responder_id: String,
    ts: i64,
    nonce: String,
    sig: String,
}

#[derive(Deserialize)]
struct RelayTicketIdentityRequest {
    identity_id: String,
    ts: i64,
    nonce: String,
    sig: String,
}

#[derive(Serialize)]
struct RelayTicketOfferResponse {
    ticket_id: String,
    initiator_token: String,
    expires_in_secs: u64,
}

#[derive(Serialize)]
struct RelayMailboxPollItem {
    ticket_id: String,
    capability: String,
    epoch: i64,
    envelope: String,
}

#[derive(Serialize)]
struct RelayMailboxPollResponse {
    tickets: Vec<RelayMailboxPollItem>,
}

#[derive(Serialize)]
struct RelayTicketAcceptResponse {
    responder_token: String,
    expires_in_secs: u64,
}

#[derive(Serialize)]
struct RelayTicketStatusResponse {
    status: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxyMode {
    Disabled,
    Fly,
}

#[derive(Clone, Copy, Debug)]
struct TrustedProxyNet {
    network: IpAddr,
    prefix_len: u8,
}

impl TrustedProxyNet {
    fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        let (ip, prefix_len) = match value.split_once('/') {
            Some((ip, prefix)) => {
                let ip = ip.parse::<IpAddr>().ok()?;
                let prefix_len = prefix.parse::<u8>().ok()?;
                (ip, prefix_len)
            }
            None => {
                let ip = value.parse::<IpAddr>().ok()?;
                let prefix_len = if ip.is_ipv4() { 32 } else { 128 };
                (ip, prefix_len)
            }
        };
        if (ip.is_ipv4() && prefix_len > 32) || (ip.is_ipv6() && prefix_len > 128) {
            return None;
        }
        Some(Self {
            network: ip,
            prefix_len,
        })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                u32::from(network) & mask == u32::from(candidate) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix_len)
                };
                u128::from(network) & mask == u128::from(candidate) & mask
            }
            _ => false,
        }
    }
}

#[derive(Debug)]
struct ProxyConfig {
    mode: ProxyMode,
    trusted_hops: Vec<TrustedProxyNet>,
}

impl ProxyConfig {
    fn from_env() -> Self {
        // Deliberately require a named mode. Historically any TRUST_PROXY
        // value other than "false"/"0" trusted Fly-Client-IP from every
        // directly connected client, so typos such as "flase" silently
        // enabled spoofing. Only the exact, documented Fly mode enables the
        // Fly-specific header.
        let mode = match std::env::var("TRUST_PROXY") {
            Ok(value) if value.trim().eq_ignore_ascii_case("fly") => ProxyMode::Fly,
            _ => ProxyMode::Disabled,
        };
        let trusted_hops = std::env::var("TRUSTED_PROXY_HOPS")
            .unwrap_or_default()
            .split(',')
            .filter_map(|value| {
                let value = value.trim();
                if value.is_empty() {
                    return None;
                }
                match TrustedProxyNet::parse(value) {
                    Some(network) => Some(network),
                    None => {
                        warn!("ignoring invalid TRUSTED_PROXY_HOPS entry");
                        None
                    }
                }
            })
            .collect();
        Self { mode, trusted_hops }
    }

    fn trusts_hop(&self, ip: IpAddr) -> bool {
        self.trusted_hops.iter().any(|network| network.contains(ip))
    }

    /// Whether a connection from `peer` names its real client in
    /// `Fly-Client-IP`, so the client is unknown until request headers arrive.
    fn forwards_client_ip(&self, peer: IpAddr) -> bool {
        self.mode == ProxyMode::Fly && self.trusts_hop(peer)
    }
}

fn proxy_config() -> &'static ProxyConfig {
    static CONFIG: OnceLock<ProxyConfig> = OnceLock::new();
    CONFIG.get_or_init(ProxyConfig::from_env)
}

fn extract_client_ip_with_config(
    config: &ProxyConfig,
    headers: &HeaderMap,
    addr: SocketAddr,
) -> IpAddr {
    // A forwarded address has authority only when both controls agree:
    // deployment explicitly selected Fly mode, and the immediate TCP peer is
    // in the operator-configured proxy allowlist. This prevents a public
    // client from supplying Fly-Client-IP directly to evade rate/session caps.
    if config.forwards_client_ip(addr.ip()) {
        if let Some(val) = headers.get("fly-client-ip") {
            if let Ok(s) = val.to_str() {
                if let Ok(ip) = s.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    addr.ip()
}

fn extract_client_ip(headers: &HeaderMap, addr: SocketAddr) -> IpAddr {
    extract_client_ip_with_config(proxy_config(), headers, addr)
}

async fn check_rate_limit_bucket_in(
    limits: &RateLimitBucket,
    ip: IpAddr,
    max_requests: u64,
    window: Duration,
) -> bool {
    limits.write().await.charge(
        rate_key(ip),
        max_requests,
        window,
        Instant::now(),
        MAX_RATE_ENTRIES,
    )
}

async fn check_rate_limit_bucket(
    limits: &RateLimitBucket,
    ip: IpAddr,
    max_requests: u64,
) -> bool {
    check_rate_limit_bucket_in(limits, ip, max_requests, RATE_WINDOW).await
}

async fn check_rate_limit(state: &AppState, ip: IpAddr) -> bool {
    check_rate_limit_bucket(&state.rate_limits, ip, MAX_REQUESTS_PER_MINUTE).await
}

/// Read-only counterpart of [`check_rate_limit_bucket`]: whether `ip` has
/// already spent this window's budget. Never charges the bucket.
async fn rate_budget_exhausted(limits: &RateLimitBucket, ip: IpAddr, max_requests: u64) -> bool {
    limits
        .read()
        .await
        .exhausted(rate_key(ip), max_requests, RATE_WINDOW, Instant::now())
}

/// Which bucket a JSON route's handler charges, so the pre-body gate peeks at
/// the same one.
#[derive(Clone, Copy)]
enum BodyRateGate {
    General,
    TicketRead,
    Punch,
}

/// Handlers charge their bucket only after the `Json` extractor has read the
/// body, which a slow sender can stretch to `HTTP_REQUEST_TIMEOUT`. An address
/// that is already over budget is refused before that read. Charging stays in
/// the handlers, so malformed requests still cost nothing.
async fn reject_exhausted_rate_budget(
    State((state, gate)): State<(AppState, BodyRateGate)>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let client_ip = extract_client_ip(request.headers(), addr);
    let exhausted = match gate {
        BodyRateGate::General => {
            rate_budget_exhausted(&state.rate_limits, client_ip, MAX_REQUESTS_PER_MINUTE).await
        }
        BodyRateGate::TicketRead => {
            rate_budget_exhausted(
                &state.ticket_read_rate_limits,
                client_ip,
                MAX_TICKET_READS_PER_MINUTE,
            )
            .await
        }
        BodyRateGate::Punch => {
            rate_budget_exhausted(
                &state.punch_rate_limits,
                canonical_ip(client_ip),
                MAX_PUNCH_PER_MINUTE,
            )
            .await
        }
    };
    if exhausted {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    next.run(request).await
}

async fn check_ticket_read_rate_limit(state: &AppState, ip: IpAddr) -> bool {
    check_rate_limit_bucket(
        &state.ticket_read_rate_limits,
        ip,
        MAX_TICKET_READS_PER_MINUTE,
    )
    .await
}

/// Budget for standing up a room nobody has claimed before. Charged only once
/// the request has proved itself genuine, so a bad signature cannot spend the
/// allowance of the address it was sent from.
///
/// Two tiers: [`MAX_CHANNEL_CREATES_PER_HOUR`] per [`rate_key`], then
/// [`MAX_CHANNEL_CREATES_PER_NETWORK_PER_HOUR`] per [`client_network`].
async fn check_channel_create_rate_limit(state: &AppState, ip: IpAddr) -> bool {
    // Always taken in this order; nothing else holds both.
    let mut per_address = state.channel_create_rate_limits.write().await;
    let mut per_network = state.channel_create_network_rate_limits.write().await;
    admit_channel_create(&mut per_address, &mut per_network, ip, Instant::now())
}

/// Charges both tiers only when both admit. Charging one tier for a request
/// the other refuses spends budget on nothing: an over-limit address retrying
/// would drain its network's pool, and an address retrying against an
/// exhausted pool would burn its own allowance and stay locked out after the
/// pool recovers.
fn admit_channel_create(
    per_address: &mut RateBucket,
    per_network: &mut RateBucket,
    ip: IpAddr,
    now: Instant,
) -> bool {
    let address_key = rate_key(ip);
    let network_key = rate_key(client_network(ip));
    if per_address.exhausted(address_key, MAX_CHANNEL_CREATES_PER_HOUR, CHANNEL_CREATE_WINDOW, now)
        || per_network.exhausted(
            network_key,
            MAX_CHANNEL_CREATES_PER_NETWORK_PER_HOUR,
            CHANNEL_CREATE_WINDOW,
            now,
        )
    {
        return false;
    }
    let address_ok = per_address.charge(
        address_key,
        MAX_CHANNEL_CREATES_PER_HOUR,
        CHANNEL_CREATE_WINDOW,
        now,
        MAX_RATE_ENTRIES,
    );
    let network_ok = per_network.charge(
        network_key,
        MAX_CHANNEL_CREATES_PER_NETWORK_PER_HOUR,
        CHANNEL_CREATE_WINDOW,
        now,
        MAX_RATE_ENTRIES,
    );
    address_ok && network_ok
}

/// Admit one signed request into its replay scope. See [`ReplayGuard`].
async fn admit_signed_request(
    state: &AppState,
    signer: &[u8; 32],
    scope: u64,
    ts: i64,
    message: &[u8],
    sig: &[u8; 64],
    mode: ReplayMode,
) -> Result<(), StatusCode> {
    let digest = signed_request_digest(message, sig);
    let admission = state.replay_guard.write().await.admit(
        *signer,
        scope,
        ts,
        digest,
        mode,
        ReplayNow::current(),
    );
    replay_status(admission)
}

/// For requests replay can only repeat, not roll back: no state is kept, but
/// anything the signer has since superseded (see [`ReplayGuard::raise_floor`])
/// is refused.
async fn check_replay_floor(state: &AppState, signer: &[u8; 32], ts: i64) -> Result<(), StatusCode> {
    let admission = state
        .replay_guard
        .read()
        .await
        .check_floor(signer, ts, ReplayNow::current());
    replay_status(admission)
}

fn admit_idempotent_read_nonce<K: Eq + Hash + Copy>(
    cache: &mut ScopedNonceCache<K>,
    key: K,
    nonce: [u8; 16],
    ts: i64,
    now: Instant,
    ttl: Duration,
    max_entries: usize,
) -> IdempotentReadAdmission {
    cache.prune_expired(now);
    if let Some(entry) = cache.entries.get_mut(&key) {
        if entry.nonce != nonce {
            return IdempotentReadAdmission::NonceConflict;
        }
        if ts < entry.last_ts {
            return IdempotentReadAdmission::Replay;
        }
        let admission = if ts == entry.last_ts {
            IdempotentReadAdmission::Idempotent
        } else {
            entry.last_ts = ts;
            IdempotentReadAdmission::New
        };
        return admission;
    }
    if cache.entries.len() >= max_entries {
        return IdempotentReadAdmission::Full;
    }
    let expires_at = now + ttl;
    cache.entries.insert(
        key,
        IdempotentReadNonce {
            nonce,
            last_ts: ts,
            expires_at,
        },
    );
    cache.expirations.push_back((expires_at, key));
    IdempotentReadAdmission::New
}

async fn remember_ticket_poll_nonce(
    state: &AppState,
    responder_id: [u8; 32],
    nonce: [u8; 16],
    ts: i64,
) -> IdempotentReadAdmission {
    let mut cache = state.poll_read_nonces.write().await;
    admit_idempotent_read_nonce(
        &mut cache,
        responder_id,
        nonce,
        ts,
        Instant::now(),
        POLL_READ_NONCE_TTL,
        MAX_POLL_READ_NONCES,
    )
}

async fn remember_ticket_status_nonce(
    state: &AppState,
    initiator_id: [u8; 32],
    ticket_id: [u8; 32],
    nonce: [u8; 16],
    ts: i64,
) -> IdempotentReadAdmission {
    let mut cache = state.status_read_nonces.write().await;
    admit_idempotent_read_nonce(
        &mut cache,
        (initiator_id, ticket_id),
        nonce,
        ts,
        Instant::now(),
        STATUS_READ_NONCE_TTL,
        MAX_STATUS_READ_NONCES,
    )
}

fn replay_status(admission: ReplayAdmission) -> Result<(), StatusCode> {
    match admission {
        ReplayAdmission::Accepted | ReplayAdmission::Repeat => Ok(()),
        ReplayAdmission::Replay => Err(StatusCode::CONFLICT),
        ReplayAdmission::Stale => Err(StatusCode::BAD_REQUEST),
        ReplayAdmission::Full => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

fn idempotent_read_status(admission: IdempotentReadAdmission) -> Result<(), StatusCode> {
    match admission {
        IdempotentReadAdmission::New | IdempotentReadAdmission::Idempotent => Ok(()),
        IdempotentReadAdmission::Replay | IdempotentReadAdmission::NonceConflict => {
            Err(StatusCode::CONFLICT)
        }
        IdempotentReadAdmission::Full => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

fn validate_hex_id(id: &str) -> bool {
    id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Returns true only for IPv4 addresses safe to register as a
/// friend-reachable presence address: not unspecified, loopback,
/// multicast, broadcast, link-local, private (RFC 1918), or one of
/// the CGN / documentation / benchmark / reserved ranges that aren't
/// covered by the stable `is_private()`/`is_documentation()` helpers.
/// Mirrors (and is intentionally duplicated from, for locality) the
/// client-side filter in `src-tauri/src/network/rendezvous.rs::is_routable_public_v4`
/// — keep the two in sync if either changes. The client re-checks
/// this independently as defense-in-depth, but the server is the
/// first line of defense: rejecting non-routable addresses here means
/// they never enter the presence map at all.
fn is_routable_public_v4(ip: Ipv4Addr) -> bool {
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_link_local()
        || ip.is_private()
        || ip.is_documentation()
    {
        return false;
    }
    let octets = ip.octets();
    // 0.0.0.0/8 (already covered by is_unspecified for /32, but block
    // the whole /8 per RFC 1122).
    if octets[0] == 0 {
        return false;
    }
    // 100.64.0.0/10 — Carrier-grade NAT (RFC 6598). Not reserved by
    // `is_private()` in stable Rust.
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return false;
    }
    // 240.0.0.0/4 — reserved/future use.
    if octets[0] >= 240 {
        return false;
    }
    // 198.18.0.0/15 — benchmark.
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return false;
    }
    true
}

/// IPv6 counterpart to `is_routable_public_v4`. Rejects unspecified,
/// loopback, multicast, unique-local (`fc00::/7`), and unicast
/// link-local (`fe80::/10`) addresses. Stable `std` doesn't yet expose
/// `is_unique_local`/`is_unicast_link_local` for `Ipv6Addr`, so those
/// two ranges are matched on the leading segment directly. IPv4-mapped
/// (`::ffff:0:0/96`) addresses are unwrapped and re-checked against
/// the V4 filter, so a client can't smuggle a non-routable V4 address
/// past this filter by presenting it in mapped-V6 form.
fn is_routable_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_routable_public_v4(mapped);
    }
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    let seg0 = ip.segments()[0];
    // fc00::/7 — unique local addresses (RFC 4193).
    if seg0 & 0xfe00 == 0xfc00 {
        return false;
    }
    // fe80::/10 — link-local unicast.
    if seg0 & 0xffc0 == 0xfe80 {
        return false;
    }
    true
}

fn validate_relay_ticket_id(id: &str) -> bool {
    validate_hex_id(id)
}

/// Ticket IDs are binary values represented as hex. Use one lowercase text
/// form everywhere they become map keys, URL path components, or token-input
/// bytes so alternate-case spellings cannot produce different capabilities.
fn canonical_relay_ticket_id(id: &str) -> Option<String> {
    validate_relay_ticket_id(id).then(|| id.to_ascii_lowercase())
}

fn validate_relay_token(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn random_relay_secret_hex() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn relay_token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Derive the unique opaque token for one role of a random ticket. Only the
/// process secret and the token hash are retained server-side; the plaintext
/// token is materialized only in the authenticated offer/accept response.
fn issue_relay_role_token(state: &AppState, ticket_id: &str, role: RelayRole) -> String {
    let ticket_id = canonical_relay_ticket_id(ticket_id)
        .expect("internal relay ticket IDs must be valid 32-byte hex");
    let mut hasher = Sha256::new();
    hasher.update(state.relay_token_key);
    hasher.update(ticket_id.as_bytes());
    match role {
        RelayRole::Initiator => hasher.update(b"initiator"),
        RelayRole::Responder => hasher.update(b"responder"),
    }
    hex::encode(hasher.finalize())
}

/// Verify a signature made by a currently registered identity, returning its
/// key. The presence entry's pinned key is the authority, so callers never
/// provide a freely-chosen pubkey.
async fn verify_signed_relay_identity_signature(
    state: &AppState,
    identity_id: &str,
    message: &[u8],
    sig: &[u8; 64],
) -> Result<[u8; 32], StatusCode> {
    let pubkey = {
        let store = state.store.read().await;
        store
            .get(&identity_id.to_lowercase())
            .filter(|entry| entry.expires_at > Instant::now())
            .map(|entry| entry.pubkey)
    }
    .ok_or(StatusCode::NOT_FOUND)?;

    if !ed25519_verify(&pubkey, message, sig) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(pubkey)
}

fn prune_expired_relay_tickets(tickets: &mut RelayTicketStore, now: Instant) {
    tickets.prune_expired(now);
}

fn initiator_has_ticket_capacity(tickets: &RelayTicketStore, initiator_id: &str) -> bool {
    tickets
        .initiator_counts
        .get(initiator_id)
        .copied()
        .unwrap_or(0)
        < MAX_PENDING_RELAY_TICKETS_PER_INITIATOR
}

fn responder_has_accepted_ticket_capacity(tickets: &RelayTicketStore, responder_id: &str) -> bool {
    tickets
        .accepted_responder_counts
        .get(responder_id)
        .copied()
        .unwrap_or(0)
        < MAX_ACCEPTED_RELAY_TICKETS_PER_RESPONDER
}

/// Atomically reserves a role token and capacity before sending HTTP 101.
/// The reservation is either committed by the upgrade callback or rolled back
/// by its watchdog, so a successful handshake never races capacity admission.
async fn reserve_relay_ticket_join(
    state: &AppState,
    ticket_id: &str,
    token: &str,
    client_ip: IpAddr,
) -> Result<RelayReservation, StatusCode> {
    let ticket_id = canonical_relay_ticket_id(ticket_id).ok_or(StatusCode::BAD_REQUEST)?;
    if !validate_relay_token(token) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let token_hash = relay_token_hash(token);
    let reservation_id = state
        .next_relay_reservation_id
        .fetch_add(1, Ordering::Relaxed);
    let now = Instant::now();
    let mut tickets = state.relay_tickets.write().await;
    prune_expired_relay_tickets(&mut tickets, now);
    let ticket = tickets
        .tickets
        .get_mut(&ticket_id)
        .ok_or(StatusCode::GONE)?;
    if ticket.expires_at <= now {
        // The prune above retains an expired ticket only while a pre-upgrade
        // reservation is outstanding (so its rollback can still release the
        // per-network count). That retention must not admit new joins past expiry.
        return Err(StatusCode::GONE);
    }
    if !ticket.accepted {
        return Err(StatusCode::FORBIDDEN);
    }

    let role = if token_hash == ticket.initiator_token_hash {
        RelayRole::Initiator
    } else if token_hash == ticket.responder_token_hash {
        RelayRole::Responder
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let (already_joined, reservation) = match role {
        RelayRole::Initiator => (
            &mut ticket.initiator_joined,
            &mut ticket.initiator_reservation,
        ),
        RelayRole::Responder => (
            &mut ticket.responder_joined,
            &mut ticket.responder_reservation,
        ),
    };
    if *already_joined || reservation.is_some() {
        return Err(StatusCode::CONFLICT);
    }
    let network = client_network(client_ip);

    // The ticket lock stays held until capacity is reserved so a failed
    // pre-upgrade check neither burns the token nor returns a false 101.
    let mut counts = state.relay_network_counts.write().await;
    let global_total: usize = counts.values().sum();
    if global_total >= MAX_GLOBAL_RELAY_SESSIONS {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let count = counts.entry(network).or_insert(0);
    if *count >= MAX_RELAY_SESSIONS_PER_NETWORK {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    *count += 1;
    *reservation = Some(reservation_id);
    Ok(RelayReservation {
        ticket_id,
        role,
        client_ip,
        id: reservation_id,
    })
}

async fn commit_relay_ticket_reservation(
    state: &AppState,
    reservation: &RelayReservation,
) -> Result<(), StatusCode> {
    let mut tickets = state.relay_tickets.write().await;
    let ticket = tickets
        .tickets
        .get_mut(&reservation.ticket_id)
        .ok_or(StatusCode::GONE)?;
    let (joined, pending) = match reservation.role {
        RelayRole::Initiator => (
            &mut ticket.initiator_joined,
            &mut ticket.initiator_reservation,
        ),
        RelayRole::Responder => (
            &mut ticket.responder_joined,
            &mut ticket.responder_reservation,
        ),
    };
    if *joined || *pending != Some(reservation.id) {
        return Err(StatusCode::CONFLICT);
    }
    *pending = None;
    *joined = true;
    drop(tickets);
    state.relay_admissions.write().await.insert(
        (reservation.ticket_id.clone(), reservation.role),
        reservation.client_ip,
    );
    Ok(())
}

async fn rollback_relay_ticket_reservation(state: &AppState, reservation: &RelayReservation) {
    let released = {
        let mut tickets = state.relay_tickets.write().await;
        let Some(ticket) = tickets.tickets.get_mut(&reservation.ticket_id) else {
            return;
        };
        let pending = match reservation.role {
            RelayRole::Initiator => &mut ticket.initiator_reservation,
            RelayRole::Responder => &mut ticket.responder_reservation,
        };
        if *pending == Some(reservation.id) {
            *pending = None;
            true
        } else {
            false
        }
    };
    if released {
        release_relay_network_slots(state, [reservation.client_ip]).await;
    }
}

/// Unit-test helper for immediate, non-WebSocket callers.
#[cfg(test)]
async fn admit_relay_ticket_join(
    state: &AppState,
    ticket_id: &str,
    token: &str,
    client_ip: IpAddr,
) -> Result<RelayRole, StatusCode> {
    let reservation = reserve_relay_ticket_join(state, ticket_id, token, client_ip).await?;
    commit_relay_ticket_reservation(state, &reservation).await?;
    Ok(reservation.role)
}

async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RegisterRequest>,
) -> StatusCode {
    if !validate_hex_id(&body.id) {
        return StatusCode::BAD_REQUEST;
    }
    if body.port == 0 {
        return StatusCode::BAD_REQUEST;
    }
    if !timestamp_fresh(body.ts) {
        return StatusCode::BAD_REQUEST;
    }

    let Some(pubkey) = decode_hex_pubkey(&body.pubkey) else {
        return StatusCode::BAD_REQUEST;
    };
    let Some(sig_bytes) = decode_hex_sig(&body.sig) else {
        return StatusCode::BAD_REQUEST;
    };
    if !pubkey_matches_id(&pubkey, &body.id) {
        // Pubkey doesn't derive to the claimed id — most likely a
        // request crafted by someone who knows a victim's id but
        // doesn't hold the keypair. Treat as forbidden, not bad
        // request, so callers can distinguish "bad input" from "you
        // don't own this id".
        return StatusCode::FORBIDDEN;
    }

    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }

    // The signature must commit to (id, port, ip4, pubkey, ts), not
    // just to the id alone — otherwise a captured `/register` payload
    // could be replayed with a different ip/port to steer traffic.
    //
    // VPN-aware policy (replaces the earlier "body.ip must equal
    // conn.ip" pin from M7):
    //
    //   - `body.ip` is REQUIRED. We refuse to fall back to `client_ip`
    //     so a VPN / split-tunnel client whose HTTPS to rendezvous
    //     egresses through ISP A while their P2P listener is reachable
    //     via VPN exit B doesn't get its presence pinned to ISP A —
    //     that pin would steer every friend lookup to an unreachable
    //     address. It also means rendezvous never records a presence
    //     IP unless the app has actually detected one and signed it,
    //     which is what the user wanted: "ensure the rendezvous server
    //     doesn't get an external IP until one has been reported in
    //     the app".
    //
    //   - We TRUST `body.ip` even when it differs from `client_ip`
    //     (e.g. split-tunnel VPN). The pubkey-pin + Ed25519 PoP that
    //     friend dials still run on the actual TCP/QUIC session is the
    //     real authority: a malicious keypair holder pointing friends
    //     at a wrong IP just causes the friend dial to fail handshake.
    //     The DDoS-amplifier scenario (attacker steers many lookups
    //     at a victim) requires the attacker to first be on those
    //     friends' lists, which they can't be without manual user
    //     consent. That's a self-DoS of the attacker's own friends,
    //     not a real amplification primitive — the pin to conn.ip we
    //     used to enforce traded a real VPN-user breakage for that
    //     near-zero-risk improvement, so we drop the pin.
    //
    //   - The routability filter (no loopback / private / link-local /
    //     CGN / docs / 240.0.0.0/4) still applies, so an attacker
    //     can't point rendezvous at e.g. 127.0.0.1 to make friends
    //     dial themselves.
    let body_ip_parsed = match body
        .ip
        .as_deref()
        .and_then(|s| s.parse::<IpAddr>().ok())
        .filter(|ip| match ip {
            IpAddr::V4(v4) => is_routable_public_v4(*v4),
            IpAddr::V6(v6) => is_routable_public_v6(*v6),
        }) {
        Some(ip) => ip,
        None => {
            // Either missing, unparseable, or a non-routable address
            // (loopback / private / link-local / etc). Refuse rather
            // than silently substituting `client_ip` — see policy
            // comment above.
            return StatusCode::BAD_REQUEST;
        }
    };
    let presence_ip = body_ip_parsed;

    // The signature commits to the IPv4 quad the CLIENT signed:
    //   - If body.ip parses as IPv4, the client signed those four octets.
    //   - For IPv6 body.ip the client signed [0,0,0,0].
    // (We never reach the no-body-ip case anymore — that's rejected
    // above.)
    let signed_ip4 = match body_ip_parsed {
        IpAddr::V4(v4) => v4.octets(),
        IpAddr::V6(_) => [0u8; 4],
    };

    let Some(id_raw) = decode_hex_id(&body.id) else {
        return StatusCode::BAD_REQUEST;
    };
    let msg = build_register_msg(&id_raw, body.port, signed_ip4, &pubkey, body.ts);
    if !ed25519_verify(&pubkey, &msg, &sig_bytes) {
        return StatusCode::FORBIDDEN;
    }

    let entry = PresenceEntry {
        expires_at: Instant::now() + ENTRY_TTL,
        pubkey,
    };

    let mut store = state.store.write().await;
    // A register is a keep-alive of the pinned key: replaying one only
    // re-extends presence its owner signed for moments ago, so it keeps no
    // replay state. What it must not do is undo an unregister, which raises
    // the key's floor. Checked under the store lock that unregister's removal
    // also takes, so the two cannot interleave into a resurrection.
    if let Err(status) = check_replay_floor(&state, &pubkey, body.ts).await {
        return status;
    }
    let key = body.id.to_lowercase();
    if let Some(existing) = store.get(&key) {
        // First-write-wins on pubkey: any later /register for this id
        // MUST come from the same keypair. This is the actual squat
        // defence — even if an attacker on the same NAT presents the
        // same client_ip, a different pubkey now means rejection.
        if existing.pubkey != pubkey {
            return StatusCode::FORBIDDEN;
        }
    } else if store.len() >= MAX_STORE_ENTRIES {
        // Before failing closed on a brand-new id, purge already-expired
        // entries — a map that's merely full of stale junk (normal churn
        // between sweep cycles) shouldn't lock out legitimate new
        // registrants the same way a genuine sustained flood would.
        let now = Instant::now();
        if state.store_purge.try_begin(now) {
            store.retain(|_, e| e.expires_at > now);
        }
        if store.len() >= MAX_STORE_ENTRIES {
            return StatusCode::SERVICE_UNAVAILABLE;
        }
    }
    store.insert(key, entry);
    // debug!, not info!: per-request lines include the client IP and a
    // partial id, which together can be correlated to deanonymize a
    // user across log aggregations. Drop into debug so operators can
    // still get this with `RUST_LOG=ember_rendezvous=debug` when
    // troubleshooting, but the default log stream stays free of PII.
    debug!(
        "registered {} ip={} (conn={})",
        &body.id[..8],
        presence_ip,
        client_ip
    );
    StatusCode::OK
}

async fn legacy_presence_lookup_gone() -> StatusCode {
    // Stable Friend IDs are authentication/mailbox addresses only. They must
    // never be usable as public-presence lookup keys.
    StatusCode::GONE
}

async fn protocol_v4() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "version": 4,
        "domain": "ember-rdv-v4",
        "legacy_v3_rollout": true,
        // Clients only register an `ember3:` intro (proved with `intro_key`)
        // where this is advertised, and fall back to the legacy intro
        // elsewhere, since older servers refuse the sealed form.
        "sealed_intro": true,
    }))
}

#[derive(Deserialize)]
struct ChannelUsernameRequest {
    pubkey: String,
    name: String,
    ts: i64,
    sig: String,
}

#[derive(Deserialize)]
struct ChannelNameRequest {
    channel_id: String,
    pubkey: String,
    name: String,
    private: bool,
    ts: i64,
    sig: String,
}

#[derive(Deserialize)]
struct ChannelDeleteRequest {
    channel_id: String,
    pubkey: String,
    ts: i64,
    sig: String,
}

#[derive(Deserialize)]
struct ChannelNomineeRequest {
    channel_id: String,
    pubkey: String,
    /// User pubkey to nominate, or empty to withdraw.
    #[serde(default)]
    nominee: String,
    #[serde(default)]
    claim_after_days: u32,
    ts: i64,
    sig: String,
}

#[derive(Deserialize)]
struct ChannelHandoverRequest {
    old_channel_id: String,
    new_channel_id: String,
    new_pubkey: String,
    /// Old channel key for an explicit transfer, or the nominee's user key for
    /// a takeover. The server picks the rule from this.
    signer: String,
    ts: i64,
    sig: String,
}

async fn claim_channel_username_v4(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ChannelUsernameRequest>,
) -> StatusCode {
    if !timestamp_fresh(body.ts) {
        return StatusCode::BAD_REQUEST;
    }
    let Some(normalized) = registry::normalize_username(&body.name) else {
        return StatusCode::BAD_REQUEST;
    };
    let (Some(pubkey), Some(sig)) = (
        decode_hex_pubkey(&body.pubkey),
        decode_hex_sig(&body.sig),
    ) else {
        return StatusCode::BAD_REQUEST;
    };
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    let signed = build_channel_username_v4_msg(&pubkey, &normalized, body.ts);
    if !ed25519_verify(&pubkey, &signed, &sig) {
        return StatusCode::FORBIDDEN;
    }
    // One scope per key: replaying the handle a user renamed away from would
    // take it back.
    if let Err(status) = admit_signed_request(
        &state,
        &pubkey,
        replay_scope(OP_CHANNEL_USERNAME_V4, &[]),
        body.ts,
        &signed,
        &sig,
        ReplayMode::IdempotentRepeat,
    )
    .await
    {
        return status;
    }
    // Charged the creation budget, not just the general one. Claiming a
    // username mints permanent shared state — the entry is held for
    // `USERNAME_IDLE_SECS` (a year) and every later request pays to re-serialise
    // it — and the signature proves only that the caller generated a keypair,
    // which costs nothing. Under the general 60/min limit alone this endpoint
    // was 600x cheaper to abuse than `claim_channel_name_v4`, which charges
    // this budget for writing to the very same file. Charged after the replay
    // check so a retransmitted request cannot spend a second slot.
    let claims_new_handle = {
        let registry = state.channels_registry.read().await;
        !registry.holds_username(&hex::encode(pubkey), &normalized)
    };
    if claims_new_handle && !check_channel_create_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    let mut registry = state.channels_registry.write().await;
    let result = registry.claim_username(&hex::encode(pubkey), &normalized);
    let durable_generation = registry.durable_generation();
    drop(registry);
    acknowledge_registry_write(&state, result, durable_generation).await
}

async fn claim_channel_name_v4(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ChannelNameRequest>,
) -> StatusCode {
    if !timestamp_fresh(body.ts) {
        return StatusCode::BAD_REQUEST;
    }
    let Some(normalized) = registry::normalize_channel_name(&body.name) else {
        return StatusCode::BAD_REQUEST;
    };
    let (Some(channel_id), Some(pubkey), Some(sig)) = (
        decode_hex_channel_id(&body.channel_id),
        decode_hex_pubkey(&body.pubkey),
        decode_hex_sig(&body.sig),
    ) else {
        return StatusCode::BAD_REQUEST;
    };
    if !channel_id_matches_pubkey(&pubkey, &channel_id) {
        return StatusCode::FORBIDDEN;
    }
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    // Prefer the form that commits to the display string the directory will
    // publish. A client predating it still authenticates through the legacy
    // message, but that message covers only the normalised key — so rather
    // than serving bytes nobody signed, the legacy path publishes the
    // normalised name and the room simply shows lowercase until the client
    // upgrades.
    let display = registry::strip_invisible(&body.name);
    let signed_display = build_channel_name_display_v4_msg(
        &channel_id,
        &pubkey,
        &normalized,
        &display,
        body.private,
        body.ts,
    );
    let (signed, publish_name) = if ed25519_verify(&pubkey, &signed_display, &sig) {
        (signed_display, body.name.clone())
    } else {
        let legacy =
            build_channel_name_v4_msg(&channel_id, &pubkey, &normalized, body.private, body.ts);
        if !ed25519_verify(&pubkey, &legacy, &sig) {
            return StatusCode::FORBIDDEN;
        }
        (legacy, normalized.clone())
    };
    // Replaying an older claim would flip `private` or the display name back.
    if let Err(status) = admit_signed_request(
        &state,
        &pubkey,
        replay_scope(OP_CHANNEL_NAME_V4, &[]),
        body.ts,
        &signed,
        &sig,
        ReplayMode::IdempotentRepeat,
    )
    .await
    {
        return status;
    }
    let channel_hex = hex::encode(channel_id);
    // Only a room the registry has never seen spends creation budget. An owner
    // re-claiming the name their room already holds is a refresh, and throttling
    // that would eventually release the name of a live room.
    let is_new_room = !state.channels_registry.read().await.has_channel(&channel_hex);
    if is_new_room && !check_channel_create_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    let mut registry = state.channels_registry.write().await;
    let result =
        registry.claim_channel_name(&channel_hex, &hex::encode(pubkey), &publish_name, body.private);
    let durable_generation = registry.durable_generation();
    drop(registry);
    acknowledge_registry_write(&state, result, durable_generation).await
}

/// `POST /v4/channels/rename` — same body as `/v4/channels/name`, signed with
/// [`build_channel_rename_v4_msg`]. Kept apart from claims so that only an
/// owner who asked to rename can: see `ChannelRegistry::claim_channel_name_at`.
async fn rename_channel_name_v4(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ChannelNameRequest>,
) -> StatusCode {
    if !timestamp_fresh(body.ts) {
        return StatusCode::BAD_REQUEST;
    }
    let Some(normalized) = registry::normalize_channel_name(&body.name) else {
        return StatusCode::BAD_REQUEST;
    };
    let (Some(channel_id), Some(pubkey), Some(sig)) = (
        decode_hex_channel_id(&body.channel_id),
        decode_hex_pubkey(&body.pubkey),
        decode_hex_sig(&body.sig),
    ) else {
        return StatusCode::BAD_REQUEST;
    };
    if !channel_id_matches_pubkey(&pubkey, &channel_id) {
        return StatusCode::FORBIDDEN;
    }
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    // No legacy form: every client that knows this endpoint signs the display.
    let display = registry::strip_invisible(&body.name);
    let signed =
        build_channel_rename_v4_msg(&channel_id, &pubkey, &normalized, &display, body.private, body.ts);
    if !ed25519_verify(&pubkey, &signed, &sig) {
        return StatusCode::FORBIDDEN;
    }
    // Replaying an older rename would move the room back to a name it left.
    // The newest may repeat: it names the room's current name, which the
    // registry answers as a refresh, so a retry after a lost answer succeeds.
    if let Err(status) = admit_signed_request(
        &state,
        &pubkey,
        replay_scope(OP_CHANNEL_RENAME_V4, &[]),
        body.ts,
        &signed,
        &sig,
        ReplayMode::IdempotentRepeat,
    )
    .await
    {
        return status;
    }
    let channel_hex = hex::encode(channel_id);
    // A rename of a room the registry already knows writes no new room, so it
    // is never charged the creation budget. One it has never seen is a claim
    // in all but name, and is charged exactly as `claim_channel_name_v4`
    // would charge it.
    let is_new_room = !state.channels_registry.read().await.has_channel(&channel_hex);
    if is_new_room && !check_channel_create_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    let mut registry = state.channels_registry.write().await;
    let result = registry.rename_channel_name_at(
        &channel_hex,
        &hex::encode(pubkey),
        &body.name,
        body.private,
        now_unix_secs(),
    );
    let durable_generation = registry.durable_generation();
    drop(registry);
    acknowledge_registry_write(&state, result, durable_generation).await
}

async fn delete_channel_v4(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ChannelDeleteRequest>,
) -> StatusCode {
    if !timestamp_fresh(body.ts) {
        return StatusCode::BAD_REQUEST;
    }
    let (Some(channel_id), Some(pubkey), Some(sig)) = (
        decode_hex_channel_id(&body.channel_id),
        decode_hex_pubkey(&body.pubkey),
        decode_hex_sig(&body.sig),
    ) else {
        return StatusCode::BAD_REQUEST;
    };
    if !channel_id_matches_pubkey(&pubkey, &channel_id) {
        return StatusCode::FORBIDDEN;
    }
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    let signed = build_channel_delete_v4_msg(&channel_id, &pubkey, body.ts);
    if !ed25519_verify(&pubkey, &signed, &sig) {
        return StatusCode::FORBIDDEN;
    }
    // No replay state: a tombstone is permanent, so a replayed delete can only
    // repeat itself, and a repeat is free below.
    // A delete writes a tombstone that is kept forever, so it mints more
    // durable state than a name claim does and must not be cheaper to issue.
    // Only charged when it would actually record something new: re-deleting an
    // already-tombstoned room is idempotent and free, so a client retrying
    // cannot burn its own budget.
    let channel_hex = hex::encode(channel_id);
    let records_new_tombstone = {
        let registry = state.channels_registry.read().await;
        !registry.is_deleted(&channel_hex)
    };
    if records_new_tombstone && !check_channel_create_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    let mut registry = state.channels_registry.write().await;
    let result = registry.delete_channel(&channel_hex, &hex::encode(pubkey));
    let durable_generation = registry.durable_generation();
    drop(registry);
    acknowledge_registry_write(&state, result, durable_generation).await
}

async fn set_channel_nominee_v4(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ChannelNomineeRequest>,
) -> StatusCode {
    if !timestamp_fresh(body.ts) {
        return StatusCode::BAD_REQUEST;
    }
    let (Some(channel_id), Some(pubkey), Some(sig)) = (
        decode_hex_channel_id(&body.channel_id),
        decode_hex_pubkey(&body.pubkey),
        decode_hex_sig(&body.sig),
    ) else {
        return StatusCode::BAD_REQUEST;
    };
    // Withdrawing is signed over all-zeros, so an empty nominee cannot be
    // swapped in for a real one without invalidating the signature.
    let nominee = if body.nominee.trim().is_empty() {
        [0u8; 32]
    } else {
        match decode_hex_pubkey(&body.nominee) {
            Some(pk) => pk,
            None => return StatusCode::BAD_REQUEST,
        }
    };
    if !channel_id_matches_pubkey(&pubkey, &channel_id) {
        return StatusCode::FORBIDDEN;
    }
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    let signed = build_channel_nominee_v4_msg(
        &channel_id,
        &pubkey,
        &nominee,
        body.claim_after_days,
        body.ts,
    );
    if !ed25519_verify(&pubkey, &signed, &sig) {
        return StatusCode::FORBIDDEN;
    }
    // Replaying a nomination after its withdrawal would re-grant succession.
    if let Err(status) = admit_signed_request(
        &state,
        &pubkey,
        replay_scope(OP_CHANNEL_NOMINEE_V4, &[]),
        body.ts,
        &signed,
        &sig,
        ReplayMode::IdempotentRepeat,
    )
    .await
    {
        return status;
    }
    let nominee_hex = if nominee == [0u8; 32] {
        String::new()
    } else {
        hex::encode(nominee)
    };
    let mut registry = state.channels_registry.write().await;
    let result = registry.set_channel_nominee(
        &hex::encode(channel_id),
        &hex::encode(pubkey),
        &nominee_hex,
        body.claim_after_days,
    );
    let durable_generation = registry.durable_generation();
    drop(registry);
    acknowledge_registry_write(&state, result, durable_generation).await
}

async fn handover_channel_name_v4(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ChannelHandoverRequest>,
) -> StatusCode {
    if !timestamp_fresh(body.ts) {
        return StatusCode::BAD_REQUEST;
    }
    let (Some(old_channel_id), Some(new_channel_id), Some(new_pubkey), Some(signer), Some(sig)) = (
        decode_hex_channel_id(&body.old_channel_id),
        decode_hex_channel_id(&body.new_channel_id),
        decode_hex_pubkey(&body.new_pubkey),
        decode_hex_pubkey(&body.signer),
        decode_hex_sig(&body.sig),
    ) else {
        return StatusCode::BAD_REQUEST;
    };
    // The successor has to be a real room, or a name could be parked on an id
    // nobody holds the key to.
    if !channel_id_matches_pubkey(&new_pubkey, &new_channel_id) {
        return StatusCode::FORBIDDEN;
    }
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    let signed = build_channel_handover_v4_msg(
        &old_channel_id,
        &new_channel_id,
        &new_pubkey,
        &signer,
        body.ts,
    );
    if !ed25519_verify(&signer, &signed, &sig) {
        return StatusCode::FORBIDDEN;
    }
    if let Err(status) = admit_signed_request(
        &state,
        &signer,
        replay_scope(OP_CHANNEL_HANDOVER_V4, &old_channel_id),
        body.ts,
        &signed,
        &sig,
        ReplayMode::IdempotentRepeat,
    )
    .await
    {
        return status;
    }
    let mut registry = state.channels_registry.write().await;
    let result = registry.handover_channel_name(
        &hex::encode(old_channel_id),
        &hex::encode(new_channel_id),
        &hex::encode(new_pubkey),
        &hex::encode(signer),
        now_unix_secs(),
    );
    let durable_generation = registry.durable_generation();
    drop(registry);
    acknowledge_registry_write(&state, result, durable_generation).await
}

/// Longest directory cursor accepted. Ours are at most 52 characters.
const MAX_DIRECTORY_CURSOR_LEN: usize = 128;

#[derive(Deserialize, Default)]
struct DirectoryQuery {
    /// `next_cursor` from the previous page. Omitted for the first page.
    #[serde(default)]
    cursor: Option<String>,
    /// Same as `cursor`, spelled like `/v4/channels/deleted`'s parameter.
    #[serde(default)]
    after: Option<String>,
}

/// `GET /v4/channels/directory[?cursor=<next_cursor>]`
///
/// Responds `{"channels": [...], "next_cursor": <string or null>}` with at
/// most [`registry::DIRECTORY_PAGE_SIZE`] listings per page, oldest claim
/// first, [`registry::MAX_DIRECTORY_LISTINGS`] in total. `next_cursor` is
/// non-null exactly when more listings follow. A client that predates paging
/// sends no cursor, ignores `next_cursor`, and gets the first page — the most
/// established rooms — which is bounded well under its 256 KiB limit.
async fn channel_directory_v4(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<DirectoryQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let raw_cursor = query
        .cursor
        .as_deref()
        .or(query.after.as_deref())
        .filter(|cursor| !cursor.is_empty());
    let cursor = match raw_cursor {
        None => None,
        Some(raw) if raw.len() > MAX_DIRECTORY_CURSOR_LEN => return Err(StatusCode::BAD_REQUEST),
        Some(raw) => {
            Some(registry::DirectoryCursor::parse(raw).ok_or(StatusCode::BAD_REQUEST)?)
        }
    };
    // Read-only: listings the owner stopped refreshing are filtered out, not
    // reaped, so serving Discover never needs the write lock.
    let registry = state.channels_registry.read().await;
    let page = registry.directory_page(cursor.as_ref(), registry::DIRECTORY_PAGE_SIZE);
    Ok(Json(serde_json::json!({
        "channels": page.channels,
        "next_cursor": page.next_cursor,
    })))
}

/// Ids returned per `/v4/channels/deleted` page.
///
/// Each id is 32 hex characters, so a full page is ~70 KB of JSON — well
/// inside the client's 256 KiB response bound, and a fixed ceiling on what a
/// single unauthenticated request can make the server serialise. Unpaginated,
/// this endpoint turned a ~200-byte request into an unbounded response plus an
/// O(n log n) rebuild of the whole tombstone list, and every client polls it.
const MAX_DELETED_IDS_PER_PAGE: usize = 2_000;

#[derive(Deserialize)]
struct DeletedIdsQuery {
    /// Last id the caller already has. Omitted for the first page.
    #[serde(default)]
    after: Option<String>,
}

async fn channel_deleted_v4(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<DeletedIdsQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    // The cursor is only ever compared against stored ids, so it cannot be
    // used to reach anything — but bounding it keeps a multi-megabyte query
    // string from being a cheap way to make us allocate.
    if query.after.as_deref().is_some_and(|cursor| {
        cursor.len() > 64 || !cursor.bytes().all(|b| b.is_ascii_hexdigit())
    }) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let registry = state.channels_registry.read().await;
    let ids = registry.deleted_ids_page(query.after.as_deref(), MAX_DELETED_IDS_PER_PAGE);
    // A cursor is only offered on a full page; a short page is the last one.
    // Clients that predate paging read `ids` and ignore `next`, which is
    // correct for every deployment whose tombstone set fits in one page.
    let next = (ids.len() == MAX_DELETED_IDS_PER_PAGE)
        .then(|| ids.last().cloned())
        .flatten();
    Ok(Json(serde_json::json!({
        "ids": ids,
        "next": next,
    })))
}

async fn legacy_identity_lookup(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<IdentityResponse>, StatusCode> {
    if !validate_hex_id(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let client_ip = extract_client_ip(&headers, addr);
    // Temporary rolling-deploy oracle: deliberately much tighter than the
    // authenticated v4 API and isolated in its own counter bucket.
    if !check_rate_limit_bucket(
        &state.legacy_identity_rate_limits,
        client_ip,
        MAX_LEGACY_IDENTITY_LOOKUPS_PER_MINUTE,
    )
    .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let store = state.store.read().await;
    let entry = store
        .get(&id.to_lowercase())
        .filter(|entry| entry.expires_at > Instant::now())
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(IdentityResponse {
        pubkey: hex::encode(entry.pubkey),
    }))
}

#[derive(Deserialize)]
struct IdentityLookupRequest {
    target_id: String,
    requester_id: String,
    requester_pubkey: String,
    nonce: String,
    ts: i64,
    sig: String,
}

async fn identity_lookup_v4(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<IdentityLookupRequest>,
) -> Result<Json<IdentityResponse>, StatusCode> {
    if !validate_hex_id(&body.target_id)
        || !validate_hex_id(&body.requester_id)
        || !timestamp_fresh(body.ts)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (Some(target_raw), Some(requester_raw), Some(requester_pubkey), Some(nonce), Some(sig)) = (
        decode_hex_id(&body.target_id),
        decode_hex_id(&body.requester_id),
        decode_hex_pubkey(&body.requester_pubkey),
        decode_hex_nonce(&body.nonce),
        decode_hex_sig(&body.sig),
    ) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    if !pubkey_matches_id(&requester_pubkey, &body.requester_id) {
        return Err(StatusCode::FORBIDDEN);
    }
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let requester_registered = state
        .store
        .read()
        .await
        .get(&body.requester_id.to_lowercase())
        .is_some_and(|entry| entry.expires_at > Instant::now() && entry.pubkey == requester_pubkey);
    if !requester_registered {
        return Err(StatusCode::FORBIDDEN);
    }
    let signed = build_identity_lookup_v4_msg(
        &target_raw,
        &requester_raw,
        &requester_pubkey,
        &nonce,
        body.ts,
    );
    if !ed25519_verify(&requester_pubkey, &signed, &sig) {
        return Err(StatusCode::FORBIDDEN);
    }
    // A read keeps no per-request marks: clients issue lookups for many peers
    // concurrently, so one mark per key would refuse ones that arrive out of
    // order, and one per target would exhaust the key's budget. A replay only
    // repeats a lookup the signer was authorized for, within the skew window;
    // the floor still refuses anything signed before an unregister.
    check_replay_floor(&state, &requester_pubkey, body.ts).await?;
    let store = state.store.read().await;
    let entry = store
        .get(&body.target_id.to_lowercase())
        .filter(|entry| entry.expires_at > Instant::now())
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(IdentityResponse {
        pubkey: hex::encode(entry.pubkey),
    }))
}

async fn capability_register_v3(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CapabilityRegisterRequest>,
) -> StatusCode {
    capability_register_impl(state, addr, headers, body, RendezvousVersion::LegacyV3).await
}

async fn capability_register_v4(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CapabilityRegisterRequest>,
) -> StatusCode {
    capability_register_impl(state, addr, headers, body, RendezvousVersion::IpBoundV4).await
}

async fn capability_register_impl(
    state: AppState,
    addr: SocketAddr,
    headers: HeaderMap,
    body: CapabilityRegisterRequest,
    version: RendezvousVersion,
) -> StatusCode {
    if !validate_hex_id(&body.capability)
        || body.port == 0
        || !timestamp_fresh(body.ts)
        // Same overflow as `timestamp_fresh`: `body.epoch` is attacker-chosen,
        // so compute the distance without a subtraction that can wrap.
        || body.epoch.abs_diff(now_unix_secs().div_euclid(15 * 60)) > 1
    {
        return StatusCode::BAD_REQUEST;
    }
    let (Some(capability), Some(pubkey), Some(peer_pubkey), Some(sig)) = (
        decode_hex_id(&body.capability),
        decode_hex_pubkey(&body.pubkey),
        decode_hex_pubkey(&body.peer_pubkey),
        decode_hex_sig(&body.sig),
    ) else {
        return StatusCode::BAD_REQUEST;
    };
    if VerifyingKey::from_bytes(&peer_pubkey).is_err() {
        return StatusCode::BAD_REQUEST;
    }
    if body.intro && peer_pubkey != pubkey {
        return StatusCode::BAD_REQUEST;
    }
    let intro_key = match body.intro_key.as_deref() {
        None => None,
        Some(value) if body.intro && validate_hex_id(value) => decode_hex_id(value),
        Some(_) => return SEALED_INTRO_REJECTED,
    };
    // A legacy intro capability is derived from the owner's public key and the
    // epoch, both public; a sealed one also from the owner's intro secret,
    // which every holder of its `ember3:` code knows. Either way someone other
    // than the owner can derive the current capability and sign a valid
    // registration for it with their own key. Recomputing the derivation under
    // the registrant's key binds the namespace to its owner, so nobody else
    // can claim it at all — neither to replace a live entry nor to squat an
    // epoch before the owner registers, which the owner pin alone would still
    // permit.
    if body.intro
        && capability != expected_intro_capability(&pubkey, intro_key.as_ref(), body.epoch)
    {
        return if intro_key.is_some() {
            SEALED_INTRO_REJECTED
        } else {
            StatusCode::FORBIDDEN
        };
    }
    let Ok(ip) = body.ip.parse::<IpAddr>() else {
        return StatusCode::BAD_REQUEST;
    };
    // Fail closed on IPv6 until clients verify the full signed encoding end-to-end.
    let IpAddr::V4(v4) = ip else {
        return StatusCode::BAD_REQUEST;
    };
    if !is_routable_public_v4(v4) {
        return StatusCode::BAD_REQUEST;
    }
    let legacy_sig = match (version, body.legacy_sig.as_deref()) {
        (RendezvousVersion::LegacyV3, None) => None,
        (RendezvousVersion::LegacyV3, Some(_)) => return StatusCode::BAD_REQUEST,
        (RendezvousVersion::IpBoundV4, None) => None,
        (RendezvousVersion::IpBoundV4, Some(value)) => {
            let Some(signature) = decode_hex_sig(value) else {
                return StatusCode::BAD_REQUEST;
            };
            Some(signature)
        }
    };
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    let owner_id = id_from_pubkey(&pubkey);
    let owner_is_registered = state
        .store
        .read()
        .await
        .get(&owner_id)
        .is_some_and(|entry| entry.expires_at > Instant::now() && entry.pubkey == pubkey);
    if !owner_is_registered {
        return StatusCode::FORBIDDEN;
    }
    let signed = match version {
        RendezvousVersion::LegacyV3 => build_capability_register_v3_msg(
            &capability,
            body.epoch,
            body.port,
            v4.octets(),
            &pubkey,
            &peer_pubkey,
            body.ts,
        ),
        RendezvousVersion::IpBoundV4 => build_capability_register_v4_msg(
            &capability,
            body.epoch,
            body.port,
            &encode_signed_ip(ip),
            &pubkey,
            &peer_pubkey,
            body.ts,
        ),
    };
    if !ed25519_verify(&pubkey, &signed, &sig) {
        return StatusCode::FORBIDDEN;
    }
    let legacy_signed = legacy_sig.map(|_| {
        build_capability_register_v3_msg(
            &capability,
            body.epoch,
            body.port,
            v4.octets(),
            &pubkey,
            &peer_pubkey,
            body.ts,
        )
    });
    if let (Some(legacy_sig), Some(legacy_signed)) = (legacy_sig, legacy_signed.as_ref()) {
        if !ed25519_verify(&pubkey, legacy_signed, &legacy_sig) {
            return StatusCode::FORBIDDEN;
        }
    }
    // A capability registration is a periodic refresh, sent for every friend
    // and neighbour each heartbeat, so it keeps no per-request replay state.
    // Replaying one within the skew window re-extends an address its owner
    // signed moments ago; what a replay must not do is roll a newer address
    // back, which the timestamp comparison under the lock below refuses.
    if let Err(status) = check_replay_floor(&state, &pubkey, body.ts).await {
        return status;
    }
    let mut capabilities = state.capability_store.write().await;
    let key = body.capability.to_lowercase();
    let now = Instant::now();
    // A capability is a namespace whose presence owner must remain stable for
    // its live lifetime. Pairwise capabilities are secret, but friend-code
    // intro capabilities are intentionally derivable from a public key and
    // epoch; without this pin, anyone holding a friend's public code could
    // register the same current-epoch intro capability with their own identity
    // and replace the real owner's address. The signature proves only that the
    // *claimant* owns its key, not that it owns this capability.
    //
    // Let an expired entry be claimed by a new owner: it is no longer a live
    // presence, and the normal insertion path below will replace it. A live
    // owner can still refresh an address, port, proof version, or peer binding.
    //
    // Reaching here with `body.intro` set means the derivation above matched,
    // which proves this claimant owns the namespace — a stronger claim than
    // first-come, so it outranks the pin and reclaims the entry. That matters
    // because the derivation check only applies to intro registrations: a
    // *pairwise* registration can name a victim's derivable intro capability
    // and skip the proof entirely, and the pin would otherwise make that squat
    // permanent, locking the owner out of its own friend-code presence for as
    // long as the squatter kept refreshing. A proved intro claim cannot collide
    // with a real pairwise capability without a BLAKE3 preimage, so letting it
    // win cannot be turned around against pairwise entries.
    if !body.intro
        && capabilities
            .get(&key)
            .is_some_and(|entry| !capability_owner_allows_register(entry, &pubkey, now))
    {
        return StatusCode::FORBIDDEN;
    }
    if capabilities.len() >= MAX_STORE_ENTRIES && !capabilities.contains_key(&key) {
        if state.capability_purge.try_begin(now) {
            capabilities.retain(|_, entry| entry.expires_at > now);
        }
        if capabilities.len() >= MAX_STORE_ENTRIES {
            return StatusCode::SERVICE_UNAVAILABLE;
        }
    }
    let matching = capabilities.get(&key).is_some_and(|entry| {
        entry.ip == ip
            && entry.port == body.port
            && entry.peer_pubkey == peer_pubkey
            && entry.open_intro == body.intro
            && entry.pubkey == pubkey
            && entry.epoch == body.epoch
    });
    // The owner's live entry was signed no earlier than this request: keeping
    // it alive is harmless, replacing it with what this request says is a
    // rollback — including within the same second, since timestamps cannot
    // order two registrations signed in it. Comparing against both proofs also
    // covers a v3 refresh landing between a v4 request and its replay. An
    // owner whose clock stepped back is only refused if it also changed
    // address meanwhile.
    let superseded = capabilities.get(&key).is_some_and(|entry| {
        entry.expires_at > now
            && entry.pubkey == pubkey
            && entry
                .legacy_proof
                .into_iter()
                .chain(entry.v4_proof)
                .any(|(signed_ts, _)| signed_ts >= body.ts)
    });
    if superseded && !matching {
        return StatusCode::CONFLICT;
    }
    if !matching {
        capabilities.insert(
            key.clone(),
            PairwisePresenceEntry {
                ip,
                port: body.port,
                expires_at: Instant::now() + ENTRY_TTL,
                peer_pubkey,
                open_intro: body.intro,
                pubkey,
                epoch: body.epoch,
                legacy_proof: None,
                v4_proof: None,
            },
        );
    }
    let entry = capabilities
        .get_mut(&key)
        .expect("matching or inserted capability remains while lock is held");
    entry.expires_at = Instant::now() + ENTRY_TTL;
    // Lookups hand these proofs to peers, so never swap one for an older one.
    let keep_newest = |slot: &mut Option<(i64, [u8; 64])>, proof: [u8; 64]| {
        if slot.is_none_or(|(signed_ts, _)| signed_ts <= body.ts) {
            *slot = Some((body.ts, proof));
        }
    };
    match version {
        RendezvousVersion::LegacyV3 => keep_newest(&mut entry.legacy_proof, sig),
        RendezvousVersion::IpBoundV4 => {
            keep_newest(&mut entry.v4_proof, sig);
            if let Some(legacy_sig) = legacy_sig {
                keep_newest(&mut entry.legacy_proof, legacy_sig);
            }
        }
    }
    StatusCode::OK
}

async fn capability_lookup_v3(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CapabilityLookupRequest>,
) -> Result<Json<CapabilityLookupResponse>, StatusCode> {
    capability_lookup_impl(state, addr, headers, body, RendezvousVersion::LegacyV3).await
}

async fn capability_lookup_v4(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CapabilityLookupRequest>,
) -> Result<Json<CapabilityLookupResponse>, StatusCode> {
    capability_lookup_impl(state, addr, headers, body, RendezvousVersion::IpBoundV4).await
}

async fn capability_lookup_impl(
    state: AppState,
    addr: SocketAddr,
    headers: HeaderMap,
    body: CapabilityLookupRequest,
    version: RendezvousVersion,
) -> Result<Json<CapabilityLookupResponse>, StatusCode> {
    if !validate_hex_id(&body.capability)
        || !validate_hex_id(&body.requester_id)
        || !timestamp_fresh(body.ts)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (Some(capability), Some(requester_raw), Some(requester_pubkey), Some(nonce), Some(sig)) = (
        decode_hex_id(&body.capability),
        decode_hex_id(&body.requester_id),
        decode_hex_pubkey(&body.requester_pubkey),
        decode_hex_nonce(&body.nonce),
        decode_hex_sig(&body.sig),
    ) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    if !pubkey_matches_id(&requester_pubkey, &body.requester_id) {
        return Err(StatusCode::FORBIDDEN);
    }
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let requester_registered = state
        .store
        .read()
        .await
        .get(&body.requester_id.to_lowercase())
        .is_some_and(|entry| entry.expires_at > Instant::now() && entry.pubkey == requester_pubkey);
    if !requester_registered {
        return Err(StatusCode::FORBIDDEN);
    }
    let signed = match version {
        RendezvousVersion::LegacyV3 => build_capability_lookup_v3_msg(
            &capability,
            body.epoch,
            &requester_raw,
            &requester_pubkey,
            &nonce,
            body.ts,
        ),
        RendezvousVersion::IpBoundV4 => build_capability_lookup_v4_msg(
            &capability,
            body.epoch,
            &requester_raw,
            &requester_pubkey,
            &nonce,
            body.ts,
        ),
    };
    if !ed25519_verify(&requester_pubkey, &signed, &sig) {
        return Err(StatusCode::FORBIDDEN);
    }
    // A read, like `identity_lookup_v4`: floor only.
    check_replay_floor(&state, &requester_pubkey, body.ts).await?;
    let capabilities = state.capability_store.read().await;
    let entry = capabilities
        .get(&body.capability.to_lowercase())
        .filter(|entry| {
            capability_allows_peer(entry, &requester_pubkey, body.epoch, Instant::now())
        })
        .ok_or(StatusCode::NOT_FOUND)?;
    let (proof_version, proof) = match version {
        RendezvousVersion::LegacyV3 => (
            RendezvousVersion::LegacyV3,
            entry.legacy_proof.ok_or(StatusCode::NOT_FOUND)?,
        ),
        RendezvousVersion::IpBoundV4 => entry
            .v4_proof
            .map(|proof| (RendezvousVersion::IpBoundV4, proof))
            .or_else(|| {
                entry
                    .legacy_proof
                    .map(|proof| (RendezvousVersion::LegacyV3, proof))
            })
            .ok_or(StatusCode::NOT_FOUND)?,
    };
    Ok(Json(CapabilityLookupResponse {
        acknowledged: true,
        capability: body.capability.to_lowercase(),
        epoch: entry.epoch,
        ip: entry.ip.to_string(),
        port: entry.port,
        pubkey: hex::encode(entry.pubkey),
        ts: proof.0,
        sig: hex::encode(proof.1),
        proof_version: (version == RendezvousVersion::IpBoundV4)
            .then(|| proof_version.wire_value()),
    }))
}

async fn unregister(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<UnregisterRequest>,
) -> StatusCode {
    if !validate_hex_id(&body.id) {
        return StatusCode::BAD_REQUEST;
    }
    if !timestamp_fresh(body.ts) {
        return StatusCode::BAD_REQUEST;
    }
    let Some(sig_bytes) = decode_hex_sig(&body.sig) else {
        return StatusCode::BAD_REQUEST;
    };
    let Some(id_raw) = decode_hex_id(&body.id) else {
        return StatusCode::BAD_REQUEST;
    };

    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }

    let id = body.id.to_lowercase();
    let pubkey = state.store.read().await.get(&id).map(|entry| entry.pubkey);
    if let Some(pubkey) = pubkey {
        // Verify with the pinned pubkey rather than trusting the current
        // connection IP. The signature is the authority across address churn.
        let msg = build_unregister_msg(&id_raw, body.ts);
        if ed25519_verify(&pubkey, &msg, &sig_bytes) {
            // Raising the floor refuses a replay of this unregister, which
            // would knock a re-registered user offline, and of any register
            // signed before it, which would resurrect them. It must land
            // before the removal below; see `register`.
            let admission =
                state
                    .replay_guard
                    .write()
                    .await
                    .raise_floor(pubkey, body.ts, ReplayNow::current());
            if let Err(status) = replay_status(admission) {
                return status;
            }
            // Crypto and replay work is deliberately outside the global
            // presence write lock. Re-check the pinned key before removal in
            // case the entry was refreshed while verification ran.
            let mut store = state.store.write().await;
            if store.get(&id).is_some_and(|entry| entry.pubkey == pubkey) {
                store.remove(&id);
            }
            debug!("unregistered {} from {}", &body.id[..8], client_ip);
            return StatusCode::OK;
        }
        return StatusCode::FORBIDDEN;
    }
    StatusCode::NOT_FOUND
}

// ---------------------------------------------------------------------------
// Hole-punch coordination
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CapabilityPunchRequest {
    from_id: String,
    target_id: String,
    capability: String,
    epoch: i64,
    port: u16,
    /// V4 initiator-claimed, signature-bound dial address. Legacy v3 omits it
    /// and uses the server-observed address exactly as before.
    #[serde(default)]
    ip: Option<String>,
    nat_type: u8,
    ts: i64,
    nonce: String,
    sig: String,
}

#[derive(Deserialize)]
struct CapabilityPunchPollRequest {
    target_id: String,
    ts: i64,
    nonce: String,
    sig: String,
}

#[derive(Deserialize)]
struct CapabilityPunchAckRequest {
    target_id: String,
    capability: String,
    epoch: i64,
    punch_id: String,
    ts: i64,
    nonce: String,
    sig: String,
}

#[derive(Serialize)]
struct PunchResponse {
    punch_id: String,
    from_id: String,
    ip: String,
    port: u16,
    nat_type: u8,
    capability: String,
    epoch: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_version: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    register_ts: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    register_nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    register_sig: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from_pubkey: Option<String>,
}

fn punch_live(entry: &PunchEntry, now: Instant) -> bool {
    now.saturating_duration_since(entry.created_at) < PUNCH_TTL
}

fn punch_available(entry: &PunchEntry, now: Instant) -> bool {
    entry.leased_until.is_none_or(|until| until <= now)
}

async fn legacy_punch_gone() -> StatusCode {
    StatusCode::GONE
}

async fn punch_register_v3(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CapabilityPunchRequest>,
) -> StatusCode {
    punch_register_impl(state, addr, headers, body, RendezvousVersion::LegacyV3).await
}

async fn punch_register_v4(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CapabilityPunchRequest>,
) -> StatusCode {
    punch_register_impl(state, addr, headers, body, RendezvousVersion::IpBoundV4).await
}

async fn punch_register_impl(
    state: AppState,
    addr: SocketAddr,
    headers: HeaderMap,
    body: CapabilityPunchRequest,
    version: RendezvousVersion,
) -> StatusCode {
    if !validate_hex_id(&body.from_id)
        || !validate_hex_id(&body.target_id)
        || !validate_hex_id(&body.capability)
        || body.port == 0
        || !timestamp_fresh(body.ts)
    {
        return StatusCode::BAD_REQUEST;
    }
    let (Some(from_raw), Some(target_raw), Some(capability), Some(nonce), Some(sig)) = (
        decode_hex_id(&body.from_id),
        decode_hex_id(&body.target_id),
        decode_hex_id(&body.capability),
        decode_hex_nonce(&body.nonce),
        decode_hex_sig(&body.sig),
    ) else {
        return StatusCode::BAD_REQUEST;
    };
    // `extract_client_ip` returns a forwarded address only in the explicit
    // trusted-Fly-proxy mode and only when the immediate hop is allowlisted.
    // Canonicalizing mapped IPv4 makes the signed/body comparison independent
    // of the listener/proxy's textual address family representation.
    let observed_ip = canonical_ip(extract_client_ip(&headers, addr));
    if !check_rate_limit_bucket(&state.punch_rate_limits, observed_ip, MAX_PUNCH_PER_MINUTE).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    let dial_ip = match version {
        RendezvousVersion::LegacyV3 => observed_ip,
        RendezvousVersion::IpBoundV4 => {
            let Some(claimed_ip) = body.ip.as_deref().and_then(parse_routable_ip) else {
                return StatusCode::BAD_REQUEST;
            };
            if claimed_ip != observed_ip {
                return StatusCode::FORBIDDEN;
            }
            // Persist only the server-observed (or explicitly trusted-proxy)
            // address. Equality above ensures this is the signed address too.
            observed_ip
        }
    };
    let signed = match version {
        RendezvousVersion::LegacyV3 => build_punch_register_v3_msg(
            &from_raw,
            &target_raw,
            &capability,
            body.epoch,
            body.port,
            body.nat_type,
            &nonce,
            body.ts,
        ),
        RendezvousVersion::IpBoundV4 => build_punch_register_v4_msg(
            &from_raw,
            &target_raw,
            &capability,
            body.epoch,
            body.port,
            &encode_signed_ip(dial_ip),
            body.nat_type,
            &nonce,
            body.ts,
        ),
    };
    let signer = match verify_signed_relay_identity_signature(&state, &body.from_id, &signed, &sig)
        .await
    {
        Ok(signer) => signer,
        Err(status) => return status,
    };
    let target = body.target_id.to_lowercase();
    let (target_pubkey, from_pubkey) = {
        let store = state.store.read().await;
        let Some(target_pubkey) = store
            .get(&target)
            .filter(|entry| entry.expires_at > Instant::now())
            .map(|entry| entry.pubkey)
        else {
            return StatusCode::NOT_FOUND;
        };
        let Some(from_pubkey) = store
            .get(&body.from_id.to_lowercase())
            .filter(|entry| entry.expires_at > Instant::now())
            .map(|entry| entry.pubkey)
        else {
            return StatusCode::FORBIDDEN;
        };
        (target_pubkey, from_pubkey)
    };
    // `capability_allows_peer` short-circuits on `open_intro`, so a public
    // friend-code capability authorizes *any* registered identity — which is the
    // point, since a stranger holding the code must be able to reach the owner.
    // Track whether that is the only reason this request passed, so the slot
    // accounting below can keep strangers from filling a target's queue and
    // starving the friends it is actually bound to.
    let (capability_authorized, via_open_intro) = state
        .capability_store
        .read()
        .await
        .get(&body.capability.to_lowercase())
        .map_or((false, false), |entry| {
            let authorized = capability_allows_peer(entry, &from_pubkey, body.epoch, Instant::now())
                && entry.pubkey == target_pubkey;
            let pairwise_bound = entry.peer_pubkey == from_pubkey;
            (authorized, authorized && entry.open_intro && !pairwise_bound)
        });
    if !capability_authorized {
        return StatusCode::FORBIDDEN;
    }
    // One-time per request, scoped to the target. A replay would re-queue a
    // punch its initiator already finished, or overwrite a newer one with an
    // older port — and a legacy v3 registration does not sign its address, so
    // a replay from another host would have the target punch toward it.
    if let Err(status) = admit_signed_request(
        &state,
        &signer,
        replay_scope(OP_PUNCH_REGISTER_V4, &target_raw),
        body.ts,
        &signed,
        &sig,
        ReplayMode::OneTime,
    )
    .await
    {
        return status;
    }
    let from = body.from_id.to_lowercase();
    let mut punches = state.punch_requests.write().await;
    let now = Instant::now();
    punches.prune_expired(now);
    if !punches.contains(&target, &from)
        && (punches.len() >= MAX_PUNCH_REQUESTS_TOTAL
            || punches.target_len(&target) >= MAX_PUNCH_PER_TARGET)
    {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    // A stranger authorized only by a public intro capability gets a small share
    // of the per-target queue. Identities are free to mint and the per-target cap
    // is keyed on `(target, from)`, so without this a handful of throwaway keys
    // filled all eight slots — the cap's own rationale assumes an attacker has to
    // source from many IPs, which the open-intro path removes. Friends bound to a
    // pairwise capability keep the rest.
    if via_open_intro
        && !punches.contains(&target, &from)
        && open_intro_punch_slots_exhausted(&punches, &target)
    {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    punches.insert(
        target,
        from.clone(),
        PunchEntry {
            punch_id: random_relay_secret_hex(),
            from_id: from,
            from_ip: dial_ip,
            from_port: body.port,
            nat_type: body.nat_type,
            capability,
            epoch: body.epoch,
            created_at: now,
            leased_until: None,
            proof_version: version,
            register_nonce: (version == RendezvousVersion::IpBoundV4).then_some(nonce),
            register_ts: (version == RendezvousVersion::IpBoundV4).then_some(body.ts),
            register_sig: (version == RendezvousVersion::IpBoundV4).then_some(sig),
            from_pubkey: (version == RendezvousVersion::IpBoundV4).then_some(from_pubkey),
            via_open_intro,
        },
    );
    StatusCode::OK
}

async fn punch_poll_v3(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CapabilityPunchPollRequest>,
) -> Result<Json<PunchResponse>, StatusCode> {
    punch_poll_impl(state, addr, headers, body, RendezvousVersion::LegacyV3).await
}

async fn punch_poll_v4(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CapabilityPunchPollRequest>,
) -> Result<Json<PunchResponse>, StatusCode> {
    punch_poll_impl(state, addr, headers, body, RendezvousVersion::IpBoundV4).await
}

async fn punch_poll_impl(
    state: AppState,
    addr: SocketAddr,
    headers: HeaderMap,
    body: CapabilityPunchPollRequest,
    version: RendezvousVersion,
) -> Result<Json<PunchResponse>, StatusCode> {
    if !validate_hex_id(&body.target_id) || !timestamp_fresh(body.ts) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (Some(target_raw), Some(nonce), Some(sig)) = (
        decode_hex_id(&body.target_id),
        decode_hex_nonce(&body.nonce),
        decode_hex_sig(&body.sig),
    ) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let signed = match version {
        RendezvousVersion::LegacyV3 => build_punch_poll_v3_msg(&target_raw, &nonce, body.ts),
        RendezvousVersion::IpBoundV4 => build_punch_poll_v4_msg(&target_raw, &nonce, body.ts),
    };
    // A replayed poll would lease the target's current queue head — possibly
    // registered after the original poll — to whoever holds it. Polls come
    // one at a time from each client, so a single one-time scope per key
    // (shared by v3 and v4) costs one mark and never refuses an honest poll.
    let signer =
        verify_signed_relay_identity_signature(&state, &body.target_id, &signed, &sig).await?;
    admit_signed_request(
        &state,
        &signer,
        replay_scope(OP_PUNCH_POLL_V4, &[]),
        body.ts,
        &signed,
        &sig,
        ReplayMode::OneTime,
    )
    .await?;
    let target = body.target_id.to_lowercase();
    let mut punches = state.punch_requests.write().await;
    let now = Instant::now();
    punches.prune_expired(now);
    let entry = punches
        .lease_next(&target, version, now)
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(PunchResponse {
        punch_id: entry.punch_id.clone(),
        from_id: entry.from_id.clone(),
        ip: entry.from_ip.to_string(),
        port: entry.from_port,
        nat_type: entry.nat_type,
        capability: hex::encode(entry.capability),
        epoch: entry.epoch,
        proof_version: (version == RendezvousVersion::IpBoundV4)
            .then(|| entry.proof_version.wire_value()),
        register_ts: (version == RendezvousVersion::IpBoundV4)
            .then_some(entry.register_ts)
            .flatten(),
        register_nonce: (version == RendezvousVersion::IpBoundV4)
            .then_some(entry.register_nonce)
            .flatten()
            .map(hex::encode),
        register_sig: (version == RendezvousVersion::IpBoundV4)
            .then_some(entry.register_sig)
            .flatten()
            .map(hex::encode),
        from_pubkey: (version == RendezvousVersion::IpBoundV4)
            .then_some(entry.from_pubkey)
            .flatten()
            .map(hex::encode),
    }))
}

async fn punch_ack_v3(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CapabilityPunchAckRequest>,
) -> StatusCode {
    punch_ack_impl(state, addr, headers, body, RendezvousVersion::LegacyV3).await
}

async fn punch_ack_v4(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CapabilityPunchAckRequest>,
) -> StatusCode {
    punch_ack_impl(state, addr, headers, body, RendezvousVersion::IpBoundV4).await
}

async fn punch_ack_impl(
    state: AppState,
    addr: SocketAddr,
    headers: HeaderMap,
    body: CapabilityPunchAckRequest,
    version: RendezvousVersion,
) -> StatusCode {
    if !validate_hex_id(&body.target_id)
        || !validate_hex_id(&body.capability)
        || !validate_hex_id(&body.punch_id)
        || !timestamp_fresh(body.ts)
    {
        return StatusCode::BAD_REQUEST;
    }
    let (Some(target_raw), Some(capability), Some(punch_raw), Some(nonce), Some(sig)) = (
        decode_hex_id(&body.target_id),
        decode_hex_id(&body.capability),
        decode_hex_id(&body.punch_id),
        decode_hex_nonce(&body.nonce),
        decode_hex_sig(&body.sig),
    ) else {
        return StatusCode::BAD_REQUEST;
    };
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    let signed = match version {
        RendezvousVersion::LegacyV3 => build_punch_ack_v3_msg(
            &target_raw,
            &capability,
            body.epoch,
            &punch_raw,
            &nonce,
            body.ts,
        ),
        RendezvousVersion::IpBoundV4 => build_punch_ack_v4_msg(
            &target_raw,
            &capability,
            body.epoch,
            &punch_raw,
            &nonce,
            body.ts,
        ),
    };
    // No per-request marks: an ack removes the entry carrying this random
    // `punch_id`, and a re-registration always gets a new one, so a replay can
    // only miss.
    let signer =
        match verify_signed_relay_identity_signature(&state, &body.target_id, &signed, &sig).await
        {
            Ok(signer) => signer,
            Err(status) => return status,
        };
    if let Err(status) = check_replay_floor(&state, &signer, body.ts).await {
        return status;
    }
    let target = body.target_id.to_lowercase();
    let mut punches = state.punch_requests.write().await;
    punches.prune_expired(Instant::now());
    if punches.remove_acked(&target, &body.punch_id, &capability, body.epoch) {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

// ---------------------------------------------------------------------------
// Authenticated, role-bound server relay tickets
// ---------------------------------------------------------------------------

async fn relay_mailbox_offer(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RelayMailboxOfferRequest>,
) -> Result<Json<RelayTicketOfferResponse>, StatusCode> {
    if !validate_hex_id(&body.initiator_id)
        || !validate_hex_id(&body.responder_id)
        || !validate_hex_id(&body.capability)
        || !validate_relay_ticket_id(&body.ticket_id)
        || !timestamp_fresh(body.ts)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let envelope = hex::decode(&body.envelope).map_err(|_| StatusCode::BAD_REQUEST)?;
    if envelope.is_empty() || envelope.len() > 2 * 1024 {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let (
        Some(initiator_raw),
        Some(responder_raw),
        Some(capability),
        Some(ticket_raw),
        Some(nonce),
        Some(sig),
    ) = (
        decode_hex_id(&body.initiator_id),
        decode_hex_id(&body.responder_id),
        decode_hex_id(&body.capability),
        decode_hex_id(&body.ticket_id),
        decode_hex_nonce(&body.nonce),
        decode_hex_sig(&body.sig),
    )
    else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let signed = build_relay_mailbox_offer_msg(
        &initiator_raw,
        &responder_raw,
        &capability,
        body.epoch,
        &ticket_raw,
        &envelope,
        &nonce,
        body.ts,
    );
    let signer =
        verify_signed_relay_identity_signature(&state, &body.initiator_id, &signed, &sig).await?;

    // The opaque capability must name live presence owned by the intended
    // responder. Knowing only its stable mailbox ID cannot satisfy this.
    let (responder_pubkey, initiator_pubkey) = {
        let store = state.store.read().await;
        let responder_pubkey = store
            .get(&body.responder_id.to_lowercase())
            .filter(|entry| entry.expires_at > Instant::now())
            .map(|entry| entry.pubkey)
            .ok_or(StatusCode::NOT_FOUND)?;
        let initiator_pubkey = store
            .get(&body.initiator_id.to_lowercase())
            .filter(|entry| entry.expires_at > Instant::now())
            .map(|entry| entry.pubkey)
            .ok_or(StatusCode::FORBIDDEN)?;
        (responder_pubkey, initiator_pubkey)
    };
    let capability_live = state
        .capability_store
        .read()
        .await
        .get(&body.capability.to_lowercase())
        .is_some_and(|entry| {
            capability_allows_peer(entry, &initiator_pubkey, body.epoch, Instant::now())
                && entry.pubkey == responder_pubkey
        });
    if !capability_live {
        return Err(StatusCode::FORBIDDEN);
    }
    // One-time per request, scoped to the responder. Once the ticket expires
    // a replay would re-create it under the same id, and role tokens derive
    // from that id, so the replayer would be handed the initiator token.
    admit_signed_request(
        &state,
        &signer,
        replay_scope(OP_RELAY_MAILBOX_OFFER, &responder_raw),
        body.ts,
        &signed,
        &sig,
        ReplayMode::OneTime,
    )
    .await?;

    let ticket_id = canonical_relay_ticket_id(&body.ticket_id).ok_or(StatusCode::BAD_REQUEST)?;
    let initiator_token = issue_relay_role_token(&state, &ticket_id, RelayRole::Initiator);
    let responder_token = issue_relay_role_token(&state, &ticket_id, RelayRole::Responder);
    let now = Instant::now();
    let ticket = RelayTicket {
        initiator_id: body.initiator_id.to_lowercase(),
        responder_id: body.responder_id.to_lowercase(),
        capability,
        epoch: body.epoch,
        mailbox_envelope: envelope,
        initiator_token_hash: relay_token_hash(&initiator_token),
        responder_token_hash: relay_token_hash(&responder_token),
        initiator_joined: false,
        responder_joined: false,
        initiator_reservation: None,
        responder_reservation: None,
        accepted: false,
        expires_at: now + RELAY_TICKET_TTL,
    };
    let mut tickets = state.relay_tickets.write().await;
    prune_expired_relay_tickets(&mut tickets, now);
    if tickets.tickets.len() >= MAX_RELAY_TICKETS {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    if tickets.tickets.contains_key(&ticket_id)
        || tickets
            .by_responder
            .get(&ticket.responder_id)
            .is_some_and(|by_initiator| by_initiator.contains_key(&ticket.initiator_id))
    {
        return Err(StatusCode::CONFLICT);
    }
    if !initiator_has_ticket_capacity(&tickets, &ticket.initiator_id) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    tickets.insert(ticket_id.clone(), ticket);
    Ok(Json(RelayTicketOfferResponse {
        ticket_id,
        initiator_token,
        expires_in_secs: RELAY_TICKET_TTL.as_secs(),
    }))
}

async fn relay_mailbox_poll(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RelayMailboxPollRequest>,
) -> Result<Json<RelayMailboxPollResponse>, StatusCode> {
    if !validate_hex_id(&body.responder_id) || !timestamp_fresh(body.ts) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (Some(responder_raw), Some(nonce), Some(sig)) = (
        decode_hex_id(&body.responder_id),
        decode_hex_nonce(&body.nonce),
        decode_hex_sig(&body.sig),
    ) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let client_ip = extract_client_ip(&headers, addr);
    if !check_ticket_read_rate_limit(&state, client_ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let signed = build_relay_mailbox_poll_msg(&responder_raw, &nonce, body.ts);
    let signer =
        verify_signed_relay_identity_signature(&state, &body.responder_id, &signed, &sig).await?;
    check_replay_floor(&state, &signer, body.ts).await?;
    let admission = remember_ticket_poll_nonce(&state, responder_raw, nonce, body.ts).await;
    idempotent_read_status(admission)?;

    let now = Instant::now();
    let responder_id = body.responder_id.to_lowercase();
    let mut tickets = state.relay_tickets.write().await;
    prune_expired_relay_tickets(&mut tickets, now);
    let page_ids = match admission {
        IdempotentReadAdmission::Idempotent => tickets
            .cached_mailbox_page(&responder_id, &nonce, body.ts, now)
            .unwrap_or_else(|| {
                // Process restart dropped the cache: peek without advancing so a
                // lost-response retry cannot skip an unread page.
                tickets.mailbox_peek_page_ids(&responder_id, now)
            }),
        IdempotentReadAdmission::New => {
            let page = tickets.mailbox_page_ids(&responder_id, now);
            tickets.store_mailbox_page(&responder_id, nonce, body.ts, page.clone(), now);
            page
        }
        IdempotentReadAdmission::Replay
        | IdempotentReadAdmission::NonceConflict
        | IdempotentReadAdmission::Full => {
            // idempotent_read_status already rejected these admissions.
            unreachable!("rejected mailbox poll admission reached page selection");
        }
    };
    let mut items = Vec::new();
    for ticket_id in page_ids {
        if let Some(ticket) = tickets.tickets.get(&ticket_id) {
            items.push(RelayMailboxPollItem {
                ticket_id,
                capability: hex::encode(ticket.capability),
                epoch: ticket.epoch,
                envelope: hex::encode(&ticket.mailbox_envelope),
            });
        }
    }
    Ok(Json(RelayMailboxPollResponse { tickets: items }))
}

async fn relay_ticket_accept(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(ticket_id): Path<String>,
    Json(body): Json<RelayTicketIdentityRequest>,
) -> Result<Json<RelayTicketAcceptResponse>, StatusCode> {
    let ticket_id = canonical_relay_ticket_id(&ticket_id).ok_or(StatusCode::BAD_REQUEST)?;
    if !validate_hex_id(&body.identity_id) || !timestamp_fresh(body.ts) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (Some(identity_raw), Some(ticket_raw), Some(nonce), Some(sig)) = (
        decode_hex_id(&body.identity_id),
        decode_hex_id(&ticket_id),
        decode_hex_nonce(&body.nonce),
        decode_hex_sig(&body.sig),
    ) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let signed = build_relay_ticket_action_msg(
        OP_RELAY_TICKET_ACCEPT,
        &identity_raw,
        &ticket_raw,
        &nonce,
        body.ts,
    );
    // No replay state: acceptance is one-time in the ticket itself (a second
    // accept is refused below), and offers are replay-protected, so a ticket
    // id is never re-created for a replayed accept to hit.
    let signer =
        verify_signed_relay_identity_signature(&state, &body.identity_id, &signed, &sig).await?;
    check_replay_floor(&state, &signer, body.ts).await?;

    let now = Instant::now();
    let mut tickets = state.relay_tickets.write().await;
    prune_expired_relay_tickets(&mut tickets, now);
    let responder_id = body.identity_id.to_lowercase();
    let ticket = tickets.tickets.get(&ticket_id).ok_or(StatusCode::GONE)?;
    if ticket.responder_id != responder_id {
        return Err(StatusCode::FORBIDDEN);
    }
    if ticket.accepted {
        // Tokens are deliberately never returned twice. A response replay or
        // a second accept request must create a new ticket rather than gaining
        // another chance to recover a role capability.
        return Err(StatusCode::CONFLICT);
    }
    if !responder_has_accepted_ticket_capacity(&tickets, &responder_id) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    if !tickets.mark_accepted(&ticket_id) {
        return Err(StatusCode::CONFLICT);
    }
    let responder_token = issue_relay_role_token(&state, &ticket_id, RelayRole::Responder);
    Ok(Json(RelayTicketAcceptResponse {
        responder_token,
        expires_in_secs: tickets
            .tickets
            .get(&ticket_id)
            .expect("accepted ticket remains present while the store lock is held")
            .expires_at
            .saturating_duration_since(now)
            .as_secs(),
    }))
}

async fn relay_ticket_status(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(ticket_id): Path<String>,
    Json(body): Json<RelayTicketIdentityRequest>,
) -> Result<Json<RelayTicketStatusResponse>, StatusCode> {
    let ticket_id = canonical_relay_ticket_id(&ticket_id).ok_or(StatusCode::BAD_REQUEST)?;
    if !validate_hex_id(&body.identity_id) || !timestamp_fresh(body.ts) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (Some(identity_raw), Some(ticket_raw), Some(nonce), Some(sig)) = (
        decode_hex_id(&body.identity_id),
        decode_hex_id(&ticket_id),
        decode_hex_nonce(&body.nonce),
        decode_hex_sig(&body.sig),
    ) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let client_ip = extract_client_ip(&headers, addr);
    if !check_ticket_read_rate_limit(&state, client_ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let signed = build_relay_ticket_action_msg(
        OP_RELAY_TICKET_STATUS,
        &identity_raw,
        &ticket_raw,
        &nonce,
        body.ts,
    );
    let signer =
        verify_signed_relay_identity_signature(&state, &body.identity_id, &signed, &sig).await?;
    check_replay_floor(&state, &signer, body.ts).await?;

    let now = Instant::now();
    let tickets = state.relay_tickets.read().await;
    let ticket = tickets.tickets.get(&ticket_id).ok_or(StatusCode::GONE)?;
    if ticket.expires_at <= now {
        return Err(StatusCode::GONE);
    }
    if ticket.initiator_id != body.identity_id.to_lowercase() {
        return Err(StatusCode::FORBIDDEN);
    }
    let accepted = ticket.accepted;
    drop(tickets);
    idempotent_read_status(
        remember_ticket_status_nonce(&state, identity_raw, ticket_raw, nonce, body.ts).await,
    )?;
    Ok(Json(RelayTicketStatusResponse {
        status: if accepted { "accepted" } else { "offered" },
    }))
}

// ---------------------------------------------------------------------------
// WebSocket relay
// ---------------------------------------------------------------------------

async fn relay_ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(ticket_id): Path<String>,
) -> impl IntoResponse {
    let Some(ticket_id) = canonical_relay_ticket_id(&ticket_id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .and_then(|(scheme, token)| {
            scheme
                .eq_ignore_ascii_case("bearer")
                .then_some(token.trim())
        });
    let Some(token) = token.filter(|token| !token.is_empty()) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let reservation = match reserve_relay_ticket_join(&state, &ticket_id, token, client_ip).await {
        Ok(reservation) => reservation,
        Err(status) => return status.into_response(),
    };
    let watchdog_state = state.clone();
    let watchdog_reservation = reservation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(RELAY_UPGRADE_RESERVATION_TIMEOUT).await;
        rollback_relay_ticket_reservation(&watchdog_state, &watchdog_reservation).await;
    });
    ws.max_frame_size(MAX_RELAY_FRAME_BYTES)
        .max_message_size(MAX_RELAY_FRAME_BYTES)
        .on_upgrade(move |socket| handle_relay_ws_guarded(socket, state, reservation))
        .into_response()
}

/// Legacy arbitrary room IDs are intentionally retired. A relay may only be
/// joined with an authenticated, role-bound ticket; returning Gone makes old
/// clients fail closed instead of preserving an unauthenticated bandwidth
/// relay behind a compatibility path.
async fn legacy_relay_gone() -> StatusCode {
    StatusCode::GONE
}

async fn handle_relay_ws_guarded(
    mut socket: WebSocket,
    state: AppState,
    reservation: RelayReservation,
) {
    if commit_relay_ticket_reservation(&state, &reservation)
        .await
        .is_err()
    {
        // The watchdog may have released an abandoned reservation before this
        // callback ran. Capacity was never overcommitted; close this late
        // socket rather than consuming a second slot.
        let _ = socket.send(Message::Close(None)).await;
        return;
    }
    let session_id = reservation.ticket_id.clone();
    let client_ip = reservation.client_ip;
    let role = reservation.role;
    let cleanup_state = state.clone();
    let cleanup_session = session_id.clone();
    let result =
        std::panic::AssertUnwindSafe(handle_relay_ws(socket, state, session_id, client_ip, role))
            .catch_unwind()
            .await;
    if result.is_err() {
        cleanup_relay(&cleanup_state, &cleanup_session, role).await;
    }
}

async fn handle_relay_ws(
    mut socket: WebSocket,
    state: AppState,
    session_id: String,
    client_ip: IpAddr,
    role: RelayRole,
) {
    let mut sessions = state.relay_sessions.write().await;

    let session_taken = sessions.remove(&session_id);
    if let Some(mut session) = session_taken {
        // Second peer joining — drain the rendezvous slot we just took
        // out of the map (peer1's inbox sender + the announce one-shot
        // for peer2's inbox sender) and run the bidirectional bridge.
        // Removing eagerly prevents a third joiner from observing a
        // half-torn-down entry.
        let peer1_inbox_tx = session.peer1_inbox_tx.take();
        let announce_tx = session.peer2_announce_tx.take();
        let session_deadline = session.deadline;
        drop(sessions);

        let (Some(peer1_inbox_tx), Some(announce_tx)) = (peer1_inbox_tx, announce_tx) else {
            // Slot was already drained — refuse rather than silently
            // half-bridging.
            let _ = socket.send(Message::Close(None)).await;
            cleanup_relay(&state, &session_id, role).await;
            return;
        };

        let (peer2_inbox_tx, peer2_inbox_rx) = relay_queue();
        // Allocate the shared byte counter on the peer2 side so we can
        // hand a clone to peer1 through the announce channel. Both
        // halves will count against it.
        let total_bytes = Arc::new(AtomicUsize::new(0));
        // Hand peer2's inbox sender + shared counter to peer1. If peer1's
        // loop has already exited (timeout/close/etc.), this fails —
        // drop it on the floor; the bridge is moot.
        if announce_tx
            .send((peer2_inbox_tx, total_bytes.clone()))
            .is_err()
        {
            let _ = socket.send(Message::Close(None)).await;
            cleanup_relay(&state, &session_id, role).await;
            return;
        }
        state.bridged_relays.write().await.insert(
            session_id.clone(),
            BridgedRelayEntry {
                deadline: session_deadline,
            },
        );
        debug!(
            "relay session {} bridged (peer2={})",
            &session_id[..8.min(session_id.len())],
            client_ip
        );
        bridge_relay(
            socket,
            peer1_inbox_tx,
            peer2_inbox_rx,
            total_bytes,
            &state,
            &session_id,
            role,
            session_deadline,
        )
        .await;
    } else {
        // First peer — set up the rendezvous slot and run the peer1
        // loop until peer2 joins (announce_rx fires) or we time out.
        let (peer1_inbox_tx, peer1_inbox_rx) = relay_queue();
        let (peer2_announce_tx, peer2_announce_rx) =
            tokio::sync::oneshot::channel::<RelayPeerChannel>();
        let session_deadline = Instant::now() + RELAY_SESSION_TIMEOUT;

        sessions.insert(
            session_id.clone(),
            RelaySessionEntry {
                peer1_inbox_tx: Some(peer1_inbox_tx),
                peer2_announce_tx: Some(peer2_announce_tx),
                deadline: session_deadline,
            },
        );
        drop(sessions);

        debug!(
            "relay session {} created ({role:?}, peer={})",
            &session_id[..8.min(session_id.len())],
            client_ip
        );

        run_peer1_loop(
            socket,
            peer1_inbox_rx,
            peer2_announce_rx,
            &session_id,
            session_deadline,
        )
        .await;
        cleanup_relay(&state, &session_id, role).await;
    }
}

fn enqueue_prebridge_frame(
    frames: &mut VecDeque<Vec<u8>>,
    buffered_bytes: &mut usize,
    frame: Vec<u8>,
    max_frames: usize,
    max_bytes: usize,
) -> Result<(), ()> {
    if frames.len() >= max_frames
        || buffered_bytes
            .checked_add(frame.len())
            .is_none_or(|total| total > max_bytes)
    {
        return Err(());
    }
    *buffered_bytes += frame.len();
    frames.push_back(frame);
    Ok(())
}

/// Peer1 buffers a bounded initial handshake FIFO until peer2 joins, then
/// flushes it in order. This preserves the immediate eMule `OP_HELLO` sent by
/// whichever authenticated role connects first.
async fn run_peer1_loop(
    mut socket: WebSocket,
    mut peer1_inbox_rx: RelayQueueReceiver,
    peer2_announce_rx: tokio::sync::oneshot::Receiver<RelayPeerChannel>,
    session_id: &str,
    session_deadline: Instant,
) {
    let idle_timeout = tokio::time::sleep(RELAY_IDLE_TIMEOUT);
    tokio::pin!(idle_timeout);
    let mut announce_rx = Some(peer2_announce_rx);
    let mut peer2_tx: Option<RelayQueueSender> = None;
    let mut total_bytes: Option<Arc<AtomicUsize>> = None;
    let mut prebridge_frames = VecDeque::<Vec<u8>>::new();
    let mut prebridge_bytes = 0usize;
    // A bridged session has two halves, and only the second joiner runs
    // `bridge_relay` — the first stays here for the whole session. This loop
    // writes only when forwarding a frame from peer2, so during a quiet session
    // peer1's socket saw neither reads nor writes and `HTTP_IDLE_TIMEOUT` killed
    // it from the transport at 30s, tearing the relay down from this end. Adding
    // the keepalive to `bridge_relay` alone fixed only peer2's half. Nothing
    // pings us: the client library answers pings but never initiates them.
    let mut transport_keepalive = tokio::time::interval(RELAY_TRANSPORT_KEEPALIVE);
    transport_keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The immediate first tick would ping before anything can go idle.
    transport_keepalive.tick().await;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(session_deadline.into()) => {
                break;
            }
            // Only once bridged: before that `RELAY_IDLE_TIMEOUT` is the shorter
            // deadline anyway, and a session still waiting for peer2 has nothing
            // to keep alive.
            _ = transport_keepalive.tick(), if peer2_tx.is_some() => {
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
            _ = &mut idle_timeout, if peer2_tx.is_none() => {
                info!("relay session {} timed out waiting for peer2", &session_id[..8.min(session_id.len())]);
                break;
            }
            announced = async { announce_rx.as_mut().unwrap().await }, if announce_rx.is_some() => {
                announce_rx = None;
                match announced {
                    Ok((tx, counter)) => {
                        peer2_tx = Some(tx);
                        total_bytes = Some(counter);
                        let Some(ref tx) = peer2_tx else { return };
                        let Some(ref counter) = total_bytes else { return };
                        while let Some(frame) = prebridge_frames.pop_front() {
                            let new_total =
                                counter.fetch_add(frame.len(), Ordering::Relaxed) + frame.len();
                            if new_total > RELAY_BANDWIDTH_CAP_BYTES {
                                info!("relay session {} bandwidth cap reached flushing pre-bridge frames", &session_id[..8.min(session_id.len())]);
                                return;
                            }
                            if tx.send(frame).await.is_err() {
                                return;
                            }
                        }
                        prebridge_bytes = 0;
                    }
                    Err(_) => {
                        // Sender was dropped (peer2 join handler aborted before sending).
                        break;
                    }
                }
            }
            // Stop reading while a bounded pre-bridge queue is full. This
            // applies WebSocket/TCP backpressure instead of silently losing
            // handshake frames.
            msg = socket.recv(), if peer2_tx.is_some()
                || (prebridge_frames.len() < MAX_PREBRIDGE_RELAY_FRAMES
                    && prebridge_bytes < MAX_PREBRIDGE_RELAY_BYTES) => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        if data.len() > MAX_RELAY_FRAME_BYTES {
                            break;
                        }
                        if let (Some(ref tx), Some(ref counter)) = (&peer2_tx, &total_bytes) {
                            let new_total =
                                counter.fetch_add(data.len(), Ordering::Relaxed) + data.len();
                            if new_total > RELAY_BANDWIDTH_CAP_BYTES {
                                info!("relay session {} bandwidth cap reached (peer1→peer2)", &session_id[..8.min(session_id.len())]);
                                break;
                            }
                            if tx.send(data.to_vec()).await.is_err() {
                                break;
                            }
                        } else if enqueue_prebridge_frame(
                            &mut prebridge_frames,
                            &mut prebridge_bytes,
                            data.to_vec(),
                            MAX_PREBRIDGE_RELAY_FRAMES,
                            MAX_PREBRIDGE_RELAY_BYTES,
                        )
                        .is_err() {
                            info!("relay session {} exceeded pre-bridge buffer", &session_id[..8.min(session_id.len())]);
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
            data = peer1_inbox_rx.recv() => {
                match data {
                    Some(bytes) => {
                        if !matches!(
                            tokio::time::timeout(
                                RELAY_FORWARD_TIMEOUT,
                                socket.send(Message::Binary(axum::body::Bytes::from(bytes))),
                            )
                            .await,
                            Ok(Ok(()))
                        ) {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
        if Instant::now() > session_deadline {
            break;
        }
    }
}

/// Bidirectional relay between peer2's WebSocket and the channels
/// established when peer2 joined: `peer1_inbox_tx` ferries inbound
/// peer2 WS frames to peer1, `peer2_inbox_rx` drains peer1's frames
/// onto peer2's WebSocket.
///
/// `total_bytes` is the per-session shared counter; peer1's loop
/// holds a clone and increments it for peer1→peer2 frames when it
/// forwards them, and we increment here for peer2→peer1 frames.
/// That way `RELAY_BANDWIDTH_CAP_BYTES` applies uniformly to the sum
/// of both directions. We do NOT re-count on the `peer2_inbox_rx` drain
/// side — those bytes were already counted once by peer1's loop
/// when they entered the relay; counting them again would
/// double-charge the same payload.
#[allow(clippy::too_many_arguments)]
async fn bridge_relay(
    mut socket: WebSocket,
    peer1_inbox_tx: RelayQueueSender,
    mut peer2_inbox_rx: RelayQueueReceiver,
    total_bytes: Arc<AtomicUsize>,
    state: &AppState,
    session_id: &str,
    role: RelayRole,
    deadline: Instant,
) {
    let bridge_idle_timeout = tokio::time::sleep(RELAY_BRIDGE_IDLE_TIMEOUT);
    tokio::pin!(bridge_idle_timeout);
    // The upgraded socket still sits on the `IdleTimeoutStream` that
    // `serve_connection` was given, and `with_upgrades()` hands that same IO to
    // this task — so `HTTP_IDLE_TIMEOUT` outranks every relay lifetime rule
    // above unless bytes keep moving. Silence is the normal state here: an eD2K
    // peer parked in an upload queue sends nothing until its reask (~29 min) and
    // an Ember friend session keepalives at 90s, both far longer than the HTTP
    // idle window, so quiet-but-healthy relays were being killed by the
    // transport. A ping is a write, and `IdleTimeoutStream::poll_write` resets
    // the deadline, so this hands liveness back to `RELAY_BRIDGE_IDLE_TIMEOUT`
    // and the absolute cap while still letting a genuinely dead socket fail on
    // the write.
    let mut transport_keepalive = tokio::time::interval(RELAY_TRANSPORT_KEEPALIVE);
    transport_keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The immediate first tick would ping before anything can go idle.
    transport_keepalive.tick().await;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline.into()) => {
                break;
            }
            _ = transport_keepalive.tick() => {
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
            _ = &mut bridge_idle_timeout => {
                info!(
                    "relay session {} timed out after {:?} without bridged traffic",
                    &session_id[..8.min(session_id.len())],
                    RELAY_BRIDGE_IDLE_TIMEOUT
                );
                break;
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        if data.len() > MAX_RELAY_FRAME_BYTES {
                            break;
                        }
                        let new_total =
                            total_bytes.fetch_add(data.len(), Ordering::Relaxed) + data.len();
                        if new_total > RELAY_BANDWIDTH_CAP_BYTES {
                            info!(
                                "relay session {} bandwidth cap reached (peer2→peer1)",
                                &session_id[..8.min(session_id.len())]
                            );
                            break;
                        }
                        if peer1_inbox_tx.send(data.to_vec()).await.is_err() {
                            break;
                        }
                        bridge_idle_timeout
                            .as_mut()
                            .reset(tokio::time::Instant::now() + RELAY_BRIDGE_IDLE_TIMEOUT);
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
            data = peer2_inbox_rx.recv() => {
                match data {
                    Some(bytes) => {
                        // Cheap guard: if peer1's loop has already
                        // pushed us over the cap via its own
                        // `fetch_add`, don't keep forwarding. No
                        // second `fetch_add` here — those bytes were
                        // already counted on entry.
                        if total_bytes.load(Ordering::Relaxed) > RELAY_BANDWIDTH_CAP_BYTES {
                            break;
                        }
                        if !matches!(
                            tokio::time::timeout(
                                RELAY_FORWARD_TIMEOUT,
                                socket.send(Message::Binary(axum::body::Bytes::from(bytes))),
                            )
                            .await,
                            Ok(Ok(()))
                        ) {
                            break;
                        }
                        bridge_idle_timeout
                            .as_mut()
                            .reset(tokio::time::Instant::now() + RELAY_BRIDGE_IDLE_TIMEOUT);
                    }
                    None => break,
                }
            }
        }
        if Instant::now() > deadline {
            break;
        }
    }

    cleanup_relay(state, session_id, role).await;
}

async fn cleanup_relay(state: &AppState, session_id: &str, role: RelayRole) {
    state.relay_sessions.write().await.remove(session_id);
    state.bridged_relays.write().await.remove(session_id);
    let client_ip = state
        .relay_admissions
        .write()
        .await
        .remove(&(session_id.to_owned(), role));
    if let Some(client_ip) = client_ip {
        release_relay_network_slots(state, [client_ip]).await;
    }
}

async fn release_relay_network_slots(
    state: &AppState,
    client_ips: impl IntoIterator<Item = IpAddr>,
) {
    let mut counts = state.relay_network_counts.write().await;
    for client_ip in client_ips {
        let network = client_network(client_ip);
        if let Some(count) = counts.get_mut(&network) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&network);
            }
        }
    }
}

async fn cleanup_relay_session_all(state: &AppState, session_id: &str) {
    state.relay_sessions.write().await.remove(session_id);
    state.bridged_relays.write().await.remove(session_id);
    let removed_ips = {
        let mut admissions = state.relay_admissions.write().await;
        let keys: Vec<_> = admissions
            .keys()
            .filter(|(ticket_id, _)| ticket_id == session_id)
            .cloned()
            .collect();
        keys.into_iter()
            .filter_map(|key| admissions.remove(&key))
            .collect::<Vec<_>>()
    };
    if removed_ips.is_empty() {
        return;
    }
    release_relay_network_slots(state, removed_ips).await;
}

async fn stats_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let relay_count =
        state.relay_sessions.read().await.len() + state.bridged_relays.read().await.len();
    let punch_count = state.punch_requests.read().await.len();
    let relay_ip_count = state.relay_network_counts.read().await.len();
    let presence_count = state.store.read().await.len();
    let uptime_secs = state.started_at.elapsed().as_secs();
    let channels_registry_read_only = state.channels_registry.read().await.is_read_only();

    Ok(Json(serde_json::json!({
        "active_relay_sessions": relay_count,
        "active_punch_requests": punch_count,
        "relay_ip_count": relay_ip_count,
        "registered_peers": presence_count,
        "uptime_seconds": uptime_secs,
        "max_global_relays": MAX_GLOBAL_RELAY_SESSIONS,
        "channels_registry_read_only": channels_registry_read_only,
    })))
}

async fn health() -> &'static str {
    "ok"
}

/// How often the sweeper reaps abandoned channel names and usernames.
const REGISTRY_REAP_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// Debounce window for channel registry refreshes: every mutation in it lands
/// in one snapshot. Durable mutations wake the flusher instead of waiting.
const REGISTRY_FLUSH_INTERVAL: Duration = Duration::from_secs(5);
/// How long a durable registry write may wait for its snapshot to land before
/// the request is answered 503. Inside `HTTP_REQUEST_TIMEOUT`.
const REGISTRY_DURABLE_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_millis(200)
} else {
    Duration::from_secs(10)
};

/// Lets a handler wait until its registry mutation is on disk. Every write
/// publishes the generation its snapshot covered, so concurrent durable
/// writes share one snapshot rather than each serialising the registry.
struct RegistryPersister {
    wake: tokio::sync::Notify,
    persisted: tokio::sync::watch::Sender<u64>,
}

impl Default for RegistryPersister {
    fn default() -> Self {
        Self {
            wake: tokio::sync::Notify::new(),
            persisted: tokio::sync::watch::channel(0).0,
        }
    }
}

async fn write_persist_job(job: registry::PersistJob, persister: &RegistryPersister) -> bool {
    let generation = job.generation();
    let written = tokio::task::spawn_blocking(move || job.write())
        .await
        .unwrap_or(false);
    if written {
        persister
            .persisted
            .send_modify(|persisted| *persisted = (*persisted).max(generation));
    }
    written
}

/// Write the registry if it changed since the last snapshot. The snapshot is
/// serialised under a read lock and written after it is released.
async fn flush_channels_registry(
    registry: &RwLock<registry::ChannelRegistry>,
    persister: &RegistryPersister,
) -> bool {
    let job = registry.read().await.take_persist_job();
    match job {
        Some(job) => write_persist_job(job, persister).await,
        None => true,
    }
}

/// Final write at shutdown. Closing under the write lock first means nothing
/// acknowledged afterwards can miss the snapshot: later writes get 503.
async fn close_channels_registry(
    registry: &RwLock<registry::ChannelRegistry>,
    persister: &RegistryPersister,
) -> bool {
    let job = {
        let mut registry = registry.write().await;
        registry.close_for_shutdown();
        registry.take_persist_job()
    };
    match job {
        Some(job) => write_persist_job(job, persister).await,
        None => true,
    }
}

async fn flush_channels_registry_periodically(
    registry: Arc<RwLock<registry::ChannelRegistry>>,
    persister: Arc<RegistryPersister>,
) {
    let mut interval = tokio::time::interval(REGISTRY_FLUSH_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = persister.wake.notified() => {}
        }
        flush_channels_registry(&registry, &persister).await;
    }
}

/// Answer a successful registry write only once every durable mutation up to
/// `durable_generation` (sampled under the lock, after this write) is on disk.
/// A tombstone, handover or first claim lost to a crash after its 200 has no
/// retry path.
///
/// Waiting on the registry-wide generation rather than on whether this call
/// bumped it matters for retries: a write answered 503 stays applied in
/// memory, so its retry is a no-op that would otherwise be acknowledged while
/// the original change is still only in memory. With nothing pending this
/// returns at once, so refreshes stay debounced.
async fn acknowledge_registry_write(
    state: &AppState,
    result: Result<(), registry::RegistryError>,
    durable_generation: u64,
) -> StatusCode {
    if let Err(err) = result {
        return registry_error_status(err);
    }
    let persister = &state.registry_persister;
    let mut persisted = persister.persisted.subscribe();
    if *persisted.borrow_and_update() >= durable_generation {
        return StatusCode::OK;
    }
    persister.wake.notify_one();
    let durable = matches!(
        tokio::time::timeout(
            REGISTRY_DURABLE_TIMEOUT,
            persisted.wait_for(|generation| *generation >= durable_generation),
        )
        .await,
        Ok(Ok(_))
    );
    if durable {
        StatusCode::OK
    } else {
        warn!("channel registry write not yet durable; answering 503");
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn sweep_expired(state: AppState) {
    let mut last_registry_reap = Instant::now();
    loop {
        tokio::time::sleep(SWEEP_INTERVAL).await;
        let now = Instant::now();

        // Each map gets its OWN scoped write-lock guard so only one lock
        // is held at a time. Previously the rate_limits sweep was
        // duplicated (the second copy was unscoped) which held that
        // lock for the entire sweep body; meanwhile `punches` and
        // `relays` guards below were also un-scoped, blocking all
        // user-facing handlers that needed any of those maps for the
        // whole sweep cycle. Scoping keeps the critical sections
        // minimal and lets register/lookup/punch requests interleave
        // with the sweep.
        state.rate_limits.write().await.prune(now, RATE_WINDOW * 2);
        state
            .legacy_identity_rate_limits
            .write()
            .await
            .prune(now, RATE_WINDOW * 2);
        state
            .ticket_read_rate_limits
            .write()
            .await
            .prune(now, RATE_WINDOW * 2);

        // Sweep the punch-specific rate-limit map on the same cadence
        // as the general one so the per-IP entries don't pile up after
        // a punch burst goes quiet.
        state.punch_rate_limits.write().await.prune(now, RATE_WINDOW * 2);

        // Swept against its own hour-long window. Using the general one here
        // would drop entries that are still inside their budget and hand the
        // creator a fresh six rooms every couple of minutes.
        state
            .channel_create_rate_limits
            .write()
            .await
            .prune(now, CHANNEL_CREATE_WINDOW);
        state
            .channel_create_network_rate_limits
            .write()
            .await
            .prune(now, CHANNEL_CREATE_WINDOW);

        state.replay_guard.write().await.prune(ReplayNow::current());
        {
            let mut nonces = state.poll_read_nonces.write().await;
            nonces.prune_expired(now);
        }
        {
            let mut nonces = state.status_read_nonces.write().await;
            nonces.prune_expired(now);
        }

        // Sweep expired punch requests
        {
            let punch_removed = state.punch_requests.write().await.prune_expired(now);
            if punch_removed > 0 {
                info!("swept {} expired punch requests", punch_removed);
            }
        }

        // Claims reap only the names they touch, so everything else abandoned
        // is forgotten here. Written out by the next registry flush.
        if last_registry_reap.elapsed() >= REGISTRY_REAP_INTERVAL {
            last_registry_reap = Instant::now();
            state
                .channels_registry
                .write()
                .await
                .reap_stale(now_unix_secs());
        }

        {
            let mut tickets = state.relay_tickets.write().await;
            let before = tickets.tickets.len();
            prune_expired_relay_tickets(&mut tickets, now);
            let removed = before - tickets.tickets.len();
            if removed > 0 {
                debug!("swept {removed} expired relay tickets");
            }
        }

        // Sweep both waiting and actively bridged sessions at their original
        // absolute deadline. Counter release is registry-backed and
        // idempotent, so racing task cleanup cannot double-decrement.
        {
            let mut expired: HashSet<String> = state
                .relay_sessions
                .read()
                .await
                .iter()
                .filter(|(_, entry)| entry.deadline <= now)
                .map(|(id, _)| id.clone())
                .collect();
            expired.extend(
                state
                    .bridged_relays
                    .read()
                    .await
                    .iter()
                    .filter(|(_, entry)| entry.deadline <= now)
                    .map(|(id, _)| id.clone()),
            );
            for session_id in &expired {
                cleanup_relay_session_all(&state, session_id).await;
            }
            if !expired.is_empty() {
                info!("swept {} expired relay sessions", expired.len());
            }
        }

        // Sweep expired presence-map entries. Entries whose `expires_at`
        // has passed should be evicted so that the `MAX_STORE_ENTRIES`
        // cap reflects only actually-live registrations. Without this
        // sweep, a flood of unique-id registrations expires for lookup
        // purposes (the per-entry expiry check inside `lookup` returns
        // 404) but stays in the map forever, eventually filling the
        // 100k cap and 503-ing every new registration.
        {
            let mut store = state.store.write().await;
            let store_before = store.len();
            store.retain(|_, e| e.expires_at > now);
            let store_removed = store_before - store.len();
            if store_removed > 0 {
                info!("swept {} expired presence entries", store_removed);
            }
        }
        {
            let mut capabilities = state.capability_store.write().await;
            capabilities.retain(|_, entry| entry.expires_at > now);
        }
    }
}

fn build_router(state: AppState) -> Router {
    let rate_gate = |gate| {
        axum::middleware::from_fn_with_state((state.clone(), gate), reject_exhausted_rate_budget)
    };
    // Every route that extracts a JSON body sits in exactly one of these three
    // groups, matching the bucket its handler charges.
    let general_body_routes = Router::new()
        .route("/register", post(register))
        .route("/unregister", delete(unregister))
        .route("/v3/presence/register", post(capability_register_v3))
        .route("/v3/presence/lookup", post(capability_lookup_v3))
        .route("/v4/identity/lookup", post(identity_lookup_v4))
        .route("/v4/presence/register", post(capability_register_v4))
        .route("/v4/presence/lookup", post(capability_lookup_v4))
        .route("/v3/punch/poll", post(punch_poll_v3))
        .route("/v3/punch/ack", post(punch_ack_v3))
        .route("/v4/punch/poll", post(punch_poll_v4))
        .route("/v4/punch/ack", post(punch_ack_v4))
        .route("/v4/channels/username", post(claim_channel_username_v4))
        .route("/v4/channels/name", post(claim_channel_name_v4))
        .route("/v4/channels/rename", post(rename_channel_name_v4))
        .route("/v4/channels/delete", post(delete_channel_v4))
        .route("/v4/channels/nominee", post(set_channel_nominee_v4))
        .route("/v4/channels/handover", post(handover_channel_name_v4))
        .route("/v4/relay-mailbox/offer", post(relay_mailbox_offer))
        .route(
            "/v2/relay-tickets/{ticket_id}/accept",
            post(relay_ticket_accept),
        )
        .route_layer(rate_gate(BodyRateGate::General));
    let ticket_read_body_routes = Router::new()
        .route("/v4/relay-mailbox/poll", post(relay_mailbox_poll))
        .route(
            "/v2/relay-tickets/{ticket_id}/status",
            post(relay_ticket_status),
        )
        .route_layer(rate_gate(BodyRateGate::TicketRead));
    let punch_body_routes = Router::new()
        .route("/v3/punch/register", post(punch_register_v3))
        .route("/v4/punch/register", post(punch_register_v4))
        .route_layer(rate_gate(BodyRateGate::Punch));

    Router::new()
        .merge(general_body_routes)
        .merge(ticket_read_body_routes)
        .merge(punch_body_routes)
        .route("/lookup/{id}", get(legacy_presence_lookup_gone))
        .route("/v3/identity/{id}", get(legacy_identity_lookup))
        .route("/v4/protocol", get(protocol_v4))
        .route("/punch", post(legacy_punch_gone))
        .route("/punch/{id}", get(legacy_punch_gone))
        .route("/v2/punch/register", post(legacy_punch_gone))
        .route("/v2/punch/poll", post(legacy_punch_gone))
        .route("/v2/punch/ack", post(legacy_punch_gone))
        .route("/v4/channels/directory", get(channel_directory_v4))
        .route("/v4/channels/deleted", get(channel_deleted_v4))
        .route("/v2/relay-tickets/offer", post(legacy_punch_gone))
        .route("/v2/relay-tickets/poll", post(legacy_punch_gone))
        .route("/v3/relay-tickets/poll", post(legacy_punch_gone))
        .route("/v2/relay/{ticket_id}", get(relay_ws))
        .route("/relay/{session_id}", get(legacy_relay_gone))
        .route("/relay-invite", post(legacy_relay_gone))
        .route("/relay-invites/{id}", get(legacy_relay_gone))
        // No `/bootstrap`: the Ember DHT joins through the KAD bridge, peer
        // exchange, DHT gossip, and its persisted contact file, so the
        // rendezvous never learns a node's DHT identity or address. Keeping a
        // central pool would have handed the operator an identity-to-IP map
        // for every participant, which is the opposite of what the overlay is
        // for.
        .route("/health", get(health))
        .route("/stats", get(stats_handler))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ember_rendezvous=info".into()),
        )
        .init();

    // Pins the replay guard's monotonic base to the wall clock at startup.
    ReplayNow::current();
    let state = AppState {
        store: Arc::new(RwLock::new(HashMap::new())),
        capability_store: Arc::new(RwLock::new(HashMap::new())),
        rate_limits: Arc::new(RwLock::new(RateBucket::default())),
        legacy_identity_rate_limits: Arc::new(RwLock::new(RateBucket::default())),
        ticket_read_rate_limits: Arc::new(RwLock::new(RateBucket::default())),
        punch_rate_limits: Arc::new(RwLock::new(RateBucket::default())),
        channel_create_rate_limits: Arc::new(RwLock::new(RateBucket::default())),
        channel_create_network_rate_limits: Arc::new(RwLock::new(RateBucket::default())),
        punch_requests: Arc::new(RwLock::new(PunchStore::default())),
        relay_sessions: Arc::new(RwLock::new(HashMap::new())),
        bridged_relays: Arc::new(RwLock::new(HashMap::new())),
        relay_admissions: Arc::new(RwLock::new(HashMap::new())),
        relay_network_counts: Arc::new(RwLock::new(HashMap::new())),
        next_relay_reservation_id: Arc::new(AtomicU64::new(1)),
        relay_tickets: Arc::new(RwLock::new(RelayTicketStore::default())),
        relay_token_key: {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            key
        },
        replay_guard: Arc::new(RwLock::new(ReplayGuard::default())),
        store_purge: Arc::new(PurgeThrottle::default()),
        capability_purge: Arc::new(PurgeThrottle::default()),
        poll_read_nonces: Arc::new(RwLock::new(ScopedNonceCache::new())),
        status_read_nonces: Arc::new(RwLock::new(ScopedNonceCache::new())),
        started_at: Instant::now(),
        channels_registry: load_channels_registry(),
        registry_persister: Arc::new(RegistryPersister::default()),
    };

    tokio::spawn(sweep_expired(state.clone()));
    let channels_registry = state.channels_registry.clone();
    let registry_persister = state.registry_persister.clone();
    tokio::spawn(flush_channels_registry_periodically(
        channels_registry.clone(),
        registry_persister.clone(),
    ));

    let app = build_router(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("rendezvous server listening on {}", addr);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to {addr}: {e}");
            std::process::exit(1);
        }
    };
    let ordinary = Arc::new(tokio::sync::Semaphore::new(
        MAX_HTTP_CONNECTIONS - RESERVED_HEALTH_CONNECTIONS,
    ));
    let health_reserve = Arc::new(tokio::sync::Semaphore::new(RESERVED_HEALTH_CONNECTIONS));
    let network_limiter = NetworkConnectionLimiter::default();
    let mut shutdown = Box::pin(shutdown_signal());
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, peer_addr) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        warn!("HTTP accept failed: {error}");
                        continue;
                    }
                };
                let network_slot = Arc::new(std::sync::Mutex::new(None));
                let (permit, reserve_only) = match ordinary.clone().try_acquire_owned() {
                    Ok(permit) => (permit, false),
                    Err(_) => match health_reserve.clone().try_acquire_owned() {
                        Ok(permit) => (permit, true),
                        Err(_) => {
                            drop(stream);
                            continue;
                        }
                    },
                };
                let app = app.clone();
                let network_limiter = network_limiter.clone();
                tokio::spawn(async move {
                    use tower::ServiceExt;
                    let _permit = permit;
                    let service = hyper::service::service_fn(
                        move |request: hyper::Request<hyper::body::Incoming>| {
                            let app = app.clone();
                            let network_limiter = network_limiter.clone();
                            let network_slot = network_slot.clone();
                            async move {
                                let path = request.uri().path().to_owned();
                                if !http_path_admitted(reserve_only, &path) {
                                    let response = hyper::Response::builder()
                                        .status(StatusCode::SERVICE_UNAVAILABLE)
                                        .header("connection", "close")
                                        .body(axum::body::Body::from("reserved for health"))
                                        .expect("static HTTP response is valid");
                                    return Ok::<_, std::convert::Infallible>(response);
                                }
                                if !admit_client_network(
                                    &network_limiter,
                                    &network_slot,
                                    &path,
                                    extract_client_ip(request.headers(), peer_addr),
                                ) {
                                    let response = hyper::Response::builder()
                                        .status(StatusCode::TOO_MANY_REQUESTS)
                                        .header("connection", "close")
                                        .body(axum::body::Body::from(
                                            "too many connections from this network",
                                        ))
                                        .expect("static HTTP response is valid");
                                    return Ok::<_, std::convert::Infallible>(response);
                                }
                                let mut request = request.map(axum::body::Body::new);
                                request.extensions_mut().insert(ConnectInfo(peer_addr));
                                let mut response = match tokio::time::timeout(
                                    HTTP_REQUEST_TIMEOUT,
                                    app.oneshot(request),
                                )
                                .await
                                {
                                    Ok(response) => {
                                        response.expect("axum router is infallible")
                                    }
                                    Err(_) => hyper::Response::builder()
                                        .status(StatusCode::REQUEST_TIMEOUT)
                                        .header("connection", "close")
                                        .body(axum::body::Body::from(
                                            "request processing timed out",
                                        ))
                                        .expect("static HTTP response is valid"),
                                };
                                // Admission is per TCP connection. Close
                                // ordinary HTTP/1.1 responses so a client
                                // cannot retain one of the finite permits
                                // indefinitely with cheap keep-alive traffic.
                                // A successful WebSocket upgrade owns its
                                // liveness through the relay/session loops.
                                if response.status() != StatusCode::SWITCHING_PROTOCOLS {
                                    response.headers_mut().insert(
                                        "connection",
                                        HeaderValue::from_static("close"),
                                    );
                                }
                                Ok::<_, std::convert::Infallible>(response)
                            }
                        },
                    );
                    let io = hyper_util::rt::TokioIo::new(IdleTimeoutStream::new(
                        stream,
                        HTTP_IDLE_TIMEOUT,
                    ));
                    // This listener deliberately serves HTTP/1.1 only. A
                    // single HTTP/2 connection can carry endless control
                    // frames and many streams while holding one admission
                    // permit; HTTP/1.1 lets the per-request deadline bound a
                    // slow body and leaves upgraded WebSockets to relay-level
                    // liveness limits.
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    builder
                        .timer(hyper_util::rt::TokioTimer::new())
                        .header_read_timeout(HTTP_HEADER_TIMEOUT)
                        .max_buf_size(32 * 1024);
                    if let Err(error) = builder
                        .serve_connection(io, service)
                        .with_upgrades()
                        .await
                    {
                        debug!("HTTP connection from {peer_addr} closed: {error}");
                    }
                });
            }
        }
    }
    if close_channels_registry(&channels_registry, &registry_persister).await {
        info!("channels registry flushed for shutdown");
    } else {
        warn!("could not flush the channels registry at shutdown");
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let term = signal(SignalKind::terminate());
        let int = signal(SignalKind::interrupt());
        match (term, int) {
            (Ok(mut term), Ok(mut int)) => {
                tokio::select! {
                    _ = term.recv() => {},
                    _ = int.recv() => {},
                }
            }
            (Err(e), _) | (_, Err(e)) => {
                tracing::warn!("Failed to register signal handler: {e}, falling back to ctrl_c");
                tokio::signal::ctrl_c().await.ok();
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
    }
    info!("shutdown signal received");
}

#[cfg(test)]
mod relay_ticket_tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn test_state() -> AppState {
        AppState {
            store: Arc::new(RwLock::new(HashMap::new())),
            capability_store: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(RwLock::new(RateBucket::default())),
            legacy_identity_rate_limits: Arc::new(RwLock::new(RateBucket::default())),
            ticket_read_rate_limits: Arc::new(RwLock::new(RateBucket::default())),
            punch_rate_limits: Arc::new(RwLock::new(RateBucket::default())),
            channel_create_rate_limits: Arc::new(RwLock::new(RateBucket::default())),
            channel_create_network_rate_limits: Arc::new(RwLock::new(RateBucket::default())),
            punch_requests: Arc::new(RwLock::new(PunchStore::default())),
            relay_sessions: Arc::new(RwLock::new(HashMap::new())),
            bridged_relays: Arc::new(RwLock::new(HashMap::new())),
            relay_admissions: Arc::new(RwLock::new(HashMap::new())),
            relay_network_counts: Arc::new(RwLock::new(HashMap::new())),
            next_relay_reservation_id: Arc::new(AtomicU64::new(1)),
            relay_tickets: Arc::new(RwLock::new(RelayTicketStore::default())),
            relay_token_key: [0x5a; 32],
            replay_guard: Arc::new(RwLock::new(ReplayGuard::default())),
            store_purge: Arc::new(PurgeThrottle::default()),
            capability_purge: Arc::new(PurgeThrottle::default()),
            poll_read_nonces: Arc::new(RwLock::new(ScopedNonceCache::new())),
            status_read_nonces: Arc::new(RwLock::new(ScopedNonceCache::new())),
            started_at: Instant::now(),
            channels_registry: Arc::new(RwLock::new(registry::ChannelRegistry::in_memory())),
            registry_persister: Arc::new(RegistryPersister::default()),
        }
    }

    async fn insert_test_identity(
        state: &AppState,
        seed: u8,
    ) -> (ed25519_dalek::SigningKey, String, [u8; 32]) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let pubkey = key.verifying_key().to_bytes();
        let id = id_from_pubkey(&pubkey);
        state.store.write().await.insert(
            id.clone(),
            PresenceEntry {
                expires_at: Instant::now() + ENTRY_TTL,
                pubkey,
            },
        );
        (key, id, pubkey)
    }

    #[tokio::test]
    async fn stable_id_presence_lookup_is_denied() {
        assert_eq!(legacy_presence_lookup_gone().await, StatusCode::GONE);
    }

    #[test]
    fn pairwise_capability_rejects_unbound_sybil_peer() {
        let authorized = [0x11; 32];
        let entry = PairwisePresenceEntry {
            ip: "8.8.8.8".parse().unwrap(),
            port: 4662,
            expires_at: Instant::now() + Duration::from_secs(30),
            peer_pubkey: authorized,
            open_intro: false,
            pubkey: [0x22; 32],
            epoch: 7,
            legacy_proof: None,
            v4_proof: Some((now_unix_secs(), [0; 64])),
        };
        assert!(capability_allows_peer(
            &entry,
            &authorized,
            7,
            Instant::now()
        ));
        assert!(!capability_allows_peer(
            &entry,
            &[0x33; 32],
            7,
            Instant::now()
        ));
        let open = PairwisePresenceEntry {
            open_intro: true,
            ..entry.clone()
        };
        assert!(capability_allows_peer(
            &open,
            &[0x33; 32],
            7,
            Instant::now()
        ));
    }

    #[test]
    fn capability_owner_pin_allows_refresh_and_expired_reclaim() {
        let owner = [0x22; 32];
        let claimant = [0x33; 32];
        let now = Instant::now();
        let entry = PairwisePresenceEntry {
            ip: "8.8.8.8".parse().unwrap(),
            port: 4662,
            expires_at: now + Duration::from_secs(30),
            peer_pubkey: owner,
            open_intro: true,
            pubkey: owner,
            epoch: 7,
            legacy_proof: None,
            v4_proof: None,
        };

        assert!(capability_owner_allows_register(&entry, &owner, now));
        assert!(!capability_owner_allows_register(&entry, &claimant, now));

        let expired = PairwisePresenceEntry {
            expires_at: now
                .checked_sub(Duration::from_secs(1))
                .expect("instant supports a one-second subtraction"),
            ..entry
        };
        assert!(capability_owner_allows_register(&expired, &claimant, now));
    }

    #[tokio::test]
    async fn intro_capability_registration_allows_any_registered_lookup() {
        let state = test_state();
        let (bob, _bob_id, bob_pubkey) = insert_test_identity(&state, 5).await;
        let (alice, alice_id, alice_pubkey) = insert_test_identity(&state, 3).await;
        let epoch = now_unix_secs().div_euclid(15 * 60);
        // The server recomputes this derivation, so an intro registration only
        // succeeds for the key the capability actually belongs to.
        let capability = derive_intro_presence_capability(&bob_pubkey, epoch);
        let register_ts = now_unix_secs();
        let register_message = build_capability_register_v4_msg(
            &capability,
            epoch,
            4662,
            &encode_signed_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
            &bob_pubkey,
            &bob_pubkey,
            register_ts,
        );
        let legacy_register_message = build_capability_register_v3_msg(
            &capability,
            epoch,
            4662,
            [8, 8, 4, 4],
            &bob_pubkey,
            &bob_pubkey,
            register_ts,
        );
        assert_eq!(
            capability_register_v4(
                State(state.clone()),
                ConnectInfo("8.8.8.8:1000".parse().unwrap()),
                HeaderMap::new(),
                Json(CapabilityRegisterRequest {
                    capability: hex::encode(capability),
                    epoch,
                    port: 4662,
                    ip: "8.8.4.4".to_string(),
                    pubkey: hex::encode(bob_pubkey),
                    peer_pubkey: hex::encode(bob_pubkey),
                    ts: register_ts,
                    sig: hex::encode(bob.sign(&register_message).to_bytes()),
                    intro: true,
                    legacy_sig: Some(hex::encode(bob.sign(&legacy_register_message).to_bytes())),
                    intro_key: None,
                }),
            )
            .await,
            StatusCode::OK
        );

        let nonce = [0x2A; 16];
        let lookup_ts = now_unix_secs();
        let alice_raw = decode_hex_id(&alice_id).unwrap();
        let lookup_message = build_capability_lookup_v4_msg(
            &capability,
            epoch,
            &alice_raw,
            &alice_pubkey,
            &nonce,
            lookup_ts,
        );
        let response = capability_lookup_v4(
            State(state.clone()),
            ConnectInfo("1.1.1.1:2000".parse().unwrap()),
            HeaderMap::new(),
            Json(CapabilityLookupRequest {
                capability: hex::encode(capability),
                epoch,
                requester_id: alice_id,
                requester_pubkey: hex::encode(alice_pubkey),
                nonce: hex::encode(nonce),
                ts: lookup_ts,
                sig: hex::encode(alice.sign(&lookup_message).to_bytes()),
            }),
        )
        .await
        .expect("intro lookup should succeed for any registered peer");
        assert_eq!(response.0.ip, "8.8.4.4");
        assert_eq!(response.0.port, 4662);
        assert_eq!(response.0.pubkey, hex::encode(bob_pubkey));

        // An `ember2:` friend code intentionally exposes enough public data for
        // anyone to derive the owner's current intro capability, so a registered
        // attacker can produce a perfectly valid signature over it with their
        // own identity. The namespace still belongs to the key it derives from.
        let attacker_message = build_capability_register_v4_msg(
            &capability,
            epoch,
            4663,
            &encode_signed_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            &alice_pubkey,
            &alice_pubkey,
            register_ts,
        );
        let attacker_legacy_message = build_capability_register_v3_msg(
            &capability,
            epoch,
            4663,
            [1, 1, 1, 1],
            &alice_pubkey,
            &alice_pubkey,
            register_ts,
        );
        assert_eq!(
            capability_register_v4(
                State(state.clone()),
                ConnectInfo("1.1.1.1:1000".parse().unwrap()),
                HeaderMap::new(),
                Json(CapabilityRegisterRequest {
                    capability: hex::encode(capability),
                    epoch,
                    port: 4663,
                    ip: "1.1.1.1".to_string(),
                    pubkey: hex::encode(alice_pubkey),
                    peer_pubkey: hex::encode(alice_pubkey),
                    ts: register_ts,
                    sig: hex::encode(alice.sign(&attacker_message).to_bytes()),
                    intro: true,
                    legacy_sig: Some(hex::encode(alice.sign(&attacker_legacy_message).to_bytes(),)),
                    intro_key: None,
                }),
            )
            .await,
            StatusCode::FORBIDDEN,
            "an intro capability may only be registered by the key it derives from"
        );
        let entry = state
            .capability_store
            .read()
            .await
            .get(&hex::encode(capability))
            .cloned()
            .expect("the owner's live capability remains");
        assert_eq!(entry.pubkey, bob_pubkey);
        assert_eq!(entry.ip, "8.8.4.4".parse::<IpAddr>().unwrap());
        assert_eq!(entry.port, 4662);
    }

    /// The derivation proof only gates `intro: true`, so a pairwise registration
    /// can name a victim's derivable intro capability and skip it. Owner pinning
    /// must not then lock the real owner out of its own namespace — before the
    /// pin existed the owner's next heartbeat simply overwrote such a squat, and
    /// that must stay true.
    #[tokio::test]
    async fn a_proved_intro_owner_reclaims_a_namespace_squatted_as_pairwise() {
        let state = test_state();
        let (attacker, _attacker_id, attacker_pubkey) = insert_test_identity(&state, 3).await;
        let (victim, _victim_id, victim_pubkey) = insert_test_identity(&state, 5).await;
        let epoch = now_unix_secs().div_euclid(15 * 60);
        let register_ts = now_unix_secs();
        let capability = derive_intro_presence_capability(&victim_pubkey, epoch);

        let squat = |port: u16, octet: u8| {
            let signed_ip = encode_signed_ip(IpAddr::V4(Ipv4Addr::new(octet, 1, 1, 1)));
            let message = build_capability_register_v4_msg(
                &capability,
                epoch,
                port,
                &signed_ip,
                &attacker_pubkey,
                &attacker_pubkey,
                register_ts,
            );
            CapabilityRegisterRequest {
                capability: hex::encode(capability),
                epoch,
                port,
                ip: format!("{octet}.1.1.1"),
                pubkey: hex::encode(attacker_pubkey),
                peer_pubkey: hex::encode(attacker_pubkey),
                ts: register_ts,
                sig: hex::encode(attacker.sign(&message).to_bytes()),
                // Skipping the derivation proof is the whole point of the squat.
                intro: false,
                legacy_sig: None,
                intro_key: None,
            }
        };

        assert_eq!(
            capability_register_v4(
                State(state.clone()),
                ConnectInfo("1.1.1.1:1000".parse().unwrap()),
                HeaderMap::new(),
                Json(squat(4663, 1)),
            )
            .await,
            StatusCode::OK,
            "a pairwise registration for an unclaimed key is accepted"
        );

        let owner_message = build_capability_register_v4_msg(
            &capability,
            epoch,
            4662,
            &encode_signed_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
            &victim_pubkey,
            &victim_pubkey,
            register_ts,
        );
        assert_eq!(
            capability_register_v4(
                State(state.clone()),
                ConnectInfo("8.8.4.4:1000".parse().unwrap()),
                HeaderMap::new(),
                Json(CapabilityRegisterRequest {
                    capability: hex::encode(capability),
                    epoch,
                    port: 4662,
                    ip: "8.8.4.4".to_string(),
                    pubkey: hex::encode(victim_pubkey),
                    peer_pubkey: hex::encode(victim_pubkey),
                    ts: register_ts,
                    sig: hex::encode(victim.sign(&owner_message).to_bytes()),
                    intro: true,
                    legacy_sig: None,
                    intro_key: None,
                }),
            )
            .await,
            StatusCode::OK,
            "the derivation-proved owner must reclaim its own namespace"
        );

        let entry = state
            .capability_store
            .read()
            .await
            .get(&hex::encode(capability))
            .cloned()
            .expect("the reclaimed capability is present");
        assert_eq!(entry.pubkey, victim_pubkey);
        assert!(entry.open_intro, "the reclaimed entry is intro presence");
        assert_eq!(entry.ip, "8.8.4.4".parse::<IpAddr>().unwrap());

        assert_eq!(
            capability_register_v4(
                State(state.clone()),
                ConnectInfo("2.1.1.1:1000".parse().unwrap()),
                HeaderMap::new(),
                Json(squat(4664, 2)),
            )
            .await,
            StatusCode::FORBIDDEN,
            "the squatter cannot take a live owned namespace back"
        );
    }

    /// Owner pinning alone would leave an unclaimed epoch open: whoever
    /// registers first wins, so an attacker holding a public friend code could
    /// take the victim's namespace at each epoch rollover and suppress their
    /// friend-code discovery. Verifying the derivation refuses the claim
    /// outright, with no live entry needed to defend it.
    #[tokio::test]
    async fn intro_capability_cannot_be_squatted_before_its_owner_registers() {
        let state = test_state();
        let (alice, _alice_id, alice_pubkey) = insert_test_identity(&state, 3).await;
        let victim_pubkey = [0x77; 32];
        let epoch = now_unix_secs().div_euclid(15 * 60);
        let register_ts = now_unix_secs();
        let capability = derive_intro_presence_capability(&victim_pubkey, epoch);
        let squat_message = build_capability_register_v4_msg(
            &capability,
            epoch,
            4663,
            &encode_signed_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            &alice_pubkey,
            &alice_pubkey,
            register_ts,
        );

        assert_eq!(
            capability_register_v4(
                State(state.clone()),
                ConnectInfo("1.1.1.1:1000".parse().unwrap()),
                HeaderMap::new(),
                Json(CapabilityRegisterRequest {
                    capability: hex::encode(capability),
                    epoch,
                    port: 4663,
                    ip: "1.1.1.1".to_string(),
                    pubkey: hex::encode(alice_pubkey),
                    peer_pubkey: hex::encode(alice_pubkey),
                    ts: register_ts,
                    sig: hex::encode(alice.sign(&squat_message).to_bytes()),
                    intro: true,
                    legacy_sig: None,
                    intro_key: None,
                }),
            )
            .await,
            StatusCode::FORBIDDEN,
            "an unclaimed intro namespace must not be squattable by a stranger"
        );
        assert!(
            state.capability_store.read().await.is_empty(),
            "a refused squat must not leave presence behind"
        );
    }

    /// The client's per-epoch key derivation, kept here only so the tests can
    /// produce what a real `ember3:` owner sends.
    fn client_intro_epoch_key(owner: &[u8; 32], intro_secret: &[u8; 16], epoch: i64) -> [u8; 32] {
        let mut input = [0u8; 48];
        input[..32].copy_from_slice(owner);
        input[32..].copy_from_slice(intro_secret);
        blake3::derive_key(&format!("ember-intro-epoch-key-v2:{epoch}"), &input)
    }

    #[allow(clippy::too_many_arguments)]
    fn intro_register_request(
        key: &ed25519_dalek::SigningKey,
        capability: &[u8; 32],
        epoch: i64,
        port: u16,
        octet: u8,
        intro: bool,
        intro_key: Option<String>,
    ) -> CapabilityRegisterRequest {
        let pubkey = key.verifying_key().to_bytes();
        let ts = now_unix_secs();
        let message = build_capability_register_v4_msg(
            capability,
            epoch,
            port,
            &encode_signed_ip(IpAddr::V4(Ipv4Addr::new(octet, 8, 4, 4))),
            &pubkey,
            &pubkey,
            ts,
        );
        CapabilityRegisterRequest {
            capability: hex::encode(capability),
            epoch,
            port,
            ip: format!("{octet}.8.4.4"),
            pubkey: hex::encode(pubkey),
            peer_pubkey: hex::encode(pubkey),
            ts,
            sig: hex::encode(key.sign(&message).to_bytes()),
            intro,
            legacy_sig: None,
            intro_key,
        }
    }

    async fn register_v4(state: &AppState, request: CapabilityRegisterRequest) -> StatusCode {
        capability_register_v4(
            State(state.clone()),
            ConnectInfo("8.8.8.8:1000".parse().unwrap()),
            HeaderMap::new(),
            Json(request),
        )
        .await
    }

    #[tokio::test]
    async fn the_protocol_probe_advertises_sealed_intro() {
        let Json(body) = protocol_v4().await;
        assert_eq!(body["version"], 4);
        assert_eq!(body["sealed_intro"], true);
    }

    #[test]
    fn sealed_intro_derivation_matches_the_client() {
        let owner = [0x42u8; 32];
        let epoch_key = client_intro_epoch_key(&owner, &[0x07; 16], 9);
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&owner);
        input[32..].copy_from_slice(&epoch_key);
        assert_eq!(
            derive_sealed_intro_presence_capability(&owner, &epoch_key, 9),
            blake3::derive_key("ember-intro-presence-v2:9", &input)
        );
        assert_ne!(
            derive_sealed_intro_presence_capability(&owner, &epoch_key, 9),
            derive_intro_presence_capability(&owner, 9)
        );
    }

    /// An `ember3:` owner registers a capability the server cannot derive from
    /// the public key, proves it with the epoch key, and gets open-intro
    /// presence any registered peer can resolve.
    #[tokio::test]
    async fn sealed_intro_registration_is_accepted_as_open_intro() {
        let state = test_state();
        let (bob, _bob_id, bob_pubkey) = insert_test_identity(&state, 5).await;
        let (alice, alice_id, alice_pubkey) = insert_test_identity(&state, 3).await;
        let epoch = now_unix_secs().div_euclid(15 * 60);
        let epoch_key = client_intro_epoch_key(&bob_pubkey, &[0x5A; 16], epoch);
        let capability = derive_sealed_intro_presence_capability(&bob_pubkey, &epoch_key, epoch);

        assert_eq!(
            register_v4(
                &state,
                intro_register_request(&bob, &capability, epoch, 4662, 8, true, Some(hex::encode(epoch_key))),
            )
            .await,
            StatusCode::OK
        );
        let entry = state
            .capability_store
            .read()
            .await
            .get(&hex::encode(capability))
            .cloned()
            .expect("sealed intro stored");
        assert!(entry.open_intro);
        assert_eq!(entry.pubkey, bob_pubkey);

        let nonce = [0x2B; 16];
        let lookup_ts = now_unix_secs();
        let alice_raw = decode_hex_id(&alice_id).unwrap();
        let lookup_message = build_capability_lookup_v4_msg(
            &capability,
            epoch,
            &alice_raw,
            &alice_pubkey,
            &nonce,
            lookup_ts,
        );
        let response = capability_lookup_v4(
            State(state.clone()),
            ConnectInfo("1.1.1.1:2000".parse().unwrap()),
            HeaderMap::new(),
            Json(CapabilityLookupRequest {
                capability: hex::encode(capability),
                epoch,
                requester_id: alice_id,
                requester_pubkey: hex::encode(alice_pubkey),
                nonce: hex::encode(nonce),
                ts: lookup_ts,
                sig: hex::encode(alice.sign(&lookup_message).to_bytes()),
            }),
        )
        .await
        .expect("a code holder can resolve the sealed intro");
        assert_eq!(response.0.pubkey, hex::encode(bob_pubkey));
        assert_eq!(response.0.port, 4662);
    }

    /// Holding someone's `ember3:` code yields their secret and so their
    /// capability, but not a claim to it: the proof is recomputed under the
    /// registrant's own key.
    #[tokio::test]
    async fn a_code_holder_cannot_claim_a_sealed_intro() {
        let state = test_state();
        let (_bob, _bob_id, bob_pubkey) = insert_test_identity(&state, 5).await;
        let (alice, _alice_id, _alice_pubkey) = insert_test_identity(&state, 3).await;
        let epoch = now_unix_secs().div_euclid(15 * 60);
        let epoch_key = client_intro_epoch_key(&bob_pubkey, &[0x5A; 16], epoch);
        let capability = derive_sealed_intro_presence_capability(&bob_pubkey, &epoch_key, epoch);

        assert_eq!(
            register_v4(
                &state,
                intro_register_request(&alice, &capability, epoch, 4663, 1, true, Some(hex::encode(epoch_key))),
            )
            .await,
            SEALED_INTRO_REJECTED
        );
        assert_eq!(
            register_v4(
                &state,
                intro_register_request(&alice, &capability, epoch, 4664, 1, true, None),
            )
            .await,
            StatusCode::FORBIDDEN,
            "a sealed capability is not a valid legacy intro either"
        );
        assert!(state.capability_store.read().await.is_empty());
    }

    #[tokio::test]
    async fn malformed_or_misplaced_intro_keys_are_refused() {
        let state = test_state();
        let (bob, _bob_id, bob_pubkey) = insert_test_identity(&state, 5).await;
        let epoch = now_unix_secs().div_euclid(15 * 60);
        let epoch_key = client_intro_epoch_key(&bob_pubkey, &[0x5A; 16], epoch);
        let capability = derive_sealed_intro_presence_capability(&bob_pubkey, &epoch_key, epoch);

        assert_eq!(
            register_v4(
                &state,
                intro_register_request(&bob, &capability, epoch, 4662, 8, false, Some(hex::encode(epoch_key))),
            )
            .await,
            SEALED_INTRO_REJECTED,
            "an intro key on a pairwise registration is refused"
        );
        assert_eq!(
            register_v4(
                &state,
                intro_register_request(&bob, &capability, epoch, 4663, 8, true, Some("zz".repeat(32))),
            )
            .await,
            SEALED_INTRO_REJECTED
        );
        assert_eq!(
            register_v4(
                &state,
                intro_register_request(&bob, &capability, epoch, 4664, 8, true, Some(hex::encode([0u8; 16]))),
            )
            .await,
            SEALED_INTRO_REJECTED
        );
        assert_eq!(
            register_v4(
                &state,
                intro_register_request(&bob, &capability, epoch, 4665, 8, true, Some(hex::encode([0x11u8; 32]))),
            )
            .await,
            SEALED_INTRO_REJECTED,
            "a key that does not derive the capability is no proof"
        );
        assert!(state.capability_store.read().await.is_empty());
    }

    /// Only a sealed-intro-specific refusal uses `SEALED_INTRO_REJECTED`; the
    /// generic failures a correct sealed registration can still hit keep
    /// their own statuses, so the client does not mistake them for "sealed
    /// intro unsupported" and downgrade.
    #[tokio::test]
    async fn generic_rejections_of_a_valid_sealed_intro_keep_their_own_status() {
        let state = test_state();
        let bob = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
        let bob_pubkey = bob.verifying_key().to_bytes();
        let epoch = now_unix_secs().div_euclid(15 * 60);
        let epoch_key = client_intro_epoch_key(&bob_pubkey, &[0x5A; 16], epoch);
        let capability = derive_sealed_intro_presence_capability(&bob_pubkey, &epoch_key, epoch);

        // Owner not registered, as after a server restart.
        assert_eq!(
            register_v4(
                &state,
                intro_register_request(&bob, &capability, epoch, 4662, 8, true, Some(hex::encode(epoch_key))),
            )
            .await,
            StatusCode::FORBIDDEN
        );

        insert_test_identity(&state, 5).await;
        let mut stale =
            intro_register_request(&bob, &capability, epoch, 4663, 8, true, Some(hex::encode(epoch_key)));
        stale.ts -= 24 * 3600;
        assert_eq!(register_v4(&state, stale).await, StatusCode::BAD_REQUEST);
        assert!(state.capability_store.read().await.is_empty());
    }

    /// Same reclaim guarantee as the legacy intro: a code holder can squat the
    /// namespace as a pairwise entry, and the proved owner takes it back.
    #[tokio::test]
    async fn a_sealed_intro_owner_reclaims_a_namespace_squatted_as_pairwise() {
        let state = test_state();
        let (bob, _bob_id, bob_pubkey) = insert_test_identity(&state, 5).await;
        let (alice, _alice_id, _alice_pubkey) = insert_test_identity(&state, 3).await;
        let epoch = now_unix_secs().div_euclid(15 * 60);
        let epoch_key = client_intro_epoch_key(&bob_pubkey, &[0x5A; 16], epoch);
        let capability = derive_sealed_intro_presence_capability(&bob_pubkey, &epoch_key, epoch);

        assert_eq!(
            register_v4(
                &state,
                intro_register_request(&alice, &capability, epoch, 4663, 1, false, None),
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            register_v4(
                &state,
                intro_register_request(&bob, &capability, epoch, 4662, 8, true, Some(hex::encode(epoch_key))),
            )
            .await,
            StatusCode::OK
        );
        let entry = state
            .capability_store
            .read()
            .await
            .get(&hex::encode(capability))
            .cloned()
            .expect("reclaimed");
        assert_eq!(entry.pubkey, bob_pubkey);
        assert!(entry.open_intro);
    }

    #[tokio::test]
    async fn signed_pairwise_capability_registration_and_lookup_succeeds() {
        let state = test_state();
        let (alice, alice_id, alice_pubkey) = insert_test_identity(&state, 3).await;
        let (bob, _bob_id, bob_pubkey) = insert_test_identity(&state, 5).await;
        let capability = [0xA7; 32];
        let epoch = now_unix_secs().div_euclid(15 * 60);
        let register_ts = now_unix_secs();
        let legacy_register_message = build_capability_register_v3_msg(
            &capability,
            epoch,
            4662,
            [8, 8, 4, 4],
            &bob_pubkey,
            &alice_pubkey,
            register_ts,
        );
        let register_message = build_capability_register_v4_msg(
            &capability,
            epoch,
            4662,
            &encode_signed_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
            &bob_pubkey,
            &alice_pubkey,
            register_ts,
        );
        let register_status = capability_register_v4(
            State(state.clone()),
            ConnectInfo("8.8.8.8:1000".parse().unwrap()),
            HeaderMap::new(),
            Json(CapabilityRegisterRequest {
                capability: hex::encode(capability),
                epoch,
                port: 4662,
                ip: "8.8.4.4".to_string(),
                pubkey: hex::encode(bob_pubkey),
                peer_pubkey: hex::encode(alice_pubkey),
                ts: register_ts,
                sig: hex::encode(bob.sign(&register_message).to_bytes()),
                intro: false,
                legacy_sig: Some(hex::encode(bob.sign(&legacy_register_message).to_bytes())),
                intro_key: None,
            }),
        )
        .await;
        assert_eq!(register_status, StatusCode::OK);

        let nonce = [0x19; 16];
        let lookup_ts = now_unix_secs();
        let alice_raw = decode_hex_id(&alice_id).unwrap();
        let lookup_message = build_capability_lookup_v4_msg(
            &capability,
            epoch,
            &alice_raw,
            &alice_pubkey,
            &nonce,
            lookup_ts,
        );
        let response = capability_lookup_v4(
            State(state.clone()),
            ConnectInfo("1.1.1.1:2000".parse().unwrap()),
            HeaderMap::new(),
            Json(CapabilityLookupRequest {
                capability: hex::encode(capability),
                epoch,
                requester_id: alice_id.clone(),
                requester_pubkey: hex::encode(alice_pubkey),
                nonce: hex::encode(nonce),
                ts: lookup_ts,
                sig: hex::encode(alice.sign(&lookup_message).to_bytes()),
            }),
        )
        .await
        .expect("authorized capability lookup");
        assert!(response.0.acknowledged);
        assert_eq!(response.0.ip, "8.8.4.4");
        assert_eq!(response.0.proof_version, Some(4));

        let legacy_nonce = [0x1A; 16];
        let legacy_ts = now_unix_secs();
        let legacy_lookup_message = build_capability_lookup_v3_msg(
            &capability,
            epoch,
            &alice_raw,
            &alice_pubkey,
            &legacy_nonce,
            legacy_ts,
        );
        let legacy_response = capability_lookup_v3(
            State(state),
            ConnectInfo("1.1.1.1:2002".parse().unwrap()),
            HeaderMap::new(),
            Json(CapabilityLookupRequest {
                capability: hex::encode(capability),
                epoch,
                requester_id: alice_id,
                requester_pubkey: hex::encode(alice_pubkey),
                nonce: hex::encode(legacy_nonce),
                ts: legacy_ts,
                sig: hex::encode(alice.sign(&legacy_lookup_message).to_bytes()),
            }),
        )
        .await
        .expect("old client can verify the mirrored legacy proof");
        assert_eq!(legacy_response.0.proof_version, None);
    }

    #[tokio::test]
    async fn old_client_payloads_work_on_new_server_legacy_routes() {
        let state = test_state();
        let (alice, alice_id, alice_pubkey) = insert_test_identity(&state, 31).await;
        let (bob, bob_id, bob_pubkey) = insert_test_identity(&state, 32).await;
        let identity = legacy_identity_lookup(
            State(state.clone()),
            ConnectInfo("9.9.9.9:9000".parse().unwrap()),
            HeaderMap::new(),
            Path(bob_id),
        )
        .await
        .expect("temporary legacy identity route supports old clients");
        assert_eq!(identity.0.pubkey, hex::encode(bob_pubkey));
        let capability = [0xB7; 32];
        let epoch = now_unix_secs().div_euclid(15 * 60);
        let register_ts = now_unix_secs();
        let register_message = build_capability_register_v3_msg(
            &capability,
            epoch,
            4662,
            [8, 8, 4, 4],
            &bob_pubkey,
            &alice_pubkey,
            register_ts,
        );
        let status = capability_register_v3(
            State(state.clone()),
            ConnectInfo("8.8.8.8:1000".parse().unwrap()),
            HeaderMap::new(),
            Json(CapabilityRegisterRequest {
                capability: hex::encode(capability),
                epoch,
                port: 4662,
                ip: "8.8.4.4".to_string(),
                pubkey: hex::encode(bob_pubkey),
                peer_pubkey: hex::encode(alice_pubkey),
                ts: register_ts,
                sig: hex::encode(bob.sign(&register_message).to_bytes()),
                intro: false,
                legacy_sig: None,
                intro_key: None,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let nonce = [0x29; 16];
        let lookup_ts = now_unix_secs();
        let alice_raw = decode_hex_id(&alice_id).unwrap();
        let lookup_message = build_capability_lookup_v3_msg(
            &capability,
            epoch,
            &alice_raw,
            &alice_pubkey,
            &nonce,
            lookup_ts,
        );
        let response = capability_lookup_v3(
            State(state.clone()),
            ConnectInfo("1.1.1.1:2000".parse().unwrap()),
            HeaderMap::new(),
            Json(CapabilityLookupRequest {
                capability: hex::encode(capability),
                epoch,
                requester_id: alice_id.clone(),
                requester_pubkey: hex::encode(alice_pubkey),
                nonce: hex::encode(nonce),
                ts: lookup_ts,
                sig: hex::encode(alice.sign(&lookup_message).to_bytes()),
            }),
        )
        .await
        .expect("legacy lookup remains available during rollout");
        assert_eq!(response.0.ip, "8.8.4.4");
        assert_eq!(response.0.proof_version, None);

        let v4_nonce = [0x2A; 16];
        let v4_ts = now_unix_secs();
        let v4_lookup_message = build_capability_lookup_v4_msg(
            &capability,
            epoch,
            &alice_raw,
            &alice_pubkey,
            &v4_nonce,
            v4_ts,
        );
        let v4_response = capability_lookup_v4(
            State(state),
            ConnectInfo("1.1.1.1:2001".parse().unwrap()),
            HeaderMap::new(),
            Json(CapabilityLookupRequest {
                capability: hex::encode(capability),
                epoch,
                requester_id: alice_id,
                requester_pubkey: hex::encode(alice_pubkey),
                nonce: hex::encode(v4_nonce),
                ts: v4_ts,
                sig: hex::encode(alice.sign(&v4_lookup_message).to_bytes()),
            }),
        )
        .await
        .expect("new client can consume an explicitly legacy presence proof");
        assert_eq!(v4_response.0.proof_version, Some(3));
    }

    #[test]
    fn signed_payload_version_vectors_have_distinct_domains_and_opcodes() {
        let legacy = build_capability_register_v3_msg(
            &[1; 32],
            7,
            4662,
            [8, 8, 4, 4],
            &[2; 32],
            &[3; 32],
            9,
        );
        let v4 = build_capability_register_v4_msg(
            &[1; 32],
            7,
            4662,
            &[SIGNED_IP_V4, 8, 8, 4, 4],
            &[2; 32],
            &[3; 32],
            9,
        );
        assert_eq!(&legacy[..RDV_DOMAIN.len()], RDV_DOMAIN);
        assert_eq!(legacy[RDV_DOMAIN.len()], OP_CAPABILITY_REGISTER);
        assert_eq!(&v4[..RDV_V4_DOMAIN.len()], RDV_V4_DOMAIN);
        assert_eq!(v4[RDV_V4_DOMAIN.len()], OP_CAPABILITY_REGISTER_V4);
        assert_eq!(legacy.len() + 1, v4.len());
        assert_ne!(legacy, v4);
    }

    #[test]
    fn v4_punch_registration_matches_desktop_transcript_vector() {
        let transcript = build_punch_register_v4_msg(
            &[0x11; 32],
            &[0x22; 32],
            &[0x33; 32],
            0x0102_0304_0506_0708,
            0x1234,
            &[SIGNED_IP_V4, 8, 8, 4, 4],
            5,
            &[0x44; 16],
            0x1112_1314_1516_1718,
        );
        assert_eq!(
            hex::encode(transcript),
            "656d6265722d7264762d76342311111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333308070605040302013412040808040405444444444444444444444444444444441817161514131211"
        );
    }

    #[test]
    fn legacy_punch_response_shape_omits_all_v4_proof_fields() {
        let value = serde_json::to_value(PunchResponse {
            punch_id: "11".repeat(32),
            from_id: "22".repeat(32),
            ip: "8.8.8.8".to_string(),
            port: 4662,
            nat_type: 1,
            capability: "33".repeat(32),
            epoch: 7,
            proof_version: None,
            register_ts: None,
            register_nonce: None,
            register_sig: None,
            from_pubkey: None,
        })
        .unwrap();
        let object = value.as_object().unwrap();
        for field in [
            "proof_version",
            "register_ts",
            "register_nonce",
            "register_sig",
            "from_pubkey",
        ] {
            assert!(!object.contains_key(field));
        }
    }

    async fn insert_ticket(
        state: &AppState,
        ticket_id: &str,
        expires_at: Instant,
    ) -> (String, String) {
        let initiator_token = issue_relay_role_token(state, ticket_id, RelayRole::Initiator);
        let responder_token = issue_relay_role_token(state, ticket_id, RelayRole::Responder);
        state.relay_tickets.write().await.insert(
            ticket_id.to_owned(),
            RelayTicket {
                initiator_id: "11".repeat(32),
                responder_id: "22".repeat(32),
                capability: [0; 32],
                epoch: 0,
                mailbox_envelope: Vec::new(),
                initiator_token_hash: relay_token_hash(&initiator_token),
                responder_token_hash: relay_token_hash(&responder_token),
                initiator_joined: false,
                responder_joined: false,
                initiator_reservation: None,
                responder_reservation: None,
                accepted: true,
                expires_at,
            },
        );
        (initiator_token, responder_token)
    }

    async fn join_from(
        state: &AppState,
        ticket_id: &str,
        token: &str,
        ip: &str,
    ) -> Result<RelayRole, StatusCode> {
        admit_relay_ticket_join(state, ticket_id, token, ip.parse().unwrap()).await
    }

    fn ticket_for_test(responder_id: &str, accepted: bool) -> RelayTicket {
        ticket_with_parties(&"11".repeat(32), responder_id, accepted)
    }

    fn ticket_with_parties(initiator_id: &str, responder_id: &str, accepted: bool) -> RelayTicket {
        RelayTicket {
            initiator_id: initiator_id.to_owned(),
            responder_id: responder_id.to_owned(),
            capability: [0; 32],
            epoch: 0,
            mailbox_envelope: Vec::new(),
            initiator_token_hash: [0u8; 32],
            responder_token_hash: [0u8; 32],
            initiator_joined: false,
            responder_joined: false,
            initiator_reservation: None,
            responder_reservation: None,
            accepted,
            expires_at: Instant::now() + Duration::from_secs(30),
        }
    }

    #[test]
    fn current_privacy_operation_codes_are_stable() {
        assert_eq!(OP_RELAY_TICKET_ACCEPT, 0x09);
        assert_eq!(OP_RELAY_TICKET_STATUS, 0x0a);
        assert_eq!(OP_CAPABILITY_REGISTER, 0x0c);
        assert_eq!(OP_CAPABILITY_LOOKUP, 0x0d);
        assert_eq!(OP_RELAY_MAILBOX_OFFER, 0x0e);
        assert_eq!(OP_RELAY_MAILBOX_POLL, 0x0f);
        assert_eq!(OP_PUNCH_REGISTER_V3, 0x10);
        assert_eq!(OP_PUNCH_POLL_V3, 0x11);
        assert_eq!(OP_PUNCH_ACK_V3, 0x12);
        assert_eq!(OP_IDENTITY_LOOKUP_V4, 0x20);
        assert_eq!(OP_CAPABILITY_REGISTER_V4, 0x21);
        assert_eq!(OP_CAPABILITY_LOOKUP_V4, 0x22);
        assert_eq!(OP_PUNCH_REGISTER_V4, 0x23);
        assert_eq!(OP_PUNCH_POLL_V4, 0x24);
        assert_eq!(OP_PUNCH_ACK_V4, 0x25);
        assert_eq!(OP_CHANNEL_USERNAME_V4, 0x26);
        assert_eq!(OP_CHANNEL_NAME_V4, 0x27);
        assert_eq!(OP_CHANNEL_DELETE_V4, 0x28);
        assert_eq!(OP_CHANNEL_NOMINEE_V4, 0x29);
        assert_eq!(OP_CHANNEL_HANDOVER_V4, 0x2a);
        assert_eq!(OP_CHANNEL_NAME_DISPLAY_V4, 0x2b);
    }

    #[test]
    fn repeated_v4_mailbox_reads_are_idempotent() {
        let responder = [1u8; 32];
        let nonce = [2u8; 16];
        let timestamp = 42;
        assert_ne!(
            build_relay_mailbox_poll_msg(&responder, &nonce, timestamp),
            build_relay_mailbox_poll_msg(&[3u8; 32], &nonce, timestamp)
        );

        let mut cache = ScopedNonceCache::new();
        let now = Instant::now();
        assert_eq!(
            admit_idempotent_read_nonce(
                &mut cache,
                responder,
                nonce,
                timestamp,
                now,
                POLL_READ_NONCE_TTL,
                MAX_POLL_READ_NONCES,
            ),
            IdempotentReadAdmission::New
        );
        assert_eq!(
            admit_idempotent_read_nonce(
                &mut cache,
                responder,
                nonce,
                timestamp,
                now,
                POLL_READ_NONCE_TTL,
                MAX_POLL_READ_NONCES,
            ),
            IdempotentReadAdmission::Idempotent
        );
    }

    #[test]
    fn rate_key_is_the_address_for_ipv4_and_the_slash_64_for_ipv6() {
        let v4: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(rate_key(v4), v4, "IPv4 is not grouped, to spare CGNAT neighbours");
        assert_eq!(
            rate_key("::ffff:203.0.113.9".parse().unwrap()),
            v4,
            "a mapped IPv4 address is the same client as the plain one"
        );
        assert_eq!(
            rate_key("2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap()),
            "2001:db8:1:2::".parse::<IpAddr>().unwrap()
        );
        assert_ne!(
            rate_key("2001:db8:1:2::1".parse().unwrap()),
            rate_key("2001:db8:1:3::1".parse().unwrap()),
            "neighbouring /64s stay separate"
        );
    }

    #[tokio::test]
    async fn one_ipv6_slash_64_shares_a_single_general_budget() {
        let state = test_state();
        for i in 0..MAX_REQUESTS_PER_MINUTE {
            let ip: IpAddr = format!("2001:db8:7:7::{:x}", i + 1).parse().unwrap();
            assert!(check_rate_limit(&state, ip).await);
        }
        let rotated: IpAddr = "2001:db8:7:7:ffff:ffff:ffff:ffff".parse().unwrap();
        assert!(
            !check_rate_limit(&state, rotated).await,
            "rotating the interface id must not buy a fresh budget"
        );
        assert!(
            rate_budget_exhausted(&state.rate_limits, rotated, MAX_REQUESTS_PER_MINUTE).await,
            "the pre-body gate must see the same /64 bucket"
        );
        assert!(check_rate_limit(&state, "2001:db8:7:8::1".parse().unwrap()).await);
        assert_eq!(state.rate_limits.read().await.entries.len(), 2);
    }

    #[test]
    fn a_full_rate_bucket_evicts_its_oldest_window_instead_of_refusing() {
        let mut bucket = RateBucket::default();
        let t0 = Instant::now();
        let a: IpAddr = "198.51.100.1".parse().unwrap();
        let b: IpAddr = "198.51.100.2".parse().unwrap();
        let c: IpAddr = "198.51.100.3".parse().unwrap();
        assert!(bucket.charge(a, 5, RATE_WINDOW, t0, 2));
        assert!(bucket.charge(b, 5, RATE_WINDOW, t0 + Duration::from_secs(1), 2));
        assert!(
            bucket.charge(c, 5, RATE_WINDOW, t0 + Duration::from_secs(2), 2),
            "a newcomer is admitted at capacity"
        );
        assert_eq!(bucket.entries.len(), 2);
        assert!(!bucket.entries.contains_key(&a), "the oldest window went");
        assert!(bucket.entries.contains_key(&b) && bucket.entries.contains_key(&c));
        assert_eq!(bucket.by_age.len(), bucket.entries.len());
    }

    #[test]
    fn a_rate_window_reset_moves_the_entry_to_the_young_end() {
        let mut bucket = RateBucket::default();
        let t0 = Instant::now();
        let a: IpAddr = "198.51.100.1".parse().unwrap();
        let b: IpAddr = "198.51.100.2".parse().unwrap();
        let c: IpAddr = "198.51.100.3".parse().unwrap();
        assert!(bucket.charge(a, 5, RATE_WINDOW, t0, 2));
        assert!(bucket.charge(b, 5, RATE_WINDOW, t0 + Duration::from_secs(1), 2));
        // `a`'s window lapses and restarts, so `b` is now the oldest.
        let later = t0 + RATE_WINDOW + Duration::from_secs(1);
        assert!(bucket.charge(a, 5, RATE_WINDOW, later, 2));
        assert!(bucket.charge(c, 5, RATE_WINDOW, later, 2));
        assert!(bucket.entries.contains_key(&a));
        assert!(!bucket.entries.contains_key(&b));
        assert_eq!(bucket.by_age.len(), bucket.entries.len());
    }

    #[test]
    fn rate_bucket_prune_drops_only_lapsed_windows_and_keeps_the_index_in_step() {
        let mut bucket = RateBucket::default();
        let t0 = Instant::now();
        let old: IpAddr = "198.51.100.1".parse().unwrap();
        let fresh: IpAddr = "198.51.100.2".parse().unwrap();
        assert!(bucket.charge(old, 5, RATE_WINDOW, t0, MAX_RATE_ENTRIES));
        assert!(bucket.charge(
            fresh,
            5,
            RATE_WINDOW,
            t0 + RATE_WINDOW,
            MAX_RATE_ENTRIES
        ));
        bucket.prune(t0 + RATE_WINDOW * 2, RATE_WINDOW * 2);
        assert!(!bucket.entries.contains_key(&old));
        assert!(bucket.entries.contains_key(&fresh));
        assert_eq!(bucket.by_age.len(), 1);
    }

    #[test]
    fn a_rate_bucket_still_counts_within_a_window() {
        let mut bucket = RateBucket::default();
        let t0 = Instant::now();
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        for _ in 0..3 {
            assert!(bucket.charge(ip, 3, RATE_WINDOW, t0, MAX_RATE_ENTRIES));
        }
        assert!(!bucket.charge(ip, 3, RATE_WINDOW, t0, MAX_RATE_ENTRIES));
        assert!(bucket.exhausted(ip, 3, RATE_WINDOW, t0));
        assert!(!bucket.exhausted(ip, 3, RATE_WINDOW, t0 + RATE_WINDOW));
    }

    #[tokio::test]
    async fn the_create_budget_is_pooled_per_slash_24_on_top_of_per_address() {
        let state = test_state();
        let per_addr = MAX_CHANNEL_CREATES_PER_HOUR;
        let addresses = MAX_CHANNEL_CREATES_PER_NETWORK_PER_HOUR / per_addr;
        for host in 1..=addresses {
            let ip: IpAddr = format!("203.0.113.{host}").parse().unwrap();
            for _ in 0..per_addr {
                assert!(check_channel_create_rate_limit(&state, ip).await);
            }
            assert!(
                !check_channel_create_rate_limit(&state, ip).await,
                "each address still has its own ceiling"
            );
        }
        assert_eq!(
            state
                .channel_create_network_rate_limits
                .read()
                .await
                .entries
                .get(&"203.0.113.0".parse::<IpAddr>().unwrap())
                .unwrap()
                .count,
            MAX_CHANNEL_CREATES_PER_NETWORK_PER_HOUR,
            "refusals at the per-address tier must not drain the shared pool"
        );
        let next: IpAddr = format!("203.0.113.{}", addresses + 1).parse().unwrap();
        assert!(
            !check_channel_create_rate_limit(&state, next).await,
            "a fresh address in an exhausted /24 gets nothing"
        );
        assert!(
            check_channel_create_rate_limit(&state, "203.0.114.1".parse().unwrap()).await,
            "a neighbouring /24 is unaffected"
        );
    }

    #[test]
    fn an_exhausted_pool_does_not_spend_the_address_allowance() {
        let mut per_address = RateBucket::default();
        let mut per_network = RateBucket::default();
        let t0 = Instant::now();
        let hosts = MAX_CHANNEL_CREATES_PER_NETWORK_PER_HOUR / MAX_CHANNEL_CREATES_PER_HOUR;
        for host in 1..=hosts {
            let ip: IpAddr = format!("203.0.113.{host}").parse().unwrap();
            for _ in 0..MAX_CHANNEL_CREATES_PER_HOUR {
                assert!(admit_channel_create(&mut per_address, &mut per_network, ip, t0));
            }
        }

        let latecomer: IpAddr = "203.0.113.200".parse().unwrap();
        for _ in 0..MAX_CHANNEL_CREATES_PER_HOUR * 2 {
            assert!(
                !admit_channel_create(&mut per_address, &mut per_network, latecomer, t0),
                "the pool is exhausted"
            );
        }
        assert!(
            !per_address.entries.contains_key(&latecomer),
            "refused retries must not touch the address's own count"
        );

        let pool_reset = t0 + CHANNEL_CREATE_WINDOW;
        for _ in 0..MAX_CHANNEL_CREATES_PER_HOUR {
            assert!(
                admit_channel_create(&mut per_address, &mut per_network, latecomer, pool_reset),
                "the full personal allowance survives the pool's recovery"
            );
        }
        assert!(!admit_channel_create(
            &mut per_address,
            &mut per_network,
            latecomer,
            pool_reset
        ));
    }

    #[test]
    fn an_over_limit_address_does_not_drain_the_pool() {
        let mut per_address = RateBucket::default();
        let mut per_network = RateBucket::default();
        let t0 = Instant::now();
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        for _ in 0..MAX_CHANNEL_CREATES_PER_HOUR {
            assert!(admit_channel_create(&mut per_address, &mut per_network, ip, t0));
        }
        for _ in 0..10 {
            assert!(!admit_channel_create(&mut per_address, &mut per_network, ip, t0));
        }
        assert_eq!(
            per_network
                .entries
                .get(&"203.0.113.0".parse::<IpAddr>().unwrap())
                .unwrap()
                .count,
            MAX_CHANNEL_CREATES_PER_HOUR
        );
    }

    #[tokio::test]
    async fn the_create_budget_is_per_slash_64_for_ipv6() {
        let state = test_state();
        for i in 0..MAX_CHANNEL_CREATES_PER_HOUR {
            let ip: IpAddr = format!("2001:db8:9:9::{:x}", i + 1).parse().unwrap();
            assert!(check_channel_create_rate_limit(&state, ip).await);
        }
        assert!(
            !check_channel_create_rate_limit(&state, "2001:db8:9:9::beef".parse().unwrap()).await
        );
    }

    #[tokio::test]
    async fn ticket_read_budget_is_isolated_from_general_requests() {
        let state = test_state();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        for _ in 0..MAX_REQUESTS_PER_MINUTE {
            assert!(check_rate_limit(&state, ip).await);
        }
        assert!(!check_rate_limit(&state, ip).await);
        assert!(check_ticket_read_rate_limit(&state, ip).await);
    }

    #[tokio::test]
    async fn legacy_identity_budget_is_isolated_from_rollout_traffic() {
        let state = test_state();
        let (_, target_id, target_pubkey) = insert_test_identity(&state, 44).await;
        let addr: SocketAddr = "8.8.8.8:4000".parse().unwrap();
        for _ in 0..MAX_REQUESTS_PER_MINUTE {
            assert!(check_rate_limit(&state, addr.ip()).await);
        }
        assert!(!check_rate_limit(&state, addr.ip()).await);

        // A legacy client with nine registered friends can arrive here after
        // ten general mutations. Its independent identity budget must still
        // permit the full bounded compatibility window.
        for _ in 0..MAX_LEGACY_IDENTITY_LOOKUPS_PER_MINUTE {
            let response = legacy_identity_lookup(
                State(state.clone()),
                ConnectInfo(addr),
                HeaderMap::new(),
                Path(target_id.clone()),
            )
            .await
            .expect("legacy identity budget is independent");
            assert_eq!(response.0.pubkey, hex::encode(target_pubkey));
        }
        let denied = legacy_identity_lookup(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            Path(target_id),
        )
        .await;
        assert!(matches!(denied, Err(StatusCode::TOO_MANY_REQUESTS)));
        assert_eq!(
            state
                .rate_limits
                .read()
                .await
                .entries
                .get(&addr.ip())
                .unwrap()
                .count,
            MAX_REQUESTS_PER_MINUTE + 1,
            "legacy reads must not alter the general counter"
        );
    }

    #[tokio::test]
    async fn thirty_v4_rollout_registrations_charge_once_and_store_both_proofs() {
        let state = test_state();
        let (peer, _peer_id, peer_pubkey) = insert_test_identity(&state, 45).await;
        let (owner, _owner_id, owner_pubkey) = insert_test_identity(&state, 46).await;
        let epoch = now_unix_secs().div_euclid(15 * 60);
        let ts = now_unix_secs();
        let addr: SocketAddr = "8.8.8.8:5000".parse().unwrap();

        for index in 0..30u32 {
            let mut capability = [0xC3; 32];
            capability[..4].copy_from_slice(&index.to_le_bytes());
            let v4 = build_capability_register_v4_msg(
                &capability,
                epoch,
                4662,
                &encode_signed_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
                &owner_pubkey,
                &peer_pubkey,
                ts,
            );
            let legacy = build_capability_register_v3_msg(
                &capability,
                epoch,
                4662,
                [8, 8, 4, 4],
                &owner_pubkey,
                &peer_pubkey,
                ts,
            );
            assert_eq!(
                capability_register_v4(
                    State(state.clone()),
                    ConnectInfo(addr),
                    HeaderMap::new(),
                    Json(CapabilityRegisterRequest {
                        capability: hex::encode(capability),
                        epoch,
                        port: 4662,
                        ip: "8.8.4.4".to_string(),
                        pubkey: hex::encode(owner_pubkey),
                        peer_pubkey: hex::encode(peer_pubkey),
                        ts,
                        sig: hex::encode(owner.sign(&v4).to_bytes()),
                        intro: false,
                        legacy_sig: Some(hex::encode(owner.sign(&legacy).to_bytes())),
                        intro_key: None,
                    }),
                )
                .await,
                StatusCode::OK
            );
            let capabilities = state.capability_store.read().await;
            let stored = capabilities.get(&hex::encode(capability)).unwrap();
            assert!(stored.v4_proof.is_some());
            assert!(stored.legacy_proof.is_some());
        }

        assert_eq!(
            state
                .rate_limits
                .read()
                .await
                .entries
                .get(&addr.ip())
                .unwrap()
                .count,
            30,
            "bundled v4+v3 proofs are one logical admission each"
        );

        // A standalone old-client v3 registration still consumes one general
        // admission; bundling does not create a free legacy route.
        let capability = [0xD4; 32];
        let legacy = build_capability_register_v3_msg(
            &capability,
            epoch,
            4662,
            [8, 8, 4, 4],
            &owner_pubkey,
            &peer_pubkey,
            ts,
        );
        assert_eq!(
            capability_register_v3(
                State(state.clone()),
                ConnectInfo(addr),
                HeaderMap::new(),
                Json(CapabilityRegisterRequest {
                    capability: hex::encode(capability),
                    epoch,
                    port: 4662,
                    ip: "8.8.4.4".to_string(),
                    pubkey: hex::encode(owner_pubkey),
                    peer_pubkey: hex::encode(peer_pubkey),
                    ts,
                    sig: hex::encode(owner.sign(&legacy).to_bytes()),
                    intro: false,
                    legacy_sig: None,
                    intro_key: None,
                }),
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            state
                .rate_limits
                .read()
                .await
                .entries
                .get(&addr.ip())
                .unwrap()
                .count,
            31
        );
        drop(peer);
    }

    const T: i64 = 1_700_000_000;

    fn admit_one_time(guard: &mut ReplayGuard, key: u8, scope: u64, ts: i64, digest: u128, now: i64) -> ReplayAdmission {
        guard.admit([key; 32], scope, ts, digest, ReplayMode::OneTime, ReplayNow::at(now))
    }

    #[test]
    fn a_one_time_request_is_accepted_once() {
        let mut guard = ReplayGuard::default();
        assert_eq!(admit_one_time(&mut guard, 1, 7, T, 1, T), ReplayAdmission::Accepted);
        assert_eq!(admit_one_time(&mut guard, 1, 7, T, 1, T + 60), ReplayAdmission::Replay);
        // Same second, different request: accepted once as well.
        assert_eq!(admit_one_time(&mut guard, 1, 7, T, 2, T), ReplayAdmission::Accepted);
        assert_eq!(admit_one_time(&mut guard, 1, 7, T, 2, T), ReplayAdmission::Replay);
        // A newer request supersedes the scope; nothing older gets back in.
        assert_eq!(admit_one_time(&mut guard, 1, 7, T + 5, 3, T + 5), ReplayAdmission::Accepted);
        assert_eq!(admit_one_time(&mut guard, 1, 7, T, 4, T + 5), ReplayAdmission::Replay);
        assert_eq!(admit_one_time(&mut guard, 1, 7, T + 4, 5, T + 5), ReplayAdmission::Replay);
        // Other scopes and other keys keep their own clocks.
        assert_eq!(admit_one_time(&mut guard, 1, 8, T, 6, T + 5), ReplayAdmission::Accepted);
        assert_eq!(admit_one_time(&mut guard, 2, 7, T, 1, T + 5), ReplayAdmission::Accepted);
        assert_eq!(guard.marks, 3, "one scope's superseded marks are released");
        assert_eq!(
            admit_one_time(&mut guard, 3, 7, T - MAX_TIMESTAMP_SKEW_SECS - 1, 1, T),
            ReplayAdmission::Stale,
            "the guard re-checks freshness against its own clock"
        );
        assert_eq!(replay_status(ReplayAdmission::Replay), Err(StatusCode::CONFLICT));
        assert_eq!(replay_status(ReplayAdmission::Stale), Err(StatusCode::BAD_REQUEST));
        assert_eq!(
            replay_status(ReplayAdmission::Full),
            Err(StatusCode::SERVICE_UNAVAILABLE)
        );
    }

    #[test]
    fn an_idempotent_scope_allows_only_the_newest_request_again() {
        let mut guard = ReplayGuard::default();
        let admit = |guard: &mut ReplayGuard, ts, digest| {
            guard.admit([1; 32], 9, ts, digest, ReplayMode::IdempotentRepeat, ReplayNow::at(T))
        };
        assert_eq!(admit(&mut guard, T, 1), ReplayAdmission::Accepted);
        assert_eq!(admit(&mut guard, T, 1), ReplayAdmission::Repeat);
        assert_eq!(admit(&mut guard, T, 2), ReplayAdmission::Accepted);
        assert_eq!(admit(&mut guard, T, 2), ReplayAdmission::Repeat);
        assert_eq!(
            admit(&mut guard, T, 1),
            ReplayAdmission::Replay,
            "an earlier state from the same second would roll the newer one back"
        );
        assert_eq!(admit(&mut guard, T + 1, 3), ReplayAdmission::Accepted);
        assert_eq!(admit(&mut guard, T, 2), ReplayAdmission::Replay);
    }

    /// One key flooding distinct scopes stays within its own mark budget and
    /// pays for it alone; what it gives up stays refused.
    #[test]
    fn a_flooding_key_is_bounded_and_leaves_other_keys_alone() {
        let mut guard = ReplayGuard::with_limits(100, 200, 8);
        for scope in 0..1_000u64 {
            let admission = admit_one_time(&mut guard, 1, scope, T + scope as i64 / 10, scope as u128, T + 100);
            assert!(
                matches!(admission, ReplayAdmission::Accepted | ReplayAdmission::Replay),
                "{admission:?}"
            );
        }
        assert!(guard.keys[&[1; 32]].marks.len() <= 8);
        assert!(guard.marks <= 8);
        assert_eq!(
            admit_one_time(&mut guard, 1, 0, T, 0, T + 100),
            ReplayAdmission::Replay,
            "an evicted mark's request is still refused by the raised floor"
        );
        for key in 2..50u8 {
            assert_eq!(admit_one_time(&mut guard, key, 0, T, 0, T + 100), ReplayAdmission::Accepted);
            assert_eq!(admit_one_time(&mut guard, key, 0, T, 0, T + 100), ReplayAdmission::Replay);
        }
    }

    /// When every key is still inside the skew window the guard refuses a new
    /// key rather than evict one — eviction is only ever of lapsed keys.
    #[test]
    fn capacity_never_evicts_a_key_that_can_still_be_replayed() {
        let mut guard = ReplayGuard::with_limits(2, 100, 8);
        assert_eq!(admit_one_time(&mut guard, 1, 0, T, 1, T), ReplayAdmission::Accepted);
        // A future-dated request keeps its key live for longer.
        assert_eq!(
            admit_one_time(&mut guard, 2, 0, T + MAX_TIMESTAMP_SKEW_SECS, 1, T),
            ReplayAdmission::Accepted
        );
        assert_eq!(admit_one_time(&mut guard, 3, 0, T, 1, T), ReplayAdmission::Full);
        assert_eq!(admit_one_time(&mut guard, 1, 0, T, 1, T), ReplayAdmission::Replay);

        let lapsed = T + MAX_TIMESTAMP_SKEW_SECS + 1;
        assert_eq!(admit_one_time(&mut guard, 3, 0, lapsed, 1, lapsed), ReplayAdmission::Accepted);
        assert!(!guard.keys.contains_key(&[1; 32]), "key 1 lapsed and was evicted");
        assert!(guard.keys.contains_key(&[2; 32]), "key 2 is still replayable");
        assert_eq!(
            admit_one_time(&mut guard, 1, 0, T, 1, lapsed),
            ReplayAdmission::Stale,
            "the evicted key's request can no longer pass freshness"
        );
        assert_eq!(
            admit_one_time(&mut guard, 2, 0, T + MAX_TIMESTAMP_SKEW_SECS, 1, lapsed),
            ReplayAdmission::Replay
        );
        assert_eq!(admit_one_time(&mut guard, 4, 0, lapsed, 1, lapsed), ReplayAdmission::Full);
    }

    /// Filling the shared pool makes a key recycle its own marks instead of
    /// taking more, so a pool full of one sender does not refuse everyone.
    #[test]
    fn a_full_mark_pool_makes_busy_keys_recycle_their_own_marks() {
        let mut guard = ReplayGuard::with_limits(10, 4, 4);
        for scope in 0..4 {
            assert_eq!(
                admit_one_time(&mut guard, 1, scope, T + scope as i64, 1, T + 10),
                ReplayAdmission::Accepted
            );
        }
        assert_eq!(guard.marks, 4);
        assert_eq!(admit_one_time(&mut guard, 2, 0, T, 1, T + 10), ReplayAdmission::Full);
        assert_eq!(admit_one_time(&mut guard, 1, 9, T + 10, 1, T + 10), ReplayAdmission::Accepted);
        assert_eq!(guard.marks, 4);
        assert_eq!(admit_one_time(&mut guard, 1, 0, T, 1, T + 10), ReplayAdmission::Replay);
    }

    /// A backward wall-clock step must not re-admit what the guard already
    /// forgot, and must not make it forget anything more until wall time
    /// catches up.
    #[test]
    fn a_backward_wall_clock_step_does_not_reopen_dropped_replays() {
        let mut guard = ReplayGuard::with_limits(1, 10, 8);
        let start = ReplayNow::from_parts(T, 0, T);
        assert_eq!(guard.admit([1; 32], 0, T, 1, ReplayMode::OneTime, start), ReplayAdmission::Accepted);

        // Time passes normally; key 1 lapses and is evicted for key 2.
        let lapsed = T + MAX_TIMESTAMP_SKEW_SECS + 1;
        let later = ReplayNow::from_parts(T, lapsed - T, lapsed);
        assert_eq!(
            guard.admit([2; 32], 0, lapsed, 1, ReplayMode::OneTime, later),
            ReplayAdmission::Accepted
        );
        assert!(!guard.keys.contains_key(&[1; 32]));

        // Then the wall clock steps back far enough that key 1's request would
        // pass the ordinary freshness check again.
        let stepped_back = ReplayNow::from_parts(T, lapsed - T + 1, T + 100);
        assert!(fresh_at(T, stepped_back.wall), "by the stepped-back wall clock it would pass");
        assert_eq!(
            guard.admit([1; 32], 0, T, 1, ReplayMode::OneTime, stepped_back),
            ReplayAdmission::Stale,
            "a request whose protection was dropped stays refused"
        );
        assert_eq!(
            guard.raise_floor([1; 32], T, stepped_back),
            ReplayAdmission::Stale,
            "nor can a dropped unregister be replayed"
        );
        assert_eq!(
            guard.admit([3; 32], 0, T + 100, 1, ReplayMode::OneTime, stepped_back),
            ReplayAdmission::Full,
            "key 2 is not evicted while the wall clock is behind"
        );
        assert!(guard.keys.contains_key(&[2; 32]));

        let first = ReplayNow::current();
        let second = ReplayNow::current();
        assert!(second.lapse >= first.lapse);
    }

    /// A server that booted with its clock fast and was then corrected must
    /// accept correctly timed requests again rather than until restart.
    #[test]
    fn a_fast_clock_corrected_accepts_requests_again() {
        let fast = T + 3_600;
        let mut guard = ReplayGuard::with_limits(10, 100, 8);
        let booted_fast = ReplayNow::from_parts(fast, 0, fast);
        assert_eq!(
            guard.admit([1; 32], 0, fast, 1, ReplayMode::OneTime, booted_fast),
            ReplayAdmission::Accepted
        );
        // NTP corrects the wall clock an hour back; monotonic time keeps going.
        let corrected = ReplayNow::from_parts(fast, 60, T + 60);
        assert_eq!(
            guard.admit([2; 32], 0, T + 60, 1, ReplayMode::OneTime, corrected),
            ReplayAdmission::Accepted,
            "nothing was dropped, so correctly timed requests pass at once"
        );
        assert_eq!(guard.check_floor(&[3; 32], T + 60, corrected), ReplayAdmission::Accepted);
        assert_eq!(
            guard.admit([1; 32], 0, fast, 1, ReplayMode::OneTime, corrected),
            ReplayAdmission::Stale,
            "fast-era requests are refused as future-dated"
        );

        // Had the fast era already dropped protection, one-time requests at or
        // below what it dropped are held back until wall time passes it —
        // bounded, where previously it lasted until restart — while
        // registrations and reads are never held back.
        let mut dropped = ReplayGuard::with_limits(10, 100, 8);
        assert_eq!(
            dropped.admit([1; 32], 0, fast, 1, ReplayMode::OneTime, booted_fast),
            ReplayAdmission::Accepted
        );
        let fast_later = ReplayNow::from_parts(fast, 400, fast + 400);
        dropped.prune(fast_later);
        assert!(dropped.keys.is_empty());
        let corrected = ReplayNow::from_parts(fast, 460, T + 460);
        assert_eq!(
            dropped.admit([2; 32], 0, T + 460, 1, ReplayMode::OneTime, corrected),
            ReplayAdmission::Stale
        );
        assert_eq!(dropped.check_floor(&[2; 32], T + 460, corrected), ReplayAdmission::Accepted);
        dropped.prune(corrected);
        assert_eq!(dropped.dropped_through, fast, "nothing more is dropped while behind");
        let caught_up = ReplayNow::from_parts(fast, 4_000, fast + 50);
        assert_eq!(
            dropped.admit([1; 32], 0, fast, 1, ReplayMode::OneTime, caught_up),
            ReplayAdmission::Stale,
            "the dropped fast-era request is still refused once it looks fresh"
        );
        assert_eq!(
            dropped.admit([4; 32], 0, fast + 50, 1, ReplayMode::OneTime, caught_up),
            ReplayAdmission::Accepted
        );
    }

    #[test]
    fn a_floor_refuses_everything_signed_before_it() {
        let mut guard = ReplayGuard::default();
        let at = ReplayNow::at;
        assert_eq!(guard.check_floor(&[1; 32], T, at(T)), ReplayAdmission::Accepted);
        assert_eq!(guard.raise_floor([1; 32], T + 10, at(T + 10)), ReplayAdmission::Accepted);
        assert_eq!(guard.raise_floor([1; 32], T + 10, at(T + 10)), ReplayAdmission::Replay);
        assert_eq!(guard.check_floor(&[1; 32], T + 10, at(T + 10)), ReplayAdmission::Replay);
        assert_eq!(guard.check_floor(&[1; 32], T + 11, at(T + 11)), ReplayAdmission::Accepted);
        assert_eq!(guard.check_floor(&[2; 32], T, at(T + 11)), ReplayAdmission::Accepted);
        assert_eq!(
            admit_one_time(&mut guard, 1, 0, T + 5, 1, T + 11),
            ReplayAdmission::Replay
        );
    }

    #[test]
    fn idempotent_read_nonce_is_bounded_per_scope() {
        let now = Instant::now();
        let mut cache = ScopedNonceCache::new();
        assert_eq!(
            admit_idempotent_read_nonce(
                &mut cache,
                [1; 32],
                [2; 16],
                10,
                now,
                Duration::from_secs(60),
                1,
            ),
            IdempotentReadAdmission::New
        );
        assert_eq!(
            admit_idempotent_read_nonce(
                &mut cache,
                [1; 32],
                [2; 16],
                10,
                now,
                Duration::from_secs(60),
                1,
            ),
            IdempotentReadAdmission::Idempotent
        );
        assert_eq!(
            admit_idempotent_read_nonce(
                &mut cache,
                [1; 32],
                [3; 16],
                11,
                now,
                Duration::from_secs(60),
                1,
            ),
            IdempotentReadAdmission::NonceConflict
        );
        assert_eq!(
            admit_idempotent_read_nonce(
                &mut cache,
                [4; 32],
                [5; 16],
                10,
                now,
                Duration::from_secs(60),
                1,
            ),
            IdempotentReadAdmission::Full
        );
        assert_eq!(
            admit_idempotent_read_nonce(
                &mut cache,
                [1; 32],
                [2; 16],
                9,
                now,
                Duration::from_secs(60),
                1,
            ),
            IdempotentReadAdmission::Replay
        );
        assert_eq!(
            idempotent_read_status(IdempotentReadAdmission::Replay),
            Err(StatusCode::CONFLICT)
        );
    }

    #[test]
    fn accepted_ticket_capacity_does_not_count_pending_offers() {
        let responder_id = "22".repeat(32);
        let mut tickets = RelayTicketStore::default();
        for index in 0..(MAX_ACCEPTED_RELAY_TICKETS_PER_RESPONDER * 2) {
            tickets.insert(
                format!("{:064x}", index + 100),
                ticket_for_test(&responder_id, false),
            );
        }
        assert!(
            responder_has_accepted_ticket_capacity(&tickets, &responder_id),
            "unaccepted offers must not consume friend-acceptance capacity"
        );

        for index in 0..MAX_ACCEPTED_RELAY_TICKETS_PER_RESPONDER {
            tickets.insert(
                format!("{index:064x}"),
                ticket_for_test(&responder_id, true),
            );
        }
        assert!(!responder_has_accepted_ticket_capacity(
            &tickets,
            &responder_id
        ));

        tickets.remove(&format!("{:064x}", 0));
        assert!(responder_has_accepted_ticket_capacity(
            &tickets,
            &responder_id
        ));
    }

    #[test]
    fn mailbox_pages_round_robin_past_first_eight_initiators() {
        let responder_id = "44".repeat(32);
        let mut tickets = RelayTicketStore::default();
        for index in 0..9 {
            tickets.insert(
                format!("{:064x}", index + 100),
                ticket_with_parties(&format!("{index:064x}"), &responder_id, false),
            );
        }

        let first = tickets.mailbox_page_ids(&responder_id, Instant::now());
        assert_eq!(first.len(), MAX_RELAY_MAILBOX_RESULTS);
        let second = tickets.mailbox_page_ids(&responder_id, Instant::now());
        assert_eq!(
            second.first(),
            Some(&format!("{:064x}", 108)),
            "the ninth offer must not remain hidden behind the first page"
        );
    }

    #[test]
    fn mailbox_idempotent_page_cache_does_not_readvance_cursor() {
        let responder_id = "55".repeat(32);
        let mut tickets = RelayTicketStore::default();
        for index in 0..9 {
            tickets.insert(
                format!("{:064x}", index + 100),
                ticket_with_parties(&format!("{index:064x}"), &responder_id, false),
            );
        }
        let now = Instant::now();
        let nonce = [0x42; 16];
        let ts = 1_700_000_000_i64;
        let first = tickets.mailbox_page_ids(&responder_id, now);
        tickets.store_mailbox_page(&responder_id, nonce, ts, first.clone(), now);
        let cached = tickets
            .cached_mailbox_page(&responder_id, &nonce, ts, now)
            .expect("cached page");
        assert_eq!(cached, first);
        // A lost-response retry must replay the same page; advancing again would
        // hide the first eight offers until wrap-around.
        let peek = tickets.mailbox_peek_page_ids(&responder_id, now);
        assert_ne!(
            peek.first(),
            first.first(),
            "cursor already advanced after the first New poll"
        );
        assert_eq!(
            tickets
                .cached_mailbox_page(&responder_id, &nonce, ts, now)
                .as_ref(),
            Some(&first)
        );
    }

    #[test]
    fn accepted_tickets_do_not_consume_mailbox_scan_budget() {
        let responder_id = "aa".repeat(32);
        let mut tickets = RelayTicketStore::default();
        for index in 0..MAX_ACCEPTED_RELAY_TICKETS_PER_RESPONDER {
            tickets.insert(
                format!("{:064x}", index + 1),
                ticket_with_parties(&format!("{index:064x}"), &responder_id, true),
            );
        }
        // Lexicographically after the accepted initiator ids above.
        tickets.insert(
            format!("{:064x}", 200),
            ticket_with_parties(&"f0".repeat(32), &responder_id, false),
        );
        let page = tickets.mailbox_page_ids(&responder_id, Instant::now());
        assert_eq!(
            page,
            vec![format!("{:064x}", 200)],
            "accepted pair slots must not hide live pending offers"
        );
        assert!(tickets.pending_by_responder.contains_key(&responder_id));
    }

    /// `(now - ts).abs()` wrapped to `i64::MIN` for a crafted `ts`, which
    /// compares `<= MAX_TIMESTAMP_SKEW_SECS` — so the freshness gate, which runs
    /// on an unauthenticated body before any signature check, failed open.
    #[test]
    fn timestamp_freshness_rejects_values_that_overflow_the_skew_check() {
        assert!(!timestamp_fresh(now_unix_secs().wrapping_sub(i64::MIN)));
        assert!(!timestamp_fresh(i64::MIN));
        assert!(!timestamp_fresh(i64::MAX));
        assert!(timestamp_fresh(now_unix_secs()));
        assert!(timestamp_fresh(now_unix_secs() - MAX_TIMESTAMP_SKEW_SECS));
        assert!(!timestamp_fresh(now_unix_secs() - MAX_TIMESTAMP_SKEW_SECS - 1));
    }

    /// Strangers holding only a public friend-code capability must not be able
    /// to crowd a target's actual friends out of its punch queue.
    #[test]
    fn open_intro_requesters_only_get_their_share_of_a_targets_punch_slots() {
        let target = "tt".repeat(32);
        let mut punches = PunchStore::default();
        let entry = |from: &str, via_open_intro: bool| PunchEntry {
            punch_id: "11".repeat(32),
            from_id: from.to_string(),
            from_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            from_port: 4662,
            nat_type: 1,
            capability: [3; 32],
            epoch: 1,
            created_at: Instant::now(),
            leased_until: None,
            proof_version: RendezvousVersion::IpBoundV4,
            register_nonce: Some([4; 16]),
            register_ts: Some(1),
            register_sig: Some([5; 64]),
            from_pubkey: Some([6; 32]),
            via_open_intro,
        };

        assert!(!open_intro_punch_slots_exhausted(&punches, &target));
        for i in 0..MAX_PUNCH_PER_TARGET_OPEN_INTRO {
            punches.insert(
                target.clone(),
                format!("{i:064x}"),
                entry(&format!("{i:064x}"), true),
            );
        }
        assert!(
            open_intro_punch_slots_exhausted(&punches, &target),
            "a stranger past the reserved share must be refused"
        );

        // Pairwise-bound friends never count against that share, and the share is
        // per target rather than global.
        let mut pairwise_only = PunchStore::default();
        for i in 0..MAX_PUNCH_PER_TARGET {
            pairwise_only.insert(
                target.clone(),
                format!("{i:064x}"),
                entry(&format!("{i:064x}"), false),
            );
        }
        assert!(!open_intro_punch_slots_exhausted(&pairwise_only, &target));
        assert!(!open_intro_punch_slots_exhausted(&punches, &"uu".repeat(32)));
    }

    #[test]
    fn punch_lease_hides_entry_until_expiry() {
        let now = Instant::now();
        let entry = PunchEntry {
            punch_id: "11".repeat(32),
            from_id: "22".repeat(32),
            from_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            from_port: 4662,
            nat_type: 1,
            capability: [3; 32],
            epoch: 1,
            created_at: now,
            leased_until: Some(now + PUNCH_LEASE),
            proof_version: RendezvousVersion::IpBoundV4,
            register_nonce: Some([4; 16]),
            register_ts: Some(1),
            register_sig: Some([5; 64]),
            from_pubkey: Some([6; 32]),
            via_open_intro: false,
        };
        assert!(!punch_available(&entry, now));
        assert!(punch_available(
            &entry,
            now + PUNCH_LEASE + Duration::from_millis(1)
        ));
    }

    fn punch_entry(from: &str, punch_id: &str, created_at: Instant, version: RendezvousVersion) -> PunchEntry {
        PunchEntry {
            punch_id: punch_id.to_string(),
            from_id: from.to_string(),
            from_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            from_port: 1,
            nat_type: 1,
            capability: [1; 32],
            epoch: 1,
            created_at,
            leased_until: None,
            proof_version: version,
            register_nonce: Some([1; 16]),
            register_ts: Some(1),
            register_sig: Some([1; 64]),
            from_pubkey: Some([1; 32]),
            via_open_intro: false,
        }
    }

    #[test]
    fn punch_lease_prefers_unleased_over_leased_head() {
        let now = Instant::now();
        let target = "tt".repeat(32);
        let mut punches = PunchStore::default();
        let mut leased = punch_entry(&"aa".repeat(32), &"11".repeat(32), now, RendezvousVersion::IpBoundV4);
        leased.leased_until = Some(now + PUNCH_LEASE);
        punches.insert(target.clone(), "aa".repeat(32), leased);
        punches.insert(
            target.clone(),
            "bb".repeat(32),
            punch_entry(
                &"bb".repeat(32),
                &"22".repeat(32),
                now + Duration::from_millis(1),
                RendezvousVersion::IpBoundV4,
            ),
        );
        let chosen = punches
            .lease_next(&target, RendezvousVersion::IpBoundV4, now)
            .map(|entry| entry.punch_id.clone());
        assert_eq!(chosen.as_deref(), Some(&*"22".repeat(32)));
        // Both leased now: a re-poll refreshes the oldest rather than 404ing.
        let again = punches
            .lease_next(&target, RendezvousVersion::IpBoundV4, now)
            .map(|entry| entry.punch_id.clone());
        assert_eq!(again.as_deref(), Some(&*"11".repeat(32)));
    }

    #[test]
    fn the_punch_index_serves_only_its_target_and_version() {
        let now = Instant::now();
        let mut punches = PunchStore::default();
        let (a, b) = ("aa".repeat(32), "bb".repeat(32));
        punches.insert(a.clone(), "01".repeat(32), punch_entry("01", &"11".repeat(32), now, RendezvousVersion::LegacyV3));
        punches.insert(b.clone(), "02".repeat(32), punch_entry("02", &"22".repeat(32), now, RendezvousVersion::IpBoundV4));
        assert!(
            punches.lease_next(&a, RendezvousVersion::IpBoundV4, now).is_none(),
            "a v4 poll never observes a legacy registration"
        );
        assert!(punches.lease_next(&a, RendezvousVersion::LegacyV3, now).is_some());
        assert_eq!(
            punches
                .lease_next(&b, RendezvousVersion::IpBoundV4, now)
                .map(|entry| entry.punch_id.clone()),
            Some("22".repeat(32))
        );
        assert_eq!((punches.len(), punches.target_len(&a), punches.target_len(&b)), (2, 1, 1));

        // Re-registering the same pair replaces it in place.
        punches.insert(a.clone(), "01".repeat(32), punch_entry("01", &"33".repeat(32), now, RendezvousVersion::LegacyV3));
        assert_eq!(punches.len(), 2);
        assert!(!punches.remove_acked(&a, &"11".repeat(32), &[1; 32], 1), "the old punch id is gone");
        assert!(!punches.remove_acked(&b, &"33".repeat(32), &[1; 32], 1), "acks are per target");
        assert!(punches.remove_acked(&a, &"33".repeat(32).to_uppercase(), &[1; 32], 1));
        assert_eq!(punches.len(), 1);
        assert!(!punches.by_target.contains_key(&a), "an emptied target is dropped");
    }

    #[test]
    fn punch_expiry_removes_only_what_expired() {
        let start = Instant::now();
        let mut punches = PunchStore::default();
        let target = "aa".repeat(32);
        punches.insert(target.clone(), "01".repeat(32), punch_entry("01", "p1", start, RendezvousVersion::IpBoundV4));
        punches.insert(target.clone(), "02".repeat(32), punch_entry("02", "p2", start, RendezvousVersion::IpBoundV4));
        // Refreshed later: its first expiry item must not remove the new entry.
        let refreshed = start + Duration::from_secs(10);
        punches.insert(target.clone(), "01".repeat(32), punch_entry("01", "p3", refreshed, RendezvousVersion::IpBoundV4));
        assert_eq!(punches.prune_expired(start + PUNCH_TTL - Duration::from_millis(1)), 0);
        assert_eq!(punches.prune_expired(start + PUNCH_TTL), 1);
        assert!(punches.contains(&target, &"01".repeat(32)));
        assert!(!punches.contains(&target, &"02".repeat(32)));
        assert_eq!(punches.prune_expired(refreshed + PUNCH_TTL), 1);
        assert_eq!(punches.len(), 0);
        assert!(punches.expirations.is_empty());
        assert!(punches.by_target.is_empty());
    }

    #[test]
    fn a_full_store_purge_runs_at_most_once_per_interval() {
        let throttle = PurgeThrottle::default();
        let now = Instant::now();
        assert!(throttle.try_begin(now));
        assert!(!throttle.try_begin(now + STORE_PURGE_MIN_INTERVAL - Duration::from_millis(1)));
        assert!(throttle.try_begin(now + STORE_PURGE_MIN_INTERVAL));
    }

    #[test]
    fn signed_ip_encoding_binds_v4_and_rejects_raw_mismatch() {
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let encoded = encode_signed_ip(ip);
        assert_eq!(encoded[0], SIGNED_IP_V4);
        assert_eq!(&encoded[1..], &[198, 51, 100, 7]);
        assert_ne!(encoded, ip.to_string().into_bytes());
    }

    #[test]
    fn parse_routable_ip_rejects_ipv6_fail_closed() {
        assert!(parse_routable_ip("8.8.8.8").is_some());
        assert!(parse_routable_ip("2001:db8::1").is_none());
        assert!(parse_routable_ip("10.0.0.1").is_none());
    }

    #[test]
    fn ticket_capacity_counts_accepted_and_offered_tickets() {
        let initiator_id = "33".repeat(32);
        let mut tickets = RelayTicketStore::default();
        for index in 0..MAX_PENDING_RELAY_TICKETS_PER_INITIATOR {
            tickets.insert(
                format!("{index:064x}"),
                ticket_with_parties(&initiator_id, &format!("{:064x}", index + 100), index == 0),
            );
        }
        assert!(!initiator_has_ticket_capacity(&tickets, &initiator_id));
        assert!(
            tickets
                .by_responder
                .get(&format!("{:064x}", 100))
                .is_some_and(|by_initiator| by_initiator.contains_key(&initiator_id)),
            "accepted/offered pair occupancy is indexed"
        );
    }

    #[test]
    fn ticket_expiry_queue_removes_all_admission_indexes() {
        let initiator_id = "55".repeat(32);
        let responder_id = "66".repeat(32);
        let mut tickets = RelayTicketStore::default();
        let mut expired = ticket_with_parties(&initiator_id, &responder_id, true);
        expired.expires_at = Instant::now() - Duration::from_secs(1);
        tickets.insert("77".repeat(32), expired);

        prune_expired_relay_tickets(&mut tickets, Instant::now());
        assert!(tickets.tickets.is_empty());
        assert!(tickets.by_responder.is_empty());
        assert!(tickets.pending_by_responder.is_empty());
        assert!(tickets.initiator_counts.is_empty());
        assert!(tickets.accepted_responder_counts.is_empty());
    }

    #[test]
    fn prebridge_frames_are_bounded_and_fifo() {
        let mut frames = VecDeque::new();
        let mut buffered_bytes = 0;
        enqueue_prebridge_frame(&mut frames, &mut buffered_bytes, b"hello".to_vec(), 2, 8).unwrap();
        enqueue_prebridge_frame(&mut frames, &mut buffered_bytes, b"yo".to_vec(), 2, 8).unwrap();
        assert_eq!(buffered_bytes, 7);
        assert_eq!(frames.pop_front(), Some(b"hello".to_vec()));
        assert_eq!(frames.pop_front(), Some(b"yo".to_vec()));
        assert!(enqueue_prebridge_frame(
            &mut frames,
            &mut buffered_bytes,
            b"123456789".to_vec(),
            2,
            8
        )
        .is_err());
    }

    #[tokio::test]
    async fn ticket_id_canonicalization_preserves_token_derivation_and_admission() {
        let state = test_state();
        let lower = "ab".repeat(32);
        let upper = lower.to_ascii_uppercase();
        let (initiator_token, _) =
            insert_ticket(&state, &lower, Instant::now() + Duration::from_secs(30)).await;

        assert_eq!(
            issue_relay_role_token(&state, &lower, RelayRole::Initiator),
            issue_relay_role_token(&state, &upper, RelayRole::Initiator)
        );
        assert_eq!(
            admit_relay_ticket_join(&state, &upper, &initiator_token, "8.8.8.8".parse().unwrap())
                .await,
            Ok(RelayRole::Initiator)
        );
    }

    #[tokio::test]
    async fn pre_upgrade_reservation_rolls_back_or_commits_atomically() {
        let state = test_state();
        let ticket_id = "ac".repeat(32);
        let (initiator_token, _) =
            insert_ticket(&state, &ticket_id, Instant::now() + Duration::from_secs(30)).await;
        let client_ip: IpAddr = "8.8.4.4".parse().unwrap();

        let reservation =
            reserve_relay_ticket_join(&state, &ticket_id, &initiator_token, client_ip)
                .await
                .unwrap();
        assert_eq!(
            state
                .relay_network_counts
                .read()
                .await
                .get(&client_network(client_ip)),
            Some(&1)
        );
        rollback_relay_ticket_reservation(&state, &reservation).await;
        assert!(state.relay_network_counts.read().await.is_empty());
        assert_eq!(
            state
                .relay_tickets
                .read()
                .await
                .tickets
                .get(&ticket_id)
                .unwrap()
                .initiator_reservation,
            None
        );

        let reservation =
            reserve_relay_ticket_join(&state, &ticket_id, &initiator_token, client_ip)
                .await
                .unwrap();
        commit_relay_ticket_reservation(&state, &reservation)
            .await
            .unwrap();
        assert_eq!(
            state
                .relay_network_counts
                .read()
                .await
                .get(&client_network(client_ip)),
            Some(&1)
        );
    }

    #[tokio::test]
    async fn relay_ticket_admission_is_role_bound_and_one_time() {
        let state = test_state();
        let ticket_id = "ab".repeat(32);
        let (initiator_token, responder_token) =
            insert_ticket(&state, &ticket_id, Instant::now() + Duration::from_secs(30)).await;
        let client_ip: IpAddr = "8.8.8.8".parse().unwrap();

        assert_eq!(
            admit_relay_ticket_join(&state, &ticket_id, &initiator_token, client_ip)
                .await
                .unwrap(),
            RelayRole::Initiator
        );
        assert_eq!(
            admit_relay_ticket_join(&state, &ticket_id, &initiator_token, client_ip)
                .await
                .unwrap_err(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            admit_relay_ticket_join(&state, &ticket_id, &responder_token, client_ip)
                .await
                .unwrap(),
            RelayRole::Responder
        );
        assert_eq!(
            admit_relay_ticket_join(&state, &ticket_id, &"cd".repeat(32), client_ip)
                .await
                .unwrap_err(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn relay_ticket_admission_rejects_expired_ticket() {
        let state = test_state();
        let ticket_id = "ef".repeat(32);
        let (initiator_token, _) =
            insert_ticket(&state, &ticket_id, Instant::now() - Duration::from_secs(1)).await;
        let client_ip: IpAddr = "1.1.1.1".parse().unwrap();

        assert_eq!(
            admit_relay_ticket_join(&state, &ticket_id, &initiator_token, client_ip)
                .await
                .unwrap_err(),
            StatusCode::GONE
        );
        assert!(state.relay_tickets.read().await.tickets.is_empty());
    }

    #[tokio::test]
    async fn prune_retains_reserved_ticket_until_rollback_releases_capacity() {
        let state = test_state();
        let ticket_id = "ba".repeat(32);
        let (initiator_token, _) =
            insert_ticket(&state, &ticket_id, Instant::now() + Duration::from_secs(30)).await;
        let client_ip: IpAddr = "9.9.9.9".parse().unwrap();

        let reservation =
            reserve_relay_ticket_join(&state, &ticket_id, &initiator_token, client_ip)
                .await
                .unwrap();
        assert_eq!(
            state
                .relay_network_counts
                .read()
                .await
                .get(&client_network(client_ip)),
            Some(&1)
        );

        // The ticket expires while the pre-upgrade reservation is still
        // outstanding. Pruning must retain it so the reservation's rollback
        // can still find the ticket and release the per-IP count.
        let after_expiry = Instant::now() + Duration::from_secs(31);
        {
            let mut tickets = state.relay_tickets.write().await;
            prune_expired_relay_tickets(&mut tickets, after_expiry);
            assert!(
                tickets.tickets.contains_key(&ticket_id),
                "expired ticket with an outstanding reservation must be retained"
            );
        }

        rollback_relay_ticket_reservation(&state, &reservation).await;
        assert!(
            state.relay_network_counts.read().await.is_empty(),
            "rollback must release the reserved per-IP count"
        );

        // Once the watchdog window has passed and the reservation is gone,
        // the next sweep removes the ticket and all its indexes.
        let after_watchdog =
            after_expiry + RELAY_UPGRADE_RESERVATION_TIMEOUT + Duration::from_secs(1);
        let mut tickets = state.relay_tickets.write().await;
        prune_expired_relay_tickets(&mut tickets, after_watchdog);
        assert!(tickets.tickets.is_empty());
        assert!(tickets.by_responder.is_empty());
        assert!(tickets.expirations.is_empty());
    }

    #[tokio::test]
    async fn relay_queue_enforces_byte_budget() {
        let (sender, mut receiver) = relay_queue();
        for _ in 0..(MAX_RELAY_QUEUE_BYTES / MAX_RELAY_FRAME_BYTES) {
            sender.send(vec![0u8; MAX_RELAY_FRAME_BYTES]).await.unwrap();
        }
        assert!(sender.send(vec![1]).await.is_err());
        assert_eq!(receiver.recv().await.unwrap().len(), MAX_RELAY_FRAME_BYTES);
        sender.send(vec![1]).await.unwrap();
        assert_eq!(MAX_RELAY_FRAME_BYTES, 16 * 1024);
    }

    #[tokio::test]
    async fn relay_registry_cleanup_is_idempotent() {
        let state = test_state();
        let session = "cd".repeat(32);
        let first: IpAddr = "1.1.1.1".parse().unwrap();
        let second: IpAddr = "8.8.8.8".parse().unwrap();
        state
            .relay_admissions
            .write()
            .await
            .insert((session.clone(), RelayRole::Initiator), first);
        state
            .relay_admissions
            .write()
            .await
            .insert((session.clone(), RelayRole::Responder), second);
        state
            .relay_network_counts
            .write()
            .await
            .insert(client_network(first), 1);
        state
            .relay_network_counts
            .write()
            .await
            .insert(client_network(second), 1);
        state.bridged_relays.write().await.insert(
            session.clone(),
            BridgedRelayEntry {
                deadline: Instant::now(),
            },
        );

        cleanup_relay_session_all(&state, &session).await;
        cleanup_relay_session_all(&state, &session).await;
        assert!(state.relay_admissions.read().await.is_empty());
        assert!(state.relay_network_counts.read().await.is_empty());
        assert!(state.bridged_relays.read().await.is_empty());
    }

    #[test]
    fn client_network_groups_ipv4_by_24_and_ipv6_by_64() {
        let network = |ip: &str| client_network(ip.parse().unwrap());
        let parsed = |ip: &str| ip.parse::<IpAddr>().unwrap();
        assert_eq!(network("203.0.113.7"), network("203.0.113.250"));
        assert_eq!(network("203.0.113.7"), parsed("203.0.113.0"));
        assert_ne!(network("203.0.113.7"), network("203.0.114.7"));
        assert_eq!(network("::ffff:203.0.113.9"), network("203.0.113.7"));

        assert_eq!(network("2001:db8:1:2::1"), network("2001:db8:1:2:ffff::1"));
        assert_eq!(network("2001:db8:1:2::1"), parsed("2001:db8:1:2::"));
        assert_ne!(network("2001:db8:1:2::1"), network("2001:db8:1:3::1"));
    }

    #[tokio::test]
    async fn relay_cap_counts_every_address_in_a_network_together() {
        let state = test_state();
        let mut joined = 0usize;
        for index in 0..=MAX_RELAY_SESSIONS_PER_NETWORK {
            let ticket_id = format!("{index:064x}");
            let (initiator_token, _) =
                insert_ticket(&state, &ticket_id, Instant::now() + Duration::from_secs(30)).await;
            let address = IpAddr::V6(Ipv6Addr::from(
                0x2001_0db8_0009_0009_0000_0000_0000_0001_u128 + index as u128,
            ));
            match admit_relay_ticket_join(&state, &ticket_id, &initiator_token, address).await {
                Ok(RelayRole::Initiator) => joined += 1,
                result => {
                    assert_eq!(result, Err(StatusCode::TOO_MANY_REQUESTS));
                    assert_eq!(index, MAX_RELAY_SESSIONS_PER_NETWORK);
                }
            }
        }
        assert_eq!(joined, MAX_RELAY_SESSIONS_PER_NETWORK);

        let ticket_id = "f0".repeat(32);
        let (initiator_token, _) =
            insert_ticket(&state, &ticket_id, Instant::now() + Duration::from_secs(30)).await;
        assert_eq!(
            join_from(&state, &ticket_id, &initiator_token, "2001:db8:9:a::1").await,
            Ok(RelayRole::Initiator),
            "a neighbouring /64 has its own budget"
        );
    }

    #[test]
    fn network_connection_limiter_caps_each_network() {
        let limiter = NetworkConnectionLimiter::default();
        let limit = MAX_HTTP_CONNECTIONS_PER_NETWORK;
        let mut held: Vec<_> = (0..limit)
            .map(|host| {
                limiter
                    .try_acquire(IpAddr::V4(Ipv4Addr::new(203, 0, 113, host as u8)), limit)
                    .expect("under the per-network cap")
            })
            .collect();
        let refused = |ip: &str| limiter.try_acquire(ip.parse().unwrap(), limit).is_none();
        assert!(refused("203.0.113.250"));
        assert!(refused("::ffff:203.0.113.251"));
        let neighbour = limiter
            .try_acquire("203.0.114.1".parse().unwrap(), limit)
            .expect("another /24 is not affected");

        held.pop();
        let replacement = limiter
            .try_acquire("203.0.113.250".parse().unwrap(), limit)
            .expect("a released slot is reusable");

        drop((held, neighbour, replacement));
        assert!(limiter.counts.lock().unwrap().is_empty());
    }

    #[test]
    fn connection_is_charged_once_to_its_named_client() {
        let limiter = NetworkConnectionLimiter::default();
        let client: IpAddr = "2001:db8:7:7::1".parse().unwrap();
        let connections: Vec<_> = (0..MAX_HTTP_CONNECTIONS_PER_NETWORK)
            .map(|_| std::sync::Mutex::new(None))
            .collect();
        for slot in &connections {
            assert!(admit_client_network(&limiter, slot, "/register", client));
            // Later requests on the same connection reuse its slot.
            assert!(admit_client_network(&limiter, slot, "/register", client));
        }
        let admit =
            |slot, path, ip: &str| admit_client_network(&limiter, slot, path, ip.parse().unwrap());
        let extra = std::sync::Mutex::new(None);
        assert!(!admit(&extra, "/register", "2001:db8:7:7::2"));
        assert!(extra.lock().unwrap().is_none());
        assert!(admit(&extra, "/register", "2001:db8:7:8::1"));

        let trusted = ProxyConfig {
            mode: ProxyMode::Fly,
            trusted_hops: vec![TrustedProxyNet::parse("10.0.0.0/8").unwrap()],
        };
        assert!(trusted.forwards_client_ip("10.1.2.3".parse().unwrap()));
        assert!(!trusted.forwards_client_ip("9.9.9.9".parse().unwrap()));
        let disabled = ProxyConfig {
            mode: ProxyMode::Disabled,
            ..trusted
        };
        assert!(!disabled.forwards_client_ip("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn health_and_loopback_bypass_the_network_cap() {
        let limiter = NetworkConnectionLimiter::default();
        let full: Vec<_> = (0..MAX_HTTP_CONNECTIONS_PER_NETWORK)
            .map(|host| {
                let slot = std::sync::Mutex::new(None);
                let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, host as u8));
                assert!(admit_client_network(&limiter, &slot, "/register", ip));
                slot
            })
            .collect();
        let admit = |path, ip: &str| {
            let slot = std::sync::Mutex::new(None);
            let admitted = admit_client_network(&limiter, &slot, path, ip.parse().unwrap());
            (admitted, slot.into_inner().unwrap().is_some())
        };

        assert_eq!(admit("/register", "203.0.113.200"), (false, false));
        assert_eq!(admit("/health", "203.0.113.200"), (true, false));

        // A local reverse proxy without TRUST_PROXY makes every client look
        // like loopback; none of them may be charged to one shared network.
        for _ in 0..=MAX_HTTP_CONNECTIONS_PER_NETWORK {
            assert_eq!(admit("/register", "127.0.0.1"), (true, false));
            assert_eq!(admit("/register", "::1"), (true, false));
            assert_eq!(admit("/register", "::ffff:127.0.0.1"), (true, false));
        }
        drop(full);
        assert!(limiter.counts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn exhausted_budget_is_refused_before_the_body_is_read() {
        use tower::ServiceExt;

        let state = test_state();
        let exhausted: SocketAddr = "8.8.8.8:4000".parse().unwrap();
        for _ in 0..MAX_REQUESTS_PER_MINUTE {
            assert!(check_rate_limit(&state, exhausted.ip()).await);
        }
        let app = build_router(state.clone());
        let send = |path: &'static str, addr: SocketAddr| {
            let request = axum::http::Request::builder()
                .method("POST")
                .uri(path)
                .extension(ConnectInfo(addr))
                .body(axum::body::Body::from("not json"))
                .unwrap();
            let app = app.clone();
            async move { app.oneshot(request).await.unwrap().status() }
        };

        let limited = StatusCode::TOO_MANY_REQUESTS;
        assert_eq!(send("/register", exhausted).await, limited);
        assert_eq!(send("/v4/relay-mailbox/offer", exhausted).await, limited);
        // Other addresses, and routes billed to other buckets, reach the
        // handler's own body rejection.
        let fresh: SocketAddr = "1.1.1.1:4000".parse().unwrap();
        assert_ne!(send("/register", fresh).await, limited);
        assert_ne!(send("/v4/relay-mailbox/poll", exhausted).await, limited);
        assert_ne!(send("/v4/punch/register", exhausted).await, limited);
        // Peeking never charges the bucket.
        assert_eq!(
            state.rate_limits.read().await.entries[&exhausted.ip()].count,
            MAX_REQUESTS_PER_MINUTE
        );
    }

    #[tokio::test]
    async fn signed_v4_capability_punch_binds_observed_ip_and_round_trips_proof() {
        use ed25519_dalek::Signer;

        fn identity(seed: u8) -> (ed25519_dalek::SigningKey, String, [u8; 32]) {
            let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
            let public = key.verifying_key().to_bytes();
            let public_hash = blake3::hash(&public);
            let ember_hash = &public_hash.as_bytes()[..16];
            let id_raw: [u8; 32] = Sha256::digest(ember_hash).into();
            (key, hex::encode(id_raw), id_raw)
        }

        let state = test_state();
        let (from_key, from_id, from_raw) = identity(7);
        let (target_key, target_id, target_raw) = identity(8);
        for (id, key) in [
            (from_id.clone(), from_key.verifying_key().to_bytes()),
            (target_id.clone(), target_key.verifying_key().to_bytes()),
        ] {
            state.store.write().await.insert(
                id,
                PresenceEntry {
                    expires_at: Instant::now() + ENTRY_TTL,
                    pubkey: key,
                },
            );
        }
        let capability = [0xA3; 32];
        let epoch = now_unix_secs().div_euclid(15 * 60);
        state.capability_store.write().await.insert(
            hex::encode(capability),
            PairwisePresenceEntry {
                ip: "8.8.8.8".parse().unwrap(),
                port: 4662,
                expires_at: Instant::now() + ENTRY_TTL,
                peer_pubkey: from_key.verifying_key().to_bytes(),
                open_intro: false,
                pubkey: target_key.verifying_key().to_bytes(),
                epoch,
                legacy_proof: None,
                v4_proof: Some((now_unix_secs(), [0; 64])),
            },
        );
        let addr: SocketAddr = "8.8.8.8:40000".parse().unwrap();
        let ts = now_unix_secs();

        // A correctly signed claim for a different public address is still
        // forbidden. The observed address (including a trusted proxy header
        // when explicitly configured) is the sole v4 dial address authority.
        let mismatch_nonce = [0xF0; 16];
        let mismatch_message = build_punch_register_v4_msg(
            &from_raw,
            &target_raw,
            &capability,
            epoch,
            5000,
            &encode_signed_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            1,
            &mismatch_nonce,
            ts,
        );
        assert_eq!(
            punch_register_v4(
                State(state.clone()),
                ConnectInfo(addr),
                HeaderMap::new(),
                Json(CapabilityPunchRequest {
                    from_id: from_id.clone(),
                    target_id: target_id.clone(),
                    capability: hex::encode(capability),
                    epoch,
                    port: 5000,
                    ip: Some("1.1.1.1".to_string()),
                    nat_type: 1,
                    ts,
                    nonce: hex::encode(mismatch_nonce),
                    sig: hex::encode(from_key.sign(&mismatch_message).to_bytes()),
                }),
            )
            .await,
            StatusCode::FORBIDDEN
        );
        assert!(state.punch_requests.read().await.is_empty());

        let nonce = [1u8; 16];
        let register_message = build_punch_register_v4_msg(
            &from_raw,
            &target_raw,
            &capability,
            epoch,
            5000,
            &encode_signed_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            1,
            &nonce,
            ts,
        );
        assert_eq!(
            punch_register_v4(
                State(state.clone()),
                ConnectInfo(addr),
                HeaderMap::new(),
                Json(CapabilityPunchRequest {
                    from_id: from_id.clone(),
                    target_id: target_id.clone(),
                    capability: hex::encode(capability),
                    epoch,
                    port: 5000,
                    ip: Some("8.8.8.8".to_string()),
                    nat_type: 1,
                    ts,
                    nonce: hex::encode(nonce),
                    sig: hex::encode(from_key.sign(&register_message).to_bytes()),
                }),
            )
            .await,
            StatusCode::OK
        );

        let mut punch_id = String::new();
        for poll_nonce in [[2u8; 16], [3u8; 16]] {
            let poll_ts = now_unix_secs();
            let poll_message = build_punch_poll_v4_msg(&target_raw, &poll_nonce, poll_ts);
            let response = punch_poll_v4(
                State(state.clone()),
                ConnectInfo(addr),
                HeaderMap::new(),
                Json(CapabilityPunchPollRequest {
                    target_id: target_id.clone(),
                    ts: poll_ts,
                    nonce: hex::encode(poll_nonce),
                    sig: hex::encode(target_key.sign(&poll_message).to_bytes()),
                }),
            )
            .await
            .unwrap()
            .0;
            if punch_id.is_empty() {
                assert_eq!(response.proof_version, Some(4));
                assert_eq!(response.ip, addr.ip().to_string());
                let proof_nonce = decode_hex_nonce(
                    response
                        .register_nonce
                        .as_deref()
                        .expect("v4 response carries register nonce"),
                )
                .unwrap();
                let proof_sig = decode_hex_sig(
                    response
                        .register_sig
                        .as_deref()
                        .expect("v4 response carries register signature"),
                )
                .unwrap();
                let proof_pubkey = decode_hex_pubkey(
                    response
                        .from_pubkey
                        .as_deref()
                        .expect("v4 response carries initiator key"),
                )
                .unwrap();
                let proof_message = build_punch_register_v4_msg(
                    &from_raw,
                    &target_raw,
                    &capability,
                    response.epoch,
                    response.port,
                    &encode_signed_ip(response.ip.parse().unwrap()),
                    response.nat_type,
                    &proof_nonce,
                    response
                        .register_ts
                        .expect("v4 response carries register time"),
                );
                assert!(ed25519_verify(&proof_pubkey, &proof_message, &proof_sig));
                punch_id = response.punch_id;
            } else {
                assert_eq!(response.punch_id, punch_id);
            }
        }

        let punch_raw = decode_hex_id(&punch_id).unwrap();
        let ack_nonce = [4u8; 16];
        let ack_ts = now_unix_secs();
        let ack_message = build_punch_ack_v4_msg(
            &target_raw,
            &capability,
            epoch,
            &punch_raw,
            &ack_nonce,
            ack_ts,
        );
        assert_eq!(
            punch_ack_v4(
                State(state.clone()),
                ConnectInfo(addr),
                HeaderMap::new(),
                Json(CapabilityPunchAckRequest {
                    target_id,
                    capability: hex::encode(capability),
                    epoch,
                    punch_id,
                    ts: ack_ts,
                    nonce: hex::encode(ack_nonce),
                    sig: hex::encode(target_key.sign(&ack_message).to_bytes()),
                }),
            )
            .await,
            StatusCode::OK
        );
        assert!(state.punch_requests.read().await.is_empty());
    }

    #[test]
    fn canonical_ip_treats_ipv4_mapped_observation_as_ipv4() {
        let mapped: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
        assert_eq!(canonical_ip(mapped), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn forwarded_punch_observation_requires_explicit_trusted_proxy_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("fly-client-ip", "8.8.8.8".parse().unwrap());
        let trusted = ProxyConfig {
            mode: ProxyMode::Fly,
            trusted_hops: vec![TrustedProxyNet::parse("10.0.0.0/8").unwrap()],
        };
        let trusted_addr: SocketAddr = "10.1.2.3:443".parse().unwrap();
        assert_eq!(
            extract_client_ip_with_config(&trusted, &headers, trusted_addr),
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );

        let untrusted_addr: SocketAddr = "9.9.9.9:443".parse().unwrap();
        assert_eq!(
            extract_client_ip_with_config(&trusted, &headers, untrusted_addr),
            untrusted_addr.ip(),
            "a public client cannot self-assert Fly-Client-IP"
        );
    }

    #[test]
    fn health_reserve_rejects_non_health_paths() {
        assert!(http_path_admitted(false, "/register"));
        assert!(http_path_admitted(true, "/health"));
        assert!(!http_path_admitted(true, "/register"));
        assert_eq!(MAX_HTTP_CONNECTIONS - RESERVED_HEALTH_CONNECTIONS, 240);
    }

    #[tokio::test]
    async fn idle_timeout_stream_terminates_silent_connection() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let _stream = tokio::net::TcpStream::connect(address).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let (server, _) = listener.accept().await.unwrap();
        let mut timed = IdleTimeoutStream::new(server, Duration::from_millis(10));
        tokio::time::sleep(Duration::from_millis(20)).await;
        let error = timed.read_u8().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        client.await.unwrap();
    }

    fn test_channel_id(pubkey: &[u8; 32]) -> [u8; 16] {
        let hash = blake3::hash(pubkey);
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash.as_bytes()[..16]);
        id
    }

    /// Standing up rooms is bounded per address, but keeping one is not: the
    /// owner refresh path re-claims a name the room already holds, and
    /// throttling that would eventually release the name of a live room.
    #[tokio::test]
    async fn new_rooms_are_capped_per_hour_but_refreshing_one_is_not() {
        let state = test_state();
        let addr: SocketAddr = "9.9.9.9:1000".parse().unwrap();
        // A distinct timestamp per call, so each claim is a new request rather
        // than an idempotent re-send of the previous one.
        let claim = |state: AppState, seed: u8, name: String, ts: i64| async move {
            let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
            let pubkey = key.verifying_key().to_bytes();
            let mut channel_id = [0u8; 16];
            channel_id.copy_from_slice(&blake3::hash(&pubkey).as_bytes()[..16]);
            let signed = build_channel_name_v4_msg(&channel_id, &pubkey, &name, false, ts);
            claim_channel_name_v4(
                State(state),
                ConnectInfo(addr),
                HeaderMap::new(),
                Json(ChannelNameRequest {
                    channel_id: hex::encode(channel_id),
                    pubkey: hex::encode(pubkey),
                    name,
                    private: false,
                    ts,
                    sig: hex::encode(key.sign(&signed).to_bytes()),
                }),
            )
            .await
        };

        let base_ts = now_unix_secs();
        for seed in 0..MAX_CHANNEL_CREATES_PER_HOUR as u8 {
            assert_eq!(
                claim(state.clone(), seed, format!("room{seed}"), base_ts + seed as i64).await,
                StatusCode::OK,
                "room {seed} is inside the hourly budget"
            );
        }
        assert_eq!(
            claim(state.clone(), 200, "onetoomany".to_string(), base_ts + 100).await,
            StatusCode::TOO_MANY_REQUESTS,
            "one past the budget is refused"
        );
        // The first room re-claiming the name it already holds is a refresh,
        // and is not charged even though the creation budget is spent.
        assert_eq!(
            claim(state.clone(), 0, "room0".to_string(), base_ts + 101).await,
            StatusCode::OK,
            "an owner can still keep the name of a room that already exists"
        );
    }

    #[tokio::test]
    async fn channel_username_first_write_wins_over_http() {
        let state = test_state();
        let alice = ed25519_dalek::SigningKey::from_bytes(&[0xA1; 32]);
        let bob = ed25519_dalek::SigningKey::from_bytes(&[0xB2; 32]);
        let alice_pk = alice.verifying_key().to_bytes();
        let bob_pk = bob.verifying_key().to_bytes();
        let ts = now_unix_secs();
        let signed = build_channel_username_v4_msg(&alice_pk, "ada", ts);
        assert_eq!(
            claim_channel_username_v4(
                State(state.clone()),
                ConnectInfo("1.1.1.1:1000".parse().unwrap()),
                HeaderMap::new(),
                Json(ChannelUsernameRequest {
                    pubkey: hex::encode(alice_pk),
                    name: "Ada".to_string(),
                    ts,
                    sig: hex::encode(alice.sign(&signed).to_bytes()),
                }),
            )
            .await,
            StatusCode::OK
        );
        let bob_signed = build_channel_username_v4_msg(&bob_pk, "ada", ts);
        assert_eq!(
            claim_channel_username_v4(
                State(state.clone()),
                ConnectInfo("2.2.2.2:1000".parse().unwrap()),
                HeaderMap::new(),
                Json(ChannelUsernameRequest {
                    pubkey: hex::encode(bob_pk),
                    name: "ada".to_string(),
                    ts,
                    sig: hex::encode(bob.sign(&bob_signed).to_bytes()),
                }),
            )
            .await,
            StatusCode::CONFLICT
        );
        let rename_ts = ts + 1;
        let renamed = build_channel_username_v4_msg(&alice_pk, "adalovelace", rename_ts);
        assert_eq!(
            claim_channel_username_v4(
                State(state.clone()),
                ConnectInfo("1.1.1.1:1001".parse().unwrap()),
                HeaderMap::new(),
                Json(ChannelUsernameRequest {
                    pubkey: hex::encode(alice_pk),
                    name: "AdaLovelace".to_string(),
                    ts: rename_ts,
                    sig: hex::encode(alice.sign(&renamed).to_bytes()),
                }),
            )
            .await,
            StatusCode::OK
        );
        let bob_retry = build_channel_username_v4_msg(&bob_pk, "ada", rename_ts);
        assert_eq!(
            claim_channel_username_v4(
                State(state),
                ConnectInfo("2.2.2.2:1001".parse().unwrap()),
                HeaderMap::new(),
                Json(ChannelUsernameRequest {
                    pubkey: hex::encode(bob_pk),
                    name: "Ada".to_string(),
                    ts: rename_ts,
                    sig: hex::encode(bob.sign(&bob_retry).to_bytes()),
                }),
            )
            .await,
            StatusCode::OK
        );
    }

    /// End to end over HTTP: a nominated successor takes the name once the
    /// owner has gone quiet, and nobody else can.
    #[tokio::test]
    async fn channel_name_handover_follows_the_room() {
        let state = test_state();
        let owner = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]);
        let successor = ed25519_dalek::SigningKey::from_bytes(&[0x22; 32]);
        let nominee = ed25519_dalek::SigningKey::from_bytes(&[0x33; 32]);
        let thief = ed25519_dalek::SigningKey::from_bytes(&[0x44; 32]);
        let owner_pk = owner.verifying_key().to_bytes();
        let successor_pk = successor.verifying_key().to_bytes();
        let nominee_pk = nominee.verifying_key().to_bytes();
        let old_id = test_channel_id(&owner_pk);
        let new_id = test_channel_id(&successor_pk);
        let ts = now_unix_secs();
        let addr = "8.8.8.8:1000".parse().unwrap();

        // Signed the way a current client does — over the display string as
        // well as the key — so the room keeps its casing in the directory.
        let claim =
            build_channel_name_display_v4_msg(&old_id, &owner_pk, "lobby", "Lobby", false, ts);
        assert_eq!(
            claim_channel_name_v4(
                State(state.clone()),
                ConnectInfo(addr),
                HeaderMap::new(),
                Json(ChannelNameRequest {
                    channel_id: hex::encode(old_id),
                    pubkey: hex::encode(owner_pk),
                    name: "Lobby".to_string(),
                    private: false,
                    ts,
                    sig: hex::encode(owner.sign(&claim).to_bytes()),
                }),
            )
            .await,
            StatusCode::OK
        );

        let nom = build_channel_nominee_v4_msg(&old_id, &owner_pk, &nominee_pk, 7, ts);
        assert_eq!(
            set_channel_nominee_v4(
                State(state.clone()),
                ConnectInfo(addr),
                HeaderMap::new(),
                Json(ChannelNomineeRequest {
                    channel_id: hex::encode(old_id),
                    pubkey: hex::encode(owner_pk),
                    nominee: hex::encode(nominee_pk),
                    claim_after_days: 7,
                    ts,
                    sig: hex::encode(owner.sign(&nom).to_bytes()),
                }),
            )
            .await,
            StatusCode::OK
        );

        // Signed correctly, but by a key the owner never nominated.
        let thief_pk = thief.verifying_key().to_bytes();
        let stolen =
            build_channel_handover_v4_msg(&old_id, &new_id, &successor_pk, &thief_pk, ts);
        assert_eq!(
            handover_channel_name_v4(
                State(state.clone()),
                ConnectInfo(addr),
                HeaderMap::new(),
                Json(ChannelHandoverRequest {
                    old_channel_id: hex::encode(old_id),
                    new_channel_id: hex::encode(new_id),
                    new_pubkey: hex::encode(successor_pk),
                    signer: hex::encode(thief_pk),
                    ts,
                    sig: hex::encode(thief.sign(&stolen).to_bytes()),
                }),
            )
            .await,
            StatusCode::FORBIDDEN
        );

        // The outgoing owner's own key needs no waiting period.
        let handover =
            build_channel_handover_v4_msg(&old_id, &new_id, &successor_pk, &owner_pk, ts);
        assert_eq!(
            handover_channel_name_v4(
                State(state.clone()),
                ConnectInfo(addr),
                HeaderMap::new(),
                Json(ChannelHandoverRequest {
                    old_channel_id: hex::encode(old_id),
                    new_channel_id: hex::encode(new_id),
                    new_pubkey: hex::encode(successor_pk),
                    signer: hex::encode(owner_pk),
                    ts,
                    sig: hex::encode(owner.sign(&handover).to_bytes()),
                }),
            )
            .await,
            StatusCode::OK
        );

        let dir = channel_directory_v4(State(state.clone()), ConnectInfo(addr), HeaderMap::new(), Query(DirectoryQuery::default()))
            .await
            .expect("directory");
        let channels = dir.0["channels"].as_array().unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0]["channel_id"], hex::encode(new_id));
        assert_eq!(
            channels[0]["name"], "Lobby",
            "the successor inherits the display name"
        );
    }

    /// A client that predates the display-committing message still
    /// authenticates, but the directory must not serve bytes its signature
    /// never covered — so the legacy path publishes the normalised name.
    #[tokio::test]
    async fn a_legacy_name_claim_publishes_only_what_it_signed() {
        let state = test_state();
        let owner = ed25519_dalek::SigningKey::from_bytes(&[0x5A; 32]);
        let owner_pk = owner.verifying_key().to_bytes();
        let channel_id = test_channel_id(&owner_pk);
        let ts = now_unix_secs();
        let addr: SocketAddr = "8.8.8.8:1000".parse().unwrap();

        let legacy = build_channel_name_v4_msg(&channel_id, &owner_pk, "lobby", false, ts);
        assert_eq!(
            claim_channel_name_v4(
                State(state.clone()),
                ConnectInfo(addr),
                HeaderMap::new(),
                Json(ChannelNameRequest {
                    channel_id: hex::encode(channel_id),
                    pubkey: hex::encode(owner_pk),
                    name: "LoBBy".to_string(),
                    private: false,
                    ts,
                    sig: hex::encode(owner.sign(&legacy).to_bytes()),
                }),
            )
            .await,
            StatusCode::OK,
            "a legacy signature is still accepted"
        );

        let dir = channel_directory_v4(State(state), ConnectInfo(addr), HeaderMap::new(), Query(DirectoryQuery::default()))
            .await
            .expect("directory");
        assert_eq!(
            dir.0["channels"].as_array().unwrap()[0]["name"], "lobby",
            "casing the legacy signature did not cover must not be published"
        );
    }

    async fn post_rename(
        state: &AppState,
        key: &ed25519_dalek::SigningKey,
        channel_id: &[u8; 16],
        name: &str,
        ts: i64,
        signed: &[u8],
    ) -> StatusCode {
        rename_channel_name_v4(
            State(state.clone()),
            ConnectInfo("8.8.8.8:1000".parse().unwrap()),
            HeaderMap::new(),
            Json(ChannelNameRequest {
                channel_id: hex::encode(channel_id),
                pubkey: hex::encode(key.verifying_key().to_bytes()),
                name: name.to_string(),
                private: false,
                ts,
                sig: hex::encode(key.sign(signed).to_bytes()),
            }),
        )
        .await
    }

    fn rename_msg(key: &ed25519_dalek::SigningKey, name: &str, ts: i64) -> Vec<u8> {
        let pubkey = key.verifying_key().to_bytes();
        let display = registry::strip_invisible(name);
        build_channel_rename_v4_msg(
            &test_channel_id(&pubkey),
            &pubkey,
            &display.to_lowercase(),
            &display,
            false,
            ts,
        )
    }

    async fn directory_names(state: &AppState) -> Vec<String> {
        let dir = channel_directory_v4(
            State(state.clone()),
            ConnectInfo("8.8.8.8:1000".parse().unwrap()),
            HeaderMap::new(),
            Query(DirectoryQuery::default()),
        )
        .await
        .expect("directory");
        dir.0["channels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap().to_string())
            .collect()
    }

    /// End to end over HTTP: only a rename signed as one, by the room's own
    /// key, moves the room's name; a claim for another name does not.
    #[tokio::test]
    async fn channel_rename_needs_its_own_signature_and_the_rooms_key() {
        let state = test_state();
        let owner = ed25519_dalek::SigningKey::from_bytes(&[0x61; 32]);
        let other = ed25519_dalek::SigningKey::from_bytes(&[0x62; 32]);
        let owner_pk = owner.verifying_key().to_bytes();
        let channel_id = test_channel_id(&owner_pk);
        let ts = now_unix_secs();
        let addr: SocketAddr = "8.8.8.8:1000".parse().unwrap();

        let claim =
            build_channel_name_display_v4_msg(&channel_id, &owner_pk, "lobby", "Lobby", false, ts - 10);
        assert_eq!(
            claim_channel_name_v4(
                State(state.clone()),
                ConnectInfo(addr),
                HeaderMap::new(),
                Json(ChannelNameRequest {
                    channel_id: hex::encode(channel_id),
                    pubkey: hex::encode(owner_pk),
                    name: "Lobby".to_string(),
                    private: false,
                    ts: ts - 10,
                    sig: hex::encode(owner.sign(&claim).to_bytes()),
                }),
            )
            .await,
            StatusCode::OK
        );

        // A claim signature on the rename endpoint is not a rename.
        let claim_for_den =
            build_channel_name_display_v4_msg(&channel_id, &owner_pk, "den", "Den", false, ts - 9);
        assert_eq!(
            post_rename(&state, &owner, &channel_id, "Den", ts - 9, &claim_for_den).await,
            StatusCode::FORBIDDEN
        );
        // Nor does a plain claim for another name rename the room.
        assert_eq!(
            claim_channel_name_v4(
                State(state.clone()),
                ConnectInfo(addr),
                HeaderMap::new(),
                Json(ChannelNameRequest {
                    channel_id: hex::encode(channel_id),
                    pubkey: hex::encode(owner_pk),
                    name: "Den".to_string(),
                    private: false,
                    ts: ts - 8,
                    sig: hex::encode(owner.sign(&build_channel_name_display_v4_msg(
                        &channel_id, &owner_pk, "den", "Den", false, ts - 8,
                    ))
                    .to_bytes()),
                }),
            )
            .await,
            StatusCode::CONFLICT
        );
        // Signed as a rename, but by a key that is not the room's.
        assert_eq!(
            post_rename(&state, &other, &channel_id, "Den", ts - 7, &rename_msg(&other, "Den", ts - 7))
                .await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(directory_names(&state).await, vec!["Lobby".to_string()]);

        assert_eq!(
            post_rename(&state, &owner, &channel_id, "Den", ts - 6, &rename_msg(&owner, "Den", ts - 6))
                .await,
            StatusCode::OK
        );
        assert_eq!(directory_names(&state).await, vec!["Den".to_string()]);
    }

    /// A second rename inside the day is 425, distinct from the limiter's 429;
    /// an older rename cannot be replayed to move the room back; and the
    /// newest one may be retried after a lost answer.
    #[tokio::test]
    async fn channel_rename_is_rationed_and_replay_safe() {
        let state = test_state();
        let owner = ed25519_dalek::SigningKey::from_bytes(&[0x63; 32]);
        let channel_id = test_channel_id(&owner.verifying_key().to_bytes());
        let ts = now_unix_secs();

        // A room the registry has not seen gets its first name this way.
        let first = rename_msg(&owner, "Lobby", ts - 10);
        assert_eq!(
            post_rename(&state, &owner, &channel_id, "Lobby", ts - 10, &first).await,
            StatusCode::OK
        );
        let second = rename_msg(&owner, "Den", ts - 5);
        assert_eq!(
            post_rename(&state, &owner, &channel_id, "Den", ts - 5, &second).await,
            StatusCode::OK
        );
        assert_eq!(
            post_rename(&state, &owner, &channel_id, "Den", ts - 5, &second).await,
            StatusCode::OK,
            "the newest rename may be retried"
        );
        assert_ne!(
            post_rename(&state, &owner, &channel_id, "Lobby", ts - 10, &first).await,
            StatusCode::OK,
            "an older one may not be replayed"
        );
        let third = rename_msg(&owner, "Attic", ts);
        assert_eq!(
            post_rename(&state, &owner, &channel_id, "Attic", ts, &third).await,
            StatusCode::TOO_EARLY
        );
        assert_eq!(directory_names(&state).await, vec!["Den".to_string()]);
    }

    /// The two signed forms must not be interchangeable, or the new opcode
    /// buys nothing.
    #[test]
    fn channel_name_signed_forms_are_unambiguous() {
        let channel_id = [7u8; 16];
        let pubkey = [9u8; 32];
        let ts = 1_700_000_000;
        assert_ne!(
            build_channel_name_v4_msg(&channel_id, &pubkey, "lobby", false, ts),
            build_channel_name_display_v4_msg(&channel_id, &pubkey, "lobby", "lobby", false, ts)
        );
        // Length prefixes, so a shifted split between the two strings cannot
        // produce the same bytes.
        assert_ne!(
            build_channel_name_display_v4_msg(&channel_id, &pubkey, "ab", "cd", false, ts),
            build_channel_name_display_v4_msg(&channel_id, &pubkey, "abc", "d", false, ts)
        );
        assert_ne!(
            build_channel_name_display_v4_msg(&channel_id, &pubkey, "lobby", "Lobby", false, ts),
            build_channel_rename_v4_msg(&channel_id, &pubkey, "lobby", "Lobby", false, ts),
            "a claim is never a rename"
        );
    }

    #[tokio::test]
    async fn channel_name_claim_delete_and_directory() {
        let state = test_state();
        let owner = ed25519_dalek::SigningKey::from_bytes(&[0xC3; 32]);
        let other = ed25519_dalek::SigningKey::from_bytes(&[0xD4; 32]);
        let owner_pk = owner.verifying_key().to_bytes();
        let other_pk = other.verifying_key().to_bytes();
        let channel_id = test_channel_id(&owner_pk);
        let other_id = test_channel_id(&other_pk);
        let ts = now_unix_secs();
        let addr = "8.8.8.8:1000".parse().unwrap();

        let private_msg = build_channel_name_v4_msg(&channel_id, &owner_pk, "secret", true, ts);
        assert_eq!(
            claim_channel_name_v4(
                State(state.clone()),
                ConnectInfo(addr),
                HeaderMap::new(),
                Json(ChannelNameRequest {
                    channel_id: hex::encode(channel_id),
                    pubkey: hex::encode(owner_pk),
                    name: "Secret".to_string(),
                    private: true,
                    ts,
                    sig: hex::encode(owner.sign(&private_msg).to_bytes()),
                }),
            )
            .await,
            StatusCode::OK
        );

        let dir = channel_directory_v4(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            Query(DirectoryQuery::default()),
        )
        .await
        .expect("directory");
        assert_eq!(dir.0["channels"].as_array().unwrap().len(), 0);

        let taken = build_channel_name_v4_msg(&other_id, &other_pk, "secret", false, ts);
        assert_eq!(
            claim_channel_name_v4(
                State(state.clone()),
                ConnectInfo("1.1.1.1:2000".parse().unwrap()),
                HeaderMap::new(),
                Json(ChannelNameRequest {
                    channel_id: hex::encode(other_id),
                    pubkey: hex::encode(other_pk),
                    name: "secret".to_string(),
                    private: false,
                    ts,
                    sig: hex::encode(other.sign(&taken).to_bytes()),
                }),
            )
            .await,
            StatusCode::CONFLICT,
            "a taken name must not reveal that the room is private"
        );

        let public_id_key = ed25519_dalek::SigningKey::from_bytes(&[0xE5; 32]);
        let public_pk = public_id_key.verifying_key().to_bytes();
        let public_id = test_channel_id(&public_pk);
        let public_msg = build_channel_name_v4_msg(&public_id, &public_pk, "lobby", false, ts);
        assert_eq!(
            claim_channel_name_v4(
                State(state.clone()),
                ConnectInfo(addr),
                HeaderMap::new(),
                Json(ChannelNameRequest {
                    channel_id: hex::encode(public_id),
                    pubkey: hex::encode(public_pk),
                    name: "Lobby".to_string(),
                    private: false,
                    ts,
                    sig: hex::encode(public_id_key.sign(&public_msg).to_bytes()),
                }),
            )
            .await,
            StatusCode::OK
        );
        let dir = channel_directory_v4(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            Query(DirectoryQuery::default()),
        )
        .await
        .expect("directory");
        assert_eq!(dir.0["channels"].as_array().unwrap().len(), 1);

        let forged = build_channel_delete_v4_msg(&public_id, &other_pk, ts);
        assert_eq!(
            delete_channel_v4(
                State(state.clone()),
                ConnectInfo("9.9.9.9:1000".parse().unwrap()),
                HeaderMap::new(),
                Json(ChannelDeleteRequest {
                    channel_id: hex::encode(public_id),
                    pubkey: hex::encode(other_pk),
                    ts,
                    sig: hex::encode(other.sign(&forged).to_bytes()),
                }),
            )
            .await,
            StatusCode::FORBIDDEN
        );

        let delete_msg = build_channel_delete_v4_msg(&public_id, &public_pk, ts);
        assert_eq!(
            delete_channel_v4(
                State(state.clone()),
                ConnectInfo(addr),
                HeaderMap::new(),
                Json(ChannelDeleteRequest {
                    channel_id: hex::encode(public_id),
                    pubkey: hex::encode(public_pk),
                    ts,
                    sig: hex::encode(public_id_key.sign(&delete_msg).to_bytes()),
                }),
            )
            .await,
            StatusCode::OK
        );
        let gone = channel_deleted_v4(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            Query(DeletedIdsQuery { after: None }),
        )
        .await
        .expect("deleted");
        let ids = gone.0["ids"].as_array().unwrap();
        assert!(ids.iter().any(|v| v.as_str() == Some(&hex::encode(public_id))));

        let reuse_key = ed25519_dalek::SigningKey::from_bytes(&[0xF6; 32]);
        let reuse_pk = reuse_key.verifying_key().to_bytes();
        let reuse_id = test_channel_id(&reuse_pk);
        let reuse = build_channel_name_v4_msg(&reuse_id, &reuse_pk, "lobby", false, ts + 1);
        assert_eq!(
            claim_channel_name_v4(
                State(state),
                ConnectInfo(addr),
                HeaderMap::new(),
                Json(ChannelNameRequest {
                    channel_id: hex::encode(reuse_id),
                    pubkey: hex::encode(reuse_pk),
                    name: "Lobby".to_string(),
                    private: false,
                    ts: ts + 1,
                    sig: hex::encode(reuse_key.sign(&reuse).to_bytes()),
                }),
            )
            .await,
            StatusCode::CONFLICT,
            "a deleted name must not be reclaimable"
        );
    }

    async fn send_register(
        state: &AppState,
        key: &ed25519_dalek::SigningKey,
        port: u16,
        ts: i64,
    ) -> StatusCode {
        let pubkey = key.verifying_key().to_bytes();
        let id = id_from_pubkey(&pubkey);
        let id_raw = decode_hex_id(&id).unwrap();
        let signed = build_register_msg(&id_raw, port, [8, 8, 8, 8], &pubkey, ts);
        register(
            State(state.clone()),
            ConnectInfo("8.8.8.8:1000".parse().unwrap()),
            HeaderMap::new(),
            Json(RegisterRequest {
                id,
                port,
                ip: Some("8.8.8.8".to_string()),
                pubkey: hex::encode(pubkey),
                ts,
                sig: hex::encode(key.sign(&signed).to_bytes()),
            }),
        )
        .await
    }

    async fn send_unregister(state: &AppState, key: &ed25519_dalek::SigningKey, ts: i64) -> StatusCode {
        let id = id_from_pubkey(&key.verifying_key().to_bytes());
        let signed = build_unregister_msg(&decode_hex_id(&id).unwrap(), ts);
        unregister(
            State(state.clone()),
            ConnectInfo("8.8.8.8:1000".parse().unwrap()),
            HeaderMap::new(),
            Json(UnregisterRequest {
                id,
                ts,
                sig: hex::encode(key.sign(&signed).to_bytes()),
            }),
        )
        .await
    }

    /// A register is a keep-alive: re-sending one is harmless and costs no
    /// replay state, but nothing signed before an unregister gets back in.
    #[tokio::test]
    async fn register_refreshes_freely_but_cannot_undo_an_unregister() {
        let state = test_state();
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x71; 32]);
        let ts = now_unix_secs();
        assert_eq!(send_register(&state, &key, 4662, ts).await, StatusCode::OK);
        assert_eq!(
            send_register(&state, &key, 4662, ts).await,
            StatusCode::OK,
            "an identical re-send is a refresh"
        );
        assert!(state.replay_guard.read().await.keys.is_empty());

        assert_eq!(send_unregister(&state, &key, ts + 1).await, StatusCode::OK);
        assert_eq!(
            send_register(&state, &key, 4662, ts).await,
            StatusCode::CONFLICT,
            "a register signed before the unregister must not resurrect presence"
        );
        assert!(state.store.read().await.is_empty());
        assert_eq!(send_register(&state, &key, 4662, ts + 2).await, StatusCode::OK);
        assert_eq!(
            send_unregister(&state, &key, ts + 1).await,
            StatusCode::CONFLICT,
            "a replayed unregister must not knock the user offline again"
        );
        assert_eq!(state.store.read().await.len(), 1);
    }

    async fn send_capability_register(
        state: &AppState,
        owner: &ed25519_dalek::SigningKey,
        peer_pubkey: [u8; 32],
        capability: [u8; 32],
        ip: Ipv4Addr,
        ts: i64,
    ) -> StatusCode {
        let owner_pubkey = owner.verifying_key().to_bytes();
        let epoch = now_unix_secs().div_euclid(15 * 60);
        let v4 = build_capability_register_v4_msg(
            &capability,
            epoch,
            4662,
            &encode_signed_ip(IpAddr::V4(ip)),
            &owner_pubkey,
            &peer_pubkey,
            ts,
        );
        let legacy = build_capability_register_v3_msg(
            &capability,
            epoch,
            4662,
            ip.octets(),
            &owner_pubkey,
            &peer_pubkey,
            ts,
        );
        capability_register_v4(
            State(state.clone()),
            ConnectInfo("8.8.8.8:5000".parse().unwrap()),
            HeaderMap::new(),
            Json(CapabilityRegisterRequest {
                capability: hex::encode(capability),
                epoch,
                port: 4662,
                ip: ip.to_string(),
                pubkey: hex::encode(owner_pubkey),
                peer_pubkey: hex::encode(peer_pubkey),
                ts,
                sig: hex::encode(owner.sign(&v4).to_bytes()),
                intro: false,
                legacy_sig: Some(hex::encode(owner.sign(&legacy).to_bytes())),
                intro_key: None,
            }),
        )
        .await
    }

    /// Capability refreshes are the bulk of all signed traffic. They must keep
    /// no replay state (the v3 proof bundled with v4 used to cost a second
    /// entry), yet an older registration must not roll a newer address back.
    #[tokio::test]
    async fn capability_refreshes_keep_no_replay_state_and_never_roll_back() {
        let state = test_state();
        let (_, _, peer_pubkey) = insert_test_identity(&state, 72).await;
        let (owner, _, _) = insert_test_identity(&state, 73).await;
        let capability = [0xE1; 32];
        let ts = now_unix_secs();
        let first = Ipv4Addr::new(8, 8, 4, 4);
        let moved = Ipv4Addr::new(9, 9, 9, 9);

        for _ in 0..3 {
            assert_eq!(
                send_capability_register(&state, &owner, peer_pubkey, capability, first, ts).await,
                StatusCode::OK
            );
        }
        assert!(state.replay_guard.read().await.keys.is_empty());

        assert_eq!(
            send_capability_register(&state, &owner, peer_pubkey, capability, moved, ts + 1).await,
            StatusCode::OK
        );
        assert_eq!(
            send_capability_register(&state, &owner, peer_pubkey, capability, first, ts).await,
            StatusCode::CONFLICT,
            "replaying the old address must not undo the move"
        );
        assert_eq!(
            send_capability_register(&state, &owner, peer_pubkey, capability, moved, ts).await,
            StatusCode::OK,
            "an older request for the current address only keeps it alive"
        );
        let capabilities = state.capability_store.read().await;
        let entry = &capabilities[&hex::encode(capability)];
        assert_eq!(entry.ip, IpAddr::V4(moved));
        assert_eq!(entry.v4_proof.map(|(signed_ts, _)| signed_ts), Some(ts + 1));
        assert_eq!(entry.legacy_proof.map(|(signed_ts, _)| signed_ts), Some(ts + 1));
    }

    /// Punch registration stays strictly one-time, and a key flooding it has no
    /// effect on anyone else's.
    #[tokio::test]
    async fn a_replayed_punch_registration_is_refused() {
        let state = test_state();
        let (from_key, from_id, from_pubkey) = insert_test_identity(&state, 74).await;
        let (_, target_id, target_pubkey) = insert_test_identity(&state, 75).await;
        let capability = [0xE2; 32];
        let epoch = now_unix_secs().div_euclid(15 * 60);
        state.capability_store.write().await.insert(
            hex::encode(capability),
            PairwisePresenceEntry {
                ip: "8.8.8.8".parse().unwrap(),
                port: 4662,
                expires_at: Instant::now() + ENTRY_TTL,
                peer_pubkey: from_pubkey,
                open_intro: false,
                pubkey: target_pubkey,
                epoch,
                legacy_proof: None,
                v4_proof: Some((now_unix_secs(), [0; 64])),
            },
        );
        let ts = now_unix_secs();
        let nonce = [9u8; 16];
        let signed = build_punch_register_v3_msg(
            &decode_hex_id(&from_id).unwrap(),
            &decode_hex_id(&target_id).unwrap(),
            &capability,
            epoch,
            5000,
            1,
            &nonce,
            ts,
        );
        let request = || CapabilityPunchRequest {
            from_id: from_id.clone(),
            target_id: target_id.clone(),
            capability: hex::encode(capability),
            epoch,
            port: 5000,
            ip: None,
            nat_type: 1,
            ts,
            nonce: hex::encode(nonce),
            sig: hex::encode(from_key.sign(&signed).to_bytes()),
        };
        let send = |addr: &'static str| {
            punch_register_v3(
                State(state.clone()),
                ConnectInfo(addr.parse().unwrap()),
                HeaderMap::new(),
                Json(request()),
            )
        };
        assert_eq!(send("8.8.8.8:5000").await, StatusCode::OK);
        assert_eq!(
            send("1.2.3.4:5000").await,
            StatusCode::CONFLICT,
            "a replay from another host must not steer the target's punches"
        );
        assert_eq!(state.punch_requests.read().await.len(), 1);
    }

    async fn directory_page(state: &AppState, cursor: Option<String>) -> Result<serde_json::Value, StatusCode> {
        channel_directory_v4(
            State(state.clone()),
            ConnectInfo("8.8.8.8:1000".parse().unwrap()),
            HeaderMap::new(),
            Query(DirectoryQuery {
                cursor,
                after: None,
            }),
        )
        .await
        .map(|json| json.0)
    }

    #[tokio::test]
    async fn the_directory_endpoint_pages_with_a_cursor_and_bounds_the_first_page() {
        let state = test_state();
        let total = registry::DIRECTORY_PAGE_SIZE + 20;
        {
            let mut registry = state.channels_registry.write().await;
            for i in 0..total {
                assert!(registry
                    .claim_channel_name(
                        &format!("{:032x}", i + 1),
                        &format!("{:064x}", i + 1),
                        &format!("room{i}"),
                        false,
                    )
                    .is_ok());
            }
        }
        let first = directory_page(&state, None).await.unwrap();
        assert_eq!(
            first["channels"].as_array().unwrap().len(),
            registry::DIRECTORY_PAGE_SIZE,
            "a client that sends no cursor gets one bounded page"
        );
        let next = first["next_cursor"].as_str().unwrap().to_string();
        let second = directory_page(&state, Some(next)).await.unwrap();
        assert_eq!(second["channels"].as_array().unwrap().len(), 20);
        assert!(second["next_cursor"].is_null());

        let mut seen = HashSet::new();
        for page in [&first, &second] {
            for listing in page["channels"].as_array().unwrap() {
                assert!(seen.insert(listing["channel_id"].as_str().unwrap().to_string()));
            }
        }
        assert_eq!(seen.len(), total);

        for bad in ["nope".to_string(), "1.".to_string(), "9".repeat(200)] {
            assert_eq!(directory_page(&state, Some(bad)).await, Err(StatusCode::BAD_REQUEST));
        }
        assert_eq!(
            directory_page(&state, Some(String::new())).await.unwrap()["channels"]
                .as_array()
                .unwrap()
                .len(),
            registry::DIRECTORY_PAGE_SIZE,
            "an empty cursor is the first page"
        );
    }

    #[tokio::test]
    async fn the_registry_is_flushed_on_schedule_and_at_shutdown() {
        let path = std::env::temp_dir().join(format!(
            "ember-shutdown-flush-{}-{}.json",
            std::process::id(),
            now_unix_secs()
        ));
        let registry = RwLock::new(registry::ChannelRegistry::load(path.clone()));
        let persister = RegistryPersister::default();
        let owner = "aa".repeat(32);
        assert!(registry.write().await.claim_username(&owner, "Ada").is_ok());
        assert!(!path.exists(), "a claim alone writes nothing");
        assert!(flush_channels_registry(&registry, &persister).await);
        assert!(registry::ChannelRegistry::load(path.clone()).holds_username(&owner, "Ada"));
        assert_eq!(
            *persister.persisted.borrow(),
            registry.read().await.durable_generation(),
            "a write publishes the generation it covered"
        );

        assert!(registry.write().await.claim_username(&owner, "Lovelace").is_ok());
        assert!(close_channels_registry(&registry, &persister).await);
        assert!(
            registry::ChannelRegistry::load(path.clone()).holds_username(&owner, "Lovelace"),
            "shutdown writes the pending change"
        );
        assert_eq!(
            registry.write().await.claim_username(&owner, "Byron"),
            Err(registry::RegistryError::ReadOnly),
            "nothing is acknowledged after the final snapshot"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A state-creating registry write is on disk before its 200; a refresh
    /// stays debounced.
    #[tokio::test]
    async fn durable_registry_writes_are_persisted_before_they_are_acknowledged() {
        let path = std::env::temp_dir().join(format!(
            "ember-durable-ack-{}-{}.json",
            std::process::id(),
            now_unix_secs()
        ));
        let mut state = test_state();
        state.channels_registry = Arc::new(RwLock::new(registry::ChannelRegistry::load(path.clone())));
        let flusher = tokio::spawn(flush_channels_registry_periodically(
            state.channels_registry.clone(),
            state.registry_persister.clone(),
        ));
        let user = ed25519_dalek::SigningKey::from_bytes(&[0x76; 32]);
        let user_pk = user.verifying_key().to_bytes();
        let claim = |ts: i64| {
            let signed = build_channel_username_v4_msg(&user_pk, "ada", ts);
            claim_channel_username_v4(
                State(state.clone()),
                ConnectInfo("8.8.8.8:1000".parse().unwrap()),
                HeaderMap::new(),
                Json(ChannelUsernameRequest {
                    pubkey: hex::encode(user_pk),
                    name: "Ada".to_string(),
                    ts,
                    sig: hex::encode(user.sign(&signed).to_bytes()),
                }),
            )
        };
        let ts = now_unix_secs();
        assert_eq!(claim(ts).await, StatusCode::OK);
        assert!(
            registry::ChannelRegistry::load(path.clone()).holds_username(&hex::encode(user_pk), "Ada"),
            "a first claim is on disk by the time it is acknowledged"
        );

        let durable = state.channels_registry.read().await.durable_generation();
        assert_eq!(claim(ts + 1).await, StatusCode::OK);
        let registry = state.channels_registry.read().await;
        assert_eq!(registry.durable_generation(), durable, "a refresh is not durable");
        drop(registry);
        flusher.abort();
        let _ = std::fs::remove_file(&path);
    }

    /// A write answered 503 stays applied in memory, so its retry is a no-op;
    /// that retry must still wait for the pending write to reach disk.
    #[tokio::test]
    async fn a_retry_after_a_503_is_only_acknowledged_once_on_disk() {
        let path = std::env::temp_dir().join(format!(
            "ember-durable-retry-{}-{}.json",
            std::process::id(),
            now_unix_secs()
        ));
        let mut state = test_state();
        state.channels_registry = Arc::new(RwLock::new(registry::ChannelRegistry::load(path.clone())));
        let user = ed25519_dalek::SigningKey::from_bytes(&[0x7C; 32]);
        let user_pk = user.verifying_key().to_bytes();
        let claim = |ts: i64| {
            let signed = build_channel_username_v4_msg(&user_pk, "ada", ts);
            claim_channel_username_v4(
                State(state.clone()),
                ConnectInfo("8.8.8.8:1000".parse().unwrap()),
                HeaderMap::new(),
                Json(ChannelUsernameRequest {
                    pubkey: hex::encode(user_pk),
                    name: "Ada".to_string(),
                    ts,
                    sig: hex::encode(user.sign(&signed).to_bytes()),
                }),
            )
        };
        let ts = now_unix_secs();
        // No flusher is running, so nothing can reach disk.
        assert_eq!(claim(ts).await, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            claim(ts + 1).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "the retry is a refresh in memory, but the claim is still not on disk"
        );
        assert!(!path.exists());

        let flusher = tokio::spawn(flush_channels_registry_periodically(
            state.channels_registry.clone(),
            state.registry_persister.clone(),
        ));
        assert_eq!(claim(ts + 2).await, StatusCode::OK);
        assert!(registry::ChannelRegistry::load(path.clone()).holds_username(&hex::encode(user_pk), "Ada"));
        // With nothing pending, a refresh is answered without waiting.
        assert_eq!(claim(ts + 3).await, StatusCode::OK);
        flusher.abort();
        let _ = std::fs::remove_file(&path);
    }

    /// Two registrations signed in the same second cannot be ordered, so only
    /// a byte-for-byte refresh of the live entry is accepted at its timestamp.
    #[tokio::test]
    async fn a_same_second_capability_registration_cannot_change_the_address() {
        let state = test_state();
        let (_, _, peer_pubkey) = insert_test_identity(&state, 77).await;
        let (owner, _, _) = insert_test_identity(&state, 78).await;
        let capability = [0xE3; 32];
        let ts = now_unix_secs();
        let live = Ipv4Addr::new(8, 8, 4, 4);
        assert_eq!(
            send_capability_register(&state, &owner, peer_pubkey, capability, live, ts).await,
            StatusCode::OK
        );
        assert_eq!(
            send_capability_register(&state, &owner, peer_pubkey, capability, Ipv4Addr::new(9, 9, 9, 9), ts)
                .await,
            StatusCode::CONFLICT
        );
        assert_eq!(
            send_capability_register(&state, &owner, peer_pubkey, capability, live, ts).await,
            StatusCode::OK,
            "an identical refresh is still idempotent"
        );
        assert_eq!(
            state.capability_store.read().await[&hex::encode(capability)].ip,
            IpAddr::V4(live)
        );
    }

    async fn send_punch_poll(
        state: &AppState,
        key: &ed25519_dalek::SigningKey,
        target_id: &str,
        nonce: [u8; 16],
        ts: i64,
    ) -> StatusCode {
        let signed = build_punch_poll_v4_msg(&decode_hex_id(target_id).unwrap(), &nonce, ts);
        match punch_poll_v4(
            State(state.clone()),
            ConnectInfo("8.8.8.8:1000".parse().unwrap()),
            HeaderMap::new(),
            Json(CapabilityPunchPollRequest {
                target_id: target_id.to_string(),
                ts,
                nonce: hex::encode(nonce),
                sig: hex::encode(key.sign(&signed).to_bytes()),
            }),
        )
        .await
        {
            Ok(_) => StatusCode::OK,
            Err(status) => status,
        }
    }

    /// A replayed poll would lease whatever is queued now to whoever holds it.
    #[tokio::test]
    async fn a_punch_poll_is_one_time_and_costs_one_mark() {
        let state = test_state();
        let (key, id, pubkey) = insert_test_identity(&state, 79).await;
        let ts = now_unix_secs();
        assert_eq!(send_punch_poll(&state, &key, &id, [1; 16], ts).await, StatusCode::NOT_FOUND);
        assert_eq!(
            send_punch_poll(&state, &key, &id, [1; 16], ts).await,
            StatusCode::CONFLICT,
            "the same poll is not served twice"
        );
        assert_eq!(
            send_punch_poll(&state, &key, &id, [2; 16], ts).await,
            StatusCode::NOT_FOUND,
            "a second poll in the same second is a new request"
        );
        assert_eq!(send_punch_poll(&state, &key, &id, [3; 16], ts + 1).await, StatusCode::NOT_FOUND);
        assert_eq!(send_punch_poll(&state, &key, &id, [2; 16], ts).await, StatusCode::CONFLICT);
        assert_eq!(state.replay_guard.read().await.keys[&pubkey].marks.len(), 1);
    }

    /// Reads keep no marks, but nothing signed before an unregister is served.
    #[tokio::test]
    async fn reads_signed_before_an_unregister_are_refused() {
        let state = test_state();
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x7A; 32]);
        let pubkey = key.verifying_key().to_bytes();
        let id = id_from_pubkey(&pubkey);
        let (_, target_id, _) = insert_test_identity(&state, 0x7B).await;
        let ts = now_unix_secs();
        assert_eq!(send_register(&state, &key, 4662, ts).await, StatusCode::OK);

        let nonce = [5u8; 16];
        let signed = build_identity_lookup_v4_msg(
            &decode_hex_id(&target_id).unwrap(),
            &decode_hex_id(&id).unwrap(),
            &pubkey,
            &nonce,
            ts,
        );
        let lookup = || {
            identity_lookup_v4(
                State(state.clone()),
                ConnectInfo("8.8.8.8:1000".parse().unwrap()),
                HeaderMap::new(),
                Json(IdentityLookupRequest {
                    target_id: target_id.clone(),
                    requester_id: id.clone(),
                    requester_pubkey: hex::encode(pubkey),
                    nonce: hex::encode(nonce),
                    ts,
                    sig: hex::encode(key.sign(&signed).to_bytes()),
                }),
            )
        };
        assert!(lookup().await.is_ok());
        assert_eq!(send_unregister(&state, &key, ts + 1).await, StatusCode::OK);
        assert_eq!(send_register(&state, &key, 4662, ts + 2).await, StatusCode::OK);
        assert_eq!(lookup().await.err(), Some(StatusCode::CONFLICT));
        assert_eq!(
            send_punch_poll(&state, &key, &id, [6; 16], ts).await,
            StatusCode::CONFLICT,
            "a poll signed before the unregister is refused too"
        );
    }
}
