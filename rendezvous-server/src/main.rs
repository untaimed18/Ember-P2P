use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
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
        ConnectInfo, DefaultBodyLimit, Path, State,
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
const REPLAY_CACHE_TTL: Duration = Duration::from_secs((MAX_TIMESTAMP_SKEW_SECS as u64) * 2);
const MAX_REPLAY_CACHE_ENTRIES: usize = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplayCacheAdmission {
    Remembered,
    Replay,
    Full,
}

/// Read-only ticket poll/status requests intentionally reuse a stable nonce
/// and are safe to serve idempotently. Keep just one nonce per read scope,
/// rather than one entry per periodic request, so normal polling cannot
/// exhaust the mutation replay cache.
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
    let now = now_unix_secs();
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

fn signed_request_replay_key(message: &[u8], sig: &[u8; 64]) -> [u8; 32] {
    let mut sha = Sha256::new();
    sha.update(message);
    sha.update(sig);
    sha.finalize().into()
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
/// New channel names one IP may claim per hour.
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
/// remainder keeps a stranger with the target's `ember2:` code from crowding its
/// actual friends out of the queue.
const MAX_PUNCH_PER_TARGET_OPEN_INTRO: usize = 2;
const MAX_PUNCH_REQUESTS_TOTAL: usize = 100_000;
/// Per-IP relay session cap. Was `2`, which was the cause of every
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
const MAX_RELAY_SESSIONS_PER_IP: usize = 32;
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
    /// capability. Used for friend-code intro presence (holders of `ember2:`).
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
fn open_intro_punch_slots_exhausted(
    punches: &HashMap<(String, String), PunchEntry>,
    target: &str,
) -> bool {
    punches
        .iter()
        .filter(|((candidate, _), entry)| candidate == target && entry.via_open_intro)
        .count()
        >= MAX_PUNCH_PER_TARGET_OPEN_INTRO
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

#[derive(Clone)]
struct RateEntry {
    count: u64,
    window_start: Instant,
}

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
    initiator: &String,
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
    *last_scanned = Some(initiator.clone());
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
                // the ticket now would strand its `relay_ip_counts` increment
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

#[derive(Default)]
struct ReplayCache {
    entries: HashMap<[u8; 32], Instant>,
    expirations: VecDeque<(Instant, [u8; 32])>,
}

impl ReplayCache {
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
                .is_some_and(|expires_at| *expires_at <= now)
            {
                self.entries.remove(&key);
            }
        }
    }
}

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
    /// Per-IP rate-limit window for the **general** API surface
    /// (`register`, `lookup`, `unregister`, `relay-invite`, etc.).
    /// Punch traffic now lives in `punch_rate_limits` so a flood of
    /// punch registrations no longer steals the budget from unrelated
    /// endpoints — earlier this map was shared, and a single LowID
    /// peer's punch retries could 429 lookup/register for the same IP.
    rate_limits: Arc<RwLock<HashMap<IpAddr, RateEntry>>>,
    /// Temporary unauthenticated v3 identity oracle budget. It must not share
    /// counters with authenticated registration/lookup traffic: otherwise a
    /// normal rollout registration burst can consume the tighter legacy cap
    /// before an old client performs its first identity lookup.
    legacy_identity_rate_limits: Arc<RwLock<HashMap<IpAddr, RateEntry>>>,
    /// Separate per-IP budget for authenticated relay ticket poll/status
    /// reads. This prevents normal fallback traffic from consuming punch or
    /// general API capacity.
    ticket_read_rate_limits: Arc<RwLock<HashMap<IpAddr, RateEntry>>>,
    /// Per-IP rate-limit window for hole-punch register traffic.
    /// Counted separately from `rate_limits` so the documented
    /// `MAX_PUNCH_PER_MINUTE` budget is the only thing throttling
    /// punch attempts.
    punch_rate_limits: Arc<RwLock<HashMap<IpAddr, RateEntry>>>,
    /// Per-IP, per-*hour* budget for first-time channel name claims. Separate
    /// map because it is the only bucket measured over an hour rather than a
    /// minute; sharing one would either let a minute's worth of room creation
    /// through unchecked or throttle ordinary traffic to a creation rate.
    channel_create_rate_limits: Arc<RwLock<HashMap<IpAddr, RateEntry>>>,
    /// Pending hole-punch registrations, keyed by `(target_id, from_id)`.
    /// Keying by both IDs (rather than just `target_id`) prevents an
    /// unauthenticated attacker from overwriting a legit registrant's
    /// slot for a given victim — the worst they can do now is fill an
    /// extra slot under their own attacker-controlled `from_id`, which
    /// the per-target cap below bounds.
    punch_requests: Arc<RwLock<HashMap<(String, String), PunchEntry>>>,
    relay_sessions: Arc<RwLock<HashMap<String, RelaySessionEntry>>>,
    bridged_relays: Arc<RwLock<HashMap<String, BridgedRelayEntry>>>,
    relay_admissions: Arc<RwLock<HashMap<(String, RelayRole), IpAddr>>>,
    relay_ip_counts: Arc<RwLock<HashMap<IpAddr, usize>>>,
    next_relay_reservation_id: Arc<AtomicU64>,
    relay_tickets: Arc<RwLock<RelayTicketStore>>,
    /// Process-lifetime secret used to issue role tokens on demand. Ticket
    /// records retain only SHA-256 token hashes; rotating this key on restart
    /// invalidates every outstanding short-lived ticket.
    relay_token_key: [u8; 32],
    /// Recently accepted signed mutating requests. Timestamps keep messages
    /// fresh; this cache prevents replaying a captured fresh register or
    /// unregister within that allowed skew window. It intentionally excludes
    /// idempotent ticket reads; see the scope-bounded caches below.
    replay_cache: Arc<RwLock<ReplayCache>>,
    /// One stable poll nonce per live responder identity. Replays are
    /// idempotent reads, while a different nonce for the same identity is
    /// rejected until the entry expires.
    poll_read_nonces: Arc<RwLock<ScopedNonceCache<[u8; 32]>>>,
    /// One stable status nonce per `(initiator, ticket)` pair. Keeping this
    /// separate bounds rapid initiator status checks without weakening the
    /// one-time mutation cache used by offer/accept.
    status_read_nonces: Arc<RwLock<ScopedNonceCache<([u8; 32], [u8; 32])>>>,
    started_at: Instant,
    /// Unique Channel usernames and room names. Persistence is a JSON file
    /// when `CHANNELS_REGISTRY_PATH` is set; otherwise names live only in
    /// this process and vanish on restart.
    channels_registry: Arc<RwLock<registry::ChannelRegistry>>,
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
    if config.mode == ProxyMode::Fly && config.trusts_hop(addr.ip()) {
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
    limits: &Arc<RwLock<HashMap<IpAddr, RateEntry>>>,
    ip: IpAddr,
    max_requests: u64,
    window: Duration,
) -> bool {
    let mut limits = limits.write().await;
    let now = Instant::now();
    if limits.len() >= MAX_RATE_ENTRIES && !limits.contains_key(&ip) {
        // Same rationale as the store cap in `register`: purge
        // entries that are stale by the sweep's own definition before
        // failing closed on a brand-new IP, so a map that's merely
        // full of old churn doesn't 429 every first-time caller until
        // the next sweep cycle happens to run.
        limits.retain(|_, entry| now.duration_since(entry.window_start) < window * 2);
        if limits.len() >= MAX_RATE_ENTRIES && !limits.contains_key(&ip) {
            return false;
        }
    }
    let entry = limits.entry(ip).or_insert(RateEntry {
        count: 0,
        window_start: now,
    });
    if now.duration_since(entry.window_start) >= window {
        entry.count = 1;
        entry.window_start = now;
        true
    } else {
        entry.count += 1;
        entry.count <= max_requests
    }
}

async fn check_rate_limit_bucket(
    limits: &Arc<RwLock<HashMap<IpAddr, RateEntry>>>,
    ip: IpAddr,
    max_requests: u64,
) -> bool {
    check_rate_limit_bucket_in(limits, ip, max_requests, RATE_WINDOW).await
}

async fn check_rate_limit(state: &AppState, ip: IpAddr) -> bool {
    check_rate_limit_bucket(&state.rate_limits, ip, MAX_REQUESTS_PER_MINUTE).await
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
async fn check_channel_create_rate_limit(state: &AppState, ip: IpAddr) -> bool {
    check_rate_limit_bucket_in(
        &state.channel_create_rate_limits,
        ip,
        MAX_CHANNEL_CREATES_PER_HOUR,
        CHANNEL_CREATE_WINDOW,
    )
    .await
}

#[cfg(test)]
fn admit_replay_key(
    cache: &mut ReplayCache,
    key: [u8; 32],
    now: Instant,
    max_entries: usize,
) -> ReplayCacheAdmission {
    cache.prune_expired(now);
    if cache.entries.contains_key(&key) {
        return ReplayCacheAdmission::Replay;
    }
    if cache.entries.len() >= max_entries {
        // A still-fresh replay entry is security state. Evicting it to make
        // room would re-open its replay window, so fail closed instead.
        return ReplayCacheAdmission::Full;
    }
    let expires_at = now + REPLAY_CACHE_TTL;
    cache.entries.insert(key, expires_at);
    cache.expirations.push_back((expires_at, key));
    ReplayCacheAdmission::Remembered
}

fn admit_replay_keys(
    cache: &mut ReplayCache,
    keys: &[[u8; 32]],
    now: Instant,
    max_entries: usize,
) -> ReplayCacheAdmission {
    cache.prune_expired(now);
    for (index, key) in keys.iter().enumerate() {
        if cache.entries.contains_key(key) || keys[..index].contains(key) {
            return ReplayCacheAdmission::Replay;
        }
    }
    if keys.len() > max_entries.saturating_sub(cache.entries.len()) {
        return ReplayCacheAdmission::Full;
    }
    let expires_at = now + REPLAY_CACHE_TTL;
    for key in keys {
        cache.entries.insert(*key, expires_at);
        cache.expirations.push_back((expires_at, *key));
    }
    ReplayCacheAdmission::Remembered
}

async fn remember_signed_request(state: &AppState, key: [u8; 32]) -> ReplayCacheAdmission {
    let mut cache = state.replay_cache.write().await;
    admit_replay_keys(
        &mut cache,
        std::slice::from_ref(&key),
        Instant::now(),
        MAX_REPLAY_CACHE_ENTRIES,
    )
}

async fn remember_signed_requests(state: &AppState, keys: &[[u8; 32]]) -> ReplayCacheAdmission {
    let mut cache = state.replay_cache.write().await;
    admit_replay_keys(&mut cache, keys, Instant::now(), MAX_REPLAY_CACHE_ENTRIES)
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

fn replay_cache_status(admission: ReplayCacheAdmission) -> Result<(), StatusCode> {
    match admission {
        ReplayCacheAdmission::Remembered => Ok(()),
        ReplayCacheAdmission::Replay => Err(StatusCode::CONFLICT),
        ReplayCacheAdmission::Full => Err(StatusCode::SERVICE_UNAVAILABLE),
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

/// Verify a signature made by a currently registered identity. The presence
/// entry's pinned key is the authority, so callers never provide a
/// freely-chosen pubkey.
async fn verify_signed_relay_identity_signature(
    state: &AppState,
    identity_id: &str,
    message: &[u8],
    sig: &[u8; 64],
) -> Result<(), StatusCode> {
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
    Ok(())
}

/// Verify and one-time-admit a mutating ticket action. Poll/status reads use
/// their own bounded idempotent nonce caches instead.
async fn verify_signed_relay_identity(
    state: &AppState,
    identity_id: &str,
    message: &[u8],
    sig: &[u8; 64],
) -> Result<(), StatusCode> {
    verify_signed_relay_identity_signature(state, identity_id, message, sig).await?;
    replay_cache_status(
        remember_signed_request(state, signed_request_replay_key(message, sig)).await,
    )?;
    Ok(())
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
        // per-IP count). That retention must not admit new joins past expiry.
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

    // The ticket lock stays held until capacity is reserved so a failed
    // pre-upgrade check neither burns the token nor returns a false 101.
    let mut counts = state.relay_ip_counts.write().await;
    let global_total: usize = counts.values().sum();
    if global_total >= MAX_GLOBAL_RELAY_SESSIONS {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let count = counts.entry(client_ip).or_insert(0);
    if *count >= MAX_RELAY_SESSIONS_PER_IP {
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
        let mut counts = state.relay_ip_counts.write().await;
        if let Some(count) = counts.get_mut(&reservation.client_ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&reservation.client_ip);
            }
        }
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
    if let Err(status) = replay_cache_status(
        remember_signed_request(&state, signed_request_replay_key(&msg, &sig_bytes)).await,
    ) {
        return status;
    }

    let entry = PresenceEntry {
        expires_at: Instant::now() + ENTRY_TTL,
        pubkey,
    };

    let mut store = state.store.write().await;
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
        // Before failing closed on a brand-new id, opportunistically
        // purge already-expired entries — a map that's merely full of
        // stale junk (normal churn between sweep cycles) shouldn't
        // lock out legitimate new registrants the same way a genuine
        // sustained flood would. This is cheap (O(n) scan, no
        // allocation beyond the retain) and bounded to the same work
        // the periodic sweep already does every `SWEEP_INTERVAL`.
        let now = Instant::now();
        store.retain(|_, e| e.expires_at > now);
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
    if let Err(status) =
        replay_cache_status(remember_signed_request(&state, signed_request_replay_key(&signed, &sig)).await)
    {
        return status;
    }
    let mut registry = state.channels_registry.write().await;
    match registry.claim_username(&hex::encode(pubkey), &normalized) {
        Ok(()) => StatusCode::OK,
        Err(err) => registry_error_status(err),
    }
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
    let signed = build_channel_name_v4_msg(&channel_id, &pubkey, &normalized, body.private, body.ts);
    if !ed25519_verify(&pubkey, &signed, &sig) {
        return StatusCode::FORBIDDEN;
    }
    if let Err(status) =
        replay_cache_status(remember_signed_request(&state, signed_request_replay_key(&signed, &sig)).await)
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
    match registry.claim_channel_name(&channel_hex, &hex::encode(pubkey), &body.name, body.private)
    {
        Ok(()) => StatusCode::OK,
        Err(err) => registry_error_status(err),
    }
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
    if let Err(status) =
        replay_cache_status(remember_signed_request(&state, signed_request_replay_key(&signed, &sig)).await)
    {
        return status;
    }
    let mut registry = state.channels_registry.write().await;
    match registry.delete_channel(&hex::encode(channel_id), &hex::encode(pubkey)) {
        Ok(()) => StatusCode::OK,
        Err(err) => registry_error_status(err),
    }
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
    if let Err(status) =
        replay_cache_status(remember_signed_request(&state, signed_request_replay_key(&signed, &sig)).await)
    {
        return status;
    }
    let nominee_hex = if nominee == [0u8; 32] {
        String::new()
    } else {
        hex::encode(nominee)
    };
    let mut registry = state.channels_registry.write().await;
    match registry.set_channel_nominee(
        &hex::encode(channel_id),
        &hex::encode(pubkey),
        &nominee_hex,
        body.claim_after_days,
    ) {
        Ok(()) => StatusCode::OK,
        Err(err) => registry_error_status(err),
    }
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
    if let Err(status) =
        replay_cache_status(remember_signed_request(&state, signed_request_replay_key(&signed, &sig)).await)
    {
        return status;
    }
    let mut registry = state.channels_registry.write().await;
    match registry.handover_channel_name(
        &hex::encode(old_channel_id),
        &hex::encode(new_channel_id),
        &hex::encode(new_pubkey),
        &hex::encode(signer),
        now_unix_secs(),
    ) {
        Ok(()) => StatusCode::OK,
        Err(err) => registry_error_status(err),
    }
}

async fn channel_directory_v4(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    // Read-only: `public_directory` already hides listings the owner has
    // stopped refreshing, so serving Discover never needs the write lock that
    // reaping takes.
    let registry = state.channels_registry.read().await;
    Ok(Json(serde_json::json!({
        "channels": registry.public_directory(),
    })))
}

async fn channel_deleted_v4(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let registry = state.channels_registry.read().await;
    Ok(Json(serde_json::json!({
        "ids": registry.deleted_ids(),
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
    replay_cache_status(
        remember_signed_request(&state, signed_request_replay_key(&signed, &sig)).await,
    )?;
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
    // An intro capability is derived from the owner's public key and the epoch,
    // both of which travel in a public `ember2:` friend code. Anyone holding
    // that code can therefore derive a victim's current capability and sign a
    // valid registration for it with their own key. Recomputing the derivation
    // binds the namespace to its owner, so a stranger cannot claim it at all —
    // neither to replace a live entry nor to squat an epoch before the owner
    // registers, which the owner pin alone would still permit.
    if body.intro && capability != derive_intro_presence_capability(&pubkey, body.epoch) {
        return StatusCode::FORBIDDEN;
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
    let mut replay_keys = vec![signed_request_replay_key(&signed, &sig)];
    if let (Some(legacy_sig), Some(legacy_signed)) = (legacy_sig, legacy_signed.as_ref()) {
        replay_keys.push(signed_request_replay_key(legacy_signed, &legacy_sig));
    }
    if let Err(status) = replay_cache_status(remember_signed_requests(&state, &replay_keys).await) {
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
        capabilities.retain(|_, entry| entry.expires_at > now);
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
    match version {
        RendezvousVersion::LegacyV3 => entry.legacy_proof = Some((body.ts, sig)),
        RendezvousVersion::IpBoundV4 => {
            entry.v4_proof = Some((body.ts, sig));
            if let Some(legacy_sig) = legacy_sig {
                entry.legacy_proof = Some((body.ts, legacy_sig));
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
    replay_cache_status(
        remember_signed_request(&state, signed_request_replay_key(&signed, &sig)).await,
    )?;
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
            if let Err(status) = replay_cache_status(
                remember_signed_request(&state, signed_request_replay_key(&msg, &sig_bytes)).await,
            ) {
                return status;
            }
            // Crypto and replay-cache work is deliberately outside the global
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

fn prune_expired_punches(punches: &mut HashMap<(String, String), PunchEntry>, now: Instant) {
    punches.retain(|_, entry| now.duration_since(entry.created_at) < PUNCH_TTL);
}

fn punch_available(entry: &PunchEntry, now: Instant) -> bool {
    entry.leased_until.map_or(true, |until| until <= now)
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
    if let Err(status) = verify_signed_relay_identity(&state, &body.from_id, &signed, &sig).await {
        return status;
    }
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
    let from = body.from_id.to_lowercase();
    let key = (target.clone(), from.clone());
    let now = Instant::now();
    let mut punches = state.punch_requests.write().await;
    prune_expired_punches(&mut punches, now);
    if !punches.contains_key(&key)
        && (punches.len() >= MAX_PUNCH_REQUESTS_TOTAL
            || punches
                .keys()
                .filter(|(candidate, _)| candidate == &target)
                .count()
                >= MAX_PUNCH_PER_TARGET)
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
        && !punches.contains_key(&key)
        && open_intro_punch_slots_exhausted(&punches, &target)
    {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    punches.insert(
        key,
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
    verify_signed_relay_identity(&state, &body.target_id, &signed, &sig).await?;
    let target = body.target_id.to_lowercase();
    let now = Instant::now();
    let mut punches = state.punch_requests.write().await;
    prune_expired_punches(&mut punches, now);
    let key = punches
        .iter()
        .filter(|((candidate, _), entry)| {
            candidate == &target
                && punch_available(entry, now)
                // v4 clients must only observe IP-bound registrations. Serving a
                // legacy entry on /v4/punch/poll would force the desktop to either
                // fail open (previous bug) or 404 mid-handshake.
                && (version == RendezvousVersion::LegacyV3
                    || entry.proof_version == RendezvousVersion::IpBoundV4)
        })
        .min_by_key(|(_, entry)| entry.created_at)
        .map(|(key, _)| key.clone())
        .or_else(|| {
            // Idempotent re-poll: if every entry is still leased to us, refresh
            // the oldest lease rather than 404 mid-handshake.
            punches
                .iter()
                .filter(|((candidate, _), entry)| {
                    candidate == &target
                        && (version == RendezvousVersion::LegacyV3
                            || entry.proof_version == RendezvousVersion::IpBoundV4)
                })
                .min_by_key(|(_, entry)| entry.created_at)
                .map(|(key, _)| key.clone())
        })
        .ok_or(StatusCode::NOT_FOUND)?;
    let entry = punches.get_mut(&key).ok_or(StatusCode::NOT_FOUND)?;
    entry.leased_until = Some(now + PUNCH_LEASE);
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
    if let Err(status) = verify_signed_relay_identity(&state, &body.target_id, &signed, &sig).await
    {
        return status;
    }
    let target = body.target_id.to_lowercase();
    let mut punches = state.punch_requests.write().await;
    let key = punches
        .iter()
        .find(|((candidate, _), entry)| {
            candidate == &target
                && entry.punch_id.eq_ignore_ascii_case(&body.punch_id)
                && entry.capability == capability
                && entry.epoch == body.epoch
        })
        .map(|(key, _)| key.clone());
    match key.and_then(|key| punches.remove(&key)) {
        Some(_) => StatusCode::OK,
        None => StatusCode::NOT_FOUND,
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
    verify_signed_relay_identity(&state, &body.initiator_id, &signed, &sig).await?;

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
    verify_signed_relay_identity_signature(&state, &body.responder_id, &signed, &sig).await?;
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
    verify_signed_relay_identity(&state, &body.identity_id, &signed, &sig).await?;

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
    verify_signed_relay_identity_signature(&state, &body.identity_id, &signed, &sig).await?;

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
    let Some(client_ip) = client_ip else {
        return;
    };
    let mut counts = state.relay_ip_counts.write().await;
    if let Some(count) = counts.get_mut(&client_ip) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(&client_ip);
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
    let mut counts = state.relay_ip_counts.write().await;
    for ip in removed_ips {
        if let Some(count) = counts.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&ip);
            }
        }
    }
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
    let relay_ip_count = state.relay_ip_counts.read().await.len();
    let presence_count = state.store.read().await.len();
    let uptime_secs = state.started_at.elapsed().as_secs();

    Ok(Json(serde_json::json!({
        "active_relay_sessions": relay_count,
        "active_punch_requests": punch_count,
        "relay_ip_count": relay_ip_count,
        "registered_peers": presence_count,
        "uptime_seconds": uptime_secs,
        "max_global_relays": MAX_GLOBAL_RELAY_SESSIONS,
    })))
}

async fn health() -> &'static str {
    "ok"
}

async fn sweep_expired(state: AppState) {
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
        {
            let mut limits = state.rate_limits.write().await;
            limits.retain(|_, entry| now.duration_since(entry.window_start) < RATE_WINDOW * 2);
        }
        {
            let mut limits = state.legacy_identity_rate_limits.write().await;
            limits.retain(|_, entry| now.duration_since(entry.window_start) < RATE_WINDOW * 2);
        }
        {
            let mut limits = state.ticket_read_rate_limits.write().await;
            limits.retain(|_, entry| now.duration_since(entry.window_start) < RATE_WINDOW * 2);
        }

        // Sweep the punch-specific rate-limit map on the same cadence
        // as the general one so the per-IP entries don't pile up after
        // a punch burst goes quiet.
        {
            let mut limits = state.punch_rate_limits.write().await;
            limits.retain(|_, entry| now.duration_since(entry.window_start) < RATE_WINDOW * 2);
        }

        // Swept against its own hour-long window. Using the general one here
        // would drop entries that are still inside their budget and hand the
        // creator a fresh six rooms every couple of minutes.
        {
            let mut limits = state.channel_create_rate_limits.write().await;
            limits
                .retain(|_, entry| now.duration_since(entry.window_start) < CHANNEL_CREATE_WINDOW);
        }

        {
            let mut replay = state.replay_cache.write().await;
            replay.prune_expired(now);
        }
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
            let mut punches = state.punch_requests.write().await;
            let punch_before = punches.len();
            punches.retain(|_, e| now.duration_since(e.created_at) < PUNCH_TTL);
            let punch_removed = punch_before - punches.len();
            if punch_removed > 0 {
                info!("swept {} expired punch requests", punch_removed);
            }
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ember_rendezvous=info".into()),
        )
        .init();

    let state = AppState {
        store: Arc::new(RwLock::new(HashMap::new())),
        capability_store: Arc::new(RwLock::new(HashMap::new())),
        rate_limits: Arc::new(RwLock::new(HashMap::new())),
        legacy_identity_rate_limits: Arc::new(RwLock::new(HashMap::new())),
        ticket_read_rate_limits: Arc::new(RwLock::new(HashMap::new())),
        punch_rate_limits: Arc::new(RwLock::new(HashMap::new())),
        channel_create_rate_limits: Arc::new(RwLock::new(HashMap::new())),
        punch_requests: Arc::new(RwLock::new(HashMap::new())),
        relay_sessions: Arc::new(RwLock::new(HashMap::new())),
        bridged_relays: Arc::new(RwLock::new(HashMap::new())),
        relay_admissions: Arc::new(RwLock::new(HashMap::new())),
        relay_ip_counts: Arc::new(RwLock::new(HashMap::new())),
        next_relay_reservation_id: Arc::new(AtomicU64::new(1)),
        relay_tickets: Arc::new(RwLock::new(RelayTicketStore::default())),
        relay_token_key: {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            key
        },
        replay_cache: Arc::new(RwLock::new(ReplayCache::default())),
        poll_read_nonces: Arc::new(RwLock::new(ScopedNonceCache::new())),
        status_read_nonces: Arc::new(RwLock::new(ScopedNonceCache::new())),
        started_at: Instant::now(),
        channels_registry: load_channels_registry(),
    };

    tokio::spawn(sweep_expired(state.clone()));

    let app = Router::new()
        .route("/register", post(register))
        .route("/lookup/{id}", get(legacy_presence_lookup_gone))
        .route("/unregister", delete(unregister))
        .route("/v3/identity/{id}", get(legacy_identity_lookup))
        .route("/v3/presence/register", post(capability_register_v3))
        .route("/v3/presence/lookup", post(capability_lookup_v3))
        .route("/v4/protocol", get(protocol_v4))
        .route("/v4/identity/lookup", post(identity_lookup_v4))
        .route("/v4/presence/register", post(capability_register_v4))
        .route("/v4/presence/lookup", post(capability_lookup_v4))
        .route("/punch", post(legacy_punch_gone))
        .route("/punch/{id}", get(legacy_punch_gone))
        .route("/v2/punch/register", post(legacy_punch_gone))
        .route("/v2/punch/poll", post(legacy_punch_gone))
        .route("/v2/punch/ack", post(legacy_punch_gone))
        .route("/v3/punch/register", post(punch_register_v3))
        .route("/v3/punch/poll", post(punch_poll_v3))
        .route("/v3/punch/ack", post(punch_ack_v3))
        .route("/v4/punch/register", post(punch_register_v4))
        .route("/v4/punch/poll", post(punch_poll_v4))
        .route("/v4/punch/ack", post(punch_ack_v4))
        .route("/v4/channels/username", post(claim_channel_username_v4))
        .route("/v4/channels/name", post(claim_channel_name_v4))
        .route("/v4/channels/delete", post(delete_channel_v4))
        .route("/v4/channels/nominee", post(set_channel_nominee_v4))
        .route("/v4/channels/handover", post(handover_channel_name_v4))
        .route("/v4/channels/directory", get(channel_directory_v4))
        .route("/v4/channels/deleted", get(channel_deleted_v4))
        .route("/v2/relay-tickets/offer", post(legacy_punch_gone))
        .route("/v2/relay-tickets/poll", post(legacy_punch_gone))
        .route("/v3/relay-tickets/poll", post(legacy_punch_gone))
        .route("/v4/relay-mailbox/offer", post(relay_mailbox_offer))
        .route("/v4/relay-mailbox/poll", post(relay_mailbox_poll))
        .route(
            "/v2/relay-tickets/{ticket_id}/accept",
            post(relay_ticket_accept),
        )
        .route(
            "/v2/relay-tickets/{ticket_id}/status",
            post(relay_ticket_status),
        )
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
        .with_state(state);

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
                tokio::spawn(async move {
                    use tower::ServiceExt;
                    let _permit = permit;
                    let service = hyper::service::service_fn(
                        move |request: hyper::Request<hyper::body::Incoming>| {
                            let app = app.clone();
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
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            legacy_identity_rate_limits: Arc::new(RwLock::new(HashMap::new())),
            ticket_read_rate_limits: Arc::new(RwLock::new(HashMap::new())),
            punch_rate_limits: Arc::new(RwLock::new(HashMap::new())),
            channel_create_rate_limits: Arc::new(RwLock::new(HashMap::new())),
            punch_requests: Arc::new(RwLock::new(HashMap::new())),
            relay_sessions: Arc::new(RwLock::new(HashMap::new())),
            bridged_relays: Arc::new(RwLock::new(HashMap::new())),
            relay_admissions: Arc::new(RwLock::new(HashMap::new())),
            relay_ip_counts: Arc::new(RwLock::new(HashMap::new())),
            next_relay_reservation_id: Arc::new(AtomicU64::new(1)),
            relay_tickets: Arc::new(RwLock::new(RelayTicketStore::default())),
            relay_token_key: [0x5a; 32],
            replay_cache: Arc::new(RwLock::new(ReplayCache::default())),
            poll_read_nonces: Arc::new(RwLock::new(ScopedNonceCache::new())),
            status_read_nonces: Arc::new(RwLock::new(ScopedNonceCache::new())),
            started_at: Instant::now(),
            channels_registry: Arc::new(RwLock::new(registry::ChannelRegistry::in_memory())),
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
                .get(&addr.ip())
                .unwrap()
                .count,
            31
        );
        drop(peer);
    }

    #[test]
    fn replay_cache_fails_closed_without_evicting_fresh_entries() {
        let now = Instant::now();
        let mut cache = ReplayCache::default();
        assert_eq!(
            admit_replay_key(&mut cache, [1; 32], now, 2),
            ReplayCacheAdmission::Remembered
        );
        assert_eq!(
            admit_replay_key(&mut cache, [2; 32], now, 2),
            ReplayCacheAdmission::Remembered
        );
        assert_eq!(
            admit_replay_key(&mut cache, [3; 32], now, 2),
            ReplayCacheAdmission::Full
        );
        assert!(cache.entries.contains_key(&[1; 32]));
        assert!(cache.entries.contains_key(&[2; 32]));
        assert!(!cache.entries.contains_key(&[3; 32]));
        assert_eq!(
            replay_cache_status(ReplayCacheAdmission::Full),
            Err(StatusCode::SERVICE_UNAVAILABLE)
        );
        assert_eq!(
            replay_cache_status(ReplayCacheAdmission::Replay),
            Err(StatusCode::CONFLICT)
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
        assert!(tickets.pending_by_responder.get(&responder_id).is_some());
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
        let mut punches = HashMap::new();
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
                (target.clone(), format!("{i:064x}")),
                entry(&format!("{i:064x}"), true),
            );
        }
        assert!(
            open_intro_punch_slots_exhausted(&punches, &target),
            "a stranger past the reserved share must be refused"
        );

        // Pairwise-bound friends never count against that share, and the share is
        // per target rather than global.
        let mut pairwise_only = HashMap::new();
        for i in 0..MAX_PUNCH_PER_TARGET {
            pairwise_only.insert(
                (target.clone(), format!("{i:064x}")),
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

    #[test]
    fn punch_lease_prefers_unleased_over_leased_head() {
        let now = Instant::now();
        let mut punches = HashMap::new();
        punches.insert(
            ("tt".repeat(32), "aa".repeat(32)),
            PunchEntry {
                punch_id: "11".repeat(32),
                from_id: "aa".repeat(32),
                from_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                from_port: 1,
                nat_type: 1,
                capability: [1; 32],
                epoch: 1,
                created_at: now,
                leased_until: Some(now + PUNCH_LEASE),
                proof_version: RendezvousVersion::IpBoundV4,
                register_nonce: Some([1; 16]),
                register_ts: Some(1),
                register_sig: Some([1; 64]),
                from_pubkey: Some([1; 32]),
                via_open_intro: false,
            },
        );
        punches.insert(
            ("tt".repeat(32), "bb".repeat(32)),
            PunchEntry {
                punch_id: "22".repeat(32),
                from_id: "bb".repeat(32),
                from_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
                from_port: 2,
                nat_type: 1,
                capability: [2; 32],
                epoch: 1,
                created_at: now + Duration::from_millis(1),
                leased_until: None,
                proof_version: RendezvousVersion::IpBoundV4,
                register_nonce: Some([2; 16]),
                register_ts: Some(1),
                register_sig: Some([2; 64]),
                from_pubkey: Some([2; 32]),
                via_open_intro: false,
            },
        );
        let target = "tt".repeat(32);
        let chosen = punches
            .iter()
            .filter(|((candidate, _), entry)| candidate == &target && punch_available(entry, now))
            .min_by_key(|(_, entry)| entry.created_at)
            .map(|(_, entry)| entry.punch_id.clone());
        assert_eq!(chosen.as_deref(), Some(&*"22".repeat(32)));
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
        assert_eq!(state.relay_ip_counts.read().await.get(&client_ip), Some(&1));
        rollback_relay_ticket_reservation(&state, &reservation).await;
        assert!(state.relay_ip_counts.read().await.is_empty());
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
        assert_eq!(state.relay_ip_counts.read().await.get(&client_ip), Some(&1));
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
        assert_eq!(state.relay_ip_counts.read().await.get(&client_ip), Some(&1));

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
            state.relay_ip_counts.read().await.is_empty(),
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
        state.relay_ip_counts.write().await.insert(first, 1);
        state.relay_ip_counts.write().await.insert(second, 1);
        state.bridged_relays.write().await.insert(
            session.clone(),
            BridgedRelayEntry {
                deadline: Instant::now(),
            },
        );

        cleanup_relay_session_all(&state, &session).await;
        cleanup_relay_session_all(&state, &session).await;
        assert!(state.relay_admissions.read().await.is_empty());
        assert!(state.relay_ip_counts.read().await.is_empty());
        assert!(state.bridged_relays.read().await.is_empty());
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
        // A distinct timestamp per call: two identical claims inside the same
        // second sign identical bytes, which the replay cache refuses before
        // any of this is reached.
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

        let claim = build_channel_name_v4_msg(&old_id, &owner_pk, "lobby", false, ts);
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

        let dir = channel_directory_v4(State(state.clone()), ConnectInfo(addr), HeaderMap::new())
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
}
