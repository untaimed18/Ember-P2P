use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use axum::{
    extract::{
        ConnectInfo, Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::{debug, info};

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
// 0x03..=0x06 reserved for future signing of /punch and /relay-invite
// endpoints once those IDs are migrated from synthetic (ip, port)
// strings to presence-map ember-hash ids. Until then those endpoints
// rely on per-IP rate-limiting and per-target caps for abuse control.

/// Maximum allowed clock skew between the client and server timestamps
/// in a signed request. 5 minutes covers normal NTP-skewed clients
/// without giving an attacker a useful replay window.
const MAX_TIMESTAMP_SKEW_SECS: i64 = 300;
const REPLAY_CACHE_TTL: Duration = Duration::from_secs((MAX_TIMESTAMP_SKEW_SECS as u64) * 2);
const MAX_REPLAY_CACHE_ENTRIES: usize = 100_000;

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn timestamp_fresh(ts: i64) -> bool {
    let now = now_unix_secs();
    (now - ts).abs() <= MAX_TIMESTAMP_SKEW_SECS
}

fn decode_hex_pubkey(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    if hex::decode_to_slice(s, &mut out).is_ok() { Some(out) } else { None }
}

fn decode_hex_sig(s: &str) -> Option<[u8; 64]> {
    let mut out = [0u8; 64];
    if hex::decode_to_slice(s, &mut out).is_ok() { Some(out) } else { None }
}

fn decode_hex_id(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    if hex::decode_to_slice(s, &mut out).is_ok() { Some(out) } else { None }
}

/// Re-derive the rendezvous id from a pubkey and check it matches the
/// claimed id. Mirrors the client-side derivation chain
/// `pubkey -> ember_hash (BLAKE3 truncated) -> id (SHA256)`.
fn pubkey_matches_id(pubkey: &[u8; 32], claimed_id: &str) -> bool {
    let pk_blake = blake3::hash(pubkey);
    let ember_hash = &pk_blake.as_bytes()[..16];
    let mut sha = Sha256::new();
    sha.update(ember_hash);
    let derived = hex::encode(sha.finalize());
    derived.eq_ignore_ascii_case(claimed_id)
}

fn ed25519_verify(pubkey: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else { return false };
    let signature = Signature::from_bytes(sig);
    // verify_strict rejects malleable signatures and small-subgroup
    // attacks; the strict flavour is what the protocol audit
    // recommended, so use it everywhere on the server.
    vk.verify_strict(message, &signature).is_ok()
}

fn build_register_msg(id_raw: &[u8; 32], port: u16, ip4: [u8; 4], pubkey: &[u8; 32], ts: i64) -> Vec<u8> {
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

fn signed_request_replay_key(message: &[u8], sig: &[u8; 64]) -> [u8; 32] {
    let mut sha = Sha256::new();
    sha.update(message);
    sha.update(sig);
    sha.finalize().into()
}

const ENTRY_TTL: Duration = Duration::from_secs(300);
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const MAX_REQUESTS_PER_MINUTE: u64 = 60;
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
/// Cap on simultaneous pending punch entries per `target_id`. Bounds
/// the impact of `punch_register` spam against a victim once the
/// per-IP rate limit is exhausted (the attacker would have to source
/// from many IPs to fill more slots, which is also bounded by
/// `MAX_GLOBAL_RELAY_SESSIONS` upstream).
const MAX_PUNCH_PER_TARGET: usize = 8;
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
const RELAY_BANDWIDTH_CAP_BYTES: usize = 256 * 1024;
const RELAY_SESSION_TIMEOUT: Duration = Duration::from_secs(120);
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RELAY_INVITES_PER_TARGET: usize = 8;
const RELAY_INVITE_TTL: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct PresenceEntry {
    ip: IpAddr,
    port: u16,
    /// IP we observed the registration request from. Kept for
    /// diagnostics / future heuristics; the auth model no longer
    /// relies on it (signature is the authority), so it's marked
    /// `dead_code` while still emitted in `debug!` logs.
    #[allow(dead_code)]
    conn_ip: IpAddr,
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
struct RateEntry {
    count: u64,
    window_start: Instant,
}

/// A hole-punch coordination request waiting for the other peer to poll.
#[derive(Clone)]
struct PunchEntry {
    from_id: String,
    from_ip: IpAddr,
    from_port: u16,
    nat_type: u8,
    created_at: Instant,
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
/// traffic — making the 256 KiB `RELAY_BANDWIDTH_CAP_BYTES` cap
/// effectively vary per-direction and per-attach-order.
///
/// Replaces the older single-direction relay where peer1's WS frames
/// were silently dropped. The bridge is now genuinely full-duplex.
struct RelaySessionEntry {
    peer1_inbox_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    peer2_announce_tx: Option<
        tokio::sync::oneshot::Sender<(tokio::sync::mpsc::Sender<Vec<u8>>, Arc<AtomicUsize>)>,
    >,
    #[allow(dead_code)]
    first_ip: IpAddr,
    created_at: Instant,
}

#[derive(Clone)]
struct RelayInvite {
    session_id: String,
    created_at: Instant,
}

#[derive(Clone)]
struct AppState {
    store: Arc<RwLock<HashMap<String, PresenceEntry>>>,
    /// Per-IP rate-limit window for the **general** API surface
    /// (`register`, `lookup`, `unregister`, `relay-invite`, etc.).
    /// Punch traffic now lives in `punch_rate_limits` so a flood of
    /// punch registrations no longer steals the budget from unrelated
    /// endpoints — earlier this map was shared, and a single LowID
    /// peer's punch retries could 429 lookup/register for the same IP.
    rate_limits: Arc<RwLock<HashMap<IpAddr, RateEntry>>>,
    /// Per-IP rate-limit window for hole-punch register traffic.
    /// Counted separately from `rate_limits` so the documented
    /// `MAX_PUNCH_PER_MINUTE` budget is the only thing throttling
    /// punch attempts.
    punch_rate_limits: Arc<RwLock<HashMap<IpAddr, RateEntry>>>,
    /// Pending hole-punch registrations, keyed by `(target_id, from_id)`.
    /// Keying by both IDs (rather than just `target_id`) prevents an
    /// unauthenticated attacker from overwriting a legit registrant's
    /// slot for a given victim — the worst they can do now is fill an
    /// extra slot under their own attacker-controlled `from_id`, which
    /// the per-target cap below bounds.
    punch_requests: Arc<RwLock<HashMap<(String, String), PunchEntry>>>,
    relay_sessions: Arc<RwLock<HashMap<String, RelaySessionEntry>>>,
    relay_ip_counts: Arc<RwLock<HashMap<IpAddr, usize>>>,
    relay_invites: Arc<RwLock<HashMap<String, Vec<RelayInvite>>>>,
    /// Recently accepted signed mutating requests. Timestamps keep messages
    /// fresh; this cache prevents replaying a captured fresh register or
    /// unregister within that allowed skew window.
    replay_cache: Arc<RwLock<HashMap<[u8; 32], Instant>>>,
    started_at: Instant,
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
struct LookupResponse {
    ip: String,
    port: u16,
}

#[derive(Deserialize)]
struct UnregisterRequest {
    id: String,
    ts: i64,
    /// Signature over `RDV_DOMAIN || OP_UNREGISTER || sha256_id_raw || ts_le`.
    sig: String,
}

fn extract_client_ip(headers: &HeaderMap, addr: SocketAddr) -> IpAddr {
    // Only trust proxy headers when running behind a reverse proxy (e.g. Fly.io).
    // Set TRUST_PROXY=false to disable when running without a proxy.
    let trust_proxy = std::env::var("TRUST_PROXY")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(false);

    if trust_proxy {
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

async fn check_rate_limit(state: &AppState, ip: IpAddr) -> bool {
    let mut limits = state.rate_limits.write().await;
    if limits.len() >= MAX_RATE_ENTRIES && !limits.contains_key(&ip) {
        return false;
    }
    let now = Instant::now();
    let entry = limits.entry(ip).or_insert(RateEntry {
        count: 0,
        window_start: now,
    });
    if now.duration_since(entry.window_start) >= RATE_WINDOW {
        entry.count = 1;
        entry.window_start = now;
        true
    } else {
        entry.count += 1;
        entry.count <= MAX_REQUESTS_PER_MINUTE
    }
}

async fn remember_signed_request(state: &AppState, key: [u8; 32]) -> bool {
    let now = Instant::now();
    let mut cache = state.replay_cache.write().await;
    cache.retain(|_, seen_at| now.duration_since(*seen_at) < REPLAY_CACHE_TTL);
    if cache.contains_key(&key) {
        return false;
    }
    if cache.len() >= MAX_REPLAY_CACHE_ENTRIES {
        if let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, seen_at)| *seen_at)
            .map(|(k, _)| *k)
        {
            cache.remove(&oldest);
        } else {
            return false;
        }
    }
    cache.insert(key, now);
    true
}

fn validate_hex_id(id: &str) -> bool {
    id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

fn validate_relay_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
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
    let body_ip_parsed = match body.ip
        .as_deref()
        .and_then(|s| s.parse::<IpAddr>().ok())
        .filter(|ip| match ip {
            IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_unspecified()
                && !v4.is_private() && !v4.is_link_local(),
            IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified()
                && !v6.is_multicast(),
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
    if !remember_signed_request(&state, signed_request_replay_key(&msg, &sig_bytes)).await {
        return StatusCode::CONFLICT;
    }

    let entry = PresenceEntry {
        ip: presence_ip,
        port: body.port,
        conn_ip: client_ip,
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
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    store.insert(key, entry);
    // debug!, not info!: per-request lines include the client IP and a
    // partial id, which together can be correlated to deanonymize a
    // user across log aggregations. Drop into debug so operators can
    // still get this with `RUST_LOG=ember_rendezvous=debug` when
    // troubleshooting, but the default log stream stays free of PII.
    debug!("registered {} ip={} (conn={})", &body.id[..8], presence_ip, client_ip);
    StatusCode::OK
}

async fn lookup(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<LookupResponse>, StatusCode> {
    if !validate_hex_id(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let store = state.store.read().await;
    match store.get(&id.to_lowercase()) {
        Some(entry) if entry.expires_at > Instant::now() => {
            // See `register` above: per-request lines stay at debug to
            // avoid PII in the default log stream.
            debug!("lookup hit {} from {}", &id[..8], client_ip);
            Ok(Json(LookupResponse {
                ip: entry.ip.to_string(),
                port: entry.port,
            }))
        }
        _ => {
            debug!("lookup miss {} from {}", &id[..8], client_ip);
            Err(StatusCode::NOT_FOUND)
        }
    }
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

    let mut store = state.store.write().await;
    if let Some(entry) = store.get(&body.id.to_lowercase()) {
        // Verify the signature with the pinned pubkey rather than
        // trusting `client_ip == entry.conn_ip` (which CGN /
        // proxy-mismatch / new ISP session breaks). The signature is
        // the only authority that survives address churn.
        let msg = build_unregister_msg(&id_raw, body.ts);
        if ed25519_verify(&entry.pubkey, &msg, &sig_bytes) {
            if !remember_signed_request(&state, signed_request_replay_key(&msg, &sig_bytes)).await
            {
                return StatusCode::CONFLICT;
            }
            store.remove(&body.id.to_lowercase());
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
struct PunchRequest {
    from_id: String,
    target_id: String,
    port: u16,
    nat_type: u8,
}

#[derive(Serialize)]
struct PunchResponse {
    from_id: String,
    ip: String,
    port: u16,
    nat_type: u8,
}

/// Register a hole-punch request targeting another peer.
async fn punch_register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PunchRequest>,
) -> StatusCode {
    // Reject anything that isn't a well-formed 64-char hex id. The
    // earlier `len != 64` check let punk inputs through (high-byte
    // unicode, garbage from buggy clients) which then polluted logs
    // and downstream `from_id` storage. `register` already enforced
    // this; punch endpoints now match.
    if !validate_hex_id(&body.from_id) || !validate_hex_id(&body.target_id) {
        return StatusCode::BAD_REQUEST;
    }
    if body.port == 0 {
        return StatusCode::BAD_REQUEST;
    }
    // NOTE: punch endpoints are intentionally NOT signature-gated. The
    // current `/punch` keying scheme uses synthetic ids derived from
    // the target peer's `(ip, port)` (see broker code path in the
    // client), which are NOT registered presence-map identities and
    // therefore have no pinned pubkey to verify against. Defenses
    // remain: per-IP rate limiting, per-target cap, and the fact
    // that a punch entry is just (ip, port, nat_type) — useless
    // without a working QUIC handshake on top, which is mutually
    // authenticated in `ember::broker`.
    let client_ip = extract_client_ip(&headers, addr);

    // Punch-specific rate limit. Uses its own per-IP map so heavy
    // punch retries don't consume the budget for `register` /
    // `lookup` / `relay-invite` from the same IP.
    {
        let mut limits = state.punch_rate_limits.write().await;
        if limits.len() >= MAX_RATE_ENTRIES && !limits.contains_key(&client_ip) {
            return StatusCode::TOO_MANY_REQUESTS;
        }
        let now = Instant::now();
        let entry = limits.entry(client_ip).or_insert(RateEntry {
            count: 0,
            window_start: now,
        });
        if now.duration_since(entry.window_start) >= RATE_WINDOW {
            entry.count = 1;
            entry.window_start = now;
        } else {
            entry.count += 1;
            if entry.count > MAX_PUNCH_PER_MINUTE {
                return StatusCode::TOO_MANY_REQUESTS;
            }
        }
    }

    let from = body.from_id.to_lowercase();
    let target = body.target_id.to_lowercase();
    let entry = PunchEntry {
        from_id: from.clone(),
        from_ip: client_ip,
        from_port: body.port,
        nat_type: body.nat_type,
        created_at: Instant::now(),
    };

    let mut punches = state.punch_requests.write().await;
    // Enforce per-target cap. If we'd exceed it (and this isn't a
    // refresh of an existing (target, from) entry), evict the oldest
    // entry for this target to make room.
    if !punches.contains_key(&(target.clone(), from.clone())) {
        let count_for_target = punches.keys().filter(|(t, _)| t == &target).count();
        if count_for_target >= MAX_PUNCH_PER_TARGET {
            if let Some(oldest_key) = punches
                .iter()
                .filter(|((t, _), _)| t == &target)
                .min_by_key(|(_, e)| e.created_at)
                .map(|(k, _)| k.clone())
            {
                punches.remove(&oldest_key);
            }
        }
    }
    punches.insert((target.clone(), from.clone()), entry);
    drop(punches);
    info!("punch registered: {} -> {} from {}", &from[..8], &target[..8], client_ip);
    StatusCode::OK
}

/// Poll for incoming punch requests targeting our ID.
async fn punch_poll(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<PunchResponse>, StatusCode> {
    if !validate_hex_id(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    // NOTE: not signature-gated — see `punch_register` for the
    // rationale (punch ids are `(ip, port)`-derived, not presence
    // ember-hash ids, so there's no pubkey to verify against).
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let target = id.to_lowercase();
    let mut punches = state.punch_requests.write().await;
    let now = Instant::now();

    // Remove expired entries while we're here.
    punches.retain(|_, e| now.duration_since(e.created_at) < PUNCH_TTL);

    // Each call returns the oldest pending punch for this target and
    // removes only that one entry. Other pending punches for the same
    // target stay queued for subsequent polls — this preserves the
    // single-PunchInfo response shape the client expects while still
    // accommodating the multi-from_id storage that prevents
    // overwrite attacks (see `MAX_PUNCH_PER_TARGET`).
    let oldest = punches
        .iter()
        .filter(|((t, _), _)| t == &target)
        .min_by_key(|(_, e)| e.created_at)
        .map(|(k, _)| k.clone());
    match oldest.and_then(|k| punches.remove(&k)) {
        Some(entry) => {
            info!("punch poll hit: {} from {}", &target[..8], client_ip);
            Ok(Json(PunchResponse {
                from_id: entry.from_id,
                ip: entry.from_ip.to_string(),
                port: entry.from_port,
                nat_type: entry.nat_type,
            }))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

// ---------------------------------------------------------------------------
// Relay invitations (server-relay signaling)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RelayInviteRequest {
    target_id: String,
    session_id: String,
}

#[derive(Serialize)]
struct RelayInviteResponse {
    session_id: String,
}

async fn relay_invite_post(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RelayInviteRequest>,
) -> StatusCode {
    if !validate_hex_id(&body.target_id) || !validate_relay_session_id(&body.session_id) {
        return StatusCode::BAD_REQUEST;
    }
    // NOTE: relay-invite POSTs are intentionally NOT signed. The
    // `target_id` here is a synthetic `(relay_ip:relay_port)`-derived
    // hex string (see `mod.rs::our_relay_id`), not a presence-map id,
    // so the server can't use the pinned-pubkey path that
    // `register`/`unregister`/`punch_*` rely on. Defenses for this
    // endpoint are: per-IP rate limiting, per-target invite cap, and
    // (most importantly) the fact that a relay invite by itself is
    // useless without a working QUIC session — the actual relay path
    // is mutually authenticated via the eMule/Ember handshake the
    // peers run AFTER they connect to the relay.
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }

    let target = body.target_id.to_lowercase();
    let mut invites = state.relay_invites.write().await;
    let list = invites.entry(target.clone()).or_default();

    let now = Instant::now();
    list.retain(|i| now.duration_since(i.created_at) < RELAY_INVITE_TTL);

    if list.len() >= MAX_RELAY_INVITES_PER_TARGET {
        return StatusCode::TOO_MANY_REQUESTS;
    }

    list.push(RelayInvite {
        session_id: body.session_id.clone(),
        created_at: now,
    });
    info!("relay invite stored for {} session={} from {}", &target[..8], &body.session_id[..8.min(body.session_id.len())], client_ip);
    StatusCode::OK
}

async fn relay_invite_poll(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<RelayInviteResponse>>, StatusCode> {
    if !validate_hex_id(&id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    // NOTE: relay-invite polls are intentionally NOT signature-gated.
    // See `relay_invite_post` for the rationale — `id` here is a
    // `(relay_ip:relay_port)` synthesis, not an ember-hash id, so it
    // has no pinned pubkey to verify against. The actual relay path
    // is mutually authenticated by the eMule/Ember handshake AFTER
    // the QUIC session is established; an attacker dequeuing an
    // invite on the relay node simply learns "session_id X targeted
    // this relay" and gets no privileged access.
    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let key = id.to_lowercase();
    let mut invites = state.relay_invites.write().await;

    match invites.remove(&key) {
        Some(list) => {
            let now = Instant::now();
            let results: Vec<RelayInviteResponse> = list
                .into_iter()
                .filter(|i| now.duration_since(i.created_at) < RELAY_INVITE_TTL)
                .map(|i| RelayInviteResponse { session_id: i.session_id })
                .collect();
            if results.is_empty() {
                Err(StatusCode::NOT_FOUND)
            } else {
                info!("relay invite poll: {} invites for {} from {}", results.len(), &key[..8], client_ip);
                Ok(Json(results))
            }
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

// ---------------------------------------------------------------------------
// WebSocket relay
// ---------------------------------------------------------------------------

async fn relay_ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    if !validate_relay_session_id(&session_id) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let client_ip = extract_client_ip(&headers, addr);
    ws.on_upgrade(move |socket| handle_relay_ws(socket, state, session_id, client_ip))
        .into_response()
}

async fn handle_relay_ws(
    mut socket: WebSocket,
    state: AppState,
    session_id: String,
    client_ip: IpAddr,
) {
    // Take the per-IP slot atomically with the global cap check so two
    // concurrent joins from the same IP can't both observe `current <
    // cap` and then both proceed. Same write-lock window also guards the
    // global cap to close the prior TOCTOU window between the read+write
    // halves.
    {
        let mut counts = state.relay_ip_counts.write().await;
        let global_total: usize = counts.values().sum();
        if global_total >= MAX_GLOBAL_RELAY_SESSIONS {
            drop(counts);
            info!("relay rejected: global cap reached ({} sessions)", global_total);
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
        let entry = counts.entry(client_ip).or_insert(0);
        if *entry >= MAX_RELAY_SESSIONS_PER_IP {
            let current = *entry;
            drop(counts);
            info!("relay rejected: {} already has {} sessions", client_ip, current);
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
        *entry += 1;
    }

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
        drop(sessions);

        let (Some(peer1_inbox_tx), Some(announce_tx)) = (peer1_inbox_tx, announce_tx) else {
            // Slot was already drained — refuse rather than silently
            // half-bridging.
            let _ = socket.send(Message::Close(None)).await;
            cleanup_relay(&state, &session_id, client_ip).await;
            return;
        };

        let (peer2_inbox_tx, peer2_inbox_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
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
            cleanup_relay(&state, &session_id, client_ip).await;
            return;
        }
        info!("relay session {} bridged (peer2={})", &session_id[..8.min(session_id.len())], client_ip);
        bridge_relay(
            socket,
            peer1_inbox_tx,
            peer2_inbox_rx,
            total_bytes,
            &state,
            &session_id,
            client_ip,
        )
        .await;
    } else {
        // First peer — set up the rendezvous slot and run the peer1
        // loop until peer2 joins (announce_rx fires) or we time out.
        let (peer1_inbox_tx, peer1_inbox_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        let (peer2_announce_tx, peer2_announce_rx) =
            tokio::sync::oneshot::channel::<(tokio::sync::mpsc::Sender<Vec<u8>>, Arc<AtomicUsize>)>();

        sessions.insert(session_id.clone(), RelaySessionEntry {
            peer1_inbox_tx: Some(peer1_inbox_tx),
            peer2_announce_tx: Some(peer2_announce_tx),
            first_ip: client_ip,
            created_at: Instant::now(),
        });
        drop(sessions);

        info!("relay session {} created (peer1={})", &session_id[..8.min(session_id.len())], client_ip);

        run_peer1_loop(socket, peer1_inbox_rx, peer2_announce_rx, &session_id).await;
        cleanup_relay(&state, &session_id, client_ip).await;
    }
}

/// Peer1's main loop. Pre-bridge it just waits for peer2 (via
/// `announce_rx`) or the idle timeout; inbound WS frames are
/// dropped because there's no sink yet (matching protocol intent —
/// peer1 should not transmit before peer2 attaches). Once peer2's
/// inbox sender arrives, the same loop forwards inbound WS frames
/// to it and drains `peer1_inbox_rx` to the WebSocket.
///
/// Pre-bridge byte accounting note: dropped pre-bridge bytes must
/// NOT count against `RELAY_BANDWIDTH_CAP_BYTES`. Earlier logic did
/// count them, which let a misbehaving peer1 silently burn the
/// session's entire relay budget with junk frames before peer2 ever
/// attached, so peer2's legitimate first Binary frame would
/// immediately trip the cap and tear the bridge down. We now only
/// accumulate bytes that are actually forwarded, and only after
/// peer2 has joined (at which point `total_bytes` is the shared
/// counter passed from the peer2 side of the bridge).
async fn run_peer1_loop(
    mut socket: WebSocket,
    mut peer1_inbox_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    peer2_announce_rx: tokio::sync::oneshot::Receiver<(
        tokio::sync::mpsc::Sender<Vec<u8>>,
        Arc<AtomicUsize>,
    )>,
    session_id: &str,
) {
    let idle_timeout = tokio::time::sleep(RELAY_IDLE_TIMEOUT);
    tokio::pin!(idle_timeout);
    let mut announce_rx = Some(peer2_announce_rx);
    let mut peer2_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>> = None;
    let mut total_bytes: Option<Arc<AtomicUsize>> = None;
    let session_deadline = Instant::now() + RELAY_SESSION_TIMEOUT;

    loop {
        tokio::select! {
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
                    }
                    Err(_) => {
                        // Sender was dropped (peer2 join handler aborted before sending).
                        break;
                    }
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        // Only count (and forward) bytes once peer2 is
                        // attached; pre-bridge frames are dropped with
                        // zero cap impact so a noisy peer1 can't
                        // starve the session before peer2 joins.
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
                        }
                        // else: pre-bridge, drop silently.
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
            data = peer1_inbox_rx.recv() => {
                match data {
                    Some(bytes) => {
                        if socket.send(Message::Binary(axum::body::Bytes::from(bytes))).await.is_err() {
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
/// That way the 256 KiB cap applies uniformly to the sum of both
/// directions. We do NOT re-count on the `peer2_inbox_rx` drain
/// side — those bytes were already counted once by peer1's loop
/// when they entered the relay; counting them again would
/// double-charge the same payload.
async fn bridge_relay(
    mut socket: WebSocket,
    peer1_inbox_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut peer2_inbox_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    total_bytes: Arc<AtomicUsize>,
    state: &AppState,
    session_id: &str,
    client_ip: IpAddr,
) {
    let deadline = Instant::now() + RELAY_SESSION_TIMEOUT;

    loop {
        tokio::select! {
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
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
                        if socket.send(Message::Binary(axum::body::Bytes::from(bytes))).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
        if Instant::now() > deadline {
            break;
        }
    }

    cleanup_relay(state, session_id, client_ip).await;
}

async fn cleanup_relay(state: &AppState, session_id: &str, client_ip: IpAddr) {
    state.relay_sessions.write().await.remove(session_id);
    let mut counts = state.relay_ip_counts.write().await;
    if let Some(count) = counts.get_mut(&client_ip) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(&client_ip);
        }
    }
}

async fn stats_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let relay_count = state.relay_sessions.read().await.len();
    let punch_count = state.punch_requests.read().await.len();
    let relay_ip_count = state.relay_ip_counts.read().await.len();
    let presence_count = state.store.read().await.len();
    let uptime_secs = state.started_at.elapsed().as_secs();

    Json(serde_json::json!({
        "active_relay_sessions": relay_count,
        "active_punch_requests": punch_count,
        "relay_ip_count": relay_ip_count,
        "registered_peers": presence_count,
        "uptime_seconds": uptime_secs,
        "max_global_relays": MAX_GLOBAL_RELAY_SESSIONS,
    }))
}

async fn health() -> &'static str {
    "ok"
}

/// L12: DHT bootstrap stub.
///
/// `ember/dht/bootstrap.rs::fetch_bootstrap_nodes` GETs
/// `<rendezvous>/bootstrap` and expects a JSON array of
/// `BootstrapNode { node_id, addr, noise_pub, ed25519_pub }`. The
/// V1 client never actually consumes the result (DHT is dormant
/// behind `ember_native_enabled = false`), but until L12 the route
/// didn't exist on the server side and every probe returned 404,
/// which the client logs as a warning. We return an empty array
/// so the client's "no peers known yet" branch fires cleanly. When
/// the Ember DHT goes live, replace the empty body with a
/// signed-and-pinned bootstrap pool — until then there's no value
/// in publishing addresses for a network that nothing is talking
/// to yet.
async fn bootstrap_stub() -> Json<Vec<serde_json::Value>> {
    Json(Vec::new())
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

        // Sweep the punch-specific rate-limit map on the same cadence
        // as the general one so the per-IP entries don't pile up after
        // a punch burst goes quiet.
        {
            let mut limits = state.punch_rate_limits.write().await;
            limits.retain(|_, entry| now.duration_since(entry.window_start) < RATE_WINDOW * 2);
        }

        {
            let mut replay = state.replay_cache.write().await;
            replay.retain(|_, seen_at| now.duration_since(*seen_at) < REPLAY_CACHE_TTL);
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

        // Sweep expired relay invites
        {
            let mut invites = state.relay_invites.write().await;
            invites.retain(|_, v| {
                v.retain(|i| now.duration_since(i.created_at) < RELAY_INVITE_TTL);
                !v.is_empty()
            });
        }

        // Sweep stale relay sessions (created but never bridged)
        {
            let mut relays = state.relay_sessions.write().await;
            let relay_before = relays.len();
            relays.retain(|_, e| now.duration_since(e.created_at) < RELAY_SESSION_TIMEOUT);
            let relay_removed = relay_before - relays.len();
            if relay_removed > 0 {
                info!("swept {} stale relay sessions", relay_removed);
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
        rate_limits: Arc::new(RwLock::new(HashMap::new())),
        punch_rate_limits: Arc::new(RwLock::new(HashMap::new())),
        punch_requests: Arc::new(RwLock::new(HashMap::new())),
        relay_sessions: Arc::new(RwLock::new(HashMap::new())),
        relay_ip_counts: Arc::new(RwLock::new(HashMap::new())),
        relay_invites: Arc::new(RwLock::new(HashMap::new())),
        replay_cache: Arc::new(RwLock::new(HashMap::new())),
        started_at: Instant::now(),
    };

    tokio::spawn(sweep_expired(state.clone()));

    let app = Router::new()
        .route("/register", post(register))
        .route("/lookup/{id}", get(lookup))
        .route("/unregister", delete(unregister))
        .route("/punch", post(punch_register))
        .route("/punch/{id}", get(punch_poll))
        .route("/relay/{session_id}", get(relay_ws))
        .route("/relay-invite", post(relay_invite_post))
        .route("/relay-invites/{id}", get(relay_invite_poll))
        // L12: DHT bootstrap stub. The Ember DHT (`ember/dht/*`) is
        // dormant in V1 (`ember_native_enabled=false`), but the
        // bootstrap module probes `/bootstrap` proactively whenever
        // the runtime hands it a rendezvous URL. Returning an empty
        // 200 OK keeps that probe quiet — the client treats an
        // empty list as "no peers known yet" and falls back to its
        // local cache, which is the correct V1 behaviour. When the
        // DHT goes live in a later version this handler can grow
        // into a real bootstrap-node serializer; for now an empty
        // array keeps the wire contract honest without adding any
        // attack surface.
        .route("/bootstrap", get(bootstrap_stub))
        .route("/health", get(health))
        .route("/stats", get(stats_handler))
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
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    {
        eprintln!("Server error: {e}");
        std::process::exit(1);
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
