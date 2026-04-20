use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
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
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info};

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
    conn_ip: IpAddr,
    expires_at: Instant,
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
/// own inbound `Sender<Vec<u8>>` to peer1's still-running loop. Peer1
/// awaits the receiver side; once it fires, peer1 forwards inbound WS
/// payloads to peer2's inbox.
///
/// Replaces the older single-direction relay where peer1's WS frames
/// were silently dropped. The bridge is now genuinely full-duplex.
struct RelaySessionEntry {
    peer1_inbox_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    peer2_announce_tx: Option<tokio::sync::oneshot::Sender<tokio::sync::mpsc::Sender<Vec<u8>>>>,
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
    rate_limits: Arc<RwLock<HashMap<IpAddr, RateEntry>>>,
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
    started_at: Instant,
}

#[derive(Deserialize)]
struct RegisterRequest {
    id: String,
    port: u16,
    ip: Option<String>,
}

#[derive(Serialize)]
struct LookupResponse {
    ip: String,
    port: u16,
}

#[derive(Deserialize)]
struct UnregisterRequest {
    id: String,
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

fn validate_hex_id(id: &str) -> bool {
    id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
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

    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }

    let presence_ip = body.ip
        .as_deref()
        .and_then(|s| s.parse::<IpAddr>().ok())
        .filter(|ip| match ip {
            IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_unspecified()
                && !v4.is_private() && !v4.is_link_local(),
            IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified()
                && !v6.is_multicast(),
        })
        .unwrap_or(client_ip);

    let entry = PresenceEntry {
        ip: presence_ip,
        port: body.port,
        conn_ip: client_ip,
        expires_at: Instant::now() + ENTRY_TTL,
    };

    let mut store = state.store.write().await;
    let key = body.id.to_lowercase();
    if let Some(existing) = store.get(&key) {
        if existing.conn_ip != client_ip && existing.expires_at > Instant::now() {
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

    let client_ip = extract_client_ip(&headers, addr);
    if !check_rate_limit(&state, client_ip).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }

    let mut store = state.store.write().await;
    if let Some(entry) = store.get(&body.id.to_lowercase()) {
        if entry.conn_ip == client_ip || entry.ip == client_ip {
            store.remove(&body.id.to_lowercase());
            // See `register` above: per-request lines stay at debug.
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
    if body.from_id.len() != 64 || body.target_id.len() != 64 {
        return StatusCode::BAD_REQUEST;
    }
    if body.port == 0 {
        return StatusCode::BAD_REQUEST;
    }

    let client_ip = extract_client_ip(&headers, addr);

    // Punch-specific rate limit
    {
        let mut limits = state.rate_limits.write().await;
        let now = Instant::now();
        let key_ip = client_ip;
        let entry = limits.entry(key_ip).or_insert(RateEntry {
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
    if id.len() != 64 {
        return Err(StatusCode::BAD_REQUEST);
    }

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
    if !validate_hex_id(&body.target_id) || body.session_id.is_empty() || body.session_id.len() > 128 {
        return StatusCode::BAD_REQUEST;
    }

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
    let client_ip = extract_client_ip(&headers, addr);
    ws.on_upgrade(move |socket| handle_relay_ws(socket, state, session_id, client_ip))
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
        // Hand peer2's inbox sender to peer1. If peer1's loop has
        // already exited (timeout/close/etc.), this fails — drop it on
        // the floor; the bridge is moot.
        if announce_tx.send(peer2_inbox_tx).is_err() {
            let _ = socket.send(Message::Close(None)).await;
            cleanup_relay(&state, &session_id, client_ip).await;
            return;
        }
        info!("relay session {} bridged (peer2={})", &session_id[..8.min(session_id.len())], client_ip);
        bridge_relay(socket, peer1_inbox_tx, peer2_inbox_rx, &state, &session_id, client_ip).await;
    } else {
        // First peer — set up the rendezvous slot and run the peer1
        // loop until peer2 joins (announce_rx fires) or we time out.
        let (peer1_inbox_tx, peer1_inbox_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        let (peer2_announce_tx, peer2_announce_rx) =
            tokio::sync::oneshot::channel::<tokio::sync::mpsc::Sender<Vec<u8>>>();

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
async fn run_peer1_loop(
    mut socket: WebSocket,
    mut peer1_inbox_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    peer2_announce_rx: tokio::sync::oneshot::Receiver<tokio::sync::mpsc::Sender<Vec<u8>>>,
    session_id: &str,
) {
    let idle_timeout = tokio::time::sleep(RELAY_IDLE_TIMEOUT);
    tokio::pin!(idle_timeout);
    let mut announce_rx = Some(peer2_announce_rx);
    let mut peer2_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>> = None;
    let mut total_bytes: usize = 0;
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
                    Ok(tx) => {
                        peer2_tx = Some(tx);
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
                        total_bytes += data.len();
                        if total_bytes > RELAY_BANDWIDTH_CAP_BYTES {
                            info!("relay session {} bandwidth cap reached", &session_id[..8.min(session_id.len())]);
                            break;
                        }
                        if let Some(ref tx) = peer2_tx {
                            if tx.send(data.to_vec()).await.is_err() {
                                break;
                            }
                        }
                        // Pre-bridge: drop. Peer1 should not be sending
                        // before peer2 has attached; if it does, we
                        // refuse to buffer to avoid an unbounded queue
                        // attack.
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
async fn bridge_relay(
    mut socket: WebSocket,
    peer1_inbox_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    mut peer2_inbox_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    state: &AppState,
    session_id: &str,
    client_ip: IpAddr,
) {
    let mut total_bytes: usize = 0;
    let deadline = Instant::now() + RELAY_SESSION_TIMEOUT;

    loop {
        tokio::select! {
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        total_bytes += data.len();
                        if total_bytes > RELAY_BANDWIDTH_CAP_BYTES {
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
                        total_bytes += bytes.len();
                        if total_bytes > RELAY_BANDWIDTH_CAP_BYTES {
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

async fn sweep_expired(state: AppState) {
    loop {
        tokio::time::sleep(SWEEP_INTERVAL).await;
        let now = Instant::now();

        {
            let mut limits = state.rate_limits.write().await;
            limits.retain(|_, entry| now.duration_since(entry.window_start) < RATE_WINDOW * 2);
        }

        let mut limits = state.rate_limits.write().await;
        limits.retain(|_, entry| now.duration_since(entry.window_start) < RATE_WINDOW * 2);

        // Sweep expired punch requests
        let mut punches = state.punch_requests.write().await;
        let punch_before = punches.len();
        punches.retain(|_, e| now.duration_since(e.created_at) < PUNCH_TTL);
        let punch_removed = punch_before - punches.len();
        if punch_removed > 0 {
            info!("swept {} expired punch requests", punch_removed);
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
        let mut relays = state.relay_sessions.write().await;
        let relay_before = relays.len();
        relays.retain(|_, e| now.duration_since(e.created_at) < RELAY_SESSION_TIMEOUT);
        let relay_removed = relay_before - relays.len();
        if relay_removed > 0 {
            info!("swept {} stale relay sessions", relay_removed);
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
        punch_requests: Arc::new(RwLock::new(HashMap::new())),
        relay_sessions: Arc::new(RwLock::new(HashMap::new())),
        relay_ip_counts: Arc::new(RwLock::new(HashMap::new())),
        relay_invites: Arc::new(RwLock::new(HashMap::new())),
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
