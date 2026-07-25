use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tracing::{debug, info};

const MSG_RELAY_REQUEST: u8 = 0x01;
const MSG_RELAY_ACCEPT: u8 = 0x02;
const MSG_RELAY_CONNECT: u8 = 0x03;
const MSG_RELAY_CLOSE: u8 = 0x05;
const MSG_RELAY_REJECT: u8 = 0x06;

/// Wire version for signed RELAY_REQUEST payloads (PoP).
pub const RELAY_REQUEST_VERSION: u8 = 2;
/// Fixed payload size for v2: version(1) + target(6) + file(16) +
/// attestation_hash(32) + pubkey(32) + ember_hash(16) + nonce(16) + sig(64).
pub const RELAY_REQUEST_V2_PAYLOAD_LEN: usize = 183;
const RELAY_REQUEST_NONCE_LEN: usize = 16;
const RELAY_REQUEST_SIGNATURE_DOMAIN: &[u8] = b"ember-relay-request-v2\0";
/// Reject reasons for RELAY_REJECT payload.
const REJECT_CAPACITY: u8 = 0x01;
const REJECT_BAD_TARGET: u8 = 0x02;
const REJECT_AUTH: u8 = 0x03;
const REJECT_BAD_SIGNATURE: u8 = 0x04;
/// How long a (requester pubkey, nonce) pair is remembered to block replays.
const RELAY_REQUEST_NONCE_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_RELAY_REQUEST_NONCE_CACHE: usize = 4096;

/// Build a hardened reqwest client for relay/punch HTTP calls.
///
/// M8: previously each helper called `reqwest::Client::new()`,
/// which omitted `https_only`, `no_proxy`, and any body-size
/// guard — strictly weaker than the rendezvous client built in
/// `network/rendezvous.rs::client()`. The relay/punch endpoints
/// hit the same rendezvous server, so they should be subject to
/// the same defense-in-depth posture: refuse to follow a redirect
/// onto plain HTTP, never route through an environment proxy, and
/// hard-cap the request timeout. The body size is bounded
/// indirectly by reqwest's default response cap and the very small
/// JSON shapes these endpoints accept; if a future endpoint needs
/// larger bodies, add an explicit `bytes_per_response` cap here.
async fn relay_http_client(rendezvous_url: &str) -> Result<reqwest::Client, String> {
    let (_, host, addrs) = crate::security::validate_fetch_url(rendezvous_url)
        .await
        .map_err(|e| format!("rendezvous URL rejected: {e}"))?;
    crate::security::build_pinned_client(&host, &addrs)
}

/// Defense-in-depth: refuse to contact a non-HTTPS rendezvous/relay URL.
/// `relay_http_client()` already sets `https_only(true)`, but this makes the
/// requirement explicit at each call site and also covers the (near-
/// impossible) builder-failure fallback client.
fn require_https(url: &str) -> Result<(), String> {
    if url.starts_with("https://") {
        Ok(())
    } else {
        Err(format!("refusing non-HTTPS rendezvous/relay URL: {url}"))
    }
}

/// Rendezvous/relay endpoints return tiny JSON shapes; 64 KiB is generous.
const MAX_RENDEZVOUS_JSON_BYTES: usize = 64 * 1024;

/// Read a response body into memory with a hard cap, then deserialize it.
/// `reqwest::Response::json()` buffers the whole body with no size limit, so
/// a malicious or compromised rendezvous server could OOM us by streaming an
/// unbounded body. Stream chunks and bail once the cap is exceeded.
async fn read_json_capped<T: serde::de::DeserializeOwned>(
    mut resp: reqwest::Response,
    max_bytes: usize,
    ctx: &str,
) -> Result<T, String> {
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| format!("{ctx}: {e}"))? {
        if buf.len() + chunk.len() > max_bytes {
            return Err(format!("{ctx}: response exceeds {max_bytes} byte cap"));
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf).map_err(|e| format!("{ctx} parse: {e}"))
}
/// Per-direction byte ceiling for a single relay session. Picked to be
/// large enough that real file transfers (eD2K parts are ~9.5 MiB,
/// whole files commonly hundreds of MiB to several GiB) complete
/// without bumping into this cap, while still bounding the worst-case
/// uplink that a misbehaving peer can extract from a relay node — in
/// combination with `MAX_CONCURRENT_RELAY_SESSIONS = 4` and
/// `RELAY_MAX_DURATION = 2h`, the relay's effective uplink ceiling is
/// `4 sessions * 2 dirs * 8 GiB = 64 GiB per 2h window`. The previous
/// constant (`512 KiB`) was misleadingly named "bandwidth limit" but
/// applied as a total-bytes cap via `AsyncRead::take`, which silently
/// stalled every LowID-to-LowID transfer past ~512 KiB per direction.
const RELAY_MAX_BYTES_PER_DIRECTION: u64 = 8 * 1024 * 1024 * 1024;
const MAX_CONCURRENT_RELAY_SESSIONS: usize = 4;
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
const RELAY_MAX_DURATION: Duration = Duration::from_secs(7200);
const MAX_WS_RELAY_FRAME: usize = 16 * 1024;

/// A relay session between two LowID peers through an intermediary.
#[derive(Debug)]
pub struct RelaySession {
    pub session_id: u32,
    pub initiator_ip: Ipv4Addr,
    pub initiator_port: u16,
    pub target_ip: Ipv4Addr,
    pub target_port: u16,
    pub file_hash: [u8; 16],
    pub state: RelaySessionState,
    pub created: Instant,
    pub last_activity: Instant,
    pub bytes_relayed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RelaySessionState {
    /// Waiting for target peer to connect to the relay.
    WaitingForTarget,
    /// Both peers connected; actively relaying data.
    Active,
}

impl RelaySession {
    pub fn new(
        session_id: u32,
        initiator_ip: Ipv4Addr,
        initiator_port: u16,
        target_ip: Ipv4Addr,
        target_port: u16,
        file_hash: [u8; 16],
    ) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            initiator_ip,
            initiator_port,
            target_ip,
            target_port,
            file_hash,
            state: RelaySessionState::WaitingForTarget,
            created: now,
            last_activity: now,
            bytes_relayed: 0,
        }
    }

    pub fn is_expired(&self) -> bool {
        if self.created.elapsed() > RELAY_MAX_DURATION {
            return true;
        }
        self.state == RelaySessionState::WaitingForTarget
            && self.last_activity.elapsed() > RELAY_IDLE_TIMEOUT
    }

    pub fn mark_active(&mut self) {
        self.state = RelaySessionState::Active;
        self.last_activity = Instant::now();
    }

    pub fn add_relayed_bytes(&mut self, count: u64) {
        self.bytes_relayed += count;
        self.last_activity = Instant::now();
    }

    /// One-line routing description used in relay lifecycle logs. Reading the
    /// endpoint/file metadata here is also what keeps these fields live — they
    /// are the relay's audit trail of which peers a session bridged and for
    /// which file hash.
    pub fn describe(&self) -> String {
        format!(
            "session {} {}:{} -> {}:{} file {}",
            self.session_id,
            self.initiator_ip,
            self.initiator_port,
            self.target_ip,
            self.target_port,
            hex::encode(self.file_hash),
        )
    }
}

/// Manages relay sessions when this node acts as a relay for others.
pub struct RelayManager {
    sessions: HashMap<u32, RelaySession>,
    attestation_hashes: HashMap<[u8; 32], u64>,
    /// Recently seen (requester_pubkey, nonce) pairs to reject replays of
    /// otherwise-valid signed RELAY_REQUESTs within [`RELAY_REQUEST_NONCE_TTL`].
    recent_request_nonces: HashMap<([u8; 32], [u8; 16]), Instant>,
    next_session_id: u32,
    total_bytes_relayed: u64,
}

impl RelayManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            attestation_hashes: HashMap::new(),
            recent_request_nonces: HashMap::new(),
            next_session_id: 1,
            total_bytes_relayed: 0,
        }
    }

    pub fn set_current_attestation_hash(&mut self, hash: [u8; 32], expires_at_unix: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.attestation_hashes.retain(|_, exp| *exp > now);
        self.attestation_hashes.insert(hash, expires_at_unix);
    }

    fn accepts_attestation_hash(&mut self, hash: &[u8; 32]) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.attestation_hashes.retain(|_, exp| *exp > now);
        self.attestation_hashes.contains_key(hash)
    }

    /// Returns `true` if this nonce is fresh for `pubkey` and records it.
    /// Returns `false` on replay (or when the cache is full of still-fresh
    /// entries for other peers — fail closed rather than accept unbounded growth).
    fn consume_request_nonce(&mut self, pubkey: &[u8; 32], nonce: &[u8; 16]) -> bool {
        let now = Instant::now();
        self.recent_request_nonces
            .retain(|_, seen| now.duration_since(*seen) < RELAY_REQUEST_NONCE_TTL);
        let key = (*pubkey, *nonce);
        if self.recent_request_nonces.contains_key(&key) {
            return false;
        }
        if self.recent_request_nonces.len() >= MAX_RELAY_REQUEST_NONCE_CACHE {
            return false;
        }
        self.recent_request_nonces.insert(key, now);
        true
    }

    /// Create a new relay session if capacity allows.
    pub fn create_session(
        &mut self,
        initiator_ip: Ipv4Addr,
        initiator_port: u16,
        target_ip: Ipv4Addr,
        target_port: u16,
        file_hash: [u8; 16],
    ) -> Option<u32> {
        if self.sessions.len() >= MAX_CONCURRENT_RELAY_SESSIONS {
            debug!(
                "RelayManager: at capacity ({} sessions)",
                self.sessions.len()
            );
            return None;
        }

        let id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);

        let session = RelaySession::new(
            id,
            initiator_ip,
            initiator_port,
            target_ip,
            target_port,
            file_hash,
        );
        info!("RelayManager: created {}", session.describe());
        self.sessions.insert(id, session);
        Some(id)
    }

    pub fn get_session_mut(&mut self, id: u32) -> Option<&mut RelaySession> {
        self.sessions.get_mut(&id)
    }

    /// Removes a session and folds its `bytes_relayed` into the cumulative
    /// lifetime total before returning it. Every call site removes a
    /// session because it's ending (normal completion, error, or explicit
    /// teardown) — without folding here, only `cleanup()`'s expiry path
    /// contributed to `total_bytes_relayed()`, so sessions that ended any
    /// other way (the common case) silently dropped their bytes from the
    /// lifetime counter reported in stats/logs.
    pub fn remove_session(&mut self, id: u32) -> Option<RelaySession> {
        let session = self.sessions.remove(&id)?;
        self.total_bytes_relayed += session.bytes_relayed;
        Some(session)
    }

    /// Clean up expired sessions.
    pub fn cleanup(&mut self) -> Vec<u32> {
        let expired: Vec<u32> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.is_expired())
            .map(|(id, _)| *id)
            .collect();

        for id in &expired {
            if let Some(session) = self.remove_session(*id) {
                info!(
                    "RelayManager: expired {} ({} bytes relayed)",
                    session.describe(),
                    session.bytes_relayed
                );
            }
        }
        expired
    }

    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn total_bytes_relayed(&self) -> u64 {
        self.total_bytes_relayed + self.sessions.values().map(|s| s.bytes_relayed).sum::<u64>()
    }
}

/// Encode a relay protocol message.
pub fn encode_relay_message(msg_type: u8, session_id: u32, payload: &[u8]) -> Vec<u8> {
    // The wire framing uses a u16 length prefix. Every relay control message
    // stays well under that — ACCEPT/CLOSE are empty, REJECT is 1 byte,
    // CONNECT carries a 16-byte file hash, and REQUEST is a fixed 183-byte
    // signed v2 payload — but assert it so a future caller that overflows
    // the prefix (which would silently corrupt the framing) is caught in
    // debug builds rather than producing undecodable messages.
    debug_assert!(
        payload.len() <= u16::MAX as usize,
        "relay message payload {} exceeds u16 length prefix",
        payload.len()
    );
    let len = payload.len() as u16;
    let mut buf = Vec::with_capacity(7 + payload.len());
    buf.push(msg_type);
    buf.extend_from_slice(&session_id.to_le_bytes());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Decode a relay protocol message header. Returns (msg_type, session_id, payload).
pub fn decode_relay_message(data: &[u8]) -> Option<(u8, u32, &[u8])> {
    if data.len() < 7 {
        return None;
    }
    let msg_type = data[0];
    let session_id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let payload_len = u16::from_le_bytes([data[5], data[6]]) as usize;
    if data.len() < 7 + payload_len {
        return None;
    }
    Some((msg_type, session_id, &data[7..7 + payload_len]))
}

/// Decode just the 7-byte relay header. Used by the QUIC accept loop
/// where we have only read the fixed-size header and still need to
/// know how much body to `read_exact` next; calling
/// [`decode_relay_message`] on the bare header would always fail for
/// any message with a non-zero `payload_len` (e.g. `RELAY_REQUEST`),
/// which previously broke peer-relay accept entirely.
///
/// Returns `(msg_type, session_id, payload_len)`. Always succeeds when
/// `data.len() >= 7`.
pub fn decode_relay_header(data: &[u8]) -> Option<(u8, u32, u16)> {
    if data.len() < 7 {
        return None;
    }
    let msg_type = data[0];
    let session_id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let payload_len = u16::from_le_bytes([data[5], data[6]]);
    Some((msg_type, session_id, payload_len))
}

/// Parsed + verified v2 RELAY_REQUEST fields (signature already checked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayRequestV2 {
    pub target_ip: Ipv4Addr,
    pub target_port: u16,
    pub file_hash: [u8; 16],
    pub attestation_hash: [u8; 32],
    pub requester_pubkey: [u8; 32],
    pub requester_ember_hash: [u8; 16],
    pub nonce: [u8; 16],
}

fn build_relay_request_signed_message(
    session_id: u32,
    attestation_hash: &[u8; 32],
    target_ip: Ipv4Addr,
    target_port: u16,
    file_hash: &[u8; 16],
    requester_pubkey: &[u8; 32],
    requester_ember_hash: &[u8; 16],
    nonce: &[u8; 16],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        RELAY_REQUEST_SIGNATURE_DOMAIN.len() + 4 + 32 + 4 + 2 + 16 + 32 + 16 + 16,
    );
    msg.extend_from_slice(RELAY_REQUEST_SIGNATURE_DOMAIN);
    msg.extend_from_slice(&session_id.to_le_bytes());
    msg.extend_from_slice(attestation_hash);
    msg.extend_from_slice(&target_ip.octets());
    msg.extend_from_slice(&target_port.to_le_bytes());
    msg.extend_from_slice(file_hash);
    msg.extend_from_slice(requester_pubkey);
    msg.extend_from_slice(requester_ember_hash);
    msg.extend_from_slice(nonce);
    msg
}

/// Build a signed v2 RELAY_REQUEST (proof-of-possession).
///
/// The requester signs a domain-separated message binding session id,
/// the relay's public ERAT attestation hash, target, file hash, and a
/// fresh nonce. The attestation hash alone is no longer accepted as a
/// bearer credential.
pub fn build_relay_request_v2(
    session_id: u32,
    target_ip: Ipv4Addr,
    target_port: u16,
    file_hash: &[u8; 16],
    attestation_hash: &[u8; 32],
    requester_pubkey: &[u8; 32],
    requester_ember_hash: &[u8; 16],
    requester_secret_key: &[u8; 32],
) -> Vec<u8> {
    use rand::RngCore;

    let mut nonce = [0u8; RELAY_REQUEST_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let signed = build_relay_request_signed_message(
        session_id,
        attestation_hash,
        target_ip,
        target_port,
        file_hash,
        requester_pubkey,
        requester_ember_hash,
        &nonce,
    );
    let signing_key = super::crypto::signing_key_from_bytes(requester_secret_key);
    let signature = super::crypto::sign(&signing_key, &signed);

    let mut payload = Vec::with_capacity(RELAY_REQUEST_V2_PAYLOAD_LEN);
    payload.push(RELAY_REQUEST_VERSION);
    payload.extend_from_slice(&target_ip.octets());
    payload.extend_from_slice(&target_port.to_le_bytes());
    payload.extend_from_slice(file_hash);
    payload.extend_from_slice(attestation_hash);
    payload.extend_from_slice(requester_pubkey);
    payload.extend_from_slice(requester_ember_hash);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&signature);
    debug_assert_eq!(payload.len(), RELAY_REQUEST_V2_PAYLOAD_LEN);
    encode_relay_message(MSG_RELAY_REQUEST, session_id, &payload)
}

/// Parse and cryptographically verify a v2 RELAY_REQUEST payload.
///
/// Does **not** check attestation-hash membership or nonce replay —
/// those are policy checks owned by [`RelayManager`] on the accept path.
pub fn parse_and_verify_relay_request_v2(
    session_id: u32,
    payload: &[u8],
) -> Result<RelayRequestV2, &'static str> {
    if payload.len() != RELAY_REQUEST_V2_PAYLOAD_LEN {
        return Err("unexpected relay request payload length");
    }
    if payload[0] != RELAY_REQUEST_VERSION {
        return Err("unsupported relay request version");
    }
    let target_ip = Ipv4Addr::new(payload[1], payload[2], payload[3], payload[4]);
    let target_port = u16::from_le_bytes([payload[5], payload[6]]);
    let mut file_hash = [0u8; 16];
    file_hash.copy_from_slice(&payload[7..23]);
    let mut attestation_hash = [0u8; 32];
    attestation_hash.copy_from_slice(&payload[23..55]);
    let mut requester_pubkey = [0u8; 32];
    requester_pubkey.copy_from_slice(&payload[55..87]);
    let mut requester_ember_hash = [0u8; 16];
    requester_ember_hash.copy_from_slice(&payload[87..103]);
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&payload[103..119]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&payload[119..183]);

    if !super::crypto::verify_ember_hash_binding(&requester_pubkey, &requester_ember_hash) {
        return Err("requester pubkey does not bind to ember_hash");
    }
    let Some(vk) = super::crypto::verifying_key_from_bytes(&requester_pubkey) else {
        return Err("invalid requester pubkey");
    };
    let signed = build_relay_request_signed_message(
        session_id,
        &attestation_hash,
        target_ip,
        target_port,
        &file_hash,
        &requester_pubkey,
        &requester_ember_hash,
        &nonce,
    );
    if !super::crypto::verify(&vk, &signed, &signature) {
        return Err("bad relay request signature");
    }
    Ok(RelayRequestV2 {
        target_ip,
        target_port,
        file_hash,
        attestation_hash,
        requester_pubkey,
        requester_ember_hash,
        nonce,
    })
}

/// Build a RELAY_ACCEPT message.
pub fn build_relay_accept(session_id: u32) -> Vec<u8> {
    encode_relay_message(MSG_RELAY_ACCEPT, session_id, &[])
}

/// Build a RELAY_REJECT message.
pub fn build_relay_reject(session_id: u32, reason: u8) -> Vec<u8> {
    encode_relay_message(MSG_RELAY_REJECT, session_id, &[reason])
}

/// Build a RELAY_CONNECT message sent to the target peer,
/// carrying the file_hash so the target knows what to serve.
pub fn build_relay_connect(session_id: u32, file_hash: &[u8; 16]) -> Vec<u8> {
    encode_relay_message(MSG_RELAY_CONNECT, session_id, file_hash)
}

/// Build a RELAY_CLOSE message.
pub fn build_relay_close(session_id: u32) -> Vec<u8> {
    encode_relay_message(MSG_RELAY_CLOSE, session_id, &[])
}

const PUNCH_RDV_DOMAIN: &[u8] = b"ember-rdv-v1";
const OP_PUNCH_REGISTER_V3: u8 = 0x10;
const OP_PUNCH_POLL_V3: u8 = 0x11;
const OP_PUNCH_ACK_V3: u8 = 0x12;
const PUNCH_RDV_V4_DOMAIN: &[u8] = b"ember-rdv-v4";
const OP_PUNCH_REGISTER_V4: u8 = 0x23;
const OP_PUNCH_POLL_V4: u8 = 0x24;
const OP_PUNCH_ACK_V4: u8 = 0x25;
const PUNCH_PROOF_TTL_SECS: i64 = 30;
const PUNCH_PROOF_CLOCK_SKEW_SECS: i64 = 300;
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

fn punch_identity(ember_hash: &[u8; 16]) -> (String, [u8; 32]) {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(ember_hash);
    let raw: [u8; 32] = digest.into();
    (hex::encode(raw), raw)
}

fn punch_nonce() -> [u8; 16] {
    use rand::RngCore;
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

fn sign_punch(secret_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    ed25519_dalek::SigningKey::from_bytes(secret_key)
        .sign(message)
        .to_bytes()
}

fn our_punch_pubkey(secret_key: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(secret_key)
        .verifying_key()
        .to_bytes()
}

fn punch_register_wire(
    protocol: crate::network::rendezvous::RendezvousProtocol,
) -> (&'static [u8], u8, &'static str) {
    match protocol {
        crate::network::rendezvous::RendezvousProtocol::LegacyV3 => {
            (PUNCH_RDV_DOMAIN, OP_PUNCH_REGISTER_V3, "/v3/punch/register")
        }
        crate::network::rendezvous::RendezvousProtocol::IpBoundV4 => (
            PUNCH_RDV_V4_DOMAIN,
            OP_PUNCH_REGISTER_V4,
            "/v4/punch/register",
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_punch_register_message(
    protocol: crate::network::rendezvous::RendezvousProtocol,
    from_id: &[u8; 32],
    target_id: &[u8; 32],
    capability: &[u8; 32],
    epoch: i64,
    port: u16,
    advertised_ip: IpAddr,
    nat_type: u8,
    nonce: &[u8; 16],
    ts: i64,
) -> Vec<u8> {
    let (domain, operation, _) = punch_register_wire(protocol);
    let signed_ip = (protocol == crate::network::rendezvous::RendezvousProtocol::IpBoundV4)
        .then(|| encode_signed_ip(advertised_ip));
    let mut signed = Vec::with_capacity(
        domain.len() + 1 + 32 * 3 + 8 + 2 + signed_ip.as_ref().map_or(0, Vec::len) + 1 + 16 + 8,
    );
    signed.extend_from_slice(domain);
    signed.push(operation);
    signed.extend_from_slice(from_id);
    signed.extend_from_slice(target_id);
    signed.extend_from_slice(capability);
    signed.extend_from_slice(&epoch.to_le_bytes());
    signed.extend_from_slice(&port.to_le_bytes());
    if let Some(signed_ip) = signed_ip {
        signed.extend_from_slice(&signed_ip);
    }
    signed.push(nat_type);
    signed.extend_from_slice(nonce);
    signed.extend_from_slice(&ts.to_le_bytes());
    signed
}

/// Register a signed hole-punch request under the rotating pairwise
/// capability shared with the target friend. `advertised_ip` is bound into
/// the signature and must match the rendezvous-observed client address.
pub async fn register_punch_with_ip(
    rendezvous_url: &str,
    from_ember_hash: &[u8; 16],
    target_ember_hash: &[u8; 16],
    port: u16,
    nat_type: u8,
    advertised_ip: IpAddr,
    secret_key: &[u8; 32],
    our_ember_hash_for_identity: &[u8; 16],
) -> Result<(), String> {
    require_https(rendezvous_url)?;
    let protocol = crate::network::rendezvous::negotiate_protocol(rendezvous_url).await?;
    if matches!(advertised_ip, IpAddr::V6(_)) {
        return Err("punch registration rejects IPv6 until end-to-end verify lands".to_string());
    }
    let (from_id, from_raw) = punch_identity(from_ember_hash);
    let (target_id, target_raw) = punch_identity(target_ember_hash);
    let ts = crate::network::rendezvous::current_timestamp();
    let epoch = super::crypto::pairwise_capability_epoch(ts);
    let our_pubkey = our_punch_pubkey(secret_key);
    let target_pubkey = crate::network::rendezvous::fetch_identity_pubkey_authenticated(
        rendezvous_url,
        target_ember_hash,
        our_ember_hash_for_identity,
        &our_pubkey,
        secret_key,
    )
    .await?
    .ok_or_else(|| "punch target has no registered v2 identity".to_string())?;
    let capability = super::crypto::derive_pairwise_presence_capability(
        secret_key,
        &target_pubkey,
        &target_pubkey,
        epoch,
    )
    .ok_or_else(|| "could not derive pairwise punch capability".to_string())?;
    let nonce = punch_nonce();
    let (_, _, route) = punch_register_wire(protocol);
    let signed = build_punch_register_message(
        protocol,
        &from_raw,
        &target_raw,
        &capability,
        epoch,
        port,
        advertised_ip,
        nat_type,
        &nonce,
        ts,
    );
    let sig = sign_punch(secret_key, &signed);
    let mut body = serde_json::json!({
        "from_id": from_id,
        "target_id": target_id,
        "capability": hex::encode(capability),
        "epoch": epoch,
        "port": port,
        "nat_type": nat_type,
        "ts": ts,
        "nonce": hex::encode(nonce),
        "sig": hex::encode(sig),
    });
    if protocol == crate::network::rendezvous::RendezvousProtocol::IpBoundV4 {
        body.as_object_mut().expect("JSON object").insert(
            "ip".to_string(),
            serde_json::Value::String(advertised_ip.to_string()),
        );
    }
    let client = relay_http_client(rendezvous_url).await?;
    let resp = client
        .post(format!("{}{}", rendezvous_url.trim_end_matches('/'), route))
        .json(&body)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("punch register: {e}"))?;

    let status = resp.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("punch register: status {status}"))
    }
}

/// Verify initiator register proof returned by punch poll before dialing.
pub fn verify_punch_register_proof(
    info: &PunchInfo,
    protocol: crate::network::rendezvous::RendezvousProtocol,
) -> Result<(), String> {
    use ed25519_dalek::{Signature, VerifyingKey};
    match protocol {
        crate::network::rendezvous::RendezvousProtocol::LegacyV3 => {
            // Legacy polls never carried an IP-bound register proof. Accept only
            // the expected wire version so a v3 client cannot be confused by a
            // spoofed proof_version field into skipping checks it does not have.
            if info.proof_version != 3 {
                return Err("punch proof: legacy poll requires proof_version 3".to_string());
            }
            Ok(())
        }
        crate::network::rendezvous::RendezvousProtocol::IpBoundV4 => {
            // IpBoundV4's threat model includes a lying rendezvous. Never fail
            // open on a claimed legacy proof_version — require the IP-bound
            // signature over the dial endpoint.
            if info.proof_version != 4 {
                return Err(
                    "punch proof: v4 poll requires IP-bound proof_version 4".to_string(),
                );
            }
            verify_punch_proof_freshness(
                info.register_ts,
                info.epoch,
                crate::network::rendezvous::current_timestamp(),
            )?;
            if info.from_id.len() != 64 || !info.from_id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("punch proof: invalid from_id".to_string());
            }
            let mut from_raw = [0u8; 32];
            hex::decode_to_slice(&info.from_id, &mut from_raw)
                .map_err(|_| "punch proof: invalid from_id".to_string())?;
            if !crate::network::rendezvous::pubkey_matches_id(&info.from_pubkey, &info.from_id) {
                return Err("punch proof: from_pubkey does not match from_id".to_string());
            }
            let ip: IpAddr = info
                .ip
                .parse()
                .map_err(|_| "punch proof: invalid ip".to_string())?;
            if matches!(ip, IpAddr::V6(_)) {
                return Err("punch proof: IPv6 unsupported".to_string());
            }
            let Ok(target_raw) = hex::decode(&info.target_id_raw_hex) else {
                return Err("punch proof: missing target binding".to_string());
            };
            if target_raw.len() != 32 {
                return Err("punch proof: invalid target binding".to_string());
            }
            let mut target = [0u8; 32];
            target.copy_from_slice(&target_raw);
            let signed = build_punch_register_message(
                crate::network::rendezvous::RendezvousProtocol::IpBoundV4,
                &from_raw,
                &target,
                &info.capability,
                info.epoch,
                info.port,
                ip,
                info.nat_type,
                &info.register_nonce,
                info.register_ts,
            );
            let Ok(vk) = VerifyingKey::from_bytes(&info.from_pubkey) else {
                return Err("punch proof: invalid from_pubkey".to_string());
            };
            let signature = Signature::from_bytes(&info.register_sig);
            vk.verify_strict(&signed, &signature)
                .map_err(|_| "punch proof: register signature invalid".to_string())
        }
    }
}

fn verify_punch_proof_freshness(register_ts: i64, epoch: i64, now: i64) -> Result<(), String> {
    let age = now.saturating_sub(register_ts);
    if age > PUNCH_PROOF_TTL_SECS + PUNCH_PROOF_CLOCK_SKEW_SECS
        || age < -PUNCH_PROOF_CLOCK_SKEW_SECS
    {
        return Err(
            "punch proof: register timestamp is stale or too far in the future".to_string(),
        );
    }
    let current_epoch = super::crypto::pairwise_capability_epoch(now);
    if epoch != current_epoch && epoch != current_epoch - 1 {
        return Err("punch proof: capability epoch is not current or previous".to_string());
    }
    Ok(())
}

/// Signed self-mailbox poll. No friend list or stable target candidates are
/// sent; the returned capability is checked by the caller against its local
/// friend relationship before acknowledgement.
pub async fn poll_punch(
    rendezvous_url: &str,
    our_ember_hash: &[u8; 16],
    secret_key: &[u8; 32],
) -> Result<Option<PunchInfo>, String> {
    require_https(rendezvous_url)?;
    let protocol = crate::network::rendezvous::negotiate_protocol(rendezvous_url).await?;
    let (domain, operation, route) = match protocol {
        crate::network::rendezvous::RendezvousProtocol::LegacyV3 => {
            (PUNCH_RDV_DOMAIN, OP_PUNCH_POLL_V3, "/v3/punch/poll")
        }
        crate::network::rendezvous::RendezvousProtocol::IpBoundV4 => {
            (PUNCH_RDV_V4_DOMAIN, OP_PUNCH_POLL_V4, "/v4/punch/poll")
        }
    };
    let (target_id, target_raw) = punch_identity(our_ember_hash);
    let ts = crate::network::rendezvous::current_timestamp();
    let nonce = punch_nonce();
    let mut signed = Vec::with_capacity(domain.len() + 1 + 32 + 16 + 8);
    signed.extend_from_slice(domain);
    signed.push(operation);
    signed.extend_from_slice(&target_raw);
    signed.extend_from_slice(&nonce);
    signed.extend_from_slice(&ts.to_le_bytes());
    let sig = sign_punch(secret_key, &signed);
    let client = relay_http_client(rendezvous_url).await?;
    let resp = client
        .post(format!("{}{}", rendezvous_url.trim_end_matches('/'), route))
        .json(&serde_json::json!({
            "target_id": target_id,
            "ts": ts,
            "nonce": hex::encode(nonce),
            "sig": hex::encode(sig),
        }))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("punch poll: {e}"))?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!("punch poll: status {}", resp.status()));
    }

    let body: serde_json::Value =
        read_json_capped(resp, MAX_RENDEZVOUS_JSON_BYTES, "punch poll").await?;
    let mut capability = [0u8; 32];
    hex::decode_to_slice(
        body["capability"].as_str().unwrap_or_default(),
        &mut capability,
    )
    .map_err(|_| "punch poll: invalid capability".to_string())?;
    let proof_version = body["proof_version"]
        .as_u64()
        .and_then(|value| u8::try_from(value).ok())
        .unwrap_or(match protocol {
            crate::network::rendezvous::RendezvousProtocol::LegacyV3 => 3,
            crate::network::rendezvous::RendezvousProtocol::IpBoundV4 => 0,
        });
    let mut register_nonce = [0u8; 16];
    let mut register_sig = [0u8; 64];
    let mut from_pubkey = [0u8; 32];
    if proof_version == 4 {
        hex::decode_to_slice(
            body["register_nonce"].as_str().unwrap_or_default(),
            &mut register_nonce,
        )
        .map_err(|_| "punch poll: invalid register_nonce".to_string())?;
        hex::decode_to_slice(
            body["register_sig"].as_str().unwrap_or_default(),
            &mut register_sig,
        )
        .map_err(|_| "punch poll: invalid register_sig".to_string())?;
        hex::decode_to_slice(
            body["from_pubkey"].as_str().unwrap_or_default(),
            &mut from_pubkey,
        )
        .map_err(|_| "punch poll: invalid from_pubkey".to_string())?;
    }
    let info = PunchInfo {
        punch_id: body["punch_id"].as_str().unwrap_or("").to_string(),
        from_id: body["from_id"].as_str().unwrap_or("").to_string(),
        ip: body["ip"].as_str().unwrap_or("").to_string(),
        port: u16::try_from(body["port"].as_u64().unwrap_or(0)).unwrap_or(0),
        nat_type: u8::try_from(body["nat_type"].as_u64().unwrap_or(5)).unwrap_or(5),
        capability,
        epoch: body["epoch"]
            .as_i64()
            .ok_or_else(|| "punch poll: missing capability epoch".to_string())?,
        proof_version,
        register_ts: if proof_version == 4 {
            body["register_ts"]
                .as_i64()
                .ok_or_else(|| "punch poll: missing register_ts".to_string())?
        } else {
            0
        },
        register_nonce,
        register_sig,
        from_pubkey,
        target_id_raw_hex: hex::encode(target_raw),
    };
    verify_punch_register_proof(&info, protocol)?;
    Ok(Some(info))
}

pub async fn ack_punch(
    rendezvous_url: &str,
    our_ember_hash: &[u8; 16],
    punch_id: &str,
    capability: &[u8; 32],
    epoch: i64,
    secret_key: &[u8; 32],
) -> Result<(), String> {
    require_https(rendezvous_url)?;
    let protocol = crate::network::rendezvous::negotiate_protocol(rendezvous_url).await?;
    if punch_id.len() != 64 || !punch_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("punch ack: invalid punch id".to_string());
    }
    let mut punch_raw = [0u8; 32];
    hex::decode_to_slice(punch_id, &mut punch_raw)
        .map_err(|_| "punch ack: invalid punch id".to_string())?;
    let (target_id, target_raw) = punch_identity(our_ember_hash);
    let ts = crate::network::rendezvous::current_timestamp();
    let nonce = punch_nonce();
    let (domain, operation, route) = match protocol {
        crate::network::rendezvous::RendezvousProtocol::LegacyV3 => {
            (PUNCH_RDV_DOMAIN, OP_PUNCH_ACK_V3, "/v3/punch/ack")
        }
        crate::network::rendezvous::RendezvousProtocol::IpBoundV4 => {
            (PUNCH_RDV_V4_DOMAIN, OP_PUNCH_ACK_V4, "/v4/punch/ack")
        }
    };
    let mut signed = Vec::with_capacity(domain.len() + 1 + 32 * 3 + 8 + 16 + 8);
    signed.extend_from_slice(domain);
    signed.push(operation);
    signed.extend_from_slice(&target_raw);
    signed.extend_from_slice(capability);
    signed.extend_from_slice(&epoch.to_le_bytes());
    signed.extend_from_slice(&punch_raw);
    signed.extend_from_slice(&nonce);
    signed.extend_from_slice(&ts.to_le_bytes());
    let sig = sign_punch(secret_key, &signed);
    let response = relay_http_client(rendezvous_url)
        .await?
        .post(format!("{}{}", rendezvous_url.trim_end_matches('/'), route))
        .json(&serde_json::json!({
            "target_id": target_id,
            "capability": hex::encode(capability),
            "epoch": epoch,
            "punch_id": punch_id.to_ascii_lowercase(),
            "ts": ts,
            "nonce": hex::encode(nonce),
            "sig": hex::encode(sig),
        }))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|error| format!("punch ack: {error}"))?;
    if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
        Ok(())
    } else {
        Err(format!("punch ack: status {}", response.status()))
    }
}

#[derive(Debug, Clone)]
pub struct PunchInfo {
    pub punch_id: String,
    pub from_id: String,
    pub ip: String,
    pub port: u16,
    pub nat_type: u8,
    pub capability: [u8; 32],
    pub epoch: i64,
    pub proof_version: u8,
    pub register_ts: i64,
    pub register_nonce: [u8; 16],
    pub register_sig: [u8; 64],
    pub from_pubkey: [u8; 32],
    /// Hex-encoded target id raw bytes used when verifying the register proof.
    pub target_id_raw_hex: String,
}

/// Connect to a relay-capable peer over QUIC and negotiate a relay session.
/// Returns the QUIC streams on success.
pub async fn connect_to_peer_relay(
    endpoint: &quinn::Endpoint,
    relay_addr: SocketAddr,
    target_ip: Ipv4Addr,
    target_port: u16,
    file_hash: &[u8; 16],
    attestation_hash: &[u8; 32],
    requester_pubkey: &[u8; 32],
    requester_ember_hash: &[u8; 16],
    requester_secret_key: &[u8; 32],
    pin: Option<(&[u8], &[u8], [u8; 16])>,
) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
    info!("Relay: connecting to peer relay at {relay_addr}");

    let conn = super::quic::connect_pinned(endpoint, relay_addr, "ember-relay", pin)
        .await
        .map_err(|e| format!("relay QUIC handshake failed: {e}"))?;

    let (mut send, mut recv) = tokio::time::timeout(RELAY_CONTROL_TIMEOUT, conn.open_bi())
        .await
        .map_err(|_| "relay open_bi timed out".to_string())?
        .map_err(|e| format!("relay open_bi failed: {e}"))?;

    let session_id = rand::random::<u32>();
    let request = build_relay_request_v2(
        session_id,
        target_ip,
        target_port,
        file_hash,
        attestation_hash,
        requester_pubkey,
        requester_ember_hash,
        requester_secret_key,
    );

    tokio::time::timeout(RELAY_CONTROL_TIMEOUT, send.write_all(&request))
        .await
        .map_err(|_| "relay write request timed out".to_string())?
        .map_err(|e| format!("relay write request: {e}"))?;

    // Read header first (always 7 bytes: msg_type | session_id | payload_len),
    // then drain the payload by length so we don't desynchronize the
    // stream if a future protocol revision (or non-conforming relay)
    // ever sends a non-empty accept/reject body. Cap payload to 64 KiB
    // to avoid reading an attacker-chosen huge `payload_len` into
    // memory.
    let mut resp_header = [0u8; 7];
    read_relay_control(&mut recv, &mut resp_header, "relay read response").await?;
    let payload_len = u16::from_le_bytes([resp_header[5], resp_header[6]]) as usize;
    if payload_len > 64 * 1024 {
        return Err(format!(
            "relay response payload_len {payload_len} exceeds 64 KiB cap"
        ));
    }
    let mut payload_buf = vec![0u8; payload_len];
    if payload_len > 0 {
        read_relay_control(&mut recv, &mut payload_buf, "relay read response payload").await?;
    }
    let mut full = Vec::with_capacity(7 + payload_len);
    full.extend_from_slice(&resp_header);
    full.extend_from_slice(&payload_buf);

    let (msg_type, returned_sid, payload) =
        decode_relay_message(&full).ok_or_else(|| "invalid relay response".to_string())?;

    if msg_type == MSG_RELAY_REJECT {
        // Payload is a single reason byte (see `build_relay_reject`):
        // 0x01 capacity, 0x02 bad target, 0x03 auth/attestation, 0x04 bad PoP.
        let reason = payload.first().copied();
        return Err(match reason {
            Some(REJECT_CAPACITY) => "relay peer rejected request: at capacity".to_string(),
            Some(REJECT_BAD_TARGET) => {
                "relay peer rejected request: invalid/non-public target".to_string()
            }
            Some(REJECT_AUTH) => {
                "relay peer rejected request: unauthenticated or unknown attestation".to_string()
            }
            Some(REJECT_BAD_SIGNATURE) => {
                "relay peer rejected request: bad requester signature or replay".to_string()
            }
            Some(other) => format!("relay peer rejected request: reason 0x{other:02X}"),
            None => "relay peer rejected request".to_string(),
        });
    }
    if msg_type != MSG_RELAY_ACCEPT {
        return Err(format!("unexpected relay response type: {msg_type}"));
    }
    // The relay echoes back our session ID; a mismatch here means either a
    // desynchronized/multiplexed response on this connection or a relay
    // implementation that doesn't preserve it — either way we can't trust
    // the ACCEPT actually corresponds to the request we just sent.
    if returned_sid != session_id {
        return Err(format!(
            "relay accept echoed mismatched session id: expected {session_id}, got {returned_sid}"
        ));
    }

    info!("Relay: peer relay accepted at {relay_addr}, session {session_id}");
    Ok((send, recv))
}

/// WebSocket adapter that implements AsyncRead + AsyncWrite over a
/// tokio-tungstenite WebSocket stream.
pub struct WsStream {
    inner: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl WsStream {
    pub fn new(
        ws: tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> Self {
        Self {
            inner: ws,
            read_buf: Vec::new(),
            read_pos: 0,
        }
    }
}

impl AsyncRead for WsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Drain non-data WebSocket frames (Ping/Pong/Text/etc.) in a
        // single poll without waking ourselves up — the old code called
        // `wake_by_ref()` and returned `Poll::Pending`, which makes the
        // runtime re-poll immediately and pegs a core at 100% whenever
        // the peer sends frames we don't care about. `tokio-tungstenite`
        // handles ping/pong internally by default, but a buggy or
        // hostile peer could still emit Text frames and we'd spin.
        // Looping here also means we only return `Poll::Pending` when
        // the underlying socket really is out of data.
        loop {
            match Stream::poll_next(Pin::new(&mut self.inner), cx) {
                Poll::Ready(Some(Ok(msg))) => {
                    use tokio_tungstenite::tungstenite::Message;
                    match msg {
                        Message::Binary(data) => {
                            if data.len() > MAX_WS_RELAY_FRAME {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!(
                                        "relay websocket frame too large: {} bytes",
                                        data.len()
                                    ),
                                )));
                            }
                            let to_copy = data.len().min(buf.remaining());
                            buf.put_slice(&data[..to_copy]);
                            if to_copy < data.len() {
                                self.read_buf = data[to_copy..].to_vec();
                                self.read_pos = 0;
                            }
                            return Poll::Ready(Ok(()));
                        }
                        // Close and stream-end both surface as EOF
                        // (zero bytes filled). Subsequent polls will
                        // return EOF again via `Poll::Ready(None)`.
                        Message::Close(_) => return Poll::Ready(Ok(())),
                        // Text, Ping, Pong, Frame: not data we should
                        // propagate through an AsyncRead. Drop and
                        // read the next frame in the same poll call.
                        _ => continue,
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        use tokio_tungstenite::tungstenite::Message;

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let write_len = buf.len().min(MAX_WS_RELAY_FRAME);
        let msg = Message::Binary(buf[..write_len].to_vec().into());
        match Sink::poll_ready(Pin::new(&mut self.inner), cx) {
            Poll::Ready(Ok(())) => match Sink::start_send(Pin::new(&mut self.inner), msg) {
                Ok(()) => Poll::Ready(Ok(write_len)),
                Err(e) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e))),
            },
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Sink::<tokio_tungstenite::tungstenite::Message>::poll_flush(
            Pin::new(&mut self.inner),
            cx,
        ) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Sink::<tokio_tungstenite::tungstenite::Message>::poll_close(
            Pin::new(&mut self.inner),
            cx,
        ) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Timeout for the relay node to connect to the target peer.
const RELAY_TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Bound every control-plane stream open/read/write after the QUIC handshake.
/// Data-plane relay copies remain governed by `RELAY_MAX_DURATION`.
const RELAY_CONTROL_TIMEOUT: Duration = Duration::from_secs(15);

async fn read_relay_control(
    recv: &mut quinn::RecvStream,
    buffer: &mut [u8],
    context: &str,
) -> Result<(), String> {
    tokio::time::timeout(RELAY_CONTROL_TIMEOUT, recv.read_exact(buffer))
        .await
        .map_err(|_| format!("{context}: timed out"))?
        .map_err(|e| format!("{context}: {e}"))
}

/// A relay target must be a globally-routable IPv4 unicast address.
///
/// The relay dials whatever `target_ip:target_port` the initiator puts in the
/// RELAY_REQUEST. Without this filter a malicious initiator could point the
/// relay at loopback, RFC1918, link-local or other reserved ranges and use the
/// operator's node as an SSRF / internal-port-scan proxy into its own LAN.
/// Only public unicast targets are dialable.
fn is_public_relay_target(ip: Ipv4Addr) -> bool {
    !crate::security::is_special_use_v4(ip)
}

/// Maximum number of in-flight QUIC accept tasks. The semaphore is
/// taken **before** spawning to bound pre-auth work — without this,
/// a peer flooding QUIC connections could exhaust scheduler/memory
/// regardless of `RelayManager::MAX_CONCURRENT_RELAY_SESSIONS`
/// (which only kicks in *after* the spawned task has read and
/// parsed the first message).
///
/// The permit is held for the **lifetime of the accepted session**: relay
/// bridges keep it in their task, while direct/relay-target handoffs transfer
/// it with both stream halves into the upload subsystem. The cap therefore
/// bounds relays, hole-punched direct connections, and in-progress handshakes.
/// Sized at 64 to leave room for normal traffic spikes while still being
/// orders of magnitude below a real scheduler/memory exhaustion threshold.
const QUIC_ACCEPT_INFLIGHT_CAP: usize = 64;
const QUIC_ACCEPT_RESERVED_FRIENDS: usize = 8;
const QUIC_ACCEPT_ORDINARY_CAP: usize = QUIC_ACCEPT_INFLIGHT_CAP - QUIC_ACCEPT_RESERVED_FRIENDS;
/// Concurrent handshakes when ordinary session slots are full, so a friend can
/// prove identity before spending a reserved session permit.
const QUIC_HANDSHAKE_OVERFLOW_CAP: usize = 16;
const QUIC_PENDING_PER_IP: usize = 4;
const QUIC_ACTIVE_PER_PRINCIPAL: usize = 4;
const QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const QUIC_FIRST_STREAM_TIMEOUT: Duration = Duration::from_secs(8);

enum PreSessionPermit {
    Ordinary(tokio::sync::OwnedSemaphorePermit),
    HandshakeOverflow(tokio::sync::OwnedSemaphorePermit),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuicIncomingAddressPolicy {
    Retry,
    ApplyAdmissionLimits,
}

fn quic_incoming_address_policy(remote_address_validated: bool) -> QuicIncomingAddressPolicy {
    if remote_address_validated {
        QuicIncomingAddressPolicy::ApplyAdmissionLimits
    } else {
        QuicIncomingAddressPolicy::Retry
    }
}

struct PendingIpGuard {
    counts: std::sync::Arc<parking_lot::Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl Drop for PendingIpGuard {
    fn drop(&mut self) {
        let mut counts = self.counts.lock();
        if let Some(count) = counts.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ActiveSessionPrincipal {
    Friend([u8; 16]),
    Ip(IpAddr),
}

struct ActiveSessionGuard {
    counts: std::sync::Arc<parking_lot::Mutex<HashMap<ActiveSessionPrincipal, usize>>>,
    principal: ActiveSessionPrincipal,
}

impl Drop for ActiveSessionGuard {
    fn drop(&mut self) {
        let mut counts = self.counts.lock();
        if let Some(count) = counts.get_mut(&self.principal) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.principal);
            }
        }
    }
}

fn try_acquire_active_session(
    counts: &std::sync::Arc<parking_lot::Mutex<HashMap<ActiveSessionPrincipal, usize>>>,
    principal: ActiveSessionPrincipal,
) -> Option<std::sync::Arc<ActiveSessionGuard>> {
    let mut locked = counts.lock();
    let count = locked.entry(principal).or_insert(0);
    if *count >= QUIC_ACTIVE_PER_PRINCIPAL {
        return None;
    }
    *count += 1;
    drop(locked);
    Some(std::sync::Arc::new(ActiveSessionGuard {
        counts: counts.clone(),
        principal,
    }))
}

struct QuicSessionGuard {
    _permit: tokio::sync::OwnedSemaphorePermit,
    _active: std::sync::Arc<ActiveSessionGuard>,
}

struct GuardedRead<R> {
    inner: R,
    _guard: std::sync::Arc<QuicSessionGuard>,
}

impl<R: AsyncRead + Unpin> AsyncRead for GuardedRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

struct GuardedWrite<W> {
    inner: W,
    _guard: std::sync::Arc<QuicSessionGuard>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for GuardedWrite<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Run the QUIC accept loop. Handles three kinds of inbound QUIC connections:
///   1. **RELAY_REQUEST** — peer wants us to relay a LowID transfer (existing relay logic)
///   2. **RELAY_CONNECT** — a relay node is forwarding a client to us (relay target)
///   3. **Raw eMule bytes** — hole-punched direct connection
///
/// Cases 2 and 3 both mean *we* are the firewalled source being reached by a
/// downloader (via a relay operator, or directly via a successful hole
/// punch) — we remain the upload/server role at the eD2K protocol level, so
/// both hand their stream to the upload listener's `InboundStreamRequest`
/// path rather than `kad_callback_tx` (which only adopts sources for *our
/// own* pending downloads and has no consumer for a connection with no
/// matching active download).
pub async fn run_quic_accept_loop(
    endpoint: std::sync::Arc<quinn::Endpoint>,
    relay_manager: std::sync::Arc<tokio::sync::Mutex<RelayManager>>,
    inbound_stream_tx: tokio::sync::mpsc::Sender<
        crate::network::ed2k::upload::InboundStreamRequest,
    >,
    friend_hashes: crate::app_state::SharedFriendHashes,
) {
    info!("QUIC accept loop started on {:?}", endpoint.local_addr());
    let ordinary_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(QUIC_ACCEPT_ORDINARY_CAP));
    let reserved_sem =
        std::sync::Arc::new(tokio::sync::Semaphore::new(QUIC_ACCEPT_RESERVED_FRIENDS));
    let handshake_overflow_sem =
        std::sync::Arc::new(tokio::sync::Semaphore::new(QUIC_HANDSHAKE_OVERFLOW_CAP));
    let pending_ip_counts =
        std::sync::Arc::new(parking_lot::Mutex::new(HashMap::<IpAddr, usize>::new()));
    let active_session_counts = std::sync::Arc::new(parking_lot::Mutex::new(HashMap::<
        ActiveSessionPrincipal,
        usize,
    >::new()));
    loop {
        let incoming = match endpoint.accept().await {
            Some(inc) => inc,
            None => {
                info!("QUIC accept loop: endpoint closed");
                break;
            }
        };

        if quic_incoming_address_policy(incoming.remote_address_validated())
            == QuicIncomingAddressPolicy::Retry
        {
            let remote = incoming.remote_address();
            if let Err(error) = incoming.retry() {
                debug!("QUIC accept: failed to issue Retry to {remote}: {error}");
            }
            continue;
        }

        let remote_ip = incoming.remote_address().ip();
        {
            let mut counts = pending_ip_counts.lock();
            let count = counts.entry(remote_ip).or_insert(0);
            if *count >= QUIC_PENDING_PER_IP {
                drop(counts);
                incoming.refuse();
                continue;
            }
            *count += 1;
        }
        let pending_ip_guard = PendingIpGuard {
            counts: pending_ip_counts.clone(),
            ip: remote_ip,
        };

        // Prefer an ordinary session slot. If none remain, admit a short-lived
        // handshake overflow permit so a friend can prove identity before we
        // spend a reserved session slot (non-friends never hold reserved).
        let pre_session = match ordinary_sem.clone().try_acquire_owned() {
            Ok(permit) => PreSessionPermit::Ordinary(permit),
            Err(_) => match handshake_overflow_sem.clone().try_acquire_owned() {
                Ok(permit) => PreSessionPermit::HandshakeOverflow(permit),
                Err(_) => {
                    debug!(
                        "QUIC accept: at concurrency cap, refusing inbound from {:?}",
                        incoming.remote_address(),
                    );
                    drop(pending_ip_guard);
                    incoming.refuse();
                    continue;
                }
            },
        };

        let ordinary_sem = ordinary_sem.clone();
        let reserved_sem = reserved_sem.clone();
        let mgr = relay_manager.clone();
        let ep = endpoint.clone();
        let cb_tx = inbound_stream_tx.clone();
        let friends = friend_hashes.clone();
        let active_counts = active_session_counts.clone();
        let accepted_at = tokio::time::Instant::now();
        tokio::spawn(async move {
            let pending_ip_guard = pending_ip_guard;
            let conn = match tokio::time::timeout_at(accepted_at + QUIC_HANDSHAKE_TIMEOUT, incoming)
                .await
            {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    debug!("Relay accept: handshake failed: {e}");
                    return;
                }
                Err(_) => {
                    debug!("Relay accept: handshake deadline exceeded for {remote_ip}");
                    return;
                }
            };
            // Handshake finished — release per-IP pending so long relays do not
            // starve other peers behind the same NAT address.
            drop(pending_ip_guard);

            let remote = conn.remote_address();
            debug!("Relay accept: new QUIC connection from {remote}");
            let peer_node_id = super::quic::connection_node_id(&conn);
            let known_friend = match peer_node_id {
                Some(node_id) => friends.read().await.contains(&node_id),
                None => false,
            };

            let session_permit = match pre_session {
                PreSessionPermit::Ordinary(permit) => permit,
                PreSessionPermit::HandshakeOverflow(_overflow) => {
                    if !known_friend {
                        conn.close(0u32.into(), b"friend reserve requires pinned identity");
                        return;
                    }
                    match reserved_sem.try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => match ordinary_sem.try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                conn.close(0u32.into(), b"no session capacity");
                                return;
                            }
                        },
                    }
                }
            };
            let principal = match (known_friend, peer_node_id) {
                (true, Some(node_id)) => ActiveSessionPrincipal::Friend(node_id),
                _ => ActiveSessionPrincipal::Ip(remote_ip),
            };
            let Some(active_session_guard) = try_acquire_active_session(&active_counts, principal)
            else {
                conn.close(0u32.into(), b"active principal session cap reached");
                return;
            };
            // The same shared guard follows handed-off streams into the upload
            // subsystem. For relay bridges it remains local to this task.
            // Either way, the ordinary/reserved permit and principal count are
            // released together exactly once when the final guard clone drops.
            let session_guard = std::sync::Arc::new(QuicSessionGuard {
                _permit: session_permit,
                _active: active_session_guard,
            });

            let (mut init_send, mut init_recv) = match tokio::time::timeout_at(
                accepted_at + QUIC_FIRST_STREAM_TIMEOUT,
                conn.accept_bi(),
            )
            .await
            {
                Ok(Ok(streams)) => streams,
                Ok(Err(e)) => {
                    debug!("Relay accept: accept_bi failed from {remote}: {e}");
                    return;
                }
                Err(_) => {
                    debug!("Relay accept: timed out waiting for a stream from {remote}");
                    return;
                }
            };

            // Read the first 7 bytes to determine connection type.
            // Relay framing: [msg_type(1) | session_id(4 LE) | payload_len(2 LE)]
            // eMule protocol: first byte >= 0xC5 (0xE3=ED2K, 0xC5=eMule, 0xD4=packed)
            let mut header = [0u8; 7];
            if let Err(e) =
                read_relay_control(&mut init_recv, &mut header, "read initial header").await
            {
                debug!("QUIC accept: failed to read header from {remote}: {e}");
                return;
            }

            let msg_type = header[0];

            if msg_type == MSG_RELAY_REQUEST {
                // === Peer relay request: initiator wants us to relay ===
                // We have only read the 7-byte header, so call the
                // header-only decoder rather than `decode_relay_message`,
                // which requires the full body to be present.
                let (_mt, peer_session_id, payload_len) = match decode_relay_header(&header) {
                    Some(decoded) => decoded,
                    None => {
                        debug!("QUIC accept: invalid RELAY_REQUEST header from {remote}");
                        return;
                    }
                };
                if payload_len as usize != RELAY_REQUEST_V2_PAYLOAD_LEN {
                    debug!(
                        "QUIC accept: RELAY_REQUEST from {remote} has unexpected payload_len {payload_len} (want {RELAY_REQUEST_V2_PAYLOAD_LEN}; v1 hash-only requests are rejected)"
                    );
                    // Echo reject when we can (session id is in the header).
                    let reject = build_relay_reject(peer_session_id, REJECT_AUTH);
                    let _ = init_send.write_all(&reject).await;
                    return;
                }

                let mut payload_buf = vec![0u8; payload_len as usize];
                if let Err(e) = read_relay_control(
                    &mut init_recv,
                    &mut payload_buf,
                    "read relay request payload",
                )
                .await
                {
                    debug!("QUIC accept: failed to read request payload from {remote}: {e}");
                    return;
                }

                let verified =
                    match parse_and_verify_relay_request_v2(peer_session_id, &payload_buf) {
                        Ok(req) => req,
                        Err(reason) => {
                            debug!("QUIC accept: refusing relay request from {remote}: {reason}");
                            let reject = build_relay_reject(peer_session_id, REJECT_BAD_SIGNATURE);
                            let _ = init_send.write_all(&reject).await;
                            return;
                        }
                    };

                // Refuse to relay to non-public destinations (SSRF/scan guard).
                if verified.target_port == 0 || !is_public_relay_target(verified.target_ip) {
                    debug!(
                        "QUIC accept: refusing relay to non-public target {}:{} from {remote}",
                        verified.target_ip, verified.target_port
                    );
                    let reject = build_relay_reject(peer_session_id, REJECT_BAD_TARGET);
                    let _ = init_send.write_all(&reject).await;
                    return;
                }

                {
                    let mut mgr_lock = mgr.lock().await;
                    if !mgr_lock.accepts_attestation_hash(&verified.attestation_hash) {
                        debug!(
                            "QUIC accept: refusing relay request from {remote}: unknown or expired attestation hash"
                        );
                        let reject = build_relay_reject(peer_session_id, REJECT_AUTH);
                        let _ = init_send.write_all(&reject).await;
                        return;
                    }
                    if !mgr_lock.consume_request_nonce(&verified.requester_pubkey, &verified.nonce)
                    {
                        debug!(
                            "QUIC accept: refusing relay request from {remote}: replayed or cache-full nonce"
                        );
                        let reject = build_relay_reject(peer_session_id, REJECT_BAD_SIGNATURE);
                        let _ = init_send.write_all(&reject).await;
                        return;
                    }
                }

                let initiator_ip = match remote.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => {
                        debug!("QUIC accept: non-IPv4 remote {remote}");
                        return;
                    }
                };
                let initiator_port = remote.port();
                let target_ip = verified.target_ip;
                let target_port = verified.target_port;
                let file_hash = verified.file_hash;

                let session_id = {
                    let mut mgr_lock = mgr.lock().await;
                    match mgr_lock.create_session(
                        initiator_ip,
                        initiator_port,
                        target_ip,
                        target_port,
                        file_hash,
                    ) {
                        Some(sid) => sid,
                        None => {
                            let reject = build_relay_reject(peer_session_id, REJECT_CAPACITY);
                            let _ = init_send.write_all(&reject).await;
                            debug!("QUIC accept: at capacity, rejected relay from {remote}");
                            return;
                        }
                    }
                };

                let accept_msg = build_relay_accept(peer_session_id);
                if let Err(e) = init_send.write_all(&accept_msg).await {
                    debug!("QUIC accept: failed to send ACCEPT to {remote}: {e}");
                    mgr.lock().await.remove_session(session_id);
                    return;
                }

                info!(
                    "Relay session {session_id}: accepted from {initiator_ip}:{initiator_port}, connecting to target {target_ip}:{target_port}"
                );

                let target_addr = SocketAddr::new(std::net::IpAddr::V4(target_ip), target_port);

                let target_result = tokio::time::timeout(
                    RELAY_TARGET_CONNECT_TIMEOUT,
                    connect_relay_target(&ep, target_addr, session_id, &file_hash),
                )
                .await;

                let (mut tgt_send, tgt_recv) = match target_result {
                    Ok(Ok(streams)) => streams,
                    Ok(Err(e)) => {
                        info!("Relay session {session_id}: target connect failed: {e}");
                        let close = build_relay_close(peer_session_id);
                        let _ = init_send.write_all(&close).await;
                        mgr.lock().await.remove_session(session_id);
                        return;
                    }
                    Err(_) => {
                        info!("Relay session {session_id}: target connect timed out");
                        let close = build_relay_close(peer_session_id);
                        let _ = init_send.write_all(&close).await;
                        mgr.lock().await.remove_session(session_id);
                        return;
                    }
                };

                {
                    let mut mgr_lock = mgr.lock().await;
                    if let Some(session) = mgr_lock.get_session_mut(session_id) {
                        session.mark_active();
                    }
                    info!(
                        "Relay session {session_id}: bridging ({} active sessions)",
                        mgr_lock.active_count()
                    );
                }

                let bw_limit = RELAY_MAX_BYTES_PER_DIRECTION;
                let relay_result = tokio::time::timeout(RELAY_MAX_DURATION, async {
                    let mut i2t_limited = init_recv.take(bw_limit);
                    let mut t2i_limited = tgt_recv.take(bw_limit);
                    let i2t = tokio::io::copy(&mut i2t_limited, &mut tgt_send);
                    let t2i = tokio::io::copy(&mut t2i_limited, &mut init_send);

                    match tokio::try_join!(i2t, t2i) {
                        Ok((i2t_bytes, t2i_bytes)) => {
                            let total = i2t_bytes + t2i_bytes;
                            if i2t_bytes >= bw_limit || t2i_bytes >= bw_limit {
                                info!(
                                    "Relay session {session_id}: per-direction byte ceiling reached (i→t: {i2t_bytes}B, t→i: {t2i_bytes}B)"
                                );
                            } else {
                                info!(
                                    "Relay session {session_id}: completed (i→t: {i2t_bytes}B, t→i: {t2i_bytes}B)"
                                );
                            }
                            total
                        }
                        Err(e) => {
                            debug!("Relay session {session_id}: IO error during relay: {e}");
                            0
                        }
                    }
                })
                .await;

                let total_bytes = match relay_result {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        debug!("Relay session {session_id}: max duration reached");
                        0
                    }
                };

                let _ = init_send.finish();
                let _ = tgt_send.finish();

                {
                    let mut mgr_lock = mgr.lock().await;
                    // Record the final byte count on the still-active
                    // session *before* removing it, so `remove_session`'s
                    // fold into the manager's cumulative
                    // `total_bytes_relayed` counter actually includes
                    // this session's bytes instead of the pre-transfer 0.
                    if let Some(session) = mgr_lock.get_session_mut(session_id) {
                        session.add_relayed_bytes(total_bytes);
                    }
                    if let Some(session) = mgr_lock.remove_session(session_id) {
                        info!(
                            "Relay session {session_id} ended: {} bytes relayed ({} active, {} total relayed)",
                            session.bytes_relayed,
                            mgr_lock.active_count(),
                            mgr_lock.total_bytes_relayed(),
                        );
                    }
                }
            } else if msg_type == MSG_RELAY_CONNECT {
                // === Relay target: a relay node is forwarding a client to us ===
                let payload_len = u16::from_le_bytes([header[5], header[6]]) as usize;
                if payload_len != 16 {
                    debug!(
                        "QUIC accept: RELAY_CONNECT payload length {payload_len} from {remote} (expected 16)"
                    );
                    return;
                }
                let mut file_hash = [0u8; 16];
                if let Err(e) =
                    read_relay_control(&mut init_recv, &mut file_hash, "read relay file hash").await
                {
                    debug!(
                        "QUIC accept: failed to read RELAY_CONNECT file hash from {remote}: {e}"
                    );
                    return;
                }

                info!(
                    "QUIC accept: relay-target connection from {remote}, file {}",
                    hex::encode(file_hash)
                );

                let req = crate::network::ed2k::upload::InboundStreamRequest {
                    peer_addr: remote,
                    reader: Box::new(GuardedRead {
                        inner: init_recv,
                        _guard: session_guard.clone(),
                    }),
                    writer: Box::new(GuardedWrite {
                        inner: init_send,
                        _guard: session_guard.clone(),
                    }),
                };
                if let Err(e) = cb_tx.try_send(req) {
                    debug!("QUIC accept: dropping relay-target stream from {remote}: {e}");
                }
            } else {
                // === Hole-punch or other direct connection ===
                info!(
                    "QUIC accept: direct connection from {remote} (first byte 0x{:02X})",
                    header[0]
                );

                let chained = std::io::Cursor::new(header.to_vec()).chain(init_recv);
                let req = crate::network::ed2k::upload::InboundStreamRequest {
                    peer_addr: remote,
                    reader: Box::new(GuardedRead {
                        inner: chained,
                        _guard: session_guard.clone(),
                    }),
                    writer: Box::new(GuardedWrite {
                        inner: init_send,
                        _guard: session_guard.clone(),
                    }),
                };
                if let Err(e) = cb_tx.try_send(req) {
                    debug!("QUIC accept: dropping direct stream from {remote}: {e}");
                }
            }
        });
    }
}

/// Connect to a target peer for relay bridging. Sends RELAY_CONNECT to
/// inform the target that this is a relayed connection.
async fn connect_relay_target(
    endpoint: &quinn::Endpoint,
    target_addr: SocketAddr,
    session_id: u32,
    file_hash: &[u8; 16],
) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
    let conn = endpoint
        .connect(target_addr, "ember-relay")
        .map_err(|e| format!("target connect error: {e}"))?
        .await
        .map_err(|e| format!("target QUIC handshake failed with {target_addr}: {e}"))?;

    let (mut send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("target open_bi failed: {e}"))?;

    let connect_msg = build_relay_connect(session_id, file_hash);
    send.write_all(&connect_msg)
        .await
        .map_err(|e| format!("target write RELAY_CONNECT: {e}"))?;

    debug!("Relay: connected to target {target_addr} for session {session_id}");
    Ok((send, recv))
}

fn validate_server_relay_ticket_id(ticket_id: &str) -> Result<(), String> {
    if ticket_id.len() == 64 && ticket_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("invalid server-relay ticket id".to_string())
    }
}

fn canonical_server_relay_ticket_id(ticket_id: &str) -> Result<String, String> {
    validate_server_relay_ticket_id(ticket_id)?;
    Ok(ticket_id.to_ascii_lowercase())
}

/// Connect to the rendezvous server's WebSocket relay endpoint.
/// Returns a WsStream that implements AsyncRead + AsyncWrite.
pub async fn connect_server_relay(
    rendezvous_url: &str,
    ticket_id: &str,
    role_token: &str,
) -> Result<WsStream, String> {
    let ticket_id = canonical_server_relay_ticket_id(ticket_id)?;
    if role_token.len() != 64 || !role_token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid server-relay role token".to_string());
    }

    // Validate HTTPS and resolve exactly once through the shared SSRF guard.
    // `connect_async` would resolve the hostname again after this check,
    // reopening a DNS-rebinding window. Instead, connect the TCP socket to one
    // of these validated addresses and hand that socket to the TLS upgrader.
    let (validated_url, host, addrs) = crate::security::validate_fetch_url(rendezvous_url)
        .await
        .map_err(|e| format!("rendezvous URL rejected: {e}"))?;
    let mut ws_url = reqwest::Url::parse(&validated_url)
        .map_err(|e| format!("invalid validated rendezvous URL: {e}"))?;
    ws_url
        .set_scheme("wss")
        .map_err(|_| "failed to construct secure relay WebSocket URL".to_string())?;
    let relay_path = format!(
        "{}/v2/relay/{ticket_id}",
        ws_url.path().trim_end_matches('/')
    );
    ws_url.set_path(&relay_path);
    ws_url.set_query(None);
    ws_url.set_fragment(None);

    info!("Relay: connecting to pinned server relay host {host}");

    // Bound all address attempts together so a long DNS answer cannot multiply
    // the connect timeout. No hostname is passed to TcpStream, so this performs
    // no second DNS lookup.
    let tcp_stream = tokio::time::timeout(RELAY_CONTROL_TIMEOUT, async {
        let mut last_error = None;
        for addr in &addrs {
            match tokio::net::TcpStream::connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last_error = Some(e),
            }
        }
        Err(last_error
            .map(|e| format!("all validated rendezvous addresses failed: {e}"))
            .unwrap_or_else(|| "rendezvous hostname resolved to no addresses".to_string()))
    })
    .await
    .map_err(|_| "server relay TCP connection timed out".to_string())??;
    tcp_stream
        .set_nodelay(true)
        .map_err(|e| format!("failed to configure server relay TCP socket: {e}"))?;

    // `client_async_tls_with_config` derives both TLS SNI and the HTTP Host
    // header from `ws_url`, while using the already-connected pinned socket.
    // This preserves normal certificate verification without another lookup.
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = ws_url
        .as_str()
        .into_client_request()
        .map_err(|e| format!("failed to construct relay WebSocket request: {e}"))?;
    let authorization = format!("Bearer {role_token}")
        .parse()
        .map_err(|_| "failed to construct relay authorization header".to_string())?;
    request.headers_mut().insert("authorization", authorization);

    let (ws_stream, _response) = tokio::time::timeout(
        RELAY_CONTROL_TIMEOUT,
        tokio_tungstenite::client_async_tls_with_config(
            request,
            tcp_stream,
            None,
            None,
        ),
    )
    .await
    .map_err(|_| "server relay TLS/WebSocket handshake timed out".to_string())?
    .map_err(|e| {
        // Do not include `ws_url`: its path contains a relay ticket id.
        // The header carries the one-time bearer capability and must never
        // appear in logs or surfaced error strings.
        let rendered = format!("{e}");
        if rendered.contains("404") {
            "WS relay connect failed: 404 Not Found (deployed rendezvous is missing the authenticated v2 relay route; redeploy the server)".to_string()
        } else {
            format!("WS relay connect failed: {rendered}")
        }
    })?;

    info!("Relay: server relay connected");
    Ok(WsStream::new(ws_stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_message_round_trip() {
        let original = encode_relay_message(MSG_RELAY_CONNECT, 42, b"hello world");
        let (msg_type, session_id, payload) = decode_relay_message(&original).unwrap();
        assert_eq!(msg_type, MSG_RELAY_CONNECT);
        assert_eq!(session_id, 42);
        assert_eq!(payload, b"hello world");
    }

    #[test]
    fn relay_request_v2_round_trip_and_verifies() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let port = 4662u16;
        let file_hash = [0xAA; 16];
        let attestation_hash = [0xBB; 32];
        let sk = super::super::crypto::signing_key_from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let ember_hash = super::super::crypto::node_id_from_public_key(&sk.verifying_key());
        let secret = sk.to_bytes();

        let msg = build_relay_request_v2(
            1,
            ip,
            port,
            &file_hash,
            &attestation_hash,
            &pk,
            &ember_hash,
            &secret,
        );
        let (msg_type, sid, payload) = decode_relay_message(&msg).unwrap();
        assert_eq!(msg_type, MSG_RELAY_REQUEST);
        assert_eq!(sid, 1);
        assert_eq!(payload.len(), RELAY_REQUEST_V2_PAYLOAD_LEN);
        let parsed = parse_and_verify_relay_request_v2(1, payload).unwrap();
        assert_eq!(parsed.target_ip, ip);
        assert_eq!(parsed.target_port, port);
        assert_eq!(parsed.file_hash, file_hash);
        assert_eq!(parsed.attestation_hash, attestation_hash);
        assert_eq!(parsed.requester_pubkey, pk);
        assert_eq!(parsed.requester_ember_hash, ember_hash);
    }

    #[test]
    fn relay_request_v2_rejects_tampered_payload() {
        let sk = super::super::crypto::signing_key_from_bytes(&[9u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let ember_hash = super::super::crypto::node_id_from_public_key(&sk.verifying_key());
        let secret = sk.to_bytes();
        let msg = build_relay_request_v2(
            42,
            Ipv4Addr::new(8, 8, 8, 8),
            4662,
            &[1u8; 16],
            &[2u8; 32],
            &pk,
            &ember_hash,
            &secret,
        );
        let (_, sid, payload) = decode_relay_message(&msg).unwrap();
        let mut bad = payload.to_vec();
        bad[7] ^= 0xFF; // flip a file_hash byte under the signature
        assert!(parse_and_verify_relay_request_v2(sid, &bad).is_err());
    }

    #[test]
    fn relay_request_v2_rejects_binding_mismatch() {
        let sk = super::super::crypto::signing_key_from_bytes(&[3u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let secret = sk.to_bytes();
        let wrong_hash = [0xABu8; 16];
        let msg = build_relay_request_v2(
            7,
            Ipv4Addr::new(1, 1, 1, 1),
            4662,
            &[0u8; 16],
            &[0u8; 32],
            &pk,
            &wrong_hash,
            &secret,
        );
        let (_, sid, payload) = decode_relay_message(&msg).unwrap();
        assert!(parse_and_verify_relay_request_v2(sid, payload).is_err());
    }

    #[test]
    fn v4_punch_proof_round_trip_reuses_registration_transcript() {
        let secret = [0x37; 32];
        let public = our_punch_pubkey(&secret);
        let ember_hash = super::super::crypto::node_id_from_public_key(
            &ed25519_dalek::VerifyingKey::from_bytes(&public).unwrap(),
        );
        let (from_id, from_raw) = punch_identity(&ember_hash);
        let target_raw = [0x42; 32];
        let capability = [0xA5; 32];
        let now = crate::network::rendezvous::current_timestamp();
        let epoch = super::super::crypto::pairwise_capability_epoch(now);
        let nonce = [0x19; 16];
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let signed = build_punch_register_message(
            crate::network::rendezvous::RendezvousProtocol::IpBoundV4,
            &from_raw,
            &target_raw,
            &capability,
            epoch,
            4662,
            ip,
            1,
            &nonce,
            now,
        );
        let info = PunchInfo {
            punch_id: "11".repeat(32),
            from_id,
            ip: ip.to_string(),
            port: 4662,
            nat_type: 1,
            capability,
            epoch,
            proof_version: 4,
            register_ts: now,
            register_nonce: nonce,
            register_sig: sign_punch(&secret, &signed),
            from_pubkey: public,
            target_id_raw_hex: hex::encode(target_raw),
        };
        verify_punch_register_proof(
            &info,
            crate::network::rendezvous::RendezvousProtocol::IpBoundV4,
        )
        .expect("v4 server proof verifies");

        let mut tampered = info;
        tampered.port += 1;
        assert!(verify_punch_register_proof(
            &tampered,
            crate::network::rendezvous::RendezvousProtocol::IpBoundV4,
        )
        .is_err());
    }

    #[test]
    fn v4_punch_poll_rejects_legacy_proof_version_fail_open() {
        let info = PunchInfo {
            punch_id: "11".repeat(32),
            from_id: "22".repeat(32),
            ip: "8.8.8.8".to_string(),
            port: 4662,
            nat_type: 1,
            capability: [0xA5; 32],
            epoch: 1,
            proof_version: 3,
            register_ts: 0,
            register_nonce: [0; 16],
            register_sig: [0; 64],
            from_pubkey: [0; 32],
            target_id_raw_hex: hex::encode([0x42; 32]),
        };
        let err = verify_punch_register_proof(
            &info,
            crate::network::rendezvous::RendezvousProtocol::IpBoundV4,
        )
        .expect_err("v4 must not accept proof_version 3");
        assert!(err.contains("proof_version 4"));
    }

    #[test]
    fn v4_punch_registration_matches_server_transcript_vector() {
        let transcript = build_punch_register_message(
            crate::network::rendezvous::RendezvousProtocol::IpBoundV4,
            &[0x11; 32],
            &[0x22; 32],
            &[0x33; 32],
            0x0102_0304_0506_0708,
            0x1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
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
    fn relay_manager_rejects_replayed_request_nonce() {
        let mut mgr = RelayManager::new();
        let pk = [5u8; 32];
        let nonce = [6u8; 16];
        assert!(mgr.consume_request_nonce(&pk, &nonce));
        assert!(!mgr.consume_request_nonce(&pk, &nonce));
    }

    #[test]
    fn server_relay_ticket_path_is_canonicalized() {
        let lower = "ab".repeat(32);
        assert_eq!(
            canonical_server_relay_ticket_id(&lower.to_ascii_uppercase()).unwrap(),
            lower
        );
        assert!(canonical_server_relay_ticket_id("invalid").is_err());
    }

    #[test]
    fn relay_manager_retains_unexpired_attestation_hashes() {
        let mut mgr = RelayManager::new();
        let current = [1u8; 32];
        let previous = [2u8; 32];
        let unknown = [3u8; 32];
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        mgr.set_current_attestation_hash(previous, expires);
        mgr.set_current_attestation_hash(current, expires);
        assert!(mgr.accepts_attestation_hash(&current));
        assert!(mgr.accepts_attestation_hash(&previous));
        assert!(!mgr.accepts_attestation_hash(&unknown));
    }

    #[test]
    fn active_relay_ignores_waiting_session_idle_timeout() {
        let mut session = RelaySession::new(
            1,
            Ipv4Addr::new(1, 2, 3, 4),
            4662,
            Ipv4Addr::new(5, 6, 7, 8),
            4663,
            [1u8; 16],
        );
        session.last_activity = Instant::now() - RELAY_IDLE_TIMEOUT - Duration::from_secs(1);
        assert!(session.is_expired());

        session.mark_active();
        session.last_activity = Instant::now() - RELAY_IDLE_TIMEOUT - Duration::from_secs(1);
        assert!(
            !session.is_expired(),
            "active bridges remain tracked until the hard duration cap"
        );
    }

    #[test]
    fn relay_accept_decode() {
        let msg = build_relay_accept(99);
        let (t, sid, payload) = decode_relay_message(&msg).unwrap();
        assert_eq!(t, MSG_RELAY_ACCEPT);
        assert_eq!(sid, 99);
        assert!(payload.is_empty());
    }

    #[test]
    fn relay_manager_session_lifecycle() {
        let mut mgr = RelayManager::new();
        assert_eq!(mgr.active_count(), 0);

        let sid = mgr
            .create_session(
                Ipv4Addr::new(1, 2, 3, 4),
                4662,
                Ipv4Addr::new(5, 6, 7, 8),
                4663,
                [1u8; 16],
            )
            .unwrap();

        assert_eq!(mgr.active_count(), 1);
        assert!(mgr.get_session_mut(sid).is_some());

        mgr.get_session_mut(sid).unwrap().mark_active();
        mgr.get_session_mut(sid).unwrap().add_relayed_bytes(1000);
        assert_eq!(mgr.get_session_mut(sid).unwrap().bytes_relayed, 1000);

        mgr.remove_session(sid);
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn remove_session_folds_bytes_into_cumulative_total() {
        let mut mgr = RelayManager::new();
        assert_eq!(mgr.total_bytes_relayed(), 0);

        let sid = mgr
            .create_session(
                Ipv4Addr::new(1, 2, 3, 4),
                4662,
                Ipv4Addr::new(5, 6, 7, 8),
                4663,
                [2u8; 16],
            )
            .unwrap();
        mgr.get_session_mut(sid).unwrap().add_relayed_bytes(500);

        let removed = mgr.remove_session(sid);
        assert_eq!(removed.map(|s| s.bytes_relayed), Some(500));
        assert_eq!(
            mgr.total_bytes_relayed(),
            500,
            "bytes from a normally-ended session must count toward the lifetime total, \
             not just sessions reaped by cleanup()"
        );

        // A second session's bytes accumulate on top rather than replacing.
        let sid2 = mgr
            .create_session(
                Ipv4Addr::new(9, 9, 9, 9),
                4662,
                Ipv4Addr::new(5, 6, 7, 8),
                4663,
                [3u8; 16],
            )
            .unwrap();
        mgr.get_session_mut(sid2).unwrap().add_relayed_bytes(250);
        mgr.remove_session(sid2);
        assert_eq!(mgr.total_bytes_relayed(), 750);
    }

    #[test]
    fn relay_manager_capacity_limit() {
        let mut mgr = RelayManager::new();
        for i in 0..MAX_CONCURRENT_RELAY_SESSIONS {
            let mut ip_bytes = [0u8; 4];
            ip_bytes[3] = (i + 1) as u8;
            assert!(mgr
                .create_session(
                    Ipv4Addr::from(ip_bytes),
                    4662,
                    Ipv4Addr::new(10, 10, 10, 10),
                    4663,
                    [i as u8; 16],
                )
                .is_some());
        }
        // Next one should fail
        assert!(mgr
            .create_session(
                Ipv4Addr::new(99, 99, 99, 99),
                4662,
                Ipv4Addr::new(10, 10, 10, 10),
                4663,
                [0xFF; 16],
            )
            .is_none());
    }

    #[test]
    fn quic_pending_guard_releases_per_ip_count() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let counts = std::sync::Arc::new(parking_lot::Mutex::new(HashMap::new()));
        counts.lock().insert(ip, 1);
        {
            let _guard = PendingIpGuard {
                counts: counts.clone(),
                ip,
            };
            assert_eq!(counts.lock().get(&ip), Some(&1));
        }
        assert!(!counts.lock().contains_key(&ip));
        assert_eq!(
            QUIC_ACCEPT_ORDINARY_CAP + QUIC_ACCEPT_RESERVED_FRIENDS,
            QUIC_ACCEPT_INFLIGHT_CAP
        );
        assert!(QUIC_HANDSHAKE_OVERFLOW_CAP > 0);
        assert_eq!(QUIC_PENDING_PER_IP, 4);
    }

    #[test]
    fn active_session_guard_caps_and_releases_principal() {
        let counts = std::sync::Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let principal = ActiveSessionPrincipal::Ip("203.0.113.9".parse().unwrap());
        let mut guards = Vec::new();
        for _ in 0..QUIC_ACTIVE_PER_PRINCIPAL {
            guards.push(
                try_acquire_active_session(&counts, principal)
                    .expect("principal remains below active cap"),
            );
        }
        assert!(try_acquire_active_session(&counts, principal).is_none());
        guards.pop();
        assert!(try_acquire_active_session(&counts, principal).is_some());
    }

    #[test]
    fn friend_identity_principals_do_not_share_nat_cap() {
        let counts = std::sync::Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let alice = ActiveSessionPrincipal::Friend([1; 16]);
        let bob = ActiveSessionPrincipal::Friend([2; 16]);
        let _alice = try_acquire_active_session(&counts, alice).unwrap();
        let _bob = try_acquire_active_session(&counts, bob).unwrap();
        assert_eq!(counts.lock().len(), 2);
    }

    #[tokio::test]
    async fn handed_off_stream_holds_session_permit_until_both_halves_drop() {
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let counts = std::sync::Arc::new(parking_lot::Mutex::new(HashMap::new()));
        let principal = ActiveSessionPrincipal::Ip("8.8.8.8".parse().unwrap());
        let active = try_acquire_active_session(&counts, principal).unwrap();
        let guard = std::sync::Arc::new(QuicSessionGuard {
            _permit: permit,
            _active: active,
        });
        let reader = GuardedRead {
            inner: tokio::io::empty(),
            _guard: guard.clone(),
        };
        let writer = GuardedWrite {
            inner: tokio::io::sink(),
            _guard: guard.clone(),
        };
        drop(guard);

        assert_eq!(semaphore.available_permits(), 0);
        assert_eq!(counts.lock().get(&principal), Some(&1));
        drop(reader);
        assert_eq!(semaphore.available_permits(), 0);
        assert_eq!(counts.lock().get(&principal), Some(&1));
        drop(writer);
        assert_eq!(semaphore.available_permits(), 1);
        assert!(!counts.lock().contains_key(&principal));
    }

    #[test]
    fn punch_proof_freshness_accepts_boundaries_and_current_epochs() {
        let now = 9_000;
        let epoch = super::super::crypto::pairwise_capability_epoch(now);
        assert!(verify_punch_proof_freshness(now, epoch, now).is_ok());
        assert!(verify_punch_proof_freshness(
            now - PUNCH_PROOF_TTL_SECS - PUNCH_PROOF_CLOCK_SKEW_SECS,
            epoch - 1,
            now,
        )
        .is_ok());
        assert!(
            verify_punch_proof_freshness(now + PUNCH_PROOF_CLOCK_SKEW_SECS, epoch, now,).is_ok()
        );
    }

    #[test]
    fn punch_proof_freshness_rejects_historical_replay_and_old_epoch() {
        let now = 9_000;
        let epoch = super::super::crypto::pairwise_capability_epoch(now);
        assert!(verify_punch_proof_freshness(
            now - PUNCH_PROOF_TTL_SECS - PUNCH_PROOF_CLOCK_SKEW_SECS - 1,
            epoch,
            now,
        )
        .is_err());
        assert!(verify_punch_proof_freshness(now, epoch - 2, now).is_err());
    }

    #[test]
    fn unvalidated_quic_incoming_retries_before_ip_accounting() {
        let mut pending_by_ip = HashMap::<IpAddr, usize>::new();
        let policy = quic_incoming_address_policy(false);
        if policy == QuicIncomingAddressPolicy::ApplyAdmissionLimits {
            pending_by_ip.insert("203.0.113.99".parse().unwrap(), 1);
        }
        assert_eq!(policy, QuicIncomingAddressPolicy::Retry);
        assert!(pending_by_ip.is_empty());
        assert_eq!(
            quic_incoming_address_policy(true),
            QuicIncomingAddressPolicy::ApplyAdmissionLimits
        );
    }
}
