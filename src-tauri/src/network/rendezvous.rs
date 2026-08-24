use std::net::{IpAddr, Ipv4Addr};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key as ChaChaKey, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Rendezvous-protocol Ed25519 signing. Mirrors the verification helpers
// in `rendezvous-server/src/main.rs`. The server pins each id to its
// pubkey on first `/register` and refuses any later `/register`,
// `/unregister`, or `/v3/punch/*` action that doesn't
// carry a valid signature for that pinned pubkey — closing the squat
// attack where an attacker could compute a victim's id (just SHA256
// of the friend's BLAKE3 hash, both public) and POST a fake address
// for it. The signed messages each include a domain-separation prefix,
// an op tag, and a timestamp so the server can also reject replays.
// ---------------------------------------------------------------------------

const RDV_DOMAIN: &[u8] = b"ember-rdv-v1";
const OP_REGISTER: u8 = 0x01;
const OP_UNREGISTER: u8 = 0x02;
const OP_RELAY_TICKET_ACCEPT: u8 = 0x09;
const OP_RELAY_TICKET_STATUS: u8 = 0x0a;
const OP_CAPABILITY_REGISTER: u8 = 0x0c;
const OP_CAPABILITY_LOOKUP: u8 = 0x0d;
const OP_RELAY_MAILBOX_OFFER: u8 = 0x0e;
const OP_RELAY_MAILBOX_POLL: u8 = 0x0f;
const RDV_V4_DOMAIN: &[u8] = b"ember-rdv-v4";
const OP_IDENTITY_LOOKUP_V4: u8 = 0x20;
const OP_CAPABILITY_REGISTER_V4: u8 = 0x21;
const OP_CAPABILITY_LOOKUP_V4: u8 = 0x22;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RendezvousProtocol {
    LegacyV3,
    IpBoundV4,
}

fn explicit_version_unsupported(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::NOT_FOUND
            | reqwest::StatusCode::METHOD_NOT_ALLOWED
            | reqwest::StatusCode::GONE
            | reqwest::StatusCode::NOT_IMPLEMENTED
            | reqwest::StatusCode::UPGRADE_REQUIRED
    )
}

pub(crate) async fn negotiate_protocol(base_url: &str) -> Result<RendezvousProtocol, String> {
    require_https(base_url)?;
    let response = client(base_url)
        .await?
        .get(format!("{}/v4/protocol", base_url.trim_end_matches('/')))
        .send()
        .await
        .map_err(|error| format!("rendezvous protocol probe failed: {error}"))?;
    if response.status().is_success() {
        let body: serde_json::Value =
            serde_json::from_slice(&read_bounded_bytes(response, MAX_RESPONSE_BYTES).await?)
                .map_err(|error| format!("rendezvous protocol probe bad body: {error}"))?;
        return if body["version"].as_u64() == Some(4) {
            Ok(RendezvousProtocol::IpBoundV4)
        } else {
            Err("rendezvous protocol probe returned an unsupported version".to_string())
        };
    }
    if explicit_version_unsupported(response.status()) {
        debug!("Rendezvous: server explicitly lacks v4; using bounded legacy v3 compatibility");
        Ok(RendezvousProtocol::LegacyV3)
    } else {
        Err(format!(
            "rendezvous protocol probe returned {}",
            response.status()
        ))
    }
}
/// The initiator gives the responder this total window to accept an offered
/// ticket. The network loop polls frequently enough to leave multiple
/// attempts inside this period, even when one request reaches its timeout.
pub(crate) const FRIEND_RELAY_TICKET_INITIATOR_WAIT: std::time::Duration =
    std::time::Duration::from_secs(45);
pub(crate) const FRIEND_RELAY_TICKET_RESPONDER_POLL_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(1);
pub(crate) const FRIEND_RELAY_TICKET_POLL_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(3);
pub(crate) const FRIEND_RELAY_TICKET_ACTION_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(10);
const RELAY_TICKET_READ_NONCE_DOMAIN: &[u8] = b"ember-relay-ticket-read-nonce-v1\0";
const RELAY_MAILBOX_ENVELOPE_VERSION: u8 = 1;
const RELAY_MAILBOX_NONCE_LEN: usize = 24;

pub(crate) fn is_transient_relay_ticket_read_error(error: &str) -> bool {
    [
        "status 408",
        "status 425",
        "status 429",
        "status 500",
        "status 502",
        "status 503",
        "status 504",
    ]
    .iter()
    .any(|status| error.contains(status))
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn sha256_id_raw(ember_hash: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ember_hash);
    let out = hasher.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

fn signing_key_from_secret(secret: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(secret)
}

/// Builds the exact byte sequence a registrant signs (and that the
/// server / lookup callers re-verify against). Factored out of
/// `sign_register` so `lookup`'s response-verification path can
/// reconstruct the identical message without re-deriving a signature.
/// Mirrors `rendezvous-server/src/main.rs::build_register_msg`.
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

fn sign_register(
    secret: &[u8; 32],
    pubkey: &[u8; 32],
    id_raw: &[u8; 32],
    port: u16,
    ip4: [u8; 4],
    ts: i64,
) -> Signature {
    let m = build_register_msg(id_raw, port, ip4, pubkey, ts);
    use ed25519_dalek::Signer;
    signing_key_from_secret(secret).sign(&m)
}

/// Re-derives the rendezvous id from a pubkey and checks it matches
/// the id we looked up. Mirrors the server-side derivation chain
/// `pubkey -> ember_hash (BLAKE3 truncated) -> id (SHA256)` — see
/// `rendezvous-server/src/main.rs::pubkey_matches_id`. This is what
/// lets `lookup` trust a pubkey it has never seen before: the id
/// itself is a one-way function of the pubkey, so a pubkey that
/// hashes to the id we asked for could only have been chosen by
/// whoever controls the corresponding private key (or by brute-force
/// preimage search, which SHA256/BLAKE3 make infeasible).
pub(crate) fn pubkey_matches_id(pubkey: &[u8; 32], claimed_id: &str) -> bool {
    let pk_blake = blake3::hash(pubkey);
    let ember_hash = &pk_blake.as_bytes()[..16];
    let mut sha = Sha256::new();
    sha.update(ember_hash);
    let derived = hex::encode(sha.finalize());
    derived.eq_ignore_ascii_case(claimed_id)
}

/// Strict Ed25519 verification (rejects malleable signatures /
/// small-subgroup attacks), matching the server's verifier.
fn ed25519_verify_lookup(pubkey: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let signature = Signature::from_bytes(sig);
    vk.verify_strict(message, &signature).is_ok()
}

fn sign_unregister(secret: &[u8; 32], id_raw: &[u8; 32], ts: i64) -> Signature {
    let mut m = Vec::with_capacity(RDV_DOMAIN.len() + 1 + 32 + 8);
    m.extend_from_slice(RDV_DOMAIN);
    m.push(OP_UNREGISTER);
    m.extend_from_slice(id_raw);
    m.extend_from_slice(&ts.to_le_bytes());
    use ed25519_dalek::Signer;
    signing_key_from_secret(secret).sign(&m)
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

fn random_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn stable_relay_ticket_read_nonce(secret: &[u8; 32], scope: &[u8]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(RELAY_TICKET_READ_NONCE_DOMAIN);
    hasher.update(secret);
    hasher.update(scope);
    let digest = hasher.finalize();
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&digest[..16]);
    nonce
}

fn valid_ticket_secret(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_ticket_response_field(value: &str, field: &str) -> Result<(), String> {
    if valid_ticket_secret(value) {
        Ok(())
    } else {
        Err(format!(
            "rendezvous relay ticket response has invalid {field}"
        ))
    }
}

pub(crate) fn current_timestamp() -> i64 {
    now_unix_secs()
}

/// Hard byte cap on rendezvous responses. Every payload this client
/// consumes is a small JSON blob (a signed lookup result — ip, port,
/// pubkey, ts, sig — is well under 512 bytes; relay invite list is
/// bounded server-side). 8 KiB leaves >15x headroom
/// over the largest realistic response while making us decisively
/// hostile to a malicious or misbehaving rendezvous that tries to
/// stream megabytes at us. The previous 64 KiB cap was chosen for
/// "future-proof" reasons but no current code path needs that much
/// — the smaller cap matches main and shrinks the DoS surface.
const MAX_RESPONSE_BYTES: usize = 8 * 1024;

pub fn hashed_id(ember_hash: &[u8; 16]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ember_hash);
    hex::encode(hasher.finalize())
}

async fn client(rendezvous_url: &str) -> Result<reqwest::Client, String> {
    let (_, host, addrs) = crate::security::validate_fetch_url(rendezvous_url)
        .await
        .map_err(|e| format!("rendezvous URL rejected: {e}"))?;
    crate::security::build_pinned_client(&host, &addrs)
        .map_err(|e| format!("failed to build hardened rendezvous HTTP client: {e}"))
}

/// Reject non-HTTPS rendezvous URLs before we send any traffic. The
/// rendezvous flow gives a peer the IP/port we'll connect to for a
/// friend session — over plaintext HTTP, a network-position attacker
/// could rewrite the response and steer the connection to an
/// attacker-controlled host. The HTTP client is also built with
/// `https_only(true)` (above), which catches redirects to `http://`,
/// but checking up-front gives a clearer error message.
fn require_https(url: &str) -> Result<(), String> {
    let trimmed = url.trim();
    if trimmed.starts_with("https://") {
        Ok(())
    } else {
        Err(format!(
            "rendezvous URL must use https:// (got: {})",
            // Show the scheme part only; don't echo the whole URL into
            // the user-visible error since it can be long.
            trimmed.split("://").next().unwrap_or("<empty>")
        ))
    }
}

/// Read the response body with a hard byte cap. Protects against a hostile
/// or misbehaving rendezvous server that might otherwise stream megabytes of
/// JSON at us.
async fn read_bounded_bytes(resp: reqwest::Response, limit: usize) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length() {
        if len as usize > limit {
            return Err(format!(
                "rendezvous response too large: {len} bytes (max {limit})"
            ));
        }
    }
    let mut stream = resp.bytes_stream();
    use futures::StreamExt;
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("rendezvous read failed: {e}"))?;
        if buf.len().saturating_add(chunk.len()) > limit {
            return Err(format!("rendezvous response exceeded {limit}-byte cap"));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Result of a successful classic `/register`. Presence-layer intro and
/// pairwise posts are reported here so callers can treat "on the server"
/// as distinct from "friends can look us up".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegistrationOutcome {
    pub intro_ok: bool,
    pub pairwise_attempted: usize,
    pub pairwise_failed: usize,
}

impl RegistrationOutcome {
    pub(crate) fn pairwise_succeeded(&self) -> usize {
        self.pairwise_attempted.saturating_sub(self.pairwise_failed)
    }

    /// Every pairwise POST we issued failed (and we issued at least one).
    pub(crate) fn all_pairwise_failed(&self) -> bool {
        self.pairwise_attempted > 0 && self.pairwise_failed == self.pairwise_attempted
    }

    /// Lookup tries intro first, then pairwise, and skips 404s. Existing
    /// friends are treated as blocked only when *both* paths missed: intro
    /// failed and every pairwise attempt failed. Intro-only failure degrades
    /// one-sided friend-code adds.
    ///
    /// `pairwise_attempted == 0` is *not* treated as blocked. That count
    /// conflates "no friends" with "friends exist but none have exchanged a
    /// v2 identity key" (`get_friend_public_keys` yields nothing for hash-only
    /// relationships). In the latter case an intro failure does hide us from
    /// everyone, but this helper still returns false — matching prior
    /// behavior, not a claim that hash-only friends can still find us.
    pub(crate) fn existing_friends_blocked(&self) -> bool {
        !self.intro_ok && self.all_pairwise_failed()
    }

    /// Diagnosable reason when presence was incomplete. `None` is full
    /// success. The frontend currently only keys off `discoverable` and
    /// `initial`; callers attach this so a later UI can surface degraded
    /// states without treating them as outright failure.
    pub(crate) fn degraded_reason(&self) -> Option<&'static str> {
        let intro_bad = !self.intro_ok;
        let pairwise_any = self.pairwise_failed > 0;
        match (intro_bad, self.all_pairwise_failed(), pairwise_any) {
            (false, false, false) => None,
            (true, false, false) => Some("intro_presence_failed"),
            (false, false, true) => Some("pairwise_presence_partial"),
            (false, true, _) => Some("pairwise_presence_failed"),
            (true, false, true) => Some("presence_partial"),
            (true, true, _) => Some("presence_registration_failed"),
        }
    }
}

/// Register our presence with the rendezvous server.
///
/// `pubkey` and `secret_key` are the node's Ed25519 identity keypair —
/// the pubkey is sent to the server and pinned to `id`, the secret key
/// signs the request so future re-registrations or unregistrations can
/// be authenticated. The server enforces that any later request for
/// this id MUST come from this same keypair, which is what blocks
/// the squat-and-steer attack on the rendezvous /register endpoint.
///
/// `external_ip` is REQUIRED. The server has no `client_ip` fallback
/// anymore (a VPN / split-tunnel user's HTTPS to rendezvous can egress
/// from a different address than their P2P listener, so pinning to the
/// connection address would steer every friend lookup at an
/// unreachable host). Callers must therefore wait until the firewall
/// checker / KAD probe has produced a confirmed IPv4 address before
/// invoking this function.
///
/// `port` is the TCP listener friends dial. `udp_port` is advertised
/// only on channel-neighbor capabilities so gossip peers DHT-PING the
/// Ember UDP socket instead of opening a friend TCP session.
/// `channel_neighbors` are `(channel_id, peer_pubkey)` pairs.
///
/// `Ok` means the classic `/register` POST succeeded — the node is on
/// the server and later heartbeats / courtesy unregister should run.
/// The protocol probe runs *before* that POST, so a probe failure is
/// `Err` with nothing registered (404/405/410/501/426 still fall back
/// to LegacyV3 rather than failing). Intro and pairwise presence are
/// reported on [`RegistrationOutcome`] rather than collapsed into that
/// boolean: lookup does not depend on the intro entry, and a pairwise
/// miss is what actually hides us from the affected friends.
pub async fn register(
    base_url: &str,
    ember_hash: &[u8; 16],
    port: u16,
    udp_port: u16,
    external_ip: Ipv4Addr,
    pubkey: &[u8; 32],
    secret_key: &[u8; 32],
    friend_identities: &[([u8; 16], [u8; 32])],
    channel_neighbors: &[([u8; 16], [u8; 32])],
) -> Result<RegistrationOutcome, String> {
    require_https(base_url)?;
    // Probe *before* the mutating POST. A later `?` on GET /v4/protocol used
    // to return Err after `/register` had already succeeded, so the caller
    // treated a registered node as unregistered and retried the POST every
    // 10s. Failure here now genuinely means we never registered. 404/405/410/
    // 501/426 still map to LegacyV3 inside `negotiate_protocol`.
    let protocol = negotiate_protocol(base_url).await?;
    let url = format!("{}/register", base_url.trim_end_matches('/'));
    let id = hashed_id(ember_hash);
    let id_raw = sha256_id_raw(ember_hash);
    let ts = current_timestamp();
    let signed_ip4 = external_ip.octets();
    let sig = sign_register(secret_key, pubkey, &id_raw, port, signed_ip4, ts);
    let body = serde_json::json!({
        "id": id,
        "port": port,
        "ip": external_ip.to_string(),
        "pubkey": hex::encode(pubkey),
        "ts": ts,
        "sig": hex::encode(sig.to_bytes()),
    });
    let resp = client(base_url)
        .await?
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("rendezvous register failed: {e}"))?;
    if resp.status().is_success() {
        // Don't leak the hashed friend ID or our public IP at `info!` level:
        // user-facing logs should not deanonymize the identity. Keep a terse
        // success message at info and the identifying bits at debug.
        debug!("Rendezvous: registered {}… (ip={})", &id[..8], external_ip);
        let epoch = crate::network::ember::crypto::pairwise_capability_epoch(ts);
        // Friend-code intro presence: public to holders of our ember2: code.
        // Registered before pairwise entries so one-sided Add Friend can find us.
        // Lookup tries intro *and* pairwise and skips 404, so a failed intro
        // only degrades friend-code adds — existing friends still resolve
        // via pairwise. Report it on the outcome; do not fail the register.
        let intro_capability =
            crate::network::ember::crypto::derive_intro_presence_capability(pubkey, epoch);
        let intro_ok = match register_capability_presence(
            base_url,
            &intro_capability,
            epoch,
            port,
            external_ip,
            pubkey,
            pubkey, // self-bound; server marks open_intro
            secret_key,
            protocol,
            true,
        )
        .await
        {
            Ok(()) => true,
            Err(error) => {
                warn!("Intro presence registration failed: {error}");
                false
            }
        };
        // Public presence is never indexed by the stable Friend ID. Register
        // one opaque rotating capability for each friend whose public key is
        // available; old/hash-only relationships simply fail closed until a
        // v2 identity exchange supplies that key.
        let mut pairwise_attempted = 0usize;
        let mut pairwise_failed = 0usize;
        let mut last_pairwise_error: Option<String> = None;
        for (_, friend_pubkey) in friend_identities {
            let Some(capability) =
                crate::network::ember::crypto::derive_pairwise_presence_capability(
                    secret_key,
                    friend_pubkey,
                    pubkey,
                    epoch,
                )
            else {
                continue;
            };
            pairwise_attempted += 1;
            if let Err(error) = register_capability_presence(
                base_url,
                &capability,
                epoch,
                port,
                external_ip,
                pubkey,
                friend_pubkey,
                secret_key,
                protocol,
                false,
            )
            .await
            {
                pairwise_failed += 1;
                last_pairwise_error = Some(error);
            }
        }
        // Channel gossip neighbors resolve over Ember UDP, not the friend
        // TCP listener. Capability `port` is per-entry, so these sit
        // alongside friend slots without changing `/register`.
        if udp_port > 0 {
            for (channel_id, neighbor_pubkey) in channel_neighbors {
                let Some(capability) =
                    crate::network::ember::channel::derive_channel_presence_capability(
                        secret_key,
                        neighbor_pubkey,
                        pubkey,
                        channel_id,
                        epoch,
                    )
                else {
                    continue;
                };
                if let Err(error) = register_capability_presence(
                    base_url,
                    &capability,
                    epoch,
                    udp_port,
                    external_ip,
                    pubkey,
                    neighbor_pubkey,
                    secret_key,
                    protocol,
                    false,
                )
                .await
                {
                    debug!("Channel presence registration failed: {error}");
                }
            }
        }
        if let Some(error) = last_pairwise_error {
            if pairwise_failed == pairwise_attempted {
                warn!(
                    "Rendezvous: all {pairwise_attempted} pairwise presence registration(s) failed (last error: {error})"
                );
            } else {
                warn!(
                    "Rendezvous: {pairwise_failed}/{pairwise_attempted} pairwise presence registration(s) failed (last error: {error})"
                );
            }
        }
        let outcome = RegistrationOutcome {
            intro_ok,
            pairwise_attempted,
            pairwise_failed,
        };
        if outcome.existing_friends_blocked() {
            debug!(
                "Rendezvous: registered on port {port}, but intro and all pairwise presence registrations failed — existing friends cannot resolve us"
            );
        } else if !intro_ok || pairwise_failed > 0 {
            debug!(
                "Rendezvous: registered on port {port} with degraded presence (intro_ok={intro_ok}, pairwise {}/{pairwise_attempted})",
                outcome.pairwise_succeeded()
            );
        } else {
            info!("Rendezvous: registration succeeded on port {port}");
        }
        Ok(outcome)
    } else {
        let status = resp.status();
        Err(format!("rendezvous register returned {status}"))
    }
}

/// Authenticated identity lookup. The unauthenticated GET oracle is gone.
pub(crate) async fn fetch_identity_pubkey_authenticated(
    base_url: &str,
    target_ember_hash: &[u8; 16],
    our_ember_hash: &[u8; 16],
    our_pubkey: &[u8; 32],
    our_secret_key: &[u8; 32],
) -> Result<Option<[u8; 32]>, String> {
    require_https(base_url)?;
    match negotiate_protocol(base_url).await? {
        RendezvousProtocol::LegacyV3 => {
            return fetch_identity_pubkey(base_url, target_ember_hash).await;
        }
        RendezvousProtocol::IpBoundV4 => {}
    }
    let target_id = hashed_id(target_ember_hash);
    let target_raw = sha256_id_raw(target_ember_hash);
    let requester_id = hashed_id(our_ember_hash);
    let requester_raw = sha256_id_raw(our_ember_hash);
    let ts = current_timestamp();
    let nonce = random_nonce();
    let signed = build_identity_lookup_v4_msg(&target_raw, &requester_raw, our_pubkey, &nonce, ts);
    use ed25519_dalek::Signer;
    let sig = signing_key_from_secret(our_secret_key).sign(&signed);
    let resp = client(base_url)
        .await?
        .post(format!(
            "{}/v4/identity/lookup",
            base_url.trim_end_matches('/')
        ))
        .json(&serde_json::json!({
            "target_id": target_id,
            "requester_id": requester_id,
            "requester_pubkey": hex::encode(our_pubkey),
            "nonce": hex::encode(nonce),
            "ts": ts,
            "sig": hex::encode(sig.to_bytes()),
        }))
        .send()
        .await
        .map_err(|e| format!("rendezvous identity lookup failed: {e}"))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!(
            "rendezvous identity lookup returned {}",
            resp.status()
        ));
    }
    let body: serde_json::Value =
        serde_json::from_slice(&read_bounded_bytes(resp, MAX_RESPONSE_BYTES).await?)
            .map_err(|e| format!("rendezvous identity lookup bad body: {e}"))?;
    let mut pubkey = [0u8; 32];
    if hex::decode_to_slice(body["pubkey"].as_str().unwrap_or_default(), &mut pubkey).is_err()
        || !pubkey_matches_id(&pubkey, &target_id)
    {
        return Err("rendezvous identity lookup returned an invalid identity binding".to_string());
    }
    Ok(Some(pubkey))
}

/// Temporary legacy-v3 identity lookup used only after `/v4/protocol`
/// explicitly reports unsupported. Callers must prefer
/// [`fetch_identity_pubkey_authenticated`].
pub(crate) async fn fetch_identity_pubkey(
    base_url: &str,
    ember_hash: &[u8; 16],
) -> Result<Option<[u8; 32]>, String> {
    require_https(base_url)?;
    let id = hashed_id(ember_hash);
    let response = client(base_url)
        .await?
        .get(format!(
            "{}/v3/identity/{id}",
            base_url.trim_end_matches('/')
        ))
        .send()
        .await
        .map_err(|error| format!("legacy rendezvous identity lookup failed: {error}"))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(format!(
            "legacy rendezvous identity lookup returned {}",
            response.status()
        ));
    }
    let body: serde_json::Value =
        serde_json::from_slice(&read_bounded_bytes(response, MAX_RESPONSE_BYTES).await?)
            .map_err(|error| format!("legacy rendezvous identity lookup bad body: {error}"))?;
    let mut pubkey = [0u8; 32];
    if hex::decode_to_slice(body["pubkey"].as_str().unwrap_or_default(), &mut pubkey).is_err()
        || !pubkey_matches_id(&pubkey, &id)
    {
        return Err("legacy rendezvous identity lookup returned invalid binding".to_string());
    }
    Ok(Some(pubkey))
}

async fn register_capability_presence(
    base_url: &str,
    capability: &[u8; 32],
    epoch: i64,
    port: u16,
    external_ip: Ipv4Addr,
    pubkey: &[u8; 32],
    peer_pubkey: &[u8; 32],
    secret_key: &[u8; 32],
    protocol: RendezvousProtocol,
    intro: bool,
) -> Result<(), String> {
    use ed25519_dalek::Signer;
    let ts = current_timestamp();
    let (route, signed, legacy_sig) = match protocol {
        RendezvousProtocol::LegacyV3 => (
            "/v3/presence/register",
            build_capability_register_v3_msg(
                capability,
                epoch,
                port,
                external_ip.octets(),
                pubkey,
                peer_pubkey,
                ts,
            ),
            None,
        ),
        RendezvousProtocol::IpBoundV4 => {
            // Carry the exact legacy proof in the authenticated v4 admission.
            // The server stores both versions atomically while charging one
            // logical registration, so old clients remain compatible without
            // a second rate-limited HTTP mutation.
            let legacy_signed = build_capability_register_v3_msg(
                capability,
                epoch,
                port,
                external_ip.octets(),
                pubkey,
                peer_pubkey,
                ts,
            );
            (
                "/v4/presence/register",
                build_capability_register_v4_msg(
                    capability,
                    epoch,
                    port,
                    &encode_signed_ip(IpAddr::V4(external_ip)),
                    pubkey,
                    peer_pubkey,
                    ts,
                ),
                Some(signing_key_from_secret(secret_key).sign(&legacy_signed)),
            )
        }
    };
    let sig = signing_key_from_secret(secret_key).sign(&signed);
    let mut body = serde_json::json!({
        "capability": hex::encode(capability),
        "epoch": epoch,
        "port": port,
        "ip": external_ip.to_string(),
        "pubkey": hex::encode(pubkey),
        "peer_pubkey": hex::encode(peer_pubkey),
        "ts": ts,
        "sig": hex::encode(sig.to_bytes()),
        "intro": intro,
    });
    if let Some(legacy_sig) = legacy_sig {
        body.as_object_mut()
            .expect("presence body is an object")
            .insert(
                "legacy_sig".to_string(),
                serde_json::Value::String(hex::encode(legacy_sig.to_bytes())),
            );
    }
    let resp = client(base_url)
        .await?
        .post(format!("{}{}", base_url.trim_end_matches('/'), route,))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("pairwise presence register failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "pairwise presence register returned {}",
            resp.status()
        ));
    }
    Ok(())
}

/// Look up a friend on the rendezvous server.
/// Returns `Some((ip, port))` if the friend is currently registered, `None` if not found.
///
/// The response is cryptographically authenticated, not just
/// transport-secured: the server has no signing key of its own, so it
/// can only ever return an (ip, port, pubkey, ts) tuple accompanied by
/// the registrant's own Ed25519 signature over that exact tuple
/// (produced once, at `/register` time, and replayed verbatim by the
/// server on every `/lookup`). We verify the pubkey derives to the id
/// we asked for AND that the signature checks out under that pubkey
/// before trusting the ip/port at all. That closes the hole where a
/// compromised, malicious, or MITM'd rendezvous server could steer a
/// friend-connect session at an arbitrary attacker-controlled host —
/// `require_https` + `https_only(true)` alone only guarantee the
/// response came from the configured host, not that the host told the
/// truth.
///
/// On top of that, and independent of the above: we refuse to hand
/// back addresses that would make the caller connect to loopback /
/// link-local / private / unspecified / reserved IPs — those could
/// steer a friend-connect session into the local host, the LAN, or an
/// attacker-chosen internal network. The rendezvous server is expected
/// to filter these at registration time (see
/// `rendezvous-server/src/main.rs::register`), but mirroring the check
/// on the client side closes the gap if a future server change
/// regresses it.
/// Upper bound on how old a lookup response's signed `ts` may be.
/// Defense-in-depth against a compromised/misbehaving rendezvous
/// server replaying a stale-but-still-validly-signed registration
/// after the real peer has moved or gone offline: the server is
/// already supposed to expire presence entries after `ENTRY_TTL`
/// (300s, see `rendezvous-server/src/main.rs`), so this just mirrors
/// that with headroom for clock skew and in-flight latency rather
/// than trusting the server to enforce it correctly forever.
const MAX_LOOKUP_SIG_AGE_SECS: i64 = 600;

/// Whether a lookup response's signed `ts` is too far from local time to trust.
///
/// `ts` arrives as an unvalidated `i64` from the rendezvous server's JSON, so it
/// spans the full range including `i64::MIN`. `[profile.release]` sets
/// `overflow-checks = true`, so a plain `now - ts` panics in shipped builds on a
/// value a compromised operator or MITM picks — the exact adversary the signature
/// freshness check exists to defend against. Saturating both steps keeps an
/// implausible timestamp a *refusal* instead of an abort.
fn lookup_signature_age_exceeded(now: i64, ts: i64) -> bool {
    now.saturating_sub(ts).saturating_abs() > MAX_LOOKUP_SIG_AGE_SECS
}

pub async fn lookup(
    base_url: &str,
    our_ember_hash: &[u8; 16],
    our_pubkey: &[u8; 32],
    our_secret_key: &[u8; 32],
    friend_hash: &[u8; 16],
) -> Result<Option<(Ipv4Addr, u16)>, String> {
    require_https(base_url)?;
    let Some(friend_pubkey) = fetch_identity_pubkey_authenticated(
        base_url,
        friend_hash,
        our_ember_hash,
        our_pubkey,
        our_secret_key,
    )
    .await?
    else {
        return Ok(None);
    };
    let friend_id = hashed_id(friend_hash);
    let now = current_timestamp();
    let current_epoch = crate::network::ember::crypto::pairwise_capability_epoch(now);

    // Intro first (friend-code holders), then pairwise (mutual DH).
    // For intro proofs the registrant signs peer_pubkey = owner; for
    // pairwise they sign peer_pubkey = the authorized friend (us).
    let mut candidates: Vec<([u8; 32], i64, [u8; 32])> = Vec::with_capacity(4);
    for epoch in [current_epoch, current_epoch - 1] {
        let intro =
            crate::network::ember::crypto::derive_intro_presence_capability(&friend_pubkey, epoch);
        candidates.push((intro, epoch, friend_pubkey));
        if let Some(pairwise) = crate::network::ember::crypto::derive_pairwise_presence_capability(
            our_secret_key,
            &friend_pubkey,
            &friend_pubkey,
            epoch,
        ) {
            candidates.push((pairwise, epoch, *our_pubkey));
        }
    }
    lookup_capability_entries(
        base_url,
        our_ember_hash,
        our_pubkey,
        our_secret_key,
        &friend_pubkey,
        &friend_id,
        candidates,
    )
    .await
}

/// Look up a channel gossip neighbor whose Ed25519 pubkey is already known
/// from a DHT presence record. Skips the friend identity oracle and uses
/// the channel-bound pairwise capability so a room neighbor cannot read
/// a friend presence slot.
pub async fn lookup_channel_presence(
    base_url: &str,
    our_ember_hash: &[u8; 16],
    our_pubkey: &[u8; 32],
    our_secret_key: &[u8; 32],
    peer_pubkey: &[u8; 32],
    channel_id: &[u8; 16],
) -> Result<Option<(Ipv4Addr, u16)>, String> {
    require_https(base_url)?;
    let peer_hash = crate::network::ember::channel::channel_id_from_pubkey(peer_pubkey);
    let peer_id = hashed_id(&peer_hash);
    let now = current_timestamp();
    let current_epoch = crate::network::ember::crypto::pairwise_capability_epoch(now);
    let mut candidates: Vec<([u8; 32], i64, [u8; 32])> = Vec::with_capacity(2);
    for epoch in [current_epoch, current_epoch - 1] {
        if let Some(capability) =
            crate::network::ember::channel::derive_channel_presence_capability(
                our_secret_key,
                peer_pubkey,
                peer_pubkey,
                channel_id,
                epoch,
            )
        {
            candidates.push((capability, epoch, *our_pubkey));
        }
    }
    lookup_capability_entries(
        base_url,
        our_ember_hash,
        our_pubkey,
        our_secret_key,
        peer_pubkey,
        &peer_id,
        candidates,
    )
    .await
}

async fn lookup_capability_entries(
    base_url: &str,
    our_ember_hash: &[u8; 16],
    our_pubkey: &[u8; 32],
    our_secret_key: &[u8; 32],
    expected_pubkey: &[u8; 32],
    expected_id: &str,
    candidates: Vec<([u8; 32], i64, [u8; 32])>,
) -> Result<Option<(Ipv4Addr, u16)>, String> {
    let requester_id = hashed_id(our_ember_hash);
    let requester_raw = sha256_id_raw(our_ember_hash);
    let protocol = negotiate_protocol(base_url).await?;
    let log_id = if expected_id.len() >= 8 {
        &expected_id[..8]
    } else {
        expected_id
    };

    let mut successful: Option<(reqwest::Response, [u8; 32], i64, [u8; 32])> = None;
    for (capability, epoch, proof_peer_pubkey) in candidates {
        let nonce = random_nonce();
        let ts = current_timestamp();
        let (route, signed) = match protocol {
            RendezvousProtocol::LegacyV3 => (
                "/v3/presence/lookup",
                build_capability_lookup_v3_msg(
                    &capability,
                    epoch,
                    &requester_raw,
                    our_pubkey,
                    &nonce,
                    ts,
                ),
            ),
            RendezvousProtocol::IpBoundV4 => (
                "/v4/presence/lookup",
                build_capability_lookup_v4_msg(
                    &capability,
                    epoch,
                    &requester_raw,
                    our_pubkey,
                    &nonce,
                    ts,
                ),
            ),
        };
        use ed25519_dalek::Signer;
        let sig = signing_key_from_secret(our_secret_key).sign(&signed);
        let resp = client(base_url)
            .await?
            .post(format!("{}{}", base_url.trim_end_matches('/'), route,))
            .json(&serde_json::json!({
                "capability": hex::encode(capability),
                "epoch": epoch,
                "requester_id": requester_id,
                "requester_pubkey": hex::encode(our_pubkey),
                "nonce": hex::encode(nonce),
                "ts": ts,
                "sig": hex::encode(sig.to_bytes()),
            }))
            .send()
            .await
            .map_err(|e| format!("pairwise presence lookup failed: {e}"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            continue;
        }
        if !resp.status().is_success() {
            return Err(format!(
                "pairwise presence lookup returned {}",
                resp.status()
            ));
        }
        successful = Some((resp, capability, epoch, proof_peer_pubkey));
        break;
    }
    let Some((resp, capability, epoch, proof_peer_pubkey)) = successful else {
        return Ok(None);
    };
    let bytes = read_bounded_bytes(resp, MAX_RESPONSE_BYTES).await?;
    let body: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("rendezvous lookup bad body: {e}"))?;
    if body["acknowledged"].as_bool() != Some(true)
        || body["capability"].as_str() != Some(hex::encode(capability).as_str())
        || body["epoch"].as_i64() != Some(epoch)
    {
        return Err("pairwise presence lookup acknowledgement mismatch".to_string());
    }
    let ip_str = body["ip"].as_str().unwrap_or_default();
    let raw_port = body["port"].as_u64().unwrap_or_default();
    if raw_port == 0 || raw_port > u16::MAX as u64 {
        debug!(
            "Rendezvous: lookup for {log_id}… returned invalid port: {raw_port}"
        );
        return Ok(None);
    }
    let port = raw_port as u16;

    // Authenticate the response before trusting anything in it. The
    // rendezvous server itself holds no long-term signing key we can
    // pin — instead, the response must carry the registrant's OWN
    // Ed25519 signature (produced at `/register` time and replayed
    // verbatim by the server) over exactly this (id, port, ip,
    // pubkey, ts) tuple. Two checks, both required:
    //   1. `pubkey` must derive to the `id` we asked for (one-way
    //      hash chain — see `pubkey_matches_id`), so a malicious or
    //      compromised server can't substitute a different keypair
    //      it controls.
    //   2. The signature over the reconstructed message must verify
    //      under that pubkey, so the server can't substitute a
    //      different ip/port/ts for the real registrant's pubkey
    //      without the registrant's private key.
    // Without this, a compromised/malicious rendezvous operator (or
    // a MITM that somehow defeats `https_only`) could steer a friend
    // connection at an arbitrary attacker-controlled host — the
    // routability filter below only blocks *local-network* targets,
    // not arbitrary internet hosts.
    let pubkey_hex = body["pubkey"].as_str().unwrap_or_default();
    let sig_hex = body["sig"].as_str().unwrap_or_default();
    let ts = body["ts"].as_i64().unwrap_or_default();

    let mut pubkey = [0u8; 32];
    let mut sig = [0u8; 64];
    let pubkey_ok = hex::decode_to_slice(pubkey_hex, &mut pubkey).is_ok();
    let sig_ok = hex::decode_to_slice(sig_hex, &mut sig).is_ok();
    if !pubkey_ok || !sig_ok {
        warn!(
            "Rendezvous: lookup for {log_id}… missing/malformed auth fields; refusing to connect"
        );
        return Ok(None);
    }
    if pubkey != *expected_pubkey || !pubkey_matches_id(&pubkey, expected_id) {
        warn!(
            "Rendezvous: lookup for {log_id}… pubkey does not derive to requested id; refusing to connect (server may be compromised)"
        );
        return Ok(None);
    }
    let now = current_timestamp();
    if lookup_signature_age_exceeded(now, ts) {
        warn!(
            "Rendezvous: lookup for {log_id}… returned a stale signed registration (ts={ts}); refusing to connect"
        );
        return Ok(None);
    }

    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
        let proof_version = body["proof_version"]
            .as_u64()
            .and_then(|value| u8::try_from(value).ok())
            .unwrap_or(match protocol {
                RendezvousProtocol::LegacyV3 => 3,
                RendezvousProtocol::IpBoundV4 => 0,
            });
        let msg = match proof_version {
            3 => build_capability_register_v3_msg(
                &capability,
                epoch,
                port,
                ip.octets(),
                &pubkey,
                &proof_peer_pubkey,
                ts,
            ),
            4 => build_capability_register_v4_msg(
                &capability,
                epoch,
                port,
                &encode_signed_ip(IpAddr::V4(ip)),
                &pubkey,
                &proof_peer_pubkey,
                ts,
            ),
            _ => {
                warn!("Rendezvous: lookup for {log_id}… returned unknown proof version");
                return Ok(None);
            }
        };
        if !ed25519_verify_lookup(&pubkey, &msg, &sig) {
            warn!(
                "Rendezvous: lookup for {log_id}… signature verification failed; refusing to connect (server may be compromised)"
            );
            return Ok(None);
        }
        if port > 0 && is_routable_public_v4(ip) {
            // Friend IP/port is effectively PII — keep it at debug rather than
            // info so it doesn't land in user-shared log bundles by default.
            debug!("Rendezvous: presence found for {log_id}… at {ip}:{port}");
            return Ok(Some((ip, port)));
        }
        if port > 0 {
            warn!(
                "Rendezvous: lookup for {log_id}… returned non-public IP ({ip}); refusing to connect"
            );
            return Ok(None);
        }
    }
    debug!("Rendezvous: lookup for {log_id}… returned unparseable data");
    Ok(None)
}

/// Returns true only for IPv4 addresses that are safe to dial as a
/// remote peer: not unspecified, not loopback, not multicast, not
/// broadcast, not link-local, not private (RFC 1918 / CGN), not
/// documentation/benchmark/reserved ranges. Mirrors (and intentionally
/// duplicates, for locality) the server-side filter in
/// `rendezvous-server/src/main.rs::register`.
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

#[cfg(test)]
mod registration_outcome_tests {
    use super::RegistrationOutcome;

    fn outcome(intro_ok: bool, attempted: usize, failed: usize) -> RegistrationOutcome {
        RegistrationOutcome {
            intro_ok,
            pairwise_attempted: attempted,
            pairwise_failed: failed,
        }
    }

    #[test]
    fn intro_only_failure_does_not_block_existing_friends() {
        assert!(!outcome(false, 3, 0).existing_friends_blocked());
        assert!(!outcome(false, 0, 0).existing_friends_blocked());
        assert_eq!(
            outcome(false, 3, 0).degraded_reason(),
            Some("intro_presence_failed")
        );
    }

    #[test]
    fn total_pairwise_failure_blocks_only_when_intro_also_missed() {
        assert!(outcome(false, 4, 4).existing_friends_blocked());
        assert!(!outcome(true, 4, 4).existing_friends_blocked());
        assert_eq!(
            outcome(false, 4, 4).degraded_reason(),
            Some("presence_registration_failed")
        );
        assert_eq!(
            outcome(true, 4, 4).degraded_reason(),
            Some("pairwise_presence_failed")
        );
    }

    #[test]
    fn partial_pairwise_failure_is_degraded_not_blocked() {
        let o = outcome(false, 5, 2);
        assert!(!o.existing_friends_blocked());
        assert_eq!(o.pairwise_succeeded(), 3);
        assert_eq!(o.degraded_reason(), Some("presence_partial"));
    }
}

#[cfg(test)]
mod lookup_filter_tests {
    use super::*;

    #[test]
    fn rejects_unspecified_loopback_private() {
        assert!(!is_routable_public_v4(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(!is_routable_public_v4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_routable_public_v4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_routable_public_v4(Ipv4Addr::new(172, 16, 1, 1)));
        assert!(!is_routable_public_v4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_routable_public_v4(Ipv4Addr::new(169, 254, 1, 1)));
        assert!(!is_routable_public_v4(Ipv4Addr::new(255, 255, 255, 255)));
        assert!(!is_routable_public_v4(Ipv4Addr::new(224, 0, 0, 1)));
        // Docs: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        assert!(!is_routable_public_v4(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!is_routable_public_v4(Ipv4Addr::new(198, 51, 100, 1)));
        assert!(!is_routable_public_v4(Ipv4Addr::new(203, 0, 113, 1)));
        // CGN, benchmark, reserved
        assert!(!is_routable_public_v4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(!is_routable_public_v4(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(!is_routable_public_v4(Ipv4Addr::new(240, 0, 0, 1)));
    }

    #[test]
    fn accepts_real_public_ips() {
        assert!(is_routable_public_v4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(is_routable_public_v4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(is_routable_public_v4(Ipv4Addr::new(93, 184, 216, 34)));
    }

    /// `ts` is unvalidated server-supplied JSON, so the extremes of `i64` are
    /// reachable input. With `overflow-checks = true` on release builds a plain
    /// subtraction aborts the process instead of refusing the lookup.
    #[test]
    fn extreme_signed_timestamps_are_refused_not_panicked_on() {
        let now = current_timestamp();
        assert!(lookup_signature_age_exceeded(now, i64::MIN));
        assert!(lookup_signature_age_exceeded(now, i64::MAX));
        // A far-future `ts` must be refused too, not treated as fresh.
        assert!(lookup_signature_age_exceeded(
            now,
            now.saturating_add(MAX_LOOKUP_SIG_AGE_SECS + 1)
        ));
        assert!(lookup_signature_age_exceeded(
            now,
            now.saturating_sub(MAX_LOOKUP_SIG_AGE_SECS + 1)
        ));
    }

    #[test]
    fn fresh_signed_timestamps_are_accepted() {
        let now = current_timestamp();
        assert!(!lookup_signature_age_exceeded(now, now));
        assert!(!lookup_signature_age_exceeded(now, now - 60));
        assert!(!lookup_signature_age_exceeded(
            now,
            now - MAX_LOOKUP_SIG_AGE_SECS
        ));
    }

    #[test]
    fn channel_neighbor_id_matches_rendezvous_pubkey_binding() {
        let sk = SigningKey::from_bytes(&[7; 32]);
        let pk = sk.verifying_key().to_bytes();
        let node_id = crate::network::ember::channel::channel_id_from_pubkey(&pk);
        assert!(pubkey_matches_id(&pk, &hashed_id(&node_id)));
    }

    #[test]
    fn relay_mailbox_poll_contains_only_self_identity() {
        let self_id = [0x11; 32];
        let nonce = [0x22; 16];
        let message = build_relay_mailbox_poll_msg(&self_id, &nonce, 7);
        assert_eq!(message.len(), RDV_DOMAIN.len() + 1 + 32 + 16 + 8);
        assert_eq!(
            &message[RDV_DOMAIN.len() + 1..RDV_DOMAIN.len() + 1 + 32],
            &self_id
        );
        let friend_canary = [0xAB; 32];
        assert!(!message
            .windows(friend_canary.len())
            .any(|window| window == friend_canary));
    }

    #[test]
    fn relay_mailbox_envelope_is_recipient_bound_and_tamper_evident() {
        let alice = SigningKey::from_bytes(&[7; 32]);
        let bob = SigningKey::from_bytes(&[9; 32]);
        let alice_pub = alice.verifying_key().to_bytes();
        let bob_pub = bob.verifying_key().to_bytes();
        let alice_hash =
            crate::network::ember::crypto::node_id_from_public_key(&alice.verifying_key());
        let bob_hash = crate::network::ember::crypto::node_id_from_public_key(&bob.verifying_key());
        let epoch = 5;
        let capability = crate::network::ember::crypto::derive_pairwise_presence_capability(
            &alice.to_bytes(),
            &bob_pub,
            &bob_pub,
            epoch,
        )
        .unwrap();
        let ticket_id = "55".repeat(32);
        let envelope = encrypt_relay_mailbox_envelope(
            &alice_hash,
            &alice_pub,
            &bob_hash,
            &bob_pub,
            &capability,
            epoch,
            &ticket_id,
            &alice.to_bytes(),
            "friend",
            None,
        )
        .unwrap();
        let (initiator, channel_id) = decrypt_relay_mailbox_envelope(
            &bob_hash,
            &bob.to_bytes(),
            &capability,
            &ticket_id,
            &envelope,
        )
        .unwrap();
        assert_eq!(initiator, hashed_id(&alice_hash));
        assert_eq!(channel_id, None);
        let mut tampered = envelope;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(decrypt_relay_mailbox_envelope(
            &bob_hash,
            &bob.to_bytes(),
            &capability,
            &ticket_id,
            &tampered,
        )
        .is_err());
    }
}

/// Unregister our presence from the rendezvous server (graceful shutdown).
///
/// `secret_key` signs an unregister request so the server can verify
/// the call came from the same identity that registered. Mirrors the
/// `register` signing scheme — the server pins pubkey on register,
/// then re-checks on every state-mutating request for that id.
pub async fn unregister(
    base_url: &str,
    ember_hash: &[u8; 16],
    secret_key: &[u8; 32],
) -> Result<(), String> {
    require_https(base_url)?;
    let url = format!("{}/unregister", base_url.trim_end_matches('/'));
    let id = hashed_id(ember_hash);
    let id_raw = sha256_id_raw(ember_hash);
    let ts = current_timestamp();
    let sig = sign_unregister(secret_key, &id_raw, ts);
    let resp = client(base_url)
        .await?
        .delete(&url)
        .json(&serde_json::json!({
            "id": id,
            "ts": ts,
            "sig": hex::encode(sig.to_bytes()),
        }))
        .send()
        .await
        .map_err(|e| format!("rendezvous unregister failed: {e}"))?;
    if resp.status().is_success() || resp.status() == reqwest::StatusCode::NOT_FOUND {
        debug!("Rendezvous: unregistered {}…", &id[..8]);
        Ok(())
    } else {
        let status = resp.status();
        Err(format!("rendezvous unregister returned {status}"))
    }
}

/// Capability granted to the identity that offered a friend relay ticket.
/// Keep the token out of logs: it authorizes exactly one WebSocket join.
pub struct FriendRelayTicketOffer {
    pub ticket_id: String,
    pub initiator_token: String,
}

/// An unaccepted friend or channel relay ticket visible only to its signed responder.
pub struct PendingFriendRelayTicket {
    pub ticket_id: String,
    pub initiator_id: String,
    /// Set when the mailbox envelope is a channel-capability offer. Friend
    /// tickets keep this `None` and still require `friend_hashes` admission.
    pub channel_id: Option<[u8; 16]>,
}

/// One bounded page of authenticated self-mailbox offers.
pub struct FriendRelayTicketPollPage {
    pub tickets: Vec<PendingFriendRelayTicket>,
}

fn relay_mailbox_aad(responder_raw: &[u8; 32], capability: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RDV_DOMAIN.len() + 32 + 32);
    aad.extend_from_slice(RDV_DOMAIN);
    aad.extend_from_slice(responder_raw);
    aad.extend_from_slice(capability);
    aad
}

fn encrypt_relay_mailbox_envelope(
    initiator_ember_hash: &[u8; 16],
    initiator_pubkey: &[u8; 32],
    responder_ember_hash: &[u8; 16],
    responder_pubkey: &[u8; 32],
    capability: &[u8; 32],
    epoch: i64,
    ticket_id: &str,
    secret_key: &[u8; 32],
    purpose: &str,
    channel_id: Option<&[u8; 16]>,
) -> Result<Vec<u8>, String> {
    let key = crate::network::ember::crypto::derive_pairwise_capability(
        secret_key,
        responder_pubkey,
        b"relay-mailbox",
        epoch,
    )
    .ok_or_else(|| "could not derive responder mailbox key".to_string())?;
    let mut body = serde_json::json!({
        "initiator_id": hashed_id(initiator_ember_hash),
        "initiator_pubkey": hex::encode(initiator_pubkey),
        "ticket_id": ticket_id,
        "purpose": purpose,
        "epoch": epoch,
    });
    if let Some(channel_id) = channel_id {
        body["channel_id"] = serde_json::Value::String(hex::encode(channel_id));
    }
    let plaintext = serde_json::to_vec(&body)
        .map_err(|e| format!("could not serialize relay mailbox offer: {e}"))?;
    let responder_raw = sha256_id_raw(responder_ember_hash);
    let aad = relay_mailbox_aad(&responder_raw, capability);
    let mut nonce = [0u8; RELAY_MAILBOX_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(&key));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| "could not encrypt relay mailbox offer".to_string())?;
    let mut envelope = Vec::with_capacity(1 + 8 + 32 + RELAY_MAILBOX_NONCE_LEN + ciphertext.len());
    envelope.push(RELAY_MAILBOX_ENVELOPE_VERSION);
    envelope.extend_from_slice(&epoch.to_le_bytes());
    envelope.extend_from_slice(initiator_pubkey);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn decrypt_relay_mailbox_envelope(
    responder_ember_hash: &[u8; 16],
    responder_secret_key: &[u8; 32],
    capability: &[u8; 32],
    expected_ticket_id: &str,
    envelope: &[u8],
) -> Result<(String, Option<[u8; 16]>), String> {
    const HEADER: usize = 1 + 8 + 32 + RELAY_MAILBOX_NONCE_LEN;
    if envelope.len() < HEADER + 16 || envelope[0] != RELAY_MAILBOX_ENVELOPE_VERSION {
        return Err("invalid relay mailbox envelope".to_string());
    }
    let epoch = i64::from_le_bytes(
        envelope[1..9]
            .try_into()
            .map_err(|_| "invalid relay mailbox epoch")?,
    );
    let sender_pubkey: [u8; 32] = envelope[9..41]
        .try_into()
        .map_err(|_| "invalid relay mailbox sender key")?;
    let key = crate::network::ember::crypto::derive_pairwise_capability(
        responder_secret_key,
        &sender_pubkey,
        b"relay-mailbox",
        epoch,
    )
    .ok_or_else(|| "could not derive relay mailbox key".to_string())?;
    let responder_pubkey = signing_key_from_secret(responder_secret_key)
        .verifying_key()
        .to_bytes();
    let aad = relay_mailbox_aad(&sha256_id_raw(responder_ember_hash), capability);
    let plaintext = XChaCha20Poly1305::new(ChaChaKey::from_slice(&key))
        .decrypt(
            XNonce::from_slice(&envelope[41..HEADER]),
            Payload {
                msg: &envelope[HEADER..],
                aad: &aad,
            },
        )
        .map_err(|_| "relay mailbox authentication failed".to_string())?;
    let body: serde_json::Value = serde_json::from_slice(&plaintext)
        .map_err(|_| "invalid relay mailbox plaintext".to_string())?;
    let initiator_id = body["initiator_id"].as_str().unwrap_or_default();
    if body["epoch"].as_i64() != Some(epoch)
        || body["ticket_id"].as_str() != Some(expected_ticket_id)
        || body["initiator_pubkey"].as_str() != Some(hex::encode(sender_pubkey).as_str())
        || !pubkey_matches_id(&sender_pubkey, initiator_id)
    {
        return Err("relay mailbox signed context mismatch".to_string());
    }
    let purpose = body["purpose"].as_str().unwrap_or_default();
    let channel_id = match purpose {
        "friend" => {
            let expected = crate::network::ember::crypto::derive_pairwise_presence_capability(
                responder_secret_key,
                &sender_pubkey,
                &responder_pubkey,
                epoch,
            )
            .ok_or_else(|| "could not derive relay mailbox capability".to_string())?;
            if expected != *capability {
                return Err("relay mailbox capability mismatch".to_string());
            }
            None
        }
        "channel" => {
            let mut channel_id = [0u8; 16];
            hex::decode_to_slice(body["channel_id"].as_str().unwrap_or_default(), &mut channel_id)
                .map_err(|_| "invalid channel relay mailbox id".to_string())?;
            let expected = crate::network::ember::channel::derive_channel_presence_capability(
                responder_secret_key,
                &sender_pubkey,
                &responder_pubkey,
                &channel_id,
                epoch,
            )
            .ok_or_else(|| "could not derive channel relay mailbox capability".to_string())?;
            if expected != *capability {
                return Err("relay mailbox capability mismatch".to_string());
            }
            Some(channel_id)
        }
        _ => return Err("relay mailbox signed context mismatch".to_string()),
    };
    Ok((initiator_id.to_owned(), channel_id))
}

fn sign_relay_ticket_message(secret: &[u8; 32], message: &[u8]) -> Signature {
    use ed25519_dalek::Signer;
    signing_key_from_secret(secret).sign(message)
}

fn ticket_id_raw(ticket_id: &str) -> Result<[u8; 32], String> {
    let mut raw = [0u8; 32];
    if !valid_ticket_secret(ticket_id) || hex::decode_to_slice(ticket_id, &mut raw).is_err() {
        return Err("invalid rendezvous relay ticket id".to_string());
    }
    Ok(raw)
}

/// A ticket is binary data encoded as hex. Normalize its textual form before
/// using it in a signed URL path or carrying it into relay admission, so
/// uppercase and lowercase spellings cannot diverge from server token
/// derivation.
fn canonical_ticket_id(ticket_id: &str) -> Result<String, String> {
    ticket_id_raw(ticket_id)?;
    Ok(ticket_id.to_ascii_lowercase())
}

/// Offer a relay only for the fixed `friend` purpose. The server binds both
/// registered identities and returns the initiator's one-time join token.
pub async fn offer_friend_relay_ticket(
    base_url: &str,
    initiator_ember_hash: &[u8; 16],
    responder_ember_hash: &[u8; 16],
    initiator_pubkey: &[u8; 32],
    secret_key: &[u8; 32],
) -> Result<FriendRelayTicketOffer, String> {
    require_https(base_url)?;
    let initiator_id = hashed_id(initiator_ember_hash);
    let responder_id = hashed_id(responder_ember_hash);
    let initiator_raw = sha256_id_raw(initiator_ember_hash);
    let responder_raw = sha256_id_raw(responder_ember_hash);
    let responder_pubkey = fetch_identity_pubkey_authenticated(
        base_url,
        responder_ember_hash,
        initiator_ember_hash,
        initiator_pubkey,
        secret_key,
    )
    .await?
    .ok_or_else(|| "relay responder has no registered v2 identity".to_string())?;
    let ts = current_timestamp();
    let epoch = crate::network::ember::crypto::pairwise_capability_epoch(ts);
    let capability = crate::network::ember::crypto::derive_pairwise_presence_capability(
        secret_key,
        &responder_pubkey,
        &responder_pubkey,
        epoch,
    )
    .ok_or_else(|| "could not derive relay responder capability".to_string())?;
    let mut ticket_raw = [0u8; 32];
    OsRng.fill_bytes(&mut ticket_raw);
    let ticket_id = hex::encode(ticket_raw);
    let envelope = encrypt_relay_mailbox_envelope(
        initiator_ember_hash,
        initiator_pubkey,
        responder_ember_hash,
        &responder_pubkey,
        &capability,
        epoch,
        &ticket_id,
        secret_key,
        "friend",
        None,
    )?;
    let nonce = random_nonce();
    let signed = build_relay_mailbox_offer_msg(
        &initiator_raw,
        &responder_raw,
        &capability,
        epoch,
        &ticket_raw,
        &envelope,
        &nonce,
        ts,
    );
    let sig = sign_relay_ticket_message(secret_key, &signed);
    let url = format!("{}/v4/relay-mailbox/offer", base_url.trim_end_matches('/'));
    let resp = client(base_url)
        .await?
        .post(&url)
        .json(&serde_json::json!({
            "initiator_id": initiator_id,
            "responder_id": responder_id,
            "capability": hex::encode(capability),
            "epoch": epoch,
            "ticket_id": ticket_id,
            "envelope": hex::encode(envelope),
            "ts": ts,
            "nonce": hex::encode(nonce),
            "sig": hex::encode(sig.to_bytes()),
        }))
        .send()
        .await
        .map_err(|e| format!("relay ticket offer: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("relay ticket offer: status {}", resp.status()));
    }
    let body: serde_json::Value =
        serde_json::from_slice(&read_bounded_bytes(resp, MAX_RESPONSE_BYTES).await?)
            .map_err(|e| format!("relay ticket offer bad body: {e}"))?;
    let returned_ticket_id = canonical_ticket_id(body["ticket_id"].as_str().unwrap_or_default())?;
    if returned_ticket_id != ticket_id {
        return Err("relay ticket offer acknowledgement mismatch".to_string());
    }
    let initiator_token = body["initiator_token"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    validate_ticket_response_field(&ticket_id, "ticket_id")?;
    validate_ticket_response_field(&initiator_token, "initiator_token")?;
    Ok(FriendRelayTicketOffer {
        ticket_id,
        initiator_token,
    })
}

/// Offer a rendezvous WebSocket relay bound to a channel presence capability.
/// Never uses the friend pairwise capability or `friend_hashes`.
pub async fn offer_channel_relay_ticket(
    base_url: &str,
    initiator_ember_hash: &[u8; 16],
    responder_ember_hash: &[u8; 16],
    initiator_pubkey: &[u8; 32],
    secret_key: &[u8; 32],
    channel_id: &[u8; 16],
) -> Result<FriendRelayTicketOffer, String> {
    require_https(base_url)?;
    let initiator_id = hashed_id(initiator_ember_hash);
    let responder_id = hashed_id(responder_ember_hash);
    let initiator_raw = sha256_id_raw(initiator_ember_hash);
    let responder_raw = sha256_id_raw(responder_ember_hash);
    let responder_pubkey = fetch_identity_pubkey_authenticated(
        base_url,
        responder_ember_hash,
        initiator_ember_hash,
        initiator_pubkey,
        secret_key,
    )
    .await?
    .ok_or_else(|| "relay responder has no registered v2 identity".to_string())?;
    let ts = current_timestamp();
    let epoch = crate::network::ember::crypto::pairwise_capability_epoch(ts);
    let capability = crate::network::ember::channel::derive_channel_presence_capability(
        secret_key,
        &responder_pubkey,
        &responder_pubkey,
        channel_id,
        epoch,
    )
    .ok_or_else(|| "could not derive channel relay responder capability".to_string())?;
    let mut ticket_raw = [0u8; 32];
    OsRng.fill_bytes(&mut ticket_raw);
    let ticket_id = hex::encode(ticket_raw);
    let envelope = encrypt_relay_mailbox_envelope(
        initiator_ember_hash,
        initiator_pubkey,
        responder_ember_hash,
        &responder_pubkey,
        &capability,
        epoch,
        &ticket_id,
        secret_key,
        "channel",
        Some(channel_id),
    )?;
    let nonce = random_nonce();
    let signed = build_relay_mailbox_offer_msg(
        &initiator_raw,
        &responder_raw,
        &capability,
        epoch,
        &ticket_raw,
        &envelope,
        &nonce,
        ts,
    );
    let sig = sign_relay_ticket_message(secret_key, &signed);
    let url = format!("{}/v4/relay-mailbox/offer", base_url.trim_end_matches('/'));
    let resp = client(base_url)
        .await?
        .post(&url)
        .json(&serde_json::json!({
            "initiator_id": initiator_id,
            "responder_id": responder_id,
            "capability": hex::encode(capability),
            "epoch": epoch,
            "ticket_id": ticket_id,
            "envelope": hex::encode(envelope),
            "ts": ts,
            "nonce": hex::encode(nonce),
            "sig": hex::encode(sig.to_bytes()),
        }))
        .send()
        .await
        .map_err(|e| format!("channel relay ticket offer: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "channel relay ticket offer: status {}",
            resp.status()
        ));
    }
    let body: serde_json::Value =
        serde_json::from_slice(&read_bounded_bytes(resp, MAX_RESPONSE_BYTES).await?)
            .map_err(|e| format!("channel relay ticket offer bad body: {e}"))?;
    let returned_ticket_id = canonical_ticket_id(body["ticket_id"].as_str().unwrap_or_default())?;
    if returned_ticket_id != ticket_id {
        return Err("channel relay ticket offer acknowledgement mismatch".to_string());
    }
    let initiator_token = body["initiator_token"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    validate_ticket_response_field(&ticket_id, "ticket_id")?;
    validate_ticket_response_field(&initiator_token, "initiator_token")?;
    Ok(FriendRelayTicketOffer {
        ticket_id,
        initiator_token,
    })
}

/// Poll tickets addressed to this registered identity. The server never
/// returns a responder bearer token here; the client must explicitly accept a
/// known friend's offer first. The request contains only the responder's own
/// mailbox ID; sender identity and purpose remain inside the authenticated
/// encrypted envelope and are filtered locally.
pub async fn poll_friend_relay_tickets(
    base_url: &str,
    responder_ember_hash: &[u8; 16],
    secret_key: &[u8; 32],
) -> Result<FriendRelayTicketPollPage, String> {
    require_https(base_url)?;
    let responder_id = hashed_id(responder_ember_hash);
    let responder_raw = sha256_id_raw(responder_ember_hash);
    // Keep (nonce, ts) stable across a single logical poll attempt so a lost
    // HTTP response can be retried as an Idempotent read of the same mailbox
    // page instead of advancing the server cursor again.
    let ts = current_timestamp();
    let mut nonce_scope = Vec::with_capacity(b"poll".len() + responder_raw.len());
    nonce_scope.extend_from_slice(b"mailbox-v4");
    nonce_scope.extend_from_slice(&responder_raw);
    let nonce = stable_relay_ticket_read_nonce(secret_key, &nonce_scope);
    let signed = build_relay_mailbox_poll_msg(&responder_raw, &nonce, ts);
    let sig = sign_relay_ticket_message(secret_key, &signed);
    let url = format!("{}/v4/relay-mailbox/poll", base_url.trim_end_matches('/'));
    let body = serde_json::json!({
        "responder_id": responder_id,
        "ts": ts,
        "nonce": hex::encode(nonce),
        "sig": hex::encode(sig.to_bytes()),
    });

    let mut last_error = None;
    for attempt in 0..2 {
        match tokio::time::timeout(std::time::Duration::from_secs(1), async {
            let resp = client(base_url)
                .await?
                .post(&url)
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("relay ticket poll: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("relay ticket poll: status {}", resp.status()));
            }
            parse_friend_relay_mailbox_response(resp, responder_ember_hash, secret_key).await
        })
        .await
        {
            Ok(Ok(page)) => return Ok(page),
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => last_error = Some("friend relay mailbox poll timed out".to_string()),
        }
        if attempt == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
    Err(last_error.unwrap_or_else(|| "relay ticket poll failed".to_string()))
}

async fn parse_friend_relay_mailbox_response(
    resp: reqwest::Response,
    responder_ember_hash: &[u8; 16],
    secret_key: &[u8; 32],
) -> Result<FriendRelayTicketPollPage, String> {
    let body: serde_json::Value =
        serde_json::from_slice(&read_bounded_bytes(resp, MAX_RESPONSE_BYTES).await?)
            .map_err(|e| format!("relay mailbox poll bad body: {e}"))?;
    let items = body["tickets"]
        .as_array()
        .ok_or_else(|| "relay mailbox poll missing tickets".to_string())?;
    let mut tickets = Vec::with_capacity(items.len());
    for item in items {
        let ticket_id = canonical_ticket_id(item["ticket_id"].as_str().unwrap_or_default())?;
        let mut capability = [0u8; 32];
        if hex::decode_to_slice(
            item["capability"].as_str().unwrap_or_default(),
            &mut capability,
        )
        .is_err()
        {
            continue;
        }
        let envelope = match hex::decode(item["envelope"].as_str().unwrap_or_default()) {
            Ok(envelope) => envelope,
            Err(_) => continue,
        };
        match decrypt_relay_mailbox_envelope(
            responder_ember_hash,
            secret_key,
            &capability,
            &ticket_id,
            &envelope,
        ) {
            Ok((id, channel_id)) => {
                tickets.push(PendingFriendRelayTicket {
                    ticket_id,
                    initiator_id: id,
                    channel_id,
                });
                continue;
            }
            Err(error) => {
                debug!("Ignoring unauthenticated relay mailbox item: {error}");
                continue;
            }
        };
    }
    Ok(FriendRelayTicketPollPage { tickets })
}

/// Accept a ticket after the caller has verified its initiator is a known
/// friend. This is the only endpoint that returns the responder role token.
pub async fn accept_friend_relay_ticket(
    base_url: &str,
    responder_ember_hash: &[u8; 16],
    ticket_id: &str,
    secret_key: &[u8; 32],
) -> Result<String, String> {
    require_https(base_url)?;
    let identity_id = hashed_id(responder_ember_hash);
    let identity_raw = sha256_id_raw(responder_ember_hash);
    let ticket_id = canonical_ticket_id(ticket_id)?;
    let ticket_raw = ticket_id_raw(&ticket_id)?;
    let ts = current_timestamp();
    let nonce = random_nonce();
    let signed = build_relay_ticket_action_msg(
        OP_RELAY_TICKET_ACCEPT,
        &identity_raw,
        &ticket_raw,
        &nonce,
        ts,
    );
    let sig = sign_relay_ticket_message(secret_key, &signed);
    let url = format!(
        "{}/v2/relay-tickets/{ticket_id}/accept",
        base_url.trim_end_matches('/')
    );
    let resp = client(base_url)
        .await?
        .post(&url)
        .json(&serde_json::json!({
            "identity_id": identity_id,
            "ts": ts,
            "nonce": hex::encode(nonce),
            "sig": hex::encode(sig.to_bytes()),
        }))
        .send()
        .await
        .map_err(|e| format!("relay ticket accept: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("relay ticket accept: status {}", resp.status()));
    }
    let body: serde_json::Value =
        serde_json::from_slice(&read_bounded_bytes(resp, MAX_RESPONSE_BYTES).await?)
            .map_err(|e| format!("relay ticket accept bad body: {e}"))?;
    let token = body["responder_token"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    validate_ticket_response_field(&token, "responder_token")?;
    Ok(token)
}

/// Read the offer state as its signed initiator. A client must wait for
/// `accepted` before using its one-time initiator token.
pub async fn friend_relay_ticket_accepted(
    base_url: &str,
    initiator_ember_hash: &[u8; 16],
    ticket_id: &str,
    secret_key: &[u8; 32],
) -> Result<bool, String> {
    require_https(base_url)?;
    let identity_id = hashed_id(initiator_ember_hash);
    let identity_raw = sha256_id_raw(initiator_ember_hash);
    let ticket_id = canonical_ticket_id(ticket_id)?;
    let ticket_raw = ticket_id_raw(&ticket_id)?;
    let ts = current_timestamp();
    let mut nonce_scope = Vec::with_capacity(b"status".len() + ticket_raw.len());
    nonce_scope.extend_from_slice(b"status");
    nonce_scope.extend_from_slice(&ticket_raw);
    let nonce = stable_relay_ticket_read_nonce(secret_key, &nonce_scope);
    let signed = build_relay_ticket_action_msg(
        OP_RELAY_TICKET_STATUS,
        &identity_raw,
        &ticket_raw,
        &nonce,
        ts,
    );
    let sig = sign_relay_ticket_message(secret_key, &signed);
    let url = format!(
        "{}/v2/relay-tickets/{ticket_id}/status",
        base_url.trim_end_matches('/')
    );
    let resp = client(base_url)
        .await?
        .post(&url)
        .json(&serde_json::json!({
            "identity_id": identity_id,
            "ts": ts,
            "nonce": hex::encode(nonce),
            "sig": hex::encode(sig.to_bytes()),
        }))
        .send()
        .await
        .map_err(|e| format!("relay ticket status: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("relay ticket status: status {}", resp.status()));
    }
    let body: serde_json::Value =
        serde_json::from_slice(&read_bounded_bytes(resp, MAX_RESPONSE_BYTES).await?)
            .map_err(|e| format!("relay ticket status bad body: {e}"))?;
    match body["status"].as_str() {
        Some("accepted") => Ok(true),
        Some("offered") => Ok(false),
        _ => Err("relay ticket status response is invalid".to_string()),
    }
}

#[cfg(test)]
mod relay_ticket_tests {
    use super::*;

    #[test]
    fn current_privacy_operation_codes_are_stable() {
        assert_eq!(OP_RELAY_TICKET_ACCEPT, 0x09);
        assert_eq!(OP_RELAY_TICKET_STATUS, 0x0a);
        assert_eq!(OP_CAPABILITY_REGISTER, 0x0c);
        assert_eq!(OP_CAPABILITY_LOOKUP, 0x0d);
        assert_eq!(OP_RELAY_MAILBOX_OFFER, 0x0e);
        assert_eq!(OP_RELAY_MAILBOX_POLL, 0x0f);
        assert_eq!(OP_IDENTITY_LOOKUP_V4, 0x20);
        assert_eq!(OP_CAPABILITY_REGISTER_V4, 0x21);
        assert_eq!(OP_CAPABILITY_LOOKUP_V4, 0x22);
    }

    #[test]
    fn signed_ip_encoding_prefixes_family_tag() {
        let v4 = encode_signed_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));
        assert_eq!(v4, vec![SIGNED_IP_V4, 203, 0, 113, 10]);
    }

    #[test]
    fn legacy_and_v4_presence_payload_vectors_are_unambiguous() {
        let capability = [1; 32];
        let pubkey = [2; 32];
        let peer = [3; 32];
        let legacy =
            build_capability_register_v3_msg(&capability, 7, 4662, [8, 8, 4, 4], &pubkey, &peer, 9);
        let v4 = build_capability_register_v4_msg(
            &capability,
            7,
            4662,
            &[SIGNED_IP_V4, 8, 8, 4, 4],
            &pubkey,
            &peer,
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
    fn new_client_falls_back_only_for_explicit_unsupported_version() {
        for status in [
            reqwest::StatusCode::NOT_FOUND,
            reqwest::StatusCode::METHOD_NOT_ALLOWED,
            reqwest::StatusCode::GONE,
            reqwest::StatusCode::NOT_IMPLEMENTED,
            reqwest::StatusCode::UPGRADE_REQUIRED,
        ] {
            assert!(explicit_version_unsupported(status));
        }
        assert!(!explicit_version_unsupported(
            reqwest::StatusCode::FORBIDDEN
        ));
        assert!(!explicit_version_unsupported(
            reqwest::StatusCode::UNAUTHORIZED
        ));
        assert!(!explicit_version_unsupported(
            reqwest::StatusCode::TOO_MANY_REQUESTS
        ));
    }

    #[test]
    fn responder_poll_has_multiple_attempts_inside_initiator_wait() {
        assert!(
            FRIEND_RELAY_TICKET_RESPONDER_POLL_INTERVAL + FRIEND_RELAY_TICKET_POLL_TIMEOUT
                < FRIEND_RELAY_TICKET_INITIATOR_WAIT
        );
    }

    #[test]
    fn canonical_ticket_ids_have_one_textual_form() {
        let lower = "ab".repeat(32);
        let upper = lower.to_ascii_uppercase();
        assert_eq!(canonical_ticket_id(&upper).unwrap(), lower);
        assert!(canonical_ticket_id("not-a-ticket").is_err());
    }

    #[test]
    fn ticket_read_nonces_are_stable_and_scope_bound() {
        let secret = [7u8; 32];
        let poll = stable_relay_ticket_read_nonce(&secret, b"poll-scope");
        assert_eq!(poll, stable_relay_ticket_read_nonce(&secret, b"poll-scope"));
        assert_ne!(
            poll,
            stable_relay_ticket_read_nonce(&secret, b"status-scope")
        );
    }

    #[test]
    fn mailbox_poll_signature_binds_only_responder_nonce_and_time() {
        let responder = [1u8; 32];
        let nonce = [4u8; 16];
        let first = build_relay_mailbox_poll_msg(&responder, &nonce, 5);
        assert_ne!(first, build_relay_mailbox_poll_msg(&[2u8; 32], &nonce, 5));
        assert_ne!(
            first,
            build_relay_mailbox_poll_msg(&responder, &[5u8; 16], 5)
        );
        assert_ne!(first, build_relay_mailbox_poll_msg(&responder, &nonce, 6));
    }

    #[test]
    fn transient_ticket_read_statuses_are_retryable() {
        assert!(is_transient_relay_ticket_read_error(
            "relay ticket status: status 429 Too Many Requests"
        ));
        assert!(is_transient_relay_ticket_read_error(
            "relay ticket poll: status 503 Service Unavailable"
        ));
        assert!(!is_transient_relay_ticket_read_error(
            "relay ticket status: status 403 Forbidden"
        ));
    }
}
