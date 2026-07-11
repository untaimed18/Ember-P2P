use std::net::Ipv4Addr;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Rendezvous-protocol Ed25519 signing. Mirrors the verification helpers
// in `rendezvous-server/src/main.rs`. The server pins each id to its
// pubkey on first `/register` and refuses any later `/register`,
// `/unregister`, `/punch` POST, or `/punch/{id}` poll that doesn't
// carry a valid signature for that pinned pubkey — closing the squat
// attack where an attacker could compute a victim's id (just SHA256
// of the friend's BLAKE3 hash, both public) and POST a fake address
// for it. The signed messages each include a domain-separation prefix,
// an op tag, and a timestamp so the server can also reject replays.
// ---------------------------------------------------------------------------

const RDV_DOMAIN: &[u8] = b"ember-rdv-v1";
const OP_REGISTER: u8 = 0x01;
const OP_UNREGISTER: u8 = 0x02;
// 0x03..=0x06 reserved for future signing of /punch and /relay-invite
// endpoints (keyed on synthetic (ip, port) ids today, so no pubkey to
// verify against — see rendezvous-server/src/main.rs for the matching
// note).

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
fn pubkey_matches_id(pubkey: &[u8; 32], claimed_id: &str) -> bool {
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

fn current_timestamp() -> i64 {
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
pub async fn register(
    base_url: &str,
    ember_hash: &[u8; 16],
    port: u16,
    external_ip: Ipv4Addr,
    pubkey: &[u8; 32],
    secret_key: &[u8; 32],
    noise_pub: Option<&[u8; 32]>,
    ember_port: Option<u16>,
) -> Result<(), String> {
    require_https(base_url)?;
    let url = format!("{}/register", base_url.trim_end_matches('/'));
    let id = hashed_id(ember_hash);
    let id_raw = sha256_id_raw(ember_hash);
    let ts = current_timestamp();
    let signed_ip4 = external_ip.octets();
    let sig = sign_register(secret_key, pubkey, &id_raw, port, signed_ip4, ts);
    let mut body = serde_json::json!({
        "id": id,
        "port": port,
        "ip": external_ip.to_string(),
        "pubkey": hex::encode(pubkey),
        "ts": ts,
        "sig": hex::encode(sig.to_bytes()),
    });
    // Publish our X25519 Noise key so DHT-enabled peers can bootstrap
    // from us via `/bootstrap`. Deliberately NOT part of the signed
    // message: it's our own key, and the DHT re-verifies every contact's
    // Ed25519 binding on first PING, so an unsigned value is safe (a wrong
    // key only fails a handshake). Callers pass `None` when the Ember DHT
    // is disabled so we don't advertise a contact that can't be dialled.
    if let Some(nk) = noise_pub {
        body["noise_pub"] = serde_json::Value::String(hex::encode(nk));
    }
    // Advertise the UDP port our Ember Noise transport listens on. The
    // signed `port` above is our eMule TCP port (used for friend-presence
    // dialling); Ember runs over the shared KAD UDP socket on a *different*
    // port, so the `/bootstrap` pool must hand peers this value instead.
    // Unsigned for the same reason as `noise_pub`: it only scopes a port on
    // our own signed IP, and a wrong value just fails a handshake. Only sent
    // alongside a Noise key (the two together make us bootstrap-eligible);
    // a zero port is meaningless and dropped.
    if let (Some(_), Some(ep)) = (noise_pub, ember_port.filter(|p| *p != 0)) {
        body["ember_port"] = serde_json::Value::from(ep);
    }
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
        info!("Rendezvous: registration succeeded on port {port}");
        debug!("Rendezvous: registered {}… (ip={})", &id[..8], external_ip);
        Ok(())
    } else {
        let status = resp.status();
        Err(format!("rendezvous register returned {status}"))
    }
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

pub async fn lookup(
    base_url: &str,
    friend_hash: &[u8; 16],
) -> Result<Option<(Ipv4Addr, u16)>, String> {
    require_https(base_url)?;
    let id = hashed_id(friend_hash);
    let id_raw = sha256_id_raw(friend_hash);
    let url = format!("{}/lookup/{}", base_url.trim_end_matches('/'), id);
    let resp = client(base_url)
        .await?
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("rendezvous lookup failed: {e}"))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        let status = resp.status();
        return Err(format!("rendezvous lookup returned {status}"));
    }
    let bytes = read_bounded_bytes(resp, MAX_RESPONSE_BYTES).await?;
    let body: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("rendezvous lookup bad body: {e}"))?;
    let ip_str = body["ip"].as_str().unwrap_or_default();
    let raw_port = body["port"].as_u64().unwrap_or_default();
    if raw_port == 0 || raw_port > u16::MAX as u64 {
        debug!(
            "Rendezvous: lookup for {}… returned invalid port: {}",
            &id[..8],
            raw_port
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
            "Rendezvous: lookup for {}… missing/malformed auth fields; refusing to connect",
            &id[..8]
        );
        return Ok(None);
    }
    if !pubkey_matches_id(&pubkey, &id) {
        warn!(
            "Rendezvous: lookup for {}… pubkey does not derive to requested id; refusing to connect (server may be compromised)",
            &id[..8]
        );
        return Ok(None);
    }
    let now = current_timestamp();
    if (now - ts).abs() > MAX_LOOKUP_SIG_AGE_SECS {
        warn!(
            "Rendezvous: lookup for {}… returned a stale signed registration (ts={}); refusing to connect",
            &id[..8],
            ts
        );
        return Ok(None);
    }

    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
        let msg = build_register_msg(&id_raw, port, ip.octets(), &pubkey, ts);
        if !ed25519_verify_lookup(&pubkey, &msg, &sig) {
            warn!(
                "Rendezvous: lookup for {}… signature verification failed; refusing to connect (server may be compromised)",
                &id[..8]
            );
            return Ok(None);
        }
        if port > 0 && is_routable_public_v4(ip) {
            // Friend IP/port is effectively PII — keep it at debug rather than
            // info so it doesn't land in user-shared log bundles by default.
            debug!("Rendezvous: found {}… at {}:{}", &id[..8], ip, port);
            return Ok(Some((ip, port)));
        }
        if port > 0 {
            warn!(
                "Rendezvous: lookup for {}… returned non-public IP ({}); refusing to connect",
                &id[..8],
                ip
            );
            return Ok(None);
        }
    }
    debug!(
        "Rendezvous: lookup for {}… returned unparseable data",
        &id[..8]
    );
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
