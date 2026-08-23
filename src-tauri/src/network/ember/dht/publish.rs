use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

use byteorder::{LittleEndian, WriteBytesExt};
use ed25519_dalek::SigningKey;
use tracing::{debug, trace, warn};

use super::messages;
use super::search::keyword_hash;
use super::{EmberContact, EmberNodeId};
use crate::network::ember::crypto;

/// Longest file name that still leaves a keyword or source record inside
/// [`messages::MAX_STORE_RECORD_BYTES`], so we never sign a body a storer
/// would accept and a `FOUND_VALUE` packer would then skip.
fn max_encoded_name_bytes(contact_bytes: usize) -> usize {
    messages::MAX_STORE_RECORD_BYTES
        .saturating_sub(RECORD_HEADER_LEN)
        .saturating_sub(contact_bytes)
}

/// Truncate `file_name` on a UTF-8 boundary so the encoded body fits the
/// FOUND_VALUE pack budget.
fn clamp_name_to_record_budget(file_name: &str, contact_bytes: usize) -> &str {
    let max = max_encoded_name_bytes(contact_bytes);
    let bytes = file_name.as_bytes();
    if bytes.len() <= max {
        return file_name;
    }
    let mut end = max;
    while end > 0 && (bytes[end] & 0b1100_0000) == 0b1000_0000 {
        end -= 1;
    }
    std::str::from_utf8(&bytes[..end]).unwrap_or("")
}

/// Maximum concurrent publish operations.
const MAX_ACTIVE_PUBLISHES: usize = 128;

/// How long to wait for a STORE_ACK before timing out.
const PUBLISH_TIMEOUT_SECS: u64 = 30;

/// Minimum number of nodes to store a record on.
const MIN_STORE_NODES: usize = 5;

/// Record type constants.
pub const RECORD_TYPE_KEYWORD: u8 = 0x01;
pub const RECORD_TYPE_SOURCE: u8 = 0x02;

/// Wire size of the trailing contact block a source record appends after
/// its file name: ip(4) + tcp_port(2) + udp_port(2) + flags(1) + noise_pub(32).
pub(super) const SOURCE_CONTACT_WIRE_LEN: usize = 4 + 2 + 2 + 1 + 32;

/// Optional callback trailer after the contact block, present on firewalled
/// source records: publisher eD2K user_hash(16) + buddy ip(4) + buddy
/// udp_port(2) + buddy noise_pub(32) + callback token(16), then the buddy's
/// endorsement of that endpoint — its ed25519 key(32) + expiry(8) +
/// signature(64). HighID records stay 41 bytes. v2 parsers that ignore
/// trailing bytes still accept the contact; this build reads the extra 174
/// when they are there. Not a version bump.
pub(super) const SOURCE_CALLBACK_TRAILER_LEN: usize =
    SOURCE_CALLBACK_TRAILER_V1_LEN + BUDDY_ENDORSEMENT_TRAILER_LEN;

/// The trailer as it shipped before the buddy endorsed its own endpoint:
/// user_hash(16) + buddy ip(4) + udp(2) + noise_pub(32) + token(16).
///
/// Records of this shape are already on the live network, and
/// `decode_source_contact` infers trailer presence from residual length alone
/// (deliberately, so a longer trailer is forward-compatible rather than a
/// version bump). So the endorsement had to go on the *end*: a 70-byte
/// residual still decodes as "buddy, unendorsed" — which
/// [`DiscoveredSource::takes_callback`] then refuses to dial, because nothing
/// but the publisher vouches for the address.
pub(super) const SOURCE_CALLBACK_TRAILER_V1_LEN: usize = 16 + 4 + 2 + 32 + 16;

/// Endorsement bytes appended to the v1 trailer: the buddy's Ed25519 identity
/// key, the expiry, and its signature over its own endpoint.
pub(super) const BUDDY_ENDORSEMENT_TRAILER_LEN: usize = 32 + 8 + 64;

/// Domain separator for the buddy endorsement signature.
///
/// Without one, a signature this scheme accepts could be harvested from
/// another Ember protocol that happens to sign a byte string with the same
/// shape under the same identity key.
const BUDDY_ENDORSE_DOMAIN: &[u8] = b"ember-buddy-endorse-v1";

/// The exact bytes a buddy signs to endorse itself as `publisher_id`'s buddy.
///
/// Covers the endpoint a searcher will dial (`ip`, `udp_port`, `noise_pub`),
/// the publisher the endorsement is issued to, and when it lapses. Binding the
/// publisher is what stops the endorsement being a bearer token any node could
/// lift out of someone else's record and reuse to name this buddy.
///
/// Shared by the signer (`EmberDht::build_buddy_endorse`) and the verifier
/// ([`SourceBuddy::endorsement_covers`]) so the two cannot drift.
pub fn buddy_endorsement_signing_bytes(
    ip: Ipv4Addr,
    udp_port: u16,
    noise_pub: &[u8; 32],
    publisher_id: &[u8; 16],
    expires_at: i64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(BUDDY_ENDORSE_DOMAIN.len() + 4 + 2 + 32 + 16 + 8);
    buf.extend_from_slice(BUDDY_ENDORSE_DOMAIN);
    buf.extend_from_slice(&ip.octets());
    buf.extend_from_slice(&udp_port.to_le_bytes());
    buf.extend_from_slice(noise_pub);
    buf.extend_from_slice(publisher_id);
    buf.extend_from_slice(&expires_at.to_le_bytes());
    buf
}

/// Whether a buddy would survive `decode_source_contact`.
///
/// The decoder discards a trailer whose buddy has port 0 or an unspecified IP
/// (and with it the `user_hash` and `callback_token` that share the trailer),
/// so writing one is a 174-byte round-trip loss: `decode(encode(sc)) != sc`,
/// and re-encoding the parsed contact would give 41 bytes where
/// `source_contact_encoded_len` promised 215. Both the encoder and the length
/// helper ask this question so all three agree on when the trailer exists.
///
/// The endorsement is deliberately not part of the question: an unendorsed or
/// forged buddy is one the decoder keeps and the dial gate then rejects, not a
/// trailer the encoder should silently drop.
///
/// Not reachable from the current publish path — `ember_named_source_buddy`
/// applies the stricter `SourceBuddy::is_routable` before naming anyone — but
/// this is the one helper whose entire job is predicting the encoder's output.
fn buddy_survives_decode(buddy: &SourceBuddy) -> bool {
    buddy.udp_port != 0 && !buddy.ip.is_unspecified()
}

fn source_contact_encoded_len(contact: Option<&SourceContact>) -> usize {
    match contact {
        Some(sc) if sc.buddy.as_ref().is_some_and(buddy_survives_decode) => {
            SOURCE_CONTACT_WIRE_LEN + SOURCE_CALLBACK_TRAILER_LEN
        }
        Some(_) => SOURCE_CONTACT_WIRE_LEN,
        None => 0,
    }
}

fn encode_source_contact(data: &mut Vec<u8>, sc: &SourceContact) {
    data.extend_from_slice(&sc.ip.octets());
    data.write_u16::<LittleEndian>(sc.tcp_port).unwrap();
    data.write_u16::<LittleEndian>(sc.udp_port).unwrap();
    data.push(sc.flags);
    data.extend_from_slice(&sc.noise_pub);
    if let Some(buddy) = sc.buddy.filter(buddy_survives_decode) {
        data.extend_from_slice(&sc.user_hash.unwrap_or([0u8; 16]));
        data.extend_from_slice(&buddy.ip.octets());
        data.write_u16::<LittleEndian>(buddy.udp_port).unwrap();
        data.extend_from_slice(&buddy.noise_pub);
        data.extend_from_slice(&sc.callback_token.unwrap_or([0u8; 16]));
        data.extend_from_slice(&buddy.ed25519_pub);
        data.write_i64::<LittleEndian>(buddy.endorsed_until).unwrap();
        data.extend_from_slice(&buddy.endorsement);
    }
}

fn decode_source_contact(data: &[u8], off: usize) -> Option<SourceContact> {
    if data.len() < off + SOURCE_CONTACT_WIRE_LEN {
        return None;
    }
    let ip = Ipv4Addr::new(data[off], data[off + 1], data[off + 2], data[off + 3]);
    let tcp_port = u16::from_le_bytes([data[off + 4], data[off + 5]]);
    let udp_port = u16::from_le_bytes([data[off + 6], data[off + 7]]);
    let flags = data[off + 8];
    let mut noise_pub = [0u8; 32];
    noise_pub.copy_from_slice(&data[off + 9..off + 41]);
    let mut contact = SourceContact {
        ip,
        tcp_port,
        udp_port,
        flags,
        noise_pub,
        user_hash: None,
        buddy: None,
        callback_token: None,
    };
    let rest = off + SOURCE_CONTACT_WIRE_LEN;
    // Trailer presence is still inferred from residual length, and the
    // endorsement sits last, so a record published before it existed reads
    // back as an unendorsed buddy rather than as no buddy at all.
    if data.len() >= rest + SOURCE_CALLBACK_TRAILER_V1_LEN {
        let mut user_hash = [0u8; 16];
        user_hash.copy_from_slice(&data[rest..rest + 16]);
        let b = rest + 16;
        let buddy_ip = Ipv4Addr::new(data[b], data[b + 1], data[b + 2], data[b + 3]);
        let buddy_udp = u16::from_le_bytes([data[b + 4], data[b + 5]]);
        let mut buddy_noise = [0u8; 32];
        buddy_noise.copy_from_slice(&data[b + 6..b + 38]);
        let mut token = [0u8; 16];
        token.copy_from_slice(&data[b + 38..b + 54]);
        let mut ed25519_pub = [0u8; 32];
        let mut endorsed_until = 0i64;
        let mut endorsement = [0u8; 64];
        if data.len() >= rest + SOURCE_CALLBACK_TRAILER_LEN {
            let e = b + 54;
            ed25519_pub.copy_from_slice(&data[e..e + 32]);
            endorsed_until = i64::from_le_bytes(data[e + 32..e + 40].try_into().ok()?);
            endorsement.copy_from_slice(&data[e + 40..e + 104]);
        }
        if buddy_udp != 0 && !buddy_ip.is_unspecified() {
            contact.user_hash = (user_hash != [0u8; 16]).then_some(user_hash);
            contact.buddy = Some(SourceBuddy {
                ip: buddy_ip,
                udp_port: buddy_udp,
                noise_pub: buddy_noise,
                ed25519_pub,
                endorsed_until,
                endorsement,
            });
            contact.callback_token = (token != [0u8; 16]).then_some(token);
        }
    }
    Some(contact)
}

/// Fixed-size prefix every record body carries before its file name:
/// `record_type(1) + keyword_hash(16) + file_hash(16) + ember_file_hash(32)
/// + file_size(8) + publisher_key(32) + timestamp(8) + name_len(2)`.
///
/// Shared so the readers in this module and in [`super::store`] cannot drift
/// apart on where the name — and therefore the contact block — begins.
pub(super) const RECORD_HEADER_LEN: usize = 1 + 16 + 16 + 32 + 8 + 32 + 8 + 2;

/// DHT key under which a file's source records live: `BLAKE3(file_hash)[..16]`.
///
/// Publish (`SignedRecord::source`) and find (the download source-lookup
/// driver) MUST agree on this derivation, so it lives in one place.
pub fn source_key(file_hash: &[u8; 16]) -> [u8; 16] {
    let hash = blake3::hash(file_hash);
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash.as_bytes()[..16]);
    key
}

/// HighID buddy a firewalled publisher names so a searcher can send
/// `CALLBACK_REQ` instead of dialling the unverified source address.
///
/// Every field except `ip`/`udp_port`/`noise_pub` exists to answer one
/// question: did the node at this endpoint actually agree to be named here?
/// `SOURCE_FLAG_FIREWALLED` exempts a source record from the storer's
/// anti-reflection sender-IP bind, so without an answer a publisher could name
/// any victim and have every reachable searcher open an unsolicited Noise
/// handshake to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceBuddy {
    pub ip: Ipv4Addr,
    pub udp_port: u16,
    pub noise_pub: [u8; 32],
    /// The buddy's Ed25519 identity key. Its `BLAKE3` prefix is the buddy's
    /// DHT node ID (see [`Self::node_id`]), and it is the key
    /// [`Self::endorsement`] verifies under.
    ///
    /// Zero on a record published before the trailer carried an endorsement.
    /// Those are never dialled: see [`Self::has_identity`].
    pub ed25519_pub: [u8; 32],
    /// Unix seconds after which the endorsement is stale.
    pub endorsed_until: i64,
    /// The buddy's own signature over its own endpoint, bound to the
    /// publishing node. Forging one needs the buddy's private key, which is
    /// what makes naming a third party impossible rather than merely
    /// implausible.
    pub endorsement: [u8; 64],
}

impl SourceBuddy {
    /// Whether this buddy is a plausible UDP destination for `CALLBACK_REQ`.
    /// Special-use / unspecified IPv4 and port 0 never are.
    pub fn is_routable(&self) -> bool {
        self.udp_port != 0
            && !self.ip.is_unspecified()
            && !crate::security::is_special_use_v4(self.ip)
    }

    /// Whether the trailer carried an identity key at all — i.e. whether there
    /// is an endorsement to check. False for a record published before the
    /// endorsement existed, which parks rather than dialling.
    pub fn has_identity(&self) -> bool {
        self.ed25519_pub != [0u8; 32]
    }

    /// The buddy's DHT node ID, derived from its identity key exactly as
    /// every other Ember subsystem derives one. `None` if the key is absent or
    /// not a valid curve point.
    pub fn node_id(&self) -> Option<[u8; 16]> {
        if !self.has_identity() {
            return None;
        }
        crypto::node_id_from_ed25519_bytes(&self.ed25519_pub)
    }

    /// Whether the buddy really signed this endpoint, for this publisher, and
    /// the signature has not lapsed.
    ///
    /// This is the whole defence. The publisher chose the bytes in the trailer,
    /// but it cannot produce this signature for an endpoint whose private key
    /// it does not hold — so either the endpoint belongs to a node that agreed
    /// to receive `CALLBACK_REQ` there, or the record does not pass here.
    pub fn endorsement_covers(&self, publisher_id: &[u8; 16], now: i64) -> bool {
        if !self.is_routable() || !self.has_identity() {
            return false;
        }
        if self.endorsed_until <= now {
            return false;
        }
        let Some(key) = crypto::verifying_key_from_bytes(&self.ed25519_pub) else {
            return false;
        };
        let signed = buddy_endorsement_signing_bytes(
            self.ip,
            self.udp_port,
            &self.noise_pub,
            publisher_id,
            self.endorsed_until,
        );
        crypto::verify(&key, &signed, &self.endorsement)
    }
}

/// The publisher's self-reported reachable contact, carried inside a
/// signed `RECORD_TYPE_SOURCE` record (and therefore covered by the
/// publisher's signature). A downloader uses `ip` + `tcp_port` to dial the
/// source over the existing eD2K client-to-client path; `noise_pub` is
/// stashed for future native (Noise) dialing. Firewalled records also
/// carry [`Self::buddy`] so the searcher can ask that HighID to bounce a
/// connect-back rather than dialling the unverified address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceContact {
    pub ip: Ipv4Addr,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub flags: u8,
    pub noise_pub: [u8; 32],
    /// Publisher's eD2K user hash, present with [`Self::buddy`] so a
    /// connect-back Hello can match the pending callback the way KAD
    /// matches `TAG_BUDDYHASH` sources by user hash rather than NAT IP.
    pub user_hash: Option<[u8; 16]>,
    /// HighID buddy named in the trailer. Publish `PROXY_STORE`s only this
    /// contact; consume `CALLBACK_REQ`s it.
    pub buddy: Option<SourceBuddy>,
    /// Publisher-derived token the searcher copies into `CALLBACK_REQ` and
    /// the buddy copies into `CALLBACK`. Bind connect-back to a file we
    /// actually asked this buddy to proxy.
    pub callback_token: Option<[u8; 16]>,
}

impl Default for SourceContact {
    fn default() -> Self {
        Self {
            ip: Ipv4Addr::UNSPECIFIED,
            tcp_port: 0,
            udp_port: 0,
            flags: 0,
            noise_pub: [0u8; 32],
            user_hash: None,
            buddy: None,
            callback_token: None,
        }
    }
}

/// A source record a `FIND_VALUE` returned, after signature verification.
///
/// Distinct from [`SourceContact`] so the consume path can keep the
/// publisher's Ember node ID (derived from the signed Ed25519 key) next
/// to the buddy fields without stuffing it into the on-wire contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveredSource {
    pub ip: Ipv4Addr,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub flags: u8,
    pub user_hash: Option<[u8; 16]>,
    pub buddy: Option<SourceBuddy>,
    /// Token from the signed trailer; `CALLBACK_REQ` must carry it.
    pub callback_token: Option<[u8; 16]>,
    /// `BLAKE3(publisher Ed25519)[..16]` — the identity `CALLBACK_REQ`
    /// names so the buddy can look up who it proxied for.
    pub publisher_id: [u8; 16],
}

impl DiscoveredSource {
    /// Whether a reachable searcher should `CALLBACK_REQ` this source instead
    /// of parking it. A firewalled searcher, a HighID record, a missing
    /// publisher id, an unusable buddy, or a buddy that did not endorse the
    /// endpoint for *this* publisher all return false — the caller then falls
    /// back to the firewalled EPX park path rather than dropping the source or
    /// TCP-dialling the unverified NAT address.
    ///
    /// This is the complete gate: it needs no routing-table lookup and no
    /// network round trip, so no caller can reach the dial path having checked
    /// less than this.
    pub fn takes_callback(&self, searcher_tcp_firewalled: bool, now: i64) -> bool {
        if searcher_tcp_firewalled {
            return false;
        }
        if self.flags & crate::network::ember::SOURCE_FLAG_FIREWALLED == 0 {
            return false;
        }
        if self.publisher_id == [0u8; 16] {
            return false;
        }
        let Some(token) = self.callback_token else {
            return false;
        };
        if token == [0u8; 16] {
            return false;
        }
        self.buddy
            .is_some_and(|b| b.endorsement_covers(&self.publisher_id, now))
    }
}

/// A signed record ready for DHT storage.
#[derive(Debug, Clone)]
pub struct SignedRecord {
    pub record_type: u8,
    pub keyword_hash: [u8; 16],
    pub file_hash: [u8; 16],
    pub ember_file_hash: [u8; 32],
    pub file_size: u64,
    pub file_name: String,
    pub publisher_key: [u8; 32],
    pub timestamp: i64,
    /// Serialized record data (everything above, packed).
    pub data: Vec<u8>,
    /// Ed25519 signature over `data`.
    pub signature: [u8; 64],
    /// Present only for `RECORD_TYPE_SOURCE`: the publisher's reachable
    /// contact, appended to `data` after the file name and thus signed.
    pub source_contact: Option<SourceContact>,
}

impl SignedRecord {
    /// Create a keyword record: associates a keyword hash with file metadata.
    pub fn keyword(
        keyword: &str,
        file_hash: [u8; 16],
        ember_file_hash: [u8; 32],
        file_size: u64,
        file_name: &str,
        signing_key: &SigningKey,
    ) -> Self {
        let kw_hash = keyword_hash(keyword);
        Self::build(
            RECORD_TYPE_KEYWORD,
            kw_hash,
            file_hash,
            ember_file_hash,
            file_size,
            file_name,
            None,
            signing_key,
        )
    }

    /// Create a source record: announces that `contact` is a source for the
    /// file identified by `file_hash`. The contact is part of the signed
    /// payload, so a downloader can dial it after verifying the signature.
    pub fn source(
        file_hash: [u8; 16],
        ember_file_hash: [u8; 32],
        file_size: u64,
        file_name: &str,
        contact: SourceContact,
        signing_key: &SigningKey,
    ) -> Self {
        Self::build(
            RECORD_TYPE_SOURCE,
            source_key(&file_hash),
            file_hash,
            ember_file_hash,
            file_size,
            file_name,
            Some(contact),
            signing_key,
        )
    }

    fn build(
        record_type: u8,
        keyword_hash: [u8; 16],
        file_hash: [u8; 16],
        ember_file_hash: [u8; 32],
        file_size: u64,
        file_name: &str,
        source_contact: Option<SourceContact>,
        signing_key: &SigningKey,
    ) -> Self {
        let publisher_key = signing_key.verifying_key().to_bytes();
        let timestamp = chrono::Utc::now().timestamp();
        let contact_bytes = source_contact_encoded_len(source_contact.as_ref());
        let file_name = clamp_name_to_record_budget(file_name, contact_bytes);
        let name_bytes = file_name.as_bytes();
        let name_len = name_bytes.len();

        let mut data = Vec::with_capacity(
            1 + 16 + 16 + 32 + 8 + 32 + 8 + 2 + name_len + contact_bytes,
        );
        data.push(record_type);
        data.extend_from_slice(&keyword_hash);
        data.extend_from_slice(&file_hash);
        data.extend_from_slice(&ember_file_hash);
        data.write_u64::<LittleEndian>(file_size).unwrap();
        data.extend_from_slice(&publisher_key);
        data.write_i64::<LittleEndian>(timestamp).unwrap();
        data.write_u16::<LittleEndian>(name_len as u16).unwrap();
        data.extend_from_slice(&name_bytes[..name_len]);

        // Source records append a fixed-size contact block after the name; it
        // is signed along with everything above so a relayed record can't have
        // its address rewritten.
        if let Some(sc) = source_contact {
            encode_source_contact(&mut data, &sc);
        }

        let signature = crypto::sign(signing_key, &data);

        Self {
            record_type,
            keyword_hash,
            file_hash,
            ember_file_hash,
            file_size,
            file_name: file_name.to_string(),
            publisher_key,
            timestamp,
            data,
            signature,
            source_contact,
        }
    }

    /// Verify this record's signature against the embedded publisher key.
    ///
    /// The live paths never need this: `from_wire` and `from_value_blob`
    /// both verify before handing back a record, so anything parsed is
    /// already checked. Kept as the standalone predicate those tests
    /// assert through.
    #[allow(dead_code)]
    pub fn verify(&self) -> bool {
        if let Some(pk) = crypto::verifying_key_from_bytes(&self.publisher_key) {
            crypto::verify(&pk, &self.data, &self.signature)
        } else {
            false
        }
    }

    /// Parse a record from a `FOUND_VALUE` blob, whose layout is
    /// `record_data || 64-byte publisher signature` (see the engine's
    /// `FIND_VALUE` responder). Verifies the signature; returns `None`
    /// on any malformed/forged input.
    pub fn from_value_blob(blob: &[u8]) -> Option<Self> {
        if blob.len() < 64 {
            return None;
        }
        let split = blob.len() - 64;
        let (data, sig_bytes) = blob.split_at(split);
        let signature: [u8; 64] = sig_bytes.try_into().ok()?;
        Self::from_wire(data, signature)
    }

    /// Whether `blob` carries a signature its embedded publisher key really
    /// made, without building the record.
    ///
    /// [`Self::from_value_blob`] answers the same question, but allocates a
    /// `String` for the name and copies the body to do it. A search asks this
    /// of every blob a peer offers and keeps none of the parsed fields, so it
    /// takes the verdict alone; whoever consumes the result parses properly.
    ///
    /// The framing checks mirror [`Self::from_wire`] on purpose: a blob that
    /// would be refused there has to be refused here too, or it wins a result
    /// slot only to be dropped at the far end.
    pub fn value_blob_is_authentic(blob: &[u8]) -> bool {
        if blob.len() < 115 + 64 {
            return false;
        }
        let (data, sig_bytes) = blob.split_at(blob.len() - 64);
        let name_len = u16::from_le_bytes([data[113], data[114]]) as usize;
        if data.len() < 115 + name_len {
            return false;
        }
        if data[0] == RECORD_TYPE_SOURCE && data.len() < 115 + name_len + SOURCE_CONTACT_WIRE_LEN {
            return false;
        }
        let (Ok(signature), Ok(publisher_key)) = (
            <[u8; 64]>::try_from(sig_bytes),
            <[u8; 32]>::try_from(&data[73..105]),
        ) else {
            return false;
        };
        crypto::verifying_key_from_bytes(&publisher_key)
            .is_some_and(|pk| crypto::verify(&pk, data, &signature))
    }

    /// Parse a signed record from raw data + signature.
    pub fn from_wire(data: &[u8], signature: [u8; 64]) -> Option<Self> {
        // Minimum: type(1) + kw_hash(16) + file_hash(16) + ember_hash(32) +
        //          size(8) + pub_key(32) + timestamp(8) + name_len(2) = 115
        if data.len() < 115 {
            return None;
        }

        let record_type = data[0];
        let mut keyword_hash = [0u8; 16];
        keyword_hash.copy_from_slice(&data[1..17]);
        let mut file_hash = [0u8; 16];
        file_hash.copy_from_slice(&data[17..33]);
        let mut ember_file_hash = [0u8; 32];
        ember_file_hash.copy_from_slice(&data[33..65]);
        let file_size = u64::from_le_bytes(data[65..73].try_into().ok()?);
        let mut publisher_key = [0u8; 32];
        publisher_key.copy_from_slice(&data[73..105]);
        let timestamp = i64::from_le_bytes(data[105..113].try_into().ok()?);
        let name_len = u16::from_le_bytes(data[113..115].try_into().ok()?) as usize;

        if data.len() < 115 + name_len {
            return None;
        }
        let file_name = String::from_utf8_lossy(&data[115..115 + name_len]).to_string();

        // Source records carry a fixed-size trailing contact block. Reject a
        // source record that doesn't carry it (truncated/forged) rather than
        // silently treating it as contactless.
        let source_contact = if record_type == RECORD_TYPE_SOURCE {
            let off = 115 + name_len;
            Some(decode_source_contact(data, off)?)
        } else {
            None
        };

        // Verify signature
        let pk = crypto::verifying_key_from_bytes(&publisher_key)?;
        if !crypto::verify(&pk, data, &signature) {
            return None;
        }

        Some(Self {
            record_type,
            keyword_hash,
            file_hash,
            ember_file_hash,
            file_size,
            file_name,
            publisher_key,
            timestamp,
            data: data.to_vec(),
            signature,
            source_contact,
        })
    }
}

/// Tracks a single publish operation: store a record on the closest K nodes.
pub struct PublishOperation {
    pub id: u32,
    pub record: SignedRecord,
    /// DHT key to publish under (the keyword_hash from the record).
    pub dht_key: EmberNodeId,
    /// Target nodes to store on.
    pub targets: Vec<EmberContact>,
    /// Nodes that acknowledged storage.
    pub acked: Vec<EmberNodeId>,
    /// Nodes that failed.
    pub failed: Vec<EmberNodeId>,
    /// Outstanding request IDs mapped to node IDs.
    pub pending_requests: HashMap<u32, EmberNodeId>,
    pub started_at: Instant,
    pub complete: bool,
    /// Monotonic per-publish request-id counter; see the matching
    /// field on `IterativeSearch` for the rationale (avoids the
    /// `rand::random` collision that silently overwrites a pending
    /// node mapping).
    next_request_id: u32,
}

impl PublishOperation {
    fn new(id: u32, record: SignedRecord, targets: Vec<EmberContact>) -> Self {
        let dht_key = EmberNodeId(record.keyword_hash);
        Self {
            id,
            record,
            dht_key,
            targets,
            acked: Vec::new(),
            failed: Vec::new(),
            pending_requests: HashMap::new(),
            started_at: Instant::now(),
            complete: false,
            next_request_id: 1,
        }
    }

    /// Get targets that haven't been sent to yet.
    pub fn next_to_store(&mut self) -> Vec<(EmberContact, u32)> {
        let mut batch = Vec::new();
        for target in &self.targets {
            if self.acked.contains(&target.node_id)
                || self.failed.contains(&target.node_id)
                || self
                    .pending_requests
                    .values()
                    .any(|id| *id == target.node_id)
            {
                continue;
            }
            let req_id = self.next_request_id;
            self.next_request_id = self.next_request_id.wrapping_add(1);
            self.pending_requests.insert(req_id, target.node_id);
            batch.push((target.clone(), req_id));
        }
        batch
    }

    /// Process a STORE_ACK from a node.
    pub fn process_ack(&mut self, request_id: u32) {
        if let Some(node_id) = self.pending_requests.remove(&request_id) {
            self.acked.push(node_id);
            trace!("Publish {}: node {} acked", self.id, node_id);
        }
        self.check_complete();
    }

    /// Mark a store request as failed.
    pub fn mark_failed(&mut self, request_id: u32) {
        if let Some(node_id) = self.pending_requests.remove(&request_id) {
            self.failed.push(node_id);
        }
        self.check_complete();
    }

    fn check_complete(&mut self) {
        if self.complete {
            return;
        }
        if self.started_at.elapsed().as_secs() > PUBLISH_TIMEOUT_SECS {
            self.complete = true;
            return;
        }
        if self.pending_requests.is_empty() {
            self.complete = true;
        }
    }

    /// Re-evaluate completion and report it. Lets the driver finish a
    /// publish that had zero reachable targets (nothing to ack), mirroring
    /// `IterativeSearch::poll_complete`.
    pub fn poll_complete(&mut self) -> bool {
        self.check_complete();
        self.complete
    }
}

/// Manages multiple concurrent publish operations.
pub struct PublishManager {
    operations: HashMap<u32, PublishOperation>,
    next_id: u32,
}

impl PublishManager {
    pub fn new() -> Self {
        Self {
            operations: HashMap::new(),
            next_id: 1,
        }
    }

    /// Start a publish onto an already-resolved target set.
    ///
    /// Used by buddy `PROXY_STORE` and the harness so they share the same
    /// lookup-backed replica set as library keyword/source publish, instead of
    /// storing only on whoever happens to sit in this node's table.
    pub fn start_publish_to(
        &mut self,
        record: SignedRecord,
        targets: Vec<EmberContact>,
    ) -> Option<u32> {
        if self.operations.len() >= MAX_ACTIVE_PUBLISHES {
            warn!(
                "Too many active publishes ({}), rejecting new publish",
                self.operations.len()
            );
            return None;
        }

        if targets.len() < MIN_STORE_NODES {
            debug!(
                "Only {} targets for publish (need {MIN_STORE_NODES}), publishing anyway",
                targets.len()
            );
        }

        let id = self.alloc_id()?;
        let op = PublishOperation::new(id, record, targets);
        trace!(
            "Starting publish {} on {} nodes for key {}",
            id,
            op.targets.len(),
            op.dht_key
        );
        self.operations.insert(id, op);
        Some(id)
    }

    pub fn get_mut(&mut self, publish_id: u32) -> Option<&mut PublishOperation> {
        self.operations.get_mut(&publish_id)
    }

    pub fn remove(&mut self, publish_id: u32) -> Option<PublishOperation> {
        self.operations.remove(&publish_id)
    }

    /// Clean up timed-out operations.
    pub fn cleanup_expired(&mut self) -> Vec<u32> {
        let expired: Vec<u32> = self
            .operations
            .iter()
            .filter(|(_, op)| op.started_at.elapsed().as_secs() > PUBLISH_TIMEOUT_SECS * 2)
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            self.operations.remove(id);
        }
        expired
    }

    pub fn active_count(&self) -> usize {
        self.operations.len()
    }

    fn alloc_id(&mut self) -> Option<u32> {
        for _ in 0..=MAX_ACTIVE_PUBLISHES {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);
            if !self.operations.contains_key(&id) {
                return Some(id);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn signed_keyword_record_round_trip() {
        let sk = SigningKey::generate(&mut OsRng);
        let record =
            SignedRecord::keyword("test", [1u8; 16], [2u8; 32], 12345, "test_file.txt", &sk);

        assert!(record.verify());
        assert_eq!(record.record_type, RECORD_TYPE_KEYWORD);
        assert_eq!(record.file_name, "test_file.txt");
        assert_eq!(record.file_size, 12345);

        let parsed = SignedRecord::from_wire(&record.data, record.signature).unwrap();
        assert_eq!(parsed.record_type, record.record_type);
        assert_eq!(parsed.file_hash, record.file_hash);
        assert_eq!(parsed.file_name, record.file_name);
        assert!(parsed.verify());
    }

    fn test_contact() -> SourceContact {
        SourceContact {
            ip: Ipv4Addr::new(88, 1, 2, 3),
            tcp_port: 4662,
            udp_port: 4672,
            flags: 0x05,
            noise_pub: [0x33; 32],
            ..Default::default()
        }
    }

    const BUDDY_IP: Ipv4Addr = Ipv4Addr::new(8, 8, 4, 4);
    const BUDDY_UDP: u16 = 4672;
    const BUDDY_NOISE: [u8; 32] = [0xB1; 32];
    /// `discovered_firewalled` publishes under this identity, so an endorsement
    /// has to be bound to it.
    const TEST_PUBLISHER: [u8; 16] = [0xAAu8; 16];

    /// A buddy whose endorsement bytes are structurally present but not a real
    /// signature. Enough for the wire round-trip and length tests, which do not
    /// care whether the endorsement verifies; the gate tests use
    /// [`endorsed_buddy`].
    fn test_buddy() -> SourceBuddy {
        SourceBuddy {
            ip: BUDDY_IP,
            udp_port: BUDDY_UDP,
            noise_pub: BUDDY_NOISE,
            ed25519_pub: [0xB2; 32],
            endorsed_until: 4_000_000_000,
            endorsement: [0xB3; 64],
        }
    }

    /// A buddy that really did sign its own endpoint for `publisher_id`.
    fn endorsed_buddy(buddy_sk: &SigningKey, publisher_id: &[u8; 16], until: i64) -> SourceBuddy {
        let signed = buddy_endorsement_signing_bytes(
            BUDDY_IP,
            BUDDY_UDP,
            &BUDDY_NOISE,
            publisher_id,
            until,
        );
        SourceBuddy {
            ip: BUDDY_IP,
            udp_port: BUDDY_UDP,
            noise_pub: BUDDY_NOISE,
            ed25519_pub: buddy_sk.verifying_key().to_bytes(),
            endorsed_until: until,
            endorsement: crypto::sign(buddy_sk, &signed),
        }
    }

    #[test]
    fn signed_source_record_round_trip() {
        let sk = SigningKey::generate(&mut OsRng);
        let contact = test_contact();
        let record = SignedRecord::source(
            [0xAA; 16],
            [0xBB; 32],
            99999,
            "source_file.mp3",
            contact,
            &sk,
        );

        assert!(record.verify());
        assert_eq!(record.record_type, RECORD_TYPE_SOURCE);
        // The DHT key is derived from the file hash, identical to find side.
        assert_eq!(record.keyword_hash, source_key(&[0xAA; 16]));
        assert_eq!(record.source_contact, Some(contact));

        // The contact survives a full wire round-trip (and the blob form
        // returned by FIND_VALUE).
        let parsed = SignedRecord::from_wire(&record.data, record.signature).unwrap();
        assert_eq!(parsed.source_contact, Some(contact));
        let mut blob = record.data.clone();
        blob.extend_from_slice(&record.signature);
        let from_blob = SignedRecord::from_value_blob(&blob).unwrap();
        assert_eq!(from_blob.source_contact, Some(contact));
    }

    #[test]
    fn firewalled_source_record_round_trips_the_callback_trailer() {
        let sk = SigningKey::generate(&mut OsRng);
        let contact = SourceContact {
            flags: crate::network::ember::SOURCE_FLAG_FIREWALLED,
            user_hash: Some([0xCCu8; 16]),
            buddy: Some(test_buddy()),
            callback_token: Some([0xDDu8; 16]),
            ..test_contact()
        };
        let record = SignedRecord::source(
            [0xAA; 16],
            [0xBB; 32],
            99999,
            "fw.mp3",
            contact,
            &sk,
        );
        assert_eq!(
            record.data.len(),
            115 + "fw.mp3".len() + SOURCE_CONTACT_WIRE_LEN + SOURCE_CALLBACK_TRAILER_LEN
        );
        let parsed = SignedRecord::from_wire(&record.data, record.signature).unwrap();
        assert_eq!(parsed.source_contact, Some(contact));
        let mut blob = record.data.clone();
        blob.extend_from_slice(&record.signature);
        let from_blob = SignedRecord::from_value_blob(&blob).unwrap();
        assert_eq!(from_blob.source_contact, Some(contact));
        assert!(SignedRecord::value_blob_is_authentic(&blob));
    }

    /// The trailer grew a 16-byte buddy node ID on the end, and trailer
    /// presence is inferred from residual length. Records signed before that
    /// are on the live network and cannot be re-signed, so the shorter form
    /// must still decode as a buddy — just one with no identity to
    /// verify, which the dial gate then refuses.
    #[test]
    fn a_trailer_from_before_the_endorsement_still_decodes_as_a_buddy() {
        let sk = SigningKey::generate(&mut OsRng);
        let contact = SourceContact {
            flags: crate::network::ember::SOURCE_FLAG_FIREWALLED,
            user_hash: Some([0xCCu8; 16]),
            buddy: Some(test_buddy()),
            callback_token: Some([0xDDu8; 16]),
            ..test_contact()
        };
        assert_eq!(
            (SOURCE_CALLBACK_TRAILER_V1_LEN, SOURCE_CALLBACK_TRAILER_LEN),
            (70, 174),
            "records already on the network carry the 70-byte prefix; it cannot move"
        );
        let record = SignedRecord::source([0xAA; 16], [0xBB; 32], 9, "old.mp3", contact, &sk);
        // Drop the endorsement, exactly as a v1 publisher would never have
        // written it. The signature no longer covers the body, so decode
        // directly.
        let legacy = &record.data[..record.data.len() - BUDDY_ENDORSEMENT_TRAILER_LEN];
        assert_eq!(
            legacy.len(),
            115 + "old.mp3".len() + SOURCE_CONTACT_WIRE_LEN + SOURCE_CALLBACK_TRAILER_V1_LEN
        );
        let parsed = decode_source_contact(legacy, 115 + "old.mp3".len()).expect("v1 trailer");
        let buddy = parsed.buddy.expect("v1 trailer still names a buddy");
        assert_eq!(buddy.ip, BUDDY_IP);
        assert_eq!(buddy.udp_port, BUDDY_UDP);
        assert_eq!(buddy.noise_pub, BUDDY_NOISE);
        assert_eq!(parsed.user_hash, Some([0xCCu8; 16]));
        assert_eq!(parsed.callback_token, Some([0xDDu8; 16]));
        assert!(
            !buddy.has_identity() && buddy.node_id().is_none(),
            "a v1 buddy carries no key, so there is no endorsement to check"
        );
        assert!(
            !DiscoveredSource {
                ip: parsed.ip,
                tcp_port: parsed.tcp_port,
                udp_port: parsed.udp_port,
                flags: parsed.flags,
                user_hash: parsed.user_hash,
                buddy: parsed.buddy,
                callback_token: parsed.callback_token,
                publisher_id: TEST_PUBLISHER,
            }
            .takes_callback(false, 1_000),
            "and so must park rather than be dialled"
        );
    }

    #[test]
    fn source_record_without_trailer_still_parses() {
        let sk = SigningKey::generate(&mut OsRng);
        let contact = test_contact();
        let record = SignedRecord::source([0xAA; 16], [0xBB; 32], 1, "x", contact, &sk);
        assert_eq!(
            record.data.len(),
            115 + 1 + SOURCE_CONTACT_WIRE_LEN,
            "HighID records must not grow the callback trailer"
        );
        let parsed = SignedRecord::from_wire(&record.data, record.signature).unwrap();
        assert_eq!(parsed.source_contact, Some(contact));
        assert!(parsed.source_contact.unwrap().buddy.is_none());
    }

    #[test]
    fn keyword_record_carries_no_contact() {
        let sk = SigningKey::generate(&mut OsRng);
        let record = SignedRecord::keyword("test", [1u8; 16], [2u8; 32], 1, "f.txt", &sk);
        assert_eq!(record.source_contact, None);
        let parsed = SignedRecord::from_wire(&record.data, record.signature).unwrap();
        assert_eq!(parsed.source_contact, None);
    }

    #[test]
    fn truncated_source_contact_is_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let record = SignedRecord::source([0xAA; 16], [0xBB; 32], 10, "x", test_contact(), &sk);
        // Drop a byte from the trailing contact block: the length guard in
        // from_wire must reject it rather than admit a malformed source record.
        let truncated = &record.data[..record.data.len() - 1];
        assert!(SignedRecord::from_wire(truncated, record.signature).is_none());
    }

    #[test]
    fn tampered_source_contact_fails_verify() {
        let sk = SigningKey::generate(&mut OsRng);
        let record = SignedRecord::source([0xAA; 16], [0xBB; 32], 10, "x", test_contact(), &sk);
        // Flip a byte inside the trailing (signed) contact block; the
        // publisher signature must no longer verify.
        let mut data = record.data.clone();
        let last = data.len() - 1;
        data[last] ^= 0xFF;
        assert!(SignedRecord::from_wire(&data, record.signature).is_none());
    }

    #[test]
    fn keyword_record_layout_is_stable() {
        let sk = SigningKey::generate(&mut OsRng);
        let name = "ubuntu-24.04.iso";
        let record = SignedRecord::keyword("ubuntu", [1u8; 16], [2u8; 32], 4096, name, &sk);
        // Keyword records must NOT grow a trailing contact block: the layout
        // stays the 115-byte fixed header + the UTF-8 name, byte-for-byte as
        // before slice 9, so existing keyword records remain valid.
        assert_eq!(record.data.len(), 115 + name.len());
        assert!(record.verify());
    }

    #[test]
    fn tampered_record_fails_verification() {
        let sk = SigningKey::generate(&mut OsRng);
        let record =
            SignedRecord::keyword("test", [1u8; 16], [2u8; 32], 12345, "test_file.txt", &sk);

        let mut tampered_data = record.data.clone();
        tampered_data[20] ^= 0xFF; // flip a byte
        assert!(SignedRecord::from_wire(&tampered_data, record.signature).is_none());
    }

    #[test]
    fn publish_manager_lifecycle() {
        use super::super::routing::RoutingTable;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let local = EmberNodeId([0u8; 16]);
        let mut rt = RoutingTable::new(local, false);

        for i in 1..=10u8 {
            let mut id = [0u8; 16];
            id[0] = i;
            rt.add_contact(EmberContact {
                node_id: EmberNodeId(id),
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, i, 1, 1)), 4662),
                noise_pub: [i; 32],
                ed25519_pub: [i; 32],
                last_seen: chrono::Utc::now().timestamp(),
                failed_queries: 0,
            });
        }

        let sk = SigningKey::generate(&mut OsRng);
        let record = SignedRecord::keyword("test", [0xAA; 16], [0xBB; 32], 1000, "file.txt", &sk);

        let mut pm = PublishManager::new();
        let dht_key = EmberNodeId(record.keyword_hash);
        let targets = rt.find_closest_prefer_verified(&dht_key, super::super::K_BUCKET_SIZE);
        let pub_id = pm.start_publish_to(record, targets).expect("publish slot");

        let op = pm.get_mut(pub_id).unwrap();
        let to_store = op.next_to_store();
        assert!(!to_store.is_empty());

        // Simulate acks
        for (_, req_id) in &to_store {
            op.process_ack(*req_id);
        }
        assert!(op.complete);
        assert_eq!(op.acked.len(), to_store.len());
    }

    #[test]
    fn start_publish_to_uses_the_supplied_targets_not_the_table() {
        use super::super::routing::RoutingTable;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let local = EmberNodeId([0u8; 16]);
        let rt = RoutingTable::new(local, false);
        let supplied = EmberContact {
            node_id: EmberNodeId([0x77; 16]),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 7, 1, 1)), 4662),
            noise_pub: [0x77; 32],
            ed25519_pub: [0x77; 32],
            last_seen: chrono::Utc::now().timestamp(),
            failed_queries: 0,
        };

        let sk = SigningKey::generate(&mut OsRng);
        let record = SignedRecord::keyword("test", [0xAA; 16], [0xBB; 32], 1000, "file.txt", &sk);

        let mut pm = PublishManager::new();
        let pub_id = pm
            .start_publish_to(record, vec![supplied.clone()])
            .expect("publish slot");
        let op = pm.get_mut(pub_id).unwrap();
        let to_store = op.next_to_store();
        assert_eq!(to_store.len(), 1);
        assert_eq!(to_store[0].0.node_id, supplied.node_id);
        assert!(
            rt.find_closest_prefer_verified(&EmberNodeId([0xAA; 16]), 20)
                .is_empty(),
            "the table is empty; the target must have come from start_publish_to"
        );
    }

    /// A huge filename used to produce a body the STORE decoder accepted and
    /// the FOUND_VALUE packer skipped. Encode now clamps so we never sign
    /// something a searcher cannot be served.
    #[test]
    fn a_huge_filename_is_clamped_to_the_found_value_budget() {
        let sk = SigningKey::generate(&mut OsRng);
        let huge = "n".repeat(8 * 1024);
        let record = SignedRecord::keyword("ubuntu", [0xAA; 16], [0xBB; 32], 1, &huge, &sk);
        assert!(
            record.data.len() <= super::super::messages::MAX_STORE_RECORD_BYTES,
            "encoded body {} exceeds the pack budget",
            record.data.len()
        );
        assert_eq!(
            record.data.len(),
            super::super::messages::MAX_STORE_RECORD_BYTES
        );
        assert!(record.file_name.len() < huge.len());
        assert!(record.verify());
    }

    fn discovered_firewalled(buddy: Option<SourceBuddy>) -> DiscoveredSource {
        DiscoveredSource {
            ip: Ipv4Addr::new(10, 0, 0, 9),
            tcp_port: 4662,
            udp_port: 4672,
            flags: crate::network::ember::SOURCE_FLAG_FIREWALLED,
            user_hash: Some([0xCCu8; 16]),
            buddy,
            callback_token: Some([0xDDu8; 16]),
            publisher_id: [0xAAu8; 16],
        }
    }

    #[test]
    fn routable_buddy_is_a_public_udp_destination() {
        assert!(test_buddy().is_routable());
        assert!(!SourceBuddy {
            ip: Ipv4Addr::new(10, 0, 0, 1),
            ..test_buddy()
        }
        .is_routable());
        assert!(!SourceBuddy {
            udp_port: 0,
            ..test_buddy()
        }
        .is_routable());
        assert!(
            !SourceBuddy {
                ip: Ipv4Addr::new(203, 0, 113, 10),
                ..test_buddy()
            }
            .is_routable(),
            "TEST-NET documentation addresses are not callback destinations"
        );
        assert!(
            test_buddy().has_identity()
                && !SourceBuddy {
                    ed25519_pub: [0u8; 32],
                    ..test_buddy()
                }
                .has_identity(),
            "identity is the key, independent of whether the address routes"
        );
    }

    #[test]
    fn takes_callback_requires_a_reachable_searcher_and_a_usable_buddy() {
        let buddy_sk = SigningKey::generate(&mut OsRng);
        let now = 1_000_000i64;
        let buddy = endorsed_buddy(&buddy_sk, &TEST_PUBLISHER, now + 3600);
        let src = discovered_firewalled(Some(buddy));
        assert!(src.takes_callback(false, now));
        assert!(
            !src.takes_callback(true, now),
            "a firewalled searcher must park, not CALLBACK_REQ"
        );

        let highid = DiscoveredSource {
            flags: 0,
            ..src
        };
        assert!(!highid.takes_callback(false, now));

        // A different publisher cannot ride this endorsement, and with a zero
        // publisher id there is nothing for one to be bound to.
        let no_id = DiscoveredSource {
            publisher_id: [0u8; 16],
            ..src
        };
        assert!(!no_id.takes_callback(false, now));
        let other_publisher = DiscoveredSource {
            publisher_id: [0x77u8; 16],
            ..src
        };
        assert!(
            !other_publisher.takes_callback(false, now),
            "an endorsement lifted from another publisher's record must not verify"
        );

        let lan_buddy = discovered_firewalled(Some(SourceBuddy {
            ip: Ipv4Addr::new(192, 168, 1, 1),
            ..buddy
        }));
        assert!(
            !lan_buddy.takes_callback(false, now),
            "unusable buddy must not take the callback path (park instead)"
        );

        let unendorsed = discovered_firewalled(Some(SourceBuddy {
            ed25519_pub: [0u8; 32],
            ..buddy
        }));
        assert!(
            !unendorsed.takes_callback(false, now),
            "a buddy with no identity key has no endorsement to check, so park"
        );

        let no_buddy = discovered_firewalled(None);
        assert!(!no_buddy.takes_callback(false, now));

        let no_token = DiscoveredSource {
            callback_token: None,
            ..src
        };
        assert!(!no_token.takes_callback(false, now));

        assert!(
            !src.takes_callback(false, buddy.endorsed_until),
            "an endorsement is not valid at the instant it lapses"
        );
        assert!(!src.takes_callback(false, buddy.endorsed_until + 1));
    }

    /// The attack this whole mechanism exists to stop: a validly-signed
    /// firewalled source record for a popular file naming a victim's address as
    /// the buddy, so every reachable searcher opens an unsolicited Noise
    /// handshake to it. The publisher chooses the trailer bytes freely, but it
    /// cannot produce the victim's signature over them.
    #[test]
    fn a_buddy_endpoint_its_owner_did_not_sign_is_never_dialled() {
        let buddy_sk = SigningKey::generate(&mut OsRng);
        let now = 1_000_000i64;
        let honest = endorsed_buddy(&buddy_sk, &TEST_PUBLISHER, now + 3600);
        assert!(discovered_firewalled(Some(honest)).takes_callback(false, now));

        let victim_ip = Ipv4Addr::new(9, 9, 9, 9);
        // Repoint the endpoint, keeping the real key and a real signature.
        for aimed in [
            SourceBuddy { ip: victim_ip, ..honest },
            SourceBuddy { udp_port: 53, ..honest },
            SourceBuddy {
                noise_pub: [0xC1; 32],
                ..honest
            },
        ] {
            assert!(
                !discovered_firewalled(Some(aimed)).takes_callback(false, now),
                "moving any signed field must invalidate the endorsement"
            );
        }

        // Substituting a key the attacker *does* hold changes the node ID the
        // trailer names, so it is no longer the victim being named at all.
        let attacker_sk = SigningKey::generate(&mut OsRng);
        let self_signed = SourceBuddy {
            ip: victim_ip,
            ..endorsed_buddy(&attacker_sk, &TEST_PUBLISHER, now + 3600)
        };
        assert!(
            !discovered_firewalled(Some(self_signed)).takes_callback(false, now),
            "the attacker can only sign for the endpoint it actually signed"
        );

        // And the domain separator means a signature over the same fields
        // without it does not transfer.
        let mut raw = Vec::new();
        raw.extend_from_slice(&BUDDY_IP.octets());
        raw.extend_from_slice(&BUDDY_UDP.to_le_bytes());
        raw.extend_from_slice(&BUDDY_NOISE);
        raw.extend_from_slice(&TEST_PUBLISHER);
        raw.extend_from_slice(&(now + 3600).to_le_bytes());
        let undomained = SourceBuddy {
            endorsement: crypto::sign(&buddy_sk, &raw),
            ..honest
        };
        assert!(!discovered_firewalled(Some(undomained)).takes_callback(false, now));
    }
}
