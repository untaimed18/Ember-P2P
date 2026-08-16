//! Ember Channels: identities, DHT keys, invite URIs, and gossip bodies.
//!
//! A channel is an Ed25519 keypair minted at creation. Its stable address is
//! `channel_id = BLAKE3(channel_pubkey)[..16]`, the same derivation used for
//! Ember node IDs. Display names are not unique and cannot be squatted.
//!
//! Index / presence / moderation records are published as
//! [`super::dht::publish::RECORD_TYPE_CHANNEL`] signed records. Member IPs
//! never appear in those records; two members resolve each other only when
//! they become gossip neighbors, via a pairwise rendezvous capability.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key as ChaChaKey, XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;

use super::crypto;
use super::dht::EmberNodeId;

/// BLAKE3 `derive_key` context for the channel content key. Must stay at or
/// under 64 bytes; changing it would rotate every channel's message key.
const CONTENT_KEY_CONTEXT: &str = "ember-channel-content-v1";
const INDEX_KEY_PREFIX: &[u8] = b"ember:channels:index:v1:";
const PRESENCE_KEY_PREFIX: &[u8] = b"ember:channel:presence:v1";
const MODERATION_KEY_PREFIX: &[u8] = b"ember:channel:mod:v1";
const GOSSIP_AAD_DOMAIN: &[u8] = b"ember-channel-gossip-v1\0";

/// How many public-index shards Gather walks. Sized so each shard stays under
/// the 300-records-per-key FIND_VALUE cap for longer.
pub const INDEX_SHARD_COUNT: u8 = 16;
/// Presence DHT keys rotate on this interval so departed members age out.
pub const PRESENCE_EPOCH_SECS: i64 = 15 * 60;
/// Members re-announce presence this often (inside one epoch).
pub const PRESENCE_REPUBLISH_SECS: i64 = 10 * 60;
/// How often a member walks the presence DHT keys for rooms they have joined.
pub const PRESENCE_FETCH_SECS: i64 = 5 * 60;
/// How often members re-fetch the owner-signed moderation record.
pub const MODERATION_FETCH_SECS: i64 = 5 * 60;
/// Owners re-publish moderation so the 24h record TTL cannot age out.
pub const MODERATION_REPUBLISH_SECS: i64 = 6 * 60 * 60;
/// Cap on rooms whose XOR-neighbors we register at rendezvous per heartbeat.
pub const CHANNEL_RENDEZVOUS_MAX_CHANNELS: usize = 4;
/// Deterministic gossip degree: XOR-closest members to self.
pub const CHANNEL_NEIGHBOR_COUNT: usize = 8;
/// Default hop budget for a gossip flood.
pub const CHANNEL_MSG_TTL_DEFAULT: u8 = 8;
pub const CHANNEL_MSG_VERSION: u8 = 1;
const GOSSIP_NONCE_LEN: usize = 24;
const GOSSIP_TAG_LEN: usize = 16;
/// `version(1) + nonce + tag` around the plaintext.
pub const GOSSIP_ENVELOPE_OVERHEAD: usize = 1 + GOSSIP_NONCE_LEN + GOSSIP_TAG_LEN;
/// Fixed prefix of a gossip body before the ciphertext:
/// version(1) + channel_id(16) + msg_id(16) + ttl(1) + timestamp(8) + counter(8).
pub const GOSSIP_HEADER_LEN: usize = 1 + 16 + 16 + 1 + 8 + 8;

pub const CHANNEL_KIND_PUBLIC: &str = "public";
pub const CHANNEL_KIND_PRIVATE: &str = "private";

const URI_SCHEME: &str = "ember-channel:";

/// A newly minted channel identity.
#[derive(Clone)]
pub struct ChannelIdentity {
    pub signing_key: SigningKey,
    pub pubkey: [u8; 32],
    pub channel_id: [u8; 16],
}

impl ChannelIdentity {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self::from_signing_key(signing_key)
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self::from_signing_key(SigningKey::from_bytes(seed))
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let pubkey = signing_key.verifying_key().to_bytes();
        let channel_id = channel_id_from_pubkey(&pubkey);
        Self {
            signing_key,
            pubkey,
            channel_id,
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

/// `channel_id = BLAKE3(channel_pubkey)[..16]`.
pub fn channel_id_from_pubkey(pubkey: &[u8; 32]) -> [u8; 16] {
    crypto::node_id_from_ed25519_bytes(pubkey).unwrap_or_else(|| {
        // A 32-byte value that is not a valid Ed25519 point cannot be a
        // channel pubkey we would ever mint or accept on the wire. The
        // fallback keeps the function total for hashing already-checked keys.
        let hash = blake3::hash(pubkey);
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash.as_bytes()[..16]);
        id
    })
}

/// Public channels use the channel pubkey as the join secret. Private
/// channels carry an extra 32-byte secret in the invite.
pub fn public_join_secret(channel_pubkey: &[u8; 32]) -> [u8; 32] {
    *channel_pubkey
}

pub fn generate_private_join_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    secret
}

/// Symmetric key for channel message bodies and private metadata.
pub fn content_key(join_secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(CONTENT_KEY_CONTEXT, join_secret)
}

pub fn index_shard(channel_id: &[u8; 16]) -> u8 {
    channel_id[0] % INDEX_SHARD_COUNT
}

/// DHT key for one public-index shard.
pub fn index_key(shard: u8) -> [u8; 16] {
    let shard = shard % INDEX_SHARD_COUNT;
    let mut hasher = blake3::Hasher::new();
    hasher.update(INDEX_KEY_PREFIX);
    hasher.update(&[shard]);
    let hash = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash.as_bytes()[..16]);
    key
}

pub fn index_key_for_channel(channel_id: &[u8; 16]) -> [u8; 16] {
    index_key(index_shard(channel_id))
}

/// All 16 public-index keys, in shard order, for Gather.
pub fn all_index_keys() -> [[u8; 16]; INDEX_SHARD_COUNT as usize] {
    let mut keys = [[0u8; 16]; INDEX_SHARD_COUNT as usize];
    for (i, key) in keys.iter_mut().enumerate() {
        *key = index_key(i as u8);
    }
    keys
}

pub fn presence_epoch(unix_seconds: i64) -> i64 {
    unix_seconds.div_euclid(PRESENCE_EPOCH_SECS)
}

/// Presence DHT key. Private channels fold `join_secret` in so non-members
/// cannot enumerate the room.
pub fn presence_key(
    channel_id: &[u8; 16],
    join_secret: &[u8; 32],
    epoch: i64,
) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PRESENCE_KEY_PREFIX);
    hasher.update(channel_id);
    hasher.update(join_secret);
    hasher.update(&epoch.to_le_bytes());
    let hash = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash.as_bytes()[..16]);
    key
}

pub fn moderation_key(channel_id: &[u8; 16]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MODERATION_KEY_PREFIX);
    hasher.update(channel_id);
    let hash = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash.as_bytes()[..16]);
    key
}

/// Rendezvous capability two channel members compute for each other.
///
/// Distinct from friend presence: the purpose binds the channel and the
/// presence-slot owner, so a channel neighbor cannot reuse the capability
/// to look up a friend slot, and Alice's entry cannot overwrite Bob's.
pub fn derive_channel_presence_capability(
    our_ed25519_seed: &[u8; 32],
    peer_ed25519_pubkey: &[u8; 32],
    owner_ed25519_pubkey: &[u8; 32],
    channel_id: &[u8; 16],
    epoch: i64,
) -> Option<[u8; 32]> {
    // Pairwise purpose is capped at 64 bytes. Truncate the owner to the
    // same 16-byte ID used everywhere else so the tuple still fits.
    let owner_id = channel_id_from_pubkey(owner_ed25519_pubkey);
    let mut purpose = Vec::with_capacity(10 + 16 + 16);
    purpose.extend_from_slice(b"ch-pres-v1");
    purpose.extend_from_slice(channel_id);
    purpose.extend_from_slice(&owner_id);
    crypto::derive_pairwise_capability(our_ed25519_seed, peer_ed25519_pubkey, &purpose, epoch)
}

/// XOR-closest `k` member pubkeys to `self_pub`, excluding self.
///
/// Distance is on the 16-byte IDs (`BLAKE3(pubkey)[..16]`), matching DHT
/// node IDs, so both sides independently compute the same pairing.
pub fn xor_closest_neighbors(
    self_pub: &[u8; 32],
    members: &[[u8; 32]],
    k: usize,
) -> Vec<[u8; 32]> {
    let self_id = EmberNodeId(channel_id_from_pubkey(self_pub));
    let mut ranked: Vec<([u8; 32], EmberNodeId)> = members
        .iter()
        .filter(|pk| *pk != self_pub)
        .map(|pk| {
            let id = EmberNodeId(channel_id_from_pubkey(pk));
            (*pk, self_id.distance(&id))
        })
        .collect();
    ranked.sort_by(|a, b| a.1 .0.cmp(&b.1 .0));
    ranked.truncate(k);
    ranked.into_iter().map(|(pk, _)| pk).collect()
}

/// XOR-closest gossip neighbors across joined rooms, for rendezvous
/// capability registration. Caps both the number of rooms and the degree
/// so a large join list cannot explode the heartbeat HTTP fan-out.
pub fn rendezvous_neighbor_targets(
    our_pubkey: &[u8; 32],
    members_by_channel: &[([u8; 16], Vec<[u8; 32]>)],
    max_channels: usize,
    neighbor_count: usize,
) -> Vec<([u8; 16], [u8; 32])> {
    let mut out = Vec::new();
    for (channel_id, members) in members_by_channel.iter().take(max_channels) {
        for pk in xor_closest_neighbors(our_pubkey, members, neighbor_count) {
            out.push((*channel_id, pk));
        }
    }
    out
}

/// Parsed `ember-channel:` invite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelInvite {
    pub channel_id: [u8; 16],
    pub pubkey: [u8; 32],
    pub name: String,
    pub join_secret: [u8; 32],
    pub private: bool,
}

impl ChannelInvite {
    pub fn format(&self) -> String {
        let mut uri = format!(
            "{URI_SCHEME}{}?pk={}",
            hex::encode(self.channel_id),
            hex::encode(self.pubkey)
        );
        if !self.name.is_empty() {
            uri.push_str("&name=");
            uri.push_str(&percent_encode(&self.name));
        }
        if self.private {
            uri.push_str("&k=");
            uri.push_str(&hex::encode(self.join_secret));
        }
        uri
    }

    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        let rest = trimmed.strip_prefix(URI_SCHEME)?;
        let (id_hex, query) = rest.split_once('?').unwrap_or((rest, ""));
        if id_hex.len() != 32 {
            return None;
        }
        let channel_id = hex_16(id_hex)?;
        let mut pubkey = None;
        let mut name = String::new();
        let mut join_secret = None;
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            match key {
                "pk" => pubkey = hex_32(value),
                "name" => name = percent_decode(value)?,
                "k" => join_secret = hex_32(value),
                _ => {}
            }
        }
        let pubkey = pubkey?;
        if channel_id_from_pubkey(&pubkey) != channel_id {
            return None;
        }
        let private = join_secret.is_some();
        let join_secret = join_secret.unwrap_or_else(|| public_join_secret(&pubkey));
        Some(Self {
            channel_id,
            pubkey,
            name,
            join_secret,
            private,
        })
    }
}

fn hex_16(s: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(s).ok()?;
    <[u8; 16]>::try_from(bytes).ok()
}

fn hex_32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    <[u8; 32]>::try_from(bytes).ok()
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let hi = from_hex_digit(bytes[i + 1])?;
                let lo = from_hex_digit(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn from_hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Authenticated gossip payload carried inside [`super::dht::messages::MSG_CHANNEL_MSG`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelGossip {
    pub channel_id: [u8; 16],
    pub msg_id: [u8; 16],
    pub ttl: u8,
    pub timestamp: i64,
    pub sender_counter: u64,
    pub ciphertext: Vec<u8>,
}

const CHAT_PLAIN_VERSION: u8 = 1;

/// `version(1) || sender_pubkey(32) || utf8 text` inside a gossip body.
pub fn encode_channel_chat_plain(sender_pubkey: &[u8; 32], text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + text.len());
    out.push(CHAT_PLAIN_VERSION);
    out.extend_from_slice(sender_pubkey);
    out.extend_from_slice(text.as_bytes());
    out
}

pub fn decode_channel_chat_plain(bytes: &[u8]) -> Option<([u8; 32], String)> {
    if bytes.len() < 33 || bytes[0] != CHAT_PLAIN_VERSION {
        return None;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes[1..33]);
    let text = std::str::from_utf8(&bytes[33..]).ok()?.to_string();
    Some((pk, text))
}

impl ChannelGossip {
    pub fn new_plaintext(
        channel_id: [u8; 16],
        content_key: &[u8; 32],
        sender_counter: u64,
        plaintext: &[u8],
        ttl: u8,
    ) -> Self {
        let mut msg_id = [0u8; 16];
        OsRng.fill_bytes(&mut msg_id);
        Self::sealed(
            channel_id,
            msg_id,
            content_key,
            sender_counter,
            plaintext,
            ttl,
        )
    }

    pub fn sealed(
        channel_id: [u8; 16],
        msg_id: [u8; 16],
        content_key: &[u8; 32],
        sender_counter: u64,
        plaintext: &[u8],
        ttl: u8,
    ) -> Self {
        let timestamp = chrono::Utc::now().timestamp();
        let ciphertext = encrypt_gossip_body(
            content_key,
            &channel_id,
            &msg_id,
            sender_counter,
            timestamp,
            plaintext,
        );
        Self {
            channel_id,
            msg_id,
            ttl,
            timestamp,
            sender_counter,
            ciphertext,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(GOSSIP_HEADER_LEN + self.ciphertext.len());
        buf.push(CHANNEL_MSG_VERSION);
        buf.extend_from_slice(&self.channel_id);
        buf.extend_from_slice(&self.msg_id);
        buf.push(self.ttl);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.sender_counter.to_le_bytes());
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < GOSSIP_HEADER_LEN + GOSSIP_TAG_LEN {
            return None;
        }
        if bytes[0] != CHANNEL_MSG_VERSION {
            return None;
        }
        let mut channel_id = [0u8; 16];
        channel_id.copy_from_slice(&bytes[1..17]);
        let mut msg_id = [0u8; 16];
        msg_id.copy_from_slice(&bytes[17..33]);
        let ttl = bytes[33];
        let timestamp = i64::from_le_bytes(bytes[34..42].try_into().ok()?);
        let sender_counter = u64::from_le_bytes(bytes[42..50].try_into().ok()?);
        Some(Self {
            channel_id,
            msg_id,
            ttl,
            timestamp,
            sender_counter,
            ciphertext: bytes[50..].to_vec(),
        })
    }

    pub fn decrypt(&self, content_key: &[u8; 32]) -> Option<Vec<u8>> {
        decrypt_gossip_body(
            content_key,
            &self.channel_id,
            &self.msg_id,
            self.sender_counter,
            self.timestamp,
            &self.ciphertext,
        )
    }

    pub fn decremented_ttl(&self) -> Option<Self> {
        let ttl = self.ttl.checked_sub(1)?;
        if ttl == 0 {
            return None;
        }
        let mut next = self.clone();
        next.ttl = ttl;
        Some(next)
    }
}

fn gossip_aad(
    channel_id: &[u8; 16],
    msg_id: &[u8; 16],
    sender_counter: u64,
    timestamp: i64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(GOSSIP_AAD_DOMAIN.len() + 16 + 16 + 8 + 8);
    aad.extend_from_slice(GOSSIP_AAD_DOMAIN);
    aad.extend_from_slice(channel_id);
    aad.extend_from_slice(msg_id);
    aad.extend_from_slice(&sender_counter.to_le_bytes());
    aad.extend_from_slice(&timestamp.to_le_bytes());
    aad
}

fn encrypt_gossip_body(
    key: &[u8; 32],
    channel_id: &[u8; 16],
    msg_id: &[u8; 16],
    sender_counter: u64,
    timestamp: i64,
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
    let mut nonce = [0u8; GOSSIP_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let aad = gossip_aad(channel_id, msg_id, sender_counter, timestamp);
    let encrypted = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption cannot fail for channel-sized plaintext");
    let mut out = Vec::with_capacity(1 + GOSSIP_NONCE_LEN + encrypted.len());
    out.push(CHANNEL_MSG_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&encrypted);
    out
}

fn decrypt_gossip_body(
    key: &[u8; 32],
    channel_id: &[u8; 16],
    msg_id: &[u8; 16],
    sender_counter: u64,
    timestamp: i64,
    envelope: &[u8],
) -> Option<Vec<u8>> {
    if envelope.len() < GOSSIP_ENVELOPE_OVERHEAD || envelope[0] != CHANNEL_MSG_VERSION {
        return None;
    }
    let aad = gossip_aad(channel_id, msg_id, sender_counter, timestamp);
    let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(&envelope[1..1 + GOSSIP_NONCE_LEN]),
            Payload {
                msg: &envelope[1 + GOSSIP_NONCE_LEN..],
                aad: &aad,
            },
        )
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_id_matches_ember_node_id_derivation() {
        let ident = ChannelIdentity::generate();
        let vk = crypto::verifying_key_from_bytes(&ident.pubkey).unwrap();
        assert_eq!(ident.channel_id, crypto::node_id_from_public_key(&vk));
        assert_eq!(ident.channel_id, channel_id_from_pubkey(&ident.pubkey));
    }

    #[test]
    fn public_and_private_content_keys_differ() {
        let ident = ChannelIdentity::generate();
        let public = content_key(&public_join_secret(&ident.pubkey));
        let private = content_key(&generate_private_join_secret());
        assert_ne!(public, private);
        assert_eq!(
            content_key(&public_join_secret(&ident.pubkey)),
            public,
            "content key must be deterministic"
        );
    }

    #[test]
    fn index_keys_are_sharded_and_stable() {
        let keys = all_index_keys();
        let unique: std::collections::HashSet<_> = keys.iter().copied().collect();
        assert_eq!(unique.len(), INDEX_SHARD_COUNT as usize);
        assert_eq!(index_key(0), index_key(INDEX_SHARD_COUNT));
        let id = [0x11u8; 16];
        assert_eq!(index_key_for_channel(&id), index_key(index_shard(&id)));
    }

    #[test]
    fn presence_key_rotates_with_epoch_and_secret() {
        let id = [0xAAu8; 16];
        let secret = [0xBBu8; 32];
        let e0 = presence_key(&id, &secret, 0);
        let e1 = presence_key(&id, &secret, 1);
        let other = presence_key(&id, &[0xCCu8; 32], 0);
        assert_ne!(e0, e1);
        assert_ne!(e0, other);
        assert_eq!(presence_epoch(PRESENCE_EPOCH_SECS - 1), 0);
        assert_eq!(presence_epoch(PRESENCE_EPOCH_SECS), 1);
    }

    #[test]
    fn public_invite_round_trip_binds_id_to_pubkey() {
        let ident = ChannelIdentity::generate();
        let invite = ChannelInvite {
            channel_id: ident.channel_id,
            pubkey: ident.pubkey,
            name: "General chat".into(),
            join_secret: public_join_secret(&ident.pubkey),
            private: false,
        };
        let parsed = ChannelInvite::parse(&invite.format()).unwrap();
        assert_eq!(parsed, invite);
        assert!(!parsed.format().contains("&k="));
    }

    #[test]
    fn private_invite_carries_join_secret() {
        let ident = ChannelIdentity::generate();
        let secret = generate_private_join_secret();
        let invite = ChannelInvite {
            channel_id: ident.channel_id,
            pubkey: ident.pubkey,
            name: "café ☕".into(),
            join_secret: secret,
            private: true,
        };
        let parsed = ChannelInvite::parse(&invite.format()).unwrap();
        assert_eq!(parsed.join_secret, secret);
        assert!(parsed.private);
        assert_eq!(parsed.name, "café ☕");
    }

    #[test]
    fn invite_with_mismatched_id_is_rejected() {
        let ident = ChannelIdentity::generate();
        let mut uri = format!(
            "{URI_SCHEME}{}?pk={}",
            hex::encode([0u8; 16]),
            hex::encode(ident.pubkey)
        );
        assert!(ChannelInvite::parse(&uri).is_none());
        uri = format!(
            "{URI_SCHEME}{}?pk={}",
            hex::encode(ident.channel_id),
            hex::encode([1u8; 32])
        );
        assert!(ChannelInvite::parse(&uri).is_none());
    }

    #[test]
    fn xor_neighbors_are_deterministic_and_exclude_self() {
        let self_pk = [1u8; 32];
        let mut members = vec![self_pk];
        for i in 2u8..=20 {
            members.push([i; 32]);
        }
        let a = xor_closest_neighbors(&self_pk, &members, CHANNEL_NEIGHBOR_COUNT);
        let b = xor_closest_neighbors(&self_pk, &members, CHANNEL_NEIGHBOR_COUNT);
        assert_eq!(a, b);
        assert_eq!(a.len(), CHANNEL_NEIGHBOR_COUNT);
        assert!(!a.contains(&self_pk));
    }

    #[test]
    fn gossip_round_trip_and_aad_bind() {
        let key = content_key(&[7u8; 32]);
        let channel_id = [3u8; 16];
        let msg = ChannelGossip::new_plaintext(channel_id, &key, 42, b"hello room", 4);
        let decoded = ChannelGossip::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.decrypt(&key).as_deref(), Some(b"hello room".as_slice()));
        let (pk, text) = decode_channel_chat_plain(&encode_channel_chat_plain(&[9u8; 32], "hi")).unwrap();
        assert_eq!(pk, [9u8; 32]);
        assert_eq!(text, "hi");
        assert!(decoded.decrypt(&[8u8; 32]).is_none());
        let mut tampered = decoded.clone();
        tampered.sender_counter = 43;
        assert!(tampered.decrypt(&key).is_none());
        assert_eq!(decoded.decremented_ttl().unwrap().ttl, 3);
        assert!(ChannelGossip {
            ttl: 1,
            ..decoded
        }
        .decremented_ttl()
        .is_none());
    }

    #[test]
    fn channel_presence_capability_is_pairwise_and_channel_bound() {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        let channel_id = [0x11u8; 16];
        let epoch = 9;
        let alice_to_bob = derive_channel_presence_capability(
            &alice.to_bytes(),
            &bob.verifying_key().to_bytes(),
            &bob.verifying_key().to_bytes(),
            &channel_id,
            epoch,
        )
        .unwrap();
        let bob_to_alice = derive_channel_presence_capability(
            &bob.to_bytes(),
            &alice.verifying_key().to_bytes(),
            &bob.verifying_key().to_bytes(),
            &channel_id,
            epoch,
        )
        .unwrap();
        assert_eq!(alice_to_bob, bob_to_alice);
        let other_channel = derive_channel_presence_capability(
            &alice.to_bytes(),
            &bob.verifying_key().to_bytes(),
            &bob.verifying_key().to_bytes(),
            &[0x22u8; 16],
            epoch,
        )
        .unwrap();
        assert_ne!(alice_to_bob, other_channel);
        let friend_cap = crypto::derive_pairwise_presence_capability(
            &alice.to_bytes(),
            &bob.verifying_key().to_bytes(),
            &bob.verifying_key().to_bytes(),
            epoch,
        )
        .unwrap();
        assert_ne!(
            alice_to_bob, friend_cap,
            "channel capability must not collide with friend presence"
        );
    }

    #[test]
    fn rendezvous_neighbor_targets_are_xor_closest_and_skip_self() {
        let self_pk = SigningKey::generate(&mut OsRng)
            .verifying_key()
            .to_bytes();
        let a = SigningKey::generate(&mut OsRng)
            .verifying_key()
            .to_bytes();
        let b = SigningKey::generate(&mut OsRng)
            .verifying_key()
            .to_bytes();
        let channel_id = [0xab; 16];
        let closest = xor_closest_neighbors(&self_pk, &[self_pk, a, b], 1);
        assert_eq!(closest.len(), 1);
        assert_ne!(closest[0], self_pk);
        let targets = rendezvous_neighbor_targets(
            &self_pk,
            &[(channel_id, vec![self_pk, a, b])],
            CHANNEL_RENDEZVOUS_MAX_CHANNELS,
            1,
        );
        assert_eq!(targets, vec![(channel_id, closest[0])]);
    }
}
